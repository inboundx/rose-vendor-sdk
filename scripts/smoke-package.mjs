import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';

const sdk = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'rose-vendor-sdk-'));
const archiveDir = process.argv[2] ? resolve(process.argv[2]) : temp;
mkdirSync(archiveDir, { recursive: true });
let server;
try {
  execFileSync('npm', ['pack', '--pack-destination', archiveDir], { cwd: sdk, stdio: 'pipe' });
  const metadata = JSON.parse(readFileSync(join(sdk, 'package.json'), 'utf8'));
  const archive = join(archiveDir, `${metadata.name.replace('@', '').replace('/', '-')}-${metadata.version}.tgz`);
  const contents = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' });
  assert(!/node_modules|\/test\/|\/src\/|\.env/.test(contents));
  assert(contents.includes('package/dist/index.d.ts'));
  writeFileSync(join(temp, 'package.json'), JSON.stringify({ type: 'module', private: true }));
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', archive], { cwd: temp, stdio: 'pipe' });
  const installed = join(temp, 'node_modules/@userose/vendor-sdk');
  const { createVendorHandler, createHandoverVerifier, VendorError, REVOKED_EVENT } =
    await import(pathToFileURL(join(installed, 'dist/index.js')).href);
  const { SignJWT, generateKeyPair, exportJWK } =
    await import(pathToFileURL(join(temp, 'node_modules/jose/dist/webapi/index.js')).href);

  // Compile the documented SDK API against the INSTALLED archive, not repository source.
  // The README's snippets; Rose's client guide (sdk-setup.md in the Rose repository) uses the same ones.
  const guide = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const snippets = [...guide.matchAll(/```typescript\n([\s\S]*?)\n```/g)].map(match => match[1]);
  assert.equal(snippets.length, 3);
  writeFileSync(join(temp, 'consumer.ts'), `
import { type AgentAccounts, type AgentConfig, type HandoverConfig, type Json, type VerifiedClaim, type VerifiedRevocation } from '@userose/vendor-sdk';
declare const roseAgentConfiguration: Omit<AgentConfig, 'accounts' | 'store'>;
declare const yourAccounts: AgentAccounts;
declare const incomingRequest: Request;
declare const yourRecords: {
  get(key: string): Promise<Json | undefined>;
  transaction<T>(work: (tx: { getForUpdate(key: string): Promise<Json | undefined>; put(key: string, value: Json): Promise<void>; delete(key: string): Promise<void> }) => Promise<T>): Promise<T>;
};
declare const roseTrustConfiguration: HandoverConfig;
declare const identityAssertion: string;
declare const signedEvent: string;
declare const trial: {id: string; userCode: string};
declare const yourDatabase: {claimTrialAtomically(claim: VerifiedClaim): Promise<void>; revokeBuyerAtomically(event: VerifiedRevocation): Promise<void>};
${snippets.join('\n')}
const provisioning: VendorHandlers['account'] = async (_buyer, _email, input) => ({
  account_id: 'account_1', created: true,
  next: typeof input?.company_name === 'string' ? input.company_name : 'Finish setup',
});
const legacyProvisioning: VendorHandlers['account'] = async (_buyer, _email) => ({
  account_id: 'account_1', created: false,
});
void provisioning;
void legacyProvisioning;
`);
  execFileSync(process.execPath, [join(sdk, 'node_modules/typescript/bin/tsc'), '--noEmit', '--strict',
    '--module', 'NodeNext', '--target', 'ES2022', join(temp, 'consumer.ts')], { cwd: temp, stdio: 'pipe' });

  const keys = await generateKeyPair('ES256');
  const buyerId = '3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10';
  const claimBuyer = '9b1d4c2e-0a3f-4b6c-8d7e-1f2a3b4c5d6e';
  // A throwaway Rose signing key, trusted through `keys` as in local development.
  const roseKey = generateKeyPairSync('ed25519');
  const roseKeys = { keys: [{ ...roseKey.publicKey.export({ format: 'jwk' }), kid: 'test-local' }] };
  const records = new Map();
  const trial = { id: 'trial_existing', userCode: '123456', usage: 1, key: 'old-trial-fixture', buyer: null };
  const seen = new Set();
  const cutoffs = new Map();
  let handler;
  let verifier;
  let origin;
  server = createServer(async (incoming, outgoing) => {
    try {
      const req = new Request(origin + incoming.url, { method: incoming.method, headers: incoming.headers,
        ...(!['GET', 'HEAD'].includes(incoming.method) ? { body: Readable.toWeb(incoming), duplex: 'half' } : {}) });
      let response;
      if (incoming.url === '/agent/identity/claim/complete') {
        const { identity_assertion } = await req.json();
        const claim = await verifier.verifyClaim(identity_assertion, { registrationId: trial.id, userCode: trial.userCode });
        // Sample single-process atomic storage. Production needs a database transaction.
        const owner = `${claim.environment}:${claim.buyerId}`;
        if (seen.has(claim.proofId) || claim.expiresAt <= Date.now() / 1000 || claim.authenticatedAt <= (cutoffs.get(owner) ?? 0)) {
          throw new VendorError(409, 'Claim rejected');
        }
        if (trial.buyer && trial.buyer !== owner) throw new VendorError(409, 'Owner conflict');
        if ([...records.values()].some(row => row.buyer.environment === claim.environment && row.buyer.buyerId === claim.buyerId)) {
          throw new VendorError(409, 'Existing account conflict');
        }
        seen.add(claim.proofId);
        trial.buyer = owner;
        trial.key = crypto.randomUUID();
        response = Response.json({ account_id: trial.id, usage: trial.usage, key: trial.key });
      } else if (incoming.url === '/agent/events') {
        const event = await verifier.verifyRevocation(await req.text());
        const owner = `${event.environment}:${event.buyerId}`;
        if (!seen.has(event.eventId)) {
          seen.add(event.eventId);
          cutoffs.set(owner, Math.max(cutoffs.get(owner) ?? 0, event.issuedAt));
          if (trial.buyer === owner) trial.key = '';
        }
        response = new Response(null, { status: 202 });
      } else if (incoming.url === '/api/use') {
        if (!trial.key || req.headers.get('authorization') !== `Bearer ${trial.key}`) throw new VendorError(401, 'Invalid key');
        response = Response.json({ account_id: trial.id, usage: ++trial.usage });
      } else {
        response = await handler(req);
      }
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      outgoing.writeHead(error instanceof VendorError ? error.status : 500, { 'content-type': 'application/json' });
      outgoing.end(JSON.stringify({ detail: 'Request rejected' }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  handler = createVendorHandler({ origin, keys: roseKeys, handlers: {
    async trial(_, input) { return { output: input, note: 'Sample trial' }; },
    async account(buyer) {
      if (trial.buyer === `${buyer.environment}:${buyer.buyerId}`) return { account_id: trial.id, created: false };
      const account_id = `${buyer.environment}_${buyer.buyerId}`;
      const created = !records.has(account_id);
      if (created) records.set(account_id, { buyer, usage: 0, active: false });
      return { account_id, created };
    },
    async authorizeAccount(buyer, id) {
      if (id === trial.id) return trial.buyer === `${buyer.environment}:${buyer.buyerId}`;
      const record = records.get(id);
      return record?.buyer.buyerId === buyer.buyerId && record?.buyer.environment === buyer.environment;
    },
    async lookup(buyer) {
      if (trial.buyer === `${buyer.environment}:${buyer.buyerId}`) return { account_id: trial.id };
      const id = `${buyer.environment}_${buyer.buyerId}`;
      return records.has(id) ? { account_id: id } : null;
    },
    async checkout(_, id) {
      if (id === trial.id) {
        if (!trial.key) throw new VendorError(403, 'Delegation revoked');
      } else records.get(id).active = true;
      return { status: 'active', offer: 'free' };
    },
    async access(_, id) {
      if (id === trial.id) {
        if (!trial.key) throw new VendorError(403, 'Delegation revoked');
        return { api_key: trial.key, offer: 'free', usage: trial.usage };
      }
      const record = records.get(id);
      if (!record.active) throw new VendorError(409, 'No active plan');
      return { api_key: 'sample-fixture-key', offer: 'free', usage: record.usage };
    },
    async use(_, id, input) {
      if (id === trial.id) {
        if (!trial.key) throw new VendorError(403, 'Delegation revoked');
        return { output: input, usage: ++trial.usage };
      }
      return { output: input, usage: ++records.get(id).usage };
    },
  } });
  verifier = createHandoverVerifier({ issuer: 'https://broker.example', audience: origin, environment: 'test',
    clientId: 'sdk-smoke', allowedSources: ['email'], jwks: { keys: [{ ...await exportJWK(keys.publicKey), kid: 'local-broker' }] } });
  async function signed(path, data, buyer = buyerId) {
    const method = data === undefined ? 'GET' : 'POST';
    const body = data === undefined ? '' : JSON.stringify(data);
    const created = Math.floor(Date.now() / 1000);
    const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
    const params = `("@method" "@authority" "@path" "content-digest" "x-r4a-buyer");created=${created};` +
      `expires=${created + 300};keyid="test-local";alg="ed25519";tag="r4a-contract"`;
    const base = [`"@method": ${method}`, `"@authority": ${new URL(origin).host}`, `"@path": ${path}`,
      `"content-digest": ${digest}`, `"x-r4a-buyer": ${buyer}`, `"@signature-params": ${params}`].join('\n');
    const signature = sign(null, Buffer.from(base), roseKey.privateKey).toString('base64');
    return fetch(origin + path, { method, ...(data === undefined ? {} : { body }), headers: {
      'X-R4A-Buyer': buyer, 'Content-Digest': digest, 'Signature-Input': `r4a=${params}`,
      Signature: `r4a=:${signature}:`, 'content-type': 'application/json',
    } });
  }
  const first = await signed('/r4a/accounts', { email: 'person@example.com' });
  assert.equal(first.status, 201);
  const { account_id: id } = await first.json();
  const retry = await signed('/r4a/accounts', { email: 'person@example.com' });
  assert.equal(retry.status, 200);
  assert.equal((await retry.json()).account_id, id);
  assert.equal((await (await signed('/r4a/account')).json()).account_id, id);
  assert.equal((await signed('/r4a/trial', { input: { value: 1 } })).status, 200);
  assert.equal((await signed(`/r4a/accounts/${id}/access`)).status, 409);
  assert.equal((await signed(`/r4a/accounts/${id}/checkout`, { offer_id: 'free', payment_token: null })).status, 200);
  assert.equal((await signed(`/r4a/accounts/${id}/use`, { input: { value: 2 } })).status, 200);
  assert.equal((await (await signed(`/r4a/accounts/${id}/access`)).json()).usage, 1);
  assert.equal((await signed(`/r4a/accounts/${id}/access`, undefined, crypto.randomUUID())).status, 403);
  assert.equal((await fetch(origin + '/r4a/accounts', { method: 'POST', body: '{"email":"person@example.com"}' })).status, 401);
  const now = Math.floor(Date.now() / 1000);
  const claimPayload = { iss: 'https://broker.example', aud: origin, sub: claimBuyer, iat: now, exp: now + 300,
    environment: 'test', client_id: 'sdk-smoke', email: 'person@example.com', email_verified: true,
    identity_source: 'email', auth_time: now, registration_id: trial.id, user_code: trial.userCode };
  async function jwt(payload, typ = 'oauth-id-jag+jwt') {
    return new SignJWT({ ...payload, jti: crypto.randomUUID() }).setProtectedHeader({ alg: 'ES256', typ, kid: 'local-broker' }).sign(keys.privateKey);
  }
  const proof = await jwt(claimPayload);
  const claim = token => fetch(origin + '/agent/identity/claim/complete', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ identity_assertion: token }) });
  const claimed = await claim(proof);
  assert.equal(claimed.status, 200);
  const claimedAccount = await claimed.json();
  assert.equal(claimedAccount.account_id, trial.id);
  assert.equal(claimedAccount.usage, 1);
  assert.equal((await claim(proof)).status, 409);
  const use = key => fetch(origin + '/api/use', { method: 'POST', headers: { authorization: `Bearer ${key}` } });
  assert.equal((await use('old-trial-fixture')).status, 401);
  assert.equal((await (await use(claimedAccount.key)).json()).usage, 2);
  assert.equal((await (await signed('/r4a/account', undefined, claimBuyer)).json()).account_id, trial.id);
  const reuse = await signed('/r4a/accounts', { email: 'person@example.com' }, claimBuyer);
  assert.equal(reuse.status, 200);
  assert.equal((await reuse.json()).account_id, trial.id);
  assert.equal((await (await signed(`/r4a/accounts/${trial.id}/access`, undefined, claimBuyer)).json()).api_key, claimedAccount.key);
  const event = await jwt({ ...claimPayload, events: { [REVOKED_EVENT]: {} } }, 'secevent+jwt');
  assert.equal((await fetch(origin + '/agent/events', { method: 'POST', body: event })).status, 202);
  assert.equal((await use(claimedAccount.key)).status, 401);
  assert.equal((await signed(`/r4a/accounts/${trial.id}/access`, undefined, claimBuyer)).status, 403);
  assert.equal((await claim(await jwt(claimPayload))).status, 409);
  console.log('Verified packed SDK: fresh install, exported types, signed HTTP funnel, ownership, claim continuity, credential rotation, replay and revocation cutoff.');
  if (process.argv[2]) console.log(`SDK archive: ${archive}`);
} finally {
  if (server) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  rmSync(temp, { recursive: true, force: true });
}
