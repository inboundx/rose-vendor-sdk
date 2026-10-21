import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from 'jose';
import { agentChangeKeys, applyAgentChange, CLAIM_GRANT, createAgentHandler, JWT_GRANT } from '@userose/vendor-sdk';

const ORIGIN = 'https://vendor.example';
const broker = await generateKeyPair('ES256');
const vendor = await generateKeyPair('ES256', { extractable: true });
const brokerJwk = { ...await exportJWK(broker.publicKey), kid: 'broker' };
const vendorJwk = { ...await exportJWK(vendor.publicKey), kid: 'vendor' };
const REVOKED = 'https://schemas.workos.com/events/agent/auth/identity/assertion/revoked';

/** A store that applies each change atomically, as a database transaction would. */
function memoryStore() {
  const data = new Map();
  return {
    data,
    async read(key) { return data.get(key); },
    async apply(change) {
      const records = Object.fromEntries(agentChangeKeys(change).map((key) => [key, data.get(key)]));
      const { writes, outcome } = applyAgentChange(change, records, Date.now());
      for (const [key, value] of Object.entries(writes)) value === null ? data.delete(key) : data.set(key, value);
      return outcome;
    },
  };
}

/** The vendor's product: accounts and API keys that expire and count their uses. */
function product() {
  let n = 0;
  const keys = new Map(), emails = new Map();
  return {
    keys, emails, failRevoke: false, failIssue: false, failClaimed: false, beforeIssue: null,
    async create() { return `acct_${++n}`; },
    async issueKey(account, grant) {
      if (this.failIssue) throw new Error('product unavailable');
      await this.beforeIssue?.();
      const id = `key_${++n}`, apiKey = `sk_${account}_${crypto.randomUUID()}`;
      keys.set(apiKey, { account, id, grant, uses: 0 });
      return { id, apiKey };
    },
    async revokeKey(account, id) {
      if (this.failRevoke) throw new Error('product unavailable');
      for (const [apiKey, key] of keys) if (key.account === account && key.id === id) keys.delete(apiKey);
    },
    async claimed(account, person) {
      if (this.failClaimed) throw new Error('product unavailable');
      emails.set(account, person.email);
    },
    accountOfKey(apiKey) { return keys.get(apiKey)?.account ?? null; },
    /** What the vendor's API answers to a call with this key. */
    call(apiKey) {
      const key = keys.get(apiKey);
      if (!key) return 401;
      if ((key.grant.expiresAt && key.grant.expiresAt <= Date.now()) || (key.grant.maxUses && key.uses >= key.grant.maxUses)) return 403;
      key.uses++;
      return 200;
    },
  };
}

async function setup(overrides = {}) {
  const store = memoryStore(), accounts = product();
  const agent = createAgentHandler({
    origin: ORIGIN, environment: 'test',
    rose: { issuer: 'https://identity.example', clientId: 'rose-id', allowedSources: ['google'], jwks: { keys: [brokerJwk] } },
    signing: { privateKey: await exportPKCS8(vendor.privateKey), jwks: { keys: [vendorJwk] } },
    consent: { url: 'https://id.example/agent/authorize', vendor: 'vendor', browserOrigin: 'https://id.example' },
    product: { name: 'Vendor', about: 'Vendor does one thing.', apiUrl: `${ORIGIN}/api`, usage: 'POST /api with the key.',
      scopes: { trial: 'thing:trial', full: 'thing:use' } },
    trialLimit: 2, accounts, store, operatorSecret: 'operator', ...overrides,
  });
  const post = async (path, data, headers = {}) => agent.handle(new Request(`${ORIGIN}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: typeof data === 'string' ? data : JSON.stringify(data) }));
  return { agent, store, accounts, post };
}

const json = async (response) => response.json();

async function proof(registration, buyer, overrides = {}, typ = 'oauth-id-jag+jwt') {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: 'https://identity.example', sub: buyer, aud: ORIGIN, jti: crypto.randomUUID(), iat: now, exp: now + 300,
    client_id: 'rose-id', environment: 'test', auth_time: now, email: 'person@example.com', email_verified: true, identity_source: 'google',
    registration_id: registration.registration_id, user_code: registration.claim.user_code, ...overrides })
    .setProtectedHeader({ typ, alg: 'ES256', kid: 'broker' }).sign(broker.privateKey);
}

const buyerId = () => crypto.randomUUID();
const register = async ({ post }, type = 'anonymous') => json(await post('/agent/identity', { type, ...(type === 'service_auth' ? { login_hint: 'person@example.com' } : {}) }));
const exchange = ({ post }, assertion) => post('/oauth2/token', { grant_type: JWT_GRANT, assertion });
const resume = ({ post }, r) => post('/oauth2/token', { grant_type: CLAIM_GRANT, claim_token: r.claim.claim_token });
const complete = async ({ post }, r, buyer, overrides) => post('/agent/identity/claim/complete', { identity_assertion: await proof(r, buyer, overrides) });

test('anonymous trial: a limited key at once, a claim keeps the account and replaces the key', async () => {
  const v = await setup();
  const r = await register(v);
  const trial = await json(await exchange(v, r.identity_assertion));
  assert.equal(trial.scope, 'thing:trial');
  assert.equal(v.accounts.call(trial.access_token), 200);
  assert.equal(v.accounts.call(trial.access_token), 200);
  assert.equal(v.accounts.call(trial.access_token), 403); // trialLimit
  assert.deepEqual(await json(await resume(v, r)), { error: 'authorization_pending' });

  const buyer = buyerId();
  const claimed = await json(await complete(v, r, buyer));
  assert.equal(claimed.account_id, r.registration_id);
  assert.equal(v.accounts.emails.get(r.registration_id), 'person@example.com');
  assert.equal(v.accounts.call(trial.access_token), 401); // the trial key is revoked
  assert.equal((await exchange(v, r.identity_assertion)).status, 400);
  const full = await json(await exchange(v, claimed.identity_assertion));
  assert.equal(full.scope, 'thing:use');
  assert.equal(full.account_id, r.registration_id);
  assert.equal(v.accounts.call(full.access_token), 200);
  assert.deepEqual(await json(await resume(v, r)), { error: 'slow_down' });

  // The signed /r4a door sees the same account.
  const who = { buyerId: buyer, environment: 'test' };
  assert.equal(await v.agent.contract.lookup(who), r.registration_id);
  assert.deepEqual(await v.agent.contract.provision(who, 'acct_other'), { account: r.registration_id });
  assert.equal((await v.agent.contract.access(who, r.registration_id)).apiKey, full.access_token);
  assert.equal(await v.agent.contract.access({ buyerId: buyer, environment: 'production' }, r.registration_id), 'not_owner');
});

test('service_auth: no access before the claim; the agent resumes with its claim token', async () => {
  const v = await setup();
  const r = await register(v, 'service_auth');
  assert.equal(r.identity_assertion, undefined);
  assert.equal((await complete(v, r, buyerId())).status, 200);
  const resumed = await json(await resume(v, r));
  assert.equal(resumed.scope, 'thing:use');
  assert.equal(v.accounts.call(resumed.access_token), 200);
});

test('a pending trial is refused through the signed door', async () => {
  const v = await setup();
  const r = await register(v);
  assert.equal(await v.agent.contract.access({ buyerId: buyerId(), environment: 'test' }, r.registration_id), 'not_owner');
});

test('one account per buyer: provisioning first makes a later claim a conflict', async () => {
  const v = await setup();
  const buyer = buyerId(), who = { buyerId: buyer, environment: 'test' };
  assert.deepEqual(await v.agent.contract.provision(who, 'acct_buyer'), { account: 'acct_buyer' });
  const r = await register(v);
  const claim = await complete(v, r, buyer);
  assert.equal(claim.status, 409);
  assert.deepEqual(await json(claim), { error: 'account_conflict' });
  assert.equal(await v.agent.contract.lookup(who), 'acct_buyer');
});

test('proofs are single use and claims for one buyer are serialized', async () => {
  const v = await setup();
  const r = await register(v), buyer = buyerId();
  const jwt = await proof(r, buyer);
  const replies = await Promise.all([jwt, jwt].map((identity_assertion) => v.post('/agent/identity/claim/complete', { identity_assertion })));
  assert.deepEqual(replies.map((reply) => reply.status).sort(), [200, 400]);
  const a = await register(v), b = await register(v), other = buyerId();
  const both = await Promise.all([complete(v, a, other), complete(v, b, other)]);
  assert.deepEqual(both.map((reply) => reply.status).sort(), [200, 409]);
});

test('rejects invalid identity evidence', async () => {
  const v = await setup();
  for (const overrides of [{ iss: 'https://evil.example' }, { aud: 'https://other.example' }, { client_id: 'other' }, { email_verified: false },
    { identity_source: 'github' }, { auth_time: 1 }, { environment: 'production' }, { user_code: '000000' }, { user_code: 'nope' }, { registration_id: 'acct_404' }]) {
    const r = await register(v);
    if (overrides.user_code === '000000' && r.claim.user_code === '000000') overrides.user_code = '111111';
    assert.equal((await complete(v, r, buyerId(), overrides)).status, 400, JSON.stringify(overrides));
  }
});

test('a revocation event stops the key, older proofs, and survives an unavailable product', async () => {
  const v = await setup();
  const r = await register(v), buyer = buyerId();
  const claimed = await json(await complete(v, r, buyer));
  const key = (await json(await exchange(v, claimed.identity_assertion))).access_token;
  const now = Math.floor(Date.now() / 1000);
  const cached = await proof(r, buyer, { auth_time: now });
  const event = await proof(r, buyer, { iat: now, exp: now + 300, events: { [REVOKED]: {} } }, 'secevent+jwt');

  v.accounts.failRevoke = true;
  assert.equal((await v.post('/agent/events', event)).status, 503);
  v.accounts.failRevoke = false;
  assert.equal((await v.post('/agent/events', event)).status, 202);
  assert.equal(v.accounts.call(key), 401);
  assert.equal((await v.post('/agent/events', event)).status, 202); // idempotent
  assert.deepEqual(await json(await v.post('/agent/identity/claim/complete', { identity_assertion: cached })), { error: 'fresh_authentication_required' });
  assert.equal(await v.agent.contract.access({ buyerId: buyer, environment: 'test' }, r.registration_id), 'restricted');

  const fresh = await json(await complete(v, r, buyer, { auth_time: now + 1, iat: now + 1 }));
  const renewed = await json(await exchange(v, fresh.identity_assertion));
  assert.equal(v.accounts.call(renewed.access_token), 200);
});

test('the agent revokes its own key; another key changes nothing', async () => {
  const v = await setup();
  const r = await register(v), buyer = buyerId();
  await complete(v, r, buyer);
  const key = (await json(await resume(v, r))).access_token;
  assert.equal((await v.post('/oauth2/revoke', { token: `${key.slice(0, -1)}${key.endsWith('0') ? '1' : '0'}` })).status, 200);
  assert.equal(v.accounts.call(key), 200);
  assert.equal((await v.post('/oauth2/revoke', { token: key })).status, 200);
  assert.equal(v.accounts.call(key), 401);
  assert.deepEqual(await json(await resume(v, r)), { error: 'expired_token' });
});

test('a claimed key expires with the delegation', async () => {
  const v = await setup({ credentialSeconds: 0 });
  const r = await register(v), buyer = buyerId();
  const claimed = await json(await complete(v, r, buyer));
  assert.equal((await exchange(v, claimed.identity_assertion)).status, 400);
  assert.equal(await v.agent.contract.access({ buyerId: buyer, environment: 'test' }, r.registration_id), 'restricted');
});

test('the claim code can be reminted with the claim token, not without', async () => {
  const v = await setup();
  const r = await register(v);
  const wrong = r.claim.claim_token.slice(0, -64) + '00'.repeat(32);
  assert.deepEqual(await json(await v.post('/agent/identity/claim', { claim_token: wrong, email: 'person@example.com' })), { error: 'invalid_claim_token' });
  const reset = await json(await v.post('/agent/identity/claim', { claim_token: r.claim.claim_token, email: 'person@example.com' }));
  assert.equal((await complete(v, r, buyerId())).status, 400); // the old code no longer works
  r.claim.user_code = reset.claim_attempt.user_code;
  assert.equal((await complete(v, r, buyerId())).status, 200);
});

test('discovery, consent redirect, operator view and the browser origin', async () => {
  const v = await setup();
  const meta = await json(await v.agent.handle(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`)));
  assert.deepEqual(meta.grant_types_supported, [JWT_GRANT, CLAIM_GRANT]);
  const skill = await (await v.agent.handle(new Request(`${ORIGIN}/auth.md`))).text();
  for (const part of ['Vendor does one thing.', '## Step 6 — Use the access_token', 'POST /api with the key.', '## Revocation']) assert.ok(skill.includes(part), part);
  const r = await register(v);
  const redirect = await v.agent.handle(new Request(`${ORIGIN}/claim?registration_id=${r.registration_id}`));
  assert.equal(redirect.status, 303);
  assert.ok(redirect.headers.get('location').startsWith('https://id.example/agent/authorize?vendor=vendor&registration_id=acct_'));
  assert.equal((await v.agent.handle(new Request(`${ORIGIN}/claim?registration_id=acct_nope`))).status, 404);
  const admin = (secret) => v.agent.handle(new Request(`${ORIGIN}/agent/admin/accounts/${r.registration_id}`, { headers: { Authorization: `Bearer ${secret}` } }));
  assert.equal((await admin('wrong')).status, 401);
  assert.equal((await json(await admin('operator'))).status, 'trial');
  assert.equal((await v.post('/agent/identity/claim/complete', '{}', { Origin: 'https://evil.example' })).status, 403);
  assert.equal(await v.agent.handle(new Request(`${ORIGIN}/api/other`)), null);
  assert.equal((await v.agent.handle(new Request('https://elsewhere.example/auth.md'))).status, 404);
});

test('an MCP product with its own OAuth server on the same origin', async () => {
  const seen = [];
  const v = await setup({
    product: { name: 'Vendor', about: 'Vendor does one thing.', apiUrl: `${ORIGIN}/api`, mcpUrl: `${ORIGIN}/mcp`, usage: 'Call the tools.',
      scopes: { trial: 'thing:trial', full: 'thing:use' } },
    authorizationServer: {
      metadata: { authorization_endpoint: `${ORIGIN}/oauth2/authorize`, grant_types_supported: ['authorization_code'], scopes_supported: ['thing:use'],
        issuer: 'https://ignored.example' },
      async token(fields) { seen.push(fields.grant_type); return Response.json({ access_token: 'own', token_type: 'Bearer' }); },
    },
  });
  const meta = await json(await v.agent.handle(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`)));
  assert.equal(meta.issuer, ORIGIN);
  assert.equal(meta.authorization_endpoint, `${ORIGIN}/oauth2/authorize`);
  assert.deepEqual(meta.grant_types_supported, ['authorization_code', JWT_GRANT, CLAIM_GRANT]);
  assert.deepEqual(meta.scopes_supported, ['thing:trial', 'thing:use']);
  // The vendor's own routes are not the SDK's.
  for (const path of ['/oauth2/authorize', '/oauth2/register', '/.well-known/oauth-protected-resource/mcp']) {
    assert.equal(await v.agent.handle(new Request(`${ORIGIN}${path}`)), null, path);
  }
  assert.equal((await json(await v.post('/oauth2/token', { grant_type: 'authorization_code', code: 'c' }))).access_token, 'own');
  assert.deepEqual(seen, ['authorization_code']);
  // Agent grants stay the SDK's, and name the MCP.
  const trial = await json(await exchange(v, (await register(v)).identity_assertion));
  assert.equal(trial.mcp_url, `${ORIGIN}/mcp`);
  assert.ok((await (await v.agent.handle(new Request(`${ORIGIN}/auth.md`))).text()).includes(`connect to \`${ORIGIN}/mcp\``));
});

test('a claim during a trial exchange never hands the trial a full key', async () => {
  const v = await setup();
  const r = await register(v), buyer = buyerId();
  let claimed;
  v.accounts.beforeIssue = async () => { v.accounts.beforeIssue = null; claimed = await json(await complete(v, r, buyer)); };
  assert.deepEqual(await json(await exchange(v, r.identity_assertion)), { error: 'invalid_grant' });
  assert.equal(v.accounts.keys.size, 0); // the trial key issued meanwhile is revoked
  const full = await json(await exchange(v, claimed.identity_assertion));
  assert.equal(full.scope, 'thing:use');
  assert.equal(v.accounts.keys.get(full.access_token).grant.scope, 'full');
});

test('no key until the product records the claim; the next request retries it', async () => {
  const v = await setup();
  const r = await register(v), buyer = buyerId();
  v.accounts.failClaimed = true;
  const claimed = await json(await complete(v, r, buyer));
  assert.equal(claimed.status, 'claimed');
  assert.deepEqual(await json(await exchange(v, claimed.identity_assertion)), { error: 'temporarily_unavailable' });
  await assert.rejects(v.agent.contract.access({ buyerId: buyer, environment: 'test' }, r.registration_id));
  v.accounts.failClaimed = false;
  const full = await json(await exchange(v, claimed.identity_assertion)); // the assertion was not spent
  assert.equal(v.accounts.emails.get(r.registration_id), 'person@example.com');
  assert.equal(v.accounts.call(full.access_token), 200);
});

test('a failed key issuance leaves the trial assertion usable', async () => {
  const v = await setup();
  const r = await register(v);
  v.accounts.failIssue = true;
  const failed = await exchange(v, r.identity_assertion);
  assert.equal(failed.status, 503);
  v.accounts.failIssue = false;
  assert.equal((await json(await exchange(v, r.identity_assertion))).scope, 'thing:trial');
});

test('revocation answers 503 while the key still works, and the retry revokes it', async () => {
  const v = await setup();
  const r = await register(v);
  const key = (await json(await exchange(v, r.identity_assertion))).access_token;
  v.accounts.failRevoke = true;
  assert.equal((await v.post('/oauth2/revoke', { token: key })).status, 503);
  assert.equal(v.accounts.call(key), 200);
  v.accounts.failRevoke = false;
  assert.equal((await v.post('/oauth2/revoke', { token: key })).status, 200);
  assert.equal(v.accounts.call(key), 401);
});

test('a streamed body over the limit is refused without reading it all', async () => {
  const v = await setup();
  let pulled = 0;
  const body = new ReadableStream({ pull(controller) { pulled++; controller.enqueue(new Uint8Array(4096)); } });
  const response = await v.agent.handle(new Request(`${ORIGIN}/agent/identity`, { method: 'POST', body, duplex: 'half' }));
  assert.deepEqual(await json(response), { error: 'invalid_request' });
  assert.ok(pulled < 10, `pulled ${pulled} chunks`);
});

test('the API\'s 401 points an agent with no key to auth.md; other answers pass through', async () => {
  const { agent } = await setup();
  const challenged = await agent.challenge(Response.json({ detail: 'Missing API key' }, { status: 401 }));
  assert.equal(challenged.status, 401);
  assert.equal(challenged.headers.get('WWW-Authenticate'), `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"`);
  assert.deepEqual(await challenged.json(), { detail: 'Missing API key', agent_registration: `No API key? An AI agent can start a trial itself: ${ORIGIN}/auth.md` });
  const text = await agent.challenge(new Response('no key', { status: 401, headers: { 'WWW-Authenticate': 'Bearer realm="api"' } }));
  assert.equal(text.headers.get('WWW-Authenticate'), 'Bearer realm="api"');
  assert.equal(await text.text(), 'no key');
  const ok = Response.json({ valid: true });
  assert.equal(await agent.challenge(ok), ok);
});

test('a 401 body the challenge cannot extend keeps its exact bytes and headers', async () => {
  const { agent } = await setup();
  const gzipped = new Uint8Array(await new Response(new Blob(['{"detail":"no key"}']).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
  const encoded = await agent.challenge(new Response(gzipped, { status: 401, statusText: 'Unauthorized',
    headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Content-Length': String(gzipped.length) } }));
  assert.equal(encoded.statusText, 'Unauthorized');
  assert.equal(encoded.headers.get('Content-Length'), String(gzipped.length));
  assert.deepEqual(new Uint8Array(await encoded.arrayBuffer()), gzipped);
  assert.ok(encoded.headers.get('WWW-Authenticate').startsWith('Bearer resource_metadata='));
  const latin1 = new Uint8Array([0x6e, 0x6f, 0x20, 0xe9]);
  const invalid = await agent.challenge(new Response(latin1, { status: 401, headers: { 'Content-Type': 'application/json' } }));
  assert.deepEqual(new Uint8Array(await invalid.arrayBuffer()), latin1);
  const empty = await agent.challenge(new Response(null, { status: 401 }));
  assert.equal(empty.headers.get('Content-Type'), null);
  assert.equal(await empty.text(), '');
});


// Exercises the exact solver artifact delivered to an autonomous client, including compiled
// HashWX execution. Put it below the SDK root so Node resolves its installed Cap dependency.
async function solveChallenge(v, challenge) {
  const dir = mkdtempSync(fileURLToPath(new URL('../.pow-test-', import.meta.url)));
  try {
    const solver = await v.agent.handle(new Request(`${ORIGIN}/agent/proof-of-work/solver`));
    assert.equal(solver.status, 200);
    writeFileSync(`${dir}/solve.mjs`, await solver.text());
    return JSON.parse(execFileSync(process.execPath, [`${dir}/solve.mjs`], {
      input: JSON.stringify(challenge), encoding: 'utf8', timeout: 30000,
    }));
  } finally { rmSync(dir, {recursive: true, force: true}); }
}

const signedKey = generateKeyPairSync('ed25519');
const signedJwk = { ...signedKey.publicKey.export({format: 'jwk'}), kid: 'test-pow' };
function registrationHeaders(body, options = {}) {
  const buyer = options.buyer ?? '3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10';
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const params = `("@method" "@authority" "@path" "content-digest" "x-r4a-buyer");created=${created};expires=${created + 300};keyid="${options.kid ?? 'test-pow'}";alg="ed25519";tag="r4a-contract"`;
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  const base = [`"@method": POST`, `"@authority": ${options.host ?? 'vendor.example'}`, '"@path": /agent/identity',
    `"content-digest": ${digest}`, `"x-r4a-buyer": ${buyer}`, `"@signature-params": ${params}`].join('\n');
  return { 'Content-Digest': digest, 'X-R4A-Buyer': buyer, 'Signature-Input': `r4a=${params}`,
    Signature: `r4a=:${sign(null, Buffer.from(base), signedKey.privateKey).toString('base64')}:` };
}

test('trial protection presets challenge before provisioning; service_auth remains claim-only', async () => {
  for (const [level, work] of [['low', 250000], ['medium', 1000000], ['high', 3000000]]) {
    const v = await setup({trialProtection: level});
    const response = await v.post('/agent/identity', {type: 'anonymous', rose_id: 'forged'});
    assert.equal(response.status, 428);
    const {proof_of_work: proof} = await response.json();
    assert.equal(proof.format, 2);
    assert.equal(proof.challenges.reduce((sum, p) => sum + p.payload.d, 0), work);
    assert.ok(proof.expires > Date.now());
    assert.equal(v.store.data.size, 0);
    const service = await register(v, 'service_auth');
    assert.equal(service.registration_id, 'acct_1'); // challenge allocated no product account
    assert.equal(service.identity_assertion, undefined);
    assert.equal((await complete(v, service, buyerId())).status, 200);
  }
});

test('a real solver gets a limited trial; concurrent proof redemption creates one account', async () => {
  const v = await setup({trialProtection: 'low'});
  const challenge = await json(await v.post('/agent/identity', {type: 'anonymous'}));
  const body = await solveChallenge(v, challenge);
  const responses = await Promise.all(Array.from({length: 8}, () => v.post('/agent/identity', body)));
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 409, 409, 409, 409, 409, 409, 409]);
  const registration = await json(responses.find(r => r.status === 200));
  const trial = await json(await exchange(v, registration.identity_assertion));
  assert.equal(v.accounts.call(trial.access_token), 200);
  assert.equal(v.accounts.call(trial.access_token), 200);
  assert.equal(v.accounts.call(trial.access_token), 403);
  assert.equal([...v.store.data.keys()].filter(k => k.startsWith('account:')).length, 1);
});

test('tampering, expired proofs, policy changes and malformed nonces never create accounts', async () => {
  const v = await setup({trialProtection: 'low'});
  const challenge = await json(await v.post('/agent/identity', {type: 'anonymous'}));
  const body = await solveChallenge(v, challenge);
  const token = body.proof_of_work.token;
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
  for (const changes of [
    {scope: JSON.stringify(['rose-anonymous-trial-v1', ORIGIN, 'production', 'low'])},
    {iat: Math.floor(Date.now()/1000)-301, exp: Math.floor(Date.now()/1000)-1},
    {challenges: payload.challenges.map(p => ({...p, payload: {...p.payload, d: 1}}))},
  ]) {
    const altered = await new SignJWT({...payload, ...changes}).setProtectedHeader({typ:'rose-trial-pow+jwt', alg:'ES256', kid:'vendor'}).sign(vendor.privateKey);
    assert.equal((await v.post('/agent/identity', {...body, proof_of_work:{...body.proof_of_work, token:altered}})).status, 428);
  }
  const invalid = structuredClone(body);
  invalid.proof_of_work.solutions[0].nonce = '-1';
  assert.equal((await v.post('/agent/identity', invalid)).status, 428);
  invalid.proof_of_work.solutions[0].nonce = '18446744073709551616';
  assert.equal((await v.post('/agent/identity', invalid)).status, 428);
  invalid.proof_of_work.token += 'broken';
  assert.equal((await v.post('/agent/identity', invalid)).status, 428);
  const higher = await setup({trialProtection:'high'});
  assert.equal((await higher.post('/agent/identity', body)).status, 428);
  assert.equal(v.store.data.size, 0);
  assert.equal((await v.post('/agent/identity', body)).status, 200); // invalid attempts did not consume valid proof
});

test('proof store failure fails closed before provisioning', async () => {
  const v = await setup({trialProtection:'low'});
  const body = await solveChallenge(v, await json(await v.post('/agent/identity', {type:'anonymous'})));
  const apply = v.store.apply;
  v.store.apply = async () => { throw new Error('store unavailable'); };
  assert.equal((await v.post('/agent/identity', body)).status, 503);
  v.store.apply = apply;
  assert.equal((await json(await v.post('/agent/identity', body))).registration_id, 'acct_1');
});

test('Rose policy is audience/environment bound and unavailable policies fail closed', async t => {
  let answer = {level:'medium', audience:ORIGIN, environment:'test'};
  const seen = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    seen.push([url, options]);
    if (answer === 'redirect') return new Response(null, {status:302, headers:{Location:'https://elsewhere.example/policy'}});
    return answer === null ? new Response('unavailable', {status:503}) : Response.json(answer);
  });
  const v = await setup({trialProtection:'rose'});
  assert.equal((await v.post('/agent/identity', {type:'anonymous'})).status, 428);
  assert.equal(seen[0][0], 'https://identity.example/trial-policy/vendor');
  assert.equal(seen[0][1].redirect, 'manual');
  for (const bad of [null, 'redirect', {level:'off',audience:'https://evil.example',environment:'test'},
    {level:'off',audience:ORIGIN,environment:'production'}, {level:'invalid',audience:ORIGIN,environment:'test'}]) {
    answer = bad;
    assert.equal((await v.post('/agent/identity', {type:'anonymous'})).status, 503);
  }
  assert.equal(v.store.data.size, 0);
  answer = {level:'off',audience:ORIGIN,environment:'test'};
  assert.equal((await v.post('/agent/identity', {type:'anonymous'})).status, 200);
});

test('verified Rose ID bypasses even unavailable policy; signed nonce cannot replay', async t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not fetch policy'); });
  const v = await setup({trialProtection:'rose', roseRequestKeys:{keys:[signedJwk]}});
  const body = JSON.stringify({type:'anonymous', registration_nonce:crypto.randomUUID()});
  const headers = registrationHeaders(body);
  const responses = await Promise.all([v.post('/agent/identity',body,headers),v.post('/agent/identity',body,headers)]);
  assert.deepEqual(responses.map(r => r.status).sort(), [200,409]);
  const registration = await json(responses.find(r => r.status === 200));
  assert.equal(registration.registration_type, 'anonymous');
  const trial = await json(await exchange(v,registration.identity_assertion));
  assert.equal(trial.scope,'thing:trial');
});

test('signature forgery, missing nonce and wrong environment cannot exempt a caller', async () => {
  const productionJwk = {...signedJwk, kid:'production-pow'};
  const v = await setup({trialProtection:'low',roseRequestKeys:{keys:[signedJwk,productionJwk]}});
  const body = JSON.stringify({type:'anonymous',registration_nonce:crypto.randomUUID()});
  for (const headers of [
    {'X-R4A-Buyer':'3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10'},
    registrationHeaders(body,{kid:'production-pow'}),
    registrationHeaders(body,{host:'evil.example'}),
    registrationHeaders(body,{created:Math.floor(Date.now()/1000)-301}),
    registrationHeaders(body+' '),
  ]) assert.equal((await v.post('/agent/identity',body,headers)).status,401);
  const noNonce = JSON.stringify({type:'anonymous'});
  assert.equal((await v.post('/agent/identity',noNonce,registrationHeaders(noNonce))).status,401);
  assert.equal(v.store.data.size,0);
});

test('proof replay shards prune expiry and never evict live proofs when full', () => {
  const now = Date.now(), id = 'ab'+'0'.repeat(62);
  const change = {type:'consume_trial_proof',id,expires:now+300000};
  const key = agentChangeKeys(change)[0];
  const records = {[key]: {[id]:now-1, ['ab'+'1'.repeat(62)]:now+1}};
  const next = applyAgentChange(change,records,now);
  assert.equal(next.outcome.ok,true);
  assert.equal(Object.keys(next.writes[key]).length,2);
  assert.equal(applyAgentChange(change,next.writes,now).outcome.error,'replay_detected');
  const full = Object.fromEntries(Array.from({length:1024}, (_,i)=>['ab'+(i+1).toString(16).padStart(62,'0'),now+300000]));
  assert.equal(applyAgentChange(change,{[key]:full},now).outcome.error,'proof_capacity_reached');
});
