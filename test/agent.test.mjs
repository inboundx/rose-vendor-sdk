import assert from 'node:assert/strict';
import { test } from 'node:test';
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
  assert.equal((await v.post('/oauth2/revoke', { token: `${key.slice(0, -1)}0` })).status, 200);
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
