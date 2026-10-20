import assert from 'node:assert/strict';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { createVendorHandler, VendorError, verifyRequest } from '@userose/vendor-sdk';

const buyerId = '3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10';
const otherBuyer = '9b1d4c2e-0a3f-4b6c-8d7e-1f2a3b4c5d6e';
const origin = 'https://vendor.example';
// Rose's keys as these tests see them: the published dev key (RFC 8032 test 1) and a production key.
const devKey = createPrivateKey({ format: 'jwk', key: {
  kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
  d: Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex').toString('base64url'),
} });
const privateKeys = { 'test-local': devKey, 'production-1': generateKeyPairSync('ed25519').privateKey };
const publicJwk = (kid) => {
  const { kty, crv, x } = privateKeys[kid].export({ format: 'jwk' });
  return { kty, crv, x, kid };
};
const keys = { keys: [publicJwk('test-local'), publicJwk('production-1')] };
const kids = { test: 'test-local', production: 'production-1' };
function signedHeaders(method, url, buyer, body, kid, created = Math.floor(Date.now() / 1000), signingKid = kid) {
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  const params = `("@method" "@authority" "@path" "content-digest" "x-r4a-buyer");created=${created};` +
    `expires=${created + 300};keyid="${kid}";alg="ed25519";tag="r4a-contract"`;
  const base = [`"@method": ${method}`, `"@authority": ${url.host}`, `"@path": ${url.pathname}`,
    `"content-digest": ${digest}`, `"x-r4a-buyer": ${buyer}`, `"@signature-params": ${params}`].join('\n');
  const signature = sign(null, Buffer.from(base), privateKeys[signingKid]).toString('base64');
  return { 'X-R4A-Buyer': buyer, 'Content-Digest': digest, 'Signature-Input': `r4a=${params}`, Signature: `r4a=:${signature}:` };
}
function request(path, data, options = {}) {
  const method = options.method ?? (data === undefined ? 'GET' : 'POST');
  const body = options.body ?? (data === undefined ? '' : JSON.stringify(data));
  const buyer = options.buyer ?? buyerId;
  const url = new URL(path, options.origin ?? origin);
  const kid = options.kid ?? kids[options.environment ?? 'test'];
  const signedUrl = new URL(url.pathname, options.signedOrigin ?? url.origin);
  return new Request(url, { method, ...(method !== 'GET' ? { body } : {}), headers: {
    ...signedHeaders(method, signedUrl, buyer, body, kid, options.created, options.signingKid ?? kid),
    'Content-Type': 'application/json', ...options.headers,
  } });
}
function setup(options = {}) {
  const accounts = new Map();
  let calls = 0;
  const handler = createVendorHandler({ origin, keys, ...options, handlers: {
    async trial(_, input) { calls++; return { output: input, note: 'Sample result' }; },
    async account(buyer, email) {
      calls++;
      const account_id = `account_${buyer.environment}_${buyer.buyerId}`;
      const created = !accounts.has(account_id);
      if (created) accounts.set(account_id, { owner: buyer, email, active: false, usage: 0 });
      return { account_id, created };
    },
    async authorizeAccount(buyer, id) {
      const row = accounts.get(id);
      return row?.owner.buyerId === buyer.buyerId && row?.owner.environment === buyer.environment;
    },
    async lookup(buyer) {
      const id = `account_${buyer.environment}_${buyer.buyerId}`;
      return accounts.has(id) ? { account_id: id } : null;
    },
    async checkout(_, id, offer) {
      calls++;
      if (offer !== 'free') throw new VendorError(402, { status: 'payment_required', amount_eur: 10 });
      accounts.get(id).active = true;
      return { status: 'active', offer: 'free' };
    },
    async access(_, id) {
      calls++;
      const row = accounts.get(id);
      if (!row.active) throw new VendorError(409, 'No active plan');
      return { api_key: 'fixture-only-api-key', offer: 'free', usage: row.usage };
    },
    async use(_, id, input) {
      calls++;
      const row = accounts.get(id);
      if (!row.active) throw new VendorError(409, 'No active plan');
      return { output: input, usage: ++row.usage };
    },
    ...options.handlers,
  } });
  return { handler, calls: () => calls };
}

test('verifies the shared r4a/Ibanly/Rose signature vector without reserializing JSON', async () => {
  const body = '{"input":{"iban":"GB82WEST12345698765432"}}';
  const req = new Request('https://ibanly.app/r4a/trial', { method: 'POST', body, headers: {
    'X-R4A-Buyer': buyerId,
    'Content-Digest': 'sha-256=:4O8fXjgbfw4w3UPKOSjtkQyaeKw6dT4fSIk6VtG32g8=:',
    'Signature-Input': 'r4a=("@method" "@authority" "@path" "content-digest" "x-r4a-buyer");created=1790000000;' +
      'expires=1790000300;keyid="test-vector";alg="ed25519";tag="r4a-contract"',
    Signature: 'r4a=:CY5VOg/7xRPEgfaw1uqxsmR2+LiXc9QX8iH/jMgBhxfl894b/PMK+QnKCNXP9Yovlh/5c3lRS0saJQuvJTOrCw==:',
  } });
  const vector = { keys: [{ ...publicJwk('test-local'), kid: 'test-vector' }] };
  assert.deepEqual(await verifyRequest(req, new TextEncoder().encode(body), vector, 1790000000000),
    { buyerId, environment: 'test' });
});

test('a production-key call gets the production environment', async () => {
  const req = request('/r4a/trial', { input: {} }, { environment: 'production' });
  assert.deepEqual(await verifyRequest(req, new Uint8Array(await req.clone().arrayBuffer()), keys),
    { buyerId, environment: 'production' });
});

test('routes the full signed-in funnel with idempotent creation and accumulated usage', async () => {
  const { handler } = setup();
  assert.equal((await handler(request('/r4a/trial', { input: { value: 1 } }))).status, 200);
  const first = await handler(request('/r4a/accounts', { email: 'person@example.com' }));
  assert.equal(first.status, 201);
  const { account_id: id } = await first.json();
  const again = await handler(request('/r4a/accounts', { email: 'changed@example.com' }));
  assert.equal(again.status, 200);
  assert.equal((await again.json()).account_id, id);
  assert.equal((await handler(request(`/r4a/accounts/${id}/access`))).status, 409);
  assert.equal((await handler(request(`/r4a/accounts/${id}/checkout`, { offer_id: 'paid' }))).status, 402);
  assert.equal((await handler(request(`/r4a/accounts/${id}/checkout`, { offer_id: 'free' }))).status, 200);
  assert.equal((await handler(request(`/r4a/accounts/${id}/use`, { input: { value: 2 } }))).status, 200);
  const access = await handler(request(`/r4a/accounts/${id}/access`));
  assert.equal((await access.json()).usage, 1);
  assert.equal(access.headers.get('cache-control'), 'no-store');
});

test('passes provisioning input and returns only the public account fields, including next', async () => {
  const received = [];
  const { handler } = setup({ handlers: { account: async (...args) => {
    received.push(args);
    return { account_id: 'account_1', created: received.length === 1, next: 'Finish setup', secret: 'private' };
  } } });
  for (const input of [{ company_name: 'Example', website_url: 'https://example.com' }, undefined]) {
    const response = await handler(request('/r4a/accounts', { email: 'person@example.com', input }));
    assert.equal(response.status, received.length === 1 ? 201 : 200);
    assert.deepEqual(received.at(-1), [{ buyerId, environment: 'test' }, 'person@example.com', input]);
    assert.deepEqual(await response.json(), { account_id: 'account_1', next: 'Finish setup' });
  }
});

test('rejects malformed provisioning input before calling product logic', async () => {
  const { handler, calls } = setup();
  for (const input of [null, [], '', 0, false]) {
    assert.equal((await handler(request('/r4a/accounts', { email: 'person@example.com', input }))).status, 422);
  }
  assert.equal(calls(), 0);
});

test('accepts Rose checkout with an explicit null payment token', async () => {
  let payment;
  const { handler } = setup({ handlers: { checkout: async (_, _id, _offer, token) => {
    payment = token;
    return { status: 'active' };
  } } });
  const { account_id: id } = await (await handler(request('/r4a/accounts', { email: 'person@example.com' }))).json();
  assert.equal((await handler(request(`/r4a/accounts/${id}/checkout`, { offer_id: 'free', payment_token: null }))).status, 200);
  assert.equal(payment, undefined);
  for (const token of [0, false, {}, '', []]) {
    assert.equal((await handler(request(`/r4a/accounts/${id}/checkout`, { offer_id: 'free', payment_token: token }))).status, 422);
  }
});

for (const action of ['checkout', 'access', 'use']) {
  for (const intruder of [{ buyer: otherBuyer }, { environment: 'production' }]) {
    test(`denies ${action} for ${JSON.stringify(intruder)} before product handler`, async () => {
      const { handler, calls } = setup();
      const { account_id: id } = await (await handler(request('/r4a/accounts', { email: 'person@example.com' }))).json();
      const data = action === 'access' ? undefined : action === 'checkout' ? { offer_id: 'free' } : { input: {} };
      assert.equal((await handler(request(`/r4a/accounts/${id}/${action}`, data, intruder))).status, 403);
      assert.equal(calls(), 1);
    });
  }
}

const attacks = [
  ['unsigned', () => new Request(`${origin}/r4a/trial`, { method: 'POST', body: '{"input":{}}' }), 401],
  ['bad signature', () => request('/r4a/trial', { input: {} }, { headers: { Signature: `r4a=:${'A'.repeat(86)}==:` } }), 401],
  ['stale', () => request('/r4a/trial', { input: {} }, { created: Math.floor(Date.now() / 1000) - 301 }), 401],
  ['future', () => request('/r4a/trial', { input: {} }, { created: Math.floor(Date.now() / 1000) + 301 }), 401],
  ['signed for another vendor', () => request('/r4a/trial', { input: {} }, { signedOrigin: 'https://other.example' }), 401],
  ['unknown key', () => request('/r4a/trial', { input: {} }, { kid: 'test-unknown', signingKid: 'test-local' }), 401],
  ['test key as production', () => request('/r4a/trial', { input: {} }, { kid: 'production-1', signingKid: 'test-local' }), 401],
  ['wrong origin', () => request('/r4a/trial', { input: {} }, { origin: 'https://other.example' }), 404],
  ['unsigned query', () => request('/r4a/trial?privilege=admin', { input: {} }), 404],
  ['invalid buyer', () => request('/r4a/trial', { input: {} }, { buyer: 'not-a-uuid' }), 401],
  ['wrong method', () => request('/r4a/trial'), 404],
  ['malformed JSON', () => request('/r4a/trial', null, { body: '{' }), 422],
  ['array body', () => request('/r4a/trial', []), 422],
  ['missing input', () => request('/r4a/trial', {}), 422],
  ['encoded path', () => request('/r4a/%61ccounts', { email: 'person@example.com' }), 404],
];
for (const [name, make, expected] of attacks) {
  test(`rejects ${name} without calling product logic`, async () => {
    const { handler, calls } = setup();
    assert.equal((await handler(make())).status, expected);
    assert.equal(calls(), 0);
  });
}

test('rejects changes to buyer, endpoint and exact raw bytes', async () => {
  for (const change of ['buyer', 'path', 'bytes']) {
    const { handler, calls } = setup();
    const original = request('/r4a/trial', { input: {} });
    const headers = new Headers(original.headers);
    if (change === 'buyer') headers.set('X-R4A-Buyer', otherBuyer);
    const req = new Request(`${origin}${change === 'path' ? '/r4a/accounts' : '/r4a/trial'}`, {
      method: 'POST', headers, body: change === 'bytes' ? '{ "input": {} }' : '{"input":{}}',
    });
    assert.equal((await handler(req)).status, 401);
    assert.equal(calls(), 0);
  }
});

test('enforces the byte limit on streamed input without content-length', async () => {
  const { handler, calls } = setup({ maxBodyBytes: 10 });
  assert.equal((await handler(request('/r4a/trial', { input: { long: 'x'.repeat(50) } }))).status, 413);
  assert.equal(calls(), 0);
});

test('fails closed without any Rose key and refuses a non-HTTPS origin', async () => {
  assert.equal((await setup({ keys: { keys: [] } }).handler(request('/r4a/trial', { input: {} }))).status, 503);
  assert.throws(() => setup({ origin: 'http://vendor.example' }), /HTTPS/);
});

test('hides unexpected product exceptions from Rose and logs them for the vendor', async t => {
  const errors = t.mock.method(console, 'error', () => {});
  const failure = new Error('secret-database-password');
  const handler = createVendorHandler({ origin, keys, handlers: {
    async trial() { throw failure; },
  } });
  const response = await handler(request('/r4a/trial', { input: {} }));
  assert.equal(response.status, 500);
  assert.equal((await response.text()).includes('secret-database-password'), false);
  assert.deepEqual(errors.mock.calls.map(call => call.arguments), [['Rose vendor request failed', failure]]);
});

test('a truthy non-boolean authorization result does not grant access', async () => {
  const { handler, calls } = setup({ handlers: { authorizeAccount: async () => ({ allowed: false }) } });
  const { account_id: id } = await (await handler(request('/r4a/accounts', { email: 'person@example.com' }))).json();
  assert.equal((await handler(request(`/r4a/accounts/${id}/access`))).status, 403);
  assert.equal(calls(), 1);
});

test('signed account lookup reuses the existing buyer mapping without provisioning', async () => {
  const { handler, calls } = setup();
  assert.equal((await handler(request('/r4a/account'))).status, 404);
  const { account_id } = await (await handler(request('/r4a/accounts', { email: 'person@example.com' }))).json();
  const lookup = await handler(request('/r4a/account'));
  assert.equal(lookup.status, 200);
  assert.deepEqual(await lookup.json(), { account_id });
  assert.equal(calls(), 1);
  assert.equal((await handler(request('/r4a/account', undefined, { buyer: otherBuyer }))).status, 404);
});

test('missing lookup fails closed rather than advertising that no account exists', async () => {
  const { handler } = setup({ handlers: { lookup: undefined } });
  assert.equal((await handler(request('/r4a/account'))).status, 503);
  assert.equal((await handler(new Request(`${origin}/r4a/account`))).status, 401);
});

test('lookup verifies ownership even if the product returns the wrong account', async () => {
  const { handler } = setup({ handlers: { lookup: async () => ({ account_id: `account_test_${buyerId}` }) } });
  await handler(request('/r4a/accounts', { email: 'person@example.com' }));
  assert.equal((await handler(request('/r4a/account', undefined, { buyer: otherBuyer }))).status, 403);
});

test('lookup exposes only the account ID even if the product returns its internal record', async () => {
  const account_id = `account_test_${buyerId}`;
  const { handler } = setup({ handlers: { lookup: async () => ({ account_id, email: 'private@example.com', api_key: 'private-fixture' }) } });
  await handler(request('/r4a/accounts', { email: 'person@example.com' }));
  assert.deepEqual(await (await handler(request('/r4a/account'))).json(), { account_id });
});

test('concurrent requests start one fetch of the published key directories, without awaiting it', async () => {
  const original = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async (url) => {
    fetches++;
    await new Promise(resolve => setTimeout(resolve, 10));
    const body = String(url).includes('mcp-test') ? { keys: [publicJwk('test-local')] } : { keys: [] };
    return Response.json(body);
  };
  const verify = async req => verifyRequest(req, new Uint8Array(await req.clone().arrayBuffer()))
    .catch(error => error);
  try {
    // Cold start: one request fetches; the others get a retryable 503 rather than awaiting a
    // promise another request owns, which can hang on Cloudflare Workers.
    const results = await Promise.all(Array.from({ length: 20 }, () => verify(request('/r4a/trial', { input: {} }))));
    assert.equal(fetches, 2); // one per directory, not one per request
    assert.equal(results.filter(r => r.environment === 'test').length, 1);
    assert.ok(results.filter(r => r instanceof VendorError).every(r => r.status === 503));
    // Once fetched, every request verifies from the cache.
    const cached = await Promise.all(Array.from({ length: 5 }, () => verify(request('/r4a/trial', { input: {} }))));
    assert.ok(cached.every(r => r.environment === 'test'));
    assert.equal(fetches, 2);
  } finally { globalThis.fetch = original; }
});

test('a failed key-directory fetch is logged, and the last keys keep verifying', async () => {
  const [originalFetch, originalError] = [globalThis.fetch, console.error];
  const errors = [];
  console.error = (...args) => errors.push(args.join(' '));
  const verifyAt = async at => {
    const req = request('/r4a/trial', { input: {} }, { created: Math.floor(at / 1000) });
    return verifyRequest(req, new Uint8Array(await req.clone().arrayBuffer()), undefined, at);
  };
  try {
    // Past every cache TTL so each call refreshes: once with Rose up, then with Rose down.
    const up = Date.now() + 3 * 3600_000, down = up + 2 * 3600_000;
    globalThis.fetch = async url => Response.json(String(url).includes('mcp-test') ? { keys: [publicJwk('test-local')] } : { keys: [] });
    assert.equal((await verifyAt(up)).environment, 'test');
    assert.deepEqual(errors, []);
    globalThis.fetch = async () => { throw new Error('network down'); };
    assert.equal((await verifyAt(down)).environment, 'test');
    assert.deepEqual(errors, [
      'Rose key directory unavailable: https://mcp.userose.ai/.well-known/r4a-keys.json (network down)',
      'Rose key directory unavailable: https://mcp-test.userose.ai/.well-known/r4a-keys.json (network down)',
    ]);
  } finally { [globalThis.fetch, console.error] = [originalFetch, originalError]; }
});

test('serves each operation on exactly one method and path', async () => {
  const { handler, calls } = setup();
  const { account_id: id } = await (await handler(request('/r4a/accounts', { email: 'person@example.com' }))).json();
  const routes = [['POST', '/r4a/trial'], ['POST', '/r4a/accounts'], ['GET', '/r4a/account'],
    ['POST', `/r4a/accounts/${id}/checkout`], ['GET', `/r4a/accounts/${id}/access`], ['POST', `/r4a/accounts/${id}/use`]];
  for (const [method, path] of routes) {
    const wrong = method === 'GET' ? {} : undefined; // a body makes the request a POST
    assert.equal((await handler(request(path, wrong))).status, 404, `${method === 'GET' ? 'POST' : 'GET'} ${path}`);
  }
  for (const path of ['/r4a', '/r4a/', '/r4a/accounts/', `/r4a/accounts/${id}/delete`, `/r4a/accounts/${'a'.repeat(129)}/use`, '/other/trial']) {
    assert.equal((await handler(request(path, { input: {} }))).status, 404, path);
  }
  assert.equal(calls(), 1);
});

test('mounts at a custom base path and validates its configuration', async () => {
  const { handler } = setup({ basePath: '/rose' });
  assert.equal((await handler(request('/rose/trial', { input: {} }))).status, 200);
  assert.equal((await handler(request('/r4a/trial', { input: {} }))).status, 404);
  for (const basePath of ['', 'r4a', '/r4a/', '/r4a?x']) assert.throws(() => setup({ basePath }), /basePath/);
  for (const maxBodyBytes of [0, 1.5, 1048577]) assert.throws(() => setup({ maxBodyBytes }), /maxBodyBytes/);
});

test('refuses a declared Content-Length over the limit before reading the body', async () => {
  const { handler, calls } = setup({ maxBodyBytes: 10 });
  assert.equal((await handler(request('/r4a/trial', { input: {} }, { headers: { 'Content-Length': '11' } }))).status, 413);
  assert.equal(calls(), 0);
});

test('VendorError only accepts the contract statuses', () => {
  assert.equal(new VendorError(402, { status: 'payment_required' }).status, 402);
  for (const status of [200, 500, 418]) assert.throws(() => new VendorError(status, 'x'), /Unsupported/);
});

test('a key directory only speaks for its own environment', async () => {
  const original = globalThis.fetch;
  // The production directory also lists the test key: it must neither verify nor become production.
  globalThis.fetch = async url => Response.json(String(url).includes('mcp-test')
    ? { keys: [] } : { keys: [publicJwk('test-local'), publicJwk('production-1')] });
  // Past every cache the tests above left in this process, so this call refreshes the directories.
  const at = Date.now() + 10 * 3600_000;
  const verifyAt = async environment => {
    const req = request('/r4a/trial', { input: {} }, { environment, created: Math.floor(at / 1000) });
    return verifyRequest(req, new Uint8Array(await req.clone().arrayBuffer()), undefined, at).catch(error => error);
  };
  try {
    assert.equal((await verifyAt('production')).environment, 'production');
    assert.equal((await verifyAt('test')).status, 401);
  } finally { globalThis.fetch = original; }
});
