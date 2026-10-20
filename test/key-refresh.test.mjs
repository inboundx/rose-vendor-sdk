import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';

const pair = generateKeyPairSync('ed25519');
const buyerId = '3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10';
const jwks = (...kids) => ({ keys: kids.map(kid => ({ ...pair.publicKey.export({ format: 'jwk' }), kid })) });
const body = new TextEncoder().encode('{"input":{}}');
function request(kid, now) {
  const created = Math.floor(now / 1000);
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  const params = `("@method" "@authority" "@path" "content-digest" "x-r4a-buyer");created=${created};expires=${created + 300};keyid="${kid}";alg="ed25519";tag="r4a-contract"`;
  const base = [`"@method": POST`, `"@authority": vendor.example`, `"@path": /r4a/trial`,
    `"content-digest": ${digest}`, `"x-r4a-buyer": ${buyerId}`, `"@signature-params": ${params}`].join('\n');
  return new Request('https://vendor.example/r4a/trial', { method: 'POST', body, headers: {
    'X-R4A-Buyer': buyerId, 'Content-Digest': digest, 'Signature-Input': `r4a=${params}`,
    Signature: `r4a=:${sign(null, Buffer.from(base), pair.privateKey).toString('base64')}:`,
  } });
}
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
async function freshVerifier() {
  // Each scenario gets a cold cache, independent of test order.
  return (await import(`../dist/signature.js?${crypto.randomUUID()}`)).verifyRequest;
}

for (const stage of ['headers', 'body']) {
  test(`times out stalled directory ${stage} and still verifies the other environment`, async t => {
    const verify = await freshVerifier();
    const started = deferred();
    const at = Date.now();
    let signal;
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const errors = t.mock.method(console, 'error', () => {});
    t.mock.method(globalThis, 'fetch', async (url, options) => {
      if (String(url).includes('mcp-test')) return Response.json(jwks('test-local'));
      signal = options.signal;
      const stall = () => new Promise((_, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        started.resolve();
      });
      return stage === 'headers' ? stall() : { ok: true, json: stall };
    });
    const pending = verify(request('test-local', at), body, undefined, at);
    await started.promise;
    t.mock.timers.tick(9_999);
    assert.equal(signal.aborted, false);
    t.mock.timers.tick(1);
    assert.deepEqual(await pending, { buyerId, environment: 'test' });
    assert.equal(signal.aborted, true);
    const directoryErrors = errors.mock.calls.filter(call =>
      String(call.arguments[0]).startsWith('Rose key directory unavailable:'));
    assert.equal(directoryErrors.length, 1);
  });
}

test('a directory timeout retains cached keys and clears timers after successful fetches', async t => {
  const verify = await freshVerifier();
  const at = Date.now();
  const signals = [];
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(console, 'error', () => {});
  const fetch = t.mock.method(globalThis, 'fetch', async (url, { signal }) => {
    signals.push(signal);
    return Response.json(String(url).includes('mcp-test') ? jwks() : jwks('production-old'));
  });
  await verify(request('production-old', at), body, undefined, at);
  t.mock.timers.tick(10_000);
  assert.ok(signals.every(signal => !signal.aborted));
  const started = deferred();
  fetch.mock.mockImplementation(async (url, { signal }) => {
    if (String(url).includes('mcp-test')) return Response.json(jwks());
    return new Promise((_, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      started.resolve();
    });
  });
  const later = at + 3_600_001;
  const pending = verify(request('production-old', later), body, undefined, later);
  await started.promise;
  t.mock.timers.tick(10_000);
  assert.equal((await pending).environment, 'production');
});

test('a late refresh cannot replace a newer key set', async t => {
  const verify = await freshVerifier();
  const at = Date.now();
  const oldResponse = deferred();
  let fetches = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    if (String(url).includes('mcp-test')) return Response.json(jwks());
    if (++fetches === 1) return oldResponse.promise;
    return Response.json(jwks('production-new'));
  });
  const old = verify(request('production-old', at), body, undefined, at).catch(error => error);
  // Advance the lease clock without completing the old request, as after cancellation.
  const later = at + 31_000;
  assert.equal((await verify(request('production-new', later), body, undefined, later)).environment, 'production');
  oldResponse.resolve(Response.json(jwks('production-old')));
  await old;
  assert.equal((await verify(request('production-new', later + 1), body, undefined, later + 1)).environment, 'production');
  await assert.rejects(verify(request('production-old', later + 1), body, undefined, later + 1), error => error.status === 401);
  assert.equal(fetches, 2);
});

test('a superseded refresh cannot clear the marker of a pending refresh', async t => {
  const verify = await freshVerifier();
  const at = Date.now();
  const oldResponse = deferred();
  const newResponse = deferred();
  let fetches = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    if (String(url).includes('mcp-test')) return Response.json(jwks());
    return ++fetches === 1 ? oldResponse.promise : newResponse.promise;
  });
  const old = verify(request('production-old', at), body, undefined, at);
  const later = at + 31_000;
  const newer = verify(request('production-new', later), body, undefined, later);
  oldResponse.resolve(Response.json(jwks('production-old')));
  await old;
  // This must reject immediately, without starting or awaiting another request's fetch.
  const concurrent = verify(request('production-new', later + 1), body, undefined, later + 1);
  await assert.rejects(concurrent, error => error.status === 503);
  assert.equal(fetches, 2);
  newResponse.resolve(Response.json(jwks('production-new')));
  assert.equal((await newer).environment, 'production');
});

test('an unreadable directory on a cold start is retryable for its environment only', async t => {
  const verify = await freshVerifier();
  const at = Date.now();
  t.mock.method(console, 'error', () => {});
  const fetch = t.mock.method(globalThis, 'fetch', async url => {
    if (String(url).includes('mcp-test')) return Response.json(jwks('test-local'));
    throw new Error('network down');
  });
  // The production directory could not be read, so a production call gets a 503 Rose retries, not a 401.
  await assert.rejects(verify(request('production-1', at), body, undefined, at), error => error.status === 503);
  assert.equal((await verify(request('test-local', at), body, undefined, at)).environment, 'test');
  // Once the directory answers, the next unknown-key refetch (a minute later) picks the key up.
  fetch.mock.mockImplementation(async url => Response.json(String(url).includes('mcp-test') ? jwks('test-local') : jwks('production-1')));
  const later = at + 60_000;
  assert.equal((await verify(request('production-1', later), body, undefined, later)).environment, 'production');
});

test('a malformed key is skipped without discarding the rest of its directory', async t => {
  const verify = await freshVerifier();
  const at = Date.now();
  const errors = t.mock.method(console, 'error', () => {});
  t.mock.method(globalThis, 'fetch', async url => Response.json(String(url).includes('mcp-test')
    ? { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'bad', kid: 'test-broken' }, ...jwks('test-local').keys] } : jwks()));
  assert.equal((await verify(request('test-local', at), body, undefined, at)).environment, 'test');
  assert.deepEqual(errors.mock.calls.map(call => call.arguments[0]),
    ['Rose key ignored: test-broken is not a valid Ed25519 public key']);
});
