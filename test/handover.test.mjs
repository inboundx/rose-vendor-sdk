import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createHandoverVerifier, REVOKED_EVENT, VendorError } from '@userose/vendor-sdk';

const keys = await generateKeyPair('ES256');
const publicKey = { ...await exportJWK(keys.publicKey), kid: 'fixture-broker-key' };
const config = { issuer: 'https://identity.example', audience: 'https://vendor.example',
  environment: 'test', clientId: 'vendor-client', allowedSources: ['email', 'google'], jwks: { keys: [publicKey] } };
const buyerId = '3f2a8c1e-5b7d-4e9a-9c1f-2d6b8e4a7c10';
const expected = { registrationId: 'trial_123', userCode: '123456' };
const verifier = createHandoverVerifier(config);
// `overrides` may be a function of the proof's own `now`, so time offsets never straddle a second.
async function proof(overrides = {}, typ = 'oauth-id-jag+jwt', signingKey = keys.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  if (typeof overrides === 'function') overrides = overrides(now);
  return new SignJWT({ iss: config.issuer, aud: config.audience, sub: buyerId, iat: now,
    exp: now + 300, jti: crypto.randomUUID(), environment: 'test', client_id: config.clientId,
    email: 'person@example.com', email_verified: true, identity_source: 'google', auth_time: now,
    registration_id: expected.registrationId, user_code: expected.userCode, ...overrides })
    .setProtectedHeader({ alg: 'ES256', typ, kid: 'fixture-broker-key' }).sign(signingKey);
}

test('returns verified claims bound to the stored registration and code', async () => {
  const claim = await verifier.verifyClaim(await proof(), expected);
  assert.equal(claim.buyerId, buyerId);
  assert.equal(claim.environment, 'test');
  assert.equal(claim.registrationId, expected.registrationId);
  assert.equal(claim.email, 'person@example.com');
});

const invalid = [
  ['issuer', { iss: 'https://attacker.example' }],
  ['audience', { aud: 'https://other.example' }],
  ['multiple audiences', { aud: [config.audience, 'https://other.example'] }],
  ['environment', { environment: 'production' }],
  ['client', { client_id: 'other-client' }],
  ['unverified email', { email_verified: false }],
  ['invalid email', { email: 'invalid' }],
  ['disallowed source', { identity_source: 'unknown' }],
  ['missing auth time', { auth_time: undefined }],
  ['stale auth', now => ({ auth_time: now - 3601 })],
  ['future auth', now => ({ auth_time: now + 60 })],
  ['fractional auth time', { auth_time: 0.5 }],
  ['expired proof', now => ({ exp: now - 1 })],
  ['long-lived proof', now => ({ exp: now + 301 })],
  ['future issuance', now => ({ iat: now + 60 })],
  ['missing replay id', { jti: undefined }],
  ['invalid buyer', { sub: 'not-a-uuid' }],
  ['wrong registration', { registration_id: 'other' }],
  ['wrong code', { user_code: '654321' }],
];
for (const [name, overrides] of invalid) {
  test(`rejects ${name}`, async () => {
    await assert.rejects(verifier.verifyClaim(await proof(overrides), expected), VendorError);
  });
}

test('rejects the wrong JWT type, forged signatures and a malformed expected code', async () => {
  await assert.rejects(verifier.verifyClaim(await proof({}, 'secevent+jwt'), expected), VendorError);
  const forged = await generateKeyPair('ES256');
  await assert.rejects(verifier.verifyClaim(await proof({}, 'oauth-id-jag+jwt', forged.privateKey), expected), VendorError);
  await assert.rejects(verifier.verifyClaim(await proof(), { ...expected, userCode: '' }), VendorError);
});

test('verifies signed revocation events and rejects unrelated event types', async () => {
  const token = await proof({ events: { [REVOKED_EVENT]: {} } }, 'secevent+jwt');
  const event = await verifier.verifyRevocation(token);
  assert.equal(event.buyerId, buyerId);
  assert.equal(event.environment, 'test');
  await assert.rejects(verifier.verifyRevocation(await proof({}, 'secevent+jwt')), VendorError);
  await assert.rejects(verifier.verifyRevocation(await proof({ events: { other: {} } }, 'secevent+jwt')), VendorError);
  await assert.rejects(verifier.verifyRevocation(await proof({ events: { [REVOKED_EVENT]: {}, other: {} } }, 'secevent+jwt')), VendorError);
  await assert.rejects(verifier.verifyRevocation(await proof({ events: { [REVOKED_EVENT]: {} } })), VendorError);
});

test('rejects insecure configuration and private signing keys', () => {
  assert.throws(() => createHandoverVerifier({ ...config, issuer: 'http://identity.example' }));
  assert.throws(() => createHandoverVerifier({ ...config, allowedSources: [] }));
  assert.throws(() => createHandoverVerifier({ ...config, jwks: { keys: [{ ...publicKey, d: 'private' }] } }));
  assert.throws(() => createHandoverVerifier({ ...config, jwks: { keys: [{ kty: 'oct', k: 'secret' }] } }));
});

test('captures trust configuration rather than following later caller mutation', async () => {
  const mutable = structuredClone(config);
  const fixed = createHandoverVerifier(mutable);
  mutable.issuer = 'https://other.example';
  mutable.environment = 'production';
  mutable.allowedSources.length = 0;
  mutable.jwks.keys.length = 0;
  assert.equal((await fixed.verifyClaim(await proof(), expected)).environment, 'test');
});
