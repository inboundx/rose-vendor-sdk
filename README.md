# Rose vendor SDK

Server-side TypeScript SDK for Rose for Agents. It routes Rose's signed-in vendor
requests, authenticates buyers and environments, and verifies Handover identity proofs
and signed revocation events. Uses standard `Request`, `Response` and Web Crypto APIs.

## Install

Use Node.js 22 or later with ESM, or a Web Crypto-capable server runtime. Install a release
tag in your server project; npm builds it on install:

```bash
npm install github:inboundx/rose-vendor-sdk#v0.1.2
```

The package includes compiled JavaScript, TypeScript declarations and an integration
example. It is not published to the npm registry yet.

## Connect your product

```typescript
import { createVendorHandler, type VendorHandlers } from '@userose/vendor-sdk';

export function connectProduct(origin: string, handlers: VendorHandlers) {
  return createVendorHandler({ origin, handlers, basePath: '/r4a' });
}
```

Call `connectProduct('https://api.example.com', handlers)` and mount the returned handler at
`/r4a/*` in your server's Fetch-compatible route. Rose's base URL for this integration is
`https://api.example.com/r4a`. Use the external request
URL when adapting from Node or a reverse proxy; do not trust arbitrary forwarded hosts.
Never install this SDK in browser code.

Your `handlers` implement these operations:

| Handler | Responsibility |
|---|---|
| `trial(buyer, input)` | Return `{output, note}` for a limited product action. |
| `account(buyer, email)` | Return `{account_id, created}`. Provision idempotently using **environment + buyerId**, without merging by email. |
| `lookup(buyer)` | For Handover, return `{account_id}` for an existing owned account or `null` when none exists; include accounts claimed from trials. |
| `authorizeAccount(buyer, accountId)` | Check the stored owner and environment. Return false for unknown or inaccessible accounts. |
| `checkout(buyer, accountId, offerId, paymentToken?)` | Apply your offer/payment rules and return the checkout result. |
| `access(buyer, accountId)` | Return `{api_key, offer, usage}` for permitted access. |
| `use(buyer, accountId, input)` | Enforce permissions/quotas and return `{output, usage}`. |

The SDK calls `authorizeAccount` before checkout, access and use. If ownership or access
can change concurrently, recheck it inside the transaction that performs the product
operation. Product operations, retries and payment idempotency remain your responsibility.

Handover requires `GET /r4a/account`, supplied by `lookup`, so Rose reuses an existing
account before starting another trial. The SDK authenticates the lookup and checks the
returned account's ownership. If this optional handler is absent, lookup returns 503
rather than treating an unsupported route as an absent account.

Throw `new VendorError(409, 'No active plan')` for an intentional product failure. For
payment-required results, use `new VendorError(402, {status: 'payment_required', amount_eur: 10})`.
Unexpected exceptions return a generic 500 without exposing their message.

There is no secret to store. Rose signs each request with its own Ed25519 key (HTTP Message
Signatures, RFC 9421) and the SDK checks it against Rose's published public keys, fetched
from `https://mcp.userose.ai/.well-known/r4a-keys.json` (production) and
`https://mcp-test.userose.ai/.well-known/r4a-keys.json` (test) and cached for an hour. The
signature covers the exact raw body, **your** host (from `origin`), method, path and buyer,
so a request Rose signed for another vendor is refused here. The key that verifies names the
environment, so a test call never acts on a production account. For local development and
tests, pass `keys` (a JWKS) to trust a development key instead.
The acceptance window is 300 seconds; product mutations must handle retries within it.
Queries are refused because the signing contract does not cover them. Bodies default to
64 KiB, configurable with `maxBodyBytes` up to 1 MiB. Account identifiers must contain
1–128 letters, digits, underscores or hyphens.

## Handover

Rose provides the issuer, audience, client identifier, environment, accepted identity
sources and **public** signing keys for your integration:

```typescript
import { createHandoverVerifier } from '@userose/vendor-sdk';

const handover = createHandoverVerifier(roseTrustConfiguration);
const claim = await handover.verifyClaim(identityAssertion, {
  registrationId: trial.id,
  userCode: trial.userCode,
});
await yourDatabase.claimTrialAtomically(claim);

const event = await handover.verifyRevocation(signedEvent);
await yourDatabase.revokeBuyerAtomically(event);
```

`trial` must be loaded from your database. Do not take the expected registration or code
from unverified JWT fields or the requester's supplied values. Verification pins ES256,
the JWT type, issuer, vendor audience and environment. Claims also require the configured
client, verified email, allowed source and authentication within one hour.

The verifier checks authenticity; it does not store accounts or consume proofs. Your
database transactions must:

- Reject a reused `proofId` and a proof whose `expiresAt` has passed at commit time.
- Check the trial's current code, expiry, owner and account conflicts; preserve the account
  and usage, then rotate trial credentials and enable the original assistant's resume.
- Reject `authenticatedAt <=` the buyer's persisted revocation cutoff. Perform this
  check in the same transaction as claim to prevent a claim/revocation race.
- Process `eventId` idempotently, increase the cutoff to at least `issuedAt` (never lower
  it for out-of-order events), and invalidate **all** delegated credentials and resume
  secrets for that buyer and environment before acknowledging revocation.

Both proof expiry and event issuance use Unix seconds. Handover trial creation, consent
pages, credential issuance, resume/polling, expiry and provider-connection handling are
part of your product integration; this SDK provides the verification layer. Rose
coordinates the full contract and rollout with your team. Rotate configured public keys
by creating a new verifier with the updated trusted key set.

## Develop the SDK

From the repository root:

```bash
npm ci
npm run build
npm test
node scripts/smoke-package.mjs
```

The smoke script packs the SDK, installs it in a temporary consumer app, checks its
declarations and exercises signed account operations and Handover over loopback HTTP.
It removes its temporary app and closes its own server. To retain the archive, pass an
absolute output directory as the first argument.

## License

Apache License 2.0. See [LICENSE](LICENSE).
