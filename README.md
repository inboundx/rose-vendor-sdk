# Rose vendor SDK

This SDK lets a software company (a **vendor**) sell its product to AI assistants through
Rose for Agents. You install it on your server; it handles the security and the HTTP side,
and you plug in your own accounts, plans and product.

## Context: Rose and Rose for Agents

**Rose** ([userose.ai](https://userose.ai)) builds AI sales agents for B2B software
companies. Its first product, Rose for Websites, puts an agent on a company's website that
answers visitors' questions about the product, pricing and documentation.

**Rose for Agents** sells to AI assistants instead of people. More and more buyers ask an
assistant (Claude, ChatGPT, Cursor, Codex…) to do the work for them: "find me an API that
validates IBANs, try it, and sign me up". Rose for Agents is a connector (an
[MCP server](https://modelcontextprotocol.io)) that the buyer adds to their assistant
once, and signs in to once with their Google account. Through it, the assistant can reach
every company that works with Rose:

1. **Evaluate:** ask the company's Rose agent questions, compare offers.
2. **Try:** run the product on a real input, with no account yet.
3. **Sign up:** create an account for the buyer.
4. **Pay:** pick a plan; the buyer approves any payment.
5. **Use:** get an API key, or use the product through Rose.

Rose answers step 1 itself. Steps 2 to 5 need the vendor's own systems: only you can create
an account at your company or issue your API keys. So Rose calls six HTTP endpoints that
**you** host, under one base path (`/r4a` by default), and this SDK is how you host them:

| Step | Rose calls | To |
|---|---|---|
| 2. Try | `POST /r4a/trial` | run the product on the assistant's input, with no account |
| 3. Sign up | `GET /r4a/account` | find the buyer's existing account, if any (optional today) |
| 3. Sign up | `POST /r4a/accounts` | create the buyer's account, or return the existing one |
| 4. Pay | `POST /r4a/accounts/{id}/checkout` | choose a plan, and pay if it is not free |
| 5. Use | `GET /r4a/accounts/{id}/access` | get the account's API key, plan and usage |
| 5. Use | `POST /r4a/accounts/{id}/use` | run the product through the account |

```text
Buyer ──asks──▶ AI assistant ──MCP tools──▶ Rose for Agents ──signed HTTPS──▶ your server
                (Claude, ChatGPT…)           (hosted by Rose)                  (this SDK +
                                                                               your handlers)
```

The demo vendor, Ibanly ([ibanly.app](https://ibanly.app), a fake IBAN validation API),
uses this contract end to end.

## Words used in this README

| Term | Meaning |
|---|---|
| **Vendor** | You: the company whose product is being bought. |
| **Buyer** | The person the assistant works for, signed in to Rose. Identified by a UUID (`buyerId`); Rose has verified their email. |
| **Environment** | `test` or `production`. Rose runs one connector of each (`mcp-test.userose.ai`, `mcp.userose.ai`). A test buyer must never reach a production account. |
| **Signature** | Every call from Rose is signed with Rose's private key. The SDK checks it against Rose's public keys, so nobody else can call your endpoints as Rose. |
| **Handover** | Claimable accounts: a person takes over a trial that an assistant started. **Not live yet**, see [Handover](#handover-claimable-accounts-coming). |

## What the SDK does

It has three independent parts:

- **`createVendorHandler`** serves the six endpoints above. For each call it checks that
  Rose signed it for your server, tells you which buyer and environment it is for, checks
  the buyer owns the account, and only then calls your code (one handler per endpoint, see
  [Connect your product](#connect-your-product)).
- **`createHandoverVerifier`** verifies the signed tokens of Handover (claimable accounts).
  Rose has not launched Handover yet: you do not need this part today.
- **`createAgentHandler`** runs Handover for you on top of that verifier: it serves auth.md
  and its endpoints on your accounts and store (see
  [Agent access built in](#agent-access-built-in)). Also not needed until Handover opens.

It runs on any server runtime with the standard `Request`, `Response` and Web Crypto APIs
(for example Node.js 22+ or Cloudflare Workers).

## Install

Use Node.js 22 or later with ESM, or a Web Crypto-capable server runtime. Install a release
tag in your server project; npm builds it on install:

```bash
npm install github:inboundx/rose-vendor-sdk#v0.4.0
```

The package includes compiled JavaScript, TypeScript declarations and an integration
example. It is not published to the npm registry yet.

### Ask a coding agent to do it

Paste this prompt into a coding agent (Claude Code, Codex, Cursor…) opened on your server's
repository, and replace the bracketed parts:

```text
Connect this product to Rose for Agents with the Rose vendor SDK.

1. Install it in the server project: npm install github:inboundx/rose-vendor-sdk#v0.4.0
   Then read node_modules/@userose/vendor-sdk/README.md in full. It is the contract; follow
   it over your own assumptions.
2. Find how this server routes HTTP requests, how it stores accounts, and how it runs the
   product operation an assistant should be able to call: [describe it, e.g. "convert an
   IBAN into bank details"]. Tell me what you found before writing code.
3. Mount createVendorHandler at /r4a/* with our public origin [https://api.example.com]
   and basePath '/r4a'. Build the Request from the external URL, not from forwarded headers.
4. Implement the handlers on our existing database and product code:
   - account: provision idempotently, keyed on buyer.environment + buyer.buyerId. Never
     match or merge an existing account by email.
   - authorizeAccount: return true only when the stored owner and environment match the buyer.
   - lookup: return the buyer's existing account or null.
   - trial: a limited, free version of the product action.
   - checkout, access, use: apply our plans, payments and quotas. Recheck ownership inside
     the transaction that performs the operation, and make retries idempotent.
   Throw VendorError for expected failures (402 for payment required, 409 for conflicts).
   Store test and production accounts separately.
5. Do not add a secret, an API key or an unsigned route for Rose: the SDK verifies Rose's
   signatures against its published keys. Do not install the SDK in browser code.
6. Add tests that sign requests with a local key passed through the `keys` option, covering
   provisioning twice for the same buyer, a buyer reaching another buyer's account, and a
   test buyer reaching a production account. Run our existing checks.
7. Skip Handover, createHandoverVerifier and createAgentHandler: Rose has not launched
   claimable accounts yet.
```

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

Your `handlers` implement these operations. Paths are relative to the base path; any other
method or path is a `404`.

| Route | Handler | Responsibility |
|---|---|---|
| `POST /trial` | `trial(buyer, input)` | Return `{output, note}` for a limited product action. |
| `POST /accounts` | `account(buyer, email, input?)` | Return `{account_id, created, next?}`. Provision idempotently using **environment + buyerId**, without merging by email. |
| `GET /account` | `lookup(buyer)` | For Handover, return `{account_id}` for an existing owned account or `null` when none exists; include accounts claimed from trials. |
| | `authorizeAccount(buyer, accountId)` | Check the stored owner and environment. Return `true` only for the buyer's own account. |
| `POST /accounts/{id}/checkout` | `checkout(buyer, accountId, offerId, paymentToken?)` | Apply your offer/payment rules and return the checkout result. |
| `GET /accounts/{id}/access` | `access(buyer, accountId)` | Return `{api_key, offer, usage}` for permitted access. |
| `POST /accounts/{id}/use` | `use(buyer, accountId, input)` | Enforce permissions/quotas and return `{output, usage}`. |

Each call goes through the same steps: the origin, method and path must match, the body is
read up to the size limit, Rose's signature is verified, the JSON body is parsed, and for
`/accounts/{id}/*` and `GET /account` the SDK calls `authorizeAccount`. Only then does it
call your handler.

The SDK calls `authorizeAccount` before checkout, access and use. If ownership or access
can change concurrently, recheck it inside the transaction that performs the product
operation. Product operations, retries and payment idempotency remain your responsibility.

Account provisioning passes the optional `input` object from Rose to your handler for
setup details such as a company name or website URL. Return an optional `next` string
to give the buyer's assistant your next setup step. Existing two-argument account handlers
continue to work.

`GET /r4a/account`, supplied by `lookup`, is optional today and will be required by
[Handover](#handover-claimable-accounts-coming): Rose uses it to reuse an existing account
before starting another trial. The SDK authenticates the lookup and checks the returned
account's ownership. If this optional handler is absent, lookup returns 503 rather than
treating an unsupported route as an absent account.

Throw `new VendorError(409, 'No active plan')` for an intentional product failure. For
payment-required results, use `new VendorError(402, {status: 'payment_required', amount_eur: 10})`.
Unexpected exceptions return a generic 500 without exposing their message, and are logged
with `console.error` so you can see them.

Rose passes what `trial`, `access`, `use` and `checkout` return to the buyer's assistant as
is, so you can add fields beyond the required ones (a documentation link, setup status…).
Return only what the buyer may see: never a database row or internal identifiers.

There is no secret to store. Rose signs each request with its own Ed25519 key (HTTP Message
Signatures, RFC 9421) and the SDK checks it against Rose's published public keys, fetched
from `https://mcp.userose.ai/.well-known/r4a-keys.json` (production) and
`https://mcp-test.userose.ai/.well-known/r4a-keys.json` (test) and cached for an hour. The
signature covers the exact raw body, **your** host (from `origin`), method, path and buyer,
so a request Rose signed for another vendor is refused here. The key that verifies names the
environment, so a test call never acts on a production account. For local development and
tests, pass `keys` (a JWKS) to trust a development key instead.
If a key directory cannot be read (10-second timeout), the SDK keeps that environment's last
keys and logs the failure; a call it cannot check yet gets a `503` ("Rose integration
unavailable", worth retrying) rather than a `401`.
The acceptance window is 300 seconds; product mutations must handle retries within it.
Queries are refused because the signing contract does not cover them. Bodies default to
64 KiB, configurable with `maxBodyBytes` up to 1 MiB. Account identifiers must contain
1–128 letters, digits, underscores or hyphens.

## Handover: claimable accounts (coming)

> **Status: not live.** The tokens below are signed by Rose's identity service, which is not
> hosted yet: Handover only runs on the demo vendor's local stack. Rose will tell you when it
> opens and send your trust configuration then. Until then, skip this section, except for
> **Prepare now** below.

Today every account Rose creates at your product belongs to a buyer who already signed in to
Rose. Handover adds **claimable accounts**: an assistant can start a trial before anyone has
signed in, and a person claims it later, keeping the account and its usage. It is opt-in
per vendor, and you host the endpoints that receive its tokens.

1. An assistant starts a trial at your product. You store a **registration** for it and
   show a six-digit **user code** and your claim page to the person.
2. The person signs in through Rose, with one of the agreed **identity sources** (for
   example `google`), and allows identity sharing.
3. Your claim endpoint receives an **identity assertion** signed by Rose's identity
   service: an ES256 JWT saying that buyer X, with verified email Y, claims registration Z with code C.
   `verifyClaim` checks it; your database then gives the trial's account to that buyer.
4. If the buyer later withdraws the delegation, Rose sends your events endpoint a signed
   **revocation event**. `verifyRevocation` checks it; your database then cuts off every
   credential issued for that buyer.

The paths of the two endpoints are yours (the smoke test uses
`/agent/identity/claim/complete` and `/agent/events`). Their keys are not the request-signing
keys above: they are separate ES256 keys that you configure, not fetched by the SDK. Rose
provides the issuer, audience, client identifier, environment, accepted identity sources
and **public** signing keys for your integration:

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

### Agent access built in

Instead of building that lifecycle yourself, let the SDK run it: `createAgentHandler` serves
auth.md and its endpoints (`/auth.md`, `/.well-known/*`, `/agent/*`, `/oauth2/*`, `/claim`):
anonymous trials with a limited key, the claim ceremony, token exchange, resume and both
revocation paths. Its configuration holds Rose's trust configuration (`rose`, `consent`,
`environment`), your own ES256 signing key, how auth.md describes your product, and the calls
a trial key allows (`trialLimit`); see `AgentConfig`. You supply two things:

- **`accounts`** (`AgentAccounts`): create an account, issue and revoke a key with your own
  API-key code (a trial key carries `expiresAt` and `maxUses`: enforce them), record the
  person who claimed an account (retried until it succeeds: make it idempotent), and find the
  account a key belongs to.
- **`store`** (`AgentStore`): read a record, and apply one change in one transaction over the
  records `agentChangeKeys` names, with `applyAgentChange`. Every check of a claim or a
  revocation happens inside that transaction, so concurrent claims cannot both win.

```typescript
import { agentChangeKeys, applyAgentChange, createAgentHandler, type AgentStore } from '@userose/vendor-sdk';

const store: AgentStore = {
  read: (key) => yourRecords.get(key),
  apply: (change) => yourRecords.transaction(async (tx) => {
    const records = Object.fromEntries(await Promise.all(
      agentChangeKeys(change).map(async (key) => [key, await tx.getForUpdate(key)] as const)));
    const { writes, outcome } = applyAgentChange(change, records, Date.now());
    for (const [key, value] of Object.entries(writes)) await (value === null ? tx.delete(key) : tx.put(key, value));
    return outcome;
  }),
};
const agentAccess = createAgentHandler({ ...roseAgentConfiguration, accounts: yourAccounts, store });
// Answer agent requests first; null means the request is not one of them, so your API answers,
// and its 401 gains the challenge that leads an agent with no key to auth.md.
const answer = await agentAccess.handle(incomingRequest)
  ?? await agentAccess.challenge(await yourApi(incomingRequest));
```

Wrap your API's responses with `challenge`. An agent that calls your API without a key and gets
a bare `401` concludes that only a person can sign up; the challenge
(`WWW-Authenticate: Bearer resource_metadata=…`, RFC 9728) is where auth.md discovery starts,
and a JSON body also gains a one-line pointer to `/auth.md`. Link `/auth.md` from your API docs
and `llms.txt` as well: in Rose's tests, that link is what agents followed.

#### How Rose trials your product (`mode`)

`mode` says how a buyer's agent starts a trial. The SDK publishes it in your OAuth metadata
(`agent_auth.trial_mode`) and Rose reads it from there.

- **`contract`** (default): the signed `/trial` and the anonymous trial, as above.
- **`auth-provider`**: set `acceptedIssuers` to the identity providers you trust, each with its
  issuer and public keys (`{ issuer, jwks }`; update the keys when the provider rotates them). Rose
  ID is one. An agent posts its identity token to `/oauth2/token` with
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and gets a trial key for its account.
  The token needs a verified email and your origin as audience. One person (issuer and subject)
  gets one account and one trial, for an hour and `trialLimit` calls: `issueKey` receives both
  limits, enforce them. `create` receives the person, to record with the account. The SDK refuses
  to start when `auth-provider` has no `acceptedIssuers`, or the reverse.
- **`catalogue`**: Rose runs the trial with its own key. Not available yet; the SDK refuses it.

#### When your product is an MCP server

An agent can use your MCP before anyone signs in, and keep the account once the person claims it:

- **Trial token:** `issueKey` returns whatever token your MCP accepts as `Authorization: Bearer`
  (an API key, or an access token from your authorization server) with the trial's `expiresAt`
  and `maxUses`. The claim retires it and the agent resumes with a full one.
- **`product.mcpUrl`:** auth.md and the token response (`mcp_url`) point the agent to your MCP.
- **`authorizationServer`:** when your own OAuth server (the sign-in MCP clients use for people)
  shares this origin, pass its metadata and token handler. The SDK merges the metadata into
  `/.well-known/oauth-authorization-server` and hands `/oauth2/token` every grant it does not run
  (`authorization_code`, `refresh_token`…). Your other routes (`/oauth2/authorize`,
  `/oauth2/register`, your MCP's `/.well-known/oauth-protected-resource/<path>`) stay yours:
  `handle` returns null for them.
- **After the claim**, the person signing in to your product normally should reach the claimed
  account: `claimed` gives you their verified email to link it.

`agentAccess.contract` (or `createAccountDirectory(store, accounts)` without agent access)
gives your signed `/r4a` handlers the same records: `lookup`, `provision`, `owns`, `check` and
`access` (the key the buyer's agent uses), so an account claimed from a trial is the buyer's
account through Rose too.

### Prepare now

Three choices in your signed routes make Handover a small addition later instead of a
migration:

- **Own accounts by environment + buyer, never by email.** A claim attaches an existing
  account to a buyer; an email match must never do it.
- **Implement `lookup`.** Handover needs it, and it already lets Rose reuse an account.
- **Keep credentials separate from the account.** A claim replaces the trial's API key
  while the account ID and usage stay, so a key must be replaceable without recreating
  the account.

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


### Anonymous trial protection (v0.4.0)

Set `trialProtection: "rose"` on `createAgentHandler` to use the **Proof of work**
setting in Config Studio → Rose for Agents → Agent access → Anonymous agents. It reads the policy from the configured identity
broker and validates the vendor audience and environment. An unavailable or invalid policy
fails anonymous registrations closed with 503. Verified Rose requests remain independent of
this lookup. Omitting the option, or `"off"`, preserves the existing anonymous signup behavior.

For local or vendor-managed settings use `"low"`, `"medium"`, or `"high"`: respectively
250,000, 1,000,000, or 3,000,000 expected HashWX operations split across four puzzles. These
are work budgets, not timing guarantees. No browser detection, CAPTCHA or human approval is
introduced. Fresh valid proofs can still create fresh trials; retain product quotas and rate limits.

An anonymous registration first receives HTTP 428 with `proof_of_work` in Cap format 2.
The `token` is an opaque, purpose-specific ES256 JWT; it is not a Cap redemption token.
The vendor's `/auth.md` documents the runnable Node solver at `/agent/proof-of-work/solver`
and the retry contract. The solver requires Node 22 and `capjs-core@0.1.5`.

`AgentStore.apply` must continue applying `agentChangeKeys` and `applyAgentChange` atomically.
The new `consume_trial_proof` change uses bounded expiring replay maps, before account creation;
a creation failure consumes that proof and the agent must request a new one. Existing store
adapters using these helpers need no schema change. Do not enumerate only known change types.

The Rose connector bypasses work only with a valid HTTP Message Signature and a signed UUID
`registration_nonce`. The signature binds the body, destination and buyer and must match the
configured environment. It grants trial access only, never ownership or claimed credentials.
`roseRequestKeys` replaces published verification directories for local development/tests only,
like `createVendorHandler.keys`. Never trust a body field or unsigned buyer header.

Runtime verification imports only Cap's pinned `hashwx.wasm`, not its instrumentation or
bundler modules. The upstream binary is built from `tevador/hashwx` commit
`74b567a31276a4c5d7cb232a5b7639467f49f961`, SHA-256
`b1a0dbb3ef444d3c7069e0a5e0a0273ffa4cf8fef62cbbe43761c02f7cd6aff5`.
Worker bundlers must honor the `workerd` package condition and load `.wasm` as a WebAssembly
module (Wrangler does this). Node reads the same installed binary at module initialization;
no request's pending initialization promise is shared.
