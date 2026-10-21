/**
 * Agent access (auth.md): an AI agent registers at your product, uses a trial key at once, and
 * the person it works for claims the account with their Rose identity, keeping its usage. The
 * SDK serves the endpoints and runs the lifecycle; you supply your accounts and API keys
 * (`AgentAccounts`) and a store that applies each change in one transaction (`AgentStore`).
 */
import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT, type JSONWebKeySet } from "jose";
import { createHandoverVerifier, REVOKED_EVENT } from "./handover.js";
import { type Buyer, EMAIL, type Environment, type Json, origin as httpsOrigin, readBytes, trustedUrl } from "./http.js";
import { type AccountRecord, accountKey, type AgentChange, type AgentKey, type AgentOutcome, type AgentState,
  type BuyerRecord, buyerKey, CLAIM_SECONDS, keyGrant } from "./agent-state.js";
import { agentSkill } from "./agent-skill.js";

export const JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const CLAIM_GRANT = "urn:workos:agent-auth:grant-type:claim";
const ASSERTION_TYP = "oauth-id-jag+jwt";
const ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
const MAX_BODY_BYTES = 8192;
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const CLAIM_TOKEN = /^clm_([A-Za-z0-9_-]{1,128})\.([0-9a-f]{64})$/;

/** Your database. Run `applyAgentChange` on the records `agentChangeKeys` names, in one transaction. */
export interface AgentStore {
  read(key: string): Promise<Json | undefined>;
  apply(change: AgentChange): Promise<AgentOutcome>;
}

/** Your product's accounts and API keys, called outside the store's transactions. */
export interface AgentAccounts {
  /** A new account for an agent registration; an anonymous one starts on your trial plan. */
  create(kind: AgentState["kind"]): Promise<string>;
  /** A key for the account. A trial key expires and allows `maxUses` calls; enforce both. */
  issueKey(accountId: string, grant: { scope: "trial" | "full"; expiresAt?: number; maxUses?: number }): Promise<AgentKey>;
  /** Stop a key at once. Revoking an unknown key is not an error. */
  revokeKey(accountId: string, keyId: string): Promise<void>;
  /** A person with this verified email now owns the account: record it, leave the trial plan. Retried until it succeeds. */
  claimed(accountId: string, person: { email: string }): Promise<void>;
  /** The account an API key belongs to, or null. */
  accountOfKey(apiKey: string): string | null;
}

export interface AgentConfig {
  /** Your public origin: the auth.md issuer and the audience of Rose's tokens. */
  origin: string;
  environment: Environment;
  /** Rose's identity service, from your Handover trust configuration. */
  rose: { issuer: string; clientId: string; allowedSources: readonly string[]; jwks: JSONWebKeySet };
  /** Your own ES256 key for the assertions agents exchange: PKCS#8 PEM, and its public JWKS. */
  signing: { privateKey: string; jwks: JSONWebKeySet };
  /** Rose's consent page, and the vendor name it expects. */
  consent: { url: string; vendor: string; browserOrigin: string };
  product: {
    name: string;
    /** First paragraph of your auth.md: what the product is, anything an agent must know. */
    about: string;
    apiUrl: string;
    /** How to call the API with the access token, shown in auth.md (Markdown). */
    usage: string;
    scopes: { trial: string; full: string };
    /** When your product is an MCP server: its URL. auth.md and the token response point the agent to it. */
    mcpUrl?: string;
  };
  /**
   * Your own OAuth server, when it shares this origin (an MCP client's sign-in for people): its
   * metadata is merged into the SDK's, and `/oauth2/token` hands it every grant the SDK does not run.
   */
  authorizationServer?: {
    metadata: Record<string, Json>;
    token(fields: Record<string, unknown>, request: Request): Promise<Response>;
  };
  /** Calls a trial key allows, during the 15 minutes a registration can be claimed. */
  trialLimit: number;
  /** Lifetime of a claimed agent's key. Default one hour; renewing it needs the person's consent. */
  credentialSeconds?: number;
  accounts: AgentAccounts;
  store: AgentStore;
  /** Rate limiting: return false to answer 429. */
  allow?(request: Request, action: "register" | "other"): Promise<boolean>;
  /** Bearer secret for `GET /agent/admin/accounts/{id}`, a status snapshot for your operators. */
  operatorSecret?: string;
}

class AgentError extends Error {
  constructor(public readonly code: string, public readonly status = 400) { super(code); }
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function secret(): string {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256(value: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

function userCode(): string {
  return String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, "0");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function reply(data: Json, status = 200): Response {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store", "Pragma": "no-cache", "X-Robots-Tag": "noindex, nofollow" } });
}

async function readText(request: Request): Promise<string> {
  try {
    return new TextDecoder().decode(await readBytes(request, MAX_BODY_BYTES));
  } catch {
    throw new AgentError("invalid_request");
  }
}

async function readFields(request: Request): Promise<Record<string, unknown>> {
  const raw = await readText(request);
  if (request.headers.get("content-type")?.startsWith("application/x-www-form-urlencoded")) return Object.fromEntries(new URLSearchParams(raw));
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new AgentError("invalid_request");
  return parsed as Record<string, unknown>;
}

const ownerOf = (buyer: Buyer) => `${buyer.environment}:${buyer.buyerId}`;

/**
 * Which buyer owns which of your accounts, and the key each buyer's agent uses. Your signed
 * `/r4a` handlers need it with or without agent access (`createAgentHandler` builds on it).
 */
export function createAccountDirectory(store: AgentStore, accounts: Pick<AgentAccounts, "issueKey" | "revokeKey" | "claimed">) {
  async function record(account: string): Promise<AccountRecord | undefined> {
    return (await store.read(accountKey(account))) as AccountRecord | undefined;
  }

  /** Do at your product what a change left pending: revoke the keys it retired, record its claim. */
  async function settle(account: string): Promise<void> {
    const current = await record(account);
    for (const keyId of current?.staleKeys ?? []) {
      await accounts.revokeKey(account, keyId);
      await store.apply({ type: "key_revoked", account, keyId });
    }
    const email = current?.claimedBy;
    if (email) {
      await accounts.claimed(account, { email });
      await store.apply({ type: "claim_recorded", account, email });
    }
  }

  /** The agent's key for the account, of this scope, issued when it has none and may hold one. */
  async function agentKey(account: string, scope: "trial" | "full"): Promise<string | null> {
    await settle(account);
    const current = await record(account);
    const grant = keyGrant(current, Date.now());
    if (grant?.scope !== scope) return null;
    if (current?.key) return current.key.apiKey;
    const issued = await accounts.issueKey(account, grant);
    const outcome = await store.apply({ type: "set_key", account, key: issued, scope });
    if (outcome.error || outcome.kept) await accounts.revokeKey(account, issued.id); // lost a race, or no longer allowed
    return outcome.error ? null : (outcome.key as unknown as AgentKey).apiKey;
  }

  /** Whether the buyer's agent may act on the account now. */
  async function check(buyer: Buyer, account: string): Promise<"ok" | "unknown" | "not_owner" | "restricted"> {
    const current = await record(account);
    if (!current) return "unknown";
    if (current.owner !== ownerOf(buyer)) return "not_owner";
    const agent = current.agent;
    return agent && (agent.status !== "claimed" || agent.credentialExpires <= Date.now()) ? "restricted" : "ok";
  }

  return {
    record, settle, agentKey, check,
    /** The buyer's account, provisioned or claimed. */
    async lookup(buyer: Buyer): Promise<string | null> {
      const mapped = ((await store.read(buyerKey(ownerOf(buyer)))) as BuyerRecord | undefined)?.account;
      return mapped && (await record(mapped))?.owner === ownerOf(buyer) ? mapped : null;
    },
    /** Give `account` (one you created for this buyer) to the buyer, unless it already has one: that one is returned. */
    async provision(buyer: Buyer, account: string): Promise<{ account: string } | "not_owner"> {
      const outcome = await store.apply({ type: "provision", owner: ownerOf(buyer), account });
      return outcome.error ? "not_owner" : { account: outcome.account as string };
    },
    async owns(buyer: Buyer, account: string): Promise<boolean> {
      return (await record(account))?.owner === ownerOf(buyer);
    },
    /** The API key the buyer's agent uses, or why it may not use the account now. */
    async access(buyer: Buyer, account: string): Promise<{ apiKey: string } | "unknown" | "not_owner" | "restricted"> {
      const status = await check(buyer, account);
      if (status !== "ok") return status;
      const apiKey = await agentKey(account, "full");
      return apiKey ? { apiKey } : "restricted";
    },
  };
}

/** Fetch-compatible handler for the auth.md endpoints, plus what your signed `/r4a` handlers need. */
export function createAgentHandler(config: AgentConfig) {
  const issuer = httpsOrigin(config.origin);
  const consent = trustedUrl(config.consent.url);
  const mcpUrl = config.product.mcpUrl === undefined ? undefined : trustedUrl(config.product.mcpUrl).toString();
  const browserOrigin = httpsOrigin(config.consent.browserOrigin);
  if (!["test", "production"].includes(config.environment)) throw new Error("Invalid environment");
  if (!Number.isSafeInteger(config.trialLimit) || config.trialLimit < 1 || config.trialLimit > 100) throw new Error("Invalid trialLimit");
  if (!config.signing.jwks.keys.length || config.signing.jwks.keys.some((key) => "d" in key)) throw new Error("signing.jwks must hold public keys");
  const handover = createHandoverVerifier({ ...config.rose, audience: issuer, environment: config.environment });
  const vendorKeys = createLocalJWKSet(structuredClone(config.signing.jwks));
  const signingKey = importPKCS8(config.signing.privateKey, "ES256");
  const credentialMs = (config.credentialSeconds ?? 3600) * 1000;
  const { accounts, store, product } = config;
  const scope = (grant: "trial" | "full") => product.scopes[grant];
  const directory = createAccountDirectory(store, accounts);
  const { record, settle, agentKey } = directory;
  const skill = agentSkill({ issuer, ...product, mcpUrl, trialLimit: config.trialLimit });

  function failure(code: string, status = 400): Response {
    console.log(JSON.stringify({ event: "agent_failure", reason: code }));
    return reply({ error: code }, status);
  }

  async function apply(change: AgentChange): Promise<AgentOutcome> {
    const outcome = await store.apply(change);
    if (typeof outcome.error === "string") throw new AgentError(outcome.error, outcome.error === "account_conflict" ? 409 : 400);
    return outcome;
  }

  async function assertion(account: string, id: string): Promise<string> {
    return new SignJWT({ environment: config.environment })
      .setProtectedHeader({ typ: ASSERTION_TYP, alg: "ES256", kid: config.signing.jwks.keys[0]?.kid ?? "" })
      .setIssuer(issuer).setAudience(issuer).setSubject(account).setJti(id).setIssuedAt().setExpirationTime("5m")
      .sign(await signingKey);
  }

  async function ownAssertion(token: unknown): Promise<{ account: string; id: string }> {
    if (typeof token !== "string" || token.length > MAX_BODY_BYTES) throw new AgentError("invalid_grant");
    const { payload: p } = await jwtVerify(token, vendorKeys, {
      issuer, audience: issuer, algorithms: ["ES256"], typ: ASSERTION_TYP,
      requiredClaims: ["iss", "sub", "aud", "jti", "iat", "exp"], clockTolerance: 0,
    });
    const now = Math.floor(Date.now() / 1000);
    if (typeof p.sub !== "string" || typeof p.jti !== "string" || p.jti.length > 128 || typeof p.iat !== "number" ||
        typeof p.exp !== "number" || p.exp - p.iat > 300 || p.iat > now + 30 || p.environment !== config.environment) throw new AgentError("invalid_grant");
    return { account: p.sub, id: p.jti };
  }

  /** The agent's key; a failure at your product is worth a retry, and spends no grant. */
  async function keyFor(account: string, grant: "trial" | "full"): Promise<string> {
    let apiKey: string | null;
    try {
      apiKey = await agentKey(account, grant);
    } catch {
      throw new AgentError("temporarily_unavailable", 503);
    }
    if (!apiKey) throw new AgentError("invalid_grant");
    return apiKey;
  }

  function token(account: string, apiKey: string, grant: "trial" | "full", expires: number): Response {
    console.log(JSON.stringify({ event: "agent_access_issued", account, scope: scope(grant) }));
    return reply({ access_token: apiKey, token_type: "Bearer", expires_in: Math.max(0, Math.floor((expires - Date.now()) / 1000)),
      scope: scope(grant), account_id: account, api_url: product.apiUrl, ...(mcpUrl ? { mcp_url: mcpUrl } : {}),
      api_key_delivery: `The access token is ${product.name}'s API key; use Authorization: Bearer.` });
  }

  function parseClaimToken(value: unknown): { account: string; secret: string } {
    const match = CLAIM_TOKEN.exec(typeof value === "string" ? value : "");
    if (!match) throw new AgentError("expired_token");
    return { account: match[1]!, secret: match[2]! };
  }

  async function register(data: Record<string, unknown>): Promise<Response> {
    if (data.type === "identity_assertion") {
      if (data.assertion_type !== ID_JAG) return failure("unsupported_assertion_type");
      return complete(data.assertion);
    }
    if (data.type !== "anonymous" && data.type !== "service_auth") return failure("unsupported_identity_type");
    const hint = data.login_hint;
    if (data.type === "service_auth" && (typeof hint !== "string" || !EMAIL.test(hint))) return failure("invalid_login_hint");
    const account = await accounts.create(data.type);
    if (!ACCOUNT_ID.test(account)) throw new Error("AgentAccounts.create returned an invalid account id");
    const claimSecret = secret(), code = userCode(), assertionId = crypto.randomUUID();
    const expires = Date.now() + CLAIM_SECONDS * 1000;
    const state: AgentState = { kind: data.type, status: "pending", environment: config.environment, expires,
      credentialExpires: expires, trialLimit: config.trialLimit, codeHash: await sha256(code), claimHash: await sha256(claimSecret),
      assertionId, exchanged: false, attempts: 0, lastPoll: 0, claimInitiations: 0, loginHint: typeof hint === "string" ? hint : null };
    await apply({ type: "register", account, state });
    console.log(JSON.stringify({ event: "agent_registration_attempted", account, kind: data.type }));
    const claimToken = `clm_${account}.${claimSecret}`;
    const verification = new URL("/claim", issuer);
    verification.searchParams.set("registration_id", account);
    // auth.md v0.6: only an anonymous registration gets access (and an assertion) before the claim.
    const preClaim = data.type === "anonymous" ? { identity_assertion: await assertion(account, assertionId),
      assertion_expires: new Date(Date.now() + 300_000).toISOString(), pre_claim_scopes: [scope("trial")] } : {};
    return reply({ registration_id: account, registration_type: data.type, claim_token: claimToken,
      claim_token_expires: new Date(expires).toISOString(), claim_url: `${issuer}/agent/identity/claim`, ...preClaim,
      post_claim_scopes: [scope("full")],
      claim: { claim_token: claimToken, user_code: code, verification_uri: verification.toString(), expires_in: CLAIM_SECONDS, interval: 5 } });
  }

  async function complete(token: unknown): Promise<Response> {
    if (typeof token !== "string") return failure("invalid_request");
    const claim = await handover.claimProof(token);
    const account = claim.registrationId;
    if (!ACCOUNT_ID.test(account)) return failure("invalid_request");
    const assertionId = crypto.randomUUID();
    await apply({ type: "claim", account, owner: ownerOf(claim), email: claim.email, codeHash: await sha256(claim.userCode),
      proofId: claim.proofId, proofExpires: claim.expiresAt * 1000, source: claim.identitySource, authTime: claim.authenticatedAt,
      issuedAt: claim.issuedAt, credentialExpires: Date.now() + credentialMs, assertionId });
    // Until your product records the claim the account gets no key; the agent's next request retries.
    await settle(account).catch(() => console.log(JSON.stringify({ event: "agent_settle_failed", account })));
    console.log(JSON.stringify({ event: "agent_claimed", account }));
    return reply({ status: "claimed", account_id: account, identity_assertion: await assertion(account, assertionId) });
  }

  async function revokeOwner(raw: string): Promise<Response> {
    const event = await handover.verifyRevocation(raw);
    const who = ownerOf(event);
    for (let attempt = 0; attempt < 3; attempt++) {
      const mapped = ((await store.read(buyerKey(who))) as BuyerRecord | undefined)?.account ?? null;
      const outcome = await store.apply({ type: "revoke_owner", owner: who, account: mapped, eventId: event.eventId,
        eventExpires: event.expiresAt * 1000, issuedAt: event.issuedAt });
      if (outcome.error === "moved") continue;
      if (outcome.replay) return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
      try {
        if (mapped) await settle(mapped);
      } catch {
        // Not acknowledged: Rose retries, and the retry revokes what is left.
        console.log(JSON.stringify({ event: "agent_revocation_failed", reason: "key_revocation_unavailable" }));
        return failure("temporarily_unavailable", 503);
      }
      await apply({ type: "revocation_done", owner: who, eventId: event.eventId, eventExpires: event.expiresAt * 1000 });
      return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
    }
    return failure("temporarily_unavailable", 503);
  }

  async function snapshot(request: Request, account: string): Promise<Response> {
    const supplied = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
    if (!config.operatorSecret || !safeEqual(supplied, config.operatorSecret)) return failure("unauthorized", 401);
    const agent = (await record(account))?.agent;
    if (!agent) return failure("not_found", 404);
    const expired = agent.status === "pending" ? agent.expires <= Date.now() : agent.credentialExpires <= Date.now();
    return reply({ account_id: account, status: agent.status === "revoked" ? "revoked" : expired ? "expired" : agent.status === "pending" ? "trial" : "claimed",
      kind: agent.kind, environment: agent.environment, identity_provider: agent.identitySource ? "Rose ID" : null,
      identity_source: agent.identitySource ?? null, credential_expires_at: agent.credentialExpires,
      claim_expires_at: agent.expires, trial_limit: agent.trialLimit });
  }

  async function route(request: Request, path: string): Promise<Response> {
    if (request.method === "GET") {
      if (path.startsWith("/agent/admin/accounts/")) return snapshot(request, path.slice("/agent/admin/accounts/".length));
      if (path === "/auth.md") return new Response(skill, { headers: { "Content-Type": "text/markdown; charset=utf-8", "Cache-Control": "no-store" } });
      if (path === "/.well-known/oauth-protected-resource") {
        return reply({ resource: product.apiUrl, authorization_servers: [issuer], scopes_supported: [scope("trial"), scope("full")], bearer_methods_supported: ["header"] });
      }
      if (path === "/.well-known/jwks.json") return reply(config.signing.jwks as unknown as Json);
      if (path === "/.well-known/oauth-authorization-server") {
        const own = config.authorizationServer?.metadata ?? {};
        const list = (value: Json | undefined) => (Array.isArray(value) ? value : []);
        return reply({ ...own, issuer, token_endpoint: `${issuer}/oauth2/token`, revocation_endpoint: `${issuer}/oauth2/revoke`,
          jwks_uri: `${issuer}/.well-known/jwks.json`, grant_types_supported: [...list(own.grant_types_supported), JWT_GRANT, CLAIM_GRANT],
          scopes_supported: [...list(own.scopes_supported), scope("trial"), scope("full")],
          agent_auth: { skill: `${issuer}/auth.md`, identity_endpoint: `${issuer}/agent/identity`, claim_endpoint: `${issuer}/agent/identity/claim`,
            events_endpoint: `${issuer}/agent/events`, events_supported: [REVOKED_EVENT], identity_types_supported: ["anonymous", "service_auth", "identity_assertion"],
            identity_assertion: { assertion_types_supported: [ID_JAG] },
            extensions: { ceremony_created_on_registration: true, claim_completion: `${issuer}/agent/identity/claim/complete`, api_key_delivery: true } } });
      }
      return failure("not_found", 404);
    }
    if (request.method !== "POST") return failure("not_found", 404);
    if (path === "/agent/events") return revokeOwner(await readText(request));
    const data = await readFields(request);
    if (path === "/agent/identity") return register(data);
    if (path === "/agent/identity/claim/complete") return complete(data.identity_assertion);
    if (path === "/agent/identity/claim") {
      const claim = CLAIM_TOKEN.exec(typeof data.claim_token === "string" ? data.claim_token : "");
      if (!claim || typeof data.email !== "string" || !EMAIL.test(data.email)) return failure("invalid_request");
      const account = claim[1]!, code = userCode();
      const outcome = await store.apply({ type: "code", account, claimHash: await sha256(claim[2]!), email: data.email, codeHash: await sha256(code) });
      if (typeof outcome.error === "string") return failure(outcome.error);
      return reply({ registration_id: account, status: "initiated", claim_attempt: {
        user_code: code, verification_uri: `${issuer}/claim?registration_id=${account}`, interval: 5,
        note: "The original registration expiry still applies; this does not extend trial quota or lifetime." } });
    }
    if (path === "/oauth2/token") {
      if (data.grant_type === JWT_GRANT) {
        const own = await ownAssertion(data.assertion);
        // The key before the assertion is spent, so a failure at your product leaves it usable.
        const grant = (await record(own.account))?.agent?.status === "claimed" ? "full" : "trial";
        const apiKey = await keyFor(own.account, grant);
        const outcome = await apply({ type: "exchange", account: own.account, assertionId: own.id });
        // A claim since then changed the assertion and retired that key: the exchange fails.
        if (outcome.scope !== grant) throw new AgentError("invalid_grant");
        return token(own.account, apiKey, grant, outcome.expires as number);
      }
      if (data.grant_type === CLAIM_GRANT) {
        const claim = parseClaimToken(data.claim_token);
        if (data.registration_id && data.registration_id !== claim.account) throw new AgentError("expired_token");
        const outcome = await apply({ type: "resume", account: claim.account, claimHash: await sha256(claim.secret) });
        return token(claim.account, await keyFor(claim.account, "full"), "full", outcome.expires as number);
      }
      if (config.authorizationServer) return config.authorizationServer.token(data, request);
      return failure("unsupported_grant_type");
    }
    if (path === "/oauth2/revoke") {
      const apiKey = typeof data.token === "string" ? data.token : "";
      const account = apiKey ? accounts.accountOfKey(apiKey) : null;
      if (account) {
        await store.apply({ type: "revoke_token", account, apiKey });
        try {
          await settle(account);
        } catch {
          // RFC 7009: a 503 tells the agent its token still works; its retry revokes what is left.
          console.log(JSON.stringify({ event: "agent_revocation_failed", reason: "key_revocation_unavailable" }));
          return failure("temporarily_unavailable", 503);
        }
      }
      return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
    }
    return failure("not_found", 404);
  }

  // Exact paths outside /agent/, so your own OAuth server and MCP metadata can share the origin.
  const PATHS = ["/agent/", "/oauth2/token", "/oauth2/revoke", "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server", "/.well-known/jwks.json", "/auth.md", "/claim"];

  return {
    /** Answer an auth.md request, or return null when the path is not one of the agent endpoints (yours to serve). */
    async handle(request: Request): Promise<Response | null> {
      const url = new URL(request.url), path = url.pathname;
      if (!PATHS.some((known) => path === known || (known.endsWith("/") && path.startsWith(known)))) return null;
      if (url.origin !== issuer) return failure("not_enabled", 404);
      if (path === "/claim") {
        const account = url.searchParams.get("registration_id") ?? "";
        if (!ACCOUNT_ID.test(account) || !(await record(account))?.agent) return failure("not_found", 404);
        const target = new URL(consent);
        target.searchParams.set("vendor", config.consent.vendor);
        target.searchParams.set("registration_id", account);
        return Response.redirect(target.toString(), 303);
      }
      // The only browser allowed to deliver proofs is Rose's consent page.
      const from = request.headers.get("origin");
      if (from && from !== browserOrigin && from !== issuer) return failure("unapproved_origin", 403);
      let response: Response;
      if (request.method === "OPTIONS") response = new Response(null, { status: 204 });
      else if (config.allow && !(await config.allow(request, path === "/agent/identity" ? "register" : "other"))) response = failure("rate_limited", 429);
      else {
        try {
          response = await route(request, path);
        } catch (error) {
          // Never echo tokens, inputs or cryptographic errors.
          response = error instanceof AgentError ? failure(error.code, error.status) : failure("invalid_grant");
        }
      }
      if (from === browserOrigin) {
        response = new Response(response.body, response);
        response.headers.set("Access-Control-Allow-Origin", from);
        response.headers.set("Vary", "Origin");
        response.headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
      }
      return response;
    },

    /**
     * Wrap your API's responses: a 401 gains the challenge auth.md discovery starts from
     * (RFC 9728) and, in a JSON body, a pointer to auth.md. Without them an agent with no key
     * concludes that only a person can sign up. A challenge you already send is kept.
     */
    async challenge(response: Response): Promise<Response> {
      if (response.status !== 401) return response;
      const headers = new Headers(response.headers);
      if (!headers.has("WWW-Authenticate")) headers.set("WWW-Authenticate", `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource"`);
      const init = { status: 401, statusText: response.statusText, headers };
      // Only a plain JSON body is rewritten; any other body keeps its exact bytes.
      if (!headers.get("Content-Type")?.includes("json") || headers.has("Content-Encoding")) return new Response(response.body, init);
      const bytes = await response.arrayBuffer();
      let body: unknown = null;
      try { body = JSON.parse(new TextDecoder().decode(bytes)); } catch { body = null; }
      if (!body || typeof body !== "object" || Array.isArray(body)) return new Response(bytes, init);
      headers.delete("Content-Length");
      return Response.json({ ...body, agent_registration: `No API key? An AI agent can start a trial itself: ${issuer}/auth.md` }, init);
    },

    /** For your signed `/r4a` handlers: the same store, so a claim and a provisioning agree. */
    contract: directory,
  };
}
