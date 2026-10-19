import { type Buyer, type Environment, VendorError } from "./http.js";

/**
 * Rose signs every vendor call with HTTP Message Signatures (RFC 9421) and the Ed25519 key of one
 * of its environments, and publishes the public keys. The signature covers the method, YOUR host,
 * the path, the body digest and the buyer, so a call Rose signed for another vendor never verifies
 * here. The key that verifies names the environment: test keys never act on production accounts.
 */
export interface Jwks { keys: { kty?: string; crv?: string; x?: string; kid?: string }[] }

const DIRECTORIES: Record<Environment, string> = {
  production: "https://mcp.userose.ai/.well-known/r4a-keys.json",
  test: "https://mcp-test.userose.ai/.well-known/r4a-keys.json",
};
const TTL_MS = 3600_000;
const REFETCH_AFTER_MS = 60_000; // an unknown key id refetches at most once a minute
const encoder = new TextEncoder();
const buyerPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const inputPattern =
  /^r4a=(\("@method" "@authority" "@path" "content-digest" "x-r4a-buyer"\);created=(\d{1,12});expires=(\d{1,12});keyid="([A-Za-z0-9._-]{1,64})";alg="ed25519";tag="r4a-contract")$/;
const signaturePattern = /^r4a=:([A-Za-z0-9+/]{86}==):$/;

type Keys = Map<string, { environment: Environment; key: CryptoKey }>;
let cached: { keys: Keys; at: number } | null = null;
// One refresh at a time: unauthenticated callers must not fan out into directory fetches. Requests
// do not await another request's refresh: Cloudflare Workers can hang on a promise shared across
// requests. They use the cached keys, or get a retryable 503 on a cold start. A refresh older than
// REFRESH_TIMEOUT_MS counts as over, in case its request was cancelled before it finished.
let refreshStartedAt = 0;
const REFRESH_TIMEOUT_MS = 30_000;

async function addKeys(into: Keys, jwks: unknown, only?: Environment): Promise<void> {
  const list = (jwks as Partial<Jwks> | null)?.keys;
  for (const { kty, crv, x, kid } of Array.isArray(list) ? list : []) {
    if (kty !== "OKP" || crv !== "Ed25519" || typeof x !== "string" || typeof kid !== "string") continue;
    const environment = kid.startsWith("test-") ? "test" : kid.startsWith("production-") ? "production" : null;
    // A directory only speaks for its own environment.
    if (!environment || (only && environment !== only)) continue;
    into.set(kid, { environment, key: await crypto.subtle.importKey("jwk", { kty, crv, x }, { name: "Ed25519" }, false, ["verify"]) });
  }
}

async function published(refetch: boolean, now: number): Promise<Keys> {
  if (cached && now - cached.at < (refetch ? REFETCH_AFTER_MS : TTL_MS)) return cached.keys;
  if (now - refreshStartedAt < REFRESH_TIMEOUT_MS) {
    if (cached) return cached.keys;
    throw new VendorError(503, "Rose integration unavailable");
  }
  refreshStartedAt = now;
  try {
    return await refresh(now);
  } finally {
    refreshStartedAt = 0;
  }
}

async function refresh(now: number): Promise<Keys> {
  const keys: Keys = new Map();
  for (const [environment, url] of Object.entries(DIRECTORIES) as [Environment, string][]) {
    try {
      const response = await fetch(url, { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(String(response.status));
      await addKeys(keys, await response.json(), environment);
    } catch (error) {
      // Logged, since callers only see a 503 or, with cached keys, nothing until a rotation fails.
      console.error(`Rose key directory unavailable: ${url} (${error instanceof Error ? error.message : String(error)})`);
      // Keep the last keys of this environment rather than refusing every call during an outage.
      for (const [kid, entry] of cached?.keys ?? []) if (entry.environment === environment) keys.set(kid, entry);
    }
  }
  cached = { keys, at: now };
  return keys;
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Verify Rose's signature over the exact raw body. `keys` replaces Rose's published key
 * directories: for local development and tests only.
 */
export async function verifyRequest(request: Request, bytes: Uint8Array, keys?: Jwks, now = Date.now()): Promise<Buyer> {
  const input = inputPattern.exec(request.headers.get("Signature-Input") ?? "");
  const signature = signaturePattern.exec(request.headers.get("Signature") ?? "");
  const buyerId = request.headers.get("X-R4A-Buyer") ?? "";
  const url = new URL(request.url);
  // Queries are not covered by the Rose signing contract, so do not accept them.
  if (!input || !signature || !buyerPattern.test(buyerId) || url.search) throw new VendorError(401, "Invalid Rose signature");
  const [, params = "", created = "0", expires = "0", kid = ""] = input;
  const seconds = now / 1000;
  if (Math.abs(seconds - Number(created)) > 300 || Number(expires) < seconds || Number(expires) - Number(created) > 300) {
    throw new VendorError(401, "Invalid Rose signature");
  }
  let directory: Keys;
  if (keys) {
    directory = new Map();
    await addKeys(directory, keys);
  } else {
    directory = await published(false, now);
    if (!directory.has(kid)) directory = await published(true, now);
  }
  const entry = directory.get(kid);
  // No keys, or a key rotated in while another request is fetching: retryable, not a forgery.
  const unavailable = !directory.size || (!keys && now - refreshStartedAt < REFRESH_TIMEOUT_MS);
  if (!entry) throw new VendorError(unavailable ? 503 : 401, unavailable ? "Rose integration unavailable" : "Invalid Rose signature");
  const digest = `sha-256=:${base64(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)))}:`;
  if (request.headers.get("Content-Digest") !== digest) throw new VendorError(401, "Invalid Rose signature");
  const base = [
    `"@method": ${request.method.toUpperCase()}`,
    `"@authority": ${url.host}`,
    `"@path": ${url.pathname}`,
    `"content-digest": ${digest}`,
    `"x-r4a-buyer": ${buyerId}`,
    `"@signature-params": ${params}`,
  ].join("\n");
  const raw = Uint8Array.from(atob(signature[1] ?? ""), c => c.charCodeAt(0));
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, entry.key, raw, encoder.encode(base)))) {
    throw new VendorError(401, "Invalid Rose signature");
  }
  return { buyerId, environment: entry.environment };
}
