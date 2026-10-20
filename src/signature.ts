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
let activeRefresh: { at: number } | null = null;
const REFRESH_TIMEOUT_MS = 30_000;
const DIRECTORY_TIMEOUT_MS = 10_000;

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

/** Rose's published keys, refreshed when the cache is older than `maxAgeMs`. */
async function published(now: number, maxAgeMs: number): Promise<Keys> {
  if (cached && now - cached.at < maxAgeMs) return cached.keys;
  if (activeRefresh && now - activeRefresh.at < REFRESH_TIMEOUT_MS) {
    if (cached) return cached.keys;
    throw new VendorError(503, "Rose integration unavailable");
  }
  const refresh = { at: now };
  activeRefresh = refresh;
  try {
    const keys = await fetchKeys();
    // A cancelled or slow request may outlive its lease. It must not roll back newer keys.
    if (activeRefresh === refresh) cached = { keys, at: now };
    return cached?.keys ?? keys;
  } finally {
    if (activeRefresh === refresh) activeRefresh = null;
  }
}

async function fetchKeys(): Promise<Keys> {
  const keys: Keys = new Map();
  for (const [environment, url] of Object.entries(DIRECTORIES) as [Environment, string][]) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DIRECTORY_TIMEOUT_MS);
    try {
      const response = await fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
      if (!response.ok) throw new Error(String(response.status));
      await addKeys(keys, await response.json(), environment);
    } catch (error) {
      // Logged, since callers only see a 503 or, with cached keys, nothing until a rotation fails.
      console.error(`Rose key directory unavailable: ${url} (${error instanceof Error ? error.message : String(error)})`);
      // Keep the last keys of this environment rather than refusing every call during an outage.
      for (const [kid, entry] of cached?.keys ?? []) if (entry.environment === environment) keys.set(kid, entry);
    } finally {
      clearTimeout(timeout);
    }
  }
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
  const invalid = () => new VendorError(401, "Invalid Rose signature");
  const input = inputPattern.exec(request.headers.get("Signature-Input") ?? "");
  const signature = signaturePattern.exec(request.headers.get("Signature") ?? "");
  const buyerId = request.headers.get("X-R4A-Buyer") ?? "";
  const url = new URL(request.url);
  // Queries are not covered by the Rose signing contract, so do not accept them.
  if (!input || !signature || !buyerPattern.test(buyerId) || url.search) throw invalid();
  const [, params = "", created = "0", expires = "0", kid = ""] = input;
  const seconds = now / 1000;
  const fresh = Math.abs(seconds - Number(created)) <= 300 && Number(expires) >= seconds &&
    Number(expires) - Number(created) <= 300;
  if (!fresh) throw invalid();

  let directory: Keys;
  if (keys) {
    directory = new Map();
    await addKeys(directory, keys);
  } else {
    directory = await published(now, TTL_MS);
    if (!directory.has(kid)) directory = await published(now, REFETCH_AFTER_MS); // maybe a newly rotated key
  }
  const entry = directory.get(kid);
  if (!entry) {
    // No keys at all, or another request is still fetching the directories: retryable, not a forgery.
    const retryable = !directory.size || (!keys && activeRefresh && now - activeRefresh.at < REFRESH_TIMEOUT_MS);
    if (retryable) throw new VendorError(503, "Rose integration unavailable");
    throw invalid();
  }

  const digest = `sha-256=:${base64(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)))}:`;
  if (request.headers.get("Content-Digest") !== digest) throw invalid();
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
    throw invalid();
  }
  return { buyerId, environment: entry.environment };
}
