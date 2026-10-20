export type Environment = "test" | "production";
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Buyer { buyerId: string; environment: Environment }
/** A buyer ID as Rose sends it: a lowercase UUID. The same buyer must match in every token. */
export const BUYER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** An expected product error. Unexpected exceptions are never returned to callers. */
export class VendorError extends Error {
  constructor(public readonly status: number, public readonly detail: Json) {
    super("Vendor request failed");
    if (![400, 401, 402, 403, 404, 409, 413, 422, 429, 503].includes(status)) {
      throw new Error("Unsupported vendor error status");
    }
  }
}

export function json(value: Json, status = 200): Response {
  return Response.json(value, { status, headers: {
    "Cache-Control": "no-store", "Pragma": "no-cache", "X-Robots-Tag": "noindex, nofollow",
  } });
}

export async function readBytes(request: Request, limit: number): Promise<Uint8Array> {
  if (Number(request.headers.get("content-length") ?? 0) > limit) {
    throw new VendorError(413, "Request too large");
  }
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new VendorError(413, "Request too large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export function object(bytes: Uint8Array): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch { /* Return a public validation error, without including product input. */ }
  throw new VendorError(422, "Expected a JSON object");
}

export function input(value: unknown): { [key: string]: Json } {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new VendorError(422, "Expected an input object");
  }
  // The only caller passes a value parsed from JSON.
  return value as { [key: string]: Json };
}

export function text(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim() || value.length > 1024) {
    throw new VendorError(422, `Invalid ${name}`);
  }
  return value;
}

export const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** HTTPS (HTTP only on loopback, for development), without credentials, query or fragment. */
export function trustedUrl(value: string): URL {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || url.search || url.hash) {
    throw new Error("Use an HTTPS URL (HTTP is allowed only for loopback development)");
  }
  return url;
}

export function origin(value: string): string {
  const url = trustedUrl(value);
  if (url.pathname !== "/") throw new Error("Use an HTTPS origin, without a path");
  return url.origin;
}
