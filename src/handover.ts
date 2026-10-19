import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import { type Buyer, VendorError, origin } from "./http.js";

export const REVOKED_EVENT = "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked";
export interface HandoverConfig {
  issuer: string;
  audience: string;
  environment: Buyer["environment"];
  clientId: string;
  allowedSources: readonly string[];
  /** Public keys provided by Rose. Replace the verifier when the trust configuration rotates. */
  jwks: JSONWebKeySet;
}
export interface VerifiedClaim extends Buyer {
  registrationId: string;
  userCode: string;
  email: string;
  identitySource: string;
  authenticatedAt: number;
  proofId: string;
  expiresAt: number;
}
export interface VerifiedRevocation extends Buyer {
  eventId: string;
  issuedAt: number;
  expiresAt: number;
}

/** Cryptographic checks only: atomically enforce replay, ownership and revocation in your database. */
export function createHandoverVerifier(config: HandoverConfig) {
  const issuer = new URL(config.issuer);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname);
  if ((issuer.protocol !== "https:" && !(local && issuer.protocol === "http:")) ||
      issuer.username || issuer.password || issuer.search || issuer.hash ||
      !["test", "production"].includes(config.environment) || !config.clientId ||
      !config.allowedSources.length || !config.jwks.keys.length ||
      config.jwks.keys.some(key => "d" in key || "k" in key)) throw new Error("Invalid Handover trust configuration");
  const audience = origin(config.audience);
  const sources = new Set(config.allowedSources);
  const keys = createLocalJWKSet(structuredClone(config.jwks));
  const expectedIssuer = config.issuer;
  const environment = config.environment;
  const clientId = config.clientId;

  async function verify(token: string, typ: string): Promise<JWTPayload & {
    sub: string; jti: string; iat: number; exp: number;
  }> {
    try {
      if (typeof token !== "string" || token.length > 8192) throw new Error("Invalid token");
      const { payload: p } = await jwtVerify(token, keys, {
        issuer: expectedIssuer, audience, algorithms: ["ES256"], typ,
        requiredClaims: ["iss", "aud", "sub", "jti", "iat", "exp"], clockTolerance: 0,
      });
      const now = Math.floor(Date.now() / 1000);
      if (typeof p.sub !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(p.sub) ||
          typeof p.jti !== "string" || !p.jti.length || p.jti.length > 128 ||
          !Number.isInteger(p.iat) || !Number.isInteger(p.exp) ||
          typeof p.iat !== "number" || typeof p.exp !== "number" ||
          p.exp <= p.iat || p.exp - p.iat > 300 || p.iat > now + 30 ||
          p.environment !== environment || p.aud !== audience) throw new Error("Invalid claims");
      return p as JWTPayload & { sub: string; jti: string; iat: number; exp: number };
    } catch { throw new VendorError(401, "Invalid Rose identity proof"); }
  }

  return {
    async verifyClaim(token: string, expected: { registrationId: string; userCode: string }): Promise<VerifiedClaim> {
      const p = await verify(token, "oauth-id-jag+jwt");
      const now = Math.floor(Date.now() / 1000);
      if (!expected.registrationId || !/^\d{6}$/.test(expected.userCode) ||
          p.registration_id !== expected.registrationId || p.user_code !== expected.userCode ||
          p.client_id !== clientId || p.email_verified !== true ||
          typeof p.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(p.email) ||
          typeof p.identity_source !== "string" || !sources.has(p.identity_source) ||
          typeof p.auth_time !== "number" || !Number.isInteger(p.auth_time) ||
          p.auth_time > now + 30 || now - p.auth_time > 3600) {
        throw new VendorError(401, "Invalid Rose identity proof");
      }
      return { buyerId: p.sub, environment, registrationId: expected.registrationId,
        userCode: expected.userCode, email: p.email, identitySource: p.identity_source,
        authenticatedAt: p.auth_time, proofId: p.jti, expiresAt: p.exp };
    },
    async verifyRevocation(token: string): Promise<VerifiedRevocation> {
      const p = await verify(token, "secevent+jwt");
      if (!p.events || typeof p.events !== "object" || Array.isArray(p.events) ||
          !Object.hasOwn(p.events, REVOKED_EVENT) || Object.keys(p.events).length !== 1) {
        throw new VendorError(401, "Invalid Rose revocation event");
      }
      return { buyerId: p.sub, environment, eventId: p.jti, issuedAt: p.iat, expiresAt: p.exp };
    },
  };
}
