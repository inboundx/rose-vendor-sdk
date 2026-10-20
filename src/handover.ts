import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import { BUYER_ID, type Buyer, EMAIL, VendorError, origin, trustedUrl } from "./http.js";

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

const MAX_LIFETIME_S = 300; // a proof or event is valid for five minutes at most
const CLOCK_SKEW_S = 30;
const MAX_AUTH_AGE_S = 3600; // the person signed in within the last hour
const isSeconds = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);
type Token = JWTPayload & { sub: string; jti: string; iat: number; exp: number };

/** Cryptographic checks only: atomically enforce replay, ownership and revocation in your database. */
export function createHandoverVerifier(config: HandoverConfig) {
  trustedUrl(config.issuer);
  if (!["test", "production"].includes(config.environment) || !config.clientId ||
      !config.allowedSources.length || !config.jwks.keys.length) throw new Error("Invalid Handover trust configuration");
  // A private EC key ("d") or a shared secret ("k") does not belong in a verifier.
  if (config.jwks.keys.some(key => "d" in key || "k" in key)) throw new Error("Handover keys must be public");
  // Copied now, so later changes to `config` do not change what this verifier trusts.
  const { issuer, environment, clientId } = config;
  const audience = origin(config.audience);
  const sources = new Set(config.allowedSources);
  const keys = createLocalJWKSet(structuredClone(config.jwks));
  const reject = () => new VendorError(401, "Invalid Rose identity proof");

  /** Checks shared by claims and revocation events: signature, type, issuer, audience, environment, lifetime. */
  async function verify(token: string, typ: string): Promise<Token> {
    let p: JWTPayload;
    try {
      if (typeof token !== "string" || token.length > 8192) throw new Error("Invalid token");
      ({ payload: p } = await jwtVerify(token, keys, {
        issuer, audience, algorithms: ["ES256"], typ,
        requiredClaims: ["iss", "aud", "sub", "jti", "iat", "exp"], clockTolerance: 0,
      }));
    } catch { throw reject(); }
    const { sub, jti, iat, exp } = p;
    const now = Math.floor(Date.now() / 1000);
    const ids = typeof sub === "string" && BUYER_ID.test(sub) && typeof jti === "string" && jti.length > 0 && jti.length <= 128;
    const times = isSeconds(iat) && isSeconds(exp) && exp > iat && exp - iat <= MAX_LIFETIME_S && iat <= now + CLOCK_SKEW_S;
    // jose accepts an audience array that contains ours; require exactly ours.
    const forUs = p.aud === audience && p.environment === environment;
    if (!ids || !times || !forUs) throw reject();
    return p as Token;
  }

  return {
    async verifyClaim(token: string, expected: { registrationId: string; userCode: string }): Promise<VerifiedClaim> {
      const p = await verify(token, "oauth-id-jag+jwt");
      const { email, identity_source: source, auth_time: authTime } = p;
      const now = Math.floor(Date.now() / 1000);
      const forTrial = !!expected.registrationId && /^\d{6}$/.test(expected.userCode) &&
        p.registration_id === expected.registrationId && p.user_code === expected.userCode;
      const person = p.client_id === clientId && p.email_verified === true &&
        typeof email === "string" && EMAIL.test(email) && typeof source === "string" && sources.has(source);
      const recent = isSeconds(authTime) && authTime <= now + CLOCK_SKEW_S && now - authTime <= MAX_AUTH_AGE_S;
      if (!forTrial || !person || !recent) throw reject();
      return { buyerId: p.sub, environment, registrationId: expected.registrationId,
        userCode: expected.userCode, email, identitySource: source,
        authenticatedAt: authTime, proofId: p.jti, expiresAt: p.exp };
    },
    async verifyRevocation(token: string): Promise<VerifiedRevocation> {
      const p = await verify(token, "secevent+jwt");
      const { events } = p;
      const onlyRevocation = !!events && typeof events === "object" && !Array.isArray(events) &&
        Object.keys(events).length === 1 && Object.hasOwn(events, REVOKED_EVENT);
      if (!onlyRevocation) throw new VendorError(401, "Invalid Rose revocation event");
      return { buyerId: p.sub, environment, eventId: p.jti, issuedAt: p.iat, expiresAt: p.exp };
    },
  };
}
