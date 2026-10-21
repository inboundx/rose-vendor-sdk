/** Optional anonymous-trial friction; identity and proof redemption both fail closed. */
import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT } from "jose";
import { challenges, verifySolutions, type HashwxPuzzle } from "./hashwx.js";
import type { AgentConfig } from "./agent.js";
import { readBytes, VendorError } from "./http.js";
import { verifyRequest } from "./signature.js";


export type TrialProtectionLevel = "off" | "low" | "medium" | "high";
export type TrialProtection = TrialProtectionLevel | "rose";
const DIFFICULTY = { low: 250_000, medium: 1_000_000, high: 3_000_000 };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const levels: readonly string[] = ["off", "low", "medium", "high"];

function error(code: string, status: number): Response {
  return Response.json({ error: code }, { status, headers: { "Cache-Control": "no-store", Pragma: "no-cache" } });
}

async function digest(value: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function levelFor(config: AgentConfig): Promise<TrialProtectionLevel> {
  const setting = config.trialProtection ?? "off";
  if (setting !== "rose") {
    if (!levels.includes(setting)) throw new Error("Invalid trialProtection");
    return setting;
  }
  const url = `${config.rose.issuer.replace(/\/$/, "")}/trial-policy/${encodeURIComponent(config.consent.vendor)}`;
  // workerd supports manual/follow only; reject 3xx below without following policy redirects.
  const response = await fetch(url, { signal: AbortSignal.timeout(5000), redirect: "manual", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("Trial policy unavailable");
  const policy = JSON.parse(new TextDecoder().decode(await readBytes(response, 4096))) as Record<string, unknown>;
  if (!levels.includes(String(policy.level)) || policy.audience !== config.origin || policy.environment !== config.environment) {
    throw new Error("Invalid trial policy");
  }
  return policy.level as TrialProtectionLevel;
}

/** Return a refusal/challenge, or null once a registration may create an account. */
export async function trialGate(config: AgentConfig, request: Request, data: Record<string, unknown>, bytes: Uint8Array): Promise<Response | null> {
  // A signed Rose call is identity evidence only after verification of the exact request.
  // Consume its signed nonce even when protection is off: replaying one exempt request
  // must not mint multiple accounts. No email or assistant bearer token is accepted here.
  if (["Signature", "Signature-Input", "X-R4A-Buyer"].some((name) => request.headers.has(name))) {
    try {
      const buyer = await verifyRequest(request, bytes, config.roseRequestKeys);
      if (buyer.environment !== config.environment || typeof data.registration_nonce !== "string" || !UUID.test(data.registration_nonce)) {
        return error("invalid_rose_identity", 401);
      }
      const id = await digest(JSON.stringify(["rose-registration", config.origin, buyer.environment, buyer.buyerId, data.registration_nonce]));
      const expiry = /;expires=(\d+);/.exec(request.headers.get("Signature-Input") ?? "")?.[1];
      const outcome = await config.store.apply({ type: "consume_trial_proof", id, expires: Number(expiry) * 1000 });
      if (outcome.error) return error(String(outcome.error), outcome.error === "replay_detected" ? 409 : 503);
      return null;
    } catch (cause) {
      return error(cause instanceof VendorError && cause.status === 401 ? "invalid_rose_identity" : "temporarily_unavailable",
        cause instanceof VendorError && cause.status === 401 ? 401 : 503);
    }
  }

  let stage = "policy";
  try {
    const level = await levelFor(config);
    if (level === "off") return null;
    stage = "verification";
    const scope = JSON.stringify(["rose-anonymous-trial-v1", config.origin, config.environment, level]);
    const submitted = data.proof_of_work;
    if (submitted && typeof submitted === "object" && !Array.isArray(submitted)) {
      const body = submitted as { token?: unknown; solutions?: unknown };
      if (typeof body.token === "string" && Array.isArray(body.solutions) && body.solutions.length === 4) {
        let proof: { id: string; expires: number; puzzles: HashwxPuzzle[] } | null = null;
        try {
          const { payload } = await jwtVerify(body.token, createLocalJWKSet(config.signing.jwks), {
            issuer: config.origin, audience: config.origin, algorithms: ["ES256"], typ: "rose-trial-pow+jwt",
            requiredClaims: ["iss", "aud", "jti", "iat", "exp", "scope", "challenges"],
          });
          if (payload.scope === scope && typeof payload.jti === "string" && UUID.test(payload.jti) &&
              typeof payload.iat === "number" && typeof payload.exp === "number" && payload.exp - payload.iat === 300 &&
              payload.iat <= Date.now() / 1000 && Array.isArray(payload.challenges) && payload.challenges.length === 4) {
            const puzzles = payload.challenges as HashwxPuzzle[];
            if (puzzles.every((p) => p?.protocol === "hashwx" && p.payload?.d === DIFFICULTY[level] / 4 &&
                p.payload.n === 65536 && /^[0-9a-f]{64}$/.test(p.payload.c))) {
              proof = { id: await digest(`${scope}\n${payload.jti}`), expires: payload.exp * 1000, puzzles };
            }
          }
        } catch { /* An invalid/expired proof receives a fresh challenge, never access. */ }
        if (proof && await verifySolutions(proof.puzzles, body.solutions)) {
          const outcome = await config.store.apply({ type: "consume_trial_proof", id: proof.id, expires: proof.expires });
          if (!outcome.error) return null;
          return error(outcome.error === "replay_detected" ? "replay_detected" : "temporarily_unavailable",
            outcome.error === "replay_detected" ? 409 : 503);
        }
      }
    }
    stage = "challenge";
    const puzzles = challenges(DIFFICULTY[level]), now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ scope, challenges: puzzles }).setProtectedHeader({ typ: "rose-trial-pow+jwt", alg: "ES256",
      kid: config.signing.jwks.keys[0]?.kid ?? "" }).setIssuer(config.origin).setAudience(config.origin).setJti(crypto.randomUUID())
      .setIssuedAt(now).setExpirationTime(now + 300).sign(await importPKCS8(config.signing.privateKey, "ES256"));
    const challenge = { token, format: 2, challenges: puzzles, expires: (now + 300) * 1000 };
    return Response.json({ error: "proof_of_work_required", proof_of_work: challenge }, {
      status: 428, headers: { "Cache-Control": "no-store", Pragma: "no-cache" },
    });
  } catch (cause) {
    console.error(JSON.stringify({ event: "agent_trial_failure", stage, kind: cause instanceof Error ? cause.name : "unknown" }));
    return error("temporarily_unavailable", 503);
  }
}
