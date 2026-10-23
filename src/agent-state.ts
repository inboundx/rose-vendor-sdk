/**
 * The agent-access lifecycle (auth.md registration, claim, exchange, revocation) as pure state
 * changes. Your store runs `applyAgentChange` inside one transaction over the records that
 * `agentChangeKeys` names, so every check and write of a change is atomic on any database.
 */
import type { Json } from "./http.js";

export const CLAIM_SECONDS = 900; // a registration can be claimed for 15 minutes
const MAX_CODE_ATTEMPTS = 5;
const MAX_CODE_REISSUES = 5;
const POLL_INTERVAL_MS = 5000;

/** One agent registration, stored with its account. Times are milliseconds unless named in seconds. */
export interface AgentState {
  kind: "anonymous" | "service_auth";
  status: "pending" | "claimed" | "revoked";
  environment: "test" | "production";
  expires: number;
  credentialExpires: number;
  trialLimit: number;
  codeHash: string;
  claimHash: string;
  assertionId: string;
  exchanged: boolean;
  attempts: number;
  lastPoll: number;
  claimInitiations: number;
  loginHint: string | null;
  identitySource?: string;
  authenticatedAt?: number; // seconds
  proofIssuedAt?: number; // seconds
  revokedAt?: number; // seconds
}

export interface AgentKey { id: string; apiKey: string }

/** `account:<id>`: who owns the account at your product, and the agent's credential. */
export interface AccountRecord {
  owner?: string; // `<environment>:<buyer id>`
  agent?: AgentState;
  key?: AgentKey;
  staleKeys?: string[]; // keys to revoke at your product
  claimedBy?: string; // email of the claim to record at your product; no key until then
  trial?: { expires: number; maxUses: number; revoked?: boolean }; // started by a trusted issuer: a trial key until `expires`, until a signed provision upgrades it
}

/** `buyer:<environment>:<buyer id>`: the buyer's one account, used proofs and revocation cutoff. */
export interface BuyerRecord {
  account?: string;
  seen: Record<string, number>; // proof id -> expiry (ms)
  revocations: Record<string, number>; // completed event id -> expiry (ms)
  revokedAt?: number; // seconds
}

export type AgentChange =
  | { type: "consume_trial_proof"; id: string; expires: number }
  | { type: "register"; account: string; state: AgentState }
  | { type: "code"; account: string; claimHash: string; email: string; codeHash: string }
  | { type: "claim"; account: string; owner: string; email: string; codeHash: string; proofId: string; proofExpires: number;
      source: string; authTime: number; issuedAt: number; credentialExpires: number; assertionId: string }
  | { type: "exchange"; account: string; assertionId: string }
  | { type: "resume"; account: string; claimHash: string }
  | { type: "revoke_token"; account: string; apiKey: string }
  | { type: "revoke_owner"; owner: string; account: string | null; eventId: string; eventExpires: number; issuedAt: number }
  | { type: "revocation_done"; owner: string; eventId: string; eventExpires: number }
  | { type: "provision"; owner: string; account: string }
  | { type: "issuer_trial"; owner: string; account: string; expires: number; maxUses: number; issuedAt: number }
  | { type: "trial_upgrade"; owner: string; account: string }
  | { type: "set_key"; account: string; key: AgentKey; scope: "trial" | "full" }
  | { type: "claim_recorded"; account: string; email: string }
  | { type: "key_revoked"; account: string; keyId: string };

/** `ok` with details, or `error` with an auth.md error code. */
export type AgentOutcome = { [key: string]: Json };

export function accountKey(account: string): string { return `account:${account}`; }
export function buyerKey(owner: string): string { return `buyer:${owner}`; }

/** The records a change reads and may write: load these, locked, before `applyAgentChange`. */
export function agentChangeKeys(change: AgentChange): string[] {
  switch (change.type) {
    case "consume_trial_proof":
      return [`trial-proof:${change.id.slice(0, 2)}`];
    case "claim":
      return [accountKey(change.account), buyerKey(change.owner)];
    case "provision":
    case "issuer_trial":
      return [accountKey(change.account), buyerKey(change.owner)];
    case "revoke_owner":
      return change.account ? [buyerKey(change.owner), accountKey(change.account)] : [buyerKey(change.owner)];
    case "revocation_done":
      return [buyerKey(change.owner)];
    default:
      return [accountKey(change.account)];
  }
}

/** The grant an account's agent key should carry now, or null when it may hold none. */
export function keyGrant(record: AccountRecord | undefined, now: number): { scope: "trial" | "full"; expiresAt?: number; maxUses?: number } | null {
  if ((!record?.owner && !record?.agent) || record.claimedBy) return null;
  const agent = record.agent;
  if (!agent) {
    if (!record.trial) return { scope: "full" };
    return record.trial.expires > now ? { scope: "trial", expiresAt: record.trial.expires, maxUses: record.trial.maxUses } : null;
  }
  if (agent.status === "claimed") return agent.credentialExpires > now ? { scope: "full", expiresAt: agent.credentialExpires } : null;
  if (agent.status === "pending" && agent.kind === "anonymous" && agent.expires > now) {
    return { scope: "trial", expiresAt: agent.expires, maxUses: agent.trialLimit };
  }
  return null;
}

function equal(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function fresh(seen: Record<string, number>, now: number): Record<string, number> {
  return Object.fromEntries(Object.entries(seen).filter(([, expiry]) => expiry > now));
}

/** Revoke the agent's delegation: its key goes stale, resume and exchange stop. */
function retireKey(record: AccountRecord): void {
  if (record.key) record.staleKeys = [...(record.staleKeys ?? []), record.key.id];
  delete record.key;
}

/** End an issuer trial for good: its key goes stale and no assertion can bring it back. */
function endTrial(record: AccountRecord): void {
  if (record.trial) Object.assign(record.trial, { expires: 0, revoked: true });
  retireKey(record);
}

function revoke(record: AccountRecord, agent: AgentState, issuedAt: number): void {
  agent.status = "revoked";
  agent.revokedAt = Math.max(agent.revokedAt ?? 0, issuedAt);
  retireKey(record);
}

/**
 * Apply one change to the records named by `agentChangeKeys` (missing records are undefined).
 * Persist every entry of `writes` (null deletes) in the same transaction, then return `outcome`.
 */
export function applyAgentChange(change: AgentChange, records: Record<string, Json | undefined>, now: number):
  { writes: Record<string, Json | null>; outcome: AgentOutcome } {
  const writes: Record<string, Json | null> = {};
  const load = <T>(key: string): T | undefined => records[key] === undefined ? undefined : structuredClone(records[key]) as T;
  const save = (key: string, value: AccountRecord | BuyerRecord) => { writes[key] = value as unknown as Json; };
  const fail = (error: string): { writes: typeof writes; outcome: AgentOutcome } => ({ writes, outcome: { error } });
  const done = (outcome: AgentOutcome = {}) => ({ writes, outcome: { ok: true, ...outcome } });

  switch (change.type) {
    case "consume_trial_proof": {
      // Fixed shards avoid one permanent row per anonymous request. Expired entries are
      // pruned on each redemption; a full shard fails closed instead of evicting live proofs.
      if (!/^[0-9a-f]{64}$/.test(change.id) || !Number.isSafeInteger(change.expires) ||
          change.expires <= now || change.expires > now + 600_000) return fail("invalid_proof");
      const key = `trial-proof:${change.id.slice(0, 2)}`;
      const seen = fresh(load<Record<string, number>>(key) ?? {}, now);
      if (seen[change.id]) return fail("replay_detected");
      if (Object.keys(seen).length >= 1024) return fail("proof_capacity_reached");
      seen[change.id] = change.expires;
      writes[key] = seen;
      return done();
    }

    case "register": {
      if (records[accountKey(change.account)] !== undefined) return fail("conflict");
      save(accountKey(change.account), { agent: change.state });
      return done();
    }

    case "code": {
      const record = load<AccountRecord>(accountKey(change.account)), agent = record?.agent;
      if (!record || !agent || !equal(agent.claimHash, change.claimHash)) return fail("invalid_claim_token");
      if (agent.status !== "pending" || agent.expires <= now) return fail("expired_token");
      if (agent.kind === "service_auth" && agent.loginHint?.toLowerCase() !== change.email.toLowerCase()) return fail("wrong_account");
      if (agent.claimInitiations >= MAX_CODE_REISSUES) return fail("claim_limit_reached");
      Object.assign(agent, { codeHash: change.codeHash, attempts: 0, loginHint: change.email, claimInitiations: agent.claimInitiations + 1 });
      save(accountKey(change.account), record);
      return done();
    }

    case "claim": {
      const buyer = load<BuyerRecord>(buyerKey(change.owner)) ?? { seen: {}, revocations: {} };
      const cutoff = buyer.revokedAt;
      if (cutoff !== undefined && (change.authTime <= cutoff || change.issuedAt <= cutoff)) return fail("fresh_authentication_required");
      buyer.seen = fresh(buyer.seen, now);
      if (buyer.seen[change.proofId]) return fail("replay_detected");
      buyer.seen[change.proofId] = change.proofExpires;
      save(buyerKey(change.owner), buyer); // a proof is spent even when the claim fails
      if (buyer.account && buyer.account !== change.account) return fail("account_conflict");

      const record = load<AccountRecord>(accountKey(change.account)), agent = record?.agent;
      if (!record || !agent) return fail("unknown");
      const renewal = record.owner === change.owner;
      if (record.owner && !renewal) return fail("not_owner");
      if (agent.revokedAt !== undefined && (change.authTime <= agent.revokedAt || change.issuedAt <= agent.revokedAt)) return fail("fresh_authentication_required");
      if (!renewal && (agent.status === "revoked" || agent.expires <= now || agent.attempts >= MAX_CODE_ATTEMPTS)) return fail("expired_token");
      agent.attempts += 1;
      save(accountKey(change.account), record);
      if (!equal(agent.codeHash, change.codeHash)) return fail("invalid_code");
      if (!change.owner.startsWith(`${agent.environment}:`)) return fail("not_owner");
      if (agent.loginHint && agent.loginHint.toLowerCase() !== change.email.toLowerCase()) return fail("wrong_account");

      record.owner = change.owner;
      record.claimedBy = change.email;
      buyer.account = change.account;
      retireKey(record); // the trial's key stops working
      Object.assign(agent, {
        status: "claimed", identitySource: change.source, authenticatedAt: change.authTime, proofIssuedAt: change.issuedAt,
        credentialExpires: change.credentialExpires, assertionId: change.assertionId, exchanged: false,
        expires: now + CLAIM_SECONDS * 1000, // the original agent may resume for 15 minutes
      });
      save(accountKey(change.account), record);
      save(buyerKey(change.owner), buyer);
      return done({ first: !renewal });
    }

    case "exchange": {
      const record = load<AccountRecord>(accountKey(change.account)), agent = record?.agent;
      if (!record || !agent || agent.assertionId !== change.assertionId || agent.exchanged) return fail("invalid_grant");
      if (agent.credentialExpires <= now || agent.status === "revoked" ||
          (agent.status === "pending" && (agent.expires <= now || agent.kind !== "anonymous"))) return fail("invalid_grant");
      agent.exchanged = true;
      save(accountKey(change.account), record);
      return done({ scope: agent.status === "claimed" ? "full" : "trial", expires: agent.credentialExpires });
    }

    case "resume": {
      const record = load<AccountRecord>(accountKey(change.account)), agent = record?.agent;
      if (!record || !agent || !equal(agent.claimHash, change.claimHash)) return fail("expired_token");
      if (agent.status === "revoked" || agent.credentialExpires <= now || agent.expires <= now) return fail("expired_token");
      if (now - agent.lastPoll < POLL_INTERVAL_MS) return fail("slow_down");
      agent.lastPoll = now;
      save(accountKey(change.account), record);
      if (agent.status !== "claimed") return fail("authorization_pending");
      return done({ scope: "full", expires: agent.credentialExpires });
    }

    case "revoke_token": {
      const record = load<AccountRecord>(accountKey(change.account)), agent = record?.agent;
      if (!record || !record.key || !equal(record.key.apiKey, change.apiKey) || (!agent && !record.trial)) return done({ revoked: false });
      if (agent) revoke(record, agent, Math.floor(now / 1000));
      else endTrial(record);
      save(accountKey(change.account), record);
      return done({ revoked: true });
    }

    case "revoke_owner": {
      const buyer = load<BuyerRecord>(buyerKey(change.owner)) ?? { seen: {}, revocations: {} };
      buyer.revocations = fresh(buyer.revocations, now);
      if (buyer.revocations[change.eventId]) return done({ replay: true });
      if ((buyer.account ?? null) !== change.account) return fail("moved"); // read again and retry
      buyer.revokedAt = Math.max(buyer.revokedAt ?? 0, change.issuedAt);
      save(buyerKey(change.owner), buyer);
      const record = change.account ? load<AccountRecord>(accountKey(change.account)) : undefined, agent = record?.agent;
      if (record && agent && record.owner === change.owner) {
        // A retried or delayed event must not disable credentials granted after its cutoff.
        if ((agent.authenticatedAt ?? 0) > change.issuedAt && (agent.proofIssuedAt ?? 0) > change.issuedAt) {
          agent.revokedAt = Math.max(agent.revokedAt ?? 0, change.issuedAt);
        } else {
          revoke(record, agent, change.issuedAt);
        }
        save(accountKey(change.account as string), record);
      } else if (record && !agent && record.trial && record.owner === change.owner) {
        endTrial(record);
        save(accountKey(change.account as string), record);
      }
      return done();
    }

    case "revocation_done": {
      const buyer = load<BuyerRecord>(buyerKey(change.owner)) ?? { seen: {}, revocations: {} };
      buyer.revocations = { ...fresh(buyer.revocations, now), [change.eventId]: change.eventExpires };
      save(buyerKey(change.owner), buyer);
      return done();
    }

    case "provision": {
      const buyer = load<BuyerRecord>(buyerKey(change.owner)) ?? { seen: {}, revocations: {} };
      if (buyer.account) return done({ account: buyer.account, created: false });
      const record = load<AccountRecord>(accountKey(change.account)) ?? {};
      if ((record.owner && record.owner !== change.owner) || record.agent) return fail("not_owner");
      record.owner = change.owner;
      buyer.account = change.account;
      save(accountKey(change.account), record);
      save(buyerKey(change.owner), buyer);
      return done({ account: change.account, created: true });
    }

    case "issuer_trial": {
      // One trial per person: a later request finds the same account, expired or not.
      const buyer = load<BuyerRecord>(buyerKey(change.owner)) ?? { seen: {}, revocations: {} };
      if (buyer.account) return done({ account: buyer.account, created: false });
      // A token issued before an acknowledged revocation cannot start a trial.
      if (buyer.revokedAt !== undefined && change.issuedAt <= buyer.revokedAt) return fail("fresh_authentication_required");
      if (records[accountKey(change.account)] !== undefined) return fail("account_conflict");
      buyer.account = change.account;
      save(accountKey(change.account), { owner: change.owner, trial: { expires: change.expires, maxUses: change.maxUses } });
      save(buyerKey(change.owner), buyer);
      return done({ account: change.account, created: true });
    }

    case "trial_upgrade": {
      // The signed contract provisions the buyer's account: a trial that was not revoked becomes that account.
      const record = load<AccountRecord>(accountKey(change.account));
      if (!record || record.owner !== change.owner || record.agent || !record.trial || record.trial.revoked) return done({ upgraded: false });
      delete record.trial;
      retireKey(record); // the trial's key stops working; the account's full key comes with its checkout
      save(accountKey(change.account), record);
      return done({ upgraded: true });
    }

    case "set_key": {
      const record = load<AccountRecord>(accountKey(change.account));
      // A key issued for the trial must not become the claimed account's key, nor the reverse; the stored key
      // is returned only when its scope is still the one asked for.
      if (!record || keyGrant(record, now)?.scope !== change.scope) return fail("restricted");
      if (record.key) return done({ key: record.key as unknown as Json, kept: true });
      record.key = change.key;
      save(accountKey(change.account), record);
      return done({ key: change.key as unknown as Json, kept: false });
    }

    case "claim_recorded": {
      const record = load<AccountRecord>(accountKey(change.account));
      if (record?.claimedBy !== change.email) return done();
      delete record.claimedBy;
      save(accountKey(change.account), record);
      return done();
    }

    case "key_revoked": {
      const record = load<AccountRecord>(accountKey(change.account));
      if (!record?.staleKeys?.includes(change.keyId)) return done();
      record.staleKeys = record.staleKeys.filter((id) => id !== change.keyId);
      save(accountKey(change.account), record);
      return done();
    }
  }
}
