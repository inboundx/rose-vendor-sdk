/** auth.md for a vendor, in the section layout of auth.md v0.6 (https://github.com/workos/auth.md). */

export interface SkillText {
  issuer: string;
  name: string;
  about: string;
  apiUrl: string;
  usage: string;
  scopes: { trial: string; full: string };
  trialLimit: number;
}

export function agentSkill({ issuer, name, about, apiUrl, usage, scopes, trialLimit }: SkillText): string {
  return `# auth.md

You are an agent. ${name} supports **agentic registration**: discover, register, (claim if
needed), exchange for an access_token, call the API, handle revocation. Follow the steps in
order.

${about}

Authorization server and API: \`${issuer}\`.

## Step 1 — Discover

### 1a. Fetch the Protected Resource Metadata

\`\`\`http
GET ${issuer}/.well-known/oauth-protected-resource
\`\`\`

\`resource\` is the API (\`${apiUrl}\`), \`authorization_servers\` is \`["${issuer}"]\`,
\`scopes_supported\` is \`["${scopes.trial}", "${scopes.full}"]\`, \`bearer_methods_supported\` is \`["header"]\`.

### 1b. Fetch the Authorization Server metadata

\`\`\`http
GET ${issuer}/.well-known/oauth-authorization-server
\`\`\`

It carries \`token_endpoint\`, \`revocation_endpoint\`, \`jwks_uri\`, \`grant_types_supported\` and the
\`agent_auth\` block: \`skill\` (this file), \`identity_endpoint\`, \`claim_endpoint\`,
\`events_endpoint\`, \`identity_types_supported\` and \`identity_assertion.assertion_types_supported\`.
Its \`extensions\` list what ${name} adds to the profile (a ceremony on anonymous registration, and
the claim completion Rose's sign-in page calls).

## Step 2 — Pick a method

1. **You have the user's email** → \`service_auth\`. The claim ceremony is required before any
   access.
2. **You have nothing** → \`anonymous\`: a 15-minute trial of ${trialLimit} calls at once, which the
   user can claim to keep the account.

\`identity_assertion\` accepts only an ID-JAG that Rose, ${name}'s identity provider, issued for an
existing registration and its code, during the claim (Step 4). ${name} trusts no other issuer.

## Step 3 — Register

Before \`service_auth\`, tell the user you are registering them with ${name}
and get their yes.

### anonymous

\`\`\`http
POST ${issuer}/agent/identity
Content-Type: application/json

{"type": "anonymous"}
\`\`\`

Response (200): \`registration_id\`, \`registration_type\`, \`identity_assertion\`, \`assertion_expires\`,
\`pre_claim_scopes\` (\`["${scopes.trial}"]\`), \`claim_url\`, \`claim_token\`, \`claim_token_expires\`,
\`post_claim_scopes\` (\`["${scopes.full}"]\`). ${name} also returns a \`claim\` block, so you can skip 4a.
Go to Step 5 to use the trial now.

### service_auth

\`\`\`http
POST ${issuer}/agent/identity
Content-Type: application/json

{"type": "service_auth", "login_hint": "user@example.com"}
\`\`\`

Response (200): \`registration_id\`, \`registration_type\`, \`claim_url\`, \`claim_token\`,
\`claim_token_expires\`, \`post_claim_scopes\` and the \`claim\` block (\`user_code\`, \`verification_uri\`,
\`expires_in\`, \`interval\`). No \`identity_assertion\` until the user claims. Go to Step 4.

### identity_assertion + id-jag

\`\`\`http
POST ${issuer}/agent/identity
Content-Type: application/json

{"type": "identity_assertion", "assertion_type": "urn:ietf:params:oauth:token-type:id-jag", "assertion": "<ID-JAG from Rose>"}
\`\`\`

Only for an ID-JAG Rose issued for an existing registration (see Step 2). The response (200) is \`{"status": "claimed", "account_id", "identity_assertion"}\`: go to
Step 5.

\`claim_token\` is returned once: keep it in memory until Step 4 ends; never show it to the user.

## Step 4 — Claim ceremony

### 4a. Get the ceremony materials

For a new code (or an anonymous registration without one):

\`\`\`http
POST ${issuer}/agent/identity/claim
Content-Type: application/json

{"claim_token": "clm_...", "email": "user@example.com"}
\`\`\`

The \`claim_attempt\` block has the same fields as \`claim\`. It does not extend the trial.

### 4b. Hand off to the user

> Open this link, sign in, and enter this 6-digit code: **123456**
> ${issuer}/claim?registration_id=acct_...

The link sends them to Rose's sign-in, ${name}'s identity provider. The code goes into that page,
not back to you.

### 4c. Poll for completion

\`\`\`http
POST ${issuer}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:workos:agent-auth:grant-type:claim&claim_token=clm_...
\`\`\`

At most every 5 seconds: \`authorization_pending\` means wait, \`slow_down\` means poll less often,
\`expired_token\` means stop. On success you get a token response for the same account and usage;
claiming replaces the trial key, and the old key and assertion stop working. Polling can resume a
claimed account for 15 minutes after the claim.

## Step 5 — Exchange the assertion

\`\`\`http
POST ${issuer}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<identity_assertion>
\`\`\`

Response (200): \`{"access_token", "token_type": "Bearer", "expires_in", "scope", "account_id",
"api_url"}\`. Each assertion exchanges once and expires after 5 minutes; \`invalid_grant\` means
restart at Step 3.

## Step 6 — Use the access_token

${usage}

The access token is ${name}'s API key. Claimed credentials expire within one hour; renewing them
needs the user's consent again.

## Errors

| Code | Where | What to do |
|---|---|---|
| \`invalid_request\` | \`/agent/identity\`, \`/agent/identity/claim\` | Fix the body. |
| \`unsupported_identity_type\` | \`/agent/identity\` | Use one of the three types above. |
| \`invalid_login_hint\` | \`/agent/identity\` | Send the user's email address. |
| \`unsupported_assertion_type\` | \`/agent/identity\` | Only ID-JAG is accepted. |
| \`unaccepted_identity\` | \`/agent/identity\` | The ID-JAG is not from Rose or not fresh: use \`service_auth\` or \`anonymous\`. |
| \`account_conflict\` (409) | \`/agent/identity\` | The user already has an account: a person must resolve it; never merge silently. |
| \`invalid_claim_token\`, \`expired_token\` | \`/agent/identity/claim\` | Restart at Step 3. |
| \`authorization_pending\` | \`/oauth2/token\` | Wait 5 seconds and poll again. |
| \`slow_down\` | \`/oauth2/token\` | Poll less often. |
| \`expired_token\` | \`/oauth2/token\` | Restart at Step 3. |
| \`invalid_grant\` | \`/oauth2/token\` | Restart at Step 3. |
| \`unsupported_grant_type\` | \`/oauth2/token\` | Use one of the two grants above. |
| \`not_enabled\` (404) | any | Agent registration is off on this deployment. |
| \`rate_limited\` (429) | any | Back off and retry later. |
| \`temporarily_unavailable\` (503) | \`/oauth2/token\`, \`/oauth2/revoke\` | Retry the same request in a few seconds; a token you were revoking still works. |

## Revocation

- **Credential layer:** \`POST ${issuer}/oauth2/revoke\` with \`token=<access_token>\` (form-encoded);
  200 once it no longer works.
- **Registration layer:** Rose POSTs a revocation Security Event Token to \`${issuer}/agent/events\`
  when the user unlinks ${name}. You notice it as \`invalid_grant\`: restart at Step 3.
`;
}
