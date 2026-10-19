# Rose vendor SDK — agent instructions

> `CLAUDE.md` is a symlink to this file.

Server-side TypeScript SDK that vendors install to connect their product to Rose for Agents
(r4a). r4a, its contract documentation and Ibanly (the demo vendor that uses this SDK) live in
the Rose repository (`inboundx/inboundx`).

- **The contract is r4a's.** Paths, payloads and request signing are defined by r4a
  (`backend/apps/r4a_mcp/r4a_mcp/commerce.py` and `docs/src/agents/rose-for-agents.md` in the
  Rose repository). The signature test vector in `test/vendor.test.mjs` is shared with r4a's
  and Ibanly's tests: if it changes, the contract changed. Change r4a first, accepting both the
  old and new behavior, then release the SDK, then bump Ibanly.
- **Verification only, fail closed.** Never accept a query string, an unsigned call or a key
  outside Rose's published directories (`mcp.userose.ai`, `mcp-test.userose.ai`). A
  directory only speaks for its own environment. `keys` is for local development and tests.
- **No promise shared across requests.** Vendors run this on Cloudflare Workers, where awaiting
  another request's promise can hang. See the key refresh in `src/signature.ts`.
- **Keep the client guide in step.** The README's two TypeScript snippets are compiled by
  `scripts/smoke-package.mjs`. Rose's client guide (`docs/src/client/rose-for-agents/sdk-setup.md`)
  must use the same snippets and install tag.
- **Check before finishing:** `npm ci`, `npm test`, `node scripts/smoke-package.mjs`.

## Release

Releasing is an outward action: do it only when asked.

1. Bump `version` in `package.json` and `package-lock.json` (semver; stay on 0.x while the
   contract changes) on a branch, open a PR and squash-merge it: `main` accepts only PRs.
2. Tag the squash commit on `main` (never a branch commit) `v<version>` and push the tag.
3. In the Rose repository, set Ibanly's dependency (`backend/apps/r4a_ibanly/package.json`)
   to `github:inboundx/rose-vendor-sdk#v<version>`, run `just check` there, and open a PR.
   Update the install line in this README and in Rose's client guide to the new tag.

To try an unreleased change in Ibanly, install this checkout there with
`npm install <path to this checkout>` and do not commit that change.
