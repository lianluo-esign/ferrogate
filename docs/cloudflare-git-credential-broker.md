<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, design record for the brokered
  per-operation GitHub credential path for container coding agents (issue #475):
  the credential-helper callback contract, repo-scoped installation-token issuance
  and revocation, pinned host keys, and the verified Cloudflare Secrets Store limits.
-->

# Brokered per-operation GitHub credentials for container coding agents (#475)

**Status: mechanism implemented, deployment pending** (issue #475, implementing
the `CredentialDelivery::BrokeredPerOperation` variant of the #472 contract).

Code: `crates/ferrogate-runtime/src/coding_agent/credential_broker.rs`,
`workers/agent-gateway/src/git-credential.ts`.

## The problem in one sentence

A coding agent inside a Cloudflare Container executes model-authored code over
repo content an attacker may have influenced, so any credential that *rests*
in that container — env var, file, image layer — must be assumed read and
exfiltrated.

## The shape

```
container                          agent-gateway Worker              GitHub
---------                          --------------------              ------
git fetch
  └─ credential.helper ──POST──▶ /git-credential/get
        (run-scoped                  authorize vs. grant:
         callback capability,        run · grant · repo · op · budget
         NOT a GitHub token)              │
                                          ├─ sign App JWT (RS256, ≤10 min)
                                          ├──── POST /app/installations/{id}
                                          │        /access_tokens
                                          │        {repositories:[one],
                                          │         permissions:{…}}      ──▶
                                          │   ◀── {token, expires_at: +1h}
        ◀── username=x-access-token ──────┘
            password=<token>              emit material-free audit row
  └─ git speaks to github.com with it for THIS operation

run finalize (success AND failure)
  control plane ──POST──▶ /git-credential/revoke ── DELETE /installation/token ──▶
```

The container is configured with a **callback binding**, not a credential:
`{ broker_url, run_id, grant_id, audience }` plus a run-scoped bearer
capability. That capability is a *gateway* capability — presenting it to
github.com achieves nothing, it works only against this route, only for this
run, only for the granted repo, only until the grant expires, and every use is
counted and logged.

### What still rests in the container — honest accounting

| Artifact | Where | What injected code gets from it |
|---|---|---|
| GitHub App private key | Worker secret | nothing — never crosses the boundary |
| Installation token | `git` process memory, one operation | must win a race against a live `git` |
| Callback capability | container env/file | ask *this gateway* for git ops on *one* repo, audited and budgeted |
| `known_hosts`, git config | container, world-readable | nothing; public key material |

There is no delivery in which a `git` subprocess authenticates to GitHub
without a credential existing in that subprocess's memory for the length of the
request. What brokering removes is **rest**, **scope**, **duration**, and
**silence**. A stolen callback capability buys exactly the access the run
already had; a stolen `GITHUB_TOKEN` buys durable, silent, off-platform access
to everything that token could reach.

## Wire contract

### `POST /git-credential/get`

Bearer: the run-scoped callback capability.

```json
{
  "runId": "run-1",
  "grantId": "grant-1",
  "operation": "fetch",
  "query": { "protocol": "https", "host": "github.com", "path": "acme/app.git" }
}
```

`query` is git's credential-helper stdin block, forwarded verbatim minus
anything the broker does not authorize on. The Rust `GitCredentialQuery` has
**no `password` field**, so a credential cannot ride back into the control
plane on the request path even if a helper forwards the whole block.

Approved (200):

```json
{ "username": "x-access-token", "password": "<installation token>", "expiresAtUnix": 1800000900 }
```

Refused (403): `{ "error": "<deny code>", "detail": "…" }`. The helper renders a
refusal as an **empty credential block** on stdout, so `git` fails the
operation rather than prompting or retrying.

Deny codes (`broker_deny_codes` in Rust, `DENY` in TypeScript — they must stay
in step): `run_mismatch`, `grant_mismatch`, `grant_expired`,
`delivery_not_brokered`, `protocol_not_https`, `host_not_granted`,
`path_missing`, `repo_not_granted`, `write_not_granted`,
`operation_budget_exhausted`.

### `POST /git-credential/revoke`

`{ "token": "…" }` → `{ "outcome": "revoked" | "already_expired" | "failed", "code"? }`,
mapping onto the #472 `RevocationOutcome`. HTTP 401 from GitHub means the token
is already dead, which *is* neutralization, so it is reported as
`already_expired` rather than a failure.

### `credential.useHttpPath=true` is load-bearing

By default `git` sends a helper only `protocol` and `host`. Without the path
the broker cannot tell `github.com/acme/app` from `github.com/attacker/exfil`
and repo scoping silently degrades to host scoping. `git_helper_config_lines`
sets it, and a pathless callback is denied `path_missing` rather than answered.

The same config clears inherited helpers (`credential.helper=` empty first),
pins `http.sslVerify=true`, clears `url.*.insteadOf`, and sets
`protocol.file.allow=never` / `protocol.ext.allow=never` — the submodule and
URL-rewrite vectors by which repo *content* redirects a git operation at a host
the grant does not cover.

## Issuance and revocation

**Issue** — `POST {api_base}/app/installations/{installation_id}/access_tokens`,
authenticated by a ≤10-minute RS256 App JWT, body
`{"repositories": ["<one repo>"], "permissions": {...}}`. GitHub: *"Installation
tokens expire one hour from the time you create them."* The expiry is **not**
requestable, so:

- **Repo scoping** is structural: `InstallationTokenRequest` has no constructor
  that accepts more than one repository.
- **Permissions** are *derived* from the #472 `RepoCredentialScope`, never
  passed in, so a caller cannot widen past what the grant justified.
  `contents:read` by default; `contents:write` and `pull_requests:write` only
  from a `WriteBackGrant`.
- **Lifetime** is `min(grant expiry, now + 1h, now + MAX_REPO_CREDENTIAL_TTL)`.
  GitHub's hour can only ever be shortened by the grant, never extended.

**Revoke** — `DELETE {api_base}/installation/token`, authenticated *with the
token being revoked*, 204 on success. It is the `RevocationPoint` on the
#472 grant, and `CodingRunReceipt` cannot be constructed without a
`CredentialRevocation`, so "revoked on success and on failure" is a property of
the type rather than of anyone's care.

**Budget** — a run gets `DEFAULT_BROKER_OPERATION_BUDGET` (32) callbacks.
Denials consume budget too; otherwise probing the broker is free.

## Host-key verification

`GITHUB_SSH_HOST_KEYS` pins all three keys GitHub publishes (Ed25519, ECDSA
nistp256, RSA), retrieved from GitHub's own `GET /meta` (`ssh_keys`) and
cross-checked against the published `ssh_key_fingerprints` on **2026-07-25**.
`github_known_hosts()` renders the `known_hosts` body baked into the image —
public key material, safe in a layer, and the reason no key exchange has to be
trusted on first use.

`validate_ssh_hardening` refuses any effective `StrictHostKeyChecking` value
other than `yes`/`ask` — including `accept-new`, because a container that
starts fresh every run is *always* on its first use, which makes `accept-new`
indistinguishable from `no`. `validate_transport_env` refuses
`GIT_SSL_NO_VERIFY`, `GIT_SSH_VARIANT`, `SSH_ASKPASS` in the instance
environment.

Pinning means a GitHub key rotation (as in March 2023, when the RSA key was
replaced) requires editing the constant. That is the cost of verification and
it is the correct cost.

## Credential never reaches logs, run events, or #427 memory

Enforced structurally, not by review:

- No Rust type on the authorization path has a field that can hold a token.
  `BrokerDecision::Approve` carries an *authorization*; the Worker performs the
  mint and streams the answer into the helper response. The test
  `no_broker_type_can_render_key_material` renders the broker, the decision and
  the audit event through both `Debug` and serde and asserts no token-shaped
  material appears.
- `GitCredentialAuditEvent` is ids, fingerprints and timestamps only. The
  credential appears as `credential_fingerprint` (`sha256:…` of the `cf://`
  reference), never as a value or a path.
- The Worker never logs the minted token, never persists it in the Durable
  Object, and never returns a GitHub response body in an error — only fixed
  error strings and status codes, because a GitHub body can echo request
  material.

---

## The two constraints the owner's comment flagged — verification results

### 1. Can a Worker bind a whole store and look up a secret by name at runtime?

**No. Verified from Cloudflare docs, 2026-07-25.**
(https://developers.cloudflare.com/secrets-store/integrations/workers/)

The binding names a **single secret** and is fixed at deploy time:

```toml
[[secrets_store_secrets]]
binding     = "<BINDING_VARIABLE>"
store_id    = "<STORE_ID>"
secret_name = "<MY_SECRET_NAME>"
```

and the runtime read is

```js
const apiKey = await env.<BINDING_VARIABLE>.get()
```

`get()` takes **no argument**. Name resolution happens in config, not at call
time. Binding more secrets means more entries and a redeploy. There is no
store-level binding and no runtime enumeration.

**Consequence, stated plainly:** the owner's directive — "all credentials,
including user credentials such as the GitHub token, live in Cloudflare Secrets
Store" — **cannot be implemented as written for per-user credentials.** Not
because of a cap that might be lifted, but because the read path itself is
deploy-time-static. Per-user credentials in Secrets Store would require a
Worker redeploy per user onboarding. This confirms the #418 hybrid tenancy
decision (`docs/cloudflare-secrets-tenancy.md`) rather than superseding it.

**What this design does about it:** it removes the need. Brokering converts a
*per-user* credential problem into a *single platform* credential problem. The
platform stores **one** GitHub App private key; a user's authorization is an
**installation id** — a non-secret integer that belongs in D1 next to the
tenant row. Per-user credentials stop being secrets to store at all. That is
the property that makes the directive's *intent* (no user credential in the
container, all credential material managed centrally on Cloudflare) achievable
on the platform as it actually behaves.

### 2. Are the beta caps still 1 store / 100 secrets / 1024 bytes?

**Yes, all three, unchanged. Verified from Cloudflare docs, 2026-07-25.**
(https://developers.cloudflare.com/secrets-store/manage-secrets/ — Secrets
Store is still labelled *open beta* on the overview page.)

| Cap | Value | Quote |
|---|---|---|
| Stores per account | **1** | "there can only be one store per account" |
| Secrets per account | **100** | "Customers who create a secrets store in the open beta can have up to 100 secrets per account" |
| Bytes per value | **1024** | "a secret must be a string that does not exceed 1024 bytes" |

The `ferrogate-secrets` constants (`CF_SECRETS_STORE_BETA_MAX_*`) and the #418
cap math are therefore still correct. 100 secrets does not scale to per-user
credentials — but per constraint 1 the count was never the binding limit
anyway; the static binding model was.

**A third, sharper finding this slice hit.** A GitHub App private key is a
~1.7 KB RSA PEM. It **does not fit in a Secrets Store secret at all** under the
1024-byte cap, and there is no shorter form (GitHub issues RSA 2048; PKCS#8
conversion does not shrink it). So even the *platform* credential this design
depends on cannot go in Secrets Store today. It goes in a **Worker secret**
(`wrangler secret put`), which Cloudflare caps at **5 KB per variable, 128
variables per Worker on Workers Paid** — verified 2026-07-25,
https://developers.cloudflare.com/workers/platform/limits/. This matches the
guidance already encoded in `CfSecretsCapacityPolicy::check_value_size`, which
tells operators to keep PEM keys out of the store.

The Secrets Store binding is still wired (`GITHUB_APP_PRIVATE_KEY_STORE`,
preferred when present) so that a GA cap increase needs a config change and no
code change.

### Assumed, not verified

- **GitHub's stateless installation-token rollout.** GitHub's docs note that
  from 2026-04-27 newly issued tokens may use a `ghs_APPID_JWT` format, which
  breaks any 40-character assumption. Nothing in this slice parses or measures
  a token, so it should be unaffected — but that is reasoning, not a live test.
- **Behaviour of `git`'s helper protocol under the pinned container image.**
  The parser follows the documented `key=value` block format; it has not been
  exercised against a real `git` binary in a real Cloudflare Container.

---

## What still needs deployment (not provable here)

1. **Worker deploy with a real GitHub App.** `/git-credential/*` fails closed
   with `github_app_unbound` (501) until `GITHUB_APP_ID` + a private key are
   bound. There is deliberately **no** fallback to an injected `GITHUB_TOKEN`.
2. **The in-container helper binary.** `git_helper_config_lines` names a helper
   command; the helper itself (a ~50-line static binary or shell script that
   reads git's stdin block, POSTs it, and writes `username=`/`password=` back)
   ships with the coding-agent image and is not in this slice.
3. **Grant registration in the run's Durable Object.** The Worker route accepts
   the grant record on the request today; wiring it to the run DO so the hot
   path needs no round trip is a control-plane slice.
4. **Live proof of clone + push + revoke**, and the negative test that a token
   never appears in logs/run events/memory *in a deployed run* rather than in
   unit tests.
5. **`tsc`/`vitest` for the new Worker module** — `workers/agent-gateway`
   has no `node_modules` in this environment, so the TypeScript was not
   type-checked here.

## What this does NOT settle: the #471 egress tension

Moving the credential out of the container removes the exfiltration *target*.
It does not close the egress hole. If public egress stays open, the agent can
still reach `api.anthropic.com` directly and bypass metering, guardrails and
#428 spend caps. The allowlist / proxied-git / detection-only decision in #471
is still required, and this design constrains it in one useful way: because git
authenticates through the gateway, the **GatewayProxied** posture is now
implementable without giving the container a credential — the strongest posture
became the cheapest one.

## Related

- #472 — the contract this implements (`docs/coding-agent-adapter-contract.md`).
- #423 — why `cf://` resolves only inside a Worker binding
  (`docs/cloudflare-secrets-resolution.md`).
- #418 — hybrid credential tenancy around the beta caps
  (`docs/cloudflare-secrets-tenancy.md`).
- #415 — container isolation and deny-by-default egress
  (`docs/cloudflare-container-isolation.md`).
- #471 — egress posture; unresolved and still required.
