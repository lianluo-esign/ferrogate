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
`workers/agent-gateway/src/git-credential.ts`,
`workers/agent-gateway/test/git-credential.test.ts`.

## Acceptance scorecard — read this before believing anything below

The first cut of this slice was rejected in code review for claiming more than
it did. This table is the corrective: it is the authoritative statement of what
is proven, and every "no" below is a deliberate admission, not an omission.

| #475 acceptance box | State | Where |
|---|---|---|
| Egress posture satisfying #471 | **Posture chosen and enforceable; not live-validated** | [Egress posture](#egress-posture-the-471-decision-this-slice-makes) |
| Clone from a container with a short-lived scoped credential | **Not met** — no in-container helper binary ships yet, so nothing clones | [What still needs deployment](#what-still-needs-deployment-not-provable-here) |
| Credential revoked at run end on both paths, proven by test | **Mechanism met and tested; no Rust caller drives it yet** | [Issuance and revocation](#issuance-and-revocation) |
| Host-key verification ON with pinned keys | **Keys verified; enforcement available, not wired to a start path** | [Host-key verification](#host-key-verification) |
| Test proving the credential is not in logs / run events / memory | **Partially met** — the Worker audit surface is asserted material-free; no deployed-run evidence | [Credential never reaches logs](#credential-never-reaches-logs-run-events-or-427-memory) |
| Threat-model note | **Met** | [What still rests in the container](#what-still-rests-in-the-container--honest-accounting) |

## The problem in one sentence

A coding agent inside a Cloudflare Container executes model-authored code over
repo content an attacker may have influenced, so any credential that *rests*
in that container — env var, file, image layer — must be assumed read and
exfiltrated.

## The shape

```
control plane                      agent-gateway Worker              GitHub
-------------                      --------------------              ------
before the run starts
  POST /git-credential/register ──▶ run's Durable Object:
    {grant, capabilityFingerprint}    grant + fingerprint + budget + audit ring
    (bearer: GATEWAY_CONTROL_TOKEN)   ^^^^^ the ONLY writer of a grant

container                          agent-gateway Worker              GitHub
---------                          --------------------              ------
git fetch
  └─ credential.helper ──POST──▶ /git-credential/get
        (bearer: the RUN-SCOPED       load the grant FROM THE DO
         callback capability,         verify capability vs. fingerprint
         NOT a GitHub token,          authorize: run · grant · repo · op
         NOT the control token)       charge the budget, write the audit row
                                          │
                                          ├─ sign App JWT (RS256, ≤10 min)
                                          ├──── POST /app/installations/{id}
                                          │        /access_tokens
                                          │        {repositories:[one],
                                          │         permissions:{…}}      ──▶
                                          │   ◀── {token, expires_at: +1h}
        ◀── username=x-access-token ──────┘
            password=<token>              retain the token as the run's ONE
  └─ git speaks to github.com               outstanding revocation handle
     with it for THIS operation

next operation                     supersedes ── DELETE /installation/token ──▶
                                   (the previous token dies immediately)

run finalize (success AND failure)
  POST /git-credential/revoke ────▶ delete the grant (no further mint is
    {runId}                         possible) ── DELETE /installation/token ──▶
    (bearer: GATEWAY_CONTROL_TOKEN)
```

The container is configured with a **callback binding**, not a credential:
`{ broker_url, tenant_id, run_id, grant_id, audience }` plus a run-scoped bearer
capability. That capability is a *gateway* capability — presenting it to
github.com achieves nothing, it works only against `/git-credential/get`, only
for this run, only for the granted repo, only until the grant expires or the run
is closed, and every use is counted and logged.

Two properties make that sentence true rather than aspirational, and both were
missing from the first cut of this slice:

1. **The grant is not something the caller supplies.** `/git-credential/get`
   reads it from the run's Durable Object, where only the control-plane-gated
   `register` route can have put it. A grant in the request body is ignored.
   (`test/git-credential.test.ts`, *"refuses a grant supplied by the caller"* —
   the test fails against the pre-rework route.)
2. **The capability is not `GATEWAY_CONTROL_TOKEN`.** That token also opens
   `/control/*`, `/container/*`, `/memory/*` and `/schedule/*`; a container
   holding it would have the whole gateway. `get` is the only verb the container
   can reach and it accepts only the run's own capability — checked against a
   fingerprint in the run's DO that mixes in the run's `audience`, so a
   capability lifted out of one tenant's run authenticates nothing in another's.

### What still rests in the container — honest accounting

| Artifact | Where | What injected code gets from it |
|---|---|---|
| GitHub App private key | Worker secret | nothing — never crosses the boundary |
| Installation token | `git` process memory for one operation; the run's Durable Object as the revocation handle | must win a race against a live `git`; the DO copy is platform-side and unreachable from the container |
| Callback capability | container env/file | ask *this gateway* for git ops on *one* repo, audited and budgeted — and **nothing else**: it is not the gateway control token and opens no other route |
| Callback binding (`broker_url`, ids, audience) | container | nothing; non-secret routing information |
| `known_hosts`, git config | container, world-readable | nothing; public key material |

The Durable Object copy of the token is a deliberate, named cost. GitHub has no
API to revoke an installation token by id — `DELETE /installation/token`
authenticates *with the token being revoked* — so a broker that retains nothing
can revoke nothing, which is what the first cut of this slice got wrong. The
copy lives in the run's own DO, is returned by no route, is superseded and
revoked the moment the next operation asks for a credential, and is deleted at
run close.

There is no delivery in which a `git` subprocess authenticates to GitHub
without a credential existing in that subprocess's memory for the length of the
request. What brokering removes is **rest**, **scope**, **duration**, and
**silence**. A stolen callback capability buys exactly the access the run
already had; a stolen `GITHUB_TOKEN` buys durable, silent, off-platform access
to everything that token could reach.

## Wire contract

| verb | caller | bearer |
|---|---|---|
| `POST /git-credential/register` | control plane, before the run starts | `GATEWAY_CONTROL_TOKEN` |
| `POST /git-credential/get` | the container's credential helper | the **run-scoped capability** |
| `POST /git-credential/revoke` | control plane, at run finalize | `GATEWAY_CONTROL_TOKEN` |
| `GET /git-credential/audit?runId=` | control plane | `GATEWAY_CONTROL_TOKEN` |

`get` is the only verb reachable from the container, and it is the only one that
does **not** take the gateway control token.

### `POST /git-credential/register`

Owned in Rust as `BrokerGrantRegistration` (`credential_broker.rs`) so the two
halves of the contract cannot drift; the field names are `camelCase` because
that type *is* the wire shape.

```json
{
  "grant": {
    "tenantId": "tenant-a", "runId": "run-1", "grantId": "grant-1",
    "repoId": "github:github.com/acme/app",
    "host": "github.com", "namespace": "acme", "name": "app",
    "installationId": 4242,
    "permissions": { "contents": "read", "metadata": "read" },
    "writeCapable": false, "expiresAtUnix": 1800000900,
    "delivery": "brokered_per_operation",
    "credentialFingerprint": "sha256:…"
  },
  "capabilityFingerprint": "ee84134b…"
}
```

→ `{ "registered": true, "audience": "ferrogate:git-credential:tenant-a:run-1" }`

**The capability itself is never posted here.** The control plane hands the raw
capability to the container and registers only
`sha256_hex("<audience>\n<capability>")`
(`broker_capability_fingerprint` in Rust, `capabilityFingerprint` in
TypeScript — the same test vector is pinned in both suites). So the gateway can
check a presented capability but can never mint or replay one, and there is no
secret on the register request at all.

Mixing the audience in is what binds a capability to one tenant's run: the same
secret string fingerprints differently for `tenant-b`, or for `run-2`. The
`audience` field on `BrokerCallbackBinding` is therefore checked, not decorative
— which it was not in the first cut.

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

`protocol` and `host` must be strings. `path` and `username` may be a string,
absent, or **explicitly `null`** — the null is accepted on purpose, because the
Rust `GitCredentialQuery` declares them `Option<String>` with no
`skip_serializing_if`, so a serialized pathless query is `"path": null` on the
wire rather than an absent key. That callback is denied `path_missing`, the
deny code that names its own fix (`credential.useHttpPath=true`), and it is
charged and audited like any other denial. Refusing it as `invalid_callback`
instead would spend the same budget unit and tell the operator nothing.
Anything else — a number, an object, an array — is `invalid_callback`.

There is no `grant` field. If a caller sends one it is ignored: the grant is
loaded from the run's Durable Object.

Approved (200):

```json
{ "username": "x-access-token", "password": "<installation token>",
  "expiresAtUnix": 1800000900, "operationId": "…" }
```

Refused (403): `{ "error": "<deny code>", "detail": "…" }`. The helper renders a
refusal as an **empty credential block** on stdout, so `git` fails the
operation rather than prompting or retrying. An unregistered run and a wrong
capability both answer `unauthorized` — the route must not be an oracle for
which run ids exist. A malformed body is never an uncaught Worker exception; it
is one of four typed refusals — `invalid_json` (400) when it is not JSON at
all, `invalid_request` (400) when it names no `runId` for the route to address,
`invalid_callback` (400) when a field is the wrong *type*, and `body_too_large`
(413) over the 16 KiB cap. A throw the route did not anticipate is
`authorize_failed` (502), not a 1101.

`invalid_callback` is a **charged** rejection (#501). Rust gets this boundary
for free: `GitCredentialCallback` is `Deserialize`, so `"protocol": 123` never
becomes a callback. TypeScript has no such boundary — a cast is a promise to
the compiler and nothing to the runtime — so the Worker validates every field
by type before the authorization touches it, and the run's budget is charged
whether or not the body parsed. An audit row is written too whenever the body
named a real `operation`; when it did not, the charge is recorded without a row
rather than with a fabricated one.

**Reconciliation rule for `audit` vs `operationsUsed`.** They are not required
to agree, and a mismatch is not corruption. There are three paths through the
authorization, not two:

| path | `operationsUsed` | audit row |
|---|---|---|
| approved, or denied by a deny code | +1 | one row, `approved` or the code |
| malformed body that still named `fetch`/`push` | +1 | one row, `invalid_callback` — or `operation_budget_exhausted` past the cap |
| malformed body naming no operation at all | +1 | **none** |

So `operationsUsed >= rows.length` always, and the **gap in `sequence`** is the
only trace a body of the third kind leaves. That is deliberate: `operation` is
never coerced, because a row asserting `fetch` for a body that never said
`fetch` is a wrong value in an audit trail, which is worse than an absent row.
Anything reconciling the two must read a gap as "a body too broken to name an
operation was charged here", not as a lost row.

**Three carve-outs where a probe is free**, stated rather than claimed away.
"Denials consume budget" is a claim about *authorizations*, and each of these
is a request that never reached one:

- **No capability, or the wrong one.** `unauthorized` is returned before the
  budget is touched, and it has to be: charging it would let any anonymous
  caller who guessed a run id burn that run's 32 operations and strand a real
  agent. This is the widest of the three — it is unauthenticated and
  unbounded — and it is accepted because it is also the emptiest: the answer is
  byte-identical for a run that exists and one that does not, so a prober
  learns nothing it did not already know.
- **A body that names no `runId`** (or a non-string one) cannot address a
  Durable Object, so there is no record to charge and no audit ring to write
  to — a charge is structurally *impossible*, not merely skipped. It answers
  `invalid_request` (400) at the route, deliberately neither `run_mismatch`
  (a deny code, which the Durable Object emits charged and audited — spending
  it here would give one code two accountings) nor `invalid_callback` (which is
  worth keeping to mean exactly one thing; see below).
- **A body over `MAX_CALLBACK_BODY_CHARS`** (16 KiB) is refused with 413
  `body_too_large` before the RPC, for the same structural reason: the body is
  an RPC *argument*, and an oversize argument throws at the boundary, outside
  the method that does the charging.

**`invalid_callback` implies a verified capability and a charged budget unit.**
It is emitted only by the Durable Object, and only *after* `timingSafeEqual`
accepted the capability, so the same malformed body answers `invalid_callback`
with a valid capability and `unauthorized` with an invalid one. That split is
accepted, not denied: the capability is high-entropy and run-scoped, and a
valid one already yields a 200 carrying a token, which is a far louder signal
than a status code.

`expiresAtUnix` is what the helper is told; it is **not** what bounds the
token's life. GitHub fixes that at one hour and does not accept a shorter
request. Revocation is the bound — see below.

Deny codes (`broker_deny_codes` in Rust, `DENY` in TypeScript — they must stay
in step): `run_mismatch`, `grant_mismatch`, `grant_expired`,
`delivery_not_brokered`, `protocol_not_https`, `host_not_granted`,
`path_missing`, `repo_not_granted`, `write_not_granted`,
`operation_budget_exhausted`.

`invalid_callback` is deliberately **not** in that list. Deny codes are
authorization outcomes, and Rust cannot produce this one at all — serde stops
the body a step earlier. It sits with `invalid_registration` and `unauthorized`
as a rejection of the request itself, so the ten-code parity is unchanged.

### `POST /git-credential/revoke`

`{ "runId": "run-1" }` →
`{ "outcome": "revoked" | "already_expired" | "failed", "code"?, "operationsUsed": n }`,
mapping onto the #472 `RevocationOutcome`. HTTP 401 from GitHub means the token
is already dead, which *is* neutralization, so it is reported as
`already_expired` rather than a failure; `failed` answers 502, because a failed
revocation is an incident.

It takes a **run id, not a token** — deliberately. The earlier form required the
caller to present the minted token, which nothing in the system could do, so the
route had zero possible callers. The Worker holds the run's outstanding token
itself; `revoke` deletes the grant first (so no further token can ever be
minted for that run, even if the call to GitHub then fails) and revokes second.

### `GET /git-credential/audit?runId=`

`{ "rows": [ … ], "operationsUsed": n }` — the run's material-free audit rows,
the TypeScript twin of the Rust `GitCredentialAuditEvent`. One row per callback,
approve **and** deny, each carrying `tenantId`, `runId`, `grantId`, `repoId`,
`operation`, `decisionCode`, `sequence`, `occurredAtUnix`, the
`credentialFingerprint`, and on approval an `operationId`. There is no field a
token could be written into.

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
token being revoked*, 204 on success. Because that endpoint needs the token, the
Worker retains exactly one outstanding token per run in the run's Durable
Object; it is revoked at two points:

- **on supersession** — when the next callback asks for a credential, the
  previous operation's token is revoked in `ctx.waitUntil`, so a run's tokens do
  not accumulate and each one's real life is roughly one git operation, not an
  hour;
- **at run finalize** — `POST /git-credential/revoke` on the success path and on
  the failure path.

Honest limits on that claim. `CodingRunReceipt` still cannot be constructed
without a `CredentialRevocation`, so the *type* forces a receipt — but the Rust
side only records the outcome; **no Rust production caller drives the revoke
route yet** (`materialize.rs` records, it does not call). And if the Worker is
evicted between the mint and a crash of the control plane, the DO copy survives
eviction (durable storage), but nothing re-drives revocation on its own: there
is no sweeper. Both gaps are wiring, not design, and both are listed under
[what still needs deployment](#what-still-needs-deployment-not-provable-here).

**Budget** — a run gets `DEFAULT_BROKER_OPERATION_BUDGET` (32) callbacks, and
the counter is stored in the run's Durable Object and incremented inside the
same DO method that authorizes, so concurrent callbacks cannot race past it.
Denials consume budget too; otherwise probing the broker is free. Both halves
behave the same way — the TypeScript side used to accept `operationsUsed` from
the request body and never write it back, which meant the budget was not
enforced at all. A body that fails the type check is charged on the same
grounds (#501): the throw it used to cause landed after the counter was
incremented in memory and before the record was persisted, so a capability
holder could drive unbounded callbacks that cost no budget and left no row.

The cap is enforced **ahead of** the type check, not only inside the
authorization: past 32 operations a malformed body is refused with
`operation_budget_exhausted` rather than charged again as `invalid_callback`,
so "the budget bounds probing" holds for probes that never had to be
well-typed.

Read "otherwise probing the broker is free" with its scope, which is *an
authenticated caller's authorizations*. Three refusals are still free, and they
are listed under [the callback route](#post-git-credentialget) rather than
argued away here: no capability or the wrong one, a body naming no run, and a
body over the 16 KiB cap. The first is the widest and is deliberate — charging
an unauthenticated caller would let anyone who guessed a run id exhaust that
run's budget.

**Deny-code parity** — ten codes, one list, both languages
(`broker_deny_codes` in Rust, `DENY` in TypeScript). The TypeScript side was
missing `delivery_not_brokered`; it is present and tested now.

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

**How much of this is ON, stated precisely.** `ContainerGitEnvironment::prepare`
is the single constructor of a container's git environment in this crate: it
runs `validate_transport_env` and `validate_ssh_hardening` before it will hand
back a `known_hosts` body, the git config lines, or the callback binding, so the
checks are unskippable *for anything that builds that environment through
FerroGate's Rust types*. What it does **not** do is make host-key verification
on for a deployed run: no production start path constructs one yet, and the
brokered path is HTTPS-only, so `known_hosts` matters only if a run is ever
configured for SSH. The earlier text here claimed a bootstrap path that refused
to start such an instance; there was no such path. The acceptance box stays
**unmet** until a start path calls this.

## Credential never reaches logs, run events, or #427 memory

Enforced structurally, not by review:

- No Rust type on the authorization path has a field that can hold a token.
  `BrokerDecision::Approve` carries an *authorization*; the Worker performs the
  mint and streams the answer into the helper response. The test
  `no_broker_type_can_render_key_material` renders the broker, the decision and
  the audit event through both `Debug` and serde and asserts no token-shaped
  material appears. **Be clear about what that test is worth:** it cannot fail
  today, because there is no field to leak from — it is a guard against someone
  adding one, not evidence about a component that ever holds a token.
- The falsifiable Rust twin is
  `a_registration_carries_the_fingerprint_and_never_the_capability`: it feeds a
  real capability string in and asserts it does not come back out of the
  registration, in `Debug` or in JSON.
- `GitCredentialAuditEvent` is ids, fingerprints and timestamps only. The
  credential appears as `credential_fingerprint` (`sha256:…` of the `cf://`
  reference), never as a value or a path. `tenantId` is on every row: the
  credential path used to bind `run_id` + `grant_id` + `repo_id` only, the same
  gap flagged on #472's `WriteBackGrant`.
- On the Worker — the only component that ever holds a token — the token is
  never logged, never placed on a run event, never returned by `audit`, and
  never accompanied by a GitHub response body in an error (only fixed error
  strings and status codes, because a GitHub body can echo request material).
  `test/git-credential.test.ts` asserts the audit surface the control plane
  reads back contains no token-shaped material. It **is** retained in the run's
  Durable Object as the revocation handle — see the accounting table above; the
  earlier text claimed otherwise and was wrong the moment revocation became
  real.
- Not proven here: that no token appears in logs, run events or #427 memory *in
  a deployed run*. That needs a live Cloudflare deployment.

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
- **The mint and revoke round trips.** `vitest-pool-workers` 0.18 exposes no
  outbound fetch mock, so no test here reaches
  `POST /app/installations/{id}/access_tokens` or
  `DELETE /installation/token`. Everything up to and including the mint
  *decision* is tested; the two `fetch` calls themselves are not.

### Verified in this environment

`workers/agent-gateway`: `npx tsc --noEmit` clean, `npx vitest run` 26/26 across
`test/control.test.ts` (#413) and `test/git-credential.test.ts` (#475).
`cargo test -p ferrogate-runtime credential_broker`: 37/37. The
grant-forgery test was watched failing against the pre-rework route before the
fix was restored.

To reproduce, install with **`npm install --legacy-peer-deps`**, not `npm ci`:
`package-lock.json` predates the `devDependencies` block (`npm ci` reports
`Missing: @cloudflare/vitest-pool-workers … from lock file`), and `agents@0.0.109`
declares an unsatisfiable `react` peer through `@ai-sdk/react`. Regenerating the
lockfile shifts ~1400 transitive lines and is left to its own slice.

---

## What still needs deployment (not provable here)

1. **Worker deploy with a real GitHub App.** `/git-credential/*` fails closed
   with `github_app_unbound` (501) until `GITHUB_APP_ID` + a private key are
   bound. There is deliberately **no** fallback to an injected `GITHUB_TOKEN`.
2. **The in-container helper binary.** `git_helper_config_lines` names a helper
   command; the helper itself (a ~50-line static binary or shell script that
   reads git's stdin block, POSTs it, and writes `username=`/`password=` back)
   ships with the coding-agent image and is not in this slice. **Until it
   exists nothing clones**, which is why that acceptance box is unmet.
3. **A Rust caller for `register` and `revoke`.** The routes exist, are tested,
   and are the authoritative side of the contract; `BrokerGrantRegistration` is
   the register body. What is missing is the control-plane code that POSTs them
   at run start and run finalize. Until then revocation is *performed by the
   route* but *driven by nobody*.
4. **A sweeper for orphaned tokens.** If a run is never finalized, its
   outstanding token survives in the DO until GitHub's hour elapses. A DO alarm
   or a control-plane reconcile closes that window; neither is in this slice.
5. **Live proof of clone + push + revoke**, and the negative test that a token
   never appears in logs/run events/memory *in a deployed run* rather than in
   unit tests.

## Egress posture: the #471 decision this slice makes

#475 says the egress posture must be *picked and proven*, not assumed. Picked:
**egress allowlist**, containing the FerroGate gateway and `github.com`, and
nothing else. Not `enableInternet = true`, and not detection-only.

Why the allowlist and not the alternatives:

- **Proxied git** (tunnelling the git transport through the gateway) would be
  strictly stronger, and brokering makes it *possible* — the container needs no
  credential to talk to a proxy. It is rejected here only on cost: it means
  implementing the git smart-HTTP protocol in a Worker, and it buys little once
  the credential is already gone and every authentication is audited.
- **Detection-only** is explicitly the weakest option in the issue and is
  rejected: it reconciles after the fact rather than preventing.

What the platform actually enforces, from the code rather than from intent:

- `AgentSandbox` pins `enableInternet = false` (`workers/agent-gateway/src/index.ts`).
  Cloudflare enforces this **outside** the container, so code inside — including
  model-authored code — cannot switch it back on.
- `/container/start` rejects `enableInternet: true` / `directPublicEgress: true`
  unconditionally, rejects wildcards, rejects any host outside
  `CONTAINER_GOVERNED_EGRESS_HOSTS`, and rejects LLM-provider hostnames outright
  (`validateEgressAllowlist`, `container.ts`). Unset or empty
  `CONTAINER_GOVERNED_EGRESS_HOSTS` means **sealed**, not open.
- `github.com` is a bare hostname and is not on the provider denylist, so an
  operator can authorize it; the gateway host must be authorized too, or the
  credential helper cannot call back.

So the deployment posture is: `CONTAINER_GOVERNED_EGRESS_HOSTS =
"<gateway host>,github.com"`, and a run's `egressAllowlist` naming exactly
those two. `api.anthropic.com` and friends are unreachable by construction —
that is the #471 property.

**What is still unproven:** that Cloudflare's `setAllowedHosts` blocks a
determined process inside a real container in production. That is a live
platform claim, it is derived here from Cloudflare's Containers "Handle
outbound traffic" documentation and from the code path, and it needs a deployed
run to become evidence. This slice therefore *chooses and encodes* a posture; it
does not yet *prove enforcement*.

## Related

- #472 — the contract this implements (`docs/coding-agent-adapter-contract.md`).
- #423 — why `cf://` resolves only inside a Worker binding
  (`docs/cloudflare-secrets-resolution.md`).
- #418 — hybrid credential tenancy around the beta caps
  (`docs/cloudflare-secrets-tenancy.md`).
- #415 — container isolation and deny-by-default egress
  (`docs/cloudflare-container-isolation.md`).
- #471 — egress posture; this slice picks the **allowlist** option and encodes
  it, but platform enforcement is still unproven in a deployed run.
