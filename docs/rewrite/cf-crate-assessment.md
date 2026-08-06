# `ferrogate-cloudflare` — the 21st crate: assessment and verdict

> **Historical record, superseded 2026-08-05 for tenant storage.** This audit
> describes the earlier D1-per-tenant and Cloudflare REST/lifecycle assessment.
> Current FerroGate uses CONTROL D1 plus one SQLite Durable Object per tenant;
> see [`per-tenant-durable-object-storage-2026-08.md`](../design/per-tenant-durable-object-storage-2026-08.md).
> The evidence and conclusions below are retained unchanged as audit history.

**Date:** 2026-08-01 · **Wave 16**, implemented by **wave 17** · **Branch:** `main-ts`
**Answers:** `cutover-parity-libraries.md` §6.1 and `CUTOVER-READINESS.md` §6 item 5
— *"`ferrogate-cloudflare` appears in NO row of `PORT-PLAN.md` and has four
slices with no TS equivalent anywhere."*

**Scope of this document:** a per-slice verdict — what it does, whether it is
still NEEDED now that the runtime is Workers, and where it should live if it is.
Everything below was read from `crates/ferrogate-cloudflare/**` as READ-ONLY
reference; no Rust was compiled, imported or executed, and no live Cloudflare
resource was touched.

> ## WAVE-17 AMENDMENT — the port is IMPLEMENTED. Read §0.0 first.
>
> Wave 16 wrote this assessment and implemented nothing. **Wave 17 built
> `packages/cloudflare` and ported every STILL-NEEDED slice with tests**, added
> the missing `PORT-PLAN.md` row, and closed the one live-path defect §S4
> identified. §0.0 records exactly what landed and what is still deferred; the
> per-slice sections below are unchanged and remain the rationale.

> **2026-08-06 decision record (#744):** the dead per-tenant R2 provisioning
> modules were removed. The deployed TS asset design is one shared R2 bucket
> isolated by the `assets/v1/t/{tenant}/` key prefix; bucket-per-tenant
> provisioning and bucket-scoped credential minting are not mounted features.

---

## 0.0 WAVE 17 — what was implemented

`packages/cloudflare` (`@ferrogate/cloudflare`) now exists. The mounted account
management slices have plain vitest coverage (every test drives an injected
transport and clock: no network, no real sleep, no live account). The former
per-tenant R2 provisioning slices were retired on 2026-08-06 by #744; the
remaining package is the mounted account-management surface.

| Slice | Module | Status | Mounted? |
|---|---|---|---|
| **S4** retry/backoff + typed taxonomy + envelope | `src/retry.ts`, `src/errors.ts`, `src/envelope.ts` | **PORTED** | **YES** — `@ferrogate/storage`'s `D1RestDatabase` (request path) |
| **S3** preflight + required permission groups | `src/client.ts` `preflight()`, `src/scopes.ts` | **PORTED** | not yet — needs a CLI command (`apps/cli` is not this task's scope) |
| **S5** D1 database lifecycle | `src/d1.ts` (`D1LifecycleClient`) | **PORTED** | not yet — needs a control-plane onboarding handler |
| **S1** R2 bucket provisioning + injective naming | Rust `r2.rs` reference only | **RETIRED** | #744 chose one shared bucket with tenant key-prefix isolation |
| **S2** bucket-scoped R2 credential mint | Rust `r2_token.rs` reference only | **RETIRED** | #744 chose deployment bucket credentials plus tenant key-prefix isolation |
| — D1 `/query`, `d1_proxy`, AI-Gateway REST, `cf://` resolver, `ReqwestTransport`/`TokioClock` | — | **OBSOLETE, not ported** | superseded by bindings — see §2 "What is correctly absent" |

### The one live defect this closed

§S4 recorded that `packages/storage/src/tenant-rest.ts` — the D1 REST tenant
router, **on the request path** for any deployment whose tenant fleet exceeds
the Worker binding budget — had zero retry, zero backoff and zero `Retry-After`
handling, so one 429 or one transient 502 was a hard user-visible
`StorageError`. It now imports the ported schedule. The regression test
(`packages/storage/test/d1/rest-retry.test.ts`) was written FIRST and observed
RED against the unfixed tree.

**One deliberate narrowing over the Rust, new in wave 17.** The D1 query API is
a **POST for every statement**, including `INSERT`/`UPDATE`/`DELETE`, so
"retryable status" is not the whole rule:

* a **429** is an outright REJECTION — it never reached the database — so it is
  always safe to re-issue. Retried unconditionally.
* a **5xx** is AMBIGUOUS: the statement may have executed and only the response
  was lost. Retried **only for a statement provably incapable of mutating
  state** (`isReadOnlySql`, conservative by construction).

This is the same reasoning that makes the S2 token mint non-retryable, applied
to a second call site. Blanket 5xx retry on that path would have converted a
missing-retry bug into a duplicate-write bug.

### Deliberate divergences from the Rust, all tested

1. **Retry is opt-in per call.** Rust retried EVERY method on a 5xx. Here
   `idempotent` defaults to `method === "GET"` and each non-GET caller states
   its own answer. `createScopedToken` passes `false` explicitly and a test
   proves a 500 is issued exactly once — a retried mint creates a second
   credential whose secret Cloudflare returns once and can never read back.
2. The former TS tenant-bucket naming helper was async, because `crypto.subtle`
   is the platform's hash. Its golden vectors remain historical evidence only;
   #744 removed that unmounted provisioning path in favor of the shared bucket
   and tenant key-prefix design.
3. **The transport contract is enforced at runtime, not by the type system.**
   Rust's `HttpTransport` trait restricted `execute` to returning
   `Err(CloudflareError::Transport)` and the retry loop leaned on it. TS cannot,
   so the client normalises any non-`CloudflareError` throw at the boundary.

### Mutation evidence (7 mutants, 7 killed)

Each was applied, `grep`-ed back off disk to confirm the edit landed, then
`bun run test` was run — never `bunx vitest run`, because `@ferrogate/storage`
chains a second suite behind `vitest.d1.config.ts` and the two wiring mutants
below only fail in that chained half.

| # | Mutation | Result |
|---|---|---|
| M1 | drop the **length prefix** from the canonical tenant identity (the injectivity-bearing detail) | 6 tests RED |
| M2 | widen already-exists to absorb **any 409** | 3 tests RED |
| M3 | re-add the **`10013`** numeric rate-limit match (TRAP 1) | 3 tests RED |
| M4 | make the **credential mint retryable** | 2 tests RED |
| M5 | drop one row from the required permission-group table | 1 test RED |
| M6 | **unmount** the retry from the D1 REST request path | 5 tests RED |
| M7 | treat every statement as read-only (retry an `INSERT` on a 5xx) | 2 tests RED |

### What is still open after wave 17

* **S1/S2 are retired; S5/S3 have no call site.** S1/S2 were unmounted
  provisioning capabilities, and #744 records the shared-bucket decision that
  replaces them. S5/S3 remain account-management capabilities whose composition
  roots still need to own their future call sites.
* **The deploy-time binding constraint is unchanged.** S5 makes creating a
  tenant D1 database programmable; **binding** it still needs a
  `[[d1_databases]]` stanza and a deploy.
* **§5 is still the transcription that must survive deletion.** It is now
  partly redundant with the code, but not wholly: the migration procedure in
  §5.1 and the pre-injective algorithm's collision families exist nowhere else.

---

## 0. The verdict in one table

| # | Slice | Rust source | Still NEEDED on Workers? | Where it must live | What breaks TODAY without it |
|---|---|---|---|---|---|
| **S1** | R2 **bucket** provisioning + injective per-tenant name | `r2.rs` (534) | **YES, but not yet reachable** | `packages/cloudflare` + a control-plane onboarding call site | **Nothing today.** The TS asset path uses ONE shared bucket with key-prefix isolation. Bucket-per-tenant is a *design* that is unbuilt on both sides |
| **S2** | Minting **bucket-scoped R2 S3 credentials** | `r2_token.rs` (395) | **YES — security, deferred** | same | **Nothing today, and nothing in Rust either.** Both trees sign with ONE deployment-wide key pair. The loss is blast-radius containment, not a working feature |
| **S3** | `scopes.rs` + `CloudflareClient::preflight` — required permission groups + "which group is missing" | `scopes.rs` (83), `client.rs:353` | **YES — operability** | `packages/cloudflare` + `apps/cli` (`ferrogate ops preflight`) | An under-scoped token fails at first use with an opaque string. No TS surface can say *which* permission group to grant |
| **S4** | Shared retry/backoff (~1,200 req/5 min) + typed `AUTHENTICATION_CODES` / `MISSING_SCOPE_CODES` taxonomy | `client.rs`, `error.rs` (252) | **YES — and it is the only slice on a live request path** | `packages/cloudflare`, consumed by `packages/storage/src/tenant-rest.ts` and `packages/secrets/src/cloudflare-client.ts` | `tenant-rest.ts` (the D1 REST tenant router) has **zero** retry and **zero** `Retry-After` handling. A 429 or a 502 on that path is a hard user-visible failure |
| **S5** | **D1 database lifecycle** — `create/list/get/delete database` | `d1.rs:159–219` | **YES — and §6.1 MISSED IT** | `packages/cloudflare` + control-plane tenant onboarding | Provisioning a tenant database is a **manual `wrangler d1 create` + hand-written `INSERT INTO tenant_databases` + `wrangler deploy`** — the procedure is a comment block in `apps/gateway/src/tenancy/index.ts`. There is no programmatic path |
| — | D1 **query** REST (`d1.rs:223`) | | **NO — superseded** | — | Native `env.DB` binding; `tenant-rest.ts` already covers the runtime-uuid escape hatch |
| — | `d1_proxy.rs` — the batch/`RETURNING` proxy Worker client | | **NO — superseded** | — | Native binding `batch()` is one transaction. `tenant-router.ts` models `proxy_service` as a `[[services]]` binding |
| — | `envelope.rs` (`{success,errors,messages,result}` + `result_info`) | | **YES, but as a dependency of S1/S3/S4/S5**, not on its own | `packages/cloudflare` | Two partial re-implementations exist and work; the cost is duplication, not breakage |
| — | `config.rs` / `resolver.rs` (`TokenResolver`, `env://`, `cf://` refusal) | | **MOSTLY DISSOLVES** | — | Inside a Worker a secret **is** a binding. `packages/secrets` already ports `EnvTokenResolver` for the one place a reference is still resolved |
| — | `ReqwestTransport`, `TokioClock`, `HttpTransport`/`Clock` seams | | **NO** | — | `fetch` is ambient; the seam collapses to an injectable `FetchLike` (already the idiom in `tenant-rest.ts`) |

**Headline correction to `cutover-parity-libraries.md` §6.1:** the four named
slices are real, but the list is **incomplete (S5 is missing)** and its severity
framing is wrong. §6.1 calls this crate *"the single strongest argument against
deleting the Rust."* It is not, and the reason is checkable in one command:

```
$ grep -rn "create_database\|ensure_tenant_r2_bucket\|ensure_tenant_r2_credentials" \
      crates/ --include=*.rs | grep -v "^crates/ferrogate-cloudflare/"
crates/ferrogate-cloudflare/examples/d1_live_probe.rs:59:  .create_database(...)
```

→ **Outside its own crate, examples and tests, S1/S2/S5 have NO Rust caller
either.** `r2.rs`'s own module docs say so in as many words: *"no bucket has ever
been provisioned under a tenant-derived name by this tree"*, and
`ensure_tenant_r2_bucket` *"has, across the whole repository history, exactly one
caller (`ensure_tenant_r2_credentials`), which itself has no non-test caller."*

So deleting `crates/**` does **not** lose a working feature here. It loses a
**specification**: a set of Cloudflare-verified magic constants and a decision
record that would be expensive and error-prone to re-derive. That is still a real
loss — see §5, which is the part that must be transcribed *before* any GO — but
it is a documentation loss, not a functionality regression, and the cutover
argument should say so.

---

## 1. Method and evidence

Read, in full: `lib.rs`, `config.rs`, `resolver.rs`, `client.rs`, `envelope.rs`,
`error.rs`, `scopes.rs`, `r2.rs`, `r2_token.rs`, `d1.rs`, `d1_proxy.rs`, plus
`docs/legacy/inventory-edge-control.md` §3. Cross-checked against the TS tree.

Size (`wc -l`): **2,871** non-test source lines, **3,400** test lines, **606**
lines of live-probe examples. Rust deps: `reqwest`, `rustls`, `serde`,
`serde_json`, `sha2`, `tokio`, `async-trait`, `tracing` — all of which have a
zero-dependency Workers equivalent (`fetch`, `zod`, `crypto.subtle`/`WebCrypto`,
`scheduler.wait`), so nothing here is blocked on a package.

Census commands, with their results at the time of writing:

```
$ grep -rln "api.cloudflare.com\|client/v4" packages/*/src apps/*/src
packages/config/src/schema/entities.ts      # a config field default, not a client
packages/secrets/src/cloudflare-client.ts   # PARTIAL CLIENT 1 — Secrets Store manage plane
packages/secrets/src/cloudflare-consts.ts
packages/storage/src/tenant-rest.ts         # PARTIAL CLIENT 2 — D1 query API, ON THE REQUEST PATH

$ grep -rn "r2/buckets\|/d1/database\b" packages/*/src apps/*/src
packages/storage/src/tenant-rest.ts:174   # .../d1/database/{uuid}/query — QUERY only, no lifecycle
# → zero hits for r2/buckets; zero hits for POST /d1/database

$ grep -rn "accounts/.*\/tokens" packages/*/src apps/*/src
# → nothing. No TS code mints or revokes a Cloudflare API token.
```

**One correction to the §6.1 census.** It names *three* independent partial v4
clients, counting `packages/providers`' AI-Gateway surface as the third.
`packages/providers/src/cloudflare.ts` is a **request-shaping layer** — it
rewrites an outbound URL onto `gateway.ai.cloudflare.com` and injects `cf-aig-*`
headers. It does **not** decode the `{success,errors,result}` envelope
(`grep -n "success" packages/providers/src/cloudflare.ts` → 0 hits). The correct
count is **two** envelope-decoding partial clients, plus one host-rewriting
surface that is not a REST client at all. That does not change the conclusion —
it changes which files a `@ferrogate/cloudflare` would absorb.

---

## 2. Slice-by-slice

### S1 — `r2.rs`: per-tenant R2 bucket provisioning

**What it does.** `POST/GET/DELETE /accounts/{account_id}/r2/buckets`, with
three non-obvious behaviours:

1. **Idempotent create.** A duplicate `POST` is absorbed into
   `R2BucketCreation::AlreadyExists` **only** when the envelope carries error
   code `10004` (REST) or `10073` (S3-compatible `BucketConflict`). Narrowed
   deliberately from "any HTTP 409" (`r2.rs:159`, and the `is_bucket_already_exists`
   docstring): a bare 409 — a bucket mid-deletion, a jurisdiction conflict, a
   name held elsewhere — must surface as an error, because `AlreadyExists` is
   reported to the caller as *provisioned* and S2 then mints a read+write
   credential against that name.
   The check is **status-agnostic on purpose**: Cloudflare also answers the
   duplicate create with `success:false` + `10004` under **HTTP 200**.
2. **Cursor-walked list.** `list_r2_buckets` follows `result_info.cursor`,
   `per_page=1000`, and terminates on: no/empty cursor, an empty page, **or a
   cursor the server repeats verbatim** (a server-side no-progress bug that
   would otherwise spin forever). Without the walk, "absent" really means "not on
   page 1" — the failure mode that made a live probe pass vacuously.
3. **Injective tenant→bucket derivation** (`r2_bucket_name_for_tenant`,
   `r2.rs:477`) — see §5.1. This is the security-bearing part: the bucket **is**
   the isolation boundary, so a non-injective derivation hands two tenants one
   bucket.

**Still needed?** **Yes in principle, No urgently.** No Worker binding can create
an R2 bucket — provisioning is inherently an account-management REST operation,
so this cannot be replaced by a binding. But:

- The TS asset path does **not** use bucket-per-tenant. `apps/gateway/src/assets`
  uses ONE bucket (`env.ASSETS` / `ASSET_S3_BUCKET`) and isolates tenants by
  **key prefix**, enforced in application code by `service.ts #guardKey` →
  `assertKeyBelongsToTenant` (line numbers in `apps/**` move between waves; grep the
  symbol). That is a coherent, tested design, and it is what
  is deployed.
- The Rust production path did the same: `state_assets.rs` (`AssetBucketClient::new(AssetBucketConfig { .. access_key_id, secret_access_key .. })`) builds
  `AssetBucketClient` from a single configured `[asset_bucket]` bucket +
  `access_key_id` + `secret_access_key_env`.

So this is a *designed but unwired* capability on **both** sides. Porting it
without its onboarding call site would add exactly the
implemented-tested-never-mounted dead code this project keeps getting bitten by.

**Current status.** The former TS provisioning module was removed by #744. The
deployed path uses one shared bucket and the `assets/v1/t/{tenant}/` prefix.

**What breaks today:** nothing. **What breaks at cutover:** the derivation rule
and the two already-exists codes are unrecoverable — §5.

---

### S2 — `r2_token.rs`: minting bucket-scoped R2 S3 credentials

**What it does.** There is **no** "create R2 token" endpoint; the R2 dashboard is
a UI over the generic account-owned token API. So:

- `POST /accounts/{account_id}/tokens` with ONE `allow` policy whose `resources`
  is `{ "com.cloudflare.edge.r2.bucket.{account}_{jurisdiction}_{bucket}": "*" }`
  and whose `permission_groups` is the R2 **Bucket Item** Read or Write group;
- `DELETE /accounts/{account_id}/tokens/{token_id}` to revoke;
- the S3 credential is then **derived**: `access_key_id = token.id`,
  `secret_access_key = hex(sha256(token.value))`, where `value` is the plaintext
  Cloudflare returns **exactly once**.
- Deliberately **not** idempotent: the secret cannot be read back, so
  "create-if-absent" is impossible. `ensure_tenant_r2_credentials` keeps the
  *bucket* idempotent and mints a fresh token each call.
- Account-owned (`/accounts/.../tokens`), not `/user/tokens`, so the credential
  survives the creating user.

**Still needed?** **Yes — this is the security slice.** Today
`apps/gateway/src/assets/handlers.ts::sigV4PresignerFromEnv` reads five
deployment-wide vars (`ASSET_S3_ENDPOINT/BUCKET/ACCESS_KEY_ID/SECRET_ACCESS_KEY/REGION`)
and signs **every tenant's** presigned URL with that one key pair. A presigned
URL is itself scoped to one object by SigV4, so the *URLs* are safe; the exposure
is the **credential**: if the Worker's `ASSET_S3_SECRET_ACCESS_KEY` leaks, the
blast radius is every tenant's objects. With S2 the blast radius of a leaked
per-tenant credential is one bucket = one tenant.

That said — again — the Rust had the same posture in production
(`state_assets.rs`), so **this is not a port regression**. It is an unbuilt
defense-in-depth layer on both sides.

**Current status.** The former TS token-mint module was removed by #744. The
deployed path keeps the shared bucket credential configuration and enforces
tenant isolation with the object-key prefix.

**Non-engineering prerequisite:** **R2 is not enabled on the live Cloudflare
account** (`CUTOVER-READINESS.md` §3.3). S1 and S2 cannot be verified end-to-end
until it is.

---

### S3 — `scopes.rs` + `CloudflareClient::preflight`

**What it does.** `REQUIRED_TOKEN_PERMISSION_GROUPS` (`scopes.rs:33`) is an
8-row table of permission group + access level + which subsystem consumes it
(§5.3). `preflight` (`client.rs:353`) is a cheap
`GET /accounts/{account_id}` whose failure is mapped through
`CloudflareError::from_response`: an envelope carrying `9103`/`9107`/`9109`
becomes `MissingScope { errors, required }`, whose `Display` prints *"grant the
token these permission groups: …"*.

**Still needed?** **Yes — operability, and it is cheap.** Both TS partial clients
collapse every failure into one flat `CloudflareError` carrying a formatted
string (`packages/secrets/src/cloudflare-client.ts::CloudflareClient#send`;
`packages/storage/src/tenant-rest.ts` (`!response.ok || envelope.success !== true`)). Neither can distinguish
*under-scoped* from *unauthenticated* from *rate-limited*, so an operator with a
token missing "Workers R2 Storage" learns only that a call failed, at first use,
in production.

**Where it should live.** The taxonomy in `packages/cloudflare/src/errors.ts`;
the table in `packages/cloudflare/src/scopes.ts`; the check surfaced as a CLI
command in `apps/cli` (`ferrogate ops cf-preflight`) and, optionally, as a
control-plane readiness probe. It has NO request-path consumer and must not
acquire one.

**What breaks today:** no automated surface can name a missing permission group.

---

### S4 — shared retry/backoff + typed error taxonomy

**What it does.**

- `RetryPolicy` default: `max_retries = 4`, `base_backoff = 1s`,
  `max_backoff = 60s`. `backoff_delay(attempt, retry_after)`: the server's
  `Retry-After` **wins** when present (capped at `max_backoff`); otherwise
  `base * 2^attempt`, capped, saturating. **No jitter — deterministic on
  purpose**, so the schedule is exactly assertable in tests with an injected
  `Clock`.
- Retryable statuses: `429 | 500 | 502 | 503 | 504` (`client.rs:167`).
- Retryable errors: `Transport(_)` and `RateLimited{..}` only.
- Rate-limit classification is **`status == 429` alone** — see §5.4 for the two
  numeric codes that must NOT be matched, and why.
- `MISSING_SCOPE_CODES` / `AUTHENTICATION_CODES` with a documented
  cross-namespace collision audit against R2's disjoint `10001`–`1000_7x` range.

**Still needed?** **Yes — and it is the only slice with a live consumer.**
`packages/storage/src/tenant-rest.ts` is the D1-REST tenant router; it is
**on the request path** for any deployment whose tenant fleet exceeds the Worker
binding budget, and `grep -n "retry\|backoff\|429\|Retry-After" packages/storage/src/tenant-rest.ts`
returns **nothing**. One 429 or one 502 from Cloudflare is a hard, user-visible
`StorageError`. The Secrets Store client omits retry deliberately and correctly
(*"a half-implemented retry is a duplicated-write hazard on a write-only API"*,
`cloudflare-client.ts`, the marker block) — that reasoning is sound for writes and does not
extend to the D1 query path's reads.

**Where it should live.** `packages/cloudflare/src/retry.ts` +
`packages/cloudflare/src/errors.ts`, imported by BOTH partial clients, which then
shrink to endpoint shapes. This is the one slice worth doing even if S1/S2/S5 are
never built.

**Caution when porting:** retry is safe for GET/idempotent calls. The Rust loop
retries **every** method on a 5xx; on Workers, `POST /accounts/.../tokens` (S2)
must NOT be retried — a retried mint creates a second credential whose secret is
lost. Whatever lands must make idempotency an explicit per-call flag.

---

### S5 — `d1.rs` database lifecycle (MISSED by §6.1)

**What it does.** `POST /d1/database` (create, with
`primary_location_hint`/`jurisdiction`), `GET /d1/database` (page-walked list),
`GET .../{uuid}`, `DELETE .../{uuid}`. Distinct from `POST .../{uuid}/query`,
which IS superseded.

**Why §6.1 missed it.** It classified all of `d1.rs` as *"superseded by the
native D1 binding"*. True for the **query** endpoint. False for the **lifecycle**
endpoints: no binding can create a D1 database, for the same reason no binding
can create an R2 bucket.

**Still needed? YES — and unlike S1/S2 this one has a real gap today.** The
FerroGate design is **one D1 database per tenant** (a standing user directive).
`EnvBindingTenantDatabaseRouter` resolves `tenantId → binding name` through the
control DB's `tenant_databases` table and fails closed on a miss
(`packages/storage/src/tenant-router.ts`). Nothing in the TS tree *creates* the
database or *writes* the registry row: `grep -rn "tenant_databases" apps/*/src`
finds only readers, and the documented onboarding procedure is a comment block —
`apps/gateway/src/tenancy/index.ts` (the `wrangler d1 create` … `INSERT INTO tenant_databases` block) — instructing an operator to run
`wrangler d1 create`, hand-write an `INSERT INTO tenant_databases`, add a
`[[d1_databases]]` stanza and redeploy.

**Where it should live.** `packages/cloudflare/src/d1.ts`, called from a
control-plane tenant-onboarding handler that (a) creates the database, (b) runs
`sql/d1-ts/tenant/*` migrations through the REST query endpoint, (c) inserts the
`tenant_databases` row. Note (a) and (b) are *provisioning-time*, so the REST
path's lack of atomic `batch()` is irrelevant there.

**Deploy-time constraint, unchanged:** creating the database is programmable;
**binding** it is not. A newly created database still needs a `[[d1_databases]]`
stanza and a deploy before `EnvBindingTenantDatabaseRouter` can route to it. That
is the standing open constraint on the whole one-DB-per-tenant design, and S5
does not remove it — it removes the manual half.

---

### What is correctly absent (do not "port this back")

`ferrogate-cloudflare` exists because the Rust gateway ran **outside** Cloudflare
and had to reach every product over REST. This port runs **inside** it.

| Module | Superseded by |
|---|---|
| `d1.rs` query endpoint | native `env.DB` binding (`prepare/bind/batch/RETURNING`); `tenant-rest.ts` for the runtime-uuid escape hatch |
| `d1_proxy.rs` | native binding `batch()`; `tenant-router.ts` models the proxy as a `[[services]]` binding |
| Workers-AI / AI-Gateway REST hops | `env.AI` binding (`packages/guardrails/src/adapters/workers_ai_llama_guard.ts` already has both a binding client and a REST client behind ONE `WorkersAiClient` seam) |
| agent memory / schedule / container REST hops | Durable Objects |
| `ReqwestTransport` + `TokioClock` + `HttpTransport`/`Clock` traits | ambient `fetch`; an injected `FetchLike`; `scheduler.wait` |
| `resolver.rs` `cf://` refusal, `config.rs` token references | Secrets Store **bindings**. The crate's own three reasons for refusing `cf://` (dependency cycle, write-only REST, bootstrap circularity) are a hint about the target architecture: inside a Worker, secrets are bindings, so the `TokenResolver` seam largely dissolves into `env` |

**Adjacent finding, out of this crate's scope but worth recording:**
`client.rs::request_json_with` (multipart body + bearer override) exists solely
for the Workers **script deploy** flow in `crates/ferrogate-mcp/src/mcp_worker_deploy.rs`
(`PUT /accounts/{account_id}/workers/scripts/{name}`, multipart). There is no TS
equivalent (`grep -rn "workers/scripts\|multipart/form-data" packages/*/src apps/*/src`
→ 0 hits). It belongs to the `ferrogate-mcp` row of `PORT-PLAN.md`, not this one,
and it is arguably obsolete: deploying a Worker is `wrangler deploy`'s job in this
tree.

---

## 3. The `PORT-PLAN.md` row that is missing

`PORT-PLAN.md`'s crate→package map has 17 rows and does not mention this crate.
The row to add, verbatim:

```
| `ferrogate-cloudflare` | **mostly superseded by native bindings** — see `docs/rewrite/cf-crate-assessment.md`; the account-MANAGEMENT residue targets a new `packages/cloudflare` | R2 (bucket provisioning), API Tokens (scoped R2 creds), D1 (database lifecycle), account preflight |
```

A map with 20 of 21 crates is how this went unnoticed for fourteen waves; the row
matters even though the answer is mostly "obsolete".

---

## 4. Markers — where the gap enters the ledger

**It is already in the ledger.** `packages/secrets/src/cloudflare-client.ts:4`
carries `PORT-TODO(P: 4.6/4.7)`, classified as **P38** in `MARKER-LEDGER.md:162`,
and its body (the "TREE-WIDE, HOWEVER" half of the block) enumerates S1–S4 explicitly. It is the only place in
the tree that mentions `ferrogate-cloudflare` at all, and it says the right
things, including the reason not to close it prematurely:

> *"The R2 legs in particular have no caller in the TS tree today (no app
> provisions a bucket), so they must land WITH their control-plane call site or
> not at all."*

**This wave adds no marker of its own**, for two reasons: (a) the enumerating
marker exists and is correctly classified, and (b) `packages/secrets` is outside
this task's owned scope (`packages/guardrails` + this document), and a
concurrent-write clobber is a documented hazard in this repo.

Two **comment-only** amendments are therefore handed to whoever owns
`packages/secrets` next. Neither changes behaviour.

**(a)** `packages/secrets/src/cloudflare-client.ts` — inside the existing
`PORT-TODO(P: 4.6/4.7)` block, after the four-slice list, append:

```ts
 *   - `d1.rs` database LIFECYCLE (`create/list/get/delete database`) — NOT the
 *     query endpoint, which the native binding does supersede. No binding can
 *     CREATE a D1 database, and the one-DB-per-tenant design needs one per
 *     tenant. Today onboarding is a manual `wrangler d1 create` + hand-written
 *     `INSERT INTO tenant_databases` + redeploy
 *     (`apps/gateway/src/tenancy/index.ts`). Fifth slice; §6.1 missed it.
 *
 * Full per-slice verdict, and the Cloudflare-verified constants that must be
 * transcribed BEFORE `crates/**` is deleted (permission-group ids, the R2
 * resource-scope format, the secret-key derivation, the already-exists /
 * missing-scope / auth code sets, the bucket-name derivation, the retry
 * schedule): `docs/rewrite/cf-crate-assessment.md`.
 */
```

**(b)** `packages/storage/src/tenant-rest.ts` — a NEW marker, above
`D1_REST_API_BASE`, for the one live-path consequence of S4:

```ts
/**
 * PORT-TODO(cf-crate-assessment §S4) — NO RETRY ON A REQUEST-PATH CF CALL.
 * NOT A PLATFORM LIMIT. NOT CLOSED.
 *
 * This class is on the request path for any deployment whose tenant fleet
 * exceeds the Worker binding budget, and it has no retry, no backoff and no
 * `Retry-After` handling: `grep -n "retry\|backoff\|429" ` this file → 0 hits.
 * Cloudflare's global API limit is ~1,200 req / 5 min / user, so a 429 or a
 * transient 502 becomes a hard user-visible StorageError.
 *
 * The Rust reference is `ferrogate_cloudflare::RetryPolicy`
 * (`client.rs:148-170`): 4 retries, 1s base, 60s cap, `Retry-After` wins when
 * present (capped), deterministic (NO jitter) so the schedule is assertable
 * with an injected clock; retryable statuses are exactly
 * `429 | 500 | 502 | 503 | 504`. Port it into `packages/cloudflare` and import
 * it here and in `packages/secrets/src/cloudflare-client.ts` — do NOT write a
 * third copy. Retry must be opt-in per call: a retried
 * `POST /accounts/.../tokens` mints a second credential whose secret is lost.
 */
```

---

## 5. TRANSCRIBED: the facts that die with `crates/**`

This is the section that must survive the deletion. Every value below was
**verified against Cloudflare by the Rust authors** (each carries a docstring
naming the doc page or the issue that established it) and **cannot be re-derived
by reading the TypeScript**, because the TypeScript does not contain it.

### 5.1 Per-tenant R2 bucket name derivation (`r2.rs:477`)

```
name  = "ferrogate-" + slug + "-" + digest        (slug omitted, with its "-",
                                                   when the tenant id has no
                                                   ASCII alphanumerics at all)

digest = lowercase-hex( SHA256( "ferrogate.r2.bucket.v1" + ":" + len(tenant)
                                + ":" + tenant ) )[0..32]      # 32 hex = 128 bits

slug   = cosmetic ONLY. Runs of [a-z0-9] (lowercased) joined by a single "-",
         capped at 20 chars, no leading/trailing "-", no "--". Collisions here
         are fine and expected; it carries NO isolation guarantee.

Sizing: prefix(10) + slug(<=20) + "-"(1) + digest(32) == 63 == R2's exact max.
        Min length 42. Always [a-z0-9-], always starts 'f', always ends hex.
```

- The **length prefix** is what keeps the encoding unambiguous if a second
  component (jurisdiction, realm) is ever appended. Same trick as
  `ferrogate_storage::agent_cost_burn_key`.
- **All** collision resistance is in `digest`. Injectivity is the whole point:
  two tenants sharing a bucket name read and overwrite each other's objects, and
  S2 would then scope a per-tenant credential to a *shared* bucket.
- Bumping `v1` renames every tenant's bucket → that is a **migration**, never a
  refactor.
- There is deliberately **no** legacy-name compatibility helper and **no**
  dual-read fallback (issue #496): a fallback would re-collapse two tenants onto
  one legacy bucket, which is the bug the derivation fixed. The pre-#490
  algorithm survives only as a private fixture in `r2_test.rs` — if that record
  matters, copy it out before deletion.
- A tenant id with **no ASCII alphanumeric** is rejected by
  `validate_tenant_id` at the provisioning entry point (the derivation itself is
  infallible, deliberately). Minting real storage — and a real credential — for
  an empty tenant id would hide a caller bug behind a success.

### 5.2 R2 scoped-token facts (`r2_token.rs`)

| Fact | Value |
|---|---|
| Endpoint (mint) | `POST /accounts/{account_id}/tokens` — account-owned, **not** `POST /user/tokens` |
| Endpoint (revoke) | `DELETE /accounts/{account_id}/tokens/{token_id}` |
| Resource scope key | `com.cloudflare.edge.r2.bucket.{account_id}_{jurisdiction}_{bucket}` → `"*"` |
| Default jurisdiction | `default` (lowercase-alpha token; `eu`, `fedramp` are the others) |
| **Bucket Item Read** permission-group id | `6a018a9f2fc74eb6b293b0c548f38b39` — published in the R2 *authentication* docs' Access-Policy example |
| **Bucket Item Write** permission-group id | `2efd5506f9c8494dacb1fa10a3e7d5b6` — **published only in the R2 *Data Catalog* docs**; the authentication docs carry the Read id only, so they are NOT a source for it (issue #489) |
| S3 **Access Key ID** | the created token's `id` |
| S3 **Secret Access Key** | `lowercase-hex(SHA256(token.value))`, where `value` is the plaintext Cloudflare returns **exactly once**, at creation |
| Idempotency | **None, by construction.** The secret cannot be read back, so create-if-absent is impossible. A missing `value` in the response is a hard `Decode` error, never a silent partial success |
| Input validation before any request | bucket name `[a-z0-9-]` non-empty (the `_` separator must not be smuggled into the resource id); jurisdiction lowercase-alpha; token name non-empty; token id alphanumeric |

The Write group id is the single most expensive item in this document to
re-derive: it is not in the obvious doc page.

### 5.3 Required token permission groups (`scopes.rs:33`)

| Permission group | Access | Used by |
|---|---|---|
| AI Gateway | Read, Edit | AI Gateway management + inference proxying |
| Secrets Store | Read, Write | `cf://` secret backend |
| D1 | Read, Edit | D1-backed state |
| Workers Scripts | Edit | Worker deployment |
| Workers R2 Storage | Read, Edit | R2 object storage (bucket MANAGEMENT; distinct from the S3 key pair) |
| API Tokens | Write | minting/revoking bucket-scoped R2 API tokens |
| Cloudflare Pages | Edit | Pages deployment |
| Workflows (Workers Scripts) | Write, Edit | Workflows orchestration |

Preflight is `GET /accounts/{account_id}`; a `MissingScope` result names this
whole list so an operator can provision once.

### 5.4 Error-code taxonomy (`error.rs`) — including the two traps

```
MISSING_SCOPE_CODES  = [9103, 9107, 9109]   # token authenticates, is under-scoped
AUTHENTICATION_CODES = [1000, 9106, 10000]  # token unknown / expired / malformed
R2_BUCKET_ALREADY_EXISTS_CODES = [10004, 10073]   # idempotent-create success
```

Classification precedence in `from_response`:
`429` → missing-scope codes → (`401`/`403` **or** auth codes) → generic `Api`.

**Trap 1 — do NOT treat `10013` as a rate limit.** An earlier Rust version did.
`10013` is `IncompleteBody` in R2 (HTTP 400: the request body was truncated — a
client-side failure that can *never* succeed on retry) and
`workers.api.error.unknown` (HTTP 500) in the general `client/v4` namespace.
Neither is a rate limit. The collision was live once R2 started routing through
the shared mapper.

**Trap 2 — do NOT match `10058` numerically either.** R2's real rate-limit code
IS `10058`/`TooManyRequests`, but it always arrives with HTTP **429**, so
`status == 429` already classifies it. A bare `code == 10058` match would
reintroduce the same collision class: in Cloudflare's Lists/Bulk-Redirect
namespace, `10058` means "list items incompatible with list type" (HTTP 400).

**Cross-namespace audit result (worth not repeating):** the `9xxx` account/token
codes are disjoint from R2's `10001`–`1000_7x` range plus the `100100`
`EntityTooLarge` outlier. R2's own auth codes (`10002` Unauthorized/401,
`10003` AccessDenied/403, `10035` SignatureDoesNotMatch/403, `10042`
NotEntitled/403) do not need numeric entries because the `401`/`403` status
branch already catches them.

### 5.5 Retry / rate-limit schedule (`client.rs:148–170`)

```
Cloudflare global API limit: ~1,200 requests / 5 min / user  (~4 req/s)

RetryPolicy default: max_retries = 4, base_backoff = 1s, max_backoff = 60s
backoff_delay(attempt, retry_after):
    retry_after present  -> min(retry_after, max_backoff)        # server wins
    otherwise            -> min(base * 2^attempt, max_backoff)   # saturating
    NO JITTER — deterministic so the schedule is exactly assertable

retryable HTTP statuses: 429 | 500 | 502 | 503 | 504
retryable error variants: Transport(_) | RateLimited{..}   (nothing else)

Mapped errors from `from_response` never re-enter the loop: it runs AFTER the
loop returns. A `400 + code 10013` response is therefore issued exactly once.
```

### 5.6 Pagination dialects (`envelope.rs`, `r2.rs`, `d1.rs`)

Cloudflare uses **two** dialects and both must be walked:

- **cursor** (R2 bucket list): `result_info.cursor`, echoed back as
  `?cursor=…&per_page=1000`. Terminate on absent/empty cursor, on an empty page,
  and on a **repeated** cursor. Cursors are opaque and can carry `+`, `/`, `=`,
  so they must be percent-encoded (unreserved set only) before splicing into the
  query string.
- **page-numbered** (D1 database list): `page`/`per_page`/`count`/`total_count`.

`per_page=1000` is R2's documented cap (default 20); asking for the cap
minimises request count against the 5.5 limit. If the server clamps it,
correctness is unaffected — the cursor is followed either way.

### 5.7 Miscellaneous, cheap to lose and annoying to rediscover

- Default API base `https://api.cloudflare.com/client/v4`; AI Gateway base
  `https://gateway.ai.cloudflare.com`; R2 S3 endpoint defaults per-account to
  `https://<account_id>.r2.cloudflarestorage.com`.
- R2 bucket names: 3–63 chars, `[a-z0-9-]`, never leading/trailing `-`.
- R2's S3 region is always `auto`.
- `R2CreateBucketRequest` serializes `locationHint` / `storageClass` in
  **camelCase** (the rest of the REST schema is snake_case). Location hints:
  `apac`/`eeur`/`enam`/`weur`/`wnam`/`oc`. Storage classes:
  `Standard`/`InfrequentAccess`.
- D1 REST `params` are typed as an array of **strings**; SQLite column affinity
  converts numeric strings on insert, booleans bind as `"1"`/`"0"`, and SQL NULL
  is expressed in SQL (`NULLIF(?, '')`) rather than as a JSON `null`.
- Deleting an R2 bucket requires it to be **empty**; a non-empty bucket returns
  `BucketNotEmpty`.
- The REST surface is **control plane only** — it cannot move a single object.
  Any bucket migration needs an S3 data-plane client and a SigV4 signer, which
  this crate never had. (`apps/gateway/src/assets/sigv4.ts` is the TS signer, and
  it exists for presigning, not for copying.)

---

## 6. Recommended sequencing (not this wave)

1. **S4 only** — create `packages/cloudflare` with `errors.ts` + `retry.ts` +
   `envelope.ts`, and make `packages/storage/src/tenant-rest.ts` and
   `packages/secrets/src/cloudflare-client.ts` import them. Real consumers exist
   *today*; nothing new is mounted; the duplicate envelope decoders collapse.
   Retry must be opt-in per call.
2. **S3** — `scopes.ts` + `preflight()`, surfaced as a CLI command. Cheap,
   operator-visible, no request-path consumer.
3. **S5** — `d1.ts` lifecycle **with** a control-plane onboarding handler that
   creates the database, migrates it and writes the `tenant_databases` row. The
   deploy-time binding constraint remains and must be documented at the handler.
4. **S1 + S2** — retired by #744 after the shared-bucket-plus-tenant-prefix
   decision. Do not reintroduce per-tenant provisioning without a new design
   decision and a mounted onboarding caller.
5. Add the `PORT-PLAN.md` row (§3) regardless of whether any of the above is
   scheduled.

**Before any GO on deleting `crates/**`:** §5 is the transcription. Once it is in
this repository, `crates/ferrogate-cloudflare` is safe to delete on this crate's
account — no working feature depends on it in either tree, and the facts that
were expensive to establish now live here.

---

## 7. Scope statement

Local, read-only, document-only. No `crates/**` or `workers/**` file was
modified. No Rust was compiled, imported, linked or executed; `cargo` was never
invoked. No `apps/*` file, composition root or `wrangler.toml` was touched. No
live Cloudflare resource was created, read or mutated. No test was weakened,
skipped or deleted. The only non-document change made by the task that produced
this file is in `packages/guardrails` and is described in
`packages/guardrails/src/index.ts`.
