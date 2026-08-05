# Parity audit — `ferrogate-storage` → `packages/storage`

> **Historical record, superseded 2026-08-05 for tenant storage.** This audit
> predates the implemented CONTROL D1 plus per-tenant SQLite Durable Object
> topology. See [`per-tenant-durable-object-storage-2026-08.md`](../design/per-tenant-durable-object-storage-2026-08.md).
> The findings below remain preserved as the evidence for that transition.

**Scope:** the DATA cluster only (`crates/ferrogate-storage` and its D1 backend,
`sql/001_init_postgres.sql` v59, `sql/d1/001_init_d1.sql`) against
`packages/storage`, `sql/d1-ts/`, and the storage-shaped code that ended up
inside `apps/*`.
**Method:** enumerate the 226-method `ControlPlaneStore` trait, the 69-table
Postgres schema, and the eight concurrency proofs of inventory §1.5; classify
each as PRESENT / ABSENT-AND-UNMARKED / ABSENT-BUT-MARKED / DELIBERATELY-N-A.
**Product:** this report plus 9 new `PORT-TODO` markers in
`packages/storage/src`. No behavior was implemented, so there is nothing to
mutation-test; `bun run test` in `packages/storage` is **104 pure + 152 D1 = 256
green, unchanged before and after**, and `tsc --noEmit` is clean.

---

## 0. Headline

**The 12× line-count ratio in the brief is mostly an artifact, and I am saying so
up front. But it is not entirely an artifact, and what it hides is not a missing
table — it is a missing *mount*.**

The single most consequential finding is not on the Rust-vs-TS axis at all:

> **The entire durable half of `packages/storage` has zero importers in any
> app.** Every `D1*Store`, every `Memory*Store`, and both tenant routers are
> implemented, tested (256 tests, mutation-tested per the package README §3),
> and **dead in production**. The three production call sites that do import
> `@ferrogate/storage` take pure helpers only (`periodMonthFromUnix`,
> `sha256Hex`, `boolFromSqlite`, the site-domain value types). The no-oversell
> wallet guard is not guarding any money; the tenant router is not routing
> anything, so the database-per-tenant topology is not in effect on any deployed
> path.

That is this repo's named recurring defect, in its purest form so far. Tasks #41
/#42 track the wiring, but there was **no marker in the code**, so it is now
`PORT-TODO` in `packages/storage/src/index.ts` with an explicit instruction that
the closer must add an assertion that fails when the mount is removed.

---

## 1. Where the 12× actually went (quantitative)

### 1.1 Rust: 70,721 lines is not 70,721 lines of behavior

| slice | raw lines | note |
|---|---:|---|
| `*_test.rs` files + test support | **20,897** | Rust colocates tests in the crate |
| inline `#[cfg(test)]` tails | **~4,232** | 3,349 of them in `lib.rs` alone |
| **production** | **45,592** | 37,134 excluding comments/blanks |

So the crate's *production* size is 45,592, not 70,721. Broken down:

| production slice | lines | fate on Cloudflare |
|---|---:|---|
| `lib.rs` (Stored\* DTOs + the ~1,500-line `RuntimeStorageRepositories` dispatch) | 15,081 | dispatch layer **evaporates** (one backend, not three); DTOs become TS interfaces at ~⅕ the size |
| `control_plane_store_d1/` (14 modules) | 11,446 | **the actual port target** |
| domain algorithms (`wallet`, `workflow_budget`, `payment_attempt`, `site_domain*`, `rbac`, `agent_schedule`, `guardrail_evidence`, `asset_lifecycle`, `lifecycle_gate`, `metadata_rollups`, …) | 9,352 | **the actual port target** |
| `mcp_identity.rs` | 2,827 | re-architected onto DO storage + KV in `apps/mcp` (already `unimplemented` on Rust's own D1) |
| Postgres backend (`control_plane_store_postgres` + `postgres_row_mappers` + `async_postgres`) | 2,924 | **N/A** — deadpool, Supavisor cap, TLS modes, `pg_constraint` introspection |
| `control_plane_store_memory.rs` | 2,459 | partially ported as the `Memory*Store` reference backends |
| `control_plane_store.rs` (the trait signature block) | 1,319 | **N/A** — a 3-backend abstraction with one backend is not an abstraction |
| `schema_migrations.rs` | 184 | **N/A** — `wrangler d1 migrations` |

### 1.2 TypeScript: `packages/storage` is not the whole TS storage layer

| TS location | lines | what |
|---|---:|---|
| `packages/storage/src` | 5,966 | pure algorithms + `Memory*`/`D1*` stores + tenant router |
| `apps/control-plane/src/store/{d1,api_keys}.ts` | 889 | the generic `control_plane_resources` document store + key directory |
| `apps/gateway/src/{ratelimit/quota,metering/d1,guardrails/d1,guardrails/binding,keys/store,assets/entitlements}.ts` | 2,135 | quota resolution, billing batch, guardrail CAS, key lookup, RBAC entitlements |
| `apps/mcp/src/oauth-flow.ts` | 172 | MCP OAuth (DO/KV, not D1) |
| **TS storage-domain total** | **~9,162** | 6,300 excluding comments |
| `sql/d1-ts/{control,tenant}` | 1,520 | vs Rust `sql/d1/001_init_d1.sql` 1,123 (**+35%**) |

**Corrected ratio.** Against the slices that were actually supposed to be ported
(D1 backend 11,446 + algorithms 9,352 + the DTO half of `lib.rs`), ~9,162 lines
of TS is roughly **0.35–0.45**, not 0.08 — which is a normal Rust→TS ratio once
`impl`/`match`/`Result`/lifetime boilerplate and a 3-backend dispatch table are
removed. **The reduction is mostly legitimate.** The gaps below are real but they
are *narrow* — they are specific behaviors, not whole subsystems, with two
exceptions (agent scheduling; the unmounted composition root).

---

## 2. Schema parity — the strongest result in this audit

| comparison | result |
|---|---|
| Rust D1 (`sql/d1/001_init_d1.sql`) → TS D1 (`sql/d1-ts/`) | **57 / 57 tables present. Zero missing.** TS adds 6: `api_key_directory`, `static_api_keys`, `tenant_databases`, `gateway_providers`, `gateway_models`, `payment_methods` |
| Postgres v59 (69 tables) → TS D1 (63 tables) | 12 absent — **all 12 are also absent from Rust's own D1 schema** |

The 12 Postgres-only tables, each classified:

| table(s) | classification | why |
|---|---|---|
| `metering_events`, `metering_event_routes`, `metering_event_usage`, `billing_metering_events` | DELIBERATELY-N-A | documented collapse into the single `billing_events` document table (§1.4.4) |
| `usage_aggregates` | DELIBERATELY-N-A | process-local read-of-record; a Worker has no process |
| `payment_attempts` | ABSENT-BUT-MARKED | x402 deprioritized by standing directive; marker in `d1/wallet-d1.ts` |
| `mcp_oauth_authorization_states`, `mcp_oauth_flows`, `mcp_oauth_credentials` | DELIBERATELY-N-A | re-architected onto Durable Object storage in `apps/mcp` — a DO gives the CAS that KV cannot, which is *better* than the Postgres original |
| `self_hosted_run_dispatch_capabilities` | DELIBERATELY-N-A | folded into the dispatch document (§1.4.8) |
| `guardrail_evaluations`, `guardrail_check_evaluations` | **ABSENT (pre-existing)** | see §4.10 — evidence is in-memory-only, but this matches Rust's D1 backend, not a TS regression |

**Load-bearing constraints survived the port.** Verified present in
`sql/d1-ts/`: the at-most-once fire gate `UNIQUE (schedule_id,
scheduled_fire_at_unix)`; the budget-alert idempotency gate `UNIQUE (scope_type,
scope_id, period_month, threshold_pct)`; `UNIQUE (period_month, scope_type,
scope_id)` plus the **kept** `scope_type` CHECK; the **kept**
`admin_user_tenant_memberships.role` CHECK; `UNIQUE (tenant_id, asset_type, name,
version, variant)`; `UNIQUE (tenant_id, asset_type, name, channel)`;
`wallets.tenant_id UNIQUE`. `test/d1/schema.test.ts` (20 tests) pins the split
table-by-table in both directions.

---

## 3. The eight concurrency proofs (inventory §1.5)

| # | proof | status | held by a test? |
|---|---|---|---|
| 1 | **Wallet reserve — no oversell** (3-statement atomic batch, guard inside the INSERT, empty `RETURNING` = not admitted) | **PRESENT**, faithful, incl. the `ON CONFLICT DO NOTHING` idempotency probe and the S2 `no_wallet`/`insufficient` split | **Yes** — `test/d1/wallet-d1.test.ts` (20 tests) against real SQLite in `workerd`; README §3 records the mutation "replace the in-statement guard with a naive read-then-write → 20 parallel reserves against a balance affording 7 admitted **all 20**" |
| 2 | **Wallet settle / release** | **PRESENT** — settle is one 3-statement batch with every statement guarded on `status='active'`; release is a single guarded `UPDATE … RETURNING` CAS; `settleWalletBalance` uses `balance_after_credits IS NULL` as a claim token so a replay cannot move the balance twice | **Yes** — same file |
| 3 | **Workflow-budget optimistic CAS** | **PRESENT**, and better documented than Rust: the caps are **in the guard** (a debit that decided `exceeded` against a cap of 100 must not commit that verdict if a concurrent top-up raised it to 500), and `IS` not `=` so `NULL`-cap dimensions do not miss forever; bounded at 16 attempts | **Yes** — `test/d1/workflow-budget-d1.test.ts` (18), incl. a parity test against the in-memory reference; mutation "drop the `spent_*` counters from the guard → 10 concurrent debits against a cap of 4 applied all 10" |
| 4 | **Payment-attempt state machine + CAS** | **ABSENT-BUT-MARKED** (deliberate). The pure alphabet and `transitionPaymentAttempt` are ported in `src/payment-attempt.ts`, incl. the invariant that `outcome_unknown` is **non-terminal and retains the hold**. No table, no D1 seam | partially — pure transitions only |
| 5 | **Guardrail-binding generation CAS** | **PRESENT**, but in `apps/gateway/src/guardrails/{binding,d1}.ts`, not `packages/storage`. `packages/storage/src/guardrail-binding.ts` holds the pure generation rule; the durable `UPDATE … WHERE generation = ? RETURNING policy_id` is in the app | **Yes** — `test/guardrail-binding.test.ts` (6) + the gateway's own suite |
| 6 | **Monotonic upserts** (`GREATEST`/`LEAST` → SQLite scalar `max`/`min`) | **PRESENT**, for presence, agent-cost-burn and replay floors; the counter columns correctly use `+=` and **not** `max` (two requests in the same second must both count) | **Yes** — `test/d1/monotonic.test.ts` (12) |
| 7 | **Reference-guarded deletes** | **2 of 3 PRESENT.** Project and workspace put the `NOT EXISTS` guard *inside* the DELETE, removing the TOCTOU window rather than locking it. **`delete_asset_variant_if_unreferenced` is ABSENT** → §4.9 | **Yes** for the two — `test/d1/references-d1.test.ts` (11); mutation "reshape into check-then-delete → RED on exactly 1 test, the late-reference race" |
| 8 | **Billing outbox atomic enqueue** | **PRESENT twice.** `D1BillingEventLedger` (storage, unmounted) and `apps/gateway/src/metering/d1.ts` (mounted) each write `billing_events` + `billing_ledger` + `billing_report_outbox` in one control-DB `batch()`. See §4.11 on the duplication | **Yes** — `test/d1/billing-d1.test.ts` (16) and the gateway's `test/metering/d1.test.ts` |

**Verdict on §1.5: seven of eight proofs survived the port intact, and the two
that matter most for money (1 and 3) survived with better documentation and
stronger tests than the Rust original.** This is the part of the port that is
genuinely done well, and inventing work here would be dishonest.

---

## 4. Findings — ABSENT-AND-UNMARKED (now marked)

Nine findings; each now carries a `PORT-TODO(inventory-data-billing §…)` marker
at the place a future reader will actually look.

| # | finding | inventory § | marker added at | severity |
|---|---|---|---|---|
| 4.1 | **The durable half of `packages/storage` is not mounted on any Worker** | §1.7 | `src/index.ts` | **critical** |
| 4.2 | **The agent-schedule engine is entirely absent** (no module at all) | §1.4.7, §1.2 | `src/index.ts` | **high** |
| 4.3 | `monthly_token_budget` is unenforced — `sum_api_key_committed_tokens` has no port, so `reserveTokenBudget` is unreachable | §1.2 (#330) | `src/d1/usage-d1.ts` | **high** |
| 4.4 | `usage_metadata_rollups` is never written | §1.4.4 (#171/#226) | `src/metadata-rollups.ts` | medium |
| 4.5 | Budget-alert idempotency is in-memory only and no alert path exists | §1.4.3 (#170) | `src/budget-alerts.ts` | medium |
| 4.6 | Retention planners have no storage and no executor — nothing prunes | §1.4.6, §1.2 (#263/#284) | `src/retention.ts` | medium |
| 4.7 | Site-domain verification rate limit is read-then-write, not a CAS | §1.4.6 (#576) | `src/site-domain.ts` | medium |
| 4.8 | No durable asset-metadata store — `asset_channels` never written; `moveAssetChannel` / yank / withheld absent | §1.4.6, §1.2 (#367) | `src/assets.ts` | medium |
| 4.9 | `delete_asset_variant_if_unreferenced` — §1.5.7's third guarded delete | §1.5.7 | `src/references.ts` | low |

### 4.1 The durable half is not mounted (critical)

`D1WalletStore`, `D1WorkflowBudgetStore`, `D1UsageLedger`,
`D1BillingEventLedger`, `D1ReferenceGuardedDeletes`, `TenantMonotonicUpserts`,
`ControlMonotonicUpserts`, `R2AssetBlobStore`, `EnvBindingTenantDatabaseRouter`,
`ControlDatabaseTenantRegistry`, and every `Memory*Store`: **zero importers under
`apps/*/src`.** Neither the gateway nor the control plane ever constructs a
tenant router; each hand-rolls its own D1 access against the same migrations
instead. Consequence: the database-per-tenant topology — the user's standing
directive and the port's central architectural bet — is not in effect anywhere,
and the wallet no-oversell guard protects nothing.

### 4.2 The agent-schedule engine is absent (high)

`crates/ferrogate-storage/src/agent_schedule.rs` (1,017 lines) plus
`control_plane_store_d1/agent_schedule.rs` (563) carry cron parsing (`croner`),
IANA timezones (`chrono-tz`), interval specs, `next_fire_at` computation,
`overlap_policy` (skip|allow), `catchup_policy` (skip_missed|fire_once),
`jitter_secs`, the due-query, and the at-most-once fire gate. **None of it
exists in TS.** `sql/d1-ts/tenant/` creates `agent_schedules` and
`agent_schedule_fires` *with* the `UNIQUE (schedule_id, scheduled_fire_at_unix)`
gate and no code writes either table. What exists is CRUD only:
`apps/control-plane/src/routes/admin_agent_schedule.ts` stores schedules as
generic documents, `/fires` lists a collection nothing appends to, and `run-now`
sets `{ run_now: true }` on the document — no dispatch, no fire row. **A schedule
an operator creates never fires**, and a naive firing loop added later without
the `ON CONFLICT DO NOTHING` gate turns two Workers racing the same cron minute
into duplicate paid agent runs.

### 4.3 Monthly token budget is unenforced (high)

Rust: `sum_api_key_committed_tokens(api_key_id)` pushes the sum into SQL and
feeds `try_reserve_tokens(api_key_id, committed, budget, estimated)`. TS has the
*consumer* — `RateLimiter.reserveTokenBudget(counterKey, committed, budget,
estimatedTokens)` exists in `ports.ts`, `durable-object.ts`, `memory.ts` and
`do-limiter.ts`, and is exercised by 8 assertions — but **no production caller**,
because nothing supplies `committed`. `apps/gateway/src/ratelimit/middleware.ts`
enforces rpm/tpm and the monthly **USD** budget and never touches it. The only
surviving token check is the degenerate `monthly_token_budget === 0` on **static
config** keys, so a durable key with a budget of one million tokens can never
exhaust it. This is the same "tested but unmounted" shape as 4.1, one layer down.

### 4.4 `usage_metadata_rollups` never written

`D1UsageLedger.persistUsageAggregate` batches `tenant_contexts` +
`usage_aggregate_rollups` + `usage_monthly_rollups` and stops. Metadata rollups
are the only aggregation dimension orthogonal to the scope chain — they are how
an operator answers "what did feature X cost". That question has no answer, and
the spend is unattributable after the fact. Close: one more statement per
metadata pair **inside the same batch**, so attribution cannot land without the
spend it explains.

### 4.5 Budget alerts

The table with its `UNIQUE` gate exists; `alert_threshold_pcts_json` is read into
`EffectiveQuota`; **nothing compares spend to a threshold and nothing records a
notification.** Note that a Worker isolate does not outlive the request, so
`MemoryBudgetAlertStore` cannot suppress anything — a durable implementation that
skips the table will re-fire a tenant's 80/90/100% webhook on *every* request
after the crossing.

### 4.6 Retention has planners but no storage and no executor

`planVersionRetention` / `planLogRetention` / `planBlobGc` are ported, pure and
tested (7 tests). Nothing reads or writes `retention_policies`; nothing calls the
planners; `R2AssetBlobStore.deleteOrphans` has no caller. `request_logs`,
`audit_events`, `agent_run_events` and R2 blobs are append-only on this platform
and **nothing prunes them**. `apps/gateway/src/worker.ts` already exposes a
`scheduled` handler for the billing outbox — that is where the sweeper hangs.

### 4.7 Site-domain verification: read-then-write, not CAS

Rust puts the cooldown predicate **inside the writing statement**
(`control_plane_store_d1/rbac_site_domain.rs`): `UPDATE … WHERE tenant_id = ? AND
hostname = ? AND (last_checked_at_unix IS NULL OR ? - last_checked_at_unix >= ?)`
— `changes() > 0` *is* the grant, and the pure decision function runs only to
*label* a refusal. The TS caller
(`apps/control-plane/src/routes/site_domain.ts`) reads the document, calls
`siteDomainVerificationAttemptDecision`, then issues an **unconditional** merge.
Two concurrent `POST …/verify` calls read the same `lastCheckedAtUnix`, are both
told `allowed`, and both reach `lookupTxt` — the exact burst #576 exists to stop
(an `admin.write` credential must not be able to drive unbounded outbound DNS).
The module's own docblock correctly says "every backend then reserves the slot
with an atomic conditional write on exactly this predicate"; no backend does.

### 4.8 No durable asset-metadata store

`apps/gateway/src/assets/ports.ts` declares the full `AssetMetadataStore`
(`listAssetChannels`, `moveAssetChannel`, `deleteAssetChannel`) and its **only**
implementation is `InMemoryAssetMetadataStore`. `packages/storage/src/assets.ts`
declares `ChannelMoveOutcome` with **no producer anywhere**. Nothing writes
`stored_assets` or `asset_channels`. `latest`/`stable`/`canary` are resolved at
pull time from rows that never persist, so a published asset is unresolvable on
the next request and the yank flag — the kill switch for a bad artifact — cannot
survive a deploy. `R2AssetBlobStore` already holds the bytes half; only the
metadata half is missing.

### 4.9 `delete_asset_variant_if_unreferenced`

§1.5.7 names three reference-guarded deletes; two are ported. Without the third,
deleting a variant that `latest` still points at leaves a dangling channel and
every subsequent pull 404s on a name the operator believes is published.

### 4.10 Guardrail evidence (pre-existing, NOT a TS regression — no marker added)

`guardrail_evaluations` / `guardrail_check_evaluations` are Postgres-only and
RLS-scoped; **Rust's own D1 backend never created them either.** TS ships
`InMemoryGuardrailEvidenceSink` (`apps/gateway/src/guardrails/`). The behavior
gap versus Postgres is real — sanitized evidence never survives the isolate, so
the #309 evidence-writer and the `guardrail_evidence_persistence_failure` metric
have nothing behind them — but it is inherited from the reference design, and the
sink lives outside `packages/storage`, so it belongs to a guardrails slice. Left
unmarked here deliberately; recorded so it is not lost.

### 4.11 Duplication (not a gap — recorded so it does not become one)

Three surfaces now exist twice, in `packages/storage` and again inside an app:
the billing-outbox batch (`D1BillingEventLedger` vs
`apps/gateway/src/metering/d1.ts`, the latter mounted), the asset DTOs +
`ChannelMoveOutcome` (`src/assets.ts` vs `apps/gateway/src/assets/ports.ts`), and
the guardrail-binding CAS (pure half in storage, durable half in the gateway).
Each pair is independently correct today. They are a drift hazard, and closing
4.1 is also what removes them.

---

## 5. ABSENT-BUT-MARKED (pre-existing markers — all verified accurate)

| marker | file | verdict |
|---|---|---|
| §1.6 Postgres pool — PLATFORM LIMIT | `src/provider.ts` | accurate; `PostgresStorageConfig` is inert and `test/platform-limits.test.ts` pins that it has no behavior |
| §1.4.5/§1.5.4 x402 payment attempts | `src/payment-attempt.ts` | accurate |
| §4 x402 — `sweepExpiredWalletReservations` lacks the `NOT EXISTS (payment_attempts …)` hold guard (#396/#352) | `src/d1/wallet-d1.ts` | accurate and correctly scoped: it names the money-safety consequence rather than hiding it |
| §1.5.8 no cross-database transaction — the claim/accumulate pair straddles control and tenant | `src/d1/usage-d1.ts` | accurate; the residual window **under**-counts rather than double-bills, which is the right direction to fail |
| §1.7 per-tenant D1 binding at runtime | `src/tenant-router.ts` | accurate, and `D1RestTenantDatabaseRouter` correctly **throws** rather than silently losing atomicity |
| §9.3 `control_plane_resources` has no indexable `tenant_id`; typed tables not projected | `apps/control-plane/src/store/d1.ts` | accurate |

---

## 6. DELIBERATELY-N-A-ON-CF (correctly gone; no work owed)

deadpool-postgres pool + `RecyclingMethod::Verified` + acquire metrics · the
~16-connection Supavisor cap · `PostgresTlsMode` (5 variants) · Row-Level
Security and `current_setting('ferrogate.tenant_id')` · `SELECT … FOR UPDATE` ·
JSONB + GIN indexes and JSONB operators · cross-table FK `ON DELETE CASCADE`
across databases · `GREATEST`/`LEAST` · `pg_constraint` schema introspection and
the FNV-1a DDL checksum (→ `wrangler d1 migrations`) · the `d1-proxy` HTTP hop and
its string-parameter marshalling (`CAST(? AS INTEGER)` / `NULLIF(?, '')`
wrappers, correctly dropped because `.bind(n)` sends a real number) · the
`ControlPlaneStore` 3-backend trait + `RuntimeStorageRepositories` dispatch ·
`StorageProviderKind::{TursoLibsql, Mysql}` (never implemented in Rust either).

Two of these are *improvements*, not merely losses, and deserve saying so: the
control/tenant migration split makes a mis-routed write fail loudly with `no such
table` where the Rust single-file schema silently accepted it; and
`api_key_directory` replaces Rust's authenticate-by-fan-out-over-every-tenant-
database with a point lookup, which was indefensible on the inference hot path.

---

## 7. What I checked and found genuinely fine (so nobody re-checks it)

- `StorageError` — full kind set **including** the async commit-fence bits
  (`operation_deadline_exceeded`, `operation_cancelled`,
  `operation_commit_outcome_unknown`, `commitStarted`), plus
  `sanitizeStorageError` DSN scrubbing.
- Deterministic id helpers — all 12 present, `periodMonthFromUnix` included.
- `validateQuotaPolicy`, `QuotaScopeKind`, `StoredPlan`, `OverviewUsageTotals`.
- The effective-quota merge (key→workspace→project→plan, clamp-to-ancestor,
  allowlist intersection, min-across-chain) — present in `packages/policy`, with
  a contradictory-intersection-denies-everything test. Correctly *not* in
  storage, matching Rust's own split.
- Lifecycle status: read side fails **open** on legacy/unknown tokens, write side
  is strict — both directions tested.
- Asset quota admission classifier and the `pending_scan → visible|quarantined`
  promotion CAS (pure halves).
- `errors` / `provider` / `ids` / `retention` planners / `lifecycle-status` —
  no gaps found.

---

## 8. Recommended order

1. **4.1 — mount the durable half** (tasks #41/#42). Everything else is cheaper
   afterwards, and three duplications disappear with it. The closer must add an
   assertion that fails when the mount is removed and prove it red.
2. **4.3 — `sumApiKeyCommittedTokens` + the middleware call.** One D1 read plus
   one call site; the DO ledger half is already built and tested. Highest value
   per line in this list.
3. **4.7 — the site-domain CAS.** Small, and it is a security property.
4. **4.4 + 4.5** — two statements each, both inside batches that already exist.
5. **4.8 + 4.9** — one `D1AssetMetadataStore` closes both.
6. **4.6** — the retention sweeper (hangs off the existing `scheduled` handler).
7. **4.2** — the agent-schedule engine. Largest, and the only one that needs new
   design (cron + IANA tz in a Worker; `[triggers] crons` plus a DO alarm for
   jittered/sub-minute fires).
