/**
 * `@ferrogate/storage` — the persistence boundary for the FerroGate control
 * plane and its per-tenant financial/usage/asset state.
 *
 * Clean-room re-implementation of the Rust crate `ferrogate-storage`. The Rust
 * crate carries three interchangeable backends (in-memory, Postgres/Supabase, and
 * Cloudflare D1); the CF target is D1 (SQLite), with KV for caches and R2 for
 * asset blobs. This package ports the crate's **pure, load-bearing core** — the
 * error taxonomy, the `Stored*` DTOs, the deterministic id/period helpers, and
 * every concurrency-critical algorithm (inventory §1.5): wallet no-oversell
 * reserve/settle/release, workflow-budget debit, guardrail-binding generation CAS,
 * asset quota-admission + visibility promotion, retention/GC planning, monotonic
 * presence/agent-burn upserts, budget-alert idempotency, the reference-guarded
 * project/workspace deletes (§1.5.7), and the site-domain verification
 * rate-limit CAS.
 *
 * Each algorithm ships a reference **in-memory backend** (`Memory*Store`) that is
 * the read-modify-write baseline the durable D1/Postgres backends mirror; a
 * single JS thread serializes writers exactly as the Postgres row lock / D1 atomic
 * batch does, giving the identical no-oversell / no-lost-update invariants.
 *
 * See the per-module `PORT-TODO(<inventory §>)` markers for the surfaces with no
 * clean CF equivalent (Postgres pool/RLS/FOR UPDATE, x402 payments, R2 blob move).
 *
 * ---------------------------------------------------------------------------
 * PORT-TODO(inventory-data-billing §1.7 "Proposed CF/TS mapping") — THE DURABLE
 * HALF OF THIS PACKAGE IS NOT MOUNTED ON ANY WORKER.
 *
 * Every class exported below `./tenant-router.js` — `D1WalletStore`,
 * `D1WorkflowBudgetStore`, `D1UsageLedger`, `D1BillingEventLedger`,
 * `D1ReferenceGuardedDeletes`, `TenantMonotonicUpserts`,
 * `ControlMonotonicUpserts`, `R2AssetBlobStore`,
 * `EnvBindingTenantDatabaseRouter`, `ControlDatabaseTenantRegistry` — plus every
 * every `Memory…Store` above it, has ZERO importers under any app's `src`. A
 * grep for `@ferrogate/storage` across the apps returns three call sites and all
 * three take PURE helpers only: `periodMonthFromUnix` / `boolFromSqlite` /
 * `optionalNumber` / `WALLET_RESERVATION_ACTIVE`
 * (`apps/gateway/src/ratelimit/quota.ts`), `sha256Hex`
 * (`apps/control-plane/src/site_domain_txt.ts`), and the site-domain value types
 * (`apps/control-plane/src/routes/site_domain.ts`).
 *
 * Why it matters: this is precisely the repo's recurring defect — implemented,
 * proven (104 pure + 152 D1 tests, mutation-tested per README §3), and DEAD in
 * production. The no-oversell wallet guard is not protecting any money, because
 * nothing calls `reserveWalletCredits`; the tenant router is not routing
 * anything, so the database-per-tenant topology is not in effect on any deployed
 * path. Neither the gateway nor the control plane holds a `TENANT_DB` handle:
 * `apps/gateway/src/ratelimit/quota.ts` and `apps/control-plane/src/store/d1.ts`
 * each hand-roll their own D1 access against the same migrations instead.
 *
 * The close is the composition roots, NOT this package: `apps/gateway` and
 * `apps/control-plane` must construct `EnvBindingTenantDatabaseRouter(env,
 * env.CONTROL_DB)` and route the money/usage paths through the stores here (see
 * `packages/storage/README.md` §4 for the exact wiring). Whoever does it must
 * add an assertion that FAILS when the store is unmounted — deleting the mount
 * has to turn a test red, or this comment will be true again in a month.
 *
 * PARTIAL CLOSE (tenant ROUTING half): `apps/gateway/src/tenancy/` now imports
 * `EnvBindingTenantDatabaseRouter`, `ControlDatabaseTenantRegistry`,
 * `requireAtomicBatch` and `NonAtomicD1RestTenantDatabaseRouter` and exposes
 * them to the request path as `tenantDatabase()` + `tenantDatabaseOf(c)`, with
 * the unmount gate the paragraph above demands: `apps/gateway/test/tenancy/`
 * asserts the resolver IS `EnvBindingTenantDatabaseRouter` (a hand-rolled
 * replacement turns it red), that two tenants get two PHYSICALLY different D1
 * databases, and that an unresolvable tenant errors instead of falling back to
 * the shared/control database. STILL OPEN: the `D1*Store` half — nothing yet
 * calls `reserveWalletCredits`/`debitWorkflowBudget`/`D1UsageLedger` through a
 * routed handle, so the guards still guard no money.
 * ---------------------------------------------------------------------------
 *
 * PORT-TODO(inventory-data-billing §1.4.7 `agent_schedules` / `agent_schedule_fires`)
 * — SHARPENED. The ENGINE is no longer absent; the TICK TRIGGER still is.
 *
 * CLOSED in this package: `./agent-schedule.js` ports the whole engine
 * clean-room — a 5-field cron parser (no `croner`), IANA-timezone wall-clock
 * arithmetic on `Intl.DateTimeFormat` (no `chrono-tz`) with DST transitions and
 * spring-forward gaps handled explicitly, interval specs, `next_fire_at`,
 * `overlap_policy` (skip|allow), `catchup_policy` (skip_missed|fire_once), the
 * bounded catch-up fast-forward, and the write-time validator. `jitterSecs` is
 * stored and validated and applied by NOTHING, because Rust's own tick loop
 * never reads it either — recorded rather than invented.
 * `./d1/agent-schedule-d1.js` is the durable half: the due scan over the partial
 * index, the atomic delete-with-fire-cascade (D1 has no `ON DELETE CASCADE`),
 * and the AT-MOST-ONCE fire gate `INSERT ... ON CONFLICT (schedule_id,
 * scheduled_fire_at_unix) DO NOTHING RETURNING fire_id`, whose returned row IS
 * the claim. `test/d1/agent-schedule-d1.test.ts` races two claimers on one slot,
 * asserts exactly one wins, and mutation-pins the gate.
 *
 * STILL OPEN, and NOT CLOSABLE FROM A LIBRARY PACKAGE: nothing TICKS. A
 * `packages/*` library has no Worker entry module and no `wrangler.toml`, so it
 * cannot declare `[triggers] crons` or a Durable Object alarm. Until a
 * deployable calls `listDueSchedules` → `planScheduleTick` → `insertScheduleFire`
 * → `advanceSchedule` on a schedule, a schedule an operator creates STILL never
 * fires. What exists on the deployed path today is CRUD only:
 * `apps/control-plane/src/routes/admin_agent_schedule.ts` stores schedules as
 * generic `control_plane_resources` documents, its `/fires` route lists a
 * collection nothing appends to, and `run-now` merely sets `{ run_now: true }`
 * on the document. The wiring owed is: swap that route onto
 * `D1AgentScheduleStore` on the tenant handle, and add a `scheduled` handler
 * (plus a `[triggers] crons` stanza) that drives the four calls above. A Durable
 * Object alarm is the answer for sub-minute cadences, since cron triggers do not
 * go below one minute.
 */

export * from "./errors.js";
export * from "./provider.js";
export * from "./ids.js";
export * from "./quota.js";
export * from "./wallet.js";
export * from "./workflow-budget.js";
export * from "./guardrail-binding.js";
export * from "./assets.js";
export * from "./retention.js";
export * from "./presence.js";
export * from "./agent-cost-burn.js";
export * from "./budget-alerts.js";
export * from "./metadata-rollups.js";
export * from "./lifecycle-status.js";
export * from "./site-domain.js";
export * from "./references.js";
export * from "./payment-attempt.js";
export * from "./agent-schedule.js";

/**
 * The D1 persistence foundation (JOBs 1–4).
 *
 * `./tenant-router.js` is the tenantId → D1 handle seam; `./d1/*` are the
 * durable twins of the in-memory algorithms above, running the atomic
 * `batch()` / guarded-`UPDATE ... RETURNING` primitives against a real D1
 * binding. The SQL these expect is `sql/d1-ts/control/0001_init_control.sql`
 * (account-global) and `sql/d1-ts/tenant/0001_init_tenant.sql` (one per
 * tenant); see `packages/storage/README.md` for the split and for how a
 * composition root wires the router.
 *
 * NOTE these exports pull in `@cloudflare/workers-types` `D1Database` TYPES
 * only — there is no top-level side effect and no binding is touched at import
 * time, so importing `@ferrogate/storage` from a non-Worker context (the CLI,
 * a plain vitest suite) stays safe.
 */
export * from "./tenant-router.js";
/**
 * The REST leg of the tenant router (strategy (c) of `D1_BINDING_STRATEGIES`):
 * a `D1Database`-shaped client addressed by RUNTIME `database_uuid`, with
 * `batch()` refused and `supportsAtomicBatch: false` so `requireAtomicBatch`
 * keeps every money path off it. See the file docblock for the exact
 * atomic/non-atomic table.
 */
export * from "./tenant-rest.js";
export * from "./d1/index.js";
