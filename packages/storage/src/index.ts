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
 * See the per-module `PORT_TODO(<inventory §>)` markers for the surfaces with no
 * clean CF equivalent (Postgres pool/RLS/FOR UPDATE, x402 payments, R2 blob move).
 *
 * ---------------------------------------------------------------------------
 * PORT-TODO(P: inventory-data-billing §1.7 "Proposed CF/TS mapping") — THE DURABLE
 * HALF OF THIS PACKAGE IS MOUNTED IN PART. Six exports are still dead.
 *
 * This marker used to say "not mounted on any Worker … ZERO importers". That is
 * NO LONGER TRUE, and a marker that overstates the damage is as misleading as
 * one that understates it, so it is restated against a re-grep of `apps/`:
 *
 * MOUNTED, on the real request path, through a routed tenant handle:
 *   - `EnvBindingTenantDatabaseRouter` → `apps/gateway/src/tenancy/*`
 *     (+ `src/index.ts`),
 *     `apps/control-plane/src/{adapters,store/tenancy,store/api_keys}.ts`,
 *     `apps/mcp/src/{ports,auth}.ts`. `ControlDatabaseTenantRegistry` rides
 *     along INSIDE it (the router constructs one); no app names it directly, so
 *     it is mounted transitively, not directly — the three apps that appear to
 *     import it only mention it in comments.
 *   - `NonAtomicD1RestTenantDatabaseRouter` and `SharedDatabaseTenantRouter` →
 *     `apps/gateway/src/tenancy/resolver.ts`. Both were missing from this list
 *     AND from the gate below, i.e. neither claimed live nor claimed dead — the
 *     state in which a mount can disappear with every suite still green. The
 *     REST one is the fail-closed escape hatch for a tenant fleet larger than
 *     the binding budget (`supportsAtomicBatch: false`, so `requireAtomicBatch`
 *     keeps every guarded write off it); the shared one is the development
 *     posture whose `source: "shared_development"` label says it carries no
 *     physical isolation.
 *   - `D1WalletStore` → `apps/gateway/src/ratelimit/{wallet,middleware}.ts`;
 *     the no-oversell reserve now guards real money.
 *   - `D1WorkflowBudgetStore` → `apps/gateway/src/ratelimit/workflow.ts`.
 *   - `D1UsageLedger` → `apps/gateway/src/metering/{runtime,sink,usage-ledger}.ts`
 *     and `src/ratelimit/{middleware,token-budget}.ts`.
 *   - `D1ReferenceGuardedDeletes` → `apps/control-plane/src/{ports,store/tenancy}.ts`.
 *   - `D1BudgetAlertStore` → `apps/gateway/src/metering/budget-alerts.ts`
 *     (WAVE 20). `MeteringUsageSink` compares post-charge spend against the
 *     tenant's alert thresholds and this class is the once-per-period arbiter:
 *     `claimBudgetAlertNotification` is an `INSERT` whose UNIQUE violation IS
 *     the "already notified" answer, so two isolates crossing the same
 *     threshold concurrently send ONE webhook between them. Closing cutover
 *     HOLD item A1.
 *   - `D1SiteDomainVerificationStore` →
 *     `apps/control-plane/src/routes/site_domain.ts` (#738). The
 *     `site_domain_verifications` table had NO writer at all, so a completed
 *     DNS-TXT ownership proof lived only in the generic
 *     `control_plane_resources` document and `apps/gateway`'s custom-domain
 *     resolver — which joins the typed `site_domains` and
 *     `site_domain_verifications` rows — read an empty directory on every
 *     deployment. `verifySiteDomain` now projects the proof into the typed
 *     table through this class.
 *
 * STILL DEAD — zero importers anywhere under `apps/`, so deleting any of them
 * would leave every suite in this repo green:
 *   - `D1BillingEventLedger`      (the billing outbox drain)
 *   - `D1RetentionPolicyStore`    (see `./retention.js` — no cron calls it)
 *   - `D1AgentScheduleStore`      (see the §1.4.7 marker below)
 *   - `TenantMonotonicUpserts` / `ControlMonotonicUpserts`
 *   - `R2AssetBlobStore`
 *   - `D1AssetMetadataStore`      (duplicated app-locally, see below)
 *
 * TWO of those are dead by DUPLICATION rather than by a missing trigger, which
 * is the worse failure: a second implementation exists, is live, and can drift
 * from the one that has the tests.
 *   - assets: `apps/gateway/src/assets/d1.ts` declares its own
 *     `D1AssetMetadataStore` and imports nothing from here
 *     (`docs/rewrite/parity-audit-storage.md` §4.11 records the decision).
 *   - agent schedules: `apps/control-plane/src/schedule/{cron,engine,model,
 *     scheduled}.ts` is a SECOND, independent ~1650-line schedule engine with
 *     its own 5-field cron parser, and it does not import `@ferrogate/storage`.
 *
 * The close is the composition roots, NOT this package (a library cannot mount
 * itself); `packages/storage/README.md` §4 has the exact wiring. The split above
 * is not just prose: `test/mount-inventory.test.ts` re-derives it from `apps/`
 * on every run, so mounting one of the dead exports — or unmounting a live one —
 * turns this package RED and forces the marker to be corrected with it.
 * ---------------------------------------------------------------------------
 *
 * PORT-TODO(P: inventory-data-billing §1.4.7 `agent_schedules` / `agent_schedule_fires`)
 * — SHARPENED. The ENGINE is no longer absent; the TICK TRIGGER still is, and a
 * RIVAL ENGINE has landed in `apps/control-plane` in the meantime.
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
 * STILL OPEN, and NOT CLOSABLE FROM A LIBRARY PACKAGE: nothing TICKS *this*
 * engine. A `packages/*` library has no Worker entry module and no
 * `wrangler.toml`, so it cannot declare `[triggers] crons` or a Durable Object
 * alarm; `listDueSchedules` → `planScheduleTick` → `insertScheduleFire` →
 * `advanceSchedule` has no caller under `apps/`.
 *
 * WHAT CHANGED, and why it is worse than "no trigger": a trigger now exists, on
 * a DIFFERENT engine. `apps/control-plane/src/schedule/{cron,engine,model,
 * scheduled}.ts` (~1650 lines) re-implements the cron parser, the timezone
 * arithmetic, the overlap/catch-up policies and the tick, and imports nothing
 * from here. So the repo carries TWO schedule engines: the one that ticks, and
 * the one with `test/agent-schedule.test.ts` + `test/d1/agent-schedule-d1.test.ts`
 * behind it (including the two-claimer race on the at-most-once fire gate). They
 * can disagree about when a schedule fires and no test in either tree would
 * notice.
 *
 * The resolution is a DELETION, not more code, and it belongs to whoever owns
 * the composition root: point `apps/control-plane/src/schedule/` at
 * `@ferrogate/storage`'s engine + `D1AgentScheduleStore` on the tenant handle
 * and delete the duplicate, or delete THIS engine and move its tests over.
 * Keeping both is the option that guarantees a divergence. A Durable Object
 * alarm remains the answer for sub-minute cadences, since cron triggers do not
 * go below one minute.
 */

export * from "./errors.js";
export * from "./provider.js";
export * from "./ids.js";
export * from "./quota.js";
export * from "./wallet.js";
export * from "./credits.js";
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
 * Tamper-evidence for `audit_events` (#684): the row hash chain, the anchor
 * document, and the verifier. Pure and dependency-free on purpose — the
 * customer-facing procedure (`scripts/verify-audit-chain.mjs`) imports the SAME
 * code the control-plane writer uses, so the published algorithm cannot drift
 * from the implemented one.
 */
export * from "./audit-chain.js";

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
