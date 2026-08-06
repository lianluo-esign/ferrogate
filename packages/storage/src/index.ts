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
 *   - `SharedDatabaseTenantRouter` → `apps/gateway/src/tenancy/resolver.ts`.
 *     It is the development posture whose `source: "shared_development"`
 *     label says it carries no physical isolation.
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
 *   - `D1AgentScheduleStore` -> `apps/control-plane/src/schedule/tenant-schedule.ts`
 *     (#856). Tenant-object schedules now use this store's durable claim gate;
 *     native-binding tenants remain on the compatibility scheduler during the
 *     migration.
 *
 * STILL DEAD — zero importers anywhere under `apps/`, so deleting any of them
 * would leave every suite in this repo green:
 *   - `D1BillingEventLedger`      (the billing outbox drain)
 *   - `D1RetentionPolicyStore`    (see `./retention.js` — no cron calls it)
 *   - `TenantMonotonicUpserts` / `ControlMonotonicUpserts`
 *   - `R2AssetBlobStore`
 *   - `D1AssetMetadataStore`      (duplicated app-locally, see below)
 *
 * The remaining `D1AssetMetadataStore` is dead by DUPLICATION rather than by a
 * missing trigger, which is the worse failure: a second implementation exists,
 * is live, and can drift from the one that has the tests.
 *   - assets: `apps/gateway/src/assets/d1.ts` declares its own
 *     `D1AssetMetadataStore` and imports nothing from here
 *     (`docs/rewrite/parity-audit-storage.md` §4.11 records the decision).
 *   - agent schedules: the tenant-object path uses `D1AgentScheduleStore`,
 *     while `apps/control-plane/src/schedule/{cron,engine,model,scheduled}.ts`
 *     remains a SECOND implementation for native/compatibility tenants.
 *
 * The close is the composition roots, NOT this package (a library cannot mount
 * itself); `packages/storage/README.md` §4 has the exact wiring. The split above
 * is not just prose: `test/mount-inventory.test.ts` re-derives it from `apps/`
 * on every run, so mounting one of the dead exports — or unmounting a live one —
 * turns this package RED and forces the marker to be corrected with it.
 * ---------------------------------------------------------------------------
 *
 * PORT-TODO(P: inventory-data-billing §1.4.7 `agent_schedules` / `agent_schedule_fires`)
 * — SHARPENED. The tenant-object engine is mounted; the native-binding fallback
 * and its rival scheduler remain until the migration is complete.
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
 * CLOSED for the object-backed path: `apps/control-plane/src/schedule/alarm-queue.ts`
 * calls this engine against a tenant handle after a Durable Object alarm. A
 * `packages/*` library still has no Worker entry module and no `wrangler.toml`,
 * so the native-binding compatibility path keeps its own scheduled trigger.
 *
 * WHAT CHANGED: the object-backed path now uses this engine's transaction-backed
 * claim gate and per-object alarm delivery. The native compatibility path still
 * carries a second engine, so both implementations remain covered until that
 * fallback is retired.
 *
 * The remaining resolution is to retire the native compatibility engine after
 * all tenants are object-backed. A Durable Object alarm remains the answer for
 * sub-minute cadences, since cron triggers do not go below one minute.
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
export * from "./tenant-schedule-alarm.js";
export * from "./tenant-placement.js";
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
 * The DURABLE-OBJECT leg of the tenant router (strategy `durable_object`): a
 * `D1Database`-shaped facade over one tenant's `TenantDataObject`, with
 * `batch()` forwarded into the object's `transactionSync()` in ONE round trip
 * and `supportsAtomicBatch: true`, so the 13 `requireAtomicBatch()` money paths
 * RUN over it instead of refusing.
 *
 * Exporting it from this barrel is safe and `./tenant-data-object.js` is not:
 * every reference this module makes to the object's types is `import type` and
 * is erased at compile time, so nothing here reaches `cloudflare:workers`. See
 * the note below on why the CLASS still ships through a subpath.
 */
export * from "./tenant-do.js";
/**
 * The router that picks between the two legs above PER TENANT, from
 * `tenant_databases.storage_backend`.
 *
 * `apps/control-plane` mounts it. Its tenant-data paths cannot simply switch to
 * `durable_object` — a `native_binding` tenant's rows really are in a D1
 * database — and they cannot stay on the binding router either, because since
 * #820 every newly onboarded tenant is on an object the binding router cannot
 * reach, which made an admin wallet credit write nothing and the fleet asset
 * view report an empty fleet.
 */
export * from "./tenant-dispatch.js";
/** Resumable shared-D1 to Durable-Object backfill manifest and receipts. */
export * from "./tenant-backfill.js";
/**
 * TENANT ONBOARDING (#820): the tenant's own model catalog and the seeder that
 * fills it once, plus the provisioner that refuses an unregistered tenant BEFORE
 * addressing its object, records resumable state on `tenant_databases`, and
 * states the deprovisioning retention decision as code rather than as a guess.
 *
 * Both are plain `D1Database` consumers — they reach a tenant through the
 * `TenantDatabaseRouter` port and never through a `TenantDataObject` stub — so
 * they run identically over `native_binding` and `durable_object`, and neither
 * pulls `cloudflare:workers` into this barrel's graph.
 */
export * from "./tenant-model-catalog.js";
export * from "./tenant-provisioning.js";
export * from "./mcp-catalog.js";
export * from "./tenant-config-backfill.js";
export * from "./d1/index.js";

/**
 * `TenantDataObject` (#822) IS NOT EXPORTED HERE, AND THAT IS DELIBERATE.
 *
 * It reaches consumers through the `@ferrogate/storage/durable-objects` subpath
 * in `package.json`, copying `@ferrogate/routing`'s `./durable-objects` →
 * `./src/shadow-budget-do.ts` shape. Two independent reasons, both load-bearing:
 *
 *  1. `src/tenant-data-object.ts` imports the `DurableObject` base class from
 *     `cloudflare:workers`, which resolves in `workerd` and NOWHERE ELSE. This
 *     barrel is imported by plain-node vitest suites (`test/wallet.test.ts` and
 *     nine others import `../src/index.js`) and by `apps/cli`; an `export *`
 *     here would make every one of them fail to resolve a module they never use.
 *  2. workerd resolves a `[[durable_objects.bindings]]` `class_name` against the
 *     ENTRY module's named exports. Pulling the class into every importer's
 *     graph is exactly how that resolution failure gets hidden — the class looks
 *     reachable from everywhere while `apps/gateway/src/worker.ts` is the only
 *     place the export actually counts.
 *
 * `./tenant-schema-sql.js` is likewise absent: it is a GENERATED module inlining
 * ~66 KB of `sql/d1-ts/tenant/*.sql` bytes, and its only consumer is the object
 * that applies them. Re-exporting it would put the whole tenant schema in the
 * CLI's bundle to no purpose. `test/tenant-schema-sql.test.ts` reaches it by
 * relative path and pins it byte-for-byte against the directory on disk.
 *
 * The mount claim for the class is therefore made where it can fail:
 * `test/mount-inventory.test.ts` re-derives it from `apps/` on every run, so
 * deleting the `src/worker.ts` re-export reddens this package.
 */
