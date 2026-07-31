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
export * from "./d1/index.js";
