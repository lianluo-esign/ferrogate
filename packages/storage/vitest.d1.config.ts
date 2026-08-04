import { d1SuiteConfig } from "./vitest.d1.shared.js";

/**
 * The D1 suite: `test/d1/**` runs inside the REAL local `workerd` (miniflare),
 * against REAL D1 SQLite databases — no fake, no stub, no in-memory shim.
 *
 * This is a SECOND config rather than a replacement for `vitest.config.ts`
 * because the two suites answer different questions and have different costs:
 *
 *   * `vitest.config.ts`  — the pure-algorithm tests. Plain vitest, ~250 ms.
 *     They are the executable specification of every invariant.
 *   * `vitest.d1.config.ts` (this file) — the durable twins. Boots `workerd`,
 *     so it is far slower, and it is the ONLY place the atomicity claims
 *     (`batch()` is one transaction, `RETURNING` reports the guard, SQLite
 *     serializes writers) are actually exercised. An in-memory fake asserting
 *     these would be exactly the green-but-vacuous test this repo keeps being
 *     bitten by: a fake's `batch()` is atomic because the fake says so.
 *
 * `bun run test` in this package runs all FOUR legs (see package.json). The
 * fourth is `vitest.d1do.config.ts`, which runs THIS suite again against
 * per-tenant Durable Objects through the `D1Database` facade — the acceptance
 * test for #823. The shared body of both is in `vitest.d1.shared.ts`; the only
 * difference is the `TENANT_BACKEND` binding the harness reads.
 *
 * ## Bindings
 *
 * `CONTROL_DB` plus three tenant databases. Three, not one, because the
 * router's whole job is to hand back DIFFERENT databases, and cross-tenant
 * isolation cannot be observed with a single database — the test would pass
 * against a router that ignored its argument.
 *
 * `TENANT_DB_UNBOUND` is deliberately NOT declared: `test/d1/router.test.ts`
 * registers a tenant naming it and asserts the router FAILS CLOSED rather than
 * falling back to the control database.
 */
export default d1SuiteConfig("native_binding");
