import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * The D1 suite: `test/d1/**` runs inside the REAL local `workerd` (miniflare),
 * against REAL D1 SQLite databases — no fake, no stub, no in-memory shim.
 *
 * This is a SECOND config rather than a replacement for `vitest.config.ts`
 * because the two suites answer different questions and have different costs:
 *
 *   * `vitest.config.ts`  — the 87 pure-algorithm tests. Plain vitest, ~250 ms.
 *     They are the executable specification of every invariant.
 *   * `vitest.d1.config.ts` (this file) — the durable twins. Boots `workerd`,
 *     so it is far slower, and it is the ONLY place the atomicity claims
 *     (`batch()` is one transaction, `RETURNING` reports the guard, SQLite
 *     serializes writers) are actually exercised. An in-memory fake asserting
 *     these would be exactly the green-but-vacuous test this repo keeps being
 *     bitten by: a fake's `batch()` is atomic because the fake says so.
 *
 * `bun run test` in this package runs BOTH (see package.json).
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
const here = path.dirname(fileURLToPath(import.meta.url));
const sqlRoot = path.resolve(here, "../../sql/d1-ts");

const controlMigrations = await readD1Migrations(path.join(sqlRoot, "control"));
const tenantMigrations = await readD1Migrations(path.join(sqlRoot, "tenant"));

if (controlMigrations.length === 0 || tenantMigrations.length === 0) {
  // A silently-empty migration set would make every D1 test fail with
  // "no such table" and look like a code bug. Fail here, where the cause is.
  throw new Error(
    [
      `no D1 migrations found under ${sqlRoot}; expected control/ and tenant/`,
      "to each contain at least one NNNN_*.sql file",
    ].join(" "),
  );
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2025-06-01",
        compatibilityFlags: ["nodejs_compat"],
        d1Databases: ["CONTROL_DB", "TENANT_DB_A", "TENANT_DB_B", "TENANT_DB_C"],
        bindings: {
          CONTROL_MIGRATIONS: controlMigrations,
          TENANT_MIGRATIONS: tenantMigrations,
        },
      },
    }),
  ],
  test: { include: ["test/d1/**/*.test.ts"] },
});
