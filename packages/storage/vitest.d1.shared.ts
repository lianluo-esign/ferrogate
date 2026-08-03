import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * The shared body of the two D1-suite configs.
 *
 * `test/d1/**` runs TWICE — once against real per-tenant D1 bindings
 * (`vitest.d1.config.ts`) and once against per-tenant SQLite-backed Durable
 * Objects through the `D1Database` facade (`vitest.d1do.config.ts`, #823). The
 * files themselves are backend-agnostic: they ask `test/d1/harness.ts` for a
 * router and for a tenant's database, and the harness reads the
 * `TENANT_BACKEND` binding this function sets.
 *
 * That is the acceptance test for the facade, and it is deliberately the SAME
 * files rather than a parallel suite written against the facade. A suite
 * written by someone who was thinking about the facade would agree with the
 * facade; these were written against real D1, by someone who was not, and they
 * assert the things that actually cost money — that `batch()` is one
 * transaction, that an empty `RETURNING` set is the guard's refusal, that
 * SQLite serializes writers, that five concurrent reserves against a balance
 * affording four admit exactly four.
 *
 * Two configs rather than one parameterized run because the pool builds ONE
 * miniflare environment per config: `TENANT_BACKEND` has to be fixed before
 * workerd boots, and a suite that switched backends inside a file would share
 * one set of D1 databases between two topologies.
 */
export type TenantBackendName = "native_binding" | "durable_object";

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

export function d1SuiteConfig(backend: TenantBackendName) {
  return defineConfig({
    plugins: [
      cloudflareTest({
        // The wrangler fixture exists only to give workerd an ENTRY MODULE to
        // resolve `TenantDataObject` against; a DO namespace cannot be created
        // from a bare `miniflare` block. Everything else stays below, because
        // the migration bindings are JS arrays that no toml can carry.
        wrangler: { configPath: "./test/d1/wrangler.toml" },
        miniflare: {
          d1Databases: ["CONTROL_DB", "TENANT_DB_A", "TENANT_DB_B", "TENANT_DB_C"],
          // Real R2, for the same reason as real D1: the asset commit
          // protocol's whole content is that R2 and D1 are two services with no
          // shared transaction, and a fake bucket would be "atomic" with the
          // row because the fake was written to agree.
          r2Buckets: ["ASSETS_BUCKET"],
          bindings: {
            CONTROL_MIGRATIONS: controlMigrations,
            TENANT_MIGRATIONS: tenantMigrations,
            TENANT_BACKEND: backend,
          },
        },
      }),
    ],
    test: { include: ["test/d1/**/*.test.ts"] },
  });
}
