import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** `test/tenancy/` — where the specs live; this file sits one level below. */
const SUITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Vitest project for the per-tenant D1 suite, pointed at `harness/wrangler.toml`
 * so FOUR REAL, PHYSICALLY DISTINCT D1 databases exist in `workerd`: the
 * account-global `CONTROL_DB` plus `TENANT_DB_ACME` and `TENANT_DB_GLOBEX`.
 *
 * Three databases, not one, for the reason `packages/storage/vitest.d1.config.ts`
 * states: the router's whole job is to hand back DIFFERENT databases, and
 * cross-tenant isolation cannot be observed against a single one — the test
 * would pass against a router that ignored its argument.
 *
 * It is a SECOND config rather than a change to `apps/gateway/vitest.config.ts`
 * because that file, like `wrangler.toml` and `src/index.ts`, belongs to the
 * composition root, which this slice may not edit. The specs here are named
 * `*.spec.ts`, NOT `*.test.ts`, so the app's own config — `include:
 * ["test/**\/*.test.ts"]` — does not pick up tests it has no bindings for.
 *
 * ## THIS CONFIG IS CHAINED, AND IT HAS TO BE
 *
 * `apps/gateway/package.json`'s `test` script runs `vitest run`, then the
 * rate-limit harness, then this one. Without that third leg these specs are
 * dead files: they are `*.spec.ts` under a non-default config, so a bare
 * `vitest run` matches none of them and reports a green suite that never
 * executed the cross-tenant isolation proof. Do not drop the `&&`.
 *
 * Run alone:  bun x vitest run --config test/tenancy/harness/vitest.config.ts
 *             (from apps/gateway)
 *
 * The migrations are the DEPLOYED ones, read from the same directories
 * `wrangler.toml`'s `migrations_dir` points `wrangler d1 migrations apply` at —
 * never a fixture copy — so a column rename in `sql/d1-ts/**` breaks these
 * tests instead of them passing against a private schema.
 */
const SQL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../sql/d1-ts");

const controlMigrations = await readD1Migrations(join(SQL_ROOT, "control"));
const tenantMigrations = await readD1Migrations(join(SQL_ROOT, "tenant"));

if (controlMigrations.length === 0 || tenantMigrations.length === 0) {
  // A silently-empty migration set would make every spec fail with "no such
  // table" and look like a code bug. Fail here, where the cause is.
  throw new Error(
    "no D1 migrations found under sql/d1-ts/{control,tenant}; the tenancy harness " +
      "cannot prove isolation against schemas that were never applied",
  );
}

export default defineConfig({
  root: SUITE_ROOT,
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./harness/wrangler.toml" },
      miniflare: {
        bindings: {
          CONTROL_MIGRATIONS: controlMigrations,
          TENANT_MIGRATIONS: tenantMigrations,
        },
      },
    }),
  ],
  test: { include: ["**/*.spec.ts"] },
});
