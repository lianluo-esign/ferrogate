import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** `test/durable/` — where the specs live; this file sits one level below. */
const SUITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Vitest project for the DURABLE-PORTS suite, pointed at `harness/wrangler.toml`
 * so the real `src/worker.ts` boots with TWO REAL D1 databases bound and the
 * `FG_DEV_*` bundle absent.
 *
 * It is a SECOND config rather than a change to `apps/agent-runtime/
 * vitest.config.ts` because the app's config seeds `FG_DEV_IN_MEMORY_PORTS`
 * plus the dev key/registry tables into every test — which is exactly the
 * posture these specs must NOT run in. Two postures, two configs.
 *
 * The specs here are named `*.spec.ts`, NOT `*.test.ts`, so the app's own
 * config (`include: ["test/**\/*.test.ts"]`) does not pick up tests it has no
 * D1 bindings for.
 *
 * ## THIS CONFIG IS CHAINED, AND IT HAS TO BE
 *
 * `apps/agent-runtime/package.json`'s `test` script runs `vitest run` AND THEN
 * this config. Without that second leg these specs are dead files: a bare
 * `vitest run` matches none of them and would report a green suite that never
 * executed the durable-mount proof — the precise failure mode
 * `docs/rewrite/parity-audit-dead-packages.md` catalogues. Do not drop the `&&`.
 *
 * Run alone:  bun x vitest run --config test/durable/harness/vitest.config.ts
 *             (from apps/agent-runtime)
 *
 * The migrations are the DEPLOYED ones, read from the same directories
 * `wrangler d1 migrations apply` is pointed at — never a fixture copy — so a
 * column rename in `sql/d1-ts/**` breaks these specs instead of them passing
 * against a private schema.
 */
const SQL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../sql/d1-ts");

const tenantMigrations = await readD1Migrations(join(SQL_ROOT, "tenant"));
const controlMigrations = await readD1Migrations(join(SQL_ROOT, "control"));

if (tenantMigrations.length === 0 || controlMigrations.length === 0) {
  // A silently-empty migration set would make every spec fail with "no such
  // table" and look like a code bug. Fail here, where the cause is.
  throw new Error(
    "no D1 migrations found under sql/d1-ts/{tenant,control}; the durable harness " +
      "cannot prove a mount against schemas that were never applied",
  );
}

export default defineConfig({
  root: SUITE_ROOT,
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./harness/wrangler.toml" },
      miniflare: {
        bindings: {
          TENANT_MIGRATIONS: tenantMigrations,
          CONTROL_MIGRATIONS: controlMigrations,
        },
      },
    }),
  ],
  test: { include: ["**/*.spec.ts"] },
});
