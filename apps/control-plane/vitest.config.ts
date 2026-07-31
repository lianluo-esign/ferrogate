/**
 * `apps/control-plane` test pool.
 *
 * The one non-obvious piece is `TEST_D1_SCHEMA`. The D1-backed
 * `D1ControlPlaneStore` is only worth testing against a REAL D1 binding, and a
 * real binding is only useful once the control schema exists in it. The DDL is
 * read here, in Node, from `sql/d1-ts/control/` — THE migrations directory
 * `wrangler.toml` points `wrangler d1 migrations apply` at — and handed to the
 * tests as a binding so `test/d1.ts` can apply it with `applyD1Migrations`.
 *
 * Running the deployed migrations rather than a fixture copy of the DDL is the
 * point: a column rename in the migration then breaks these tests, instead of
 * the tests passing happily against a private schema production does not have.
 */
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const migrations = await readD1Migrations("../../sql/d1-ts/control");

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: { TEST_D1_SCHEMA: migrations },
      },
    }),
  ],
});
