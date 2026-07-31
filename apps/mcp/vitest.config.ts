/**
 * Offline, docker-free Worker tests (`docs/rewrite/TESTING.md`).
 *
 * `main` is named EXPLICITLY, mirroring `apps/agent-runtime`. That is what puts
 * the Worker `SELF` drives in the SAME isolate as the test file, which two
 * things in this suite depend on:
 *
 *  - `test/fixtures.ts` seeds the in-memory port singleton and then asserts on
 *    what the Worker recorded there;
 *  - `setMcpEnvVar` overrides an operator `[vars]` value for one test, and the
 *    Worker observes it on its next request. Without an explicit `main` the
 *    pool serves `SELF` from a separate worker whose env is the `wrangler.toml`
 *    vars alone, so an override is visible to the test and NOT to the code
 *    under test — which silently degrades every guardrail assertion in
 *    `test/guardrails.test.ts` into "no detector configured ⇒ allow".
 *
 * ## `TEST_CONTROL_D1_SCHEMA` / `TEST_TENANT_D1_SCHEMA` / `TENANT_DB_A`
 *
 * `src/auth.ts` authenticates against the CONTROL database's `static_api_keys`
 * and `api_key_directory`, and then against the routed TENANT database's
 * `api_keys`. Those tables belong to the migrations slice, so the DDL is read
 * here in Node from `sql/d1-ts/{control,tenant}/` — the SAME directories
 * `wrangler d1 migrations apply` is pointed at — and handed to the tests as
 * bindings, exactly as `apps/control-plane/vitest.config.ts` does. Running the
 * DEPLOYED migration rather than a fixture copy is the point: a column rename
 * then breaks `test/d1-auth.test.ts` instead of the tests passing happily
 * against a private schema production does not have.
 *
 * `TENANT_DB_A` is declared HERE and not in `wrangler.toml`, and the asymmetry
 * is the topology rather than an oversight: a tenant's `[[d1_databases]]`
 * stanza is written by the PROVISIONING flow when that tenant is onboarded
 * (`EnvBindingTenantDatabaseRouter` maps `tenant_id -> binding_name` and looks
 * the binding up on `env` by that name), so the committed config cannot
 * enumerate tenants that do not exist yet. What the committed config DOES carry
 * is the control database, which is the only one this Worker needs in order to
 * RESOLVE a tenant.
 *
 * A second tenant is registered in `test/d1-auth.test.ts` naming a binding that
 * is deliberately NOT declared here, so the "provisioned but not yet
 * redeployed" 503 has something real to refuse.
 */
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const controlMigrations = await readD1Migrations("../../sql/d1-ts/control");
const tenantMigrations = await readD1Migrations("../../sql/d1-ts/tenant");

if (controlMigrations.length === 0 || tenantMigrations.length === 0) {
  // A silently-empty migration set makes every D1 auth test fail with
  // "no such table" and look like a code bug. Fail here, where the cause is.
  throw new Error("mcp tests: no D1 migrations found under sql/d1-ts/{control,tenant}");
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        d1Databases: ["TENANT_DB_A"],
        bindings: {
          TEST_CONTROL_D1_SCHEMA: controlMigrations,
          TEST_TENANT_D1_SCHEMA: tenantMigrations,
        },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
