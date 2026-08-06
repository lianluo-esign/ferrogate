/**
 * Applies the deployed migrations to `env.DB` and `env.CONTROL_DB` before
 * every test file.
 *
 * ## Why the whole suite needs this, not just `test/keys/`
 *
 * `wrangler.toml` declares `[[d1_databases]] binding = "DB"`, so `depsFromEnv`
 * (src/adapters.ts) builds the D1 key resolver and makes it the PRIMARY
 * credential source for EVERY request in this suite — that is the wave-5
 * wiring, and it is deliberately not test-only.
 *
 * `D1ApiKeyStore` raises `ApiKeyStoreUnavailable` when the query fails, which
 * `D1ApiKeyResolver` renders as the `unavailable` resolution — 503
 * `external_auth_unavailable`, never a 401 — and, correctly, it does NOT fall
 * through to the config-key fallback: an outage must not be indistinguishable
 * from a revocation. A missing table is such a failure. So without this file the
 * pre-existing auth/inference/asset suites would all go red with 503s, and
 * "fix" would look like removing the binding, which would silently un-wire the
 * durable key path in production.
 *
 * With the tables present and empty, the durable legs simply find no rows, the
 * fallbacks answer from `GATEWAY_NATIVE_API_KEYS` / `TENANT_RBAC_ACTIONS` /
 * `GATEWAY_GUARDRAIL_POLICIES`, and every existing expectation holds unchanged
 * — while `test/keys/*.test.ts` and the RBAC/guardrail-store suites seed real
 * rows and exercise the durable legs for real.
 *
 * ## Both databases get the FULL deployed migration directory, wrangler-style
 *
 * This file used to apply a hand-curated subset of `sql/d1-ts/control/` ("add
 * one here the moment a gateway module queries it"), and the list rotted
 * exactly the way that rule predicts: `0012_tenant_storage_provisioning.sql`
 * adds the `storage_backend` column the tenancy resolver reads on EVERY
 * authenticated request since #819 made `durable_object` routing the default,
 * nobody added it, and the entire suite answered
 * `503 quota_resolution_unavailable` (~199 failures, one cause, discovered
 * during Zero-D1 S1 #877 baselining).
 *
 * So there is no list anymore. `vitest.config.ts` reads BOTH deployed
 * directories with `readD1Migrations` (`TEST_D1_SCHEMA` = tenant,
 * `TEST_CONTROL_D1_SCHEMA` = control) and this file hands each to
 * `applyD1Migrations` — the same per-file, name-bookkept application
 * `wrangler d1 migrations apply` performs in production, idempotent via the
 * `d1_migrations` table, ALTER-only files included. The mcp and storage
 * harnesses already apply the control directory exactly this way.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";

interface D1TestBindings {
  readonly DB?: D1Database;
  readonly CONTROL_DB?: D1Database;
  readonly TEST_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_CONTROL_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

beforeAll(async () => {
  const bindings = env as unknown as D1TestBindings;
  const { DB, CONTROL_DB, TEST_D1_SCHEMA, TEST_CONTROL_D1_SCHEMA } = bindings;
  if (DB === undefined || TEST_D1_SCHEMA === undefined) {
    // Loud, never a silent skip: both are supplied by `vitest.config.ts` +
    // `wrangler.toml`, so an absent one means the wiring was removed and the
    // suite is about to prove something other than what it claims.
    throw new Error(
      "gateway test setup: expected both the `DB` binding (apps/gateway/wrangler.toml) " +
        "and `TEST_D1_SCHEMA` (apps/gateway/vitest.config.ts). " +
        "See src/keys/index.ts for why the gateway suite runs against a real D1.",
    );
  }
  await applyD1Migrations(DB, TEST_D1_SCHEMA);

  if (CONTROL_DB !== undefined) {
    if (TEST_CONTROL_D1_SCHEMA === undefined) {
      // Same loudness rule as above: a bound CONTROL_DB with no schema to
      // apply would make every rbac/quota/guardrail read answer 503 and the
      // failure would point everywhere except here.
      throw new Error(
        "gateway test setup: `CONTROL_DB` is bound but `TEST_CONTROL_D1_SCHEMA` is absent — " +
          "vitest.config.ts must read sql/d1-ts/control with readD1Migrations.",
      );
    }
    await applyD1Migrations(CONTROL_DB, TEST_CONTROL_D1_SCHEMA);

    /**
     * Roster rows for the fixture tenants of `vitest.config.ts`.
     *
     * Since #820/#824 the durable_object default routes through
     * `BackendDispatchingTenantDatabaseRouter` whenever `DB` is bound (it is,
     * for the key store above), and that router reads the roster: a tenant
     * with NO `tenant_databases` row falls to the native-binding arm, whose
     * `not_found` the wallet/quota admission renders as
     * `503 quota_resolution_unavailable` on every authenticated request. In
     * production the onboarding path writes this row the moment a tenant is
     * created; the fixture tenants are stated in a `[vars]` JSON blob and are
     * never onboarded, so their roster rows are seeded here — same backend,
     * same `ready` status, `migration_state` left at its post-cutover default
     * so the dispatch takes the durable-object arm.
     */
    const FIXTURE_TENANTS = [
      "tenant_a",
      "tenant_b",
      "tenant_b_tools",
      "tenant_readonly",
      "tenant_suspended",
      "tenant_tools",
      "tenant_unscoped",
    ];
    const seedRoster = CONTROL_DB.prepare(
      "INSERT OR IGNORE INTO tenant_databases (tenant_id, storage_backend, provisioning_status) " +
        "VALUES (?, 'durable_object', 'ready')",
    );
    await CONTROL_DB.batch(FIXTURE_TENANTS.map((tenantId) => seedRoster.bind(tenantId)));
  }
});
