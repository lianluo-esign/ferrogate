/**
 * Applies the tenant-database migration to `env.DB` before every test file.
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
 * With the table present and empty, the durable leg simply finds no row, the
 * fallback answers from `GATEWAY_NATIVE_API_KEYS` / `GATEWAY_STATIC_API_KEYS`,
 * and every existing expectation holds unchanged — while `test/keys/*.test.ts`
 * seeds real rows and exercises the durable leg for real.
 *
 * The migration is the deployed one (`sql/d1-ts/tenant/`, read by
 * `vitest.config.ts` with `readD1Migrations`), never a fixture copy, and
 * `applyD1Migrations` is idempotent and bookkept in `d1_migrations`.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";

interface D1TestBindings {
  readonly DB?: D1Database;
  readonly TEST_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

beforeAll(async () => {
  const bindings = env as unknown as D1TestBindings;
  const { DB, TEST_D1_SCHEMA } = bindings;
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
});
