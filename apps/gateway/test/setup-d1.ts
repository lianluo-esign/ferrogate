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
import controlMigrationSql from "../../../sql/d1-ts/control/0001_init_control.sql?raw";
// Issue #695. Every control migration the gateway READS from has to be applied
// here, not just the init one: `src/cache/governance.ts` queries
// `semantic_cache_policies` on the request path of every cacheable call, and a
// bound CONTROL_DB whose table is missing makes the cache fail CLOSED (bypass)
// — which would look like "the cache is off" rather than "the suite forgot a
// migration". `0002` / `0003_audit_chain` / `0003_request_log_columns` are not
// listed because they are `ALTER TABLE`s and tables no `apps/gateway` code path
// reads; add one here the moment a gateway module queries it.
import semanticCacheMigrationSql from "../../../sql/d1-ts/control/0004_semantic_cache_policies.sql?raw";
// Issue #678, and the same rule the note above states: `src/attribution/source.ts`
// reads `quota_policies.required_tags_json` / `on_missing_tags` on the request
// path of every spend-producing operation. This one is an `ALTER TABLE`, so it
// is applied through {@link applyIgnoringDuplicateColumn} rather than being
// listed with the `CREATE … IF NOT EXISTS` migrations above.
import attributionPolicyMigrationSql from "../../../sql/d1-ts/control/0006_attribution_tag_policy.sql?raw";

interface D1TestBindings {
  readonly DB?: D1Database;
  readonly CONTROL_DB?: D1Database;
  readonly TEST_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

/**
 * Split a `.sql` migration into executable statements.
 *
 * Line comments go first: the migration is mostly prose and a `;` inside a
 * comment would cut a statement in half — which fails as a `SQLITE_ERROR` on
 * some unrelated word, the least legible failure available. Same helper shape
 * as `test/metering/d1-harness.ts`, which applies this file to `BILLING_DB`.
 */
function sqlStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

beforeAll(async () => {
  const bindings = env as unknown as D1TestBindings;
  const { DB, CONTROL_DB, TEST_D1_SCHEMA } = bindings;
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

  /**
   * The CONTROL database, for exactly the same reason.
   *
   * `depsFromEnv` builds `D1RbacAuthorizer` whenever `CONTROL_DB` is bound, and
   * `guardrailDepsFromEnv` builds `D1GuardrailPolicyStore` the same way. A
   * bound database whose tables do not exist makes every `rbac_action`
   * operation answer 503 `rbac_unavailable` — deliberately, because an outage
   * must not look like a denial — so without this the whole suite would go red
   * with 503s and the "fix" would look like dropping the binding, silently
   * un-wiring the durable RBAC path in production.
   *
   * With the tables present and EMPTY the durable leg simply grants nothing and
   * the `TENANT_RBAC_ACTIONS` / `GATEWAY_GUARDRAIL_POLICIES` fallbacks answer,
   * so every pre-existing expectation holds unchanged — while the RBAC and
   * guardrail-store suites seed real rows and exercise the durable leg for real.
   *
   * The migration is the DEPLOYED one, read with `?raw` from the directory
   * `wrangler.toml`'s `migrations_dir` points at, never a fixture copy, and it
   * is `CREATE … IF NOT EXISTS` throughout so re-application is a no-op.
   */
  if (CONTROL_DB !== undefined) {
    for (const migration of [controlMigrationSql, semanticCacheMigrationSql]) {
      for (const statement of sqlStatements(migration)) {
        await CONTROL_DB.prepare(statement).run();
      }
    }
    await applyIgnoringDuplicateColumn(CONTROL_DB, attributionPolicyMigrationSql);
  }
});

/**
 * Apply an `ALTER TABLE … ADD COLUMN` migration idempotently.
 *
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, and this setup runs once per test
 * FILE against storage that a given run may or may not have already migrated —
 * so a second application must be a no-op rather than a `duplicate column name`
 * throw that fails an entire file before its first test. Any OTHER error is
 * re-thrown: a migration that is broken for a real reason must still be loud.
 */
async function applyIgnoringDuplicateColumn(db: D1Database, migration: string): Promise<void> {
  for (const statement of sqlStatements(migration)) {
    try {
      await db.prepare(statement).run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!/duplicate column name/i.test(message)) throw error;
    }
  }
}
