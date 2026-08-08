/**
 * Applies the deployed TENANT migrations to `env.DB` and seeds the CONTROL
 * object before every test file.
 *
 * ## Zero-D1 S5 (#881): CONTROL is a Durable Object now
 *
 * The `[[d1_databases]] CONTROL_DB` / `BILLING_DB` stanzas are gone. The
 * control database is the singleton `ControlDataObject` (`env.CONTROL_DATA`),
 * which applies its own 27-file control schema on first wake — so there is no
 * `applyD1Migrations` step for control any more, and no `TEST_CONTROL_D1_SCHEMA`
 * to hand it. The production code reads control through the
 * `controlDataObjectDatabase(env.CONTROL_DATA)` facade
 * (`src/control-data.ts::controlDatabaseFrom`).
 *
 * For the many suites that seed control fixtures with `env.CONTROL_DB` /
 * `env.BILLING_DB`, this file binds BOTH names to that same facade. A seed
 * written through the alias lands in the very object the code reads, so the
 * fixtures and the reads share one backend exactly as they did when both were
 * D1 aliases of `ferrogate-control` — the alias is a test-harness convenience,
 * not a second database, and there is no `[[d1_databases]]` stanza behind it.
 *
 * ## Why the whole suite needs the tenant `DB`, not just `test/keys/`
 *
 * `wrangler.toml` declares `[[d1_databases]] binding = "DB"` (the TENANT
 * database), so `depsFromEnv` (src/adapters.ts) builds the D1 key resolver and
 * makes it the PRIMARY credential source for EVERY request in this suite. With
 * the tables present and empty, the durable legs simply find no rows and the
 * config fallbacks answer; `test/keys/*.test.ts` and the RBAC/guardrail-store
 * suites seed real rows and exercise the durable legs for real.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { controlDataObjectDatabase } from "@ferrogate/storage";
import { beforeAll } from "vitest";

interface D1TestBindings {
  DB?: D1Database;
  CONTROL_DATA?: unknown;
  CONTROL_DB?: D1Database;
  BILLING_DB?: D1Database;
  readonly TEST_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

const bindings = env as unknown as D1TestBindings;

if (bindings.CONTROL_DATA === undefined) {
  // Loud, never a silent skip: the control object is declared as
  // `[[durable_objects.bindings]] CONTROL_DATA` and every rbac/quota/guardrail
  // read resolves it, so an absent one would make the whole suite answer 503
  // and point everywhere except here.
  throw new Error(
    "gateway test setup: `CONTROL_DATA` is not bound — apps/gateway/wrangler.toml must " +
      "declare the [[durable_objects.bindings]] CONTROL_DATA stanza (Zero-D1 S5, #881).",
  );
}

// The control facade over the singleton object, aliased onto the legacy binding
// names AT MODULE LOAD (before any test file's top-level `const CONTROL_DB =
// env.CONTROL_DB` capture) so fixtures that seed `env.CONTROL_DB` /
// `env.BILLING_DB` land in the very object the code reads through CONTROL_DATA.
//
// It is a Proxy that builds a FRESH facade per method access rather than a
// single cached one: `controlDataObjectDatabase` resolves its DO stub once at
// construction, and vitest-pool-workers `isolatedStorage` gives each test its
// own storage context — so a stub captured at module load would write to a
// different object than the one the code reads inside a test. Resolving the
// stub at call time keeps the seed and the read in the same context, exactly
// as the production code (which builds a facade per request) already does.
const controlAlias = new Proxy({} as D1Database, {
  get(_target, prop) {
    const db = controlDataObjectDatabase(bindings.CONTROL_DATA as never) as unknown as Record<
      string | symbol,
      unknown
    >;
    // The DO facade deliberately refuses `exec()` (it cannot report D1's
    // duration and nothing in src calls it). Test cleanup helpers DO use it,
    // so the alias implements it the way D1 documents: split on newlines and
    // run each statement through `prepare().run()`.
    if (prop === "exec") {
      return async (sql: string): Promise<{ count: number; duration: number }> => {
        const statements = sql
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line !== "");
        for (const statement of statements) {
          await (db.prepare as (s: string) => { run(): Promise<unknown> })(statement).run();
        }
        return { count: statements.length, duration: 0 };
      };
    }
    const value = db[prop];
    return typeof value === "function" ? value.bind(db) : value;
  },
});
bindings.CONTROL_DB = controlAlias;
bindings.BILLING_DB = controlAlias;

beforeAll(async () => {
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

  /**
   * Roster rows for the fixture tenants of `vitest.config.ts`.
   *
   * Since #820/#824 the durable_object default routes through
   * `BackendDispatchingTenantDatabaseRouter` whenever `DB` is bound (it is, for
   * the key store above), and that router reads the roster: a tenant with NO
   * `tenant_databases` row falls to the native-binding arm, whose `not_found`
   * the wallet/quota admission renders as `503 quota_resolution_unavailable` on
   * every authenticated request. The fixture tenants are stated in a `[vars]`
   * JSON blob and are never onboarded, so their roster rows are seeded here —
   * same backend, same `ready` status, so the dispatch takes the durable-object
   * arm. The first query below is what wakes the object and applies its schema.
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
  const control = controlDataObjectDatabase(bindings.CONTROL_DATA as never);
  const seedRoster = control.prepare(
    "INSERT OR IGNORE INTO tenant_databases (tenant_id, storage_backend, provisioning_status) " +
      "VALUES (?, 'durable_object', 'ready')",
  );
  await control.batch(FIXTURE_TENANTS.map((tenantId) => seedRoster.bind(tenantId)));
});
