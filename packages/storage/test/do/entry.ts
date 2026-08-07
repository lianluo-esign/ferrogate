/**
 * Test-only Worker entry for `vitest.do.config.ts`.
 *
 * workerd resolves a `[[durable_objects.bindings]]` `class_name` against the
 * ENTRY module's NAMED EXPORTS — a class that is merely reachable through an
 * import graph is NOT found, and the isolate refuses to start with "Durable
 * Object class TenantDataObject not found". This file is the fixture that
 * satisfies that constraint for `test/do/wrangler.toml`; in production the same
 * line lives in `apps/gateway/src/worker.ts`, and that one is gated by
 * `apps/gateway/test/wrangler-bindings.test.ts`. THIS FILE PROVES NOTHING ABOUT
 * THE DEPLOYED WORKER — the asymmetry is spelled out in `test/do/wrangler.toml`.
 *
 * `@ferrogate/storage` is a library and ships no Worker of its own, which is
 * exactly why this fixture has to exist: without an entry module there is no
 * place for workerd to look the class up, and the suite cannot boot at all.
 */
import { ControlDataObject } from "../../src/control-data-object.js";
import { CONTROL_MIGRATIONS, type ControlMigration } from "../../src/control-schema-sql.js";
import { TenantDataObject, sqlStatements } from "../../src/tenant-data-object.js";
import { TENANT_MIGRATIONS, type TenantMigration } from "../../src/tenant-schema-sql.js";

export { TenantDataObject, ControlDataObject };

/**
 * A migration set whose SECOND file fails halfway through.
 *
 * Three properties are deliberate:
 *
 *  * **Version 1 is the REAL `0001_init_tenant`.** The applier's
 *    `#assertLedgerHonest` cross-checks the ledger against the witness table
 *    `projects`, so a synthetic version 1 that did not create it would make the
 *    object refuse for the wrong reason and the "stopped at version 2" test
 *    would pass vacuously.
 *  * **`0002_faulty`'s first statement is VALID.** It creates `faulty_partial`,
 *    and the suite asserts that table is ABSENT afterwards. That is the
 *    assertion the per-file `transactionSync` exists to satisfy: an applier
 *    that ran statements one at a time outside a transaction would leave
 *    `faulty_partial` behind while reporting a failure — a half-applied schema
 *    that looks complete to every later `CREATE TABLE IF NOT EXISTS`.
 *  * **The failing statement is a duplicate `ADD COLUMN`.** Not a syntax error:
 *    `duplicate column name` is the REAL hazard this applier is built against,
 *    because SQLite has no `ADD COLUMN IF NOT EXISTS` and four of the seven
 *    tenant migrations are ALTER-only. It fails at execution rather than at
 *    parse, which is the harder case for rollback.
 *  * **Version 3 exists and must never run.** Continuing past a failure would
 *    leave the object at version 3 with version 2's tables missing — the
 *    silent-corruption outcome. The suite asserts `never_runs` is absent.
 */
const FAULTY_MIGRATIONS: readonly TenantMigration[] = [
  {
    version: 1,
    name: "0001_init_tenant",
    // The real bytes, so the witness table and the whole tenant schema are
    // genuinely present at version 1.
    sql: TENANT_MIGRATIONS[0]?.sql ?? "",
  },
  {
    version: 2,
    name: "0002_faulty",
    sql: [
      "-- Valid, and must be rolled back with the statement below it.",
      "CREATE TABLE IF NOT EXISTS faulty_partial (id TEXT PRIMARY KEY);",
      "",
      "-- `duplicate column name: id` — SQLite has no ADD COLUMN IF NOT EXISTS,",
      "-- which is precisely why the version gate has to be the ledger.",
      "ALTER TABLE faulty_partial ADD COLUMN id TEXT;",
      "",
    ].join("\n"),
  },
  {
    version: 3,
    name: "0003_never_runs",
    sql: "CREATE TABLE IF NOT EXISTS never_runs (id TEXT PRIMARY KEY);\n",
  },
];

/**
 * The fault-injection twin, bound as `FAULTY_TENANT_DATA`.
 *
 * A SEPARATE namespace rather than a flag on the real class: a migration set
 * that throws must be applied by the real constructor, on a real cold start,
 * against a real database. A `TenantDataObject` whose schema apply could be
 * disabled by a parameter would be exercising a code path production never runs.
 *
 * It overrides `migrations()` — a METHOD, not a field — because a subclass field
 * initializer runs after `super()`, i.e. after the constructor has already
 * migrated, so a field override would arrive too late to be seen.
 */
export class FaultyTenantDataObject extends TenantDataObject {
  protected override migrations(): readonly TenantMigration[] {
    return FAULTY_MIGRATIONS;
  }
}

/**
 * The control applier's fault-injection twin, with the same three properties
 * as the tenant fixture: file 1 is the REAL `0001_init_control` (so the
 * witness table `api_key_directory` genuinely exists at that point), file 2
 * fails at EXECUTION on a duplicate `ADD COLUMN` after a valid CREATE that
 * must roll back with it, and file 3 exists and must never run.
 */
const FAULTY_CONTROL_MIGRATIONS: readonly ControlMigration[] = [
  {
    ordinal: 1,
    name: "0001_init_control",
    sql: CONTROL_MIGRATIONS[0]?.sql ?? "",
  },
  {
    ordinal: 2,
    name: "0002_faulty_control",
    sql: [
      "-- Valid, and must be rolled back with the statement below it.",
      "CREATE TABLE IF NOT EXISTS faulty_control_partial (id TEXT PRIMARY KEY);",
      "",
      "-- `duplicate column name: id` — fails at execution, not at parse.",
      "ALTER TABLE faulty_control_partial ADD COLUMN id TEXT;",
      "",
    ].join("\n"),
  },
  {
    ordinal: 3,
    name: "0003_never_runs_control",
    sql: "CREATE TABLE IF NOT EXISTS never_runs_control (id TEXT PRIMARY KEY);\n",
  },
];

/** Bound as `FAULTY_CONTROL_DATA`; overrides the METHOD, same as the tenant twin. */
export class FaultyControlDataObject extends ControlDataObject {
  protected override migrations(): readonly ControlMigration[] {
    return FAULTY_CONTROL_MIGRATIONS;
  }
}

// A guard on the fixture itself. `0002_faulty` is only a mid-file failure if the
// splitter actually yields two statements from it; a future change to
// `sqlStatements` that collapsed them would turn every assertion in the
// "schema that fails mid-file" describe into a test of nothing, silently.
const faultyStatements = sqlStatements(FAULTY_MIGRATIONS[1]?.sql ?? "");
if (faultyStatements.length !== 2 || !faultyStatements[0]?.startsWith("CREATE TABLE")) {
  throw new Error(
    `test fixture broken: 0002_faulty must split into a valid CREATE then a failing ALTER, got ${JSON.stringify(faultyStatements)}`,
  );
}

export default {
  fetch(): Response {
    // The suite drives both namespaces through their bindings, never over HTTP;
    // workerd still requires the entry module to export a handler.
    return new Response("storage durable-object test worker", { status: 200 });
  },
} satisfies ExportedHandler;
