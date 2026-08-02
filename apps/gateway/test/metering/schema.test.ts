/**
 * The anti-drift guard `src/metering/d1.ts` promises.
 *
 * `METERING_SCHEMA_SQL` is a MIRROR of the three metering statements in the
 * deployed control migration, kept only so an offline harness can provision the
 * tables without a migration runner. A mirror that is allowed to drift is worse
 * than no mirror at all: the suite would pass against a private schema the
 * account does not have, and the failure would first appear as a rejected
 * `batch()` in production — after the response was already served, i.e. in the
 * one place nobody is watching.
 *
 * So this file asserts BOTH directions:
 *
 *  1. every statement in the mirror appears verbatim (modulo whitespace) in
 *     `sql/d1-ts/control/0001_init_control.sql`, and
 *  2. every `billing_*` statement in that migration appears in the mirror,
 *
 * and then that the mirror is not merely text: it is executed against the REAL
 * D1 engine, and the tables it names are the ones the deployed migration
 * created in `env.BILLING_DB`.
 */
import { describe, expect, it } from "vitest";
import { METERING_SCHEMA_SQL } from "../../src/metering/index.js";
import {
  CONTROL_MIGRATION_SQL,
  METERING_TABLES,
  applyControlMigration,
  billingDb,
  sqlStatements,
} from "./d1-harness.js";

/** Collapse runs of whitespace so indentation is not a diff. */
function normalize(statement: string): string {
  return statement.replace(/\s+/g, " ").trim();
}

const MIRROR = sqlStatements(METERING_SCHEMA_SQL).map(normalize);
const MIGRATION = sqlStatements(CONTROL_MIGRATION_SQL).map(normalize);

/** The migration statements that touch a metering table. */
const MIGRATION_METERING = MIGRATION.filter((statement) =>
  METERING_TABLES.some((table) => statement.includes(table)),
);

describe("METERING_SCHEMA_SQL mirrors the deployed control migration", () => {
  it("reads a migration that actually declares the metering tables", () => {
    // Guards the guard: an empty/renamed migration file would otherwise make
    // both set comparisons below trivially true.
    expect(MIGRATION.length).toBeGreaterThan(20);
    expect(MIGRATION_METERING.length).toBeGreaterThanOrEqual(8);
    expect(MIRROR.length).toBeGreaterThanOrEqual(8);
  });

  it("contains no statement the migration does not have", () => {
    expect(MIRROR.filter((statement) => !MIGRATION.includes(statement))).toEqual([]);
  });

  it("omits no billing_* statement the migration has", () => {
    expect(MIGRATION_METERING.filter((statement) => !MIRROR.includes(statement))).toEqual([]);
  });
});

describe("the deployed migration provisions what the store writes", () => {
  it("creates all three metering tables in env.BILLING_DB", async () => {
    await applyControlMigration();
    const result = await billingDb()
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all<{ name: string }>();
    const tables = (result.results ?? []).map((row) => row.name);
    for (const table of METERING_TABLES) {
      expect(tables).toContain(table);
    }
  });

  it("re-applying the mirror over the deployed tables is a no-op", async () => {
    await applyControlMigration();
    const db = billingDb();
    // Every statement is `IF NOT EXISTS`; if one were not, this would throw
    // "table already exists" — which is exactly what an offline harness that
    // provisions from the mirror would hit on its second test file.
    for (const statement of sqlStatements(METERING_SCHEMA_SQL)) {
      await db.prepare(statement).run();
    }
  });
});
