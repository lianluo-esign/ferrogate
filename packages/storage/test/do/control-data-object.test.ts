/**
 * `ControlDataObject` against a REAL SQLite-backed Durable Object in workerd
 * (Zero-D1 S1, #877).
 *
 * The claims that cost a workerd boot, mirroring the tenant suite's reasons:
 * that the 27-file control apply really runs on first wake and really does
 * NOT re-run on the second (the ALTER-only control files cannot be applied
 * twice), that the NAME-keyed ledger really carries all three `0003_*` files
 * past the non-unique-prefix hazard, that `transactionSync` really rolls a
 * failing batch back, and that the `DurableObjectD1Database` facade really
 * speaks to this object unchanged.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, test } from "vitest";
import {
  CONTROL_DATA_ADDRESS as ADDRESS_FROM_OBJECT,
  type ControlDataNamespace,
} from "../../src/control-data-object.js";
import {
  CONTROL_DATA_ADDRESS,
  type ControlDataNamespaceLike,
  controlDataObjectDatabase,
} from "../../src/control-do.js";
import { CONTROL_MIGRATIONS } from "../../src/control-schema-sql.js";

declare global {
  namespace Cloudflare {
    interface Env {
      CONTROL_DATA: ControlDataNamespace;
      FAULTY_CONTROL_DATA: ControlDataNamespace;
    }
  }
}

function controlStub() {
  return env.CONTROL_DATA.get(env.CONTROL_DATA.idFromName(CONTROL_DATA_ADDRESS));
}

const QUERY = (sql: string, params: readonly (string | number | null)[] = []) => ({
  tenantId: CONTROL_DATA_ADDRESS,
  sql,
  params,
});

/**
 * Await a refusal and return its message. The same helper as the tenant
 * suite, for the same reason: `.rejects` matchers over pool-workers RPC leave
 * the original in-object rejection unhandled, which vitest reports as noise
 * even while every test passes.
 */
async function refusal(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected the RPC to be refused, but it resolved");
}

describe("addressing", () => {
  test("the two modules agree on the well-known address", () => {
    // `control-do.ts` re-declares the constant to stay node-importable; this
    // is the pin its docblock promises.
    expect(CONTROL_DATA_ADDRESS).toBe(ADDRESS_FROM_OBJECT);
  });

  test("refuses any address that is not the constant", async () => {
    const stub = controlStub();
    expect(await refusal(stub.query({ tenantId: "tenant-1", sql: "SELECT 1 AS one" }))).toMatch(
      new RegExp(`control_data_object: .*answers only address "${CONTROL_DATA_ADDRESS}"`),
    );
    expect(await refusal(stub.query({ tenantId: "", sql: "SELECT 1 AS one" }))).toMatch(
      /control_data_object/,
    );
  });
});

describe("the first wake", () => {
  test("applies every control migration, keyed by NAME", async () => {
    const stub = controlStub();
    const status = await stub.schemaStatus({ tenantId: CONTROL_DATA_ADDRESS });
    expect(status.address).toBe(CONTROL_DATA_ADDRESS);
    expect(status.knownCount).toBe(CONTROL_MIGRATIONS.length);
    expect(status.appliedCount).toBe(CONTROL_MIGRATIONS.length);

    // The non-unique-prefix hazard, held directly: all three 0003_* files are
    // ledgered. A MAX(version) applier records exactly one of them.
    const ledger = await stub.query(
      QUERY("SELECT name FROM control_schema_applied ORDER BY ordinal"),
    );
    const names = ledger.results.map((row) => row.name);
    expect(names).toEqual(CONTROL_MIGRATIONS.map((migration) => migration.name));
    expect(names.filter((name) => String(name).startsWith("0003_")).length).toBeGreaterThanOrEqual(
      2,
    );

    // The witness table is real, not just ledgered.
    const witness = await stub.query(
      QUERY("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'api_key_directory'"),
    );
    expect(witness.results.length).toBe(1);
  });
});

describe("atomicity", () => {
  test("a failing batch rolls back every statement before it", async () => {
    const stub = controlStub();
    await refusal(
      stub.batch({
        tenantId: CONTROL_DATA_ADDRESS,
        statements: [
          {
            sql: "INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)",
            params: ["t-rollback", "Rollback Probe", "rollback-probe"],
          },
          { sql: "INSERT INTO no_such_table (x) VALUES (1)" },
        ],
      }),
    );

    const after = await controlStub().query(
      QUERY("SELECT id FROM tenants WHERE id = ?", ["t-rollback"]),
    );
    expect(after.results).toEqual([]);
  });
});

describe("the D1 facade", () => {
  test("prepare/bind/first and an atomic batch work unchanged over this object", async () => {
    const db = controlDataObjectDatabase(env.CONTROL_DATA as unknown as ControlDataNamespaceLike);

    await db
      .prepare("INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)")
      .bind("t-facade", "Facade Probe", "facade-probe")
      .run();
    const row = await db
      .prepare("SELECT id, name FROM tenants WHERE id = ?")
      .bind("t-facade")
      .first<{ id: string; name: string }>();
    expect(row).toEqual({ id: "t-facade", name: "Facade Probe" });

    // batch() is one transaction inside the object: the second statement's
    // failure must take the first with it.
    await refusal(
      db.batch([
        db
          .prepare("INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)")
          .bind("t-facade-2", "Facade Two", "facade-two"),
        db.prepare("INSERT INTO no_such_table (x) VALUES (1)"),
      ]),
    );
    const gone = await db.prepare("SELECT id FROM tenants WHERE id = ?").bind("t-facade-2").first();
    expect(gone).toBeNull();

    await db.prepare("DELETE FROM tenants WHERE id = ?").bind("t-facade").run();
  });
});

describe("a schema that fails mid-file", () => {
  function faultyStub() {
    return env.FAULTY_CONTROL_DATA.get(env.FAULTY_CONTROL_DATA.idFromName(CONTROL_DATA_ADDRESS));
  }

  test("names the file it stopped at, on the probe and on every refusal", async () => {
    const status = await faultyStub().schemaStatus({ tenantId: CONTROL_DATA_ADDRESS });
    expect(status.failure).toContain("stopped at 0002_faulty_control");
    expect(status.appliedCount).toBe(1);
    expect(status.knownCount).toBe(3);

    expect(
      await refusal(faultyStub().query({ tenantId: CONTROL_DATA_ADDRESS, sql: "SELECT 1 AS one" })),
    ).toMatch(/control schema migration stopped at 0002_faulty_control/);
  });

  test("rolls the failed file back ENTIRELY, and never reaches the file after it", async () => {
    // The failing file's valid first statement must NOT survive, and the file
    // after the failure must never have run.
    await runInDurableObject(faultyStub(), (_instance, state) => {
      const tables = state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?)",
          "faulty_control_partial",
          "never_runs_control",
        )
        .toArray();
      expect(tables).toEqual([]);
    });
  });
});

/**
 * LAST IN THE FILE, deliberately. `state.abort()` breaks the instance's
 * output gate, and once an abort has happened in this workerd session, every
 * LATER worker-side rejection — including ones `refusal()` fully awaited —
 * is re-surfaced to vitest as an unhandled error. Declaration order is
 * execution order, so the eviction runs after every refusal-producing test.
 * (The tenant suite dodges this by aborting per-tenant ids its refusal tests
 * never reuse; the control object is a singleton, so ordering is the tool.)
 */
describe("the second wake", () => {
  test("does NOT re-apply the migrations", async () => {
    // Evict: `abort()` rejects the call that issued it and poisons the stub;
    // re-addressing re-runs the constructor against the migrated database.
    await runInDurableObject(controlStub(), (_instance, state) => {
      state.abort("test: forcing a cold start");
    }).catch(() => {});

    const stub = controlStub();
    const status = await stub.schemaStatus({ tenantId: CONTROL_DATA_ADDRESS });
    // A re-apply of the ALTER-only files would have thrown in the constructor
    // and every RPC here would refuse; the empty per-wake list is the
    // positive evidence the gate held.
    expect(status.appliedThisWake).toEqual([]);
    expect(status.appliedCount).toBe(CONTROL_MIGRATIONS.length);
  });
});
