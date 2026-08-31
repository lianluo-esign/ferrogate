/**
 * `PlatformDataObject` against a REAL SQLite-backed Durable Object in workerd
 * (Zero-D1 Plan B).
 *
 * The platform object is the authoritative home for platform/unattributed
 * (`tenant IS NULL`) guardrail evidence that no tenant fan-out can reach. Its
 * class is a byte-for-byte copy of `ControlDataObject`'s applier, so this suite
 * is the LEAN twin of `control-data-object.test.ts`: it proves the copied
 * skeleton was wired to the RIGHT address (`"platform"`), the RIGHT witness
 * table (`guardrail_evaluations`), and the RIGHT ledger (`platform_schema_applied`),
 * that the schema really applies on first wake and really does NOT re-run on the
 * second, and that the `DurableObjectD1Database` facade speaks to this object
 * unchanged. The mid-file-failure / rollback path is NOT re-proved here — it is
 * the identical applier already exercised by `FaultyControlDataObject`, so there
 * is no faulty platform twin (see `test/do/entry.ts`).
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, test } from "vitest";
import {
  PLATFORM_DATA_ADDRESS as ADDRESS_FROM_OBJECT,
  type PlatformDataNamespace,
} from "../../src/platform-data-object.js";
import {
  PLATFORM_DATA_ADDRESS,
  type PlatformDataNamespaceLike,
  platformDataObjectDatabase,
} from "../../src/platform-do.js";
import { PLATFORM_MIGRATIONS } from "../../src/platform-schema-sql.js";

declare global {
  namespace Cloudflare {
    interface Env {
      PLATFORM_DATA: PlatformDataNamespace;
    }
  }
}

function platformStub() {
  return env.PLATFORM_DATA.get(env.PLATFORM_DATA.idFromName(PLATFORM_DATA_ADDRESS));
}

const QUERY = (sql: string, params: readonly (string | number | null)[] = []) => ({
  tenantId: PLATFORM_DATA_ADDRESS,
  sql,
  params,
});

/**
 * The NOT NULL columns of `guardrail_evaluations` that have no default, in a
 * shape convenient for the facade/atomicity probes. `tenant` is deliberately
 * left NULL — every platform row is unattributed, and the schema drops the
 * tenant `NOT NULL` precisely so this insert is legal.
 */
function insertEvaluation(id: string) {
  return {
    sql:
      "INSERT INTO guardrail_evaluations (" +
      "id, request_id, scope_type, target, protocol, stage, mode, policy_id, " +
      "policy_revision, verdict, action, enforcement_status, input_fingerprint, occurred_at_unix" +
      ") VALUES (?, ?, 'platform', 'chat', 'http', 'request', 'enforce', 'pol-1', 1, 'allow', 'allow', 'applied', 'fp', 1)",
    params: [id, `req-${id}`],
  };
}

/**
 * Await a refusal and return its message — same helper and same rationale as
 * the control suite: `.rejects` over pool-workers RPC leaves the original
 * in-object rejection unhandled, which vitest reports as noise.
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
    // `platform-do.ts` re-declares the constant to stay node-importable; this
    // is the pin its docblock promises.
    expect(PLATFORM_DATA_ADDRESS).toBe(ADDRESS_FROM_OBJECT);
  });

  test("refuses any address that is not the constant", async () => {
    const stub = platformStub();
    expect(await refusal(stub.query({ tenantId: "tenant-1", sql: "SELECT 1 AS one" }))).toMatch(
      /platform_data_object: .*answers only address "platform"/,
    );
    expect(await refusal(stub.query({ tenantId: "", sql: "SELECT 1 AS one" }))).toMatch(
      /platform_data_object/,
    );
  });
});

describe("the first wake", () => {
  test("applies the platform migration, keyed by NAME", async () => {
    const stub = platformStub();
    const status = await stub.schemaStatus({ tenantId: PLATFORM_DATA_ADDRESS });
    expect(status.address).toBe(PLATFORM_DATA_ADDRESS);
    expect(status.knownCount).toBe(PLATFORM_MIGRATIONS.length);
    expect(status.appliedCount).toBe(PLATFORM_MIGRATIONS.length);

    const ledger = await stub.query(
      QUERY("SELECT name FROM platform_schema_applied ORDER BY ordinal"),
    );
    expect(ledger.results.map((row) => row.name)).toEqual(
      PLATFORM_MIGRATIONS.map((migration) => migration.name),
    );

    // The witness table is real, not just ledgered.
    const witness = await stub.query(
      QUERY(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'guardrail_evaluations'",
      ),
    );
    expect(witness.results.length).toBe(1);
  });
});

describe("atomicity", () => {
  test("a failing batch rolls back every statement before it", async () => {
    const stub = platformStub();
    await refusal(
      stub.batch({
        tenantId: PLATFORM_DATA_ADDRESS,
        statements: [insertEvaluation("ev-rollback"), { sql: "INSERT INTO no_such_table (x) VALUES (1)" }],
      }),
    );

    const after = await platformStub().query(
      QUERY("SELECT id FROM guardrail_evaluations WHERE id = ?", ["ev-rollback"]),
    );
    expect(after.results).toEqual([]);
  });
});

describe("the D1 facade", () => {
  test("prepare/bind/first and an atomic batch work unchanged over this object", async () => {
    const db = platformDataObjectDatabase(
      env.PLATFORM_DATA as unknown as PlatformDataNamespaceLike,
    );

    const insert = insertEvaluation("ev-facade");
    await db
      .prepare(insert.sql)
      .bind(...insert.params)
      .run();
    const row = await db
      .prepare("SELECT id, tenant, scope_type FROM guardrail_evaluations WHERE id = ?")
      .bind("ev-facade")
      .first<{ id: string; tenant: string | null; scope_type: string }>();
    // The unattributed row really stored a NULL tenant.
    expect(row).toEqual({ id: "ev-facade", tenant: null, scope_type: "platform" });

    // batch() is one transaction inside the object: the second statement's
    // failure must take the first with it.
    const insert2 = insertEvaluation("ev-facade-2");
    await refusal(
      db.batch([
        db.prepare(insert2.sql).bind(...insert2.params),
        db.prepare("INSERT INTO no_such_table (x) VALUES (1)"),
      ]),
    );
    const gone = await db
      .prepare("SELECT id FROM guardrail_evaluations WHERE id = ?")
      .bind("ev-facade-2")
      .first();
    expect(gone).toBeNull();

    await db.prepare("DELETE FROM guardrail_evaluations WHERE id = ?").bind("ev-facade").run();
  });
});

/**
 * LAST IN THE FILE, deliberately — same abort-poisoning ordering constraint as
 * the control suite: `state.abort()` breaks the instance's output gate, and
 * once an abort has happened in this workerd session, every LATER worker-side
 * rejection is re-surfaced to vitest as unhandled. The platform object is a
 * singleton, so declaration order is the tool.
 */
describe("the second wake", () => {
  test("does NOT re-apply the migration", async () => {
    await runInDurableObject(platformStub(), (_instance, state) => {
      state.abort("test: forcing a cold start");
    }).catch(() => {});

    const stub = platformStub();
    const status = await stub.schemaStatus({ tenantId: PLATFORM_DATA_ADDRESS });
    expect(status.appliedThisWake).toEqual([]);
    expect(status.appliedCount).toBe(PLATFORM_MIGRATIONS.length);
  });
});
