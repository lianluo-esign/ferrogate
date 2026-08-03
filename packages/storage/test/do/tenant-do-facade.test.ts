/**
 * The `D1Database` facade over a tenant Durable Object (#823), against a REAL
 * SQLite-backed object in `workerd`.
 *
 * ## What this suite is for, and what `test/d1/**` is for
 *
 * The BAR for the facade is that every test in `test/d1/**` passes against a
 * `durable_object`-backed handle with no change to any module under `src/d1/`,
 * and that suite runs twice for exactly that reason (see
 * `test/d1/harness.ts` and `vitest.d1do.config.ts`). It is the real acceptance
 * test, because it is the one written by someone who was not thinking about
 * this facade.
 *
 * This file covers what that suite CANNOT reach:
 *
 *  * the meta fields nothing in the repo reads — `rows_written`, `last_row_id`,
 *    `size_after`, and the `duration` that this facade REFUSES to fabricate. A
 *    field that no consumer reads is a field no consumer test can pin, and
 *    "report them, do not zero-fill" is a requirement whether or not anything
 *    reads them today;
 *  * the type-domain refusals (`bigint`, `boolean`, `undefined`) which the
 *    money paths are careful never to trigger, and which therefore have no
 *    natural call site;
 *  * the round-TRIP count, which is invisible from inside a passing test —
 *    N sequential stub calls give the same answers as one batched call and
 *    lose only the transaction;
 *  * cross-tenant statement submission, which no honest caller performs.
 *
 * Every claim below is a property of the runtime. The object is real, the
 * SQLite is real, the rollback is real.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { creditsFromText } from "../../src/credits.js";
import { StorageError } from "../../src/errors.js";
import {
  DurableObjectD1Database,
  type TenantDataStub,
  requireAtomicBatch,
} from "../../src/index.js";
import type { TenantDataNamespace, TenantDataObject } from "../../src/tenant-data-object.js";

declare global {
  namespace Cloudflare {
    interface Env {
      TENANT_DATA: TenantDataNamespace;
      FAULTY_TENANT_DATA: TenantDataNamespace;
    }
  }
}

const ACME = "tenant_facade_acme";
const GLOBEX = "tenant_facade_globex";
const NOW = 1_700_000_000;

function stubFor(tenantId: string): TenantDataStub {
  return env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenantId)) as unknown as TenantDataStub;
}

/** The facade, addressed the way the router addresses it. */
function facadeFor(tenantId: string): D1Database {
  return new DurableObjectD1Database(tenantId, stubFor(tenantId)).asD1Database();
}

/**
 * Await a promise that must REJECT, and return its message.
 *
 * The same helper `tenant-data-object.test.ts` uses, for the same reason: a
 * rejected Durable Object RPC that vitest holds is also reported by workerd as
 * an uncaught exception, so `expect(...).rejects` buries the run in stack
 * traces that are not failures.
 */
async function refusal(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected a rejection, got a resolved promise");
}

/** Truncate the tables this file writes, so tests do not leak into each other. */
async function reset(tenantId: string): Promise<void> {
  const db = facadeFor(tenantId);
  await db.batch([
    db.prepare("DELETE FROM wallet_settlements"),
    db.prepare("DELETE FROM wallet_reservations"),
    db.prepare("DELETE FROM wallets"),
    db.prepare("DELETE FROM projects"),
  ]);
}

beforeEach(async () => {
  await reset(ACME);
  await reset(GLOBEX);
});

// ---------------------------------------------------------------------------

describe("the D1 statement surface", () => {
  test("first() answers null — NOT undefined — for a row that is not there", async () => {
    const db = facadeFor(ACME);
    const row = await db.prepare("SELECT id FROM wallets WHERE id = ?").bind("absent").first();

    // This is the single easiest way to put a money bug in the facade.
    // `wallet-d1.ts:282` reads `row === null ? undefined : creditsFromText(row.credits)`
    // — the EXACT balance read — and `wallet-d1.ts:753` is settleWalletBalance's
    // replay guard. `undefined` does not match `=== null`, so it falls THROUGH
    // the guard and dereferences `.credits` on a missing row. `toBeNull()` and
    // not `toBeFalsy()`: the whole assertion is which falsy value it is.
    expect(row).toBeNull();
    expect(row).not.toBeUndefined();
  });

  test("first() returns the row itself when there is one, and first(col) the cell", async () => {
    const db = facadeFor(ACME);
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, 500, NOW, NOW)
      .run();

    expect(await db.prepare("SELECT id, balance_credits FROM wallets").first()).toEqual({
      id: ACME,
      balance_credits: 500,
    });
    expect(await db.prepare("SELECT balance_credits FROM wallets").first("balance_credits")).toBe(
      500,
    );
  });

  test("bind() returns a NEW statement and mutates nothing", async () => {
    const db = facadeFor(ACME);
    // The shape five call sites use: ONE prepare(), bound N times, all N handed
    // to one batch(). `requestlog/d1.ts:162` and four siblings do exactly this.
    // A facade that stored params on the statement would collapse every record
    // in the batch to the LAST binding — silent request-log data loss, with a
    // green suite.
    const insert = db.prepare(
      "INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)",
    );
    const first = insert.bind("p1", ACME, "One", "one");
    const second = insert.bind("p2", ACME, "Two", "two");
    expect(first).not.toBe(second);
    expect(first).not.toBe(insert);

    await db.batch([first, second]);

    const rows = await db.prepare("SELECT id FROM projects ORDER BY id").all<{ id: string }>();
    expect(rows.results.map((r) => r.id)).toEqual(["p1", "p2"]);
  });

  test("a statement with no bind() at all runs, so params are optional", async () => {
    // `retention-d1.ts:271` (sweepOrphanBlobs) and six other sites call
    // `.all()`/`.run()` straight off `prepare()`. A facade that required an
    // array would break them at runtime only.
    const db = facadeFor(ACME);
    const result = await db.prepare("SELECT count(*) AS n FROM wallets").all<{ n: number }>();
    expect(result.results).toEqual([{ n: 0 }]);
  });

  test("results is always a real array, [] for a write with no RETURNING", async () => {
    const db = facadeFor(ACME);
    const written = await db
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("p_norows", ACME, "N", "n")
      .run();

    // Seventeen sites under `src/d1/` index `.results` with no guard, so
    // `undefined` here is a TypeError on a money path rather than a missing row.
    expect(Array.isArray(written.results)).toBe(true);
    expect(written.results).toEqual([]);
  });

  test("RETURNING rows come back identically through run(), all(), first() and batch()", async () => {
    const db = facadeFor(ACME);
    const sql =
      "INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?) RETURNING id, slug";

    // The three families of RETURNING read in `src/d1/`, which must agree:
    // `.first()` (the release CAS, all three workflow-budget CASes),
    // `.all().results` (ensureWallet, the reservation sweep) and
    // `batch()[i].results` (the reserve, the capture, the settle, assets,
    // agent-schedule).
    const viaRun = await db.prepare(sql).bind("r1", ACME, "R1", "r1").run();
    const viaAll = await db.prepare(sql).bind("r2", ACME, "R2", "r2").all();
    const viaFirst = await db.prepare(sql).bind("r3", ACME, "R3", "r3").first();
    const viaBatch = await db.batch([db.prepare(sql).bind("r4", ACME, "R4", "r4")]);

    expect(viaRun.results).toEqual([{ id: "r1", slug: "r1" }]);
    expect(viaAll.results).toEqual([{ id: "r2", slug: "r2" }]);
    expect(viaFirst).toEqual({ id: "r3", slug: "r3" });
    expect(viaBatch[0]?.results).toEqual([{ id: "r4", slug: "r4" }]);
  });

  test("raw() projects the same rows as arrays, with or without column names", async () => {
    const db = facadeFor(ACME);
    await db
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("p_raw", ACME, "Raw", "raw")
      .run();
    const statement = db.prepare("SELECT id, slug FROM projects");
    expect(await statement.raw()).toEqual([["p_raw", "raw"]]);
    expect(await statement.raw({ columnNames: true })).toEqual([
      ["id", "slug"],
      ["p_raw", "raw"],
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("D1Result.meta — every field, derived or refused", () => {
  test("changes is the row count, not the cursor's index-inclusive rowsWritten", async () => {
    const db = facadeFor(ACME);
    // `wallets` carries a UNIQUE on tenant_id plus the PK, so one inserted row
    // writes more than one index entry. That gap is the whole reason `changes`
    // is a `total_changes()` delta: five `changes()` helpers under `src/d1/`
    // read `changes > 0` as "the guarded write fired", and an overreported
    // value publishes an unscanned asset and skips a schedule fire forever.
    const inserted = await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, 100, NOW, NOW)
      .run();
    expect(inserted.meta.changes).toBe(1);
    expect(inserted.meta.rows_written).toBeGreaterThanOrEqual(inserted.meta.changes);

    // A read must report 0 changes. `changes()` alone would retain the previous
    // write's count across a SELECT and a read would inherit it.
    const read = await db.prepare("SELECT id FROM wallets").all();
    expect(read.meta.changes).toBe(0);
  });

  test("a guarded UPDATE matching nothing reports changes === 0", async () => {
    const db = facadeFor(ACME);
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, 100, NOW, NOW)
      .run();

    // The CAS shape `references-d1.ts`, `assets-d1.ts:392/418/492`,
    // `agent-schedule-d1.ts:342` and `retention-d1.ts:188` all branch on. The
    // guard does not hold, so nothing is written and the caller must be told 0.
    const missed = await db
      .prepare("UPDATE wallets SET balance_credits = ? WHERE id = ? AND balance_credits = ?")
      .bind(0, ACME, 999)
      .run();
    expect(missed.meta.changes).toBe(0);
    expect(missed.meta.changed_db).toBe(false);

    const hit = await db
      .prepare("UPDATE wallets SET balance_credits = ? WHERE id = ? AND balance_credits = ?")
      .bind(0, ACME, 100)
      .run();
    expect(hit.meta.changes).toBe(1);
    expect(hit.meta.changed_db).toBe(true);
  });

  test("meta is always present, and success is always true on a resolved result", async () => {
    const db = facadeFor(ACME);
    const result = await db.prepare("SELECT 1 AS one").all();
    // Six call sites read `result.meta.changes` with NO optional chain
    // (`control-plane/src/store/d1.ts:532,554,850,976`, `session/store.ts:285`,
    // `mcp/src/durable.ts:516`), so an omitted `meta` is a TypeError there.
    expect(result.meta).toBeDefined();
    expect(result.success).toBe(true);
  });

  test("rows_read, rows_written, last_row_id and size_after are measured, not zero-filled", async () => {
    const db = facadeFor(ACME);
    await db
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("m1", ACME, "M1", "m1")
      .run();
    const inserted = await db
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("m2", ACME, "M2", "m2")
      .run();

    // `rows_written` counts index writes as well as table rows, which is why it
    // is carried separately from `changes` rather than aliased onto it.
    expect(inserted.meta.rows_written).toBeGreaterThan(0);
    // `projects.id` is TEXT, so the implicit rowid is what this reports; the
    // only claim is that it is a real, advancing rowid rather than a synthetic
    // 0. Nothing in this repo reads it (grep: zero non-test hits) and it is
    // carried because `D1Meta.last_row_id` is non-optional and a fabricated 0
    // is something a future caller could believe.
    expect(inserted.meta.last_row_id).toBeGreaterThan(0);
    // 10 GB per object is a hard per-tenant wall with no shard behind it, so
    // this is the one meta field an operator has a real reason to read.
    expect(inserted.meta.size_after).toBeGreaterThan(0);

    const read = await db.prepare("SELECT id FROM projects").all();
    expect(read.meta.rows_read).toBeGreaterThanOrEqual(2);
    expect(read.meta.rows_written).toBe(0);
  });

  test("meta.duration THROWS rather than reporting a fabricated 0", async () => {
    const db = facadeFor(ACME);
    const result = await db.prepare("SELECT 1 AS one").all();

    // The object executes inside `transactionSync`, where the Durable Object
    // clock does not advance, so every honest measurement would be 0 ms — a
    // number that looks measured and is not. "Where a field genuinely cannot be
    // produced, THROW rather than lie" is the rule; this is the one field it
    // applies to.
    expect(() => result.meta.duration).toThrow(/refuses to fabricate it/);

    // …and the getter is NON-ENUMERABLE, so a spread, a JSON.stringify or a
    // log line does not detonate on a field nobody asked for. An enumerable
    // throwing getter would turn every incidental serialization into an outage.
    expect(() => JSON.stringify(result)).not.toThrow();
    expect(Object.keys(result.meta)).not.toContain("duration");
  });
});

// ---------------------------------------------------------------------------

describe("batch() — one transaction, one round trip", () => {
  test("a batch whose THIRD statement throws leaves none of the first two applied", async () => {
    const db = facadeFor(ACME);
    const message = await refusal(
      db.batch([
        db
          .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
          .bind("rb1", ACME, "One", "one"),
        db
          .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
          .bind("rb2", ACME, "Two", "two"),
        // Violates UNIQUE (tenant_id, slug) against statement 1, in the same
        // transaction. A constraint failure at EXECUTION time, not a parse
        // error — the harder case for rollback, and the one a real conflicting
        // write produces.
        db
          .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
          .bind("rb3", ACME, "Three", "one"),
      ]),
    );
    expect(message).toMatch(/UNIQUE|constraint/i);

    // THE assertion. `transactionSync` rolls back on throw, so statements 1 and
    // 2 are gone. This is the property `supportsAtomicBatch: true` is a claim
    // about, and the reason all 13 `requireAtomicBatch()` money paths may now
    // run: without it the wallet reserve's guard and its INSERT could commit
    // separately, which is an oversell.
    const rows = await db.prepare("SELECT id FROM projects").all();
    expect(rows.results).toEqual([]);
  });

  test("batch() returns exactly one result per statement, in order", async () => {
    const db = facadeFor(ACME);
    const results = await db.batch([
      db.prepare("SELECT 1 AS n"),
      db
        .prepare(
          "INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind("b1", ACME, "B", "b"),
      db.prepare("SELECT 3 AS n"),
    ]);
    // `wallet-d1.ts:377` and `billing-d1.ts:182` refuse a short array; seven
    // sites under `src/d1/` index it unguarded and would throw a TypeError.
    expect(results).toHaveLength(3);
    expect(results[0]?.results).toEqual([{ n: 1 }]);
    expect(results[1]?.results).toEqual([{ id: "b1" }]);
    expect(results[2]?.results).toEqual([{ n: 3 }]);
  });

  test("the WHOLE array crosses the stub boundary ONCE", async () => {
    // N sequential stub calls would answer every other test in this file
    // identically and lose only the transaction, so the hop count has to be
    // observed directly. This stub counts calls and forwards to the real
    // object, so what is measured is the facade's call pattern against real
    // semantics rather than against a mock's.
    const real = stubFor(ACME);
    let queryCalls = 0;
    let batchCalls = 0;
    const counting: TenantDataStub = {
      query: (request) => {
        queryCalls += 1;
        return real.query(request);
      },
      batch: (request) => {
        batchCalls += 1;
        return real.batch(request);
      },
    };
    const db = new DurableObjectD1Database(ACME, counting).asD1Database();

    await db.batch([
      db.prepare("SELECT 1 AS n"),
      db.prepare("SELECT 2 AS n"),
      db.prepare("SELECT 3 AS n"),
      db.prepare("SELECT 4 AS n"),
    ]);

    expect(batchCalls).toBe(1);
    expect(queryCalls).toBe(0);
  });

  test("an empty batch is passed through rather than short-circuited", async () => {
    // `batch([])` is a legal no-op on D1. Answering it locally would mean the
    // facade answered a question the object never saw — including the tenant
    // admission check, which is the guard that makes a mis-addressed object
    // refuse rather than serve.
    expect(await facadeFor(ACME).batch([])).toEqual([]);
  });

  test("a statement prepared against ANOTHER tenant's object is refused, not run", async () => {
    const acme = facadeFor(ACME);
    const globex = facadeFor(GLOBEX);
    const message = await refusal(
      acme.batch([
        acme.prepare("SELECT 1 AS n"),
        globex
          .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
          .bind("x", GLOBEX, "X", "x"),
      ]),
    );
    expect(message).toContain("prepared against tenant");
    expect(message).toContain(GLOBEX);
    // Refused BEFORE anything crossed the wire: statement 1 must not have run
    // either, which is what makes the refusal equivalent to a rollback.
    expect((await acme.prepare("SELECT id FROM projects").all()).results).toEqual([]);
  });

  test("a foreign D1PreparedStatement cannot be smuggled into a batch", async () => {
    const db = facadeFor(ACME);
    const foreign = { bind: () => foreign } as unknown as D1PreparedStatement;
    const message = await refusal(db.batch([foreign]));
    expect(message).toContain("not prepared against this tenant's Durable Object");
  });
});

// ---------------------------------------------------------------------------

describe("the real money path, unmodified, over the facade", () => {
  /**
   * `D1WalletStore` is used here EXACTLY as `test/d1/wallet-d1.test.ts` uses it
   * — same class, same handle shape, no facade-aware branch anywhere in
   * `src/d1/wallet-d1.ts`. That is the acceptance criterion for this slice
   * stated as a test: if the module needed editing, the facade would be wrong.
   */
  test("requireAtomicBatch ADMITS a durable_object handle and still refuses rest", () => {
    const handle = {
      tenantId: ACME,
      db: facadeFor(ACME),
      source: "durable_object" as const,
      supportsAtomicBatch: true,
    };
    // Under `rest` all 13 of these refused, which is what made the REST
    // strategy a read-only topology. They must now RUN.
    expect(requireAtomicBatch(handle, "reserve_wallet_credits")).toBe(handle);

    const restHandle = { ...handle, source: "rest" as const, supportsAtomicBatch: false };
    expect(() => requireAtomicBatch(restHandle, "reserve_wallet_credits")).toThrow(
      /refusing to run the guard non-atomically/,
    );
  });

  test("the no-oversell reserve admits exactly as many holds as the balance affords", async () => {
    const { D1WalletStore } = await import("../../src/index.js");
    const db = facadeFor(ACME);
    const handle = {
      tenantId: ACME,
      db,
      source: "durable_object" as const,
      supportsAtomicBatch: true,
    };
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, 400, NOW, NOW)
      .run();

    const store = new D1WalletStore(handle);
    const outcomes = await Promise.all(
      [1, 2, 3, 4, 5].map((n) =>
        store.reserveWalletCredits(`hold_${n}`, ACME, 100, NOW + 3_600, NOW),
      ),
    );
    expect(outcomes.filter((o) => o.kind === "reserved")).toHaveLength(4);
    expect(outcomes.filter((o) => o.kind === "insufficient")).toHaveLength(1);

    const held = await db
      .prepare(
        "SELECT COALESCE(SUM(amount_credits), 0) AS held FROM wallet_reservations WHERE tenant_id = ? AND status = 'active'",
      )
      .bind(ACME)
      .first<{ held: number }>();
    expect(held?.held).toBe(400);
  });
});

// ---------------------------------------------------------------------------

describe("type fidelity across the RPC boundary", () => {
  test("a credit value above 2^53 survives as a decimal string with INTEGER affinity", async () => {
    const db = facadeFor(ACME);
    // 1 credit = 1 micro-USD, so a $10 B balance is 10^16 — past 2^53.
    // `bindCredits()` marshals it as a decimal STRING and SQLite's INTEGER
    // affinity stores it exactly; `creditsFromText()` decodes the
    // `CAST(... AS TEXT)` read. If the facade JSON-round-tripped or coerced
    // params, the column would silently start holding TEXT and every later
    // arithmetic comparison would compare strings.
    const huge = 10_000_000_000_000_001n;
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, huge.toString(), NOW, NOW)
      .run();

    const exact = await db
      .prepare("SELECT CAST(balance_credits AS TEXT) AS credits FROM wallets WHERE id = ?")
      .bind(ACME)
      .first<{ credits: string }>();
    expect(exact).not.toBeNull();
    expect(creditsFromText(exact?.credits)).toBe(huge);

    // Affinity, proved rather than assumed: `typeof` inside SQLite reports the
    // STORAGE class. A string that landed as TEXT would answer "text" here and
    // every `balance_credits >= ?` guard in the reserve would become a string
    // comparison.
    const affinity = await db
      .prepare("SELECT typeof(balance_credits) AS t FROM wallets WHERE id = ?")
      .bind(ACME)
      .first<{ t: string }>();
    expect(affinity?.t).toBe("integer");
  });

  test("an int64 above 2^53 read as a NUMBER is lossy — which is why the money path CASTs", async () => {
    const db = facadeFor(ACME);
    const huge = 10_000_000_000_000_001n;
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, huge.toString(), NOW, NOW)
      .run();

    // The highest-risk unknown in the port, pinned EMPIRICALLY rather than
    // assumed: does `ctx.storage.sql` hand an int64 back as a `bigint` (which
    // would make `wallet-d1.ts:422`'s `balance - outstanding` a mixed-type
    // TypeError on the money path) or as a lossy `number` (which is what D1
    // does, and which `walletFromRow` already accepts for display)?
    const raw = await db
      .prepare("SELECT balance_credits AS c FROM wallets WHERE id = ?")
      .bind(ACME)
      .first<{ c: number }>();
    expect(typeof raw?.c).toBe("number");
    // Same lossiness as D1, and the reason `creditsFromText` exists. Asserting
    // the loss rather than hiding it is what keeps a future reader from
    // "simplifying" the CAST away.
    expect(raw?.c).toBe(10_000_000_000_000_000);
    expect(Number.isSafeInteger(raw?.c)).toBe(false);
  });

  test("a bigint parameter is REFUSED by name, not silently rounded", async () => {
    const db = facadeFor(ACME);
    expect(() => db.prepare("SELECT ?").bind(1n)).toThrow(StorageError);
    expect(() => db.prepare("SELECT ?").bind(1n)).toThrow(/bindCredits/);
  });

  test("a boolean parameter is REFUSED and points at boolToSqlite", () => {
    const db = facadeFor(ACME);
    // SQLite has no BOOLEAN; the schema stores 0/1 and `boolFromSqlite()`
    // accepts both spellings, so a coercion here would let a column drift
    // between them forever without anything noticing.
    expect(() => db.prepare("SELECT ?").bind(true)).toThrow(/boolToSqlite/);
  });

  test("an undefined parameter is REFUSED and points at bindOptional", () => {
    const db = facadeFor(ACME);
    // Turning it into NULL here would write an unset variable to disk as an
    // intentional NULL.
    expect(() => db.prepare("SELECT ?").bind(undefined)).toThrow(/bindOptional/);
  });

  test("NULL round-trips as null, and an ArrayBuffer round-trips as bytes", async () => {
    const db = facadeFor(ACME);
    await db
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, auto_recharge_threshold_credits, dunning, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, 0, ?, ?)",
      )
      .bind(ACME, ACME, 1, null, NOW, NOW)
      .run();
    const row = await db
      .prepare("SELECT auto_recharge_threshold_credits AS t FROM wallets WHERE id = ?")
      .bind(ACME)
      .first<{ t: number | null }>();
    expect(row?.t).toBeNull();

    // No column in `sql/d1-ts/tenant/` is a BLOB today (grep: zero hits), so
    // this asserts the CARRIER rather than a schema column: the value crosses
    // the RPC boundary structured-cloneable and comes back as bytes. The first
    // BLOB column must not also be the first bug.
    const bytes = new Uint8Array([1, 2, 3, 250]);
    const echoed = await db.prepare("SELECT ? AS b").bind(bytes).first<{ b: ArrayBuffer }>();
    expect(new Uint8Array(echoed?.b as ArrayBuffer)).toEqual(bytes);
  });
});

// ---------------------------------------------------------------------------

describe("refusals the facade keeps closed", () => {
  test("exec(), dump() and withSession() refuse with the reason", async () => {
    const db = facadeFor(ACME);
    expect(await refusal(db.exec("SELECT 1"))).toContain("does not expose exec()");
    expect(await refusal(db.dump())).toContain("does not expose dump()");
    expect(() => db.withSession()).toThrow(/single instance/);
  });

  test("the object still refuses a facade addressed with another tenant's id", async () => {
    // The facade sends the tenant id it was constructed with on every RPC, and
    // the object checks it. This is the resolver-bug case: a facade built with
    // the wrong id against the right object must be refused rather than served,
    // because every row it wrote would look correct.
    const mismatched = new DurableObjectD1Database(GLOBEX, stubFor(ACME)).asD1Database();
    expect(await refusal(mismatched.prepare("SELECT 1").all())).toContain(
      "refusing rather than serving one tenant's data to another",
    );
  });

  test("two tenants' facades address physically different databases", async () => {
    const acme = facadeFor(ACME);
    const globex = facadeFor(GLOBEX);
    await acme
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("iso", ACME, "Iso", "iso")
      .run();

    // Not a `WHERE tenant_id = ?` filter: the row is in a different SQLite file
    // inside a different object, so no query in Globex's database can reach it
    // — including one that forgot the filter.
    const seen = await globex.prepare("SELECT id FROM projects").all();
    expect(seen.results).toEqual([]);

    // Read through the object itself, not through the facade, so the isolation
    // claim does not rest on the facade being honest about it.
    await runInDurableObject(
      env.TENANT_DATA.get(env.TENANT_DATA.idFromName(GLOBEX)),
      (_instance: TenantDataObject, state: DurableObjectState) => {
        expect(state.storage.sql.exec("SELECT id FROM projects").toArray()).toEqual([]);
      },
    );
  });
});
