/**
 * `D1LedgerStore` against the REAL `env.BILLING_DB` D1 binding.
 *
 * `apps/gateway/wrangler.toml` declares `[[d1_databases]] binding = "BILLING_DB"`,
 * so `@cloudflare/vitest-pool-workers` provisions a real local SQLite for it and
 * every statement this store issues is executed by the same engine production
 * runs. Nothing here doubles the database — the previous revision of this file
 * ran against a hand-written `FakeD1Database`, which could only ever prove that
 * the store's SQL matched the double's `if (sql === …)` ladder. It could not
 * catch a `CAST(? AS INTEGER)` that SQLite rejects, an `ON CONFLICT` target that
 * does not name a real unique index, a `JOIN` whose column is ambiguous, or a
 * `bigint` that D1's binder refuses. The real binding catches all four.
 *
 * The schema applied is the DEPLOYED migration
 * (`sql/d1-ts/control/0001_init_control.sql`), read as text by
 * `./d1-harness.ts` — never a fixture copy — so a column rename in the migration
 * breaks this suite instead of the suite passing against a private schema.
 *
 * What IS wrapped is the binding, not the code under test: `RecordingDatabase`
 * is a transparent decorator that records the SQL and bound values on their way
 * through to the live D1 and can be told to fail. With `failure` unset every
 * call reaches the real database unchanged.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  BILLING_EVENT_INSERT_SQL,
  BILLING_LEDGER_INSERT_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  CREDITS_EXACT_FIELD,
  D1LedgerStore,
  InMemoryMeteringOutbox,
  METERING_SCHEMA_SQL,
  ManualClock,
  type MeteringDatabase,
  type MeteringQueueMessage,
  MeteringUsageSink,
  TrackingScheduler,
} from "../../src/metering/index.js";
import type { MeteringQueue } from "../../src/metering/index.js";
import {
  RecordingDatabase,
  billingDb,
  ledgerEntryJson,
  overwriteLedgerDocument,
  resetMeteringTables,
  rowCount,
} from "./d1-harness.js";
import { FIXTURE_CREDITS, chargeFixture, pricedBook, usageFixture } from "./fixtures.js";

// ---------------------------------------------------------------------------
// Compile-time: the ports are binding-shaped.
// ---------------------------------------------------------------------------

/**
 * This function is never CALLED — its body is the assertion. If
 * `MeteringDatabase` or `MeteringQueue` ever drifts away from the real
 * binding's shape, `tsc` fails on these two assignments, which is the failure a
 * fake database CANNOT produce and the one that would otherwise surface only at
 * deploy time.
 */
function _bindingsSatisfyThePorts(db: D1Database, queue: Queue<MeteringQueueMessage>): void {
  const database: MeteringDatabase = db;
  const meteringQueue: MeteringQueue = queue;
  void database;
  void meteringQueue;
}
void _bindingsSatisfyThePorts;

// ---------------------------------------------------------------------------

beforeEach(async () => {
  await resetMeteringTables();
});

describe("METERING_SCHEMA_SQL", () => {
  it("declares the three tables the store writes, each keyed for idempotency", () => {
    expect(METERING_SCHEMA_SQL).toContain("billing_events");
    expect(METERING_SCHEMA_SQL).toContain("billing_ledger");
    expect(METERING_SCHEMA_SQL).toContain("billing_report_outbox");
    // The idempotency keys — every one of the three inserts targets these.
    expect(METERING_SCHEMA_SQL).toContain("billing_event_id TEXT PRIMARY KEY");
    expect(METERING_SCHEMA_SQL).toContain("id TEXT PRIMARY KEY");
    // The deployed `billing_ledger` has SIX columns and none of them is
    // `credits` (see `src/metering/d1.ts`, "Where the integer credits live"), so
    // the lossless integer travels as a decimal STRING inside the document
    // column. That column is therefore load-bearing for precision.
    expect(METERING_SCHEMA_SQL).toContain("entry_json TEXT NOT NULL");
    expect(METERING_SCHEMA_SQL).not.toContain("credits REAL");
    expect(METERING_SCHEMA_SQL).not.toContain("credits DOUBLE");
  });
});

describe("D1LedgerStore.record", () => {
  it("writes the metering, ledger and outbox rows in ONE batch (issue #150)", async () => {
    const db = new RecordingDatabase();
    const store = new D1LedgerStore(db);

    expect(await store.record(chargeFixture("ferrogate:req-1", 4n))).toEqual({
      status: "recorded",
    });

    expect(await rowCount("billing_events")).toBe(1);
    expect(await rowCount("billing_ledger")).toBe(1);
    expect(await rowCount("billing_report_outbox")).toBe(1);
    expect(db.executed.map((statement) => statement.sql)).toEqual([
      BILLING_EVENT_INSERT_SQL,
      BILLING_LEDGER_INSERT_SQL,
      BILLING_OUTBOX_INSERT_SQL,
    ]);
    // Every one is ON CONFLICT DO NOTHING; the metering insert alone RETURNs.
    for (const statement of db.executed) {
      expect(statement.sql).toContain("ON CONFLICT");
      expect(statement.sql).toContain("DO NOTHING");
    }
    expect(BILLING_EVENT_INSERT_SQL).toContain("RETURNING billing_event_id");
  });

  it("binds credits as a lossless decimal string, never a number", async () => {
    const db = new RecordingDatabase();
    const store = new D1LedgerStore(db);
    const huge = 9_007_199_254_740_993n; // 2^53 + 1 — not representable as a double.

    await store.record(chargeFixture("ferrogate:req-1", huge));

    // The value SQLite actually holds, read back as raw text.
    const stored: unknown = JSON.parse((await ledgerEntryJson("ferrogate:req-1")) ?? "{}");
    const exact = (stored as Record<string, unknown>)[CREDITS_EXACT_FIELD];
    expect(exact).toBe("9007199254740993");
    expect(typeof exact).toBe("string");
    // The string is exact…
    expect(BigInt(exact as string)).toBe(huge);
    // …and the proof that a JSON number would NOT have survived: the double
    // nearest 2^53+1 is 2^53, so a numeric field comes back one credit short.
    expect(BigInt(Number(exact))).toBe(9_007_199_254_740_992n);
    expect(BigInt(Number(exact))).not.toBe(huge);

    // …and it reads back as the same bigint through the store, not a rounded
    // double, after a real SQLite round-trip.
    expect((await store.get("ferrogate:req-1"))?.credits).toBe(huge);
    expect((await store.totals()).credits).toBe(huge);
  });

  it("absorbs a replay as a duplicate via ON CONFLICT + reload-compare", async () => {
    const store = new D1LedgerStore(billingDb());
    const charge = chargeFixture("ferrogate:req-1", 4n);

    expect(await store.record(charge)).toEqual({ status: "recorded" });
    expect(await store.record(charge)).toEqual({ status: "duplicate" });

    expect(await rowCount("billing_ledger")).toBe(1);
    expect(await rowCount("billing_events")).toBe(1);
    expect(await rowCount("billing_report_outbox")).toBe(1);
    expect((await store.totals()).credits).toBe(4n);
  });

  it("reports a replay carrying different settlement data as a conflict", async () => {
    const store = new D1LedgerStore(billingDb());
    const charge = chargeFixture("ferrogate:req-1", 4n);
    await store.record(charge);

    // Forge divergence in the STORED row, so the conflict is detected by the
    // reload-compare rather than by anything the caller passed.
    const document = JSON.parse((await ledgerEntryJson("ferrogate:req-1")) ?? "{}") as Record<
      string,
      unknown
    >;
    await overwriteLedgerDocument("ferrogate:req-1", {
      ...document,
      [CREDITS_EXACT_FIELD]: "99",
    });

    const outcome = await store.record(charge);
    expect(outcome.status).toBe("conflict");
    expect(outcome.status === "conflict" && outcome.existing.credits).toBe(99n);
  });

  it("round-trips the settlement documents through entry_json / event_json", async () => {
    const store = new D1LedgerStore(billingDb());
    await store.record(chargeFixture("ferrogate:req-1", 4n));

    const reloaded = await store.get("ferrogate:req-1");
    expect(reloaded?.entry.provider_model).toBe("gpt-4o-mini-2024-07-18");
    expect(reloaded?.entry.usage.total_tokens).toBe(15);
    expect(reloaded?.entry.cost.total_cost).toBeCloseTo(4.05e-6, 12);
    expect(reloaded?.entry.tenant.organization_id).toBe("tenant_a");
    expect(reloaded?.event.provider_attempt.provider_attempt_id).toBe("ferrogate:req-1");
    expect(reloaded?.event.status_code).toBe(200);
  });

  it("throws rather than silently reporting a duplicate on a short batch", async () => {
    const shortBatch: MeteringDatabase = {
      prepare: () => ({
        bind: () => shortBatch.prepare(""),
        run: async () => ({}),
        all: async () => ({}),
      }),
      batch: async () => [],
    };
    await expect(new D1LedgerStore(shortBatch).record(chargeFixture("a", 1n))).rejects.toThrow(
      /no result for the metering insert/,
    );
  });

  it("filters list and totals by tenant", async () => {
    const store = new D1LedgerStore(billingDb());
    await store.record(chargeFixture("ferrogate:req-1", 4n));
    await store.record(
      chargeFixture("ferrogate:req-2", 7n, { tenant: { organization_id: "tenant_b" } }),
    );

    expect(await store.list({ organization_id: "tenant_b" }, 0, 10)).toHaveLength(1);
    expect((await store.totals({ organization_id: "tenant_a" })).credits).toBe(4n);
    expect((await store.totals()).credits).toBe(11n);
  });

  it("projects the scope columns the deployed indexes order on", async () => {
    // The document pattern only works because the filter/order columns are
    // projected OUT of the document; a NULL here would make every tenant-scoped
    // admin query miss the row while `get()` still found it.
    const store = new D1LedgerStore(billingDb());
    await store.record(chargeFixture("ferrogate:req-1", 4n));

    const row = await billingDb()
      .prepare(
        "SELECT organization_id, project_id, created_at_unix FROM billing_ledger WHERE id = ?",
      )
      .bind("ferrogate:req-1")
      .first<{ organization_id: string; project_id: string; created_at_unix: number }>();
    expect(row?.organization_id).toBe("tenant_a");
    expect(row?.project_id).toBe("project_1");
    expect(row?.created_at_unix).toBe(1_700_000_000);
  });
});

describe("MeteringUsageSink on D1", () => {
  it("settles a real Usage end to end and keeps the charge on an outage", async () => {
    const db = new RecordingDatabase();
    const scheduler = new TrackingScheduler();
    const outbox = new InMemoryMeteringOutbox();
    const clock = new ManualClock();
    const sink = new MeteringUsageSink({
      priceBook: pricedBook(),
      ledger: new D1LedgerStore(db),
      outbox,
      scheduler,
      clock,
    });

    sink.record(usageFixture());
    await scheduler.idle();

    expect(await rowCount("billing_ledger")).toBe(1);
    expect((await sink.ledger.totals()).credits).toBe(FIXTURE_CREDITS);

    // D1 goes away: the charge is NOT lost, it stays queued for the next drain.
    db.failure = new Error("D1_ERROR: network");
    sink.record(usageFixture({ requestId: "fg-second-request" }));
    await scheduler.idle();

    expect(outbox.size).toBe(1);
    expect(sink.stats.deliveryFailures).toBe(1);
    expect(await rowCount("billing_ledger")).toBe(1);

    db.failure = undefined;
    clock.advance(2); // past the 1s backoff the first failure scheduled
    await sink.flush();
    expect(await rowCount("billing_ledger")).toBe(2);
    expect(outbox.size).toBe(0);
  });
});
