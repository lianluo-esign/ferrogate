/**
 * The D1-backed ledger store, and the structural claim that a REAL Cloudflare
 * binding satisfies the port it is written against.
 */
import { describe, expect, it } from "vitest";
import {
  BILLING_EVENT_INSERT_SQL,
  BILLING_LEDGER_INSERT_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  D1LedgerStore,
  InMemoryMeteringOutbox,
  METERING_SCHEMA_SQL,
  ManualClock,
  MeteringUsageSink,
  TrackingScheduler,
  type MeteringDatabase,
  type MeteringQueue,
  type MeteringQueueMessage,
} from "../../src/metering/index.js";
import { FakeD1Database } from "./fake-d1.js";
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

describe("METERING_SCHEMA_SQL", () => {
  it("declares the three tables the store writes, each keyed for idempotency", () => {
    expect(METERING_SCHEMA_SQL).toContain("billing_events");
    expect(METERING_SCHEMA_SQL).toContain("billing_ledger");
    expect(METERING_SCHEMA_SQL).toContain("billing_report_outbox");
    expect(METERING_SCHEMA_SQL).toContain("billing_event_id TEXT PRIMARY KEY");
    // Credits are TEXT so a balance past 2^53 round-trips exactly.
    expect(METERING_SCHEMA_SQL).toContain("credits TEXT NOT NULL");
  });
});

describe("D1LedgerStore.record", () => {
  it("writes the metering, ledger and outbox rows in ONE batch (issue #150)", async () => {
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);

    expect(await store.record(chargeFixture("ferrogate:req-1", 4n))).toEqual({
      status: "recorded",
    });

    expect(db.eventCount).toBe(1);
    expect(db.ledgerCount).toBe(1);
    expect(db.outboxCount).toBe(1);
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
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);
    const huge = 9_007_199_254_740_993n; // 2^53 + 1

    await store.record(chargeFixture("ferrogate:req-1", huge));

    const ledgerInsert = db.executed.find(
      (statement) => statement.sql === BILLING_LEDGER_INSERT_SQL,
    );
    expect(ledgerInsert?.values[6]).toBe("9007199254740993");
    expect(typeof ledgerInsert?.values[6]).toBe("string");

    // …and it reads back as the same bigint, not a rounded double.
    expect((await store.get("ferrogate:req-1"))?.credits).toBe(huge);
    expect((await store.totals()).credits).toBe(huge);
  });

  it("absorbs a replay as a duplicate via ON CONFLICT + reload-compare", async () => {
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);
    const charge = chargeFixture("ferrogate:req-1", 4n);

    expect(await store.record(charge)).toEqual({ status: "recorded" });
    expect(await store.record(charge)).toEqual({ status: "duplicate" });

    expect(db.ledgerCount).toBe(1);
    expect((await store.totals()).credits).toBe(4n);
  });

  it("reports a replay carrying different settlement data as a conflict", async () => {
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);
    const charge = chargeFixture("ferrogate:req-1", 4n);
    await store.record(charge);

    // Forge divergence in the STORED row, so the conflict is detected by the
    // reload-compare rather than by anything the caller passed.
    db.overwriteLedger("ferrogate:req-1", { credits: "99" });

    const outcome = await store.record(charge);
    expect(outcome.status).toBe("conflict");
    expect(outcome.status === "conflict" && outcome.existing.credits).toBe(99n);
  });

  it("round-trips the settlement documents through entry_json / event_json", async () => {
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);
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
    await expect(
      new D1LedgerStore(shortBatch).record(chargeFixture("a", 1n)),
    ).rejects.toThrow(/no result for the metering insert/);
  });

  it("filters list and totals by tenant", async () => {
    const db = new FakeD1Database();
    const store = new D1LedgerStore(db);
    await store.record(chargeFixture("ferrogate:req-1", 4n));
    await store.record(
      chargeFixture("ferrogate:req-2", 7n, { tenant: { organization_id: "tenant_b" } }),
    );

    expect(await store.list({ organization_id: "tenant_b" }, 0, 10)).toHaveLength(1);
    expect((await store.totals({ organization_id: "tenant_a" })).credits).toBe(4n);
    expect((await store.totals()).credits).toBe(11n);
  });
});

describe("MeteringUsageSink on D1", () => {
  it("settles a real Usage end to end and keeps the charge on an outage", async () => {
    const db = new FakeD1Database();
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

    expect(db.ledgerCount).toBe(1);
    expect((await sink.ledger.totals()).credits).toBe(FIXTURE_CREDITS);

    // D1 goes away: the charge is NOT lost, it stays queued for the next drain.
    db.failure = new Error("D1_ERROR: network");
    sink.record(usageFixture({ requestId: "fg-second-request" }));
    await scheduler.idle();

    expect(outbox.size).toBe(1);
    expect(sink.stats.deliveryFailures).toBe(1);

    db.failure = undefined;
    clock.advance(2); // past the 1s backoff the first failure scheduled
    await sink.flush();
    expect(db.ledgerCount).toBe(2);
    expect(outbox.size).toBe(0);
  });
});
