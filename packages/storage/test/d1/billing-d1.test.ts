/**
 * The CONTROL-database billing-event claim + outbox enqueue, against REAL D1.
 *
 * The load-bearing property is that the claim and the enqueue are ONE
 * transaction, and that the claim token is the `RETURNING` row rather than the
 * row's existence. Both are properties of the D1 runtime, so this suite runs in
 * `workerd` against real SQLite — a fake's `batch()` is atomic because the fake
 * says so.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { type BillingEventRecord, D1BillingEventLedger, StorageError } from "../../src/index.js";
import "./harness.js";

const NOW = 1_784_073_600;

let ledger: D1BillingEventLedger;

beforeAll(async () => {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
  ledger = new D1BillingEventLedger(env.CONTROL_DB);
});

beforeEach(async () => {
  await env.CONTROL_DB.batch([
    env.CONTROL_DB.prepare("DELETE FROM billing_events"),
    env.CONTROL_DB.prepare("DELETE FROM billing_report_outbox"),
  ]);
});

function event(overrides: Partial<BillingEventRecord> = {}): BillingEventRecord {
  return {
    billingEventId: "led_1",
    requestId: "req_1",
    providerAttemptIndex: 0,
    occurredAtUnix: NOW,
    eventJson: '{"cost_usd":0.002,"request_id":"req_1","total_tokens":140}',
    ...overrides,
  };
}

async function rowCount(table: string): Promise<number> {
  const row = await env.CONTROL_DB.prepare(`SELECT count(*) AS n FROM ${table}`).first<{
    n: number;
  }>();
  return Number(row?.n ?? -1);
}

describe("D1BillingEventLedger — the claim", () => {
  test("a first write wins the claim and lands BOTH rows", async () => {
    const outcome = await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 1);
    expect(outcome.recorded).toBe(true);
    expect(await rowCount("billing_events")).toBe(1);
    expect(await rowCount("billing_report_outbox")).toBe(1);
  });

  test("an identical replay LOSES the claim and does not duplicate either row", async () => {
    await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 1);
    const replay = await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 99);
    // `recorded: false` is what stops the caller re-applying the charge. If this
    // ever reads `true`, every retry double-bills.
    expect(replay.recorded).toBe(false);
    expect(await rowCount("billing_events")).toBe(1);
    expect(await rowCount("billing_report_outbox")).toBe(1);
    // The replay must not have reset the live row's schedule either.
    const entry = await ledger.getBillingReportOutboxEntry("led_1");
    expect(entry?.nextAttemptUnix).toBe(NOW + 1);
  });

  test("a DIVERGENT replay on the same id is a typed conflict, not a silent no-op", async () => {
    await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 1);
    const divergent = event({
      eventJson: '{"cost_usd":99.0,"request_id":"req_1","total_tokens":140}',
    });
    await expect(
      ledger.appendBillingEventWithOutboxEnqueue(divergent, "led_1", NOW + 1),
    ).rejects.toMatchObject({ kind: "conflict" });
    // And the stored document is the ORIGINAL — a conflict must not overwrite.
    const stored = await ledger.getBillingEvent("led_1");
    expect(stored?.eventJson).toBe(event().eventJson);
  });

  test("the #135 provider-attempt index makes a retried upstream call a DIFFERENT event", async () => {
    const first = await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 1);
    const retry = await ledger.appendBillingEventWithOutboxEnqueue(
      event({ billingEventId: "led_1_attempt_1", providerAttemptIndex: 1 }),
      "led_1_attempt_1",
      NOW + 1,
    );
    expect([first.recorded, retry.recorded]).toEqual([true, true]);
    expect(await rowCount("billing_events")).toBe(2);
  });

  test("concurrent claims on one id: exactly ONE wins", async () => {
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW + 1),
      ),
    );
    const won = results.filter((r) => r.status === "fulfilled" && r.value.recorded === true).length;
    expect(won).toBe(1);
    expect(await rowCount("billing_events")).toBe(1);
  });

  test("the reloaded event round-trips its identity columns", async () => {
    await ledger.appendBillingEventWithOutboxEnqueue(
      event({ requestId: "req_zz", providerAttemptIndex: 3, occurredAtUnix: NOW + 7 }),
      "led_1",
      NOW,
    );
    expect(await ledger.getBillingEvent("led_1")).toEqual({
      billingEventId: "led_1",
      requestId: "req_zz",
      providerAttemptIndex: 3,
      occurredAtUnix: NOW + 7,
      eventJson: event().eventJson,
    });
    expect(await ledger.getBillingEvent("nope")).toBeUndefined();
  });
});

describe("D1BillingEventLedger — the outbox lifecycle", () => {
  test("listDue returns only due, non-dead-lettered rows, oldest deadline first", async () => {
    await ledger.enqueueBillingReport("c", '{"n":3}', NOW + 500);
    await ledger.enqueueBillingReport("a", '{"n":1}', NOW - 10);
    await ledger.enqueueBillingReport("b", '{"n":2}', NOW - 5);
    await ledger.enqueueBillingReport("d", '{"n":4}', NOW - 1);
    await ledger.deadLetterBillingReport("d", NOW);

    const due = await ledger.listDueBillingReports(NOW, 10);
    expect(due.map((e) => e.id)).toEqual(["a", "b"]);
    expect(due[0]?.eventJson).toBe('{"n":1}');
    expect(due[0]?.attempts).toBe(0);
    expect(due[0]?.deadLetteredAtUnix).toBeUndefined();
  });

  test("listDue honours its limit", async () => {
    await ledger.enqueueBillingReport("a", "{}", NOW - 3);
    await ledger.enqueueBillingReport("b", "{}", NOW - 2);
    await ledger.enqueueBillingReport("c", "{}", NOW - 1);
    expect((await ledger.listDueBillingReports(NOW, 2)).map((e) => e.id)).toEqual(["a", "b"]);
  });

  test("reschedule charges one attempt and moves the deadline", async () => {
    await ledger.enqueueBillingReport("a", "{}", NOW);
    await ledger.rescheduleBillingReport("a", NOW + 60);
    await ledger.rescheduleBillingReport("a", NOW + 120);
    const entry = await ledger.getBillingReportOutboxEntry("a");
    expect(entry?.attempts).toBe(2);
    expect(entry?.nextAttemptUnix).toBe(NOW + 120);
  });

  test("a dead-lettered row leaves the due set and enters the dead-letter list", async () => {
    await ledger.enqueueBillingReport("a", "{}", NOW - 1);
    await ledger.deadLetterBillingReport("a", NOW);
    expect(await ledger.listDueBillingReports(NOW, 10)).toEqual([]);
    const dead = await ledger.listDeadLetteredBillingReports(10);
    expect(dead.map((e) => e.id)).toEqual(["a"]);
    expect(dead[0]?.deadLetteredAtUnix).toBe(NOW);
  });

  test("replay is a CAS: it fires only from the dead-lettered state", async () => {
    await ledger.enqueueBillingReport("a", "{}", NOW - 1);
    await ledger.rescheduleBillingReport("a", NOW + 60);
    await ledger.deadLetterBillingReport("a", NOW);

    const replayed = await ledger.replayDeadLetteredBillingReport("a", NOW + 5, NOW + 2);
    expect(replayed.kind).toBe("replayed");
    if (replayed.kind === "replayed") {
      expect(replayed.entry.attempts).toBe(0);
      expect(replayed.entry.nextAttemptUnix).toBe(NOW + 5);
      expect(replayed.entry.deadLetteredAtUnix).toBeUndefined();
    }
    // It is now live, so a SECOND replay must refuse and report the real state
    // rather than resetting a healthy row's schedule.
    const second = await ledger.replayDeadLetteredBillingReport("a", NOW + 900, NOW + 3);
    expect(second.kind).toBe("not_dead_lettered");
    if (second.kind === "not_dead_lettered") {
      expect(second.entry.nextAttemptUnix).toBe(NOW + 5);
    }
  });

  test("replaying an unknown id reports not_found", async () => {
    expect(await ledger.replayDeadLetteredBillingReport("ghost", NOW, NOW)).toEqual({
      kind: "not_found",
    });
  });

  test("delete reaps a delivered row", async () => {
    await ledger.enqueueBillingReport("a", "{}", NOW);
    await ledger.deleteBillingReport("a");
    expect(await ledger.getBillingReportOutboxEntry("a")).toBeUndefined();
  });

  test("enqueue is idempotent on the ledger-entry id", async () => {
    await ledger.enqueueBillingReport("a", '{"n":1}', NOW);
    await ledger.enqueueBillingReport("a", '{"n":2}', NOW + 100);
    const entry = await ledger.getBillingReportOutboxEntry("a");
    expect(entry?.eventJson).toBe('{"n":1}');
    expect(entry?.nextAttemptUnix).toBe(NOW);
  });
});

describe("D1BillingEventLedger — atomicity", () => {
  /**
   * The #150 guarantee: a metering event never lands without its outbox row.
   * Proven by making statement 1 fail (a NOT NULL violation on `event_json`
   * via a raw batch that mirrors the class's SQL) and observing that statement
   * 0's insert is rolled back too.
   */
  test("a failure in the enqueue statement rolls the claim back", async () => {
    await expect(
      env.CONTROL_DB.batch([
        env.CONTROL_DB.prepare(
          "INSERT INTO billing_events (billing_event_id, request_id, provider_attempt_index, " +
            "occurred_at_unix, event_json) VALUES (?, ?, ?, ?, ?) " +
            "ON CONFLICT (billing_event_id) DO NOTHING RETURNING billing_event_id",
        ).bind("led_atomic", "req_atomic", 0, NOW, "{}"),
        // `next_attempt_unix` is `INTEGER NOT NULL`; binding NULL fails the
        // statement. (A NULL `id` would NOT: SQLite's long-standing quirk is
        // that a TEXT PRIMARY KEY without an explicit NOT NULL accepts NULL.)
        env.CONTROL_DB.prepare(
          "INSERT INTO billing_report_outbox (id, attempts, next_attempt_unix, " +
            "dead_lettered_at_unix, created_at_unix, updated_at_unix, event_json) " +
            "VALUES (?, 0, ?, NULL, unixepoch(), unixepoch(), ?)",
        ).bind("led_atomic", null, "{}"),
      ]),
    ).rejects.toThrow();
    // If D1's batch were NOT one transaction, this would be 1.
    expect(await rowCount("billing_events")).toBe(0);
  });

  test("StorageError is the taxonomy a conflicting replay surfaces", async () => {
    await ledger.appendBillingEventWithOutboxEnqueue(event(), "led_1", NOW);
    const error = await ledger
      .appendBillingEventWithOutboxEnqueue(event({ eventJson: "{}" }), "led_1", NOW)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StorageError);
    expect((error as StorageError).kind).toBe("conflict");
  });
});
