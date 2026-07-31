/**
 * The durable outbox and its retry ladder.
 *
 * The constants and the backoff curve are lifted verbatim from
 * `crates/ferrogate-gateway/src/state.rs:7055-7070`; drifting them would change
 * how long a charge survives a billing outage, which is the entire point of the
 * pattern.
 */
import { describe, expect, it } from "vitest";
import {
  BILLING_OUTBOX_BATCH,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  billingOutboxBackoffSeconds,
} from "../../src/metering/index.js";
import { chargeFixture } from "./fixtures.js";

describe("billingOutboxBackoffSeconds", () => {
  it("is the Rust curve: 1, 2, 4, 8, 16, 32, 60, 60, …", () => {
    expect([0, 1, 2, 3, 4, 5, 6, 7, 20].map(billingOutboxBackoffSeconds)).toEqual([
      1, 2, 4, 8, 16, 32, 60, 60, 60,
    ]);
  });

  it("carries the Rust batch and attempt caps", () => {
    expect(BILLING_OUTBOX_BATCH).toBe(100);
    expect(MAX_BILLING_OUTBOX_ATTEMPTS).toBe(20);
  });
});

describe("InMemoryMeteringOutbox", () => {
  it("enqueues a first-seen charge and reports it due", () => {
    const outbox = new InMemoryMeteringOutbox();
    expect(outbox.enqueue(chargeFixture("a", 4n), 100)).toBe(true);
    expect(outbox.listDue(100, 10).map((row) => row.id)).toEqual(["a"]);
  });

  it("is ON CONFLICT (id) DO NOTHING — a replay does not queue a second delivery", () => {
    const outbox = new InMemoryMeteringOutbox();
    const charge = chargeFixture("a", 4n);

    expect(outbox.enqueue(charge, 100)).toBe(true);
    expect(outbox.enqueue(charge, 100)).toBe(false);

    expect(outbox.size).toBe(1);
    expect(outbox.listDue(100, 10)).toHaveLength(1);
  });

  it("withholds a row until its deadline", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("a", 4n), 100);
    outbox.reschedule("a", 140);

    expect(outbox.listDue(139, 10)).toHaveLength(0);
    expect(outbox.listDue(140, 10)).toHaveLength(1);
    expect(outbox.get("a")?.attempts).toBe(1);
  });

  it("orders a due batch by deadline and honours the batch limit", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("late", 1n), 130);
    outbox.enqueue(chargeFixture("early", 1n), 110);
    outbox.enqueue(chargeFixture("middle", 1n), 120);

    expect(outbox.listDue(200, 10).map((row) => row.id)).toEqual(["early", "middle", "late"]);
    expect(outbox.listDue(200, 2).map((row) => row.id)).toEqual(["early", "middle"]);
  });

  it("excludes dead letters from the due batch but keeps them for inspection", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("a", 4n), 100);
    outbox.deadLetter("a", 150);

    expect(outbox.listDue(1_000, 10)).toHaveLength(0);
    expect(outbox.deadLetters().map((row) => row.id)).toEqual(["a"]);
    expect(outbox.get("a")?.deadLetteredAtUnix).toBe(150);
    // The charge itself is still there — dead-lettering never loses the money.
    expect(outbox.get("a")?.charge.credits).toBe(4n);
  });

  it("replays a dead letter back onto the ladder with attempts reset (#388)", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("a", 4n), 100);
    outbox.reschedule("a", 120);
    outbox.deadLetter("a", 150);

    expect(outbox.replayDeadLetter("a", 200)).toBe(true);
    expect(outbox.get("a")?.attempts).toBe(0);
    expect(outbox.get("a")?.deadLetteredAtUnix).toBeUndefined();
    expect(outbox.listDue(200, 10).map((row) => row.id)).toEqual(["a"]);
  });

  it("refuses to replay a row that is not dead-lettered", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("a", 4n), 100);
    expect(outbox.replayDeadLetter("a", 200)).toBe(false);
    expect(outbox.replayDeadLetter("missing", 200)).toBe(false);
  });

  it("drops a delivered row", () => {
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture("a", 4n), 100);
    outbox.delete("a");
    expect(outbox.size).toBe(0);
    expect(outbox.get("a")).toBeUndefined();
  });
});
