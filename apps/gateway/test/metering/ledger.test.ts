/**
 * The idempotency guard, in isolation.
 *
 * `LedgerStore.record` is the single thing standing between an at-least-once
 * outbox delivery and a double charge, so it is held here directly as well as
 * through the sink — a guard that is only ever exercised transitively is a
 * guard a refactor can delete without any test noticing.
 */
import { describe, expect, it } from "vitest";
import { InMemoryLedgerStore, meteredTotals } from "../../src/metering/index.js";
import { chargeFixture } from "./fixtures.js";

describe("InMemoryLedgerStore.record", () => {
  it("records a first-seen charge", async () => {
    const store = new InMemoryLedgerStore();
    expect(await store.record(chargeFixture("ferrogate:req-1", 4n))).toEqual({
      status: "recorded",
    });
    expect(store.size).toBe(1);
  });

  it("absorbs a byte-equal replay as a duplicate — one charge, not two", async () => {
    const store = new InMemoryLedgerStore();
    const charge = chargeFixture("ferrogate:req-1", 4n);

    expect(await store.record(charge)).toEqual({ status: "recorded" });
    expect(await store.record(charge)).toEqual({ status: "duplicate" });

    expect(store.size).toBe(1);
    expect((await store.totals()).credits).toBe(4n);
    expect((await store.totals()).entries).toBe(1);
  });

  it("reports a replay with DIFFERENT settlement data as a conflict", async () => {
    const store = new InMemoryLedgerStore();
    const first = chargeFixture("ferrogate:req-1", 4n);
    // Same idempotency key, different money: Rust `billing_idempotency_conflict`
    // (HTTP 409). Absorbing this as a duplicate would hide data corruption.
    const second = chargeFixture("ferrogate:req-1", 9n);

    expect(await store.record(first)).toEqual({ status: "recorded" });
    const outcome = await store.record(second);
    expect(outcome.status).toBe("conflict");
    expect(outcome.status === "conflict" && outcome.existing.credits).toBe(4n);

    // The stored settlement is the FIRST one; a conflict never overwrites.
    expect((await store.get("ferrogate:req-1"))?.credits).toBe(4n);
    expect((await store.totals()).credits).toBe(4n);
  });

  it("keys idempotency on the entry id, so distinct requests both charge", async () => {
    const store = new InMemoryLedgerStore();
    await store.record(chargeFixture("ferrogate:req-1", 4n));
    await store.record(chargeFixture("ferrogate:req-2", 7n));

    expect(store.size).toBe(2);
    expect((await store.totals()).credits).toBe(11n);
  });

  it("filters by tenant on list and totals", async () => {
    const store = new InMemoryLedgerStore();
    await store.record(chargeFixture("ferrogate:req-1", 4n));
    await store.record(
      chargeFixture("ferrogate:req-2", 7n, {
        tenant: { organization_id: "tenant_b" },
      }),
    );

    expect(await store.list({ organization_id: "tenant_b" }, 0, 10)).toHaveLength(1);
    expect((await store.totals({ organization_id: "tenant_a" })).credits).toBe(4n);
    expect((await store.totals({ organization_id: "tenant_b" })).credits).toBe(7n);
  });
});

describe("meteredTotals", () => {
  it("accumulates credits in bigint, past the number safe range", () => {
    // Two charges that a `number` accumulator merges into one.
    const totals = meteredTotals([
      chargeFixture("a", 9_007_199_254_740_993n),
      chargeFixture("b", 1n),
    ]);
    expect(totals.credits).toBe(9_007_199_254_740_994n);
    expect(totals.entries).toBe(2);
    expect(totals.totalTokens).toBe(30n);
  });
});
