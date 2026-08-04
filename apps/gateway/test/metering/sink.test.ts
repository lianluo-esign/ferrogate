/**
 * `MeteringUsageSink` — the composed settlement path.
 *
 * These drive the sink through its real `UsageSink` surface (`record(usage)`),
 * with the real `@ferrogate/billing` `charge()` doing the pricing. The only
 * things swapped are the CLOCK (so the retry ladder is reachable) and the
 * downstream publisher's availability (so an outage is a real rejection rather
 * than an assertion about one).
 */
import { PriceBook, modelPriceUsd, priceEntry } from "@ferrogate/billing";
import { beforeEach, describe, expect, it } from "vitest";
import {
  type CostDivergence,
  InMemoryBillingReportPublisher,
  InMemoryLedgerStore,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  ManualClock,
  type MeteringDiagnostics,
  type MeteringUsageSink,
  TrackingScheduler,
  createMeteringUsageSink,
} from "../../src/metering/index.js";
import {
  FIXTURE_CREDITS,
  PRICED_MODEL,
  PRICED_PROVIDER,
  pricedBook,
  usageFixture,
} from "./fixtures.js";

interface Harness {
  readonly sink: MeteringUsageSink;
  readonly ledger: InMemoryLedgerStore;
  readonly outbox: InMemoryMeteringOutbox;
  readonly publisher: InMemoryBillingReportPublisher;
  readonly scheduler: TrackingScheduler;
  readonly clock: ManualClock;
  readonly divergences: CostDivergence[];
  readonly unpricedReports: { requestId: string; providerModel: string }[];
}

function harness(
  options: {
    priceBook?: PriceBook;
    settlementMode?: "rate_card" | "serving_offering";
    settledCostUsd?: (usage: ReturnType<typeof usageFixture>) => number | undefined;
  } = {},
): Harness {
  const ledger = new InMemoryLedgerStore();
  const outbox = new InMemoryMeteringOutbox();
  const publisher = new InMemoryBillingReportPublisher();
  const scheduler = new TrackingScheduler();
  const clock = new ManualClock(1_700_000_000);
  const divergences: CostDivergence[] = [];
  const unpricedReports: { requestId: string; providerModel: string }[] = [];
  const diagnostics: MeteringDiagnostics = {
    onDivergence: (d) => divergences.push(d),
    onPriceNotFound: (info) =>
      unpricedReports.push({ requestId: info.requestId, providerModel: info.providerModel }),
  };
  const sink = createMeteringUsageSink({
    priceBook: options.priceBook ?? pricedBook(),
    ledger,
    outbox,
    publisher,
    scheduler,
    clock,
    diagnostics,
    ...(options.settlementMode === undefined ? {} : { settlementMode: options.settlementMode }),
    ...(options.settledCostUsd === undefined ? {} : { settledCostUsd: options.settledCostUsd }),
  });
  return { sink, ledger, outbox, publisher, scheduler, clock, divergences, unpricedReports };
}

describe("MeteringUsageSink — pricing", () => {
  let h: Harness;
  beforeEach(() => {
    h = harness();
  });

  it("prices from the rate card and settles in integer credits", async () => {
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    const [charge] = h.ledger.charges;
    expect(charge?.credits).toBe(FIXTURE_CREDITS);
    expect(charge?.entry.cost_source).toBe("billing_price_book");
    expect(charge?.entry.cost.total_cost).toBeCloseTo(4.05e-6, 12);
    expect(charge?.entry.tenant.organization_id).toBe("tenant_a");
    expect((await h.ledger.totals()).credits).toBe(FIXTURE_CREDITS);
  });

  it("reconciles a provider-omitted split before pricing (issue #140)", async () => {
    // Gemini-shaped: prompt + total reported, completion omitted. Billing the
    // omitted side at $0 is the defect `reconcile_split` exists to prevent.
    h.sink.record(usageFixture({ promptTokens: 11, completionTokens: undefined, totalTokens: 15 }));
    await h.scheduler.idle();

    const [charge] = h.ledger.charges;
    expect(charge?.entry.usage.completion_tokens).toBe(4);
    expect(charge?.credits).toBe(FIXTURE_CREDITS);
  });

  it("delivers the settled charge downstream and drops the outbox row", async () => {
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.publisher.delivered[0]?.credits).toBe(FIXTURE_CREDITS);
    expect(h.outbox.size).toBe(0);
    expect(h.sink.stats.delivered).toBe(1);
  });

  it("labels usage the tap never saw as a gateway estimate, not provider usage", async () => {
    h.sink.record(
      usageFixture({
        status: 502,
        promptTokens: undefined,
        completionTokens: undefined,
        totalTokens: undefined,
      }),
    );
    await h.scheduler.idle();

    const [charge] = h.ledger.charges;
    expect(charge?.entry.usage_source).toBe("gateway_estimate");
    expect(charge?.entry.status_code).toBe(502);
    expect(charge?.credits).toBe(0n);
  });
});

describe("MeteringUsageSink — gateway-settled cost is authoritative (#135/#152)", () => {
  it("records the settled figure verbatim, not the rate-card re-price", async () => {
    const h = harness({ settledCostUsd: () => 0.01 });
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    const [charge] = h.ledger.charges;
    expect(charge?.entry.cost_source).toBe("gateway_settled");
    expect(charge?.entry.cost.total_cost).toBe(0.01);
    expect(charge?.credits).toBe(10_000n);
  });

  it("WARNS on a >5% divergence but never overrides the settled figure", async () => {
    // Rate card says 4.05e-6; the gateway settled 0.01 — a 246,813% gap.
    const h = harness({ settledCostUsd: () => 0.01 });
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    expect(h.divergences).toHaveLength(1);
    expect(h.divergences[0]?.gateway_settled_cost_usd).toBe(0.01);
    expect(h.divergences[0]?.price_book_estimate_usd).toBeCloseTo(4.05e-6, 12);
    expect(h.sink.stats.divergences).toBe(1);
    // Signal only: the settled figure is what landed on the ledger.
    expect(h.ledger.charges[0]?.entry.cost.total_cost).toBe(0.01);
    expect(h.ledger.charges[0]?.credits).toBe(10_000n);
  });

  it("stays silent when the settled figure agrees with the card", async () => {
    const h = harness({ settledCostUsd: () => 4.05e-6 });
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    expect(h.divergences).toHaveLength(0);
    expect(h.ledger.charges[0]?.entry.cost_source).toBe("gateway_settled");
  });

  it("still prices from a settled cost when the model has NO rate-card rule", async () => {
    // The authoritative branch does not need a price — that asymmetry is what
    // lets a new model bill correctly the moment the gateway can settle it.
    const h = harness({ settledCostUsd: () => 0.002 });
    h.sink.record(usageFixture({ providerModel: "some-unlisted-model" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.ledger.charges[0]?.credits).toBe(2_000n);
    expect(h.sink.stats.priceNotFound).toBe(0);
  });
});

describe("MeteringUsageSink — FAIL CLOSED on an unknown price (#129)", () => {
  it("does not use a wildcard card when the serving offering is unpriced (#814)", async () => {
    const h = harness({
      priceBook: PriceBook.new([priceEntry("*", "*", modelPriceUsd(99, 99))]),
      settlementMode: "serving_offering",
      settledCostUsd: () => undefined,
    });

    h.sink.record(usageFixture({ provider: "fallback-channel", providerModel: "served-model" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(0);
    expect(h.ledger.events).toHaveLength(1);
    expect(h.ledger.events[0]?.event.provider).toBe("fallback-channel");
    expect(h.ledger.events[0]?.event.provider_model).toBe("served-model");
    expect(h.ledger.events[0]?.event.cost_usd).toBeUndefined();
    expect(h.sink.stats.priceNotFound).toBe(1);
    expect(h.sink.unpriced[0]?.message).toContain("serving offering");
  });

  it("keeps a numeric zero offering distinct from an unpriced offering (#814)", async () => {
    const h = harness({
      priceBook: PriceBook.new([priceEntry("*", "*", modelPriceUsd(99, 99))]),
      settlementMode: "serving_offering",
      settledCostUsd: () => 0,
    });

    h.sink.record(usageFixture({ provider: "free-channel", providerModel: "free-model" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.ledger.events).toHaveLength(0);
    expect(h.ledger.charges[0]?.entry.provider).toBe("free-channel");
    expect(h.ledger.charges[0]?.entry.cost_source).toBe("gateway_settled");
    expect(h.ledger.charges[0]?.entry.cost.total_cost).toBe(0);
    expect(h.sink.stats.priceNotFound).toBe(0);
  });

  it("refuses the charge instead of billing zero", async () => {
    const h = harness();
    h.sink.record(usageFixture({ providerModel: "model-with-no-price" }));
    await h.scheduler.idle();

    // Nothing billed, ANYWHERE: no ledger row, no outbox row, no delivery.
    expect(h.ledger.size).toBe(0);
    expect(h.outbox.size).toBe(0);
    expect(h.publisher.delivered).toHaveLength(0);
    expect((await h.ledger.totals()).credits).toBe(0n);

    // And it is loud, not silent.
    expect(h.sink.stats.priceNotFound).toBe(1);
    expect(h.sink.stats.charged).toBe(0);
    expect(h.sink.unpriced).toHaveLength(1);
    expect(h.sink.unpriced[0]?.providerModel).toBe("model-with-no-price");
    expect(h.sink.unpriced[0]?.message).toContain("no rate-card price");
    expect(h.unpricedReports).toEqual([
      { requestId: "fg-000000000000002a", providerModel: "model-with-no-price" },
    ]);
  });

  it("refuses an unknown PROVIDER for a known model name", async () => {
    const h = harness();
    h.sink.record(usageFixture({ provider: "some-other-provider" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(0);
    expect(h.sink.stats.priceNotFound).toBe(1);
  });

  it("charges the wildcard rule when the card configures one", async () => {
    // Fail-closed means "no matching rule", not "no exact rule": the precedence
    // ladder exact → (provider,*) → (*,model) → (*,*) is the billing package's.
    const h = harness({
      priceBook: PriceBook.new([
        priceEntry(PRICED_PROVIDER, PRICED_MODEL, modelPriceUsd(0.15, 0.6)),
        priceEntry("*", "*", modelPriceUsd(1, 1)),
      ]),
    });
    h.sink.record(usageFixture({ providerModel: "anything-at-all" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.ledger.charges[0]?.credits).toBe(15n); // 15 tokens at $1/1M
    expect(h.sink.stats.priceNotFound).toBe(0);
  });

  it("never throws out of record(), whatever the sink is handed", () => {
    const h = harness();
    expect(() => h.sink.record(usageFixture({ providerModel: "unpriced" }))).not.toThrow();
    // A NaN settled cost is not "finite and >= 0", so `charge()` falls through
    // to the rate card rather than settling a NaN charge.
    const nan = harness({ settledCostUsd: () => Number.NaN });
    expect(() => nan.sink.record(usageFixture())).not.toThrow();
  });
});

describe("MeteringUsageSink — idempotency (#213)", () => {
  it("charges ONCE for a duplicate submission of the same request id", async () => {
    const h = harness();
    const usage = usageFixture();

    h.sink.record(usage);
    await h.scheduler.idle();
    expect(h.ledger.size).toBe(1);
    expect(h.outbox.size).toBe(0); // drained, so the second enqueue is fresh

    // The replay reaches the DURABLE guard, not an in-isolate short-circuit.
    h.sink.record(usage);
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect((await h.ledger.totals()).credits).toBe(FIXTURE_CREDITS);
    expect(h.sink.stats.duplicates).toBe(1);
    expect(h.sink.stats.recorded).toBe(1);
    // The report is not re-delivered either — Rust `if !recorded { return }`.
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.outbox.size).toBe(0);
  });

  it("collapses a replay that arrives before the first drain (outbox PK)", async () => {
    const h = harness();
    const usage = usageFixture();

    h.sink.record(usage);
    h.sink.record(usage);
    // Both enqueues happened synchronously, before any drain completed.
    expect(h.outbox.size).toBe(1);
    expect(h.sink.stats.outboxDuplicates).toBe(1);

    await h.scheduler.idle();
    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
  });

  it("charges twice for two DIFFERENT request ids", async () => {
    const h = harness();
    h.sink.record(usageFixture({ requestId: "fg-aaaaaaaaaaaaaaaa" }));
    h.sink.record(usageFixture({ requestId: "fg-bbbbbbbbbbbbbbbb" }));
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(2);
    expect((await h.ledger.totals()).credits).toBe(FIXTURE_CREDITS * 2n);
  });

  it("keys on the ledger entry id the billing package derives", async () => {
    const h = harness();
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    expect(h.ledger.charges[0]?.id).toBe(
      "ferrogate:provider-attempt:fg-000000000000002a:provider-attempt:0",
    );
  });

  it("dead-letters a same-id-different-money replay instead of absorbing it", async () => {
    const h = harness();
    h.sink.record(usageFixture());
    await h.scheduler.idle();

    // Same request id, different token counts ⇒ same key, different settlement.
    h.sink.record(usageFixture({ promptTokens: 999, completionTokens: 999, totalTokens: 1998 }));
    await h.scheduler.idle();

    expect(h.sink.stats.conflicts).toBe(1);
    expect(h.ledger.size).toBe(1);
    expect((await h.ledger.totals()).credits).toBe(FIXTURE_CREDITS);
    expect(h.outbox.deadLetters()).toHaveLength(1);
    expect(h.publisher.delivered).toHaveLength(1);
  });
});

describe("MeteringUsageSink — the outbox survives a downstream outage (#137/#143)", () => {
  it("keeps the charge queued and retries with the Rust backoff", async () => {
    const h = harness();
    h.publisher.fail();

    h.sink.record(usageFixture());
    await h.scheduler.idle();

    // The ledger write landed; only the REPORT failed, so the row stays queued.
    expect(h.ledger.size).toBe(1);
    expect(h.outbox.size).toBe(1);
    expect(h.outbox.get(h.ledger.charges[0]?.id ?? "")?.attempts).toBe(1);
    expect(h.outbox.get(h.ledger.charges[0]?.id ?? "")?.nextAttemptUnix).toBe(1_700_000_000 + 1);
    expect(h.sink.stats.deliveryFailures).toBe(1);
    expect(h.publisher.delivered).toHaveLength(0);
  });

  it("delivers on a later drain once the downstream recovers — nothing lost", async () => {
    const h = harness();
    h.publisher.fail();
    h.sink.record(usageFixture());
    await h.scheduler.idle();
    expect(h.outbox.size).toBe(1);

    h.publisher.recover();
    h.clock.advance(2);
    await h.sink.flush();

    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.publisher.delivered[0]?.credits).toBe(FIXTURE_CREDITS);
    expect(h.outbox.size).toBe(0);
    // The retry re-attempts the DELIVERY only: the ledger write already
    // committed on the first pass and the row carries that fact, so the second
    // pass never touches the ledger again.
    expect(h.ledger.size).toBe(1);
    expect(h.sink.stats.recorded).toBe(1);
    expect(h.sink.stats.duplicates).toBe(0);
  });

  it("dead-letters after MAX_BILLING_OUTBOX_ATTEMPTS rather than retrying forever", async () => {
    const h = harness();
    h.publisher.fail();
    h.sink.record(usageFixture());

    for (let attempt = 0; attempt < MAX_BILLING_OUTBOX_ATTEMPTS + 2; attempt += 1) {
      h.clock.advance(120); // past the 60s backoff cap
      await h.sink.flush();
    }

    expect(h.sink.stats.deadLettered).toBe(1);
    expect(h.outbox.deadLetters()).toHaveLength(1);
    expect(h.outbox.deadLetters()[0]?.attempts).toBe(MAX_BILLING_OUTBOX_ATTEMPTS);
    // It stops consuming sweeper capacity …
    expect(h.outbox.listDue(9_999_999_999, 100)).toHaveLength(0);
    // … but the money is still on the ledger and the charge still inspectable.
    expect(h.ledger.size).toBe(1);
    expect(h.outbox.deadLetters()[0]?.charge.credits).toBe(FIXTURE_CREDITS);
  });

  it("attempts a given row at most once per drain", async () => {
    const h = harness();
    h.publisher.fail();
    h.sink.record(usageFixture());

    await h.sink.flush();
    expect(h.sink.stats.deliveryFailures).toBe(1);

    // Same drain would otherwise spin: the backoff is 1s and the clock is read
    // per loop iteration.
    h.clock.advance(3_600);
    await h.sink.flush();
    expect(h.sink.stats.deliveryFailures).toBe(2);
  });
});

describe("MeteringUsageSink — post-response scheduling", () => {
  it("does not do I/O inside record(); the durable write happens after", async () => {
    const h = harness();
    h.sink.record(usageFixture());

    // record() returned with the charge captured but nothing written yet.
    expect(h.outbox.size).toBe(1);
    expect(h.ledger.size).toBe(0);
    expect(h.scheduler.pending).toBeGreaterThan(0);

    await h.scheduler.idle();
    expect(h.ledger.size).toBe(1);
  });

  it("routes scheduled work through the injected ExecutionContext", async () => {
    const scheduled: Promise<unknown>[] = [];
    const ledger = new InMemoryLedgerStore();
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      ledger,
      scheduler: {
        waitUntil: (work) => {
          scheduled.push(work);
        },
      },
    });

    sink.record(usageFixture());
    expect(scheduled).toHaveLength(1);
    await Promise.all(scheduled);
    expect(ledger.size).toBe(1);
  });

  it("swallows a scheduled rejection instead of failing the isolate", async () => {
    const exploding = {
      record: (): Promise<never> => Promise.reject(new Error("d1 is down")),
      get: (): Promise<undefined> => Promise.resolve(undefined),
      list: (): Promise<never[]> => Promise.resolve([]),
      totals: () => Promise.resolve({ entries: 0, credits: 0n, totalTokens: 0n, costUsd: 0 }),
    };
    const scheduler = new TrackingScheduler();
    const outbox = new InMemoryMeteringOutbox();
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      ledger: exploding,
      outbox,
      scheduler,
    });

    sink.record(usageFixture());
    await expect(scheduler.idle()).resolves.toBeUndefined();
    expect(scheduler.errors).toHaveLength(0);
    // The charge is NOT lost — it is still queued for the next drain.
    expect(outbox.size).toBe(1);
    expect(sink.stats.deliveryFailures).toBe(1);
  });
});
