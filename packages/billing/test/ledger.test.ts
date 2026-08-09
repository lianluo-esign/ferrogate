import { describe, expect, it } from "vitest";
import {
  BillingError,
  type BillingEvent,
  CostSource,
  InMemoryLedgerSink,
  PriceBook,
  charge,
  costDiverges,
  ledgerEntryId,
  ledgerEntryToWire,
  modelPriceUsd,
  parseBillingEvent,
  priceEntry,
} from "../src/index.js";
const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;

function event(request_id: string, provider: string, model: string): BillingEvent {
  return parseBillingEvent({
    request_id,
    trace_id: `trace-${request_id}`,
    provider_attempt_id: `${request_id}:provider-attempt:0`,
    provider_attempt_index: 0,
    tenant: { organization_id: "org", api_key_id: "key" },
    logical_model: "fast-chat",
    provider,
    provider_model: model,
    usage: { prompt_tokens: 1_000, completion_tokens: 2_000, total_tokens: 0 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1_800_000_000,
    metadata: {},
  });
}

function book(): PriceBook {
  return PriceBook.new([priceEntry("openai", "gpt-5.5", modelPriceUsd(5.0, 15.0))]);
}

describe("charge()", () => {
  it("prices usage + credits and derives the total (mirrors charge_prices_usage_and_credits)", () => {
    const entry = charge(book(), event("req-1", "openai", "gpt-5.5"));
    expect(entry.cost.input_cost).toBeCloseTo(0.005, 12);
    expect(entry.cost.output_cost).toBeCloseTo(0.03, 12);
    expect(entry.cost.total_cost).toBeCloseTo(0.035, 12);
    expect(entry.credits).toBeCloseTo(35_000, 3);
    expect(entry.usage.total_tokens).toBe(3_000);
    expect(entry.id).toBe("ferrogate:provider-attempt:req-1:provider-attempt:0");
    expect(entry.cost_source).toBe(CostSource.BillingPriceBook);
  });

  it("fails closed with price_not_found when no rule matches", () => {
    try {
      charge(book(), event("req-2", "anthropic", "claude"));
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("price_not_found");
    }
  });

  it("honors a gateway-settled cost over the price book (#135) and scales the breakdown", () => {
    const e = { ...event("req-5", "openai", "gpt-5.5"), cost_usd: 0.01 };
    const entry = charge(book(), e);
    expect(entry.cost_source).toBe(CostSource.GatewaySettled);
    expect(entry.cost.total_cost).toBeCloseTo(0.01, 12);
    expect(entry.cost.input_cost + entry.cost.output_cost).toBeCloseTo(0.01, 12);
    expect(entry.credits).toBeCloseTo(10_000, 3);
  });

  it("honors a settled cost even without a price-book entry", () => {
    const e = { ...event("req-6", "custom-vendor", "mystery-model"), cost_usd: 0.5 };
    const entry = charge(book(), e);
    expect(entry.cost_source).toBe(CostSource.GatewaySettled);
    expect(entry.cost.total_cost).toBeCloseTo(0.5, 12);
  });

  it("reconciles a missing completion split before pricing (#140)", () => {
    const e = event("req-7", "openai", "gpt-5.5");
    e.usage = { prompt_tokens: 1_000, completion_tokens: 0, total_tokens: 3_000 };
    const entry = charge(book(), e);
    expect(entry.usage.completion_tokens).toBe(2_000);
    expect(entry.cost.output_cost).toBeCloseTo(0.03, 12);
  });

  it("invokes onDivergence but never overrides the gateway figure (#152)", () => {
    let seen = 0;
    const e = { ...event("req-8", "openai", "gpt-5.5"), cost_usd: 1.0 };
    const entry = charge(book(), e, () => {
      seen += 1;
    });
    expect(seen).toBe(1);
    expect(entry.cost.total_cost).toBeCloseTo(1.0, 12);
  });

  it("mirrors wallet-debit fields verbatim, or leaves them undefined (#169)", () => {
    const withWallet = event("req-wallet-1", "openai", "gpt-5.5");
    withWallet.wallet_delta_credits = -35_000n;
    withWallet.wallet_balance_after_credits = 465_000n;
    const entry = charge(book(), withWallet);
    expect(entry.wallet_delta_credits).toBe(-35_000n);
    expect(entry.wallet_balance_after_credits).toBe(465_000n);

    const plain = charge(book(), event("req-wallet-2", "openai", "gpt-5.5"));
    expect(plain.wallet_delta_credits).toBeUndefined();
    expect(plain.wallet_balance_after_credits).toBeUndefined();
  });
});

/**
 * The audio rails, and the check that was NOT protecting them (issue #703).
 *
 * `charge()`'s >5% divergence warning is the one mechanism that catches a
 * mispriced settled cost, and it is armed only when `book.priceFor(...)` finds a
 * rule. Before this, no rate card in the tree named an audio model, so the two
 * audio price rails had never met an invoice and a transcription settled at ten
 * times its true cost would have been recorded in silence.
 *
 * Adding a card entry alone would have been WORSE than the gap: an audio event
 * carries no tokens, so a token-only estimate values it at $0 and
 * `costDiverges(settled > 0, 0)` fires on every correctly-priced row — a warning
 * that is always on is a warning nobody reads. So the quantity travels with the
 * event and the card prices it, and only then is the check armed.
 */
function audioEvent(request_id: string, quantities: Partial<BillingEvent>): BillingEvent {
  return {
    ...parseBillingEvent({
      request_id,
      provider_attempt_id: `${request_id}:provider-attempt:0`,
      provider_attempt_index: 0,
      tenant: { organization_id: "org" },
      logical_model: "edge-whisper",
      provider: "cf-ai",
      provider_model: "@cf/openai/whisper-large-v3-turbo",
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      usage_source: "provider_usage",
      status_code: 200,
      occurred_at_unix: 1_800_000_000,
      metadata: {},
    }),
    ...quantities,
  };
}

describe("the audio rails meet an invoice (#703)", () => {
  it("prices a transcription off the card when no settled cost is supplied", () => {
    // The `price_not_found` failure this replaces was not hypothetical: it is
    // what the gateway logged for every Workers AI transcription.
    const entry = charge(
      PriceBook.withDefaultRateCard(),
      audioEvent("req-audio-1", { audio_seconds: 600 }),
    );
    expect(entry.cost_source).toBe(CostSource.BillingPriceBook);
    expect(entry.cost.total_cost).toBeGreaterThan(0);
    // Billed on the INPUT side: the recording that was decoded is the input.
    expect(entry.cost.input_cost).toBeCloseTo(entry.cost.total_cost, 12);
    expect(entry.cost.output_cost).toBeCloseTo(0, 12);
  });

  it("does NOT warn when the settled audio cost agrees with the card", () => {
    // The half that makes the check usable. A detector that fires on every
    // correct row is the same as no detector, and it is the failure mode adding
    // a token-only card entry would have produced.
    const book = PriceBook.withDefaultRateCard();
    const seconds = 600;
    const priced = charge(book, audioEvent("req-audio-2", { audio_seconds: seconds }));
    let warned = 0;
    charge(
      book,
      audioEvent("req-audio-3", {
        audio_seconds: seconds,
        cost_usd: priced.cost.total_cost,
      }),
      () => {
        warned += 1;
      },
    );
    expect(warned).toBe(0);
  });

  it("WARNS on a mispriced audio row — the whole point of the entry", () => {
    const book = PriceBook.withDefaultRateCard();
    const seconds = 600;
    const priced = charge(book, audioEvent("req-audio-4", { audio_seconds: seconds }));
    let seen: { gateway_settled_cost_usd: number; price_book_estimate_usd: number } | undefined;
    charge(
      book,
      audioEvent("req-audio-5", {
        audio_seconds: seconds,
        // Ten times the true cost — the shape of a rate typo'd by one decimal.
        cost_usd: priced.cost.total_cost * 10,
      }),
      (info) => {
        seen = info;
      },
    );
    expect(seen).toBeDefined();
    expect(seen?.price_book_estimate_usd).toBeCloseTo(priced.cost.total_cost, 12);
    expect(seen?.gateway_settled_cost_usd).toBeCloseTo(priced.cost.total_cost * 10, 12);
  });

  it("prices SPEECH on characters, on the same seam", () => {
    const entry = charge(PriceBook.withDefaultRateCard(), {
      ...audioEvent("req-audio-6", { audio_characters: 100_000 }),
      provider_model: "@cf/myshell-ai/melotts",
      logical_model: "edge-tts",
    });
    expect(entry.cost.total_cost).toBeGreaterThan(0);
    expect(entry.cost.input_cost).toBeCloseTo(entry.cost.total_cost, 12);
  });

  it("still refuses a row whose model is absent from the card entirely", () => {
    // Fail CLOSED, unchanged. An unpriced model with no settled cost is
    // `price_not_found`, never a free transcription.
    //
    // This case reaches the PRE-EXISTING no-entry refusal in `charge()` — the
    // one that predates #703 — because `book()` names only `openai/gpt-5.5`.
    // It says nothing about the new audio guard; the case below is the one
    // that holds that. Asserting the CODE rather than just `BillingError`
    // keeps the two distinguishable: they are different sentences from the
    // same class, and only the code tells you which refusal fired.
    try {
      charge(book(), {
        ...audioEvent("req-audio-7", { audio_seconds: 600 }),
        provider: "some-vendor",
        provider_model: "some-asr",
      });
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("price_not_found");
      expect((error as BillingError).message).toContain("no rate-card price for provider");
    }
  });

  it("refuses a row the card MATCHES but states no rate for the row's unit", () => {
    // THE case for `audioQuantityUnpriced`, and the one the shape above cannot
    // reach. `book()` prices `openai/gpt-5.5` — tokens only, no
    // `audio_second_price_per_1m` — so `book.priceFor(...)` HITS and the
    // no-entry refusal is passed over. What is left is a matched card that
    // cannot value the unit this row is measured in.
    //
    // Without the guard the token arithmetic answers $0 for a 600-second
    // recording and the row is written as a free transcription — the
    // free-inference bug (#129) one unit over. Disarming
    // `audioQuantityUnpriced` (returning false whenever audio is present) turns
    // this case RED and nothing else in the package with it, which is what
    // makes it the guard's only hold.
    try {
      charge(book(), {
        ...audioEvent("req-audio-7b", { audio_seconds: 600 }),
        provider: "openai",
        provider_model: "gpt-5.5",
      });
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("price_not_found");
      // ...and it is the UNIT refusal, not the no-entry one it is easy to
      // mistake it for. The card entry exists; it just cannot price seconds.
      expect((error as BillingError).message).toContain("states no audio rate for this row");
    }
  });

  it("refuses a MATCHED card that prices seconds but not the characters it is handed", () => {
    // The character half of the same guard, and it is not a copy: a card may
    // state one audio rate and not the other, and a synthesis row measured in
    // characters must not be valued at $0 by a transcription rate.
    const secondsOnly = PriceBook.new([
      priceEntry("openai", "gpt-5.5", {
        ...modelPriceUsd(5.0, 15.0),
        audio_second_price_per_1m: 6_000.0,
      }),
    ]);
    try {
      charge(secondsOnly, {
        ...audioEvent("req-audio-7c", { audio_characters: 100_000 }),
        provider: "openai",
        provider_model: "gpt-5.5",
      });
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("price_not_found");
      expect((error as BillingError).message).toContain("states no audio rate for this row");
    }
    // ...and the SAME card prices a seconds row, so the refusal above is about
    // the unit and not about the card being rejected wholesale.
    const priced = charge(secondsOnly, {
      ...audioEvent("req-audio-7d", { audio_seconds: 600 }),
      provider: "openai",
      provider_model: "gpt-5.5",
    });
    expect(priced.cost_source).toBe(CostSource.BillingPriceBook);
    expect(priced.cost.total_cost).toBeGreaterThan(0);
  });

  it("carries the audio quantities across the wire form", () => {
    // The rail is only real if the quantity survives serialization: the metering
    // event is JSON on a Queue before it is ever charged.
    const parsed = parseBillingEvent({
      request_id: "req-audio-8",
      provider_attempt_id: "req-audio-8:provider-attempt:0",
      provider_attempt_index: 0,
      tenant: { organization_id: "org" },
      logical_model: "edge-whisper",
      provider: "cf-ai",
      provider_model: "@cf/openai/whisper-large-v3-turbo",
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      usage_source: "provider_usage",
      status_code: 200,
      metadata: {},
      audio_seconds: 12.5,
      audio_characters: 42,
    });
    expect(parsed.audio_seconds).toBe(12.5);
    expect(parsed.audio_characters).toBe(42);
  });
});

describe("ledgerEntryId idempotency (#213)", () => {
  it("ignores mutable trace/request context for a provider-attempt event", () => {
    const original = event("req-original", "openai", "gpt-5.5");
    const replay = { ...original, request_id: "req-replayed", trace_id: undefined };
    expect(ledgerEntryId(original)).toBe(ledgerEntryId(replay));
    expect(ledgerEntryId(replay)).toBe(
      "ferrogate:provider-attempt:req-original:provider-attempt:0",
    );
  });

  it("preserves the trace/request key for a legacy event", () => {
    const legacy = event("req-legacy", "openai", "gpt-5.5");
    legacy.provider_attempt = { provider_attempt_id: "", provider_attempt_index: 0 };
    expect(ledgerEntryId(legacy)).toBe("ferrogate:trace-req-legacy:req-legacy");
  });
});

describe("costDiverges (#152)", () => {
  it("flags divergence beyond the relative tolerance", () => {
    expect(costDiverges(1.0, 0.035)).toBe(true);
    expect(costDiverges(0.035, 0.035)).toBe(false);
    expect(costDiverges(0.036, 0.035)).toBe(false);
    expect(costDiverges(0.037, 0.035)).toBe(true);
  });
  it("ignores near-zero noise under the absolute floor", () => {
    expect(costDiverges(0.000_001, 0.000_002)).toBe(false);
  });
});

describe("InMemoryLedgerSink idempotency", () => {
  it("settles distinct attempts and replays byte-equal entries as no-ops", () => {
    const primary = event("req-multi", "openai", "gpt-5.5");
    primary.provider_attempt = {
      provider_attempt_id: "req-multi:provider-attempt:0",
      provider_attempt_index: 0,
    };
    primary.usage = { prompt_tokens: 1_000, completion_tokens: 500, total_tokens: 1_500 };
    const fallback = event("req-multi", "openai", "gpt-5.5");
    fallback.provider_attempt = {
      provider_attempt_id: "req-multi:provider-attempt:1",
      provider_attempt_index: 1,
    };
    fallback.usage = { prompt_tokens: 2_000, completion_tokens: 1_000, total_tokens: 3_000 };

    const pe = charge(book(), primary);
    const fe = charge(book(), fallback);
    expect(pe.id).not.toBe(fe.id);

    const sink = new InMemoryLedgerSink();
    expect(sink.record(pe)).toBe(true);
    expect(sink.record(fe)).toBe(true);
    expect(sink.record(pe)).toBe(false);
    expect(sink.record(fe)).toBe(false);

    const totals = sink.totals();
    expect(totals.entries).toBe(2);
    expect(totals.total_tokens).toBe(4_500);
    expect(totals.total_cost_usd).toBeCloseTo(0.0375, 12);
  });

  it("fails closed on a same-id replay carrying different settlement data", () => {
    const original = charge(book(), event("req-collision", "openai", "gpt-5.5"));
    const sink = new InMemoryLedgerSink();
    expect(sink.record(original)).toBe(true);

    const mutated = { ...original, tenant: { ...original.tenant, organization_id: "other" } };
    try {
      sink.record(mutated);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("billing_idempotency_conflict");
    }
    expect(sink.length).toBe(1);
    expect(nn(sink.get(original.id)).tenant.organization_id).toBe("org");
  });

  it("lists (tenant-filtered) and gets by id", () => {
    const sink = new InMemoryLedgerSink();
    const entry = charge(book(), event("req-4", "openai", "gpt-5.5"));
    sink.record(entry);
    expect(sink.list({}, 0, 10)).toHaveLength(1);
    expect(sink.list({ organization_id: "org" }, 0, 10)).toHaveLength(1);
    expect(sink.list({ organization_id: "nope" }, 0, 10)).toHaveLength(0);
    expect(nn(sink.get(entry.id)).request_id).toBe("req-4");
    expect(sink.get("missing")).toBeUndefined();
  });
});

/**
 * MONEY NO-DRIFT GATE — the wallet fields are `bigint` end to end precisely so
 * no arithmetic on integer credits can drift, and JSON is the one hop where
 * that property could be dropped. It WAS being dropped: `ledgerEntryToWire`
 * rendered both fields with a bare `Number(...)`, which rounds past 2^53 and
 * returns an ordinary-looking number.
 *
 * Every assertion below fails if the refusal is removed and the bare `Number()`
 * comes back. The last one is the reason this is a correctness gate and not a
 * display nicety: two DIFFERENT balances round to the SAME double, and
 * `sameProviderAttemptSettlement` — the idempotency arbiter — widens number to
 * bigint, so the divergent replay would be accepted as a no-op instead of
 * raising `billing_idempotency_conflict`.
 */
describe("wallet credits survive the JSON-number hop, or the render refuses", () => {
  function walletEntry(id: string, delta: bigint, balance: bigint) {
    const e = event(id, "openai", "gpt-5.5");
    e.wallet_delta_credits = delta;
    e.wallet_balance_after_credits = balance;
    return charge(book(), e);
  }

  it("renders exactly-representable credits as JSON numbers (Rust serde shape)", () => {
    const wire = ledgerEntryToWire(walletEntry("req-w-ok", -35_000n, 465_000n));
    expect(wire.wallet_delta_credits).toBe(-35_000);
    expect(wire.wallet_balance_after_credits).toBe(465_000);
    // The boundary itself is still exact and must NOT be refused.
    const edge = ledgerEntryToWire(
      walletEntry("req-w-edge", BigInt(Number.MIN_SAFE_INTEGER), BigInt(Number.MAX_SAFE_INTEGER)),
    );
    expect(edge.wallet_balance_after_credits).toBe(Number.MAX_SAFE_INTEGER);
    expect(edge.wallet_delta_credits).toBe(Number.MIN_SAFE_INTEGER);
  });

  it("REFUSES a balance one unit past the exact range instead of rounding it", () => {
    const overflowing = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    try {
      ledgerEntryToWire(walletEntry("req-w-big", -1n, overflowing));
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(BillingError);
      expect((error as BillingError).code).toBe("wallet_credits_unrepresentable");
      expect((error as BillingError).message).toContain("wallet_balance_after_credits");
    }
    // …and the delta field is guarded on its own, not only the balance.
    try {
      ledgerEntryToWire(walletEntry("req-w-big2", -(BigInt(Number.MAX_SAFE_INTEGER) + 1n), 1n));
      throw new Error("expected throw");
    } catch (error) {
      expect((error as BillingError).code).toBe("wallet_credits_unrepresentable");
      expect((error as BillingError).message).toContain("wallet_delta_credits");
    }
  });

  it("the refusal is what stops a divergent replay from passing as a no-op", () => {
    const a = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    const b = BigInt(Number.MAX_SAFE_INTEGER) + 2n;
    // Two DIFFERENT i64 balances…
    expect(a).not.toBe(b);
    // …collapse onto ONE double, which is what the removed `Number()` produced.
    expect(Number(a)).toBe(Number(b));
    // So a round-trip through the wire would make them compare EQUAL.
    expect(BigInt(Number(a)) === BigInt(Number(b))).toBe(true);
    // The render therefore refuses both rather than emitting the collision.
    for (const balance of [a, b]) {
      expect(() => ledgerEntryToWire(walletEntry("req-w-collide", -1n, balance))).toThrow(
        /wallet_credits_unrepresentable|losing/,
      );
    }
  });

  it("an entry with no wallet fields renders without them and never throws", () => {
    const wire = ledgerEntryToWire(charge(book(), event("req-w-none", "openai", "gpt-5.5")));
    expect(wire.wallet_delta_credits).toBeUndefined();
    expect(wire.wallet_balance_after_credits).toBeUndefined();
  });
});
