import { describe, expect, it } from "vitest";
import {
  charge,
  costDiverges,
  CostSource,
  InMemoryLedgerSink,
  ledgerEntryId,
  modelPriceUsd,
  parseBillingEvent,
  priceEntry,
  PriceBook,
  BillingError,
  type BillingEvent,
} from "../src/index.js";

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
    const entry = charge(book(), e, () => (seen += 1));
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
    primary.provider_attempt = { provider_attempt_id: "req-multi:provider-attempt:0", provider_attempt_index: 0 };
    primary.usage = { prompt_tokens: 1_000, completion_tokens: 500, total_tokens: 1_500 };
    const fallback = event("req-multi", "openai", "gpt-5.5");
    fallback.provider_attempt = { provider_attempt_id: "req-multi:provider-attempt:1", provider_attempt_index: 1 };
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
    expect(sink.get(original.id)!.tenant.organization_id).toBe("org");
  });

  it("lists (tenant-filtered) and gets by id", () => {
    const sink = new InMemoryLedgerSink();
    const entry = charge(book(), event("req-4", "openai", "gpt-5.5"));
    sink.record(entry);
    expect(sink.list({}, 0, 10)).toHaveLength(1);
    expect(sink.list({ organization_id: "org" }, 0, 10)).toHaveLength(1);
    expect(sink.list({ organization_id: "nope" }, 0, 10)).toHaveLength(0);
    expect(sink.get(entry.id)!.request_id).toBe("req-4");
    expect(sink.get("missing")).toBeUndefined();
  });
});
