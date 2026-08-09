/**
 * Cached-read / cache-write / reasoning token PRICING (issue #667).
 *
 * These are golden-value tests: every expectation is a literal USD figure
 * arithmetically derived in the comment above it, never a value read back out
 * of the code under test. That matters more here than almost anywhere else in
 * the tree — a cached-token discount that is silently wrong still produces an
 * invoice that looks entirely plausible, so a test that computed the expected
 * value the same way the implementation does would confirm nothing.
 *
 * The three quantities and the rule each follows:
 *
 *  - `cached_input_tokens` — a SUBSET of `prompt_tokens` served from a prompt
 *    cache, billed at `cached_input_price_per_1m`.
 *  - `cache_write_tokens`  — a SUBSET of `prompt_tokens` written INTO the cache,
 *    billed at `cache_write_price_per_1m` (a premium, not a discount).
 *  - `reasoning_tokens`    — a SUBSET of `completion_tokens`, billed at
 *    `reasoning_price_per_1m`.
 *
 * Subset, not additive, is the load-bearing normalization: every provider family
 * is converted to it at capture time (see
 * `apps/gateway/src/inference/usage.ts`), so this package needs exactly one
 * pricing rule rather than one per vendor.
 *
 * Every new rate is OPTIONAL and falls back to the ordinary input/output rate,
 * so a rate card written before this issue keeps producing the numbers it
 * produced before — pinned below, because "backward compatible" is the kind of
 * claim that rots.
 */
import { describe, expect, it } from "vitest";
import {
  type ModelPrice,
  PriceBook,
  type TokenUsage,
  estimateCost,
  modelPriceUsd,
  reconcileSplit,
} from "../src/index.js";

/** A `TokenUsage` with the three new counters defaulted to zero. */
function usage(overrides: Partial<TokenUsage> = {}): TokenUsage {
  return {
    prompt_tokens: 0,
    completion_tokens: 0,
    total_tokens: 0,
    cached_input_tokens: 0,
    cache_write_tokens: 0,
    reasoning_tokens: 0,
    ...overrides,
  };
}

describe("estimateCost — cached input tokens", () => {
  it("bills the cached subset at the cached rate and only the remainder at full input", () => {
    // $3.00/1M fresh input, $0.30/1M cache read (Anthropic's published 0.1x),
    // $15.00/1M output.
    const price: ModelPrice = {
      input_price_per_1m: 3.0,
      output_price_per_1m: 15.0,
      cached_input_price_per_1m: 0.3,
      currency: "USD",
    };
    // 26 000 prompt of which 20 000 are cache reads; 500 completion.
    //   fresh  =  6 000 / 1e6 * 3.00  = 0.018
    //   cached = 20 000 / 1e6 * 0.30  = 0.006
    //   input                          = 0.024
    //   output =    500 / 1e6 * 15.00 = 0.0075
    const cost = estimateCost(
      price,
      usage({
        prompt_tokens: 26_000,
        completion_tokens: 500,
        total_tokens: 26_500,
        cached_input_tokens: 20_000,
      }),
    );
    expect(cost.input_cost).toBeCloseTo(0.024, 12);
    expect(cost.output_cost).toBeCloseTo(0.0075, 12);
    expect(cost.total_cost).toBeCloseTo(0.0315, 12);
  });

  it("bills cache WRITES at their own premium rate, disjoint from cache reads", () => {
    // Cache creation carries a premium (Anthropic's published 1.25x), so it is
    // NOT interchangeable with a cache read and must not be folded into it.
    const price: ModelPrice = {
      input_price_per_1m: 3.0,
      output_price_per_1m: 15.0,
      cached_input_price_per_1m: 0.3,
      cache_write_price_per_1m: 3.75,
      currency: "USD",
    };
    //   fresh  =  1 000 / 1e6 * 3.00 = 0.003
    //   cached = 20 000 / 1e6 * 0.30 = 0.006
    //   write  =  5 000 / 1e6 * 3.75 = 0.01875
    //   input                         = 0.02775
    //   output =    500 / 1e6 * 15.0 = 0.0075
    const cost = estimateCost(
      price,
      usage({
        prompt_tokens: 26_000,
        completion_tokens: 500,
        total_tokens: 26_500,
        cached_input_tokens: 20_000,
        cache_write_tokens: 5_000,
      }),
    );
    expect(cost.input_cost).toBeCloseTo(0.02775, 12);
    expect(cost.total_cost).toBeCloseTo(0.03525, 12);
  });

  it("falls back to the full input rate when the card states no cached rate", () => {
    // The BACKWARD-COMPATIBILITY rule: an existing rate card must keep working,
    // not start throwing and not start discounting tokens nobody priced.
    const price = modelPriceUsd(3.0, 15.0);
    //   26 000 / 1e6 * 3.00 = 0.078   (cached tokens priced as ordinary input)
    const cost = estimateCost(
      price,
      usage({
        prompt_tokens: 26_000,
        completion_tokens: 0,
        total_tokens: 26_000,
        cached_input_tokens: 20_000,
        cache_write_tokens: 5_000,
      }),
    );
    expect(cost.input_cost).toBeCloseTo(0.078, 12);
  });
});

describe("estimateCost — reasoning tokens", () => {
  it("bills reasoning tokens at the output rate by default", () => {
    // Reasoning tokens are a SUBSET of completion tokens, so with no distinct
    // rate the total must be exactly what the old arithmetic produced.
    const price = modelPriceUsd(2.5, 10.0);
    //   2 000 / 1e6 * 10.0 = 0.02
    const cost = estimateCost(
      price,
      usage({
        prompt_tokens: 0,
        completion_tokens: 2_000,
        total_tokens: 2_000,
        reasoning_tokens: 1_500,
      }),
    );
    expect(cost.output_cost).toBeCloseTo(0.02, 12);
  });

  it("bills reasoning tokens at their own rate when the card states one", () => {
    const price: ModelPrice = {
      input_price_per_1m: 2.5,
      output_price_per_1m: 10.0,
      reasoning_price_per_1m: 20.0,
      currency: "USD",
    };
    //   visible  =   500 / 1e6 * 10.0 = 0.005
    //   reasoning= 1 500 / 1e6 * 20.0 = 0.030
    const cost = estimateCost(
      price,
      usage({
        prompt_tokens: 0,
        completion_tokens: 2_000,
        total_tokens: 2_000,
        reasoning_tokens: 1_500,
      }),
    );
    expect(cost.output_cost).toBeCloseTo(0.035, 12);
  });
});

describe("estimateCost — clamping a provider that contradicts itself", () => {
  it("never bills more cached tokens than there were prompt tokens", () => {
    // A cached count larger than the prompt count is impossible under the
    // subset normalization, so it can only be a provider/adapter bug. Priced
    // naively it would produce a NEGATIVE fresh-input component — a credit to
    // the customer conjured out of a malformed usage frame.
    const price: ModelPrice = {
      input_price_per_1m: 3.0,
      output_price_per_1m: 15.0,
      cached_input_price_per_1m: 0.3,
      currency: "USD",
    };
    //   the whole 100 prompt tokens bill as cache reads: 100/1e6 * 0.30 = 3e-5
    const cost = estimateCost(
      price,
      usage({ prompt_tokens: 100, total_tokens: 100, cached_input_tokens: 10_000 }),
    );
    expect(cost.input_cost).toBeCloseTo(3e-5, 15);
    expect(cost.input_cost).toBeGreaterThanOrEqual(0);
  });

  it("never bills more reasoning tokens than there were completion tokens", () => {
    const price: ModelPrice = {
      input_price_per_1m: 2.5,
      output_price_per_1m: 10.0,
      reasoning_price_per_1m: 20.0,
      currency: "USD",
    };
    //   the whole 100 completion tokens bill as reasoning: 100/1e6 * 20 = 2e-3
    const cost = estimateCost(
      price,
      usage({ completion_tokens: 100, total_tokens: 100, reasoning_tokens: 10_000 }),
    );
    expect(cost.output_cost).toBeCloseTo(0.002, 12);
  });
});

describe("reconcileSplit carries the new counters through untouched", () => {
  it("repairs the prompt/completion split without disturbing the subsets", () => {
    const out = reconcileSplit(
      usage({
        prompt_tokens: 26_000,
        completion_tokens: 0,
        total_tokens: 26_500,
        cached_input_tokens: 20_000,
        cache_write_tokens: 5_000,
        reasoning_tokens: 0,
      }),
    );
    expect(out.completion_tokens).toBe(500);
    expect(out.cached_input_tokens).toBe(20_000);
    expect(out.cache_write_tokens).toBe(5_000);
  });
});

describe("rate-card backward compatibility", () => {
  it("parses a pre-#667 rate card that names no cached rates", () => {
    const book = PriceBook.fromJson(
      JSON.stringify({
        entries: [
          {
            provider: "*",
            model: "legacy-model",
            price: {
              input_price_per_1m: 1.0,
              output_price_per_1m: 2.0,
              currency: "USD",
            },
          },
        ],
        credits_per_usd: 1_000_000,
      }),
    );
    const price = book.priceFor("anything", "legacy-model");
    expect(price).toBeDefined();
    expect(price?.cached_input_price_per_1m).toBeUndefined();
    // And it still prices exactly as it did: 1000/1e6*1 + 100/1e6*2 = 0.0012
    expect(
      estimateCost(price as ModelPrice, {
        prompt_tokens: 1_000,
        completion_tokens: 100,
        total_tokens: 1_100,
      }).total_cost,
    ).toBeCloseTo(0.0012, 12);
  });

  it("round-trips the cached rates through the rate-card JSON form", () => {
    const book = PriceBook.fromJson(
      JSON.stringify({
        entries: [
          {
            provider: "anthropic",
            model: "claude-sonnet-4",
            price: {
              input_price_per_1m: 3.0,
              output_price_per_1m: 15.0,
              cached_input_price_per_1m: 0.3,
              cache_write_price_per_1m: 3.75,
              reasoning_price_per_1m: 15.0,
              currency: "USD",
            },
          },
        ],
      }),
    );
    const price = book.priceFor("anthropic", "claude-sonnet-4");
    expect(price?.cached_input_price_per_1m).toBe(0.3);
    expect(price?.cache_write_price_per_1m).toBe(3.75);
    expect(price?.reasoning_price_per_1m).toBe(15.0);
  });

  it("gives the default card's Anthropic entries the published cache multipliers", () => {
    // Anthropic prices cache reads at 0.1x base input and 5-minute cache writes
    // at 1.25x, independently of the model — so the default card can carry them
    // as a ratio of the base rate it already states, rather than as a second
    // invented number.
    const book = PriceBook.withDefaultRateCard();
    const sonnet = book.priceFor("*", "claude-sonnet-4");
    expect(sonnet?.input_price_per_1m).toBe(3.0);
    expect(sonnet?.cached_input_price_per_1m).toBeCloseTo(0.3, 12);
    expect(sonnet?.cache_write_price_per_1m).toBeCloseTo(3.75, 12);
  });
});
