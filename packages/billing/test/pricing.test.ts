import { describe, expect, it } from "vitest";
import {
  DEFAULT_CREDITS_PER_USD,
  DEFAULT_EGRESS_PRICE_PER_GB,
  PriceBook,
  egressCostUsd,
  modelPriceUsd,
  priceEntry,
} from "../src/index.js";

function book(): PriceBook {
  return PriceBook.new([
    priceEntry("openai", "gpt-5.5", modelPriceUsd(5.0, 15.0)),
    priceEntry("openai", "*", modelPriceUsd(1.0, 2.0)),
    priceEntry("*", "*", modelPriceUsd(10.0, 10.0)),
  ]);
}

describe("PriceBook.priceFor wildcard precedence", () => {
  it("exact match wins over wildcards", () => {
    expect(book().priceFor("openai", "gpt-5.5")).toEqual(modelPriceUsd(5.0, 15.0));
  });
  it("provider wildcard matches an unknown model", () => {
    expect(book().priceFor("openai", "gpt-4o")).toEqual(modelPriceUsd(1.0, 2.0));
  });
  it("global wildcard is the last resort", () => {
    expect(book().priceFor("mystery", "model-x")).toEqual(modelPriceUsd(10.0, 10.0));
  });
  it("returns undefined (fail-closed) when nothing matches", () => {
    const b = PriceBook.new([priceEntry("openai", "gpt-5.5", modelPriceUsd(5, 15))]);
    expect(b.priceFor("anthropic", "claude")).toBeUndefined();
  });
});

describe("credits + egress", () => {
  it("credits scale with the configured rate", () => {
    expect(PriceBook.default().withCreditsPerUsd(1_000).creditsForUsd(0.5)).toBeCloseTo(500, 9);
  });

  it("egress is undefined when unpriced and $/GB when priced (#262)", () => {
    expect(PriceBook.default().egressCostUsd(1_000_000_000)).toBeUndefined();
    const b = PriceBook.default().withEgressPricePerGb(0.09);
    expect(b.egressCostUsd(1_000_000_000)!).toBeCloseTo(0.09, 9);
    const half = b.egressCostUsd(500_000_000)!;
    expect(half).toBeCloseTo(0.045, 9);
    expect(half).toBeCloseTo(egressCostUsd(0.09, 500_000_000), 12);
  });

  it("default rate card seeds an egress rate (#262)", () => {
    const b = PriceBook.withDefaultRateCard();
    expect(b.egress_price_per_gb).toBe(DEFAULT_EGRESS_PRICE_PER_GB);
    expect(b.egressCostUsd(2_000_000_000)!).toBeGreaterThan(0);
    // CHANGED BY #667. This was `toEqual(modelPriceUsd(0.15, 0.6))` — a
    // whole-object equality that also asserted the entry carries NO other
    // fields, which is exactly the assertion that had to move once the default
    // card started stating each family's published cache-read multiplier. The
    // two base rates, which are what this egress test is actually about, are
    // asserted unchanged; the cache rates have their own golden test in
    // `./cached-tokens.test.ts`.
    const mini = b.priceFor("token4ai", "gpt-4o-mini");
    expect(mini?.input_price_per_1m).toBe(0.15);
    expect(mini?.output_price_per_1m).toBe(0.6);
    expect(mini?.currency).toBe(modelPriceUsd(0.15, 0.6).currency);
  });
});

describe("PriceBook.fromJson", () => {
  it("parses a bare array and a full object", () => {
    const fromArray = PriceBook.fromJson(
      '[{"provider":"openai","model":"gpt-5.5","price":{"input_price_per_1m":5.0,"output_price_per_1m":15.0,"currency":"USD"}}]',
    );
    expect(fromArray.length).toBe(1);
    expect(fromArray.credits_per_usd).toBe(DEFAULT_CREDITS_PER_USD);

    const fromObject = PriceBook.fromJson(
      '{"credits_per_usd":1000.0,"entries":[{"provider":"*","model":"*","price":{"input_price_per_1m":1.0,"output_price_per_1m":1.0,"currency":"USD"}}]}',
    );
    expect(fromObject.credits_per_usd).toBe(1000);
    expect(fromObject.length).toBe(1);
  });

  it("round-trips the egress rate and defaults legacy cards to unpriced (#262)", () => {
    const json = JSON.stringify(PriceBook.withDefaultRateCard());
    expect(PriceBook.fromJson(json).egress_price_per_gb).toBe(DEFAULT_EGRESS_PRICE_PER_GB);
    const legacy =
      '[{"provider":"*","model":"*","price":{"input_price_per_1m":1.0,"output_price_per_1m":1.0,"currency":"USD"}}]';
    expect(PriceBook.fromJson(legacy).egress_price_per_gb).toBeUndefined();
  });
});
