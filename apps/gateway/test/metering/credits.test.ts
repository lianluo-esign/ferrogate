/**
 * The integer-credit domain.
 *
 * `docs/legacy/inventory-data-billing.md` §2.5 makes `bigint` credits a
 * DIRECTIVE, not a preference, so these tests hold the two places a `number`
 * would silently lose money: the USD→credits multiply, and the running total.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_CREDITS_PER_USD,
  creditsToUsd,
  sumCredits,
  usdToCredits,
  walletDeltaCredits,
} from "../../src/metering/index.js";

describe("usdToCredits", () => {
  it("uses the Rust granularity: 1 USD == 1_000_000 credits", () => {
    expect(DEFAULT_CREDITS_PER_USD).toBe(1_000_000);
    expect(usdToCredits(1)).toBe(1_000_000n);
    expect(usdToCredits(0.000_001)).toBe(1n);
    expect(usdToCredits(0)).toBe(0n);
  });

  it("reproduces the Rust ledger fixture (charge_prices_usage_and_credits)", () => {
    // `ledger_test.rs:53` — $0.035 settled ⇒ 35_000 credits at the default rate.
    expect(usdToCredits(0.035)).toBe(35_000n);
  });

  it("honours a rate card's configured credits_per_usd", () => {
    // `pricing_test.rs:48` — with_credits_per_usd(1_000) ⇒ 0.5 USD == 500.
    expect(usdToCredits(0.5, 1_000)).toBe(500n);
  });

  it("is EXACT where the f64 multiply Rust uses drifts", () => {
    // `debit_wallet_for_settled_cost` computes `(cost_usd * 1e6).round()`, and
    // that product is rounded to 53 bits BEFORE `.round()` sees it. For this
    // cost the exact value is …659.5, which rounds up; the f64 product is
    // …659.4999999999999, which rounds down. One credit, on one request.
    const cost = 67_950.373_659_5;
    expect(Math.round(cost * 1_000_000)).toBe(67_950_373_659);
    expect(usdToCredits(cost)).toBe(67_950_373_660n);
  });

  it("rounds half AWAY from zero, matching Rust f64::round and not Math.round", () => {
    expect(usdToCredits(0.000_000_5)).toBe(1n);
    // Math.round(-0.5) is -0 in JS (half rounds toward +Infinity); Rust's
    // f64::round gives -1. A refund/credit-back would be under-applied.
    expect(Math.round(-0.000_000_5 * 1_000_000)).toBe(-0);
    expect(usdToCredits(-0.000_000_5)).toBe(-1n);
  });

  it("refuses a non-finite cost instead of degrading to a zero charge", () => {
    expect(() => usdToCredits(Number.NaN)).toThrow(RangeError);
    expect(() => usdToCredits(Number.POSITIVE_INFINITY)).toThrow(RangeError);
  });

  it("survives exponential-notation doubles (a tiny per-token cost)", () => {
    expect((1e-7).toString()).toBe("1e-7");
    expect(usdToCredits(1e-7)).toBe(0n);
    expect(usdToCredits(1.5e-6)).toBe(2n); // half away from zero
    expect(usdToCredits(1e21)).toBe(10n ** 27n);
  });
});

describe("sumCredits", () => {
  it("accumulates exactly past 2^53, where a number total stops counting", () => {
    const first = 9_007_199_254_740_993n; // 2^53 + 1
    const second = 1n;

    // The number path is the bug being prevented, shown rather than asserted about.
    expect(Number(first) + Number(second)).toBe(9_007_199_254_740_992);
    expect(sumCredits([first, second])).toBe(9_007_199_254_740_994n);
  });

  it("is zero for an empty run", () => {
    expect(sumCredits([])).toBe(0n);
  });
});

describe("creditsToUsd", () => {
  it("inverts the default granularity for display", () => {
    expect(creditsToUsd(35_000n)).toBeCloseTo(0.035, 12);
    expect(creditsToUsd(500n, 1_000)).toBeCloseTo(0.5, 12);
  });
});

describe("walletDeltaCredits", () => {
  it("is a NEGATIVE debit for a settled cost", () => {
    expect(walletDeltaCredits(0.035)).toBe(-35_000n);
  });

  it("distinguishes 'no wallet movement' from 'debited zero'", () => {
    // `debit_wallet_for_settled_cost`'s two early returns (`ledger_test.rs:203`).
    expect(walletDeltaCredits(0)).toBeUndefined();
    expect(walletDeltaCredits(-1)).toBeUndefined();
    expect(walletDeltaCredits(1e-9)).toBeUndefined(); // rounds to 0 credits
  });
});
