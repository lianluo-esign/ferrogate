/**
 * `src/credits.ts` — the cents↔credits unit boundary.
 *
 * Every assertion here is about a value a `number` cannot carry, because that
 * is the only thing this module exists to get right. A test that only exercised
 * `500 cents → 5_000_000 credits` would pass against a plain `cents * 10_000`
 * and prove nothing.
 */
import { describe, expect, test } from "vitest";
import {
  CREDITS_PER_CENT,
  CREDITS_PER_USD,
  bindCredits,
  centsToCredits,
  creditsFromText,
  creditsToCents,
} from "../src/credits.js";
import { MemoryWalletStore } from "../src/wallet.js";

describe("the unit constants", () => {
  test("1 USD is 1e6 credits and 1 cent is 1e4 credits", () => {
    expect(CREDITS_PER_USD).toBe(1_000_000n);
    expect(CREDITS_PER_CENT).toBe(10_000n);
    // Exactness of the cent conversion depends on this divisibility. If a
    // future rate card changed `credits_per_usd` to something not divisible by
    // 100, `centsToCredits` would start rounding and nothing else would notice.
    expect(CREDITS_PER_USD % 100n).toBe(0n);
  });
});

describe("centsToCredits", () => {
  test("is exact where a `number` multiply is not", () => {
    const cents = 100_000_000_000_001;
    // The true product; the nearest double is 1_000_000_000_000_009_984.
    expect(centsToCredits(cents)).toBe(1_000_000_000_000_010_000n);
    expect(centsToCredits(cents)).not.toBe(BigInt(cents * 10_000));
  });

  test("carries the sign through a debit", () => {
    expect(centsToCredits(-250)).toBe(-2_500_000n);
  });

  test("refuses a fractional cent rather than rounding it into money", () => {
    expect(() => centsToCredits(1.5)).toThrow(/exact integer/);
  });

  test("refuses a value that has ALREADY lost digits to the double it arrived in", () => {
    // 2^53 + 1 is not representable; the caller's `1` is already gone.
    expect(() => centsToCredits(Number.MAX_SAFE_INTEGER + 2)).toThrow(/safe-integer/);
    expect(() => centsToCredits(Number.POSITIVE_INFINITY)).toThrow(/exact integer/);
  });
});

describe("creditsToCents — display only, and it never overstates", () => {
  test("floors a positive remainder", () => {
    // $0.019999 — the customer does NOT have two cents.
    expect(creditsToCents(19_999n)).toBe(1n);
  });

  test("floors a NEGATIVE remainder toward more debt, not less", () => {
    // Truncation toward zero would report -1, i.e. less owed than is owed.
    expect(creditsToCents(-19_999n)).toBe(-2n);
  });

  test("round-trips an exact cent amount", () => {
    expect(creditsToCents(centsToCredits(1234))).toBe(1234n);
  });
});

describe("bindCredits — the D1 parameter", () => {
  test("is a decimal string, because D1 rejects a bigint parameter outright", () => {
    expect(bindCredits(1_000_000_000_000_010_000n)).toBe("1000000000000010000");
    expect(typeof bindCredits(5n)).toBe("string");
  });

  test("refuses a value SQLite would have to store as a REAL", () => {
    // Past int64 the column silently stops being exact, inside the database,
    // where no later reader could detect it.
    expect(() => bindCredits(9_223_372_036_854_775_808n)).toThrow(/int64/);
    expect(() => bindCredits(-9_223_372_036_854_775_809n)).toThrow(/int64/);
    expect(bindCredits(9_223_372_036_854_775_807n)).toBe("9223372036854775807");
  });
});

describe("creditsFromText — the exact reader", () => {
  test("decodes a CAST(... AS TEXT) column exactly", () => {
    expect(creditsFromText("1000000000000010000")).toBe(1_000_000_000_000_010_000n);
  });

  test("keeps `no row` distinct from `zero`", () => {
    expect(creditsFromText(null)).toBeUndefined();
    expect(creditsFromText(undefined)).toBeUndefined();
    expect(creditsFromText("")).toBeUndefined();
    expect(creditsFromText("0")).toBe(0n);
  });

  test("refuses a column that came back as a lossy double instead of text", () => {
    // The failure mode this guards: someone drops the CAST and the drift
    // becomes invisible again.
    expect(() => creditsFromText(1e300)).toThrow(/lossy double/);
  });

  test("refuses a non-numeric literal rather than reading it as zero", () => {
    expect(() => creditsFromText("not-a-number")).toThrow(/integer literal/);
  });
});

describe("the reference in-memory twin agrees with the D1 backend", () => {
  test("settleWalletBalance refuses a tenant with no wallet, and records nothing", () => {
    const store = new MemoryWalletStore();
    expect(() => store.settleWalletBalance("topup", "t1", 500, 1)).toThrow(/no wallet row/);

    // The hazard the D1 twin also guards: a claimed settlement id whose balance
    // move did nothing. Both halves are asserted, because a refusal that still
    // recorded the row would leave the repairing retry a no-op.
    store.upsertWallet({
      id: "t1",
      tenantId: "t1",
      balanceCredits: 0,
      dunning: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
    });
    const repaired = store.settleWalletBalance("topup", "t1", 500, 1);
    expect(repaired.newlyApplied).toBe(true);
    expect(store.getWallet("t1")?.balanceCredits).toBe(500);
  });
});
