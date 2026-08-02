import { describe, expect, test } from "vitest";
import {
  ShadowBudgetLedger,
  canarySelected,
  shadowSampled,
} from "@ferrogate/routing";

// Ports of ferrogate-routing::rollout::tests, plus TS-specific edges.

describe("canarySelected", () => {
  test("percent 0 never selects and >=100 always selects", () => {
    for (const key of ["k0", "tenant-a", "api-key-42", ""]) {
      expect(canarySelected(key, 0)).toBe(false);
      expect(canarySelected(key, 100)).toBe(true);
      expect(canarySelected(key, 200)).toBe(true); // saturating: >=100 always
    }
  });

  test("is sticky per key", () => {
    for (let i = 0; i < 1000; i++) {
      expect(canarySelected("sticky-key", 37)).toBe(canarySelected("sticky-key", 37));
    }
  });

  test("10% split is within tolerance", () => {
    const total = 10_000;
    let selected = 0;
    for (let i = 0; i < total; i++) {
      if (canarySelected(`key-${i}`, 10)) selected++;
    }
    const ratio = selected / total;
    expect(Math.abs(ratio - 0.1)).toBeLessThan(0.015);
  });

  test("bucket is monotonic in percent (raising % only adds callers)", () => {
    const key = "monotonic-key";
    let previouslySelected = false;
    for (let percent = 0; percent <= 100; percent++) {
      const selected = canarySelected(key, percent);
      if (previouslySelected) {
        expect(selected).toBe(true);
      }
      previouslySelected = selected;
    }
  });

  // Edge: negative percent is treated as "off" (Rust's u8 can't be negative;
  // TS clamps <=0 to never-select rather than underflowing).
  test("non-positive percent never selects", () => {
    expect(canarySelected("k", -5)).toBe(false);
  });
});

describe("shadowSampled", () => {
  test("boundary percentages", () => {
    for (const key of ["a", "b", ""]) {
      expect(shadowSampled(key, 0)).toBe(false);
      expect(shadowSampled(key, 100)).toBe(true);
    }
  });

  test("shadow and canary sample independently", () => {
    let differ = false;
    for (let i = 0; i < 1000; i++) {
      const key = `key-${i}`;
      if (canarySelected(key, 50) !== shadowSampled(key, 50)) {
        differ = true;
        break;
      }
    }
    expect(differ).toBe(true);
  });
});

describe("ShadowBudgetLedger", () => {
  test("caps dispatch count and keys budgets independently", () => {
    const ledger = new ShadowBudgetLedger();
    expect(ledger.tryConsume("gpt-4o", 2)).toBe(true);
    expect(ledger.tryConsume("gpt-4o", 2)).toBe(true);
    expect(ledger.tryConsume("gpt-4o", 2)).toBe(false); // third refused
    expect(ledger.consumed("gpt-4o")).toBe(2);
    // A different key has its own independent budget.
    expect(ledger.tryConsume("gpt-4o-mini", 2)).toBe(true);
    expect(ledger.consumed("gpt-4o-mini")).toBe(1);
  });

  test("zero limit is uncapped and records nothing", () => {
    const ledger = new ShadowBudgetLedger();
    for (let i = 0; i < 1000; i++) {
      expect(ledger.tryConsume("model", 0)).toBe(true);
    }
    expect(ledger.consumed("model")).toBe(0);
  });

  // Edge: an unseen key reports zero consumption.
  test("consumed of an unseen key is 0", () => {
    expect(new ShadowBudgetLedger().consumed("never-touched")).toBe(0);
  });
});
