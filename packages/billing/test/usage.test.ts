import { describe, expect, it } from "vitest";
import {
  defaultProviderAttempt,
  estimateCost,
  estimateMissingTotal,
  modelPriceUsd,
  newTokenUsage,
  providerAttemptForRequest,
  providerAttemptIsLegacy,
  reconcileSplit,
} from "../src/index.js";

describe("ModelPrice.estimate", () => {
  it("prices input/output from token usage (mirrors estimates_model_cost)", () => {
    const cost = estimateCost(modelPriceUsd(0.15, 0.6), newTokenUsage(1_000, 2_000, 3_000));
    expect(cost.currency).toBe("USD");
    expect(cost.input_cost).toBeCloseTo(0.00015, 12);
    expect(cost.output_cost).toBeCloseTo(0.0012, 12);
    expect(cost.total_cost).toBeCloseTo(0.00135, 12);
  });
});

describe("TokenUsage.reconcile_split (issue #140)", () => {
  it("derives a missing total from the split", () => {
    expect(reconcileSplit(newTokenUsage(1_000, 2_000, 0)).total_tokens).toBe(3_000);
  });

  it("derives a missing completion side from prompt + total", () => {
    const out = reconcileSplit(newTokenUsage(1_000, 0, 3_000));
    expect(out.completion_tokens).toBe(2_000);
  });

  it("derives a missing prompt side from completion + total", () => {
    const out = reconcileSplit(newTokenUsage(0, 1_000, 3_000));
    expect(out.prompt_tokens).toBe(2_000);
  });

  it("leaves a consistent split untouched", () => {
    const out = reconcileSplit(newTokenUsage(1_000, 2_000, 3_000));
    expect(out).toEqual(newTokenUsage(1_000, 2_000, 3_000));
  });

  it("estimate_missing_total only fills a zero total", () => {
    expect(estimateMissingTotal(newTokenUsage(1, 1, 5)).total_tokens).toBe(5);
    expect(estimateMissingTotal(newTokenUsage(1, 1, 0)).total_tokens).toBe(2);
  });
});

describe("ProviderAttempt (issue #213)", () => {
  it("is stable and request-scoped", () => {
    const first = providerAttemptForRequest("req-123", 0);
    const replay = providerAttemptForRequest("req-123", 0);
    const retry = providerAttemptForRequest("req-123", 1);
    expect(first).toEqual(replay);
    expect(first.provider_attempt_id).toBe("req-123:provider-attempt:0");
    expect(retry.provider_attempt_index).toBe(1);
    expect(first.provider_attempt_id).not.toBe(retry.provider_attempt_id);
    expect(providerAttemptIsLegacy(first)).toBe(false);
    expect(providerAttemptIsLegacy(defaultProviderAttempt())).toBe(true);
  });
});
