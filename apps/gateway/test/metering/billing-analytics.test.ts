/**
 * The billing dual-write to Analytics Engine (#956) — the fleet-view mirror.
 *
 * The tenant object holds the authoritative per-transaction cost; this is the
 * sampled, cross-tenant analytics copy. These tests pin the data-point SHAPE
 * (which dimension is which blob, which measure is which double) because the
 * control-plane fleet query addresses columns positionally, and pin that a
 * missing binding is a no-op rather than a throw.
 */
import { describe, expect, it } from "vitest";
import type { Usage } from "../../src/inference/ports.js";
import {
  type BillingAnalyticsDataset,
  billingAnalyticsFromEnv,
  writeBillingAnalytics,
} from "../../src/metering/billing-analytics.js";

function recorder(): {
  dataset: BillingAnalyticsDataset;
  points: { blobs?: (string | null)[]; doubles?: number[]; indexes?: string[] }[];
} {
  const points: { blobs?: (string | null)[]; doubles?: number[]; indexes?: string[] }[] = [];
  return { dataset: { writeDataPoint: (point) => points.push(point) }, points };
}

const USAGE: Usage = {
  requestId: "fg-1",
  route: "openai.chat.completions",
  logicalModel: "claude-sonnet-4-6",
  provider: "anthropic",
  providerModel: "claude-sonnet-4-6",
  stream: false,
  status: 200,
  promptTokens: 367,
  completionTokens: 4,
  tenantId: "t-1",
  projectId: "proj-a",
  billingGroupId: "grp-markup",
  billingMultiplier: 1.5,
};

describe("billing-analytics data point (#956)", () => {
  it("writes offer + final(×multiplier) prices and the query dimensions", () => {
    const { dataset, points } = recorder();
    // offer = 367*3/1e6 + 4*15/1e6 = 0.001161; final = offer * 1.5.
    writeBillingAnalytics(dataset, USAGE, 0.001161, 0.0017415);

    expect(points).toHaveLength(1);
    const p = points[0];
    expect(p?.blobs).toEqual([
      "t-1",
      "proj-a",
      "claude-sonnet-4-6",
      "anthropic",
      "grp-markup",
      "claude-sonnet-4-6",
    ]);
    // [offer, final, multiplier, promptTokens, completionTokens]
    expect(p?.doubles).toEqual([0.001161, 0.0017415, 1.5, 367, 4]);
    expect(p?.indexes).toEqual(["t-1"]);
  });

  it("honours a 0× comp (final = $0) and defaults an absent multiplier to 1", () => {
    const { dataset, points } = recorder();
    writeBillingAnalytics(dataset, { ...USAGE, billingMultiplier: 0 }, 0.001161, 0);
    expect(points[0]?.doubles?.[1]).toBe(0); // final $0
    expect(points[0]?.doubles?.[2]).toBe(0); // multiplier 0

    const { dataset: d2, points: p2 } = recorder();
    const { billingMultiplier: _omit, ...noMult } = USAGE;
    writeBillingAnalytics(d2, noMult as Usage, 0.001161, 0.001161);
    expect(p2[0]?.doubles?.[2]).toBe(1); // absent ⇒ 1
  });

  it("coerces an absent/non-finite cost to 0 rather than writing NaN", () => {
    const { dataset, points } = recorder();
    writeBillingAnalytics(dataset, USAGE, undefined, Number.NaN);
    expect(points[0]?.doubles?.[0]).toBe(0);
    expect(points[0]?.doubles?.[1]).toBe(0);
  });

  it("never throws when the dataset write throws — the mirror is best-effort", () => {
    const throwing: BillingAnalyticsDataset = {
      writeDataPoint: () => {
        throw new Error("AE down");
      },
    };
    expect(() => writeBillingAnalytics(throwing, USAGE, 0.001, 0.0015)).not.toThrow();
  });

  it("resolves the binding from env, and is null when absent or wrong-shaped", () => {
    const { dataset } = recorder();
    expect(billingAnalyticsFromEnv({ BILLING_ANALYTICS: dataset })).toBe(dataset);
    expect(billingAnalyticsFromEnv({})).toBeNull();
    expect(billingAnalyticsFromEnv(null)).toBeNull();
    expect(billingAnalyticsFromEnv({ BILLING_ANALYTICS: {} })).toBeNull();
  });
});
