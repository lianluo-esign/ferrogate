/**
 * The billing dual-write to Analytics Engine (#956) — the fleet-view mirror.
 *
 * The tenant object holds the authoritative per-transaction cost; this is the
 * sampled, cross-tenant analytics copy. These tests pin the data-point SHAPE
 * (which dimension is which blob, which measure is which double) because the
 * control-plane fleet query addresses columns positionally, that the OFFER is
 * recovered from event metadata (so a 0× comp still reports its list price), and
 * that a missing binding / a throwing dataset is a no-op rather than a failure.
 */
import type { BillingEvent } from "@ferrogate/billing";
import { describe, expect, it } from "vitest";
import {
  type BillingAnalyticsDataset,
  billingAnalyticsFromEnv,
  writeBillingAnalyticsForEvent,
} from "../../src/metering/billing-analytics.js";

function recorder(): {
  dataset: BillingAnalyticsDataset;
  points: { blobs?: (string | null)[]; doubles?: number[]; indexes?: string[] }[];
} {
  const points: { blobs?: (string | null)[]; doubles?: number[]; indexes?: string[] }[] = [];
  return { dataset: { writeDataPoint: (point) => points.push(point) }, points };
}

/** A settled event for a key on a 1.5× markup group (offer 0.001161 → final ×1.5). */
function markupEvent(overrides: Partial<BillingEvent> = {}): BillingEvent {
  return {
    request_id: "fg-1",
    trace_id: "fg-1",
    provider_attempt: "provider-attempt:0",
    tenant: { organization_id: "t-1", project_id: "proj-a" },
    logical_model: "claude-sonnet-4-6",
    provider: "anthropic",
    provider_model: "claude-sonnet-4-6",
    usage: {
      prompt_tokens: 367,
      completion_tokens: 4,
      total_tokens: 371,
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1_700_000_000,
    cost_usd: 0.0017415,
    metadata: {
      billing_group_id: "grp-markup",
      billing_multiplier: "1.5",
      offer_cost_usd: "0.001161",
      provider_cost_multiplier: "0.5",
      provider_cost_usd: "0.0005805",
    },
    ...overrides,
  } as BillingEvent;
}

describe("billing-analytics data point (#956)", () => {
  it("writes offer + final(×multiplier) prices and the query dimensions", () => {
    const { dataset, points } = recorder();
    writeBillingAnalyticsForEvent(dataset, markupEvent());

    expect(points).toHaveLength(1);
    expect(points[0]?.blobs).toEqual([
      "t-1",
      "proj-a",
      "claude-sonnet-4-6",
      "anthropic",
      "grp-markup",
      "claude-sonnet-4-6",
    ]);
    // [offer, final, multiplier, promptTokens, completionTokens, providerCost]
    expect(points[0]?.doubles).toEqual([0.001161, 0.0017415, 1.5, 367, 4, 0.0005805]);
    expect(points[0]?.indexes).toEqual(["t-1"]);
  });

  it("recovers the OFFER for a 0× comp from metadata (final $0, offer > 0)", () => {
    const { dataset, points } = recorder();
    writeBillingAnalyticsForEvent(
      dataset,
      markupEvent({
        cost_usd: 0,
        metadata: {
          billing_group_id: "grp-comp",
          billing_multiplier: "0",
          offer_cost_usd: "0.001161",
        },
      }),
    );
    expect(points[0]?.doubles?.[0]).toBe(0.001161); // offer preserved
    expect(points[0]?.doubles?.[1]).toBe(0); // final $0
    expect(points[0]?.doubles?.[2]).toBe(0); // multiplier 0
  });

  it("defaults offer to the final cost and multiplier to 1 when no group applied", () => {
    const { dataset, points } = recorder();
    // No billing metadata (a request bound to no group).
    writeBillingAnalyticsForEvent(dataset, markupEvent({ cost_usd: 0.001161, metadata: {} }));
    expect(points[0]?.doubles?.[0]).toBe(0.001161); // offer == final
    expect(points[0]?.doubles?.[1]).toBe(0.001161);
    expect(points[0]?.doubles?.[2]).toBe(1);
  });

  it("coerces an absent/non-finite cost to 0 rather than writing NaN", () => {
    const { dataset, points } = recorder();
    const { cost_usd: _drop, ...noCost } = markupEvent({ metadata: {} });
    writeBillingAnalyticsForEvent(dataset, noCost as BillingEvent);
    expect(points[0]?.doubles?.[0]).toBe(0);
    expect(points[0]?.doubles?.[1]).toBe(0);
  });

  it("never throws when the dataset write throws — the mirror is best-effort", () => {
    const throwing: BillingAnalyticsDataset = {
      writeDataPoint: () => {
        throw new Error("AE down");
      },
    };
    expect(() => writeBillingAnalyticsForEvent(throwing, markupEvent())).not.toThrow();
  });

  it("resolves the binding from env, and is null when absent or wrong-shaped", () => {
    const { dataset } = recorder();
    expect(billingAnalyticsFromEnv({ BILLING_ANALYTICS: dataset })).toBe(dataset);
    expect(billingAnalyticsFromEnv({})).toBeNull();
    expect(billingAnalyticsFromEnv(null)).toBeNull();
    expect(billingAnalyticsFromEnv({ BILLING_ANALYTICS: {} })).toBeNull();
  });
});
