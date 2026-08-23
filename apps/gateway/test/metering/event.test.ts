/**
 * `Usage` → `BillingEvent`, and the storage-document encoding.
 *
 * The two fields worth holding hardest are the ones idempotency is derived
 * from: `request_id` and the provider-attempt id feed `ledgerEntryId`, which is
 * the primary key of all three metering tables.
 */
import { ledgerEntryId } from "@ferrogate/billing";
import { describe, expect, it } from "vitest";
import {
  SINGLE_PROVIDER_ATTEMPT_INDEX,
  billingEventFromUsage,
  billingEventFromWire,
  billingEventToWire,
  creditsFromWire,
  creditsToWire,
  ledgerEntryFromWire,
  ledgerEntryToWireDocument,
  providerAttemptIndexFor,
  usageSourceFor,
} from "../../src/metering/index.js";
import { chargeFixture, usageFixture } from "./fixtures.js";

describe("billingEventFromUsage", () => {
  it("maps tenantId onto organization_id, which IS the tenant id", () => {
    const event = billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1_700_000_000 });
    expect(event.tenant).toEqual({
      organization_id: "tenant_a",
      project_id: "project_1",
    });
  });

  it("omits tenant fields entirely when the request named none", () => {
    const event = billingEventFromUsage(
      usageFixture({ tenantId: undefined, projectId: undefined }),
      { nowUnixSeconds: 1 },
    );
    expect(event.tenant).toEqual({});
  });

  it("derives an idempotency key from the request id and attempt index", () => {
    const event = billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1 });
    expect(SINGLE_PROVIDER_ATTEMPT_INDEX).toBe(0);
    expect(event.provider_attempt).toEqual({
      provider_attempt_id: "fg-000000000000002a:provider-attempt:0",
      provider_attempt_index: 0,
    });
    expect(ledgerEntryId(event)).toBe(
      "ferrogate:provider-attempt:fg-000000000000002a:provider-attempt:0",
    );
  });

  /**
   * The audio rails, and the reason they are on the EVENT (issue #703).
   *
   * `charge()` prices an audio row off `audio_seconds` / `audio_characters`; if
   * they do not survive this mapping the rate card cannot value the row, the
   * expected cost is $0 against a positive settled cost, and the >5% divergence
   * check either never runs or fires on every correct row. So this is the seam
   * that decides whether the mispricing detector works for audio at all.
   */
  describe("the audio quantities (issue #703)", () => {
    it("carries a reported duration onto the billing event", () => {
      const event = billingEventFromUsage(usageFixture({ audioSeconds: 12.5 }), {
        nowUnixSeconds: 1,
      });
      expect(event.audio_seconds).toBe(12.5);
    });

    it("carries a character count for a synthesis row", () => {
      const event = billingEventFromUsage(usageFixture({ audioCharacters: 1_234 }), {
        nowUnixSeconds: 1,
      });
      expect(event.audio_characters).toBe(1_234);
    });

    it("leaves them ABSENT — not zero — when the provider reported none", () => {
      // Zero would settle a real, billable call authoritatively at $0. The
      // whole `audioSeconds` rail is `undefined`-when-unknown for this reason,
      // and a `?? 0` anywhere on the way here would undo it silently.
      const event = billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1 });
      expect("audio_seconds" in event).toBe(false);
      expect("audio_characters" in event).toBe(false);
    });
  });

  describe("provider attempt index (issue #135)", () => {
    // The failover ladder (`inference/reliability.ts::dispatchWithFailover`) can
    // make several provider dispatches per logical request, and each is
    // separately billable. This module used to HARD-CODE index 0, which would
    // have collapsed two attempts of one request onto one `ledgerEntryId` — the
    // second absorbed by `ON CONFLICT DO NOTHING` as a healthy replay, i.e. a
    // silent under-bill. These four cases are what make the index real here so
    // the day `Usage` carries one, nothing else has to change.

    it("PARTITIONS the ledger key when the dispatcher declares an attempt", () => {
      const first = billingEventFromUsage(
        { ...usageFixture(), providerAttemptIndex: 0 },
        { nowUnixSeconds: 1 },
      );
      const second = billingEventFromUsage(
        { ...usageFixture(), providerAttemptIndex: 1 },
        { nowUnixSeconds: 1 },
      );
      expect(second.provider_attempt.provider_attempt_index).toBe(1);
      // The whole point: SAME request id, DIFFERENT ledger key.
      expect(first.request_id).toBe(second.request_id);
      expect(ledgerEntryId(second)).not.toBe(ledgerEntryId(first));
    });

    it("falls back to 0 when the dispatcher declares nothing", () => {
      expect(providerAttemptIndexFor(usageFixture())).toBe(SINGLE_PROVIDER_ATTEMPT_INDEX);
    });

    it("refuses a non-integer / negative index rather than keying on it", () => {
      // A `NaN` or `-1` reaching `ledgerEntryId` would build a primary key that
      // no replay of the same request could ever match, turning idempotent
      // retry into DOUBLE-billing — strictly worse than the under-bill above.
      for (const bad of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
        expect(providerAttemptIndexFor({ ...usageFixture(), providerAttemptIndex: bad })).toBe(0);
      }
    });

    it("accepts a large but safe index", () => {
      expect(providerAttemptIndexFor({ ...usageFixture(), providerAttemptIndex: 7 })).toBe(7);
    });
  });

  it("stamps the settlement time (issue #153), never leaving it null", () => {
    const event = billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1_700_000_123 });
    expect(event.occurred_at_unix).toBe(1_700_000_123);
  });

  it("carries a settled cost only when one was supplied", () => {
    expect(billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1 }).cost_usd).toBeUndefined();
    expect(
      billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1, settledCostUsd: 0.5 }).cost_usd,
    ).toBe(0.5);
  });

  it("carries the deployment identity when the sink was told one", () => {
    const event = billingEventFromUsage(usageFixture(), {
      nowUnixSeconds: 1,
      clusterId: "cf-colo",
      nodeId: "isolate-7",
    });
    expect(event.cluster_id).toBe("cf-colo");
    expect(event.node_id).toBe("isolate-7");
  });

  it("keeps caller metadata but REPORTS a bounds violation (issue #171)", () => {
    const reported: string[] = [];
    const tooMany = Object.fromEntries(
      Array.from({ length: 9 }, (_unused, index) => [`k${index}`, "v"]),
    );

    const event = billingEventFromUsage(usageFixture({ metadata: tooMany }), {
      nowUnixSeconds: 1,
      diagnostics: { onError: (stage, error) => reported.push(`${stage}:${String(error)}`) },
    });

    // Attribution is not silently dropped …
    expect(Object.keys(event.metadata)).toHaveLength(9);
    // … but the ingress regression that let it through is visible.
    expect(reported[0]).toContain("metadata_bounds");
    expect(reported[0]).toContain("at most 8 entries");
  });

  it("stays silent for metadata inside the bounds", () => {
    const reported: string[] = [];
    billingEventFromUsage(usageFixture({ metadata: { team: "search" } }), {
      nowUnixSeconds: 1,
      diagnostics: { onError: (stage) => reported.push(stage) },
    });
    expect(reported).toEqual([]);
  });

  it("reserves billing-group metadata for the gateway settlement result", () => {
    const spoofed = {
      billing_group_id: "spoofed-group",
      billing_multiplier: "999",
      offer_cost_usd: "0",
      provider_cost_multiplier: "999",
      provider_cost_usd: "0",
      team: "search",
    };
    const ungrouped = billingEventFromUsage(usageFixture({ metadata: spoofed }), {
      nowUnixSeconds: 1,
    });
    expect(ungrouped.metadata).toEqual({ team: "search" });

    const grouped = billingEventFromUsage(
      usageFixture({
        metadata: spoofed,
        billingGroupId: "actual-group",
        billingMultiplier: 1.5,
        providerCostMultiplier: 0.5,
      }),
      { nowUnixSeconds: 1, offerCostUsd: 0.25, providerCostUsd: 0.125 },
    );
    expect(grouped.metadata).toEqual({
      team: "search",
      billing_group_id: "actual-group",
      billing_multiplier: "1.5",
      offer_cost_usd: "0.25",
      provider_cost_multiplier: "0.5",
      provider_cost_usd: "0.125",
    });
  });
});

describe("usageSourceFor", () => {
  it("is provider_usage when ANY count was reported", () => {
    expect(usageSourceFor(usageFixture())).toBe("provider_usage");
    expect(
      usageSourceFor(
        usageFixture({ promptTokens: 5, completionTokens: undefined, totalTokens: undefined }),
      ),
    ).toBe("provider_usage");
  });

  it("is gateway_estimate when the tap scraped nothing at all", () => {
    expect(
      usageSourceFor(
        usageFixture({
          promptTokens: undefined,
          completionTokens: undefined,
          totalTokens: undefined,
        }),
      ),
    ).toBe("gateway_estimate");
  });
});

describe("storage documents", () => {
  it("round-trips a BillingEvent through the flat serde form", () => {
    const event = billingEventFromUsage(usageFixture({ metadata: { team: "search" } }), {
      nowUnixSeconds: 1_700_000_000,
      settledCostUsd: 0.25,
      clusterId: "cf-colo",
    });
    const wire = billingEventToWire(event);

    // serde flattens the provider attempt onto the top level.
    expect(wire.provider_attempt_id).toBe("fg-000000000000002a:provider-attempt:0");
    expect(wire.provider_attempt_index).toBe(0);
    expect(wire).not.toHaveProperty("provider_attempt");
    // `None` is OMITTED, not written as null.
    expect(wire).not.toHaveProperty("latency_ms");
    expect(wire).not.toHaveProperty("agent_run_id");

    expect(billingEventFromWire(JSON.parse(JSON.stringify(wire)))).toEqual(event);
  });

  it("round-trips a LedgerEntry through the flat serde form", () => {
    const { entry } = chargeFixture("ferrogate:req-1", 4n);
    const wire = ledgerEntryToWireDocument(entry);
    expect(wire.provider_attempt_id).toBe("ferrogate:req-1");
    expect(ledgerEntryFromWire(JSON.parse(JSON.stringify(wire)))).toEqual(entry);
  });

  it("carries credits as a decimal string that survives JSON", () => {
    const huge = 12_345_678_901_234_567_890n;
    expect(creditsToWire(huge)).toBe("12345678901234567890");
    expect(creditsFromWire(JSON.parse(JSON.stringify(creditsToWire(huge))))).toBe(huge);
  });

  it("refuses a credit value that cannot be read back losslessly", () => {
    // Better to fail the read than to charge a rounded number.
    expect(() => creditsFromWire(1.5)).toThrow(TypeError);
    // The precision loss below IS the subject: 2^53+1 is not representable as a
    // double, so that literal really is 2^53 at runtime — and `creditsFromWire`
    // must REFUSE it rather than silently charge the rounded value. Writing a
    // representable number instead would make the assertion unreachable.
    // biome-ignore lint/correctness/noPrecisionLoss: see above
    expect(() => creditsFromWire(9_007_199_254_740_993)).toThrow(TypeError);
    expect(() => creditsFromWire("not-a-number")).toThrow(TypeError);
    expect(() => creditsFromWire(null)).toThrow(TypeError);
  });
});
