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
