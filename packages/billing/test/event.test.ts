import { describe, expect, it } from "vitest";
import {
  type BillingEvent,
  InMemoryBillingEventSink,
  MAX_METADATA_ENTRIES,
  MAX_METADATA_KEY_LEN,
  MAX_METADATA_VALUE_LEN,
  parseBillingEvent,
  providerAttemptForRequest,
  providerAttemptIsLegacy,
  validateRequestMetadata,
} from "../src/index.js";

function wireEvent(request_id: string): Record<string, unknown> {
  return {
    request_id,
    trace_id: null,
    provider_attempt_id: `${request_id}:provider-attempt:0`,
    provider_attempt_index: 0,
    tenant: { organization_id: "org", project_id: "project", api_key_id: "key_dev" },
    logical_model: "fast-chat",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1,
    metadata: {},
  };
}

describe("validateRequestMetadata (issue #171)", () => {
  it("accepts a map within all bounds and an empty map", () => {
    expect(validateRequestMetadata({ customer_id: "acme" })).toBeNull();
    expect(validateRequestMetadata({})).toBeNull();
  });
  it("rejects too many entries", () => {
    const md: Record<string, string> = {};
    for (let i = 0; i < MAX_METADATA_ENTRIES + 1; i += 1) md[`key-${i}`] = "value";
    expect(validateRequestMetadata(md)).toContain("at most");
  });
  it("rejects an empty key", () => {
    expect(validateRequestMetadata({ "": "value" })).toContain("empty");
  });
  it("rejects an over-long key", () => {
    expect(validateRequestMetadata({ ["k".repeat(MAX_METADATA_KEY_LEN + 1)]: "v" })).toContain(
      "key",
    );
  });
  it("rejects an over-long value", () => {
    expect(
      validateRequestMetadata({ customer_id: "v".repeat(MAX_METADATA_VALUE_LEN + 1) }),
    ).toContain("value");
  });
});

describe("parseBillingEvent wire flatten", () => {
  it("nests the flattened provider-attempt keys", () => {
    const event = parseBillingEvent(wireEvent("fg-test"));
    expect(event.provider_attempt.provider_attempt_id).toBe("fg-test:provider-attempt:0");
    expect(event.tenant.organization_id).toBe("org");
    expect(event.usage.total_tokens).toBe(8);
    expect(event.usage_source).toBe("provider_usage");
  });

  it("treats a payload missing provider-attempt fields as legacy", () => {
    const wire = wireEvent("req-legacy");
    // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
    delete wire.provider_attempt_id;
    // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
    delete wire.provider_attempt_index;
    const event = parseBillingEvent(wire);
    expect(providerAttemptIsLegacy(event.provider_attempt)).toBe(true);
  });

  it("coerces the i64 wallet fields to bigint", () => {
    const wire = {
      ...wireEvent("req-wallet"),
      wallet_delta_credits: -35_000,
      wallet_balance_after_credits: 465_000,
    };
    const event = parseBillingEvent(wire);
    expect(event.wallet_delta_credits).toBe(-35_000n);
    expect(event.wallet_balance_after_credits).toBe(465_000n);
  });
});

describe("InMemoryBillingEventSink", () => {
  function event(request_id: string): BillingEvent {
    return parseBillingEvent(wireEvent(request_id));
  }

  it("records and lists events", () => {
    const sink = new InMemoryBillingEventSink();
    sink.record(event("fg-test"));
    const events = sink.list();
    expect(events).toHaveLength(1);
    expect((events[0] as NonNullable<(typeof events)[0]>).tenant.organization_id).toBe("org");
  });

  it("enforces a FIFO retention limit while tracking the running total", () => {
    const sink = InMemoryBillingEventSink.withRetentionLimit(2);
    for (const id of ["fg-1", "fg-2", "fg-3"]) sink.record(event(id));
    const events = sink.list();
    expect(sink.length).toBe(2);
    expect(sink.recordedTotal()).toBe(3);
    expect((events[0] as NonNullable<(typeof events)[0]>).request_id).toBe("fg-2");
    expect((events[1] as NonNullable<(typeof events)[1]>).request_id).toBe("fg-3");
    expect(sink.listPaginated(1, 1)[0]!.request_id).toBe("fg-3");
  });

  it("uses providerAttemptForRequest to build a request-scoped attempt id", () => {
    expect(providerAttemptForRequest("x", 2).provider_attempt_id).toBe("x:provider-attempt:2");
  });
});
