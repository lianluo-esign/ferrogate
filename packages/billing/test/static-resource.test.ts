import { describe, expect, it } from "vitest";

import { InMemoryLedgerStore } from "../src/metering/ledger.js";
import {
  DEFAULT_STATIC_RESOURCE_PRICE_PER_REQUEST,
  InMemoryStaticResourceMeter,
  LedgerStaticResourceMeter,
  STATIC_RESOURCE_PROVIDER,
  STATIC_RESOURCE_REQUESTS_METADATA_KEY,
  recordStaticResourceRequest,
  staticResourceBillingEvent,
  staticResourceRequestCost,
} from "../src/static-resource.js";

const BASE = {
  tenantId: "tenant-sr",
  apiKeyId: "key-sr",
  projectId: "project-sr",
  requestId: "request-sr",
  name: "docs/guide.md",
  version: "1",
  nowUnix: 1_800_000_000,
} as const;

describe("static-resource per-request cost", () => {
  it("prices one pull at the configured per-request rate", () => {
    expect(staticResourceRequestCost(1, DEFAULT_STATIC_RESOURCE_PRICE_PER_REQUEST)).toBeCloseTo(
      0.001,
      12,
    );
    expect(staticResourceRequestCost(5, 0.001)).toBeCloseTo(0.005, 12);
  });

  it("is unpriced (undefined, never zero) when the rate is null/undefined/invalid", () => {
    expect(staticResourceRequestCost(1, null)).toBeUndefined();
    expect(staticResourceRequestCost(1, undefined)).toBeUndefined();
    expect(staticResourceRequestCost(1, Number.NaN)).toBeUndefined();
    expect(staticResourceRequestCost(1, -1)).toBeUndefined();
  });

  it("bills nothing for a non-positive request count", () => {
    expect(staticResourceRequestCost(0, 0.001)).toBeUndefined();
    expect(staticResourceRequestCost(-2, 0.001)).toBeUndefined();
  });
});

describe("static-resource pull metering", () => {
  it("settles a priced pull and carries the credential through the charge + event", async () => {
    const meter = new InMemoryStaticResourceMeter();
    const charge = await recordStaticResourceRequest({
      ...BASE,
      pricePerRequest: DEFAULT_STATIC_RESOURCE_PRICE_PER_REQUEST,
      meter,
    });

    expect(charge?.provider).toBe(STATIC_RESOURCE_PROVIDER);
    expect(charge?.requests).toBe(1);
    expect(charge?.costUsd).toBeCloseTo(0.001, 12);
    expect(meter.charges).toHaveLength(1);

    const event = staticResourceBillingEvent(charge as NonNullable<typeof charge>);
    expect(event.provider).toBe(STATIC_RESOURCE_PROVIDER);
    expect(event.logical_model).toBe("static_resource:docs/guide.md");
    expect(event.provider_model).toBe("1");
    expect(event.usage).toEqual({ prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
    expect(event.cost_usd).toBeCloseTo(0.001, 12);
    expect(event.metadata?.[STATIC_RESOURCE_REQUESTS_METADATA_KEY]).toBe("1");
    expect(event.tenant).toMatchObject({
      organization_id: "tenant-sr",
      project_id: "project-sr",
      api_key_id: "key-sr",
    });
  });

  it("meters an unpriced pull but omits cost_usd", async () => {
    const meter = new InMemoryStaticResourceMeter();
    const charge = await recordStaticResourceRequest({ ...BASE, pricePerRequest: null, meter });

    expect(charge?.costUsd).toBeUndefined();
    const event = staticResourceBillingEvent(charge as NonNullable<typeof charge>);
    expect(event.cost_usd).toBeUndefined();
  });

  it("routes durable pull charges by their tenant authority", async () => {
    const tenantA = new InMemoryLedgerStore();
    const tenantB = new InMemoryLedgerStore();
    const meter = new LedgerStaticResourceMeter((tenantId) =>
      tenantId === "tenant-a" ? tenantA : tenantB,
    );

    await recordStaticResourceRequest({
      ...BASE,
      tenantId: "tenant-a",
      requestId: "req-a",
      pricePerRequest: 0.001,
      meter,
    });

    expect(tenantA.charges).toHaveLength(1);
    expect(tenantB.charges).toHaveLength(0);
  });

  it("skips the durable write for an unpriced pull rather than billing $0", async () => {
    const store = new InMemoryLedgerStore();
    const meter = new LedgerStaticResourceMeter(store);

    await recordStaticResourceRequest({ ...BASE, pricePerRequest: null, meter });

    expect(store.charges).toHaveLength(0);
  });

  it("is idempotent on the request id — a retried pull cannot double-charge", async () => {
    const store = new InMemoryLedgerStore();
    const meter = new LedgerStaticResourceMeter(store);

    await recordStaticResourceRequest({ ...BASE, pricePerRequest: 0.001, meter });
    await recordStaticResourceRequest({ ...BASE, pricePerRequest: 0.001, meter });

    expect(store.charges).toHaveLength(1);
  });
});
