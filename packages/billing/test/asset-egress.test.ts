import { describe, expect, it } from "vitest";

import {
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
  LedgerAssetEgressMeter,
  assetEgressBillingEvent,
  recordAssetEgress,
} from "../src/asset-egress.js";
import { InMemoryLedgerStore } from "../src/metering/ledger.js";

describe("shared asset egress attribution", () => {
  it("carries the authenticated api key through the charge and billing event", async () => {
    const meter = new InMemoryAssetEgressMeter();
    const charge = await recordAssetEgress({
      quota: {},
      apiKeyId: "key-asset-egress",
      tenantId: "tenant-asset-egress",
      projectId: "project-asset-egress",
      requestId: "request-asset-egress",
      assetType: "cli_tool",
      name: "deploy",
      version: "1.0.0",
      bytes: 32,
      pricePerGb: 0.09,
      counters: new InMemoryAssetEgressCounters(),
      meter,
      nowUnix: 1_800_000_000,
    });

    expect(charge?.apiKeyId).toBe("key-asset-egress");
    expect(assetEgressBillingEvent(charge as NonNullable<typeof charge>).tenant).toMatchObject({
      organization_id: "tenant-asset-egress",
      project_id: "project-asset-egress",
      api_key_id: "key-asset-egress",
    });
  });

  it("routes durable egress charges by their tenant authority", async () => {
    const tenantA = new InMemoryLedgerStore();
    const tenantB = new InMemoryLedgerStore();
    const meter = new LedgerAssetEgressMeter((tenantId) =>
      tenantId === "tenant-a" ? tenantA : tenantB,
    );

    for (const [tenantId, requestId] of [
      ["tenant-a", "request-a"],
      ["tenant-b", "request-b"],
    ] as const) {
      await meter.record({
        requestId,
        tenantId,
        assetType: "cli_tool",
        name: "deploy",
        version: "1.0.0",
        bytes: 32,
        provider: "asset_egress",
        logicalModel: "asset_egress:cli_tool/deploy",
        costUsd: 0.09,
        occurredAtUnix: 1_800_000_000,
      });
    }

    expect(tenantA.charges).toHaveLength(1);
    expect(tenantA.charges[0]?.event.tenant.organization_id).toBe("tenant-a");
    expect(tenantB.charges).toHaveLength(1);
    expect(tenantB.charges[0]?.event.tenant.organization_id).toBe("tenant-b");
  });
});
