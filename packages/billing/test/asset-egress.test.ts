import { describe, expect, it } from "vitest";

import {
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
  assetEgressBillingEvent,
  recordAssetEgress,
} from "../src/asset-egress.js";

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
});
