/**
 * Issue #801 red contract: MCP and gateway must consume one billing-owned
 * asset-egress surface instead of maintaining an app-local copy.
 */
import { describe, expect, it } from "vitest";

describe("#801 shared asset egress contract", () => {
  it("exports the quota, metering, and audit entry points from billing", async () => {
    const billing = (await import("@ferrogate/billing")) as Record<string, unknown>;

    expect(billing.assetEgressQuotaDenial).toBeTypeOf("function");
    expect(billing.recordAssetEgress).toBeTypeOf("function");
    expect(billing.assetPullAuditMessage).toBeTypeOf("function");
  });
});
