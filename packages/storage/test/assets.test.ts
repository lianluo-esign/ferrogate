import { beforeEach, describe, expect, test } from "vitest";
import {
  MemoryAssetStore,
  assetVisibilityFromStored,
  classifyAssetQuotaAdmission,
  promoteAssetVisibility,
  type StoredAsset,
} from "../src/index.js";

function asset(id: string, tenantId: string, sizeBytes: number, extra: Partial<StoredAsset> = {}): StoredAsset {
  return {
    id,
    tenantId,
    assetType: "tool",
    name: "cli",
    version: "1.0.0",
    contentType: "application/octet-stream",
    contentHash: "deadbeef",
    sizeBytes,
    content: new Uint8Array(),
    variant: "",
    yanked: false,
    visibility: "visible",
    createdAtUnix: 0,
    updatedAtUnix: 0,
    ...extra,
  };
}

describe("asset visibility fails closed (#366)", () => {
  test("an unrecognized visibility token parses to quarantined", () => {
    expect(assetVisibilityFromStored("visible")).toBe("visible");
    expect(assetVisibilityFromStored("pending_scan")).toBe("pending_scan");
    expect(assetVisibilityFromStored("garbage")).toBe("quarantined");
  });
});

describe("classifyAssetQuotaAdmission precedence (§1.371)", () => {
  test("an insert wins as admitted", () => {
    expect(classifyAssetQuotaAdmission(true, false, false, 0, 0, 100).kind).toBe("admitted");
  });
  test("an existing id is already_exists even when notionally over quota", () => {
    expect(classifyAssetQuotaAdmission(false, true, false, 0, 0, 100).kind).toBe("already_exists");
  });
  test("a non-existing id whose quota guard failed is over_quota", () => {
    const out = classifyAssetQuotaAdmission(false, false, false, 90, 20, 100);
    expect(out).toEqual({ kind: "over_quota", usedBytes: 90, attemptedBytes: 20, quotaBytes: 100 });
  });
});

describe("MemoryAssetStore quota admission is atomic", () => {
  let store: MemoryAssetStore;
  beforeEach(() => {
    store = new MemoryAssetStore();
  });

  test("two different-id creates cannot jointly overshoot the tenant quota", () => {
    // quota 100, each 60 → first admitted, second over-quota.
    expect(store.createAssetWithinQuota(asset("a", "t1", 60), 100).kind).toBe("admitted");
    const second = store.createAssetWithinQuota(asset("b", "t1", 60), 100);
    expect(second.kind).toBe("over_quota");
    expect(store.tenantAssetStorageBytesUsed("t1")).toBe(60);
  });

  test("a same-id retry is idempotent already_exists, never charged twice", () => {
    store.createAssetWithinQuota(asset("a", "t1", 60), 100);
    expect(store.createAssetWithinQuota(asset("a", "t1", 60), 100).kind).toBe("already_exists");
    expect(store.tenantAssetStorageBytesUsed("t1")).toBe(60);
  });

  test("an undefined quota admits any size", () => {
    expect(store.createAssetWithinQuota(asset("a", "t1", 1_000_000), undefined).kind).toBe(
      "admitted",
    );
  });
});

describe("visibility promotion CAS (#378)", () => {
  test("pure decision: only pending_scan promotes; terminal is not_pending; missing is not_found", () => {
    expect(promoteAssetVisibility("pending_scan", "visible")).toEqual({
      kind: "promoted",
      to: "visible",
    });
    expect(promoteAssetVisibility("visible", "quarantined")).toEqual({
      kind: "not_pending",
      current: "visible",
    });
    expect(promoteAssetVisibility(undefined, "visible")).toEqual({ kind: "not_found" });
  });

  test("store promotes a pending asset and refuses a second promotion", () => {
    const store = new MemoryAssetStore();
    store.upsertAsset(asset("a", "t1", 10, { visibility: "pending_scan" }));
    expect(store.promoteAssetVisibility("a", "visible", 5).kind).toBe("promoted");
    expect(store.getAsset("a")?.visibility).toBe("visible");
    expect(store.promoteAssetVisibility("a", "quarantined", 6).kind).toBe("not_pending");
  });
});
