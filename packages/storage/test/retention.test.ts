import { describe, expect, test } from "vitest";
import {
  type RetentionPolicy,
  type StoredAsset,
  type StoredAssetChannel,
  pinnedVersions,
  planBlobGc,
  planLogRetention,
  planVersionRetention,
} from "../src/index.js";

function asset(version: string, createdAtUnix: number, sizeBytes = 10): StoredAsset {
  return {
    id: `t1:tool:cli:${version}`,
    tenantId: "t1",
    assetType: "tool",
    name: "cli",
    version,
    contentType: "x",
    contentHash: "h",
    sizeBytes,
    content: new Uint8Array(),
    variant: "",
    yanked: false,
    visibility: "visible",
    createdAtUnix,
    updatedAtUnix: createdAtUnix,
  };
}

describe("planVersionRetention — fail-safe (§1.263)", () => {
  const now = 1000;
  test("keep_last_n retains the newest N, prunes the rest", () => {
    const assets = [asset("v1", 100), asset("v2", 200), asset("v3", 300)];
    const policy: RetentionPolicy = { keepLastN: 2, minAgeSecs: 0 };
    const plan = planVersionRetention(assets, new Set(), now, policy);
    expect(plan.targets.map((t) => t.version)).toEqual(["v1"]);
    expect(plan.freedBytes).toBe(10);
  });

  test("a channel-pinned version is never pruned", () => {
    const assets = [asset("v1", 100), asset("v2", 200), asset("v3", 300)];
    const policy: RetentionPolicy = { keepLastN: 1, minAgeSecs: 0 };
    const plan = planVersionRetention(assets, new Set(["v1"]), now, policy);
    expect(plan.targets.map((t) => t.version).sort()).toEqual(["v2"]);
  });

  test("the grace window protects a too-new prune candidate", () => {
    const assets = [asset("v1", 100), asset("v2", 999)]; // v2 is 1s old
    const policy: RetentionPolicy = { keepLastN: 1, minAgeSecs: 60 };
    const plan = planVersionRetention(assets, new Set(), now, policy);
    // v2 would be beyond keep window but is inside the grace window → kept.
    expect(plan.targets.map((t) => t.version)).toEqual(["v1"]);
  });

  test("a no-op policy prunes nothing", () => {
    const plan = planVersionRetention([asset("v1", 1)], new Set(), now, { minAgeSecs: 0 });
    expect(plan.targets).toEqual([]);
  });
});

describe("planLogRetention (#284)", () => {
  test("max_age prunes only rows older than the cutoff, minAge is the legal floor", () => {
    const candidates = [
      { id: "old", createdAtUnix: 0 },
      { id: "recent", createdAtUnix: 950 },
    ];
    const prune = planLogRetention(candidates, 1000, { maxAgeSecs: 100, minAgeSecs: 10 });
    expect(prune).toEqual(["old"]);
  });
});

describe("planBlobGc — orphan deletion is fail-safe", () => {
  const now = 1000;
  test("only unreferenced, known-age, past-grace objects are orphans", () => {
    const objects = [
      { key: "referenced", lastModifiedUnix: 1 },
      { key: "orphan", lastModifiedUnix: 1 },
      { key: "unknown-age", lastModifiedUnix: 0 }, // age unknown → KEEP
      { key: "too-new", lastModifiedUnix: 999 }, // inside grace → KEEP
    ];
    const referenced = new Set(["referenced"]);
    expect(planBlobGc(objects, referenced, now, 60)).toEqual(["orphan"]);
  });
});

describe("pinnedVersions", () => {
  test("collects each channel's target version", () => {
    const channels: StoredAssetChannel[] = [
      {
        id: "1",
        tenantId: "t",
        assetType: "tool",
        name: "cli",
        channel: "stable",
        version: "v1",
        updatedAtUnix: 0,
      },
      {
        id: "2",
        tenantId: "t",
        assetType: "tool",
        name: "cli",
        channel: "latest",
        version: "v2",
        updatedAtUnix: 0,
      },
    ];
    expect([...pinnedVersions(channels)].sort()).toEqual(["v1", "v2"]);
  });
});
