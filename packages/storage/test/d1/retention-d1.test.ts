/**
 * Retention storage + the sweeper executor, against REAL D1 and REAL R2
 * (#263/#284).
 *
 * The planners are pure and already covered by `test/misc.test.ts`. What needs
 * real services is the EXECUTOR, and specifically two properties a fake would
 * assert into existence:
 *
 *   1. the D1 row is deleted BEFORE the R2 object, so a crash leaves a
 *      reclaimable orphan rather than a published 404; and
 *   2. the sweep re-reads channel pins from the database instead of trusting a
 *      caller, so a publish that lands mid-sweep is not deleted.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1AssetMetadataStore,
  D1RetentionPolicyStore,
  R2AssetBlobStore,
  RETENTION_RESOURCE_ASSET,
  RETENTION_SCOPE_DEFAULT,
  type StoredAsset,
  type StoredRetentionPolicy,
  type TenantDatabaseHandle,
  assetChannelId,
  retentionPolicyId,
  retentionPolicyOf,
  storedAssetVariantId,
  sweepAssetRetention,
  sweepOrphanBlobs,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupTenantRouter, tenantDb } from "./harness.js";

declare module "cloudflare:test" {
  interface ProvidedEnv {
    ASSETS_BUCKET: R2Bucket;
  }
}

const NOW = 1_784_073_600;
const DAY = 86_400;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;
let policies: D1RetentionPolicyStore;
let assets: D1AssetMetadataStore;
let blobs: R2AssetBlobStore;

beforeAll(async () => {
  const router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
  policies = new D1RetentionPolicyStore(handleA);
  assets = new D1AssetMetadataStore(handleA);
  blobs = new R2AssetBlobStore(env.ASSETS_BUCKET);
});

beforeEach(async () => {
  await resetTenantData(tenantDb(TENANT_A));
  await resetTenantData(tenantDb(TENANT_B));
  for (const object of (await env.ASSETS_BUCKET.list({ prefix: "assets/" })).objects) {
    await env.ASSETS_BUCKET.delete(object.key);
  }
});

function policy(overrides: Partial<StoredRetentionPolicy> = {}): StoredRetentionPolicy {
  return {
    id: retentionPolicyId(TENANT_A, RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT),
    tenantId: TENANT_A,
    resourceType: RETENTION_RESOURCE_ASSET,
    scope: RETENTION_SCOPE_DEFAULT,
    keepLastN: 2,
    maxAgeSecs: undefined,
    minAgeSecs: 0,
    createdAtUnix: NOW,
    updatedAtUnix: NOW,
    ...overrides,
  };
}

async function publish(version: string, createdAtUnix: number): Promise<StoredAsset> {
  const storageUri = `assets/${TENANT_A}/skill/summarize/${version}`;
  const asset: StoredAsset = {
    id: storedAssetVariantId(TENANT_A, "skill", "summarize", version, ""),
    tenantId: TENANT_A,
    assetType: "skill",
    name: "summarize",
    version,
    variant: "",
    contentType: "application/zip",
    contentHash: `hash-${version}`,
    sizeBytes: 10,
    content: new Uint8Array(0),
    storageUri,
    yanked: false,
    visibility: "visible",
    createdAtUnix,
    updatedAtUnix: createdAtUnix,
  };
  await env.ASSETS_BUCKET.put(storageUri, new Uint8Array([1, 2, 3]));
  await assets.upsertAsset(asset);
  return asset;
}

const line = { tenantId: TENANT_A, assetType: "skill", name: "summarize" };

describe("D1RetentionPolicyStore", () => {
  test("round-trips a rule, including the NULL dimensions", async () => {
    const p = policy({ keepLastN: undefined, maxAgeSecs: 30 * DAY, minAgeSecs: DAY });
    await policies.setRetentionPolicy(p);
    expect(await policies.getRetentionPolicy(TENANT_A, RETENTION_RESOURCE_ASSET, "*")).toEqual(p);
  });

  test("setting the same triple REPLACES rather than accumulating a rival rule", async () => {
    await policies.setRetentionPolicy(policy({ keepLastN: 2 }));
    await policies.setRetentionPolicy(policy({ keepLastN: 5, updatedAtUnix: NOW + 10 }));
    const all = await policies.listRetentionPolicies(TENANT_A);
    // Two contradictory rules for one resource would need a tie-break nobody
    // has specified, and a sweep is unrecoverable.
    expect(all).toHaveLength(1);
    expect(all[0]?.keepLastN).toBe(5);
  });

  test("a replace preserves createdAtUnix", async () => {
    await policies.setRetentionPolicy(policy());
    await policies.setRetentionPolicy(
      policy({ createdAtUnix: NOW + 999, updatedAtUnix: NOW + 10 }),
    );
    expect(
      (await policies.getRetentionPolicy(TENANT_A, RETENTION_RESOURCE_ASSET, "*"))?.createdAtUnix,
    ).toBe(NOW);
  });

  test("list narrows by resource type and orders deterministically", async () => {
    await policies.setRetentionPolicy(policy({ scope: "response_body" }));
    await policies.setRetentionPolicy(policy());
    await policies.setRetentionPolicy(policy({ resourceType: "request_logs" }));
    expect(
      (await policies.listRetentionPolicies(TENANT_A)).map((p) => `${p.resourceType}/${p.scope}`),
    ).toEqual(["asset/*", "asset/response_body", "request_logs/*"]);
    expect(await policies.listRetentionPolicies(TENANT_A, "request_logs")).toHaveLength(1);
  });

  test("rules are per tenant database", async () => {
    await policies.setRetentionPolicy(policy());
    expect(await new D1RetentionPolicyStore(handleB).listRetentionPolicies(TENANT_A)).toEqual([]);
  });

  test("delete reports whether a rule existed", async () => {
    await policies.setRetentionPolicy(policy());
    expect(await policies.deleteRetentionPolicy(TENANT_A, RETENTION_RESOURCE_ASSET, "*")).toBe(
      true,
    );
    expect(await policies.deleteRetentionPolicy(TENANT_A, RETENTION_RESOURCE_ASSET, "*")).toBe(
      false,
    );
  });
});

describe("sweepAssetRetention — the executor", () => {
  test("prunes past keepLastN, newest first, and reports what it freed", async () => {
    await publish("1.0.0", NOW - 4 * DAY);
    await publish("2.0.0", NOW - 3 * DAY);
    await publish("3.0.0", NOW - 2 * DAY);
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 2 })),
      NOW,
    );
    expect(report.plan.targets.map((t) => t.version)).toEqual(["1.0.0"]);
    expect(report.plan.freedBytes).toBe(10);
    expect(report.deletedRowIds).toHaveLength(1);
    expect((await assets.listAssets(TENANT_A, "skill")).map((a) => a.version)).toEqual([
      "2.0.0",
      "3.0.0",
    ]);
  });

  test("deletes the D1 ROW before the R2 OBJECT", async () => {
    await publish("1.0.0", NOW - 4 * DAY);
    await publish("2.0.0", NOW - 3 * DAY);
    await publish("3.0.0", NOW - 2 * DAY);

    // Observe the interleaving directly: an R2 delete that arrives while the
    // row is still live is the ordering that 404s a published name.
    const order: string[] = [];
    const bucketSpy = new Proxy(env.ASSETS_BUCKET, {
      get(target, property, receiver) {
        if (property === "delete") {
          return async (key: string) => {
            const row = await tenantDb(TENANT_A)
              .prepare("SELECT COUNT(*) AS n FROM stored_assets WHERE storage_uri = ?")
              .bind(key)
              .first<{ n: number }>();
            order.push(Number(row?.n) === 0 ? "row-gone-first" : "object-first");
            return target.delete(key);
          };
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    await sweepAssetRetention(
      assets,
      new R2AssetBlobStore(bucketSpy as R2Bucket),
      line,
      retentionPolicyOf(policy({ keepLastN: 2 })),
      NOW,
    );
    expect(order).toEqual(["row-gone-first"]);
    expect(await env.ASSETS_BUCKET.head(`assets/${TENANT_A}/skill/summarize/1.0.0`)).toBeNull();
  });

  test("NEVER prunes a channel-pinned version, however old", async () => {
    const oldest = await publish("1.0.0", NOW - 400 * DAY);
    await publish("2.0.0", NOW - 3 * DAY);
    await publish("3.0.0", NOW - 2 * DAY);
    await assets.upsertAssetChannel({
      id: assetChannelId(TENANT_A, "skill", "summarize", "stable"),
      tenantId: TENANT_A,
      assetType: "skill",
      name: "summarize",
      channel: "stable",
      version: "1.0.0",
      updatedAtUnix: NOW,
    });
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 1, maxAgeSecs: DAY })),
      NOW,
    );
    expect(report.plan.targets.map((t) => t.version)).not.toContain("1.0.0");
    expect(await assets.getAsset(oldest.id)).toBeDefined();
  });

  test("re-reads the pins from D1 — a pin written after the caller looked is honored", async () => {
    // The failure this prevents: a caller passes a pin set captured a moment
    // earlier, `latest` is moved onto an old version in between, and the sweep
    // deletes the version that is now published.
    const target = await publish("1.0.0", NOW - 400 * DAY);
    await publish("2.0.0", NOW - 3 * DAY);
    await assets.upsertAssetChannel({
      id: assetChannelId(TENANT_A, "skill", "summarize", "latest"),
      tenantId: TENANT_A,
      assetType: "skill",
      name: "summarize",
      channel: "latest",
      version: "1.0.0",
      updatedAtUnix: NOW,
    });
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 1 })),
      NOW,
    );
    expect(report.deletedRowIds).toEqual([]);
    expect(await assets.getAsset(target.id)).toBeDefined();
  });

  test("NEVER prunes inside the minAgeSecs grace window", async () => {
    await publish("1.0.0", NOW - 60);
    await publish("2.0.0", NOW - 30);
    await publish("3.0.0", NOW - 10);
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 1, minAgeSecs: DAY })),
      NOW,
    );
    expect(report.deletedRowIds).toEqual([]);
  });

  test("an all-NULL policy is a NO-OP, not a delete-everything", async () => {
    await publish("1.0.0", NOW - 400 * DAY);
    await publish("2.0.0", NOW - 300 * DAY);
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: undefined, maxAgeSecs: undefined })),
      NOW,
    );
    // A half-configured rule must delete nothing rather than everything.
    expect(report.plan.targets).toEqual([]);
    expect(await assets.listAssets(TENANT_A, "skill")).toHaveLength(2);
  });

  test("dryRun produces the plan and deletes NOTHING", async () => {
    await publish("1.0.0", NOW - 4 * DAY);
    await publish("2.0.0", NOW - 3 * DAY);
    await publish("3.0.0", NOW - 2 * DAY);
    const report = await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 1 })),
      NOW,
      { dryRun: true },
    );
    expect(report.plan.targets).toHaveLength(2);
    expect(report.deletedRowIds).toEqual([]);
    expect(report.deletedObjectKeys).toEqual([]);
    expect(await assets.listAssets(TENANT_A, "skill")).toHaveLength(3);
  });

  test("only touches the named asset line", async () => {
    await publish("1.0.0", NOW - 400 * DAY);
    await assets.upsertAsset({
      ...(await publish("1.0.0", NOW - 400 * DAY)),
      id: storedAssetVariantId(TENANT_A, "skill", "other", "1.0.0", ""),
      name: "other",
    });
    await sweepAssetRetention(
      assets,
      blobs,
      line,
      retentionPolicyOf(policy({ keepLastN: 0, maxAgeSecs: DAY })),
      NOW,
    );
    expect((await assets.listAssets(TENANT_A, "skill")).map((a) => a.name)).toEqual(["other"]);
  });
});

describe("sweepOrphanBlobs", () => {
  test("deletes an object no row references, once past the grace window", async () => {
    await publish("1.0.0", NOW - DAY);
    await env.ASSETS_BUCKET.put(`assets/${TENANT_A}/skill/summarize/orphan`, new Uint8Array([9]));
    const deleted = await sweepOrphanBlobs(
      handleA,
      blobs,
      [
        { key: `assets/${TENANT_A}/skill/summarize/1.0.0`, lastModifiedUnix: NOW - DAY },
        { key: `assets/${TENANT_A}/skill/summarize/orphan`, lastModifiedUnix: NOW - DAY },
      ],
      NOW,
      3600,
    );
    expect(deleted).toEqual([`assets/${TENANT_A}/skill/summarize/orphan`]);
    // The referenced object survives — that is the whole point of the read.
    expect(await env.ASSETS_BUCKET.head(`assets/${TENANT_A}/skill/summarize/1.0.0`)).not.toBeNull();
  });

  test("KEEPS an object inside the grace window even when unreferenced", async () => {
    // The second, independent defense against deleting a publish in flight.
    await env.ASSETS_BUCKET.put(`assets/${TENANT_A}/skill/summarize/fresh`, new Uint8Array([9]));
    const deleted = await sweepOrphanBlobs(
      handleA,
      blobs,
      [{ key: `assets/${TENANT_A}/skill/summarize/fresh`, lastModifiedUnix: NOW - 10 }],
      NOW,
      3600,
    );
    expect(deleted).toEqual([]);
    expect(await env.ASSETS_BUCKET.head(`assets/${TENANT_A}/skill/summarize/fresh`)).not.toBeNull();
  });

  test("KEEPS an object whose age is unknown", async () => {
    await env.ASSETS_BUCKET.put(`assets/${TENANT_A}/skill/summarize/mystery`, new Uint8Array([9]));
    expect(
      await sweepOrphanBlobs(
        handleA,
        blobs,
        [{ key: `assets/${TENANT_A}/skill/summarize/mystery`, lastModifiedUnix: 0 }],
        NOW,
        0,
      ),
    ).toEqual([]);
  });
});
