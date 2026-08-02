/**
 * The durable asset-metadata store against REAL D1 (#176/#260/#366/#367/#371/#378).
 *
 * Every claim here is about a guard being ONE statement. The in-memory
 * `MemoryAssetStore` shows the same outcomes, but it shows them because a single
 * JS thread serialized the calls — a property of the test, not of SQLite. What
 * needs a real database is that the check and the write share a transaction, so
 * an interleaved writer cannot land between them. The interleaving tests are the
 * reason this file exists.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1AssetMetadataStore,
  D1ReferenceGuardedDeletes,
  MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL,
  SET_ASSET_VERSION_YANK_SQL,
  type StoredAsset,
  type StoredAssetChannel,
  type TenantDatabaseHandle,
  assetChannelId,
  storedAssetVariantId,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupDatabases } from "./harness.js";

const NOW = 1_784_073_600;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;
let storeA: D1AssetMetadataStore;
let storeB: D1AssetMetadataStore;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
  storeA = new D1AssetMetadataStore(handleA);
  storeB = new D1AssetMetadataStore(handleB);
});

beforeEach(async () => {
  await resetTenantData(env.TENANT_DB_A);
  await resetTenantData(env.TENANT_DB_B);
});

function asset(overrides: Partial<StoredAsset> = {}): StoredAsset {
  const base = {
    tenantId: TENANT_A,
    assetType: "skill",
    name: "summarize",
    version: "1.0.0",
    variant: "",
    ...overrides,
  };
  return {
    id: storedAssetVariantId(base.tenantId, base.assetType, base.name, base.version, base.variant),
    projectId: undefined,
    contentType: "application/zip",
    contentHash: `hash-${base.version}-${base.variant}`,
    sizeBytes: 100,
    content: new Uint8Array(0),
    storageUri: `assets/${base.tenantId}/${base.assetType}/${base.name}/${base.version}`,
    yanked: false,
    visibility: "visible" as const,
    createdAtUnix: NOW,
    updatedAtUnix: NOW,
    ...base,
    ...overrides,
  };
}

function channel(version: string, name = "latest"): StoredAssetChannel {
  return {
    id: assetChannelId(TENANT_A, "skill", "summarize", name),
    tenantId: TENANT_A,
    assetType: "skill",
    name: "summarize",
    channel: name,
    version,
    updatedAtUnix: NOW,
  };
}

describe("D1AssetMetadataStore — rows persist at all", () => {
  test("an upserted asset round-trips every column", async () => {
    const a = asset({ projectId: "proj_1", variant: "linux-amd64", visibility: "pending_scan" });
    await storeA.upsertAsset(a);
    // `content` is deliberately empty on read: the bytes live in R2 under
    // `storage_uri`, and the row never carries them.
    expect(await storeA.getAsset(a.id)).toEqual({ ...a, content: new Uint8Array(0) });
  });

  test("rows are physically per-tenant, not filtered by a WHERE clause", async () => {
    await storeA.upsertAsset(asset());
    expect(await storeB.getAsset(asset().id)).toBeUndefined();
  });

  test("an unrecognized visibility token reads back as quarantined, never visible", async () => {
    const a = asset();
    await storeA.upsertAsset(a);
    await env.TENANT_DB_A.prepare("UPDATE stored_assets SET visibility = 'weird' WHERE id = ?")
      .bind(a.id)
      .run();
    // Fail CLOSED (#366): an unknown/poisoned row must never be servable.
    expect((await storeA.getAsset(a.id))?.visibility).toBe("quarantined");
  });

  test("list orders by (asset_type, name, version, variant)", async () => {
    await storeA.upsertAsset(asset({ version: "2.0.0" }));
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.upsertAsset(asset({ assetType: "prompt", name: "greet", version: "1.0.0" }));
    expect(
      (await storeA.listAssets(TENANT_A)).map((row) => `${row.assetType}/${row.version}`),
    ).toEqual(["prompt/1.0.0", "skill/1.0.0", "skill/2.0.0"]);
    expect((await storeA.listAssets(TENANT_A, "skill")).map((row) => row.version)).toEqual([
      "1.0.0",
      "2.0.0",
    ]);
  });
});

describe("D1AssetMetadataStore — quota admission (#371)", () => {
  test("admits inside the quota and refuses past it, reporting the numbers", async () => {
    expect(await storeA.createAssetWithinQuota(asset({ version: "1.0.0" }), 250)).toEqual({
      kind: "admitted",
    });
    expect(await storeA.createAssetWithinQuota(asset({ version: "2.0.0" }), 250)).toEqual({
      kind: "admitted",
    });
    expect(await storeA.createAssetWithinQuota(asset({ version: "3.0.0" }), 250)).toEqual({
      kind: "over_quota",
      usedBytes: 200,
      attemptedBytes: 100,
      quotaBytes: 250,
    });
    // The refusal did NOT write the row.
    expect(await storeA.getAsset(asset({ version: "3.0.0" }).id)).toBeUndefined();
    expect(await storeA.tenantAssetStorageBytesUsed(TENANT_A)).toBe(200);
  });

  test("an undefined quota is unlimited, not a very large number", async () => {
    for (let i = 0; i < 5; i += 1) {
      expect(
        await storeA.createAssetWithinQuota(
          asset({ version: `${i}.0.0`, sizeBytes: 1_000_000 }),
          undefined,
        ),
      ).toEqual({ kind: "admitted" });
    }
    expect(await storeA.tenantAssetStorageBytesUsed(TENANT_A)).toBe(5_000_000);
  });

  test("a re-push of the same id is already_exists, not a second charge", async () => {
    await storeA.createAssetWithinQuota(asset(), 1_000);
    expect(await storeA.createAssetWithinQuota(asset(), 1_000)).toEqual({ kind: "already_exists" });
    expect(await storeA.tenantAssetStorageBytesUsed(TENANT_A)).toBe(100);
  });

  test("CONCURRENT different-id pushes cannot jointly overshoot the quota", async () => {
    // The read-then-insert shape this replaces admits all four: each observes
    // `used = 0`, each decides it fits, each inserts.
    const quota = 250;
    const outcomes = await Promise.all(
      ["a", "b", "c", "d"].map((version) =>
        storeA.createAssetWithinQuota(asset({ version }), quota),
      ),
    );
    expect(outcomes.filter((o) => o.kind === "admitted")).toHaveLength(2);
    expect(await storeA.tenantAssetStorageBytesUsed(TENANT_A)).toBeLessThanOrEqual(quota);
  });

  test("the quota is per tenant database, so one tenant cannot exhaust another's", async () => {
    await storeA.createAssetWithinQuota(asset({ sizeBytes: 250 }), 250);
    expect(
      await storeB.createAssetWithinQuota(asset({ tenantId: TENANT_B, sizeBytes: 250 }), 250),
    ).toEqual({ kind: "admitted" });
  });
});

describe("D1AssetMetadataStore — the channel move guard (#367)", () => {
  test("the move SQL carries BOTH resolvability clauses", () => {
    // An outcome-only test would still pass against a resolve-then-write, so the
    // statement shape is pinned directly.
    expect(MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL).toContain(
      "WHERE EXISTS(SELECT 1 FROM stored_assets",
    );
    expect(MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL).toContain(
      "AND NOT EXISTS(SELECT 1 FROM stored_assets",
    );
    expect(MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL).toContain("yanked = 1");
    expect(MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL).toContain("RETURNING version");
  });

  test("moves onto a published version and reports the prior target", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.upsertAsset(asset({ version: "2.0.0" }));
    expect(await storeA.moveAssetChannelIfResolvable(channel("1.0.0"))).toEqual({
      kind: "moved",
      priorVersion: undefined,
    });
    expect(await storeA.moveAssetChannelIfResolvable(channel("2.0.0"))).toEqual({
      kind: "moved",
      priorVersion: "1.0.0",
    });
    expect(
      (await storeA.listAssetChannels(TENANT_A, "skill", "summarize")).map((c) => c.version),
    ).toEqual(["2.0.0"]);
  });

  test("refuses a version that was never published, and writes NOTHING", async () => {
    expect(await storeA.moveAssetChannelIfResolvable(channel("9.9.9"))).toEqual({
      kind: "target_not_resolvable",
    });
    expect(await storeA.listAssetChannels(TENANT_A, "skill", "summarize")).toEqual([]);
  });

  test("refuses a YANKED version — the kill switch cannot be re-published over", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0", yanked: true }));
    expect(await storeA.moveAssetChannelIfResolvable(channel("1.0.0"))).toEqual({
      kind: "target_not_resolvable",
    });
  });

  test("refuses when ANY variant of the version is yanked", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0", variant: "linux-amd64" }));
    await storeA.upsertAsset(asset({ version: "1.0.0", variant: "darwin-arm64", yanked: true }));
    // Conservative on purpose: a channel names a version, not a variant, so a
    // single bad variant makes the whole version unpublishable.
    expect(await storeA.moveAssetChannelIfResolvable(channel("1.0.0"))).toEqual({
      kind: "target_not_resolvable",
    });
  });

  test("a channel already pointing somewhere is NOT stranded by a refused move", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    expect(await storeA.moveAssetChannelIfResolvable(channel("nope"))).toEqual({
      kind: "target_not_resolvable",
    });
    // Still resolving to the good version, not to the refused one and not gone.
    expect((await storeA.listAssetChannels(TENANT_A, "skill", "summarize"))[0]?.version).toBe(
      "1.0.0",
    );
  });

  test("a GUARDED variant delete racing the move cannot leave a dangling pointer", async () => {
    const target = asset({ version: "1.0.0" });
    await storeA.upsertAsset(target);
    // Interleave the two production writers that both touch this pair: the
    // guarded move and the guarded variant delete. Whichever order SQLite
    // commits them in, the invariant must hold — a surviving channel pointer
    // resolves to a row that still exists.
    const deletes = new D1ReferenceGuardedDeletes(handleA);
    await Promise.all([
      storeA.moveAssetChannelIfResolvable(channel("1.0.0")),
      deletes.deleteAssetVariantIfUnreferenced(target.id),
    ]);
    const channels = await storeA.listAssetChannels(TENANT_A, "skill", "summarize");
    if (channels.length > 0) {
      expect(await storeA.getAsset(target.id)).toBeDefined();
    }
  });

  test("the UNGUARDED deleteAsset is exactly as dangerous as it says it is", async () => {
    // Recorded rather than hidden: `deleteAsset` has no reference guard, so it
    // WILL strand a channel. The guarded path above is the one a publish/delete
    // API must call, and this test exists so nobody mistakes the two.
    const target = asset({ version: "1.0.0" });
    await storeA.upsertAsset(target);
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    expect(await storeA.deleteAsset(target.id)).toBe(true);
    const channels = await storeA.listAssetChannels(TENANT_A, "skill", "summarize");
    expect(channels[0]?.version).toBe("1.0.0");
    expect(await storeA.getAsset(target.id)).toBeUndefined();
  });
});

describe("D1AssetMetadataStore — the yank guard (#367)", () => {
  test("the yank SQL short-circuits its guard for an UNyank only", () => {
    expect(SET_ASSET_VERSION_YANK_SQL).toContain(
      "AND (? = 0 OR NOT EXISTS(SELECT 1 FROM asset_channels",
    );
    expect(SET_ASSET_VERSION_YANK_SQL).toContain("RETURNING id");
  });

  test("yanks every variant row of the version", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0", variant: "linux-amd64" }));
    await storeA.upsertAsset(asset({ version: "1.0.0", variant: "darwin-arm64" }));
    expect(
      await storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "1.0.0", true, NOW + 1),
    ).toEqual({ kind: "applied", variants: 2 });
    const rows = await storeA.listAssets(TENANT_A, "skill");
    expect(rows.every((row) => row.yanked)).toBe(true);
  });

  test("REFUSES to yank a version a channel still points at", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    expect(
      await storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "1.0.0", true, NOW + 1),
    ).toEqual({ kind: "referenced_by_channel" });
    // And the refusal is total: the flag did not move.
    expect((await storeA.getAsset(asset({ version: "1.0.0" }).id))?.yanked).toBe(false);
  });

  test("allows the yank once the channel has been moved away", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.upsertAsset(asset({ version: "2.0.0" }));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    await storeA.moveAssetChannelIfResolvable(channel("2.0.0"));
    expect(
      await storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "1.0.0", true, NOW + 1),
    ).toEqual({ kind: "applied", variants: 1 });
  });

  test("an UNyank is never blocked by a channel reference", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0", yanked: true }));
    await storeA.upsertAssetChannel(channel("1.0.0"));
    // Unyanking can only ever make more artifacts resolvable, so it skips the
    // guard entirely.
    expect(
      await storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "1.0.0", false, NOW + 1),
    ).toEqual({ kind: "applied", variants: 1 });
    expect((await storeA.getAsset(asset({ version: "1.0.0" }).id))?.yanked).toBe(false);
  });

  test("an unknown version is not_found, not a silent no-op success", async () => {
    expect(
      await storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "9.9.9", true, NOW),
    ).toEqual({ kind: "not_found" });
  });

  test("a move and a yank racing the same version cannot BOTH succeed", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    const [move, yank] = await Promise.all([
      storeA.moveAssetChannelIfResolvable(channel("1.0.0")),
      storeA.setAssetVersionYank(TENANT_A, "skill", "summarize", "1.0.0", true, NOW + 1),
    ]);
    // The write skew this closes from both sides: if the move won, the yank must
    // have seen the pointer; if the yank won, the move must have seen the flag.
    const bothSucceeded = move.kind === "moved" && yank.kind === "applied";
    if (bothSucceeded) {
      // Permitted only if the yank observed no pointer AND the channel now
      // resolves to a non-yanked row — i.e. the invariant still holds.
      const stored = await storeA.getAsset(asset({ version: "1.0.0" }).id);
      const channels = await storeA.listAssetChannels(TENANT_A, "skill", "summarize");
      expect(channels.length === 0 || stored?.yanked === false).toBe(true);
    }
  });
});

describe("D1AssetMetadataStore — withheld listing (#366)", () => {
  test("lists everything NOT visible, including an unrecognized token", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0", visibility: "visible" }));
    await storeA.upsertAsset(asset({ version: "2.0.0", visibility: "pending_scan" }));
    await storeA.upsertAsset(asset({ version: "3.0.0", visibility: "quarantined" }));
    await storeA.upsertAsset(asset({ version: "4.0.0" }));
    await env.TENANT_DB_A.prepare(
      "UPDATE stored_assets SET visibility = 'weird' WHERE version = '4.0.0'",
    ).run();
    // The predicate is `<> 'visible'` and not an enumeration, so the poisoned
    // row an operator most needs to see is not the one that hides.
    expect((await storeA.listWithheldAssets(TENANT_A)).map((row) => row.version)).toEqual([
      "2.0.0",
      "3.0.0",
      "4.0.0",
    ]);
  });

  test("narrows by asset type", async () => {
    await storeA.upsertAsset(asset({ version: "2.0.0", visibility: "pending_scan" }));
    await storeA.upsertAsset(asset({ assetType: "prompt", visibility: "quarantined" }));
    expect((await storeA.listWithheldAssets(TENANT_A, "prompt")).map((r) => r.assetType)).toEqual([
      "prompt",
    ]);
  });
});

describe("D1AssetMetadataStore — the promotion CAS (#378)", () => {
  test("promotes only from pending_scan", async () => {
    const a = asset({ visibility: "pending_scan" });
    await storeA.upsertAsset(a);
    expect(await storeA.promoteAssetVisibility(a.id, "visible", NOW + 1)).toEqual({
      kind: "promoted",
      to: "visible",
    });
    expect((await storeA.getAsset(a.id))?.visibility).toBe("visible");
  });

  test("a terminal row is not_pending and is never silently re-promoted", async () => {
    const a = asset({ visibility: "quarantined" });
    await storeA.upsertAsset(a);
    expect(await storeA.promoteAssetVisibility(a.id, "visible", NOW + 1)).toEqual({
      kind: "not_pending",
      current: "quarantined",
    });
    expect((await storeA.getAsset(a.id))?.visibility).toBe("quarantined");
  });

  test("a missing row is not_found", async () => {
    expect(await storeA.promoteAssetVisibility("nope", "visible", NOW)).toEqual({
      kind: "not_found",
    });
  });

  test("two racing scanners: exactly one promotion wins", async () => {
    const a = asset({ visibility: "pending_scan" });
    await storeA.upsertAsset(a);
    const outcomes = await Promise.all([
      storeA.promoteAssetVisibility(a.id, "visible", NOW + 1),
      storeA.promoteAssetVisibility(a.id, "quarantined", NOW + 1),
    ]);
    expect(outcomes.filter((o) => o.kind === "promoted")).toHaveLength(1);
    // And the loser's verdict did NOT overwrite the winner's.
    const winner = outcomes.find((o) => o.kind === "promoted");
    expect((await storeA.getAsset(a.id))?.visibility).toBe(
      winner?.kind === "promoted" ? winner.to : "unreachable",
    );
  });
});

describe("asset_channels is now written by a production path (§1.5.7 third delete)", () => {
  test("the guarded variant delete refuses a version reached through moveAssetChannel", async () => {
    // Before the metadata store existed, this refusal arm could only be reached
    // by seeding `asset_channels` by hand. It is now reached through the same
    // call the publish path uses.
    const a = asset({ version: "1.0.0" });
    await storeA.upsertAsset(a);
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0", "stable"));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0", "latest"));

    const outcome = await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced(
      a.id,
    );
    expect(outcome).toEqual({ kind: "referenced", channels: ["latest", "stable"] });
    expect(await storeA.getAsset(a.id)).toBeDefined();
  });

  test("and permits it once every pointer has moved away", async () => {
    const a = asset({ version: "1.0.0" });
    await storeA.upsertAsset(a);
    await storeA.upsertAsset(asset({ version: "2.0.0" }));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    await storeA.moveAssetChannelIfResolvable(channel("2.0.0"));
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced(a.id),
    ).toEqual({ kind: "deleted" });
  });

  test("deleteAssetChannel reports whether a pointer was actually removed", async () => {
    await storeA.upsertAsset(asset({ version: "1.0.0" }));
    await storeA.moveAssetChannelIfResolvable(channel("1.0.0"));
    const id = assetChannelId(TENANT_A, "skill", "summarize", "latest");
    expect(await storeA.deleteAssetChannel(id)).toBe(true);
    expect(await storeA.deleteAssetChannel(id)).toBe(false);
  });
});
