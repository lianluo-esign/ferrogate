/**
 * The DURABLE asset registry (`src/assets/d1.ts`) against a REAL D1 in
 * `workerd`, using the deployed tenant migration — never a fixture schema.
 *
 * Two things are being proved here, and they are different things:
 *
 *  1. **Conformance.** `D1AssetMetadataStore` and `InMemoryAssetMetadataStore`
 *     are driven through ONE shared body (`describe.each`), so every lifecycle
 *     outcome — `already_exists` vs `over_quota`, `blocked_by_channel` vs
 *     `not_found`, `referenced_by_channel`, `not_pending`,
 *     `target_not_resolvable` — is asserted identically on both. The in-memory
 *     store is the local-dev default; if the two ever disagree, the offline
 *     posture stops predicting the deployed one and every asset test that uses
 *     the harness is proving something about the wrong object.
 *
 *  2. **The properties only the durable one can have.** Persistence across
 *     store instances (a new isolate sees the row), and the concurrency guards
 *     that the single-turn in-memory store gets for free from JS but D1 has to
 *     buy with an in-statement predicate.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import {
  ASSET_CREATE_WITHIN_QUOTA_SQL,
  type AssetDatabase,
  D1AssetAuditSink,
  D1AssetMetadataStore,
  assetAuditSinkFromEnv,
  isAssetDatabase,
  sweepAssetAuditProjections,
} from "../../src/assets/d1.js";
import {
  type AssetAuditEvent,
  type AssetMetadataStore,
  InMemoryAssetAuditSink,
  InMemoryAssetMetadataStore,
  type StoredAsset,
} from "../../src/assets/ports.js";
import { evidenceProjectionKey } from "../../src/requestlog/d1.js";
import { resolverForEnv } from "../../src/tenancy/index.js";
import { tenantObjectDb } from "../tenant-object.js";

const NOW = 1_700_000_000;
const TENANT = "tenant_assets_d1";

function db(): AssetDatabase {
  const binding = (env as { DB?: unknown }).DB;
  if (!isAssetDatabase(binding)) {
    // Loud, never a silent skip: `DB` is declared in `apps/gateway/wrangler.toml`
    // and the migration is applied by `test/setup-d1.ts`. An absent binding here
    // means the durable asset registry has no database and the suite is about to
    // prove something other than what it claims.
    throw new Error("expected the `DB` binding (apps/gateway/wrangler.toml) to be a D1 database");
  }
  return binding;
}

async function truncate(): Promise<void> {
  const database = db();
  await database.prepare("DELETE FROM stored_assets").bind().all();
  await database.prepare("DELETE FROM asset_channels").bind().all();
}

/** A row shaped exactly as `AssetService.putAsset` builds it. */
function asset(overrides: Partial<StoredAsset> = {}): StoredAsset {
  const name = overrides.name ?? "cli";
  const version = overrides.version ?? "1.0.0";
  const variant = overrides.variant ?? "";
  const assetType = overrides.asset_type ?? "binaries";
  const tenantId = overrides.tenant_id ?? TENANT;
  const base = `${tenantId}:${assetType}:${name}:${version}`;
  return {
    id: overrides.id ?? (variant === "" ? base : `${base}:v:${variant}`),
    tenant_id: tenantId,
    asset_type: assetType,
    name,
    version,
    content_type: "application/octet-stream",
    content_hash: "a".repeat(64),
    size_bytes: 100,
    storage_uri: `${tenantId}/${assetType}/${name}/${version}/object`,
    variant,
    yanked: false,
    visibility: "visible",
    created_at_unix: NOW,
    updated_at_unix: NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. Conformance — one body, both stores
// ---------------------------------------------------------------------------

const IMPLEMENTATIONS: readonly [string, () => Promise<AssetMetadataStore>][] = [
  ["InMemoryAssetMetadataStore", async () => new InMemoryAssetMetadataStore()],
  [
    "D1AssetMetadataStore",
    async () => {
      await truncate();
      return new D1AssetMetadataStore(db());
    },
  ],
];

describe.each(IMPLEMENTATIONS)("%s — AssetMetadataStore conformance", (_name, build) => {
  let store: AssetMetadataStore;

  beforeEach(async () => {
    store = await build();
  });

  test("a created row reads back field-for-field", async () => {
    const row = asset({ project_id: "project_1", visibility: "pending_scan" });
    expect(await store.createAssetWithinQuota(row, undefined)).toEqual({ kind: "admitted" });
    expect(await store.getAsset(row.id)).toEqual(row);
  });

  test("OpenAI file metadata survives the durable row round trip", async () => {
    const row = asset({
      asset_type: "openai_file",
      name: "file-test123",
      version: "1",
      metadata: { filename: "notes.txt", purpose: "assistants" },
    });
    expect(await store.createAssetWithinQuota(row, undefined)).toEqual({ kind: "admitted" });
    expect((await store.getAsset(row.id))?.metadata).toEqual({
      filename: "notes.txt",
      purpose: "assistants",
    });
  });

  test("an absent id is null, not a throw", async () => {
    expect(await store.getAsset("tenant_assets_d1:binaries:nope:9.9.9")).toBeNull();
  });

  test("`yanked` survives the round trip as a boolean in both directions", async () => {
    // SQLite has no boolean; a `1` that read back as `false` would un-yank a
    // withdrawn artifact on the next isolate, which is the failure this whole
    // store exists to prevent.
    const row = asset({ yanked: true });
    await store.createAssetWithinQuota(row, undefined);
    const stored = await store.getAsset(row.id);
    expect(stored?.yanked).toBe(true);
    await store.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", false, NOW + 5);
    expect((await store.getAsset(row.id))?.yanked).toBe(false);
  });

  test("listing filters by tenant and optionally by asset type", async () => {
    await store.createAssetWithinQuota(asset({ name: "cli" }), undefined);
    await store.createAssetWithinQuota(asset({ asset_type: "skills", name: "review" }), undefined);
    await store.createAssetWithinQuota(asset({ tenant_id: "tenant_other" }), undefined);

    expect((await store.listAssets(TENANT)).map((row) => row.name).sort()).toEqual([
      "cli",
      "review",
    ]);
    expect((await store.listAssets(TENANT, "skills")).map((row) => row.name)).toEqual(["review"]);
    expect(await store.listAssets("tenant_absent")).toEqual([]);
  });

  test("listWithheldAssets returns exactly the non-visible rows (#379)", async () => {
    await store.createAssetWithinQuota(asset({ name: "clean" }), undefined);
    await store.createAssetWithinQuota(
      asset({ name: "pending", visibility: "pending_scan" }),
      undefined,
    );
    await store.createAssetWithinQuota(
      asset({ name: "bad", visibility: "quarantined" }),
      undefined,
    );

    const withheld = await store.listWithheldAssets(TENANT);
    expect(withheld.map((row) => row.name).sort()).toEqual(["bad", "pending"]);
    expect(withheld.every((row) => row.visibility !== "visible")).toBe(true);
  });

  test("tenantAssetStorageBytesUsed sums that tenant only", async () => {
    await store.createAssetWithinQuota(asset({ name: "a", size_bytes: 40 }), undefined);
    await store.createAssetWithinQuota(asset({ name: "b", size_bytes: 60 }), undefined);
    await store.createAssetWithinQuota(
      asset({ tenant_id: "tenant_other", size_bytes: 999 }),
      undefined,
    );
    expect(await store.tenantAssetStorageBytesUsed(TENANT)).toBe(100);
    expect(await store.tenantAssetStorageBytesUsed("tenant_empty")).toBe(0);
  });

  test("a republish is `already_exists`, and never rewrites the published row", async () => {
    const first = asset({ content_hash: "1".repeat(64) });
    await store.createAssetWithinQuota(first, undefined);
    const forged = asset({ content_hash: "2".repeat(64), size_bytes: 5 });
    expect(await store.createAssetWithinQuota(forged, undefined)).toEqual({
      kind: "already_exists",
    });
    // The immutability guarantee (#260) is that the FIRST bytes stay addressed.
    expect((await store.getAsset(first.id))?.content_hash).toBe("1".repeat(64));
    expect(await store.tenantAssetStorageBytesUsed(TENANT)).toBe(100);
  });

  test("over quota is refused with the arithmetic the caller renders", async () => {
    await store.createAssetWithinQuota(asset({ name: "a", size_bytes: 80 }), 100);
    expect(await store.createAssetWithinQuota(asset({ name: "b", size_bytes: 40 }), 100)).toEqual({
      kind: "over_quota",
      used_bytes: 80,
      attempted_bytes: 40,
      quota_bytes: 100,
    });
    expect(await store.getAsset(asset({ name: "b" }).id)).toBeNull();
  });

  test("an exactly-fitting push is admitted (the boundary is <=, not <)", async () => {
    await store.createAssetWithinQuota(asset({ name: "a", size_bytes: 80 }), 100);
    expect(await store.createAssetWithinQuota(asset({ name: "b", size_bytes: 20 }), 100)).toEqual({
      kind: "admitted",
    });
  });

  test("an undefined quota is unbounded", async () => {
    expect(
      await store.createAssetWithinQuota(asset({ size_bytes: 10_000_000 }), undefined),
    ).toEqual({ kind: "admitted" });
  });

  test("a conflicting id over quota reports the CONFLICT, not the quota", async () => {
    // Both refusals are possible at once; the caller renders 409 immutable
    // rather than 403 quota, because deleting the old version is the fix.
    await store.createAssetWithinQuota(asset({ size_bytes: 100 }), 100);
    expect(await store.createAssetWithinQuota(asset({ size_bytes: 100 }), 100)).toEqual({
      kind: "already_exists",
    });
  });

  test("variant rows of one version coexist under distinct ids", async () => {
    await store.createAssetWithinQuota(asset({ variant: "linux-x64" }), undefined);
    await store.createAssetWithinQuota(asset({ variant: "darwin-arm64" }), undefined);
    expect((await store.listAssets(TENANT)).map((row) => row.variant).sort()).toEqual([
      "darwin-arm64",
      "linux-x64",
    ]);
  });

  // -- channels -------------------------------------------------------------

  test("a channel move onto a resolvable version reports no prior, then the prior", async () => {
    await store.createAssetWithinQuota(asset({ version: "1.0.0" }), undefined);
    await store.createAssetWithinQuota(asset({ version: "1.1.0" }), undefined);

    expect(await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW)).toEqual(
      { kind: "moved", prior_version: undefined },
    );
    expect(
      await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.1.0", NOW + 1),
    ).toEqual({ kind: "moved", prior_version: "1.0.0" });

    const channels = await store.listAssetChannels(TENANT, "binaries", "cli");
    expect(channels).toEqual([
      {
        id: `${TENANT}:binaries:cli:latest`,
        tenant_id: TENANT,
        asset_type: "binaries",
        name: "cli",
        channel: "latest",
        version: "1.1.0",
        updated_at_unix: NOW + 1,
      },
    ]);
  });

  test("a channel cannot be moved onto an absent, yanked or withheld version", async () => {
    await store.createAssetWithinQuota(asset({ version: "1.0.0", yanked: true }), undefined);
    await store.createAssetWithinQuota(
      asset({ version: "1.1.0", visibility: "quarantined" }),
      undefined,
    );
    await store.createAssetWithinQuota(
      asset({ version: "1.2.0", visibility: "pending_scan" }),
      undefined,
    );

    for (const version of ["9.9.9", "1.0.0", "1.1.0", "1.2.0"]) {
      expect(
        await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", version, NOW),
        `version ${version} must not be resolvable`,
      ).toEqual({ kind: "target_not_resolvable" });
    }
    expect(await store.listAssetChannels(TENANT, "binaries", "cli")).toEqual([]);
  });

  test("one yanked variant makes the whole version unresolvable", async () => {
    // A channel points at a VERSION, not a variant, so a client on the yanked
    // platform would otherwise be handed the artifact that was withdrawn.
    await store.createAssetWithinQuota(asset({ variant: "linux-x64" }), undefined);
    await store.createAssetWithinQuota(asset({ variant: "darwin-arm64", yanked: true }), undefined);
    expect(await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW)).toEqual(
      { kind: "target_not_resolvable" },
    );
  });

  test("deleteAssetChannel reports whether a pointer was removed", async () => {
    await store.createAssetWithinQuota(asset(), undefined);
    await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW);
    expect(await store.deleteAssetChannel(`${TENANT}:binaries:cli:latest`)).toBe(true);
    expect(await store.deleteAssetChannel(`${TENANT}:binaries:cli:latest`)).toBe(false);
    expect(await store.listAssetChannels(TENANT, "binaries", "cli")).toEqual([]);
  });

  // -- yank -----------------------------------------------------------------

  test("a yank applies to every variant row of the version", async () => {
    await store.createAssetWithinQuota(asset({ variant: "linux-x64" }), undefined);
    await store.createAssetWithinQuota(asset({ variant: "darwin-arm64" }), undefined);
    expect(
      await store.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", true, NOW + 9),
    ).toEqual({ kind: "applied", variants: 2 });
    const rows = await store.listAssets(TENANT);
    expect(rows.every((row) => row.yanked)).toBe(true);
    expect(rows.every((row) => row.updated_at_unix === NOW + 9)).toBe(true);
  });

  test("a yank is refused while a channel still points at the version", async () => {
    await store.createAssetWithinQuota(asset(), undefined);
    await store.moveAssetChannel(TENANT, "binaries", "cli", "stable", "1.0.0", NOW);
    expect(
      await store.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", true, NOW + 1),
    ).toEqual({ kind: "referenced_by_channel" });
    expect((await store.listAssets(TENANT))[0]?.yanked).toBe(false);
  });

  test("an UNyank is never refused by a channel reference", async () => {
    await store.createAssetWithinQuota(asset({ yanked: true }), undefined);
    // A yanked version cannot be a channel target, so build the reference on a
    // sibling version and unyank through it: unyank only ever makes a version
    // MORE resolvable, so it has no invariant to break.
    expect(
      await store.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", false, NOW + 1),
    ).toEqual({ kind: "applied", variants: 1 });
    await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW + 2);
    expect(
      await store.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", false, NOW + 3),
    ).toEqual({ kind: "applied", variants: 1 });
  });

  test("yanking an unknown version is not_found, not a silent success", async () => {
    expect(await store.setAssetVersionYank(TENANT, "binaries", "cli", "9.9.9", true, NOW)).toEqual({
      kind: "not_found",
    });
  });

  // -- guarded variant delete (§1.5.7's third one) ---------------------------

  test("deleting the last live variant a channel points at is blocked", async () => {
    const only = asset();
    await store.createAssetWithinQuota(only, undefined);
    await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW);
    expect(
      await store.deleteAssetVariantIfUnreferenced(only.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "blocked_by_channel" });
    expect(await store.getAsset(only.id)).not.toBeNull();
  });

  test("deleting one of two live variants a channel points at is allowed", async () => {
    const linux = asset({ variant: "linux-x64" });
    await store.createAssetWithinQuota(linux, undefined);
    await store.createAssetWithinQuota(asset({ variant: "darwin-arm64" }), undefined);
    await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW);
    expect(
      await store.deleteAssetVariantIfUnreferenced(linux.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "deleted" });
    expect(await store.getAsset(linux.id)).toBeNull();
  });

  test("an unreferenced variant deletes, and an absent one is not_found", async () => {
    const only = asset();
    await store.createAssetWithinQuota(only, undefined);
    expect(
      await store.deleteAssetVariantIfUnreferenced(only.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "deleted" });
    expect(
      await store.deleteAssetVariantIfUnreferenced(only.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "not_found" });
  });

  // -- visibility promotion CAS ---------------------------------------------

  test("pending_scan promotes exactly once, then reports the current state", async () => {
    const row = asset({ visibility: "pending_scan" });
    await store.createAssetWithinQuota(row, undefined);
    expect(await store.promotePendingAssetVisibility(row.id, "visible", NOW + 1)).toEqual({
      kind: "promoted",
      to: "visible",
    });
    expect(await store.promotePendingAssetVisibility(row.id, "quarantined", NOW + 2)).toEqual({
      kind: "not_pending",
      current: "visible",
    });
    const stored = await store.getAsset(row.id);
    expect(stored?.visibility).toBe("visible");
    expect(stored?.updated_at_unix).toBe(NOW + 1);
  });

  test("promoting an unknown id is not_found", async () => {
    expect(await store.promotePendingAssetVisibility("nope", "visible", NOW)).toEqual({
      kind: "not_found",
    });
  });
});

// ---------------------------------------------------------------------------
// 2. The properties only the DURABLE store can have
// ---------------------------------------------------------------------------

describe("D1AssetMetadataStore — durability", () => {
  beforeEach(truncate);

  test("a published row and its yank flag survive a new store instance", async () => {
    // This is the whole point of the file: `InMemoryAssetMetadataStore` fails
    // this by construction, because a second instance is a second Map. In
    // production the "second instance" is the next isolate — i.e. the next
    // deploy, which is exactly when a yank must still be in force.
    const writer = new D1AssetMetadataStore(db());
    const row = asset();
    await writer.createAssetWithinQuota(row, undefined);
    await writer.setAssetVersionYank(TENANT, "binaries", "cli", "1.0.0", true, NOW + 1);

    const reader = new D1AssetMetadataStore(db());
    expect((await reader.getAsset(row.id))?.yanked).toBe(true);
    expect(await new InMemoryAssetMetadataStore().getAsset(row.id)).toBeNull();
  });

  test("a channel pointer survives a new store instance", async () => {
    const writer = new D1AssetMetadataStore(db());
    await writer.createAssetWithinQuota(asset(), undefined);
    await writer.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW);

    const reader = new D1AssetMetadataStore(db());
    expect((await reader.listAssetChannels(TENANT, "binaries", "cli"))[0]?.version).toBe("1.0.0");
  });

  test("CONCURRENT pushes cannot jointly overshoot the tenant quota (#371)", async () => {
    // The guard is INSIDE the INSERT. Replace it with a read-then-write pair —
    // `SELECT COALESCE(SUM(size_bytes),0)` then an unconditional INSERT — and
    // all 8 of these observe the same 0 bytes used and all 8 are admitted.
    const store = new D1AssetMetadataStore(db());
    const quota = 350;
    const results = await Promise.all(
      Array.from({ length: 8 }, (_unused, index) =>
        store.createAssetWithinQuota(asset({ name: `cli-${index}`, size_bytes: 100 }), quota),
      ),
    );

    const admitted = results.filter((result) => result.kind === "admitted");
    expect(admitted).toHaveLength(3);
    expect(results.filter((result) => result.kind === "over_quota")).toHaveLength(5);
    const used = await store.tenantAssetStorageBytesUsed(TENANT);
    expect(used).toBe(300);
    expect(used).toBeLessThanOrEqual(quota);
  });

  test("CONCURRENT first pushes of one version admit exactly one (#369)", async () => {
    const store = new D1AssetMetadataStore(db());
    const results = await Promise.all(
      Array.from({ length: 5 }, (_unused, index) =>
        store.createAssetWithinQuota(
          asset({ content_hash: String(index).repeat(64).slice(0, 64) }),
          undefined,
        ),
      ),
    );
    expect(results.filter((result) => result.kind === "admitted")).toHaveLength(1);
    expect(results.filter((result) => result.kind === "already_exists")).toHaveLength(4);
    expect(await store.listAssets(TENANT)).toHaveLength(1);
  });

  test("the create statement carries the quota predicate and the conflict clause", async () => {
    // Pins the SHAPE, so a refactor that turns the single statement back into a
    // read-then-write pair is a diff on an assertion, not a silent regression.
    expect(ASSET_CREATE_WITHIN_QUOTA_SQL).toContain("ON CONFLICT DO NOTHING");
    expect(ASSET_CREATE_WITHIN_QUOTA_SQL).toContain("RETURNING id");
    expect(ASSET_CREATE_WITHIN_QUOTA_SQL).toContain("SELECT COALESCE(SUM(size_bytes), 0)");
  });

  test("isAssetDatabase demands `batch`, not merely `prepare`", async () => {
    // `moveAssetChannel` reads the prior version and upserts in ONE
    // transaction. A handle with `prepare` alone would lose that silently, so
    // the probe that decides whether to build the durable store refuses it.
    expect(isAssetDatabase({ prepare: () => undefined })).toBe(false);
    expect(isAssetDatabase({ prepare: () => undefined, batch: () => undefined })).toBe(true);
    expect(isAssetDatabase(undefined)).toBe(false);
  });

  test("a YANKED sibling does not count as the surviving reference", async () => {
    // Both halves of §1.5.7's third guarded delete are asserted here rather
    // than in the shared body because the state is NOT reachable through the
    // store's own API: `setAssetVersionYank` refuses while a channel points at
    // the version, so "channel → version, one variant yanked" can only arrive
    // from a row written outside this store (a legacy import, or a future
    // admin path). The clause is the defense against exactly that, and the
    // fixture therefore writes the row directly.
    //
    // Without it the delete would leave the channel pointing at a version
    // whose only remaining variant is withdrawn — a live pointer to nothing
    // servable.
    const database = db();
    const store = new D1AssetMetadataStore(database);
    const linux = asset({ variant: "linux-x64" });
    const darwin = asset({ variant: "darwin-arm64" });
    await store.createAssetWithinQuota(linux, undefined);
    await store.createAssetWithinQuota(darwin, undefined);
    await store.moveAssetChannel(TENANT, "binaries", "cli", "latest", "1.0.0", NOW);
    await database
      .prepare("UPDATE stored_assets SET yanked = 1 WHERE id = ?1")
      .bind(darwin.id)
      .all();

    expect(
      await store.deleteAssetVariantIfUnreferenced(linux.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "blocked_by_channel" });
    expect(await store.getAsset(linux.id)).not.toBeNull();

    // The in-memory reference store answers identically on the same state, so
    // the two backends still agree where the shared body cannot reach.
    const memory = new InMemoryAssetMetadataStore();
    memory.assets.set(linux.id, linux);
    memory.assets.set(darwin.id, { ...darwin, yanked: true });
    memory.channels.set(`${TENANT}:binaries:cli:latest`, {
      id: `${TENANT}:binaries:cli:latest`,
      tenant_id: TENANT,
      asset_type: "binaries",
      name: "cli",
      channel: "latest",
      version: "1.0.0",
      updated_at_unix: NOW,
    });
    expect(
      await memory.deleteAssetVariantIfUnreferenced(linux.id, TENANT, "binaries", "cli", "1.0.0"),
    ).toEqual({ kind: "blocked_by_channel" });
  });

  test("an unknown visibility token reads as quarantined, never as visible", async () => {
    // The column is free TEXT with no CHECK, so a legacy/garbled value has to
    // mean something. It means "withhold".
    const database = db();
    const row = asset();
    await new D1AssetMetadataStore(database).createAssetWithinQuota(row, undefined);
    await database
      .prepare("UPDATE stored_assets SET visibility = ?2 WHERE id = ?1")
      .bind(row.id, "some_future_state")
      .all();
    const stored = await new D1AssetMetadataStore(database).getAsset(row.id);
    expect(stored?.visibility).toBe("quarantined");
    expect(await new D1AssetMetadataStore(database).listWithheldAssets(TENANT)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 3. The durable audit sink — `audit_events` on the CONTROL D1
// ---------------------------------------------------------------------------

describe("D1AssetAuditSink", () => {
  function control(): AssetDatabase {
    const binding = (env as { CONTROL_DB?: unknown }).CONTROL_DB;
    if (!isAssetDatabase(binding)) {
      throw new Error("expected the `CONTROL_DB` binding (apps/gateway/wrangler.toml)");
    }
    return binding;
  }

  function auditEvent(overrides: Partial<AssetAuditEvent> = {}): AssetAuditEvent {
    return {
      action: "asset.push",
      target: `${TENANT}:binaries:cli:1.0.0`,
      outcome: "committed",
      message: "scan=clean",
      tenantId: TENANT,
      requestId: "req_1",
      occurredAtUnix: NOW,
      ...overrides,
    };
  }

  beforeEach(async () => {
    await control().prepare("DELETE FROM audit_events").bind().all();
    await tenantObjectDb(TENANT).prepare("DELETE FROM audit_events").run();
  });

  test("nothing is written until flush, and then everything is", async () => {
    // The buffering is what lets `record` stay synchronous at 24 call sites in
    // `service.ts` without an `await` in a `return fail(...)` path.
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent({ target: "a" }));
    sink.record(auditEvent({ target: "b" }));

    const before = await control().prepare("SELECT id FROM audit_events").bind().all();
    expect(before.results ?? []).toHaveLength(0);

    await sink.flush();
    const after = await control().prepare("SELECT audit_json FROM audit_events").bind().all();
    expect(after.results ?? []).toHaveLength(2);
  });

  test("a second flush writes nothing — the drain is not a re-read", async () => {
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent());
    await sink.flush();
    await sink.flush();
    const rows = await control().prepare("SELECT id FROM audit_events").bind().all();
    expect(rows.results ?? []).toHaveLength(1);
  });

  test("a CONTROL_DB without TENANT_DATA fails closed for tenant audit", async () => {
    const sink = assetAuditSinkFromEnv({ CONTROL_DB: control() });
    if (sink === null) throw new Error("expected the configured audit sink");
    if (sink.flush === undefined) throw new Error("expected the configured audit sink to flush");
    sink.record(auditEvent());
    await expect(sink.flush()).rejects.toThrow("tenant audit object is unavailable");
    const rows = await control().prepare("SELECT id FROM audit_events").bind().all();
    expect(rows.results ?? []).toHaveLength(0);
  });

  test("the row carries the request id and the #522 agent-run correlation", async () => {
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent({ requestId: "req_522", agentRunId: "run_522" }));
    sink.record(auditEvent({ requestId: "req_plain", target: "other" }));
    await sink.flush();

    const rows = await control()
      .prepare("SELECT request_id, agent_run_id, tenant FROM audit_events ORDER BY request_id ASC")
      .bind()
      .all();
    expect(rows.results).toEqual([
      { request_id: "req_522", agent_run_id: "run_522", tenant: TENANT },
      // An absent correlation id is SQL NULL, never the string "undefined" —
      // the admin query that joins on it must not match a literal.
      { request_id: "req_plain", agent_run_id: null, tenant: TENANT },
    ]);
  });

  test("screeningEvidence reads back a committed push written by ANOTHER instance", async () => {
    // #379's whole point: the push is screened in one isolate and the withheld
    // listing is served by another. The in-memory sink answers `undefined` for
    // every such request.
    const writer = new D1AssetAuditSink(control());
    writer.record(auditEvent({ target: "asset_1", message: "scan=clean sig=absent" }));
    await writer.flush();

    const reader = new D1AssetAuditSink(control());
    expect(await reader.screeningEvidence(TENANT)).toEqual(
      new Map([["asset_1", "scan=clean sig=absent"]]),
    );
    expect(await new InMemoryAssetAuditSink().screeningEvidence(TENANT)).toEqual(new Map());
  });

  test("the LATEST verdict per target wins", async () => {
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent({ target: "asset_1", message: "first", occurredAtUnix: NOW }));
    sink.record(auditEvent({ target: "asset_1", message: "latest", occurredAtUnix: NOW + 10 }));
    await sink.flush();
    expect(await sink.screeningEvidence(TENANT)).toEqual(new Map([["asset_1", "latest"]]));
  });

  test("only committed pushes are evidence, and only this tenant's", async () => {
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent({ target: "committed" }));
    sink.record(auditEvent({ target: "rejected", outcome: "rejected_commit" }));
    sink.record(auditEvent({ target: "yanked", action: "asset.yank" }));
    sink.record(auditEvent({ target: "other_tenant", tenantId: "tenant_else" }));
    await sink.flush();
    expect([...(await sink.screeningEvidence(TENANT)).keys()]).toEqual(["committed"]);
  });

  test("a malformed audit_json row is skipped, never thrown on", async () => {
    // The listing is a read surface; one corrupt row must not 500 the page.
    await control()
      .prepare(
        "INSERT INTO audit_events (projection_key, id, request_id, tenant, occurred_at_unix, audit_json) " +
          "VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      )
      .bind(
        evidenceProjectionKey(TENANT, "aud_broken"),
        "aud_broken",
        "req_x",
        TENANT,
        NOW + 99,
        "{not json",
      )
      .all();
    const sink = new D1AssetAuditSink(control());
    sink.record(auditEvent({ target: "good" }));
    await sink.flush();
    expect([...(await sink.screeningEvidence(TENANT)).keys()]).toEqual(["good"]);
  });

  test("a fallback sink still sees every event", async () => {
    // Local-dev composition: keep the bounded in-memory ring for `wrangler
    // dev` introspection while the durable rows are the record of truth.
    const memory = new InMemoryAssetAuditSink();
    const sink = new D1AssetAuditSink(control(), memory);
    sink.record(auditEvent({ target: "asset_1" }));
    expect(memory.events).toHaveLength(1);
    await sink.flush();
    expect(
      (await control().prepare("SELECT id FROM audit_events").bind().all()).results,
    ).toHaveLength(1);
  });

  test("the scheduled repair pages through all tenant audit rows", async () => {
    const tenant = tenantObjectDb(TENANT);
    await tenant.batch(
      Array.from({ length: 3 }, (_, index) =>
        tenant
          .prepare(
            "INSERT INTO audit_events " +
              "(id, request_id, tenant, occurred_at_unix, audit_json, chain_key, seq, prev_hash, row_hash) " +
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(
            `asset-audit-${index}`,
            `asset-request-${index}`,
            TENANT,
            NOW + index,
            JSON.stringify({ action: "asset.push", target: `asset-${index}`, outcome: "committed" }),
            TENANT,
            index,
            `prev-${index}`,
            `hash-${index}`,
          ),
      ),
    );

    const bindings = env as unknown as Parameters<typeof resolverForEnv>[0];
    await sweepAssetAuditProjections(
      bindings,
      resolverForEnv(bindings).router,
      [TENANT],
      2,
    );

    const count = await control()
      .prepare("SELECT COUNT(*) AS count FROM audit_events WHERE tenant = ?")
      .bind(TENANT)
      .all();
    expect(count.results).toEqual([{ count: 3 }]);
  });
});
