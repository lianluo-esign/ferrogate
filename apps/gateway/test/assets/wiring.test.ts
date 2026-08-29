/**
 * ANTI-UNMOUNT for the durable asset registry.
 *
 * The defect class this project keeps shipping is a module that is fully
 * implemented and fully tested but never reachable from the app the Worker
 * exports. `test/assets/d1.test.ts` proves `D1AssetMetadataStore` CORRECT; it
 * proves nothing about whether the deployed data plane uses it. Before this
 * slice the asset registry was `InMemoryAssetMetadataStore` in production and
 * every one of the 200-odd asset assertions was green, because they all build
 * their own harness.
 *
 * So this file drives the REAL exported Worker over `SELF.fetch` — real
 * contract router, real auth middleware, real R2 binding, real D1 — pushes an
 * asset, and then reads `stored_assets` out of the authenticated tenant's
 * Durable Object DIRECTLY. If the route stops replacing its standalone D1
 * store with the tenant facade, the push still answers 200 (the shared or
 * in-memory fallback accepts it) but the object row is absent: the assertion
 * below goes red for the right reason.
 *
 * The same gate covers the durable AUDIT sink, which has one extra way to be
 * unmounted: the sink buffers and is committed by `await
 * serviceFor(c).flushAudit()` in the route module's `on()` wrapper, so DELETING
 * THE FLUSH leaves a sink that is wired, correct, exercised — and writes
 * nothing. That line is a mount too, and it is gated here.
 *
 * Mutation-proven, three ways, each RED here and GREEN across the rest of the
 * asset suite:
 *   1. delete `...(metadata !== null ? { metadata } : {})` from `assetDepsFromEnv`
 *   2. delete `...(audit !== null ? { audit } : {})` from `assetDepsFromEnv`
 *   3. delete `await serviceFor(context).flushAudit()` from `on()`
 */
import { SELF, env } from "cloudflare:test";
import {
  D1RetentionPolicyStore,
  RETENTION_RESOURCE_ASSET,
  RETENTION_SCOPE_DEFAULT,
  type StoredRetentionPolicy,
  retentionPolicyId,
} from "@ferrogate/storage";
import { beforeEach, describe, expect, test } from "vitest";
import tenantRegistryMigrationSql from "../../../../sql/d1-ts/control/0012_tenant_storage_provisioning.sql?raw";
import tenantBackfillMigrationSql from "../../../../sql/d1-ts/control/0021_tenant_backfill.sql?raw";
import tenantRegistryCleanupSql from "../../../../sql/d1-ts/control/0022_retire_legacy_d1_registry_columns.sql?raw";
import tenantPlacementMigrationSql from "../../../../sql/d1-ts/control/0023_tenant_object_placement.sql?raw";
import {
  D1AssetAuditSink,
  D1AssetBundleIndexStore,
  D1AssetMetadataStore,
  isAssetDatabase,
} from "../../src/assets/d1.js";
import { assetDepsFromEnv } from "../../src/assets/handlers.js";
import { tenantKeyPrefix } from "../../src/assets/keys.js";
import { InMemoryAssetMetadataStore, type StoredBundleFile } from "../../src/assets/ports.js";
import { gatewayScheduled } from "../../src/index.js";
import { gatewayMetricsSnapshot } from "../../src/routes/metrics.js";
import { seedApiKey } from "../keys/seed.js";
import { applyControlMigrations } from "../requestlog/harness.js";
import { tenantObjectDb, tenantObjectHandle } from "../tenant-object.js";

const TENANT = "tenant_asset_wiring";
const PLAN = "plan_asset_wiring";
/** `fg_` + 48 hex, the shape `virtualApiKeyPrefix` recognises. */
const SECRET = `fg_${"a1b2c3d4".repeat(6)}`;

function sqlStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

interface Bindings {
  readonly DB?: D1Database;
  readonly CONTROL_DB?: D1Database;
  readonly ASSETS?: R2Bucket;
}

function bindings(): { assets: R2Bucket; db: D1Database; control: D1Database } {
  const { ASSETS, DB, CONTROL_DB } = env as unknown as Bindings;
  if (ASSETS === undefined || DB === undefined || CONTROL_DB === undefined) {
    throw new Error(
      "expected `ASSETS`, `DB`, and `CONTROL_DB` (apps/gateway/wrangler.toml). " +
        "Without them this file would 'pass' while proving nothing about the mount.",
    );
  }
  return { assets: ASSETS, db: DB, control: CONTROL_DB };
}

function scheduledEnv(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...(env as unknown as Record<string, unknown>),
    DB: undefined,
    BILLING_DB: undefined,
    ...overrides,
  };
}

async function clearTenantObjects(): Promise<void> {
  const { assets } = bindings();
  let cursor: string | undefined;
  do {
    const page = await assets.list({ prefix: tenantKeyPrefix(TENANT), cursor });
    const keys = page.objects.map((object) => object.key);
    if (keys.length > 0) await assets.delete(keys);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
}

/**
 * Provision the tenant the way the control plane would: a durable `api_keys`
 * row (so the credential is the DURABLE leg, not the config fallback) and a
 * plan that grants asset hosting (so `tenant_can_host` is a real durable grant).
 */
async function provision(): Promise<void> {
  const { db, control } = bindings();
  const registryColumns = await control.prepare("PRAGMA table_info(tenant_databases)").all();
  const registryNames = new Set(
    (registryColumns.results as { name?: unknown }[]).map((row) => String(row.name ?? "")),
  );
  if (!registryNames.has("storage_backend")) {
    for (const statement of [
      ...sqlStatements(tenantRegistryMigrationSql),
      ...sqlStatements(tenantBackfillMigrationSql),
      ...sqlStatements(tenantRegistryCleanupSql),
    ]) {
      await control.prepare(statement).run();
    }
  }
  if (!registryNames.has("location_hint_source")) {
    for (const statement of sqlStatements(tenantPlacementMigrationSql)) {
      await control.prepare(statement).run();
    }
  }
  await clearTenantObjects();
  await db.prepare("DELETE FROM stored_assets").run();
  await db.prepare("DELETE FROM asset_channels").run();
  await db.prepare("DELETE FROM asset_bundle_files").run();
  await db.prepare("DELETE FROM retention_policies").run();
  await db.prepare("DELETE FROM api_keys WHERE tenant_id = ?1").bind(TENANT).run();
  await control.prepare("DELETE FROM audit_events WHERE tenant = ?1").bind(TENANT).run();
  const tenant = tenantObjectDb(TENANT);
  await tenant.batch([
    tenant.prepare("DELETE FROM asset_bundle_files"),
    tenant.prepare("DELETE FROM asset_channels"),
    tenant.prepare("DELETE FROM stored_assets"),
    tenant.prepare("DELETE FROM retention_policies"),
    tenant.prepare("DELETE FROM audit_events"),
  ]);

  // The SAME seeder `test/keys/` uses, so the row is hashed by the function the
  // resolver verifies against — a test can never prove auth against a hash only
  // the test knows how to make.
  await seedApiKey({
    id: "key_asset_wiring",
    secret: SECRET,
    tenantId: TENANT,
    scopes: ["assets.read", "assets.write"],
  });

  await control
    .prepare(
      "INSERT OR REPLACE INTO plans (id, name, slug, asset_hosting_enabled) VALUES (?1, ?2, ?3, 1)",
    )
    .bind(PLAN, "asset wiring", PLAN)
    .run();
  await control
    .prepare(
      "INSERT OR REPLACE INTO tenants (id, name, slug, status, plan_id) VALUES " +
        "(?1, ?2, ?3, 'active', ?4)",
    )
    .bind(TENANT, "asset wiring", TENANT, PLAN)
    .run();
  await control
    .prepare(
      "INSERT OR REPLACE INTO tenant_databases " +
        "(tenant_id, storage_backend, provisioning_status, schema_version, migration_state, migration_epoch) " +
        "VALUES (?1, 'durable_object', 'ready', 1, 'done', 0)",
    )
    .bind(TENANT)
    .run();
}

async function push(name: string, version: string, body: string): Promise<Response> {
  return SELF.fetch(`https://gateway.test/v1/assets/binaries/${name}/${version}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${SECRET}`,
      "content-type": "application/octet-stream",
    },
    body,
  });
}

describe("the deployed Worker persists asset metadata to D1", () => {
  beforeEach(async () => {
    await applyControlMigrations();
    await provision();
  });

  test("a push over SELF lands a row in the tenant Durable Object", async () => {
    const response = await push("cli", "1.0.0", "hello-ferrogate");
    expect(response.status).toBe(200);

    const rows = await tenantObjectDb(TENANT)
      .prepare("SELECT id, tenant_id, name, version, size_bytes, visibility FROM stored_assets")
      .all<Record<string, unknown>>();
    expect(rows.results).toEqual([
      {
        id: `${TENANT}:binaries:cli:1.0.0`,
        tenant_id: TENANT,
        name: "cli",
        version: "1.0.0",
        size_bytes: "hello-ferrogate".length,
        visibility: "visible",
      },
    ]);

    const shared = await bindings()
      .db.prepare("SELECT id FROM stored_assets WHERE tenant_id = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(shared.results).toEqual([]);
  });

  test("a tenant object cannot read another tenant's asset row", async () => {
    await push("cli", "1.1.0", "tenant-a-only");

    const other = new D1AssetMetadataStore(tenantObjectDb("tenant_asset_other") as never);
    expect(await other.getAsset(`${TENANT}:binaries:cli:1.1.0`)).toBeNull();
  });

  test("a yank pushed over SELF is durable — the kill switch survives the isolate", async () => {
    // §4.8's headline consequence. The yank must be readable by a store
    // instance that shares nothing with the one that wrote it.
    await push("cli", "2.0.0", "payload");
    const yank = await SELF.fetch("https://gateway.test/v1/assets/binaries/cli/2.0.0/yank", {
      method: "POST",
      headers: { Authorization: `Bearer ${SECRET}` },
    });
    expect(yank.status).toBe(200);

    const fresh = new D1AssetMetadataStore(tenantObjectDb(TENANT) as never);
    expect((await fresh.getAsset(`${TENANT}:binaries:cli:2.0.0`))?.yanked).toBe(true);
  });

  test("a channel move over SELF lands a row in the tenant Durable Object", async () => {
    await push("cli", "3.0.0", "payload");
    const move = await SELF.fetch(
      "https://gateway.test/v1/assets/binaries/cli/channels/latest?version=3.0.0",
      { method: "PUT", headers: { Authorization: `Bearer ${SECRET}` } },
    );
    expect(move.status).toBe(200);

    const rows = await tenantObjectDb(TENANT)
      .prepare("SELECT channel, version FROM asset_channels WHERE tenant_id = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(rows.results).toEqual([{ channel: "latest", version: "3.0.0" }]);

    const shared = await bindings()
      .db.prepare("SELECT id FROM asset_channels WHERE tenant_id = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(shared.results).toEqual([]);
  });

  test("a republish is refused by the DURABLE row, not by isolate state", async () => {
    // The 409 has to come from the row the previous request committed. With an
    // in-isolate registry this passes for the wrong reason whenever the two
    // requests share an isolate — so the assertion pairs it with the row count.
    expect((await push("cli", "4.0.0", "first")).status).toBe(200);
    const second = await push("cli", "4.0.0", "second");
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({
      error: { code: "asset_version_immutable" },
    });

    const rows = await tenantObjectDb(TENANT)
      .prepare("SELECT content_hash FROM stored_assets WHERE id = ?1")
      .bind(`${TENANT}:binaries:cli:4.0.0`)
      .all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(1);
  });

  test("retention policy state is stored in the tenant Durable Object", async () => {
    const policy: StoredRetentionPolicy = {
      id: retentionPolicyId(TENANT, RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT),
      tenantId: TENANT,
      resourceType: RETENTION_RESOURCE_ASSET,
      scope: RETENTION_SCOPE_DEFAULT,
      keepLastN: 2,
      maxAgeSecs: undefined,
      minAgeSecs: 0,
      createdAtUnix: 1_800_000_000,
      updatedAtUnix: 1_800_000_000,
    };
    await new D1RetentionPolicyStore(await tenantObjectHandle(TENANT)).setRetentionPolicy(policy);

    expect(
      await new D1RetentionPolicyStore(await tenantObjectHandle(TENANT)).getRetentionPolicy(
        TENANT,
        RETENTION_RESOURCE_ASSET,
        RETENTION_SCOPE_DEFAULT,
      ),
    ).toEqual(policy);
    expect(
      await new D1RetentionPolicyStore(
        await tenantObjectHandle("tenant_asset_other"),
      ).listRetentionPolicies(TENANT),
    ).toEqual([]);
    expect(
      await bindings()
        .db.prepare("SELECT id FROM retention_policies WHERE tenant_id = ?1")
        .bind(TENANT)
        .all<Record<string, unknown>>(),
    ).toMatchObject({ results: [] });
  });

  test("static-site bundle files use the tenant Durable Object", async () => {
    const file: StoredBundleFile = {
      asset_id: `${TENANT}:static_site:docs:1.0.0`,
      tenant_id: TENANT,
      path: "index.html",
      storage_uri: `assets/${TENANT}/static_site/docs/1.0.0/index.html`,
      content_type: "text/html; charset=utf-8",
      content_hash: "hash-index",
      size_bytes: 12,
      created_at_unix: 1_800_000_000,
    };
    const bundles = new D1AssetBundleIndexStore(tenantObjectDb(TENANT) as never);
    await bundles.putBundleFiles([file]);
    expect(await bundles.listBundleFiles(file.asset_id)).toEqual([file]);
    expect(
      await new D1AssetBundleIndexStore(
        tenantObjectDb("tenant_asset_other") as never,
      ).listBundleFiles(file.asset_id),
    ).toEqual([]);
    expect(
      await bindings()
        .db.prepare("SELECT asset_id FROM asset_bundle_files WHERE tenant_id = ?1")
        .bind(TENANT)
        .all<Record<string, unknown>>(),
    ).toMatchObject({ results: [] });
  });
});

describe("the deployed Worker persists the asset audit trail to the tenant object", () => {
  // The control-D1 `audit_events` mirror is intentionally OFF: the env-wired
  // sink runs with `projectToControl: false` and the per-minute projection
  // sweep is removed from `gatewayScheduled`. Authority is the tenant object's
  // own hash-chained trail; nothing syncs to the shared control mirror. See
  // `assets/d1.ts::assetAuditSinkFromEnv` and `src/index.ts`.
  beforeEach(async () => {
    await applyControlMigrations();
    await provision();
  });

  test("a push over SELF commits an `audit_events` row on the TENANT OBJECT, not the mirror", async () => {
    expect((await push("cli", "5.0.0", "payload")).status).toBe(200);

    // Authority: the row lands in the tenant object's own trail.
    const rows = await tenantObjectDb(TENANT)
      .prepare("SELECT request_id, tenant, audit_json FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(1);
    const row = rows.results?.[0];
    expect(row?.request_id).toEqual(expect.any(String));
    expect(JSON.parse(String(row?.audit_json))).toMatchObject({
      action: "asset.push",
      target: `${TENANT}:binaries:cli:5.0.0`,
      outcome: "committed",
    });

    // Mirror OFF: nothing syncs to the shared control-D1 `audit_events`.
    const { control } = bindings();
    const mirror = await control
      .prepare("SELECT id FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(mirror.results ?? []).toHaveLength(0);
  });

  test("a REFUSED request is audited too — on the tenant object", async () => {
    // The flush is in a `finally`, because every refusal leaves the handler by
    // `throw` or by an early `fail(...)`.
    await push("cli", "6.0.0", "first");
    expect((await push("cli", "6.0.0", "second")).status).toBe(409);

    const rows = await tenantObjectDb(TENANT)
      .prepare("SELECT audit_json FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    const actions = (rows.results ?? []).map((row) => JSON.parse(String(row.audit_json)).action);
    // The committed push, plus the yank/delete-free republish attempt's trail.
    expect(actions).toContain("asset.push");
    expect(rows.results?.length).toBeGreaterThanOrEqual(1);

    // Still nothing on the control mirror.
    const { control } = bindings();
    const mirror = await control
      .prepare("SELECT id FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(mirror.results ?? []).toHaveLength(0);
  });

  test("screening evidence written over SELF is readable from the tenant object (#379)", async () => {
    // The cross-isolate property. The withheld listing is served by an isolate
    // that did not screen the push, so an in-isolate ring answers `undefined`
    // for essentially every real request — the durable record now lives in the
    // tenant object, which the env-wired sink reads.
    const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    // 202: the bytes are STORED but withheld — "unproven" is indistinguishable
    // from "absent" on every read surface (#366).
    expect((await push("cli", "7.0.0", eicar)).status).toBe(202);

    const audit = assetDepsFromEnv(env as unknown as Record<string, unknown>).audit;
    if (audit?.screeningEvidence === undefined) throw new Error("expected the env-wired audit sink");
    const evidence = await audit.screeningEvidence(TENANT);
    expect(evidence.get(`${TENANT}:binaries:cli:7.0.0`)).toContain("scan=");

    // The control mirror is disabled, so a control-only sink sees nothing.
    const { control } = bindings();
    expect((await new D1AssetAuditSink(control as never).screeningEvidence(TENANT)).size).toBe(0);

    // And the row itself is withheld, so the evidence is explaining something
    // the read surfaces really refuse to serve.
    const withheld = await tenantObjectDb(TENANT)
      .prepare("SELECT visibility FROM stored_assets WHERE id = ?1")
      .bind(`${TENANT}:binaries:cli:7.0.0`)
      .all<Record<string, unknown>>();
    expect(withheld.results?.[0]?.visibility).toBe("quarantined");
  });
});

describe("the scheduled asset lifecycle sweeper", () => {
  beforeEach(async () => {
    await applyControlMigrations();
    await provision();
  });

  test("retains the newest version, deletes its row and object, emits metrics, and audits", async () => {
    expect((await push("cli", "1.0.0", "old")).status).toBe(200);
    expect((await push("cli", "2.0.0", "newer")).status).toBe(200);

    const policy: StoredRetentionPolicy = {
      id: retentionPolicyId(TENANT, RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT),
      tenantId: TENANT,
      resourceType: RETENTION_RESOURCE_ASSET,
      scope: RETENTION_SCOPE_DEFAULT,
      keepLastN: 1,
      maxAgeSecs: undefined,
      minAgeSecs: 0,
      createdAtUnix: Math.floor(Date.now() / 1000),
      updatedAtUnix: Math.floor(Date.now() / 1000),
    };
    await new D1RetentionPolicyStore(await tenantObjectHandle(TENANT)).setRetentionPolicy(policy);

    const before = await tenantObjectDb(TENANT)
      .prepare("SELECT storage_uri FROM stored_assets WHERE version = ?1")
      .bind("1.0.0")
      .first<{ storage_uri: string }>();
    expect(before?.storage_uri).toEqual(expect.stringContaining(tenantKeyPrefix(TENANT)));
    const beforeMetrics = gatewayMetricsSnapshot();

    await gatewayScheduled({}, scheduledEnv(), { waitUntil: () => {} });

    const oldRows = await tenantObjectDb(TENANT)
      .prepare("SELECT id FROM stored_assets WHERE version = ?1")
      .bind("1.0.0")
      .all<{ id: string }>();
    expect(oldRows.results).toEqual([]);
    expect(await bindings().assets.head(before?.storage_uri as string)).toBeNull();
    const newestRows = await tenantObjectDb(TENANT)
      .prepare("SELECT id FROM stored_assets WHERE version = ?1")
      .bind("2.0.0")
      .all<{ id: string }>();
    expect(newestRows.results).toEqual([{ id: `${TENANT}:binaries:cli:2.0.0` }]);

    const auditRows = await tenantObjectDb(TENANT)
      .prepare("SELECT audit_json FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<{ audit_json: string }>();
    expect(
      auditRows.results.some(
        (row) => JSON.parse(row.audit_json).action === "asset.retention_prune",
      ),
    ).toBe(true);

    const afterMetrics = gatewayMetricsSnapshot();
    expect(afterMetrics.assetLifecycleScannedTotal - beforeMetrics.assetLifecycleScannedTotal).toBe(
      1,
    );
    expect(afterMetrics.assetLifecyclePrunedTotal - beforeMetrics.assetLifecyclePrunedTotal).toBe(
      2,
    );
    expect(afterMetrics.assetLifecycleFailedTotal - beforeMetrics.assetLifecycleFailedTotal).toBe(
      0,
    );
  });

  test("reclaims an unreferenced object under the tenant prefix", async () => {
    const orphan = `${tenantKeyPrefix(TENANT)}orphan/old-object`;
    await bindings().assets.put(orphan, "orphan-bytes");
    expect(await bindings().assets.head(orphan)).not.toBeNull();

    await gatewayScheduled({}, scheduledEnv({ ASSET_RETENTION_ORPHAN_GRACE_SECS: "0" }), {
      waitUntil: () => {},
    });

    expect(await bindings().assets.head(orphan)).toBeNull();
  });
});

describe("assetDepsFromEnv resolves the registry on its own evidence", () => {
  test("the shared-`env.DB` metadata store is retired — the routed store is request-scoped (#821)", () => {
    // Before #821 PR2-delete a bound `DB` made `assetDepsFromEnv` hand back a
    // shared `D1AssetMetadataStore`. That shared registry is gone: the asset
    // tables live in each tenant's own Durable Object and the metadata store is
    // built per request from the tenant accessor (proven by the routed
    // request-path tests above). So the base factory resolves NO metadata dep,
    // even with the real `DB`/`TENANT_DATA` bindings present, and
    // `buildAssetService` keeps the local-dev store until a request scopes one.
    const deps = assetDepsFromEnv(env as unknown as Record<string, unknown>);
    expect(deps.metadata).toBeUndefined();
  });

  test("`CONTROL_DB` bound ⇒ the DURABLE audit sink", () => {
    const deps = assetDepsFromEnv(env as unknown as Record<string, unknown>);
    expect(deps.audit).toBeInstanceOf(D1AssetAuditSink);
  });

  test("`CONTROL_DB` absent ⇒ no audit dep, so the bounded in-memory ring stays", () => {
    expect(assetDepsFromEnv({}).audit).toBeUndefined();
    expect(assetDepsFromEnv({ CONTROL_DB: { prepare: () => undefined } }).audit).toBeUndefined();
  });

  test("`DB` absent ⇒ no metadata dep, so `buildAssetService` keeps the local-dev store", () => {
    // The control for the assertion above: without it, `toBeInstanceOf` would
    // prove only that SOMETHING was returned, not that the binding decided it.
    expect(assetDepsFromEnv({}).metadata).toBeUndefined();
    expect(assetDepsFromEnv({ DB: { prepare: () => undefined } }).metadata).toBeUndefined();
    expect(new InMemoryAssetMetadataStore()).not.toBeInstanceOf(D1AssetMetadataStore);
  });

  test("the binding the Worker declares is a real D1 database", () => {
    expect(isAssetDatabase((env as unknown as Bindings).DB)).toBe(true);
  });
});
