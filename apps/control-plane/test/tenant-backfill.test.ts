import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  DurableObjectTenantDatabaseRouter,
  type TenantDataStatement,
  type TenantDatabaseRouter,
  type TenantMigrationMode,
} from "@ferrogate/storage";
import { runTenantStorageMigration, TenantBackfillError } from "../src/store/tenant-backfill.js";
import { db } from "./d1.js";

let TENANT = "";
const NOW = 1_800_000_000;

interface BackfillBindings {
  readonly LEGACY_TENANT_DB: D1Database;
  readonly TENANT_DATA: ConstructorParameters<typeof DurableObjectTenantDatabaseRouter>[0];
  readonly TEST_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

const bindings = env as unknown as BackfillBindings;

function objectRouter(): DurableObjectTenantDatabaseRouter {
  return new DurableObjectTenantDatabaseRouter(bindings.TENANT_DATA, db());
}

async function reset(): Promise<void> {
  TENANT = `tenant_backfill_${crypto.randomUUID()}`;
  await db().batch([
    db().prepare("DELETE FROM audit_events"),
    db().prepare("DELETE FROM tenant_databases"),
    db().prepare("DELETE FROM tenants"),
  ]);
  await bindings.LEGACY_TENANT_DB.batch([
    bindings.LEGACY_TENANT_DB.prepare("DELETE FROM tenant_write_fences"),
    bindings.LEGACY_TENANT_DB.prepare("DELETE FROM wallet_reservations"),
    bindings.LEGACY_TENANT_DB.prepare("DELETE FROM wallet_settlements"),
    bindings.LEGACY_TENANT_DB.prepare("DELETE FROM wallets"),
    bindings.LEGACY_TENANT_DB.prepare("DELETE FROM projects"),
  ]);
  await db()
    .prepare("INSERT INTO tenants (id, name, slug, plan_id) VALUES (?, ?, ?, ?)")
    .bind(TENANT, "Backfill test", TENANT, "free")
    .run();
  await db()
    .prepare(
      `INSERT INTO tenant_databases
        (tenant_id, storage_backend, provisioning_status, migration_state, migration_epoch)
       VALUES (?, 'native_binding', 'ready', 'shared', 0)`,
    )
    .bind(TENANT)
    .run();
  await bindings.LEGACY_TENANT_DB
    .prepare(
      `INSERT INTO projects (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, 'active', ?, ?)`,
    )
    .bind("project_a", TENANT, "Project A", "project-a", NOW, NOW)
    .run();
  await bindings.LEGACY_TENANT_DB
    .prepare(
      `INSERT INTO projects (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, 'active', ?, ?)`,
    )
    .bind("project_b", TENANT, "Project B", "project-b", NOW, NOW)
    .run();
  await bindings.LEGACY_TENANT_DB
    .prepare(
      `INSERT INTO wallets (id, tenant_id, balance_credits, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(TENANT, TENANT, "1000000000000010000", NOW, NOW)
    .run();
}

async function migration(action: "start" | "resume" | "verify" | "cutover" | "rollback", router: TenantDatabaseRouter = objectRouter()) {
  return runTenantStorageMigration({
    controlDatabase: db(),
    legacyTenantDatabase: bindings.LEGACY_TENANT_DB,
    destinationRouter: router,
    tenantId: TENANT,
    action,
    locationHint: "wnam",
    requestId: "backfill-test-request",
    nowUnix: NOW,
    pageSize: 1,
    retentionSeconds: 3600,
  });
}

function interruptedRouter(): TenantDatabaseRouter {
  const delegate = objectRouter();
  let imports = 0;
  return {
    backend: delegate.backend,
    forTenant: (tenantId: string) => delegate.forTenant(tenantId),
    privilegedBatch: (tenantId: string, statements: readonly TenantDataStatement[]) =>
      delegate.privilegedBatch(tenantId, statements),
    migrationImport: async (
      tenantId: string,
      epoch: number,
      statements: readonly TenantDataStatement[],
    ) => {
      imports += 1;
      if (imports === 2) throw new Error("simulated Worker interruption");
      return delegate.migrationImport(tenantId, epoch, statements);
    },
    setMigrationMode: (tenantId: string, mode: TenantMigrationMode, epoch: number) =>
      delegate.setMigrationMode(tenantId, mode, epoch),
    migrationStatus: (tenantId: string) => delegate.migrationStatus(tenantId),
  } as unknown as TenantDatabaseRouter;
}

beforeAll(async () => {
  // Zero-D1 S5 (#881): the ControlDataObject self-applies its control schema.
  await applyD1Migrations(bindings.LEGACY_TENANT_DB, bindings.TEST_TENANT_D1_SCHEMA);
});

beforeEach(reset);

describe("tenant storage backfill", () => {
  test("refuses to run without an observed placement hint", async () => {
    await expect(
      runTenantStorageMigration({
        controlDatabase: db(),
        legacyTenantDatabase: bindings.LEGACY_TENANT_DB,
        destinationRouter: objectRouter(),
        tenantId: TENANT,
        action: "status",
      }),
    ).rejects.toMatchObject({
      code: "tenant_storage_migration_location_hint_required",
    });
  });

  test("freezes the source, resumes a page interruption, verifies all owned rows, and cuts over", async () => {
    await bindings.LEGACY_TENANT_DB
      .prepare(
        `INSERT INTO projects (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, 'active', ?, ?)`,
      )
      .bind("project_other", "tenant_other", "Other", "other", NOW, NOW)
      .run();
    const started = await migration("start");
    expect(started.migration_state).toBe("copying");
    expect(
      await db()
        .prepare(
          "SELECT location_hint, location_hint_source, location_hint_recorded_at_unix, jurisdiction " +
            "FROM tenant_databases WHERE tenant_id = ?",
        )
        .bind(TENANT)
        .first(),
    ).toEqual({
      location_hint: "wnam",
      location_hint_source: "backfill:observed tenant traffic",
      location_hint_recorded_at_unix: NOW,
      jurisdiction: null,
    });
    expect(
      await bindings.LEGACY_TENANT_DB
        .prepare("SELECT mode FROM tenant_write_fences WHERE tenant_id = ?")
        .bind(TENANT)
        .first<{ mode: string }>(),
    ).toEqual({ mode: "frozen" });
    await expect(
      bindings.LEGACY_TENANT_DB
        .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
        .bind("late", TENANT, "Late", "late")
        .run(),
    ).rejects.toThrow(/frozen/);
    await expect(
      bindings.LEGACY_TENANT_DB
        .prepare("UPDATE projects SET tenant_id = ? WHERE id = ?")
        .bind(TENANT, "project_other")
        .run(),
    ).rejects.toThrow(/frozen/);
    await expect(
      bindings.LEGACY_TENANT_DB
        .prepare(
          `INSERT INTO asset_bundle_files
             (asset_id, tenant_id, path, storage_uri, content_type, content_hash, size_bytes, created_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind("asset_without_owner", TENANT, "index.html", "r2://asset", "text/html", "hash", 1, NOW)
        .run(),
    ).rejects.toThrow(/frozen/);

    await expect(migration("resume", interruptedRouter())).rejects.toThrow(/interruption/);
    const progress = await db()
      .prepare("SELECT migration_progress_json FROM tenant_databases WHERE tenant_id = ?")
      .bind(TENANT)
      .first<{ migration_progress_json: string }>();
    expect(JSON.parse(progress?.migration_progress_json ?? "{}").cursor).toEqual(["project_a"]);

    const verified = await migration("resume");
    expect(verified.migration_state).toBe("verifying");
    expect(verified.receipt.source.length).toBeGreaterThanOrEqual(67);
    expect(verified.receipt.source).toEqual(verified.receipt.destination);

    const cut = await migration("cutover");
    expect(cut.migration_state).toBe("done");
    expect(cut.object_status?.mode).toBe("done");
    expect(
      await objectRouter()
        .forTenant(TENANT)
        .then((handle) => handle.db.prepare("SELECT id FROM projects ORDER BY id").all()),
    ).toMatchObject({ results: [{ id: "project_a" }, { id: "project_b" }] });
    expect(
      await objectRouter()
        .forTenant(TENANT)
        .then((handle) =>
          handle.db
            .prepare("SELECT CAST(balance_credits AS TEXT) AS credits FROM wallets WHERE tenant_id = ?")
            .bind(TENANT)
            .first<{ credits: string }>(),
        ),
    ).toEqual({ credits: "1000000000000010000" });
    expect(
      await db()
        .prepare("SELECT COUNT(*) AS count FROM audit_events WHERE tenant = ?")
        .bind(TENANT)
        .first<{ count: number }>(),
    ).toEqual({ count: 4 });
  });

  test("refuses rollback after an object write and allows rollback before one", async () => {
    await migration("resume");
    await migration("cutover");
    const rolledBack = await migration("rollback");
    expect(rolledBack.migration_state).toBe("shared");
    expect(rolledBack.object_status?.mode).toBe("shared");
    expect(
      await bindings.LEGACY_TENANT_DB
        .prepare("SELECT mode FROM tenant_write_fences WHERE tenant_id = ?")
        .bind(TENANT)
        .first<{ mode: string }>(),
    ).toEqual({ mode: "open" });

    await migration("resume");
    await migration("cutover");
    const handle = await objectRouter().forTenant(TENANT);
    await handle.db
      .prepare("INSERT INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("object_write", TENANT, "Object", "object-write")
      .run();
    await expect(migration("rollback")).rejects.toMatchObject({
      code: "tenant_storage_migration_write_detected",
    });
  });

  test("reconciles a control row left behind while the object is copying", async () => {
    const started = await migration("start");
    expect(started.migration_state).toBe("copying");
    await db()
      .prepare(
        "UPDATE tenant_databases SET migration_state = 'shared', migration_epoch = 0 WHERE tenant_id = ?",
      )
      .bind(TENANT)
      .run();

    const resumed = await migration("resume");
    expect(resumed.migration_state).toBe("verifying");
    expect(resumed.object_status?.mode).toBe("verifying");
  });

  test("finishes cutover when the object advanced before the control row", async () => {
    await migration("resume");
    const verified = await migration("resume");
    expect(verified.migration_state).toBe("verifying");
    await objectRouter().setMigrationMode(TENANT, "cut", verified.migration_epoch);

    const cut = await migration("cutover");
    expect(cut.migration_state).toBe("done");
    expect(cut.object_status?.mode).toBe("done");
  });
});
