import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantStorage } from "../src/adapters.js";
import type { ControlPlaneBindings, ListQuery, StoreRecord } from "../src/ports.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import {
  D1ControlPlaneStore,
  RESOURCE_TABLE,
  TENANT_RESOURCE_TABLE,
  TENANT_RESOURCE_TOMBSTONE_MARK_PREFIX,
  tenantResourceTombstoneMark,
} from "../src/store/d1.js";
import { pageOf } from "../src/store/query.js";
import { projectTenantAccount } from "../src/store/quota_registry.js";
import {
  RESOURCE_BACKFILL_BATCH_SIZE,
  backfillTenantResourceKinds,
} from "../src/store/resource-backfill.js";
import { SplitControlPlaneStore } from "../src/store/split.js";
import { applySchema, db, resetD1 } from "./d1.js";
import {
  TENANT_A,
  TENANT_B,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
} from "./tenant-db.js";

const PLATFORM = { kind: "platform_operator" } as const;
const QUERY = { offset: 0, limit: 100, paginate: false, search: null, filters: {} } as const;

function router() {
  return resolveTenantStorage(env as unknown as ControlPlaneBindings);
}

function store() {
  return new SplitControlPlaneStore(db(), router(), { requestId: "split-store-test" });
}

async function clearObjectDocuments(): Promise<void> {
  await Promise.all(
    [TENANT_A, TENANT_B].map(async (tenantId) => {
      const handle = await router().forTenant(tenantId);
      await handle.db.prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE}`).run();
    }),
  );
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
  await clearObjectDocuments();
});

describe("SplitControlPlaneStore", () => {
  it("routes tenant kinds to the tenant object and platform kinds to control D1", async () => {
    const split = store();
    const tenant = { kind: "tenant", tenantId: TENANT_A } as const;

    const workflow = await split.create("agent-workflows", tenant, {
      id: "workflow-a",
      tenant_id: TENANT_A,
      nodes: [],
    });
    await split.create("plans", PLATFORM, { id: "free", name: "Free" });

    const objectDb = (await router().forTenant(TENANT_A)).db;
    const objectRow = await objectDb
      .prepare(
        `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind("agent-workflows", workflow.id)
      .first<{ document_json: string }>();
    const controlTenantRow = await db()
      .prepare(
        `SELECT 1 AS present FROM ${RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind("agent-workflows", workflow.id)
      .first<{ present: number }>();
    const controlPlatformRow = await db()
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind("plans", "free")
      .first<{ document_json: string }>();

    expect(JSON.parse(objectRow?.document_json ?? "null")).toMatchObject({
      id: "workflow-a",
      tenant_id: TENANT_A,
    });
    expect(controlTenantRow).toBeNull();
    expect(JSON.parse(controlPlatformRow?.document_json ?? "null")).toMatchObject({
      id: "free",
      name: "Free",
    });
    await expect(
      split.get("agent-workflows", { kind: "tenant", tenantId: TENANT_B }, workflow.id),
    ).resolves.toBeNull();
  });

  it("does not restore tenant documents from legacy control rows", async () => {
    await db()
      .prepare(
        `INSERT INTO ${RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 3, 10, 20)`,
      )
      .bind(
        "agent-workflows",
        "legacy-workflow",
        JSON.stringify({ id: "legacy-workflow", tenant_id: TENANT_A, nodes: [] }),
      )
      .run();

    const split = store();
    await expect(
      split.get("agent-workflows", { kind: "tenant", tenantId: TENANT_A }, "legacy-workflow"),
    ).resolves.toBeNull();

    const objectRow = await (await router().forTenant(TENANT_A)).db
      .prepare(
        `SELECT revision, created_at_unix, updated_at_unix FROM ${TENANT_RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind("agent-workflows", "legacy-workflow")
      .first<{ revision: number; created_at_unix: number; updated_at_unix: number }>();
    expect(objectRow).toBeNull();
  });

  it("retired compatibility calls never scan or copy legacy rows", async () => {
    const rows = Array.from(
      { length: RESOURCE_BACKFILL_BATCH_SIZE + 1 },
      (_, index) =>
        [
          `legacy-workflow-${String(index).padStart(3, "0")}`,
          JSON.stringify({
            id: `legacy-workflow-${String(index).padStart(3, "0")}`,
            tenant_id: TENANT_A,
          }),
        ] as const,
    );
    for (let index = 0; index < rows.length; index += 50) {
      await db().batch(
        rows.slice(index, index + 50).map(([id, document]) =>
          db()
            .prepare(
              `INSERT INTO ${RESOURCE_TABLE}
                 (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
               VALUES (?, ?, ?, 1, 1, 1)`,
            )
            .bind("agent-workflows", id, document),
        ),
      );
    }

    const objectDb = (await router().forTenant(TENANT_A)).db;
    const first = await backfillTenantResourceKinds(db(), objectDb, TENANT_A);
    expect(first).toEqual({ scanned: 0, copied: 0 });
    expect(
      await objectDb
        .prepare(`SELECT COUNT(*) AS total FROM ${TENANT_RESOURCE_TABLE}`)
        .first<{ total: number }>(),
    ).toEqual({ total: 0 });

    const second = await backfillTenantResourceKinds(db(), objectDb, TENANT_A);
    expect(second).toEqual({ scanned: 0, copied: 0 });
    expect(
      await objectDb
        .prepare(`SELECT COUNT(*) AS total FROM ${TENANT_RESOURCE_TABLE}`)
        .first<{ total: number }>(),
    ).toEqual({ total: 0 });
  });

  it("does not return a legacy control row as a platform resource", async () => {
    await db()
      .prepare(
        `INSERT INTO ${RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, 1, 1)`,
      )
      .bind(
        "agent-workflows",
        "control-only",
        JSON.stringify({ id: "control-only", tenant_id: "tenant_unknown" }),
      )
      .run();

    await expect(store().get("agent-workflows", PLATFORM, "control-only")).resolves.toBeNull();
  });

  it("tombstones object deletes so legacy backfill cannot resurrect them", async () => {
    const id = "delete-with-legacy-row";
    await db()
      .prepare(
        `INSERT INTO ${RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, 1, 1)`,
      )
      .bind("agent-workflows", id, JSON.stringify({ id, tenant_id: TENANT_A }))
      .run();

    const objectDb = (await router().forTenant(TENANT_A)).db;
    const objectStore = new D1ControlPlaneStore(objectDb, {
      requestId: "split-tombstone-test",
      resourceTable: TENANT_RESOURCE_TABLE,
      isolation: "object",
      objectTenantId: TENANT_A,
      auditDatabase: db(),
      tombstoneMarkPrefix: TENANT_RESOURCE_TOMBSTONE_MARK_PREFIX,
    });
    await objectStore.create(
      "agent-workflows",
      { kind: "tenant", tenantId: TENANT_A },
      { id, tenant_id: TENANT_A },
    );
    await expect(
      objectStore.remove("agent-workflows", { kind: "tenant", tenantId: TENANT_A }, id),
    ).resolves.toBe(true);

    const tombstone = await objectDb
      .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
      .bind(TENANT_A, tenantResourceTombstoneMark("agent-workflows", id))
      .first<{ detail: string }>();
    expect(tombstone).not.toBeNull();

    const backfill = await backfillTenantResourceKinds(db(), objectDb, TENANT_A);
    expect(backfill.scanned).toBe(0);
    expect(backfill.copied).toBe(0);
    await expect(
      objectDb
        .prepare(
          `SELECT 1 AS present FROM ${TENANT_RESOURCE_TABLE}
           WHERE resource_kind = ? AND resource_id = ?`,
        )
        .bind("agent-workflows", id)
        .first(),
    ).resolves.toBeNull();
  });

  it("derives a tenant-account owner from its id for platform creates", async () => {
    const record = await store().create("tenant-accounts", PLATFORM, { id: TENANT_A, name: "A" });
    expect(record.tenant_id).toBe(TENANT_A);
    await expect(
      store().get("tenant-accounts", { kind: "tenant", tenantId: TENANT_A }, TENANT_A),
    ).resolves.toMatchObject({ id: TENANT_A, tenant_id: TENANT_A });
  });

  describe("operator tenant-accounts LIST without a control mirror", () => {
    // The default path always reads account documents from their owner.
    function fanOutStore() {
      return new SplitControlPlaneStore(db(), router(), {
        requestId: "split-store-test",
      });
    }

    async function seed(
      split: SplitControlPlaneStore,
      id: string,
      extra: Record<string, unknown>,
    ): Promise<StoreRecord> {
      const stored = await split.create("tenant-accounts", PLATFORM, { id, ...extra });
      await projectTenantAccount(db(), stored, 1000);
      return stored;
    }

    async function fanoutReference(seededById: Map<string, StoreRecord>, query: ListQuery) {
      const roster = await router().provisionedTenants();
      const docs = roster
        .map((id) => seededById.get(id))
        .filter((doc): doc is StoreRecord => doc !== undefined);
      return pageOf(docs, query);
    }

    it("stops writing the control mirror yet still serves the LIST from the object fan-out", async () => {
      const split = fanOutStore();
      const a = await seed(split, TENANT_A, {
        name: "Ärzte Klinik",
        status: "active",
        plan_id: "pro",
        plan_effective_at: 1234567890,
        contact_email: "ops@aerzte.example",
      });
      const b = await seed(split, TENANT_B, {
        name: "Beta Corp",
        status: "suspended",
        plan_id: "free",
      });
      const seeded = new Map([
        [TENANT_A, a],
        [TENANT_B, b],
      ]);

      const registry = await db()
        .prepare("SELECT status FROM tenants WHERE id = ?")
        .bind(TENANT_A)
        .first<{ status: string }>();
      expect(registry?.status).toBe("active");
      const columns = await db().prepare("PRAGMA table_info(tenants)").all<{ name: string }>();
      expect(columns.results.map((column) => column.name)).not.toContain("document_json");

      // Preserve the search/filter/pagination surface while reading the authority.
      const search: ListQuery = {
        offset: 0,
        limit: 100,
        paginate: true,
        search: "ärzte",
        filters: {},
      };
      const cases: ListQuery[] = [
        { offset: 0, limit: 100, paginate: false, search: null, filters: {} },
        search,
        { offset: 0, limit: 100, paginate: true, search: null, filters: { status: "active" } },
        { offset: 1, limit: 1, paginate: true, search: null, filters: {} },
      ];
      for (const query of cases) {
        const page = await split.list("tenant-accounts", PLATFORM, query);
        expect(page).toEqual(await fanoutReference(seeded, query));
      }

      // Raw fields the typed columns drop still survive — proof the fan-out
      // returns the object document, not a registry-column reconstruction.
      const searchPage = await split.list("tenant-accounts", PLATFORM, search);
      expect(searchPage.items.map((i) => i.id)).toEqual([TENANT_A]);
      expect(searchPage.items[0]).toMatchObject({ plan_effective_at: 1234567890 });
    });
  });
  it("does not restore account mirrors on the former backfill tick with legacy configuration", async () => {
    const split = store();
    const account = await split.create("tenant-accounts", PLATFORM, {
      id: TENANT_A,
      name: "No mirror",
    });
    const legacyEnv = {
      ...env,
      CONTROL_TENANT_ACCOUNT_SOURCE: "control",
    } as unknown as ControlPlaneBindings;
    await projectTenantAccount(db(), account, 1800000000, legacyEnv);
    const report = await runScheduledTick(legacyEnv, 1800000000);
    expect(report).not.toHaveProperty("tenantAccountMirror");
    const columns = await db().prepare("PRAGMA table_info(tenants)").all<{ name: string }>();
    expect(columns.results.map((column) => column.name)).not.toContain("document_json");
    expect(await split.get("tenant-accounts", PLATFORM, TENANT_A)).toEqual(account);
  });

  it("lists an account even when the narrow platform registry has no document", async () => {
    const split = store();
    const record = await split.create("tenant-accounts", PLATFORM, { id: TENANT_A, name: "Owner" });
    await projectTenantAccount(db(), record, 1000);
    expect((await split.list("tenant-accounts", PLATFORM, QUERY)).items).toContainEqual(record);
    await db().prepare("DELETE FROM tenant_databases WHERE tenant_id = ?").bind(TENANT_A).run();
    expect((await split.list("tenant-accounts", PLATFORM, QUERY)).items).not.toContainEqual(record);
  });

  it("fans out platform reads across provisioned tenants without weakening object isolation", async () => {
    const split = store();
    await split.create(
      "agent-workflows",
      { kind: "tenant", tenantId: TENANT_A },
      {
        id: "same-kind-a",
        tenant_id: TENANT_A,
      },
    );
    await split.create(
      "agent-workflows",
      { kind: "tenant", tenantId: TENANT_B },
      {
        id: "same-kind-b",
        tenant_id: TENANT_B,
      },
    );

    const page = await split.list("agent-workflows", PLATFORM, QUERY);
    expect(page.items.map((item) => item.id)).toEqual(
      expect.arrayContaining(["same-kind-a", "same-kind-b"]),
    );
    expect(page.total).toBe(2);
  });
});
