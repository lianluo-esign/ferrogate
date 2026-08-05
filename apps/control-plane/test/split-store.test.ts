import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import type { ControlPlaneBindings } from "../src/ports.js";
import { resolveTenantStorage } from "../src/adapters.js";
import { SplitControlPlaneStore } from "../src/store/split.js";
import { RESOURCE_TABLE, TENANT_RESOURCE_TABLE } from "../src/store/d1.js";
import { applySchema, db, resetD1 } from "./d1.js";
import {
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  TENANT_A,
  TENANT_B,
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

  it("backfills a legacy tenant document into the object before serving reads", async () => {
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
    ).resolves.toMatchObject({ id: "legacy-workflow", tenant_id: TENANT_A });

    const objectRow = await (await router().forTenant(TENANT_A)).db
      .prepare(
        `SELECT revision, created_at_unix, updated_at_unix FROM ${TENANT_RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind("agent-workflows", "legacy-workflow")
      .first<{ revision: number; created_at_unix: number; updated_at_unix: number }>();
    expect(objectRow).toEqual({ revision: 3, created_at_unix: 10, updated_at_unix: 20 });
  });

  it("derives a tenant-account owner from its id for platform creates", async () => {
    const record = await store().create("tenant-accounts", PLATFORM, { id: TENANT_A, name: "A" });
    expect(record.tenant_id).toBe(TENANT_A);
    await expect(
      store().get("tenant-accounts", { kind: "tenant", tenantId: TENANT_A }, TENANT_A),
    ).resolves.toMatchObject({ id: TENANT_A, tenant_id: TENANT_A });
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
