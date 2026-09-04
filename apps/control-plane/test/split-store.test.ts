import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantStorage } from "../src/adapters.js";
import type { ControlPlaneBindings, ListQuery, StoreRecord } from "../src/ports.js";
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
import { backfillTenantAccountMirror } from "../src/store/tenant-account-mirror-backfill.js";
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

  it("bounds each legacy backfill call and resumes from copied rows", async () => {
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
    expect(first.scanned).toBe(RESOURCE_BACKFILL_BATCH_SIZE);
    expect(
      await objectDb
        .prepare(`SELECT COUNT(*) AS total FROM ${TENANT_RESOURCE_TABLE}`)
        .first<{ total: number }>(),
    ).toEqual({ total: RESOURCE_BACKFILL_BATCH_SIZE });

    const second = await backfillTenantResourceKinds(db(), objectDb, TENANT_A);
    expect(second.scanned).toBe(1);
    expect(
      await objectDb
        .prepare(`SELECT COUNT(*) AS total FROM ${TENANT_RESOURCE_TABLE}`)
        .first<{ total: number }>(),
    ).toEqual({ total: RESOURCE_BACKFILL_BATCH_SIZE + 1 });
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
    expect(backfill.scanned).toBe(1);
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

  describe("operator tenant-accounts LIST (served from the control mirror)", () => {
    // Seed a tenant-account into its OBJECT (via the split store) AND into the
    // control `tenants` mirror (via `projectTenantAccount`, the route-layer sync
    // hook), exactly as a real create does. Returns the stored document.
    async function seed(
      split: SplitControlPlaneStore,
      id: string,
      extra: Record<string, unknown>,
    ): Promise<StoreRecord> {
      const stored = await split.create("tenant-accounts", PLATFORM, { id, ...extra });
      await projectTenantAccount(db(), stored, 1000);
      return stored;
    }

    // The fan-out's observable result is `pageOf(docs, query)` over one document
    // per provisioned tenant in roster order. Build that reference from the
    // captured stored docs (byte-equal to each object's row via JSON round-trip)
    // so an equality assertion pins mirror-read == fan-out-read.
    async function fanoutReference(seededById: Map<string, StoreRecord>, query: ListQuery) {
      const roster = await router().provisionedTenants();
      const docs = roster
        .map((id) => seededById.get(id))
        .filter((doc): doc is StoreRecord => doc !== undefined);
      return pageOf(docs, query);
    }

    it("matches the fan-out across search, filter and pagination", async () => {
      const split = store();
      const a = await seed(split, TENANT_A, {
        name: "Ärzte Klinik",
        status: "active",
        plan_id: "pro",
        // A field the typed projection columns DROP — proves the reader returns
        // the raw document, not a reconstruction from `id/name/slug/status/plan_id`.
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

      // Write-through fidelity: the mirror row is the document, verbatim.
      const mirrorRow = await db()
        .prepare("SELECT document_json FROM tenants WHERE id = ?")
        .bind(TENANT_A)
        .first<{ document_json: string }>();
      expect(JSON.parse(mirrorRow?.document_json ?? "null")).toEqual(a);

      // Unicode case-fold search — a SQLite `LIKE` prefilter would DROP this.
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

      // Concretely: the raw field survives and search matched the right tenant.
      const searchPage = await split.list("tenant-accounts", PLATFORM, search);
      expect(searchPage.items.map((i) => i.id)).toEqual([TENANT_A]);
      expect(searchPage.items[0]).toMatchObject({ plan_effective_at: 1234567890 });

      // Idempotent re-projection (the ON CONFLICT DO UPDATE branch, not INSERT):
      // a later mutation's document replaces the mirror in place, verbatim.
      const updated = { ...a, status: "suspended", plan_effective_at: 999 };
      await projectTenantAccount(db(), updated, 2000);
      const reread = await split.list("tenant-accounts", PLATFORM, QUERY);
      expect(reread.items.find((i) => i.id === TENANT_A)).toEqual(updated);
    });

    it("hides an out-of-band deprovisioned tenant whose mirror row is retained", async () => {
      const split = store();
      await seed(split, TENANT_A, { name: "A", status: "active" });
      await seed(split, TENANT_B, { name: "B", status: "active" });

      // Deprovision drops the roster row but RETAINS object/mirror data.
      await db().prepare("DELETE FROM tenant_databases WHERE tenant_id = ?").bind(TENANT_B).run();

      const page = await split.list("tenant-accounts", PLATFORM, QUERY);
      expect(page.items.map((i) => i.id)).toEqual([TENANT_A]);
      expect(page.total).toBe(1);
    });

    it("skips a tenant row whose document_json is not yet mirrored, then lists it after backfill", async () => {
      const split = store();
      await seed(split, TENANT_A, { name: "A", status: "active" });
      // TENANT_B: object has the doc, but its mirror row is pre-migration NULL.
      const b = await split.create("tenant-accounts", PLATFORM, {
        id: TENANT_B,
        name: "B",
        status: "active",
      });
      await db()
        .prepare(
          `INSERT INTO tenants (id, name, slug, status, plan_id, created_at_unix, updated_at_unix)
           VALUES (?, 'B', 'b', 'active', 'free', 1, 1)`,
        )
        .bind(TENANT_B)
        .run();

      const before = await split.list("tenant-accounts", PLATFORM, QUERY);
      expect(before.items.map((i) => i.id)).toEqual([TENANT_A]);

      // The one-time backfill fills the NULL row from TENANT_B's object.
      const report = await backfillTenantAccountMirror(router(), db(), 2000);
      expect(report).toMatchObject({ mirrored: 1, failed: 0 });

      const after = await split.list("tenant-accounts", PLATFORM, QUERY);
      expect(after.items.map((i) => i.id).sort()).toEqual([TENANT_A, TENANT_B]);
      expect(after.items.find((i) => i.id === TENANT_B)).toEqual(b);

      // Idempotent + convergent: a second pass opens nothing and reports complete.
      expect(await backfillTenantAccountMirror(router(), db(), 3000)).toMatchObject({
        scanned: 0,
        skipped: "complete",
      });
    });

    it("keeps GET-by-id on the tenant object, unaffected by the mirror", async () => {
      const split = store();
      const a = await seed(split, TENANT_A, { name: "A", status: "active" });

      // Operator GET-by-id reads the object, not the mirror.
      await expect(split.get("tenant-accounts", PLATFORM, TENANT_A)).resolves.toEqual(a);

      // A stale mirror row for a tenant whose object doc is gone must NOT surface
      // on GET-by-id (it reads the object → null), even though the row lingers.
      await (await router().forTenant(TENANT_A)).db
        .prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind = 'tenant-accounts'`)
        .run();
      await expect(split.get("tenant-accounts", PLATFORM, TENANT_A)).resolves.toBeNull();
    });
  });

  describe("operator tenant-accounts LIST with CONTROL_TENANT_ACCOUNT_SOURCE=tenant_object (Track A G2)", () => {
    const FLAG_ON = { CONTROL_TENANT_ACCOUNT_SOURCE: "tenant_object" } as const;

    // The flipped writer STOPS mirroring: it writes the typed registry columns
    // but leaves `document_json = NULL`. The flipped reader IGNORES the (now
    // empty) mirror and fans out across each tenant's own object.
    function fanOutStore() {
      return new SplitControlPlaneStore(db(), router(), {
        requestId: "split-store-test",
        tenantAccountSource: "tenant_object",
      });
    }

    async function seed(
      split: SplitControlPlaneStore,
      id: string,
      extra: Record<string, unknown>,
    ): Promise<StoreRecord> {
      const stored = await split.create("tenant-accounts", PLATFORM, { id, ...extra });
      await projectTenantAccount(db(), stored, 1000, FLAG_ON);
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

      // Red line: the WHOLE-document mirror is retired — the typed registry row
      // exists (roster/JOIN needs it) but its `document_json` is NULL.
      const mirrorRow = await db()
        .prepare("SELECT status, document_json FROM tenants WHERE id = ?")
        .bind(TENANT_A)
        .first<{ status: string; document_json: string | null }>();
      expect(mirrorRow?.status).toBe("active");
      expect(mirrorRow?.document_json).toBeNull();

      // The reader ignores the empty mirror and reproduces the object fan-out
      // exactly — same search/filter/pagination surface as the mirror path.
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
