/**
 * The ASSET FLEET admin surface (#743): inventory, quarantine queue, review.
 *
 * Three properties are under test and only one of them is "the endpoint
 * answers". The other two are the reasons the endpoint is dangerous:
 *
 *  1. **The cross-tenant fence.** A surface that lists assets across tenants is
 *     the single most dangerous read in this repo, so seeing another tenant's
 *     rows must be a DISTINCT, deliberate grant — `admin.assets.fleet`, held
 *     EXACTLY — and never a side effect of being a platform operator or of
 *     holding the `*` wildcard the operator keys are minted with. Every
 *     assertion below that says "403" is that fence; every assertion that says
 *     "only these ids" is the fence holding on the data rather than on the
 *     status code.
 *  2. **Metadata is not content.** The inventory answers rows, never bytes and
 *     never a locator for bytes: `storage_uri` (the R2 object key) is withheld
 *     from every projection. Listing an artifact and being able to fetch it are
 *     two different permissions and this surface only ever grants the first.
 *  3. **An unattributed release is worse than no surface.** Every review
 *     decision writes a durable, hash-chained `audit_events` row naming the
 *     actor, and the decision record it points at carries the reason. A release
 *     with no reason is a 400 and the row does not move.
 *
 * The tenant databases are REAL (`TENANT_DB_A` / `TENANT_DB_B`, the real
 * `sql/d1-ts/tenant/` migration) because `stored_assets` lives in the tenant
 * database, not the control one. Two of them, not one: a cross-tenant assertion
 * against a single shared database is vacuous — it would pass against a router
 * that ignored its argument.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, auditRows, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, tenantKey } from "./harness.js";
import {
  TENANT_A,
  TENANT_B,
  TENANT_UNROUTABLE,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
  tenantDbB,
} from "./tenant-db.js";

/** A platform operator holding the wildcard — and NOT the fleet grant. */
const WILDCARD_OPERATOR = "wildcard-operator-secret";
/** A platform operator that was deliberately granted the fleet view. */
const FLEET_OPERATOR = "fleet-operator-secret";
/** A tenant-scoped admin credential for `tenant_a`. */
const TENANT_A_KEY = "tenant-a-admin-secret";

interface AssetSeed {
  readonly id: string;
  readonly tenantId: string;
  readonly assetType?: string;
  readonly name?: string;
  readonly version?: string;
  readonly variant?: string;
  readonly visibility?: "visible" | "pending_scan" | "quarantined";
  readonly sizeBytes?: number;
  readonly yanked?: boolean;
}

/**
 * Insert `stored_assets` rows with raw SQL.
 *
 * Deliberately not through `apps/gateway`'s `D1AssetMetadataStore`: that is a
 * different Worker and cannot be driven from here, and a fixture built with the
 * code under test could not show that the reader reads what the table holds.
 */
async function seedAssets(handle: D1Database, rows: readonly AssetSeed[]): Promise<void> {
  if (rows.length === 0) return;
  await handle.batch(
    rows.map((row) =>
      handle
        .prepare(
          `INSERT INTO stored_assets
             (id, tenant_id, project_id, asset_type, name, version, content_type,
              content_hash, size_bytes, created_at_unix, updated_at_unix, storage_uri,
              variant, yanked, visibility)
           VALUES (?, ?, NULL, ?, ?, ?, 'application/x-tar', 'sha256:deadbeef', ?, 100, 200, ?, ?, ?, ?)`,
        )
        .bind(
          row.id,
          row.tenantId,
          row.assetType ?? "static_site",
          // `(tenant, asset_type, name, version, variant)` is UNIQUE, so the id
          // is the default name: a fixture that collided would fail in the
          // INSERT and never reach the assertion it was written for.
          row.name ?? row.id,
          row.version ?? "1.0.0",
          row.sizeBytes ?? 1024,
          // The R2 key. It is seeded precisely so the "no locator" assertions
          // below have something real that could leak.
          `assets/${row.tenantId}/${row.id}.tar`,
          row.variant ?? "",
          row.yanked === true ? 1 : 0,
          row.visibility ?? "visible",
        ),
    ),
  );
}

/** The `visibility` a row currently holds, straight out of the table. */
async function visibilityOf(handle: D1Database, id: string): Promise<string | null> {
  const row = await handle
    .prepare("SELECT visibility FROM stored_assets WHERE id = ?")
    .bind(id)
    .first<{ visibility: string }>();
  return row === null ? null : row.visibility;
}

interface ListBody {
  readonly object: string;
  readonly data: readonly Record<string, unknown>[];
  readonly total?: number;
}

function ids(body: ListBody): string[] {
  return body.data.map((row) => String(row.id)).sort();
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
  await Promise.all(
    [tenantDbA(), tenantDbB()].map((handle) => handle.prepare("DELETE FROM stored_assets").run()),
  );
  arm({
    store: "d1",
    staticKeys: [
      {
        secret: WILDCARD_OPERATOR,
        id: "static_wildcard_operator",
        platform_operator: true,
        scopes: ["*"],
      },
      {
        secret: FLEET_OPERATOR,
        id: "static_fleet_operator",
        platform_operator: true,
        scopes: ["admin.read", "admin.write", "admin.assets.fleet"],
      },
    ],
    nativeKeys: [tenantKey(TENANT_A_KEY, TENANT_A)],
  });
});

describe("GET /admin/v1/assets — the fleet inventory", () => {
  it("answers a tenant's own assets to its own admin credential", async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_a1", tenantId: TENANT_A, name: "docs", version: "1.0.0" },
      { id: "asset_a2", tenantId: TENANT_A, name: "cli", assetType: "binary" },
    ]);
    await seedAssets(tenantDbB(), [{ id: "asset_b1", tenantId: TENANT_B }]);

    const response = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListBody;
    expect(body.object).toBe("list");
    expect(ids(body)).toEqual(["asset_a1", "asset_a2"]);
    expect(body.data[0]).toMatchObject({
      object: "fleet_asset",
      tenant_id: TENANT_A,
      asset_type: "binary",
      visibility: "visible",
    });
  });

  it("filters by asset_type and by visibility", async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_site", tenantId: TENANT_A, assetType: "static_site" },
      { id: "asset_bin", tenantId: TENANT_A, assetType: "binary" },
      {
        id: "asset_held",
        tenantId: TENANT_A,
        assetType: "static_site",
        visibility: "quarantined",
      },
    ]);

    const byType = await SELF.fetch(`${BASE}/admin/v1/assets?asset_type=binary`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(ids((await byType.json()) as ListBody)).toEqual(["asset_bin"]);

    const byVisibility = await SELF.fetch(`${BASE}/admin/v1/assets?visibility=quarantined`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(ids((await byVisibility.json()) as ListBody)).toEqual(["asset_held"]);
  });

  it("refuses an unknown visibility rather than silently ignoring the filter", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/assets?visibility=deleted`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(response.status).toBe(400);
  });
});

describe("the cross-tenant fence — a DISTINCT grant, never a side effect", () => {
  beforeEach(async () => {
    await seedAssets(tenantDbA(), [{ id: "asset_a1", tenantId: TENANT_A }]);
    await seedAssets(tenantDbB(), [{ id: "asset_b1", tenantId: TENANT_B }]);
  });

  it("refuses a platform operator holding only the WILDCARD scope", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: bearer(WILDCARD_OPERATOR),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("asset_fleet_scope_required");
    // The refusal names the grant, so the operator's next action is to mint it
    // rather than to guess.
    expect(body.error.message).toContain("admin.assets.fleet");
  });

  it("refuses the same operator even when it names ONE tenant", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/assets?tenant_id=${TENANT_B}`, {
      headers: bearer(WILDCARD_OPERATOR),
    });
    expect(response.status).toBe(403);
    expect(await response.text()).not.toContain("asset_b1");
  });

  it("serves EVERY tenant to an operator that holds the fleet grant", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: bearer(FLEET_OPERATOR),
    });
    expect(response.status).toBe(200);
    expect(ids((await response.json()) as ListBody)).toEqual(["asset_a1", "asset_b1"]);
  });

  it("NAMES a tenant it could not read rather than dropping it silently", async () => {
    // `registerTenantDatabases` registers `tenant_unrouted` against a binding
    // this Worker does not have — "provisioned but not yet redeployed". The
    // fleet read answers what it could reach AND says what it could not; a
    // partial inventory read as complete is how an abuse response misses the
    // abuse.
    const response = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: bearer(FLEET_OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListBody & { unreadable_tenants: string[] };
    expect(ids(body)).toEqual(["asset_a1", "asset_b1"]);
    expect(body.unreadable_tenants).toEqual([TENANT_UNROUTABLE]);
  });

  it("503s when the ONE tenant the request is about is unreachable", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/assets?tenant_id=${TENANT_UNROUTABLE}`, {
      headers: bearer(FLEET_OPERATOR),
    });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("tenant_database_unavailable");
  });

  it("confines a tenant credential to its own tenant even with the grant named", async () => {
    // The scope of a native key is its tenant; asking for another tenant is a
    // refusal, not a silent coercion back to its own rows — a caller told "200"
    // over a filtered-away result set cannot tell that it was denied.
    const response = await SELF.fetch(`${BASE}/admin/v1/assets?tenant_id=${TENANT_B}`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(response.status).toBe(403);
    expect(await response.text()).not.toContain("asset_b1");
  });
});

describe("metadata is not content", () => {
  it("never returns the object key that locates the bytes", async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_a1", tenantId: TENANT_A, visibility: "quarantined" },
    ]);

    for (const path of ["/admin/v1/assets", "/admin/v1/assets/quarantine"]) {
      const response = await SELF.fetch(`${BASE}${path}`, { headers: bearer(TENANT_A_KEY) });
      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text, `${path} leaked the storage key`).not.toContain("storage_uri");
      expect(text, `${path} leaked the object key`).not.toContain("assets/tenant_a/");
    }
  });
});

describe("GET /admin/v1/assets/quarantine — the review queue", () => {
  it("lists only the WITHHELD rows, never a servable one", async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_live", tenantId: TENANT_A, visibility: "visible" },
      { id: "asset_pending", tenantId: TENANT_A, visibility: "pending_scan" },
      { id: "asset_quarantined", tenantId: TENANT_A, visibility: "quarantined" },
    ]);

    const response = await SELF.fetch(`${BASE}/admin/v1/assets/quarantine`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListBody;
    expect(ids(body)).toEqual(["asset_pending", "asset_quarantined"]);
    expect(body.data[0]).toMatchObject({ object: "quarantined_asset" });
  });

  it("is fenced by the same distinct grant as the inventory", async () => {
    await seedAssets(tenantDbB(), [
      { id: "asset_b1", tenantId: TENANT_B, visibility: "quarantined" },
    ]);
    const response = await SELF.fetch(`${BASE}/admin/v1/assets/quarantine`, {
      headers: bearer(WILDCARD_OPERATOR),
    });
    expect(response.status).toBe(403);
    expect(await response.text()).not.toContain("asset_b1");
  });
});

describe("POST /admin/v1/assets/quarantine/{asset_id} — the review decision", () => {
  beforeEach(async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_held", tenantId: TENANT_A, visibility: "pending_scan" },
      { id: "asset_live", tenantId: TENANT_A, visibility: "visible" },
    ]);
    await seedAssets(tenantDbB(), [
      { id: "asset_b_held", tenantId: TENANT_B, visibility: "quarantined" },
    ]);
  });

  it("releases a withheld version and writes an ATTRIBUTED audit row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_held`,
      jsonRequest(FLEET_OPERATOR, "POST", {
        tenant_id: TENANT_A,
        decision: "release",
        reason: "manual review: false positive on the vendored font blob",
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      object: string;
      asset_review: Record<string, unknown>;
    };
    expect(body.object).toBe("asset_review");
    expect(body.asset_review).toMatchObject({
      asset_id: "asset_held",
      tenant_id: TENANT_A,
      decision: "release",
      from_visibility: "pending_scan",
      to_visibility: "visible",
      applied: true,
      actor_scope: "platform_operator",
      actor_key_id: "static_fleet_operator",
      reason: "manual review: false positive on the vendored font blob",
    });

    // The state moved through the ONE column every read path already filters on.
    expect(await visibilityOf(tenantDbA(), "asset_held")).toBe("visible");

    // …and it is attributable. The audit row lands on the TENANT's chain (the
    // tenant whose asset was released), naming the decision record that carries
    // the reason.
    const rows = await auditRows();
    const created = rows.filter(
      (row) =>
        row.audit.collection === "asset-reviews" && row.audit.resource_id === body.asset_review.id,
    );
    expect(created.length).toBeGreaterThan(0);
    expect(created[0]?.tenant).toBe(TENANT_A);
    expect(created[0]?.audit).toMatchObject({ actor_scope: "platform_operator" });

    const stored = await db()
      .prepare(
        "SELECT document_json FROM control_plane_resources WHERE resource_kind = 'asset-reviews' AND resource_id = ?",
      )
      .bind(String(body.asset_review.id))
      .first<{ document_json: string }>();
    expect(JSON.parse(String(stored?.document_json))).toMatchObject({
      reason: "manual review: false positive on the vendored font blob",
      decision: "release",
    });
  });

  it("keeps a rejected version withheld, hardened to quarantined", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_held`,
      jsonRequest(FLEET_OPERATOR, "POST", {
        tenant_id: TENANT_A,
        decision: "reject",
        reason: "confirmed malware sample",
      }),
    );
    expect(response.status).toBe(200);
    expect(await visibilityOf(tenantDbA(), "asset_held")).toBe("quarantined");
  });

  it("REFUSES a decision with no reason, and does not move the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_held`,
      jsonRequest(FLEET_OPERATOR, "POST", { tenant_id: TENANT_A, decision: "release" }),
    );
    expect(response.status).toBe(400);
    expect(await visibilityOf(tenantDbA(), "asset_held")).toBe("pending_scan");
    // Nothing was recorded either: a decision record for a decision that was
    // never made is a lie in the trail.
    expect((await auditRows()).filter((row) => row.audit.collection === "asset-reviews")).toEqual(
      [],
    );
  });

  it("refuses to review a version that is not withheld", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_live`,
      jsonRequest(FLEET_OPERATOR, "POST", {
        tenant_id: TENANT_A,
        decision: "reject",
        reason: "taking it down",
      }),
    );
    // This surface reviews the queue; a live version is a takedown, which is a
    // different verb with a different blast radius.
    expect(response.status).toBe(409);
    expect(await visibilityOf(tenantDbA(), "asset_live")).toBe("visible");
  });

  it("cannot be used across the tenant boundary", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_b_held`,
      jsonRequest(TENANT_A_KEY, "POST", {
        tenant_id: TENANT_B,
        decision: "release",
        reason: "not mine to release",
      }),
    );
    expect(response.status).toBe(403);
    expect(await visibilityOf(tenantDbB(), "asset_b_held")).toBe("quarantined");
  });

  it("refuses a platform operator without the distinct fleet grant", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_held`,
      jsonRequest(WILDCARD_OPERATOR, "POST", {
        tenant_id: TENANT_A,
        decision: "release",
        reason: "wildcard should not be enough",
      }),
    );
    expect(response.status).toBe(403);
    expect(await visibilityOf(tenantDbA(), "asset_held")).toBe("pending_scan");
  });
});
