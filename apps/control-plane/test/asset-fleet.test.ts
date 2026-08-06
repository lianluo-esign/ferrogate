/**
 * The ASSET FLEET admin surface (#743): inventory, quarantine queue, review,
 * force-delete.
 *
 * Five properties are under test and only one of them is "the endpoint
 * answers". The others are the reasons the endpoint is dangerous:
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
 *  4. **Reading is one authority, DECIDING is another.** A tenant may SEE that
 *     its own version is withheld and may NOT move it: releasing its own
 *     quarantined asset would be the reviewed party overturning the #366
 *     screener's verdict on its own content, and force-deleting is strictly
 *     more powerful again. Both refusals are asserted on the ROW as well as on
 *     the status code — a 403 whose state changed anyway is the worse bug.
 *  5. **A takedown takes the bytes down.** The force-delete's assertions read
 *     the real R2 bucket back, so a metadata-only delete — which would answer
 *     `deleted: true` over bytes that are still there — fails them. The
 *     response also has to say WHICH operation happened: retiring an
 *     unreferenced version and taking down a version a channel is serving are
 *     different acts, and the second needs `?force=true` asked for by name.
 *
 * The tenant databases are REAL (`TENANT_DB_A` / `TENANT_DB_B`, the real
 * `sql/d1-ts/tenant/` migration) because `stored_assets` lives in the tenant
 * database, not the control one. Two of them, not one: a cross-tenant assertion
 * against a single shared database is vacuous — it would pass against a router
 * that ignored its argument.
 */
import { SELF, env } from "cloudflare:test";
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
import { tenantObjectDb } from "./tenant-object.js";

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

/**
 * The REAL asset bucket binding, the one `wrangler.toml` declares.
 *
 * The force-delete's whole claim is that the bytes go, so the assertions below
 * put real objects in this bucket and read it back afterwards. Asserting only
 * on the D1 rows would pass against exactly the metadata-only delete the verb
 * was deferred to avoid.
 */
function assetBucket(): R2Bucket {
  return (env as unknown as { ASSETS: R2Bucket }).ASSETS;
}

/** Put an object at `key`, so a later delete has something real to remove. */
async function putObject(key: string, body = "artifact-bytes"): Promise<void> {
  await assetBucket().put(key, body);
}

/** Does the bucket still hold `key`? */
async function objectExists(key: string): Promise<boolean> {
  return (await assetBucket().head(key)) !== null;
}

/** Seed one `asset_bundle_files` row (#736) — a bundle's per-file object. */
async function seedBundleFile(
  handle: D1Database,
  assetId: string,
  tenantId: string,
  path: string,
  storageUri: string,
): Promise<void> {
  await handle
    .prepare(
      `INSERT INTO asset_bundle_files
         (asset_id, tenant_id, path, storage_uri, content_type, content_hash, size_bytes, created_at_unix)
       VALUES (?, ?, ?, ?, 'text/html', 'sha256:beef', 12, 100)`,
    )
    .bind(assetId, tenantId, path, storageUri)
    .run();
}

/** Seed one `asset_channels` row — the pointer `/sites/{slug}` resolves through. */
async function seedChannel(
  handle: D1Database,
  tenantId: string,
  channel: string,
  options: { readonly assetType?: string; readonly name: string; readonly version: string },
): Promise<void> {
  const assetType = options.assetType ?? "static_site";
  await handle
    .prepare(
      `INSERT INTO asset_channels (id, tenant_id, asset_type, name, channel, version, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, 100)`,
    )
    .bind(
      `${tenantId}:${assetType}:${options.name}:${channel}`,
      tenantId,
      assetType,
      options.name,
      channel,
      options.version,
    )
    .run();
}

/** Channel names still pointing at one logical version. */
async function channelsFor(handle: D1Database, name: string): Promise<string[]> {
  const rows = await handle
    .prepare("SELECT channel FROM asset_channels WHERE name = ? ORDER BY channel")
    .bind(name)
    .all<{ channel: string }>();
  return (rows.results ?? []).map((row) => row.channel);
}

/** How many `asset_bundle_files` rows one version still owns. */
async function bundleFileCount(handle: D1Database, assetId: string): Promise<number> {
  const row = await handle
    .prepare("SELECT COUNT(*) AS n FROM asset_bundle_files WHERE asset_id = ?")
    .bind(assetId)
    .first<{ n: number }>();
  return row === null ? 0 : row.n;
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
    [tenantDbA(), tenantDbB()].flatMap((handle) => [
      handle.prepare("DELETE FROM stored_assets").run(),
      handle.prepare("DELETE FROM asset_bundle_files").run(),
      handle.prepare("DELETE FROM asset_channels").run(),
    ]),
  );
  // The pool persists R2 under `.wrangler/state` exactly as it persists D1, so
  // a leftover object from a previous run would make a "the bytes are gone"
  // assertion pass for the wrong reason (or fail for one).
  const listed = await assetBucket().list();
  if (listed.objects.length > 0) {
    await assetBucket().delete(listed.objects.map((object) => object.key));
  }
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

  it("pages a fleet wider than the fan-out cap instead of returning a truncated inventory", async () => {
    const extraTenants = Array.from({ length: 51 }, (_, index) => `tenant_extra_${index}`);
    await db().batch(
      extraTenants.map((tenantId) =>
        db()
          .prepare(
            `INSERT INTO tenant_databases
               (tenant_id, storage_backend, provisioning_status, schema_version,
                migration_state, binding_name)
             VALUES (?, 'native_binding', 'ready', 1, 'done', 'TENANT_DB_A')`,
          )
          .bind(tenantId),
      ),
    );

    const response = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: bearer(FLEET_OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListBody & {
      tenant_page: { offset: number; limit: number; total: number; has_more: boolean };
    };
    expect(body.tenant_page).toEqual({ offset: 0, limit: 50, total: 54, has_more: true });

    const nextResponse = await SELF.fetch(`${BASE}/admin/v1/assets?tenant_offset=50`, {
      headers: bearer(FLEET_OPERATOR),
    });
    expect(nextResponse.status).toBe(200);
    const nextBody = (await nextResponse.json()) as ListBody & {
      tenant_page: { offset: number; limit: number; total: number; has_more: boolean };
    };
    expect(nextBody.tenant_page).toEqual({ offset: 50, limit: 50, total: 54, has_more: false });
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

    // `asset-reviews` is tenant-private after the split; the control row is the
    // audit projection, while the decision document lives in the owning object.
    const stored = await tenantObjectDb(TENANT_A)
      .prepare(
        "SELECT document_json FROM tenant_resources WHERE resource_kind = 'asset-reviews' AND resource_id = ?",
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

  /**
   * THE escalation. A tenant may SEE that its version is withheld — that read
   * is deliberate and is asserted at the bottom of this test — and must not be
   * able to decide the screener's verdict on its own content. Releasing is
   * reversing #366's withholding for the very tenant whose bytes were
   * withheld; `apps/gateway/src/assets/d1.ts`'s promotion CAS guards
   * `AND visibility = 'pending_scan'` precisely so the data plane cannot be
   * used this way, and an admin surface that authorised the WRITE with the
   * READ's fence would hand the same power back through a different door.
   *
   * Both halves are asserted, and the second is the one that matters more: a
   * 403 whose row moved anyway is worse than an outright 200, because the
   * operator reads a refusal while the state changed.
   */
  it("REFUSES the owning tenant's own admin.write credential, and does not move the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/assets/quarantine/asset_held`,
      jsonRequest(TENANT_A_KEY, "POST", {
        tenant_id: TENANT_A,
        decision: "release",
        reason: "it is my own asset and I want it served again",
      }),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("asset_fleet_write_operator_only");

    // The row did not move: `pending_scan` is still what every read path
    // filters on, so the artifact is still withheld.
    expect(await visibilityOf(tenantDbA(), "asset_held")).toBe("pending_scan");
    // …and no decision was recorded. A refused decision that still appears in
    // the trail is a lie in the other direction.
    expect((await auditRows()).filter((row) => row.audit.collection === "asset-reviews")).toEqual(
      [],
    );

    // The READ side is untouched: the tenant can still see that its own
    // version is being withheld. Fixing the write by fencing the read would
    // hide the queue from the only party that can fix the artifact.
    const queue = await SELF.fetch(`${BASE}/admin/v1/assets/quarantine`, {
      headers: bearer(TENANT_A_KEY),
    });
    expect(queue.status).toBe(200);
    expect(ids((await queue.json()) as ListBody)).toEqual(["asset_held"]);
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

/**
 * `DELETE /admin/v1/assets/{asset_id}` — the operator FORCE-DELETE (#743's
 * third "Done when" bullet).
 *
 * Three properties, and only the first is "the endpoint answers":
 *
 *  1. **It is operator-only, like the review and for a stronger reason.** A
 *     force-delete is strictly more powerful than a release, so a tenant-scoped
 *     credential is refused and NOTHING is deleted — asserted on the row and on
 *     the bucket, because a refusal whose bytes went anyway is the worse bug.
 *  2. **The bytes actually go.** Every deletion assertion reads the REAL R2
 *     bucket back. A metadata-only delete — the exact failure this verb was
 *     deferred to avoid — passes a row-only test and fails these.
 *  3. **It says which operation the operator just performed.** Deleting an
 *     unreferenced version and taking down a version a channel is serving are
 *     different acts: the second is refused unless `force=true` is asked for by
 *     name, and when it does happen the response NAMES the channels that went
 *     dark.
 */
describe("DELETE /admin/v1/assets/{asset_id} — the operator force-delete", () => {
  const ARCHIVE = `assets/${TENANT_A}/asset_site.tar`;
  const PAGE = `assets/${TENANT_A}/asset_site/index.html`;

  beforeEach(async () => {
    await seedAssets(tenantDbA(), [
      { id: "asset_site", tenantId: TENANT_A, name: "docs", version: "1.0.0" },
    ]);
    await seedBundleFile(tenantDbA(), "asset_site", TENANT_A, "index.html", PAGE);
    await putObject(ARCHIVE);
    await putObject(PAGE);
  });

  function deleteRequest(
    secret: string,
    id: string,
    query: Record<string, string>,
  ): [string, RequestInit] {
    const search = new URLSearchParams(query).toString();
    return [
      `${BASE}/admin/v1/assets/${id}?${search}`,
      { method: "DELETE", headers: bearer(secret) },
    ];
  }

  /** Everything a refusal must leave exactly as it found it. */
  async function nothingWasDeleted(): Promise<void> {
    expect(await visibilityOf(tenantDbA(), "asset_site")).toBe("visible");
    expect(await bundleFileCount(tenantDbA(), "asset_site")).toBe(1);
    expect(await objectExists(ARCHIVE), "the archive object survived").toBe(true);
    expect(await objectExists(PAGE), "the bundle file object survived").toBe(true);
    // A destroyed artifact with no decision record is unattributable; a
    // decision record with no destroyed artifact is a lie. Neither, here.
    expect((await auditRows()).filter((row) => row.audit.collection === "asset-deletions")).toEqual(
      [],
    );
  }

  it("REFUSES a tenant credential — its own asset included — and deletes nothing", async () => {
    // The escalation, in its more dangerous form: a release can be re-reviewed,
    // a force-delete cannot be undone.
    const response = await SELF.fetch(
      ...deleteRequest(TENANT_A_KEY, "asset_site", {
        tenant_id: TENANT_A,
        reason: "it is my asset and I want it gone",
      }),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("asset_fleet_write_operator_only");
    await nothingWasDeleted();
  });

  it("refuses a platform operator without the distinct fleet grant", async () => {
    const response = await SELF.fetch(
      ...deleteRequest(WILDCARD_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "the wildcard is not this grant",
      }),
    );
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "asset_fleet_scope_required",
    );
    await nothingWasDeleted();
  });

  it("REFUSES a delete with no reason, and deletes nothing", async () => {
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", { tenant_id: TENANT_A }),
    );
    expect(response.status).toBe(400);
    await nothingWasDeleted();
  });

  it("RETIRES an unreferenced version: row, bundle index and objects all go", async () => {
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "takedown: phishing kit reported by the registrar",
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      object: string;
      asset_deletion: Record<string, unknown>;
    };
    expect(body.object).toBe("asset_deletion");
    expect(body.asset_deletion).toMatchObject({
      asset_id: "asset_site",
      tenant_id: TENANT_A,
      name: "docs",
      version: "1.0.0",
      deleted: true,
      applied: true,
      force: false,
      // Nothing was serving it, so nothing went dark — the operator is told
      // which of the two operations this was.
      served_by_channels: [],
      detached_channels: [],
      // The archive plus the one bundle file.
      objects_deleted: 2,
      reason: "takedown: phishing kit reported by the registrar",
      actor_scope: "platform_operator",
      actor_key_id: "static_fleet_operator",
    });
    // The row is gone…
    expect(await visibilityOf(tenantDbA(), "asset_site")).toBeNull();
    // …the per-file index with it (#736)…
    expect(await bundleFileCount(tenantDbA(), "asset_site")).toBe(0);
    // …and so are the BYTES. This is the assertion a metadata-only delete
    // fails, and it is the reason the verb needs the bucket binding at all.
    expect(await objectExists(ARCHIVE), "the archive object is gone").toBe(false);
    expect(await objectExists(PAGE), "the bundle file object is gone").toBe(false);

    // Attributable, on the OWNING tenant's chain — the tenant can see what was
    // deleted and by whom even though it could never have deleted it itself.
    const chained = (await auditRows()).filter(
      (row) =>
        row.audit.collection === "asset-deletions" &&
        row.audit.resource_id === body.asset_deletion.id,
    );
    expect(chained.length).toBeGreaterThan(0);
    expect(chained[0]?.tenant).toBe(TENANT_A);
  });

  it("REFUSES to take down a version a channel is serving, and NAMES the channel", async () => {
    await seedChannel(tenantDbA(), TENANT_A, "latest", { name: "docs", version: "1.0.0" });
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "abuse report",
      }),
    );
    expect(response.status).toBe(409);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("asset_version_referenced");
    // Deleting bytes out from under a live channel is a DIFFERENT operation
    // from retiring an unreferenced version, so the refusal says what would go
    // dark rather than just refusing.
    expect(body.error.message).toContain("latest");
    await nothingWasDeleted();
    expect(await channelsFor(tenantDbA(), "docs")).toEqual(["latest"]);
  });

  it("takes the live version down with force=true, and REPORTS the channels that went dark", async () => {
    await seedChannel(tenantDbA(), TENANT_A, "latest", { name: "docs", version: "1.0.0" });
    await seedChannel(tenantDbA(), TENANT_A, "stable", { name: "docs", version: "1.0.0" });
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "court-ordered takedown of the published site",
        force: "true",
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { asset_deletion: Record<string, unknown> };
    expect(body.asset_deletion).toMatchObject({
      force: true,
      served_by_channels: ["latest", "stable"],
      // THE field that says a live site was taken down, not that an unused
      // version was retired.
      detached_channels: ["latest", "stable"],
      deleted: true,
    });
    // The channels are gone WITH the version: `apps/gateway`'s invariant is
    // that a channel never points at an absent version, and a dangling channel
    // would 404 in a way that looks like a bug rather than like a takedown.
    expect(await channelsFor(tenantDbA(), "docs")).toEqual([]);
    expect(await visibilityOf(tenantDbA(), "asset_site")).toBeNull();
    expect(await objectExists(ARCHIVE)).toBe(false);
  });

  it("does not need force when another live variant keeps the channel resolving", async () => {
    await seedAssets(tenantDbA(), [
      {
        id: "asset_site_arm",
        tenantId: TENANT_A,
        name: "docs",
        version: "1.0.0",
        variant: "arm64",
      },
    ]);
    await seedChannel(tenantDbA(), TENANT_A, "latest", { name: "docs", version: "1.0.0" });
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "the x86 build was the malicious one",
      }),
    );
    // Same predicate `apps/gateway`'s own delete puts inside its statement: a
    // channel that still resolves was never stranded, so this is a retirement
    // and not a takedown.
    expect(response.status).toBe(200);
    const body = (await response.json()) as { asset_deletion: Record<string, unknown> };
    expect(body.asset_deletion).toMatchObject({
      served_by_channels: ["latest"],
      detached_channels: [],
    });
    expect(await channelsFor(tenantDbA(), "docs")).toEqual(["latest"]);
    expect(await visibilityOf(tenantDbA(), "asset_site")).toBeNull();
    expect(await visibilityOf(tenantDbA(), "asset_site_arm")).toBe("visible");
  });

  it("refuses ?force= that is neither true nor false rather than reading it as false", async () => {
    const response = await SELF.fetch(
      ...deleteRequest(FLEET_OPERATOR, "asset_site", {
        tenant_id: TENANT_A,
        reason: "typo in the flag",
        force: "yes",
      }),
    );
    expect(response.status).toBe(400);
    await nothingWasDeleted();
  });

  it("cannot be aimed at another tenant's asset by a tenant credential", async () => {
    await seedAssets(tenantDbB(), [{ id: "asset_b_live", tenantId: TENANT_B }]);
    const response = await SELF.fetch(
      ...deleteRequest(TENANT_A_KEY, "asset_b_live", {
        tenant_id: TENANT_B,
        reason: "not mine to delete",
      }),
    );
    expect(response.status).toBe(403);
    expect(await visibilityOf(tenantDbB(), "asset_b_live")).toBe("visible");
  });

  it("answers 503 and DELETES nothing when the deployment binds no ASSETS bucket", async () => {
    // A deployment that never bound the bucket must not get a metadata-only
    // delete that reports a takedown while the bytes stay where they are. The
    // binding is removed for exactly this request and restored afterwards.
    const bindings = env as unknown as { ASSETS?: R2Bucket };
    const bucket = bindings.ASSETS;
    bindings.ASSETS = undefined;
    try {
      const response = await SELF.fetch(
        ...deleteRequest(FLEET_OPERATOR, "asset_site", {
          tenant_id: TENANT_A,
          reason: "no bucket on this deployment",
        }),
      );
      expect(response.status).toBe(503);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        "asset_bucket_not_configured",
      );
      expect(await visibilityOf(tenantDbA(), "asset_site")).toBe("visible");
      expect(await bundleFileCount(tenantDbA(), "asset_site")).toBe(1);
      expect(
        (await auditRows()).filter((row) => row.audit.collection === "asset-deletions"),
      ).toEqual([]);
    } finally {
      bindings.ASSETS = bucket;
    }
  });
});
