/**
 * THE MOUNT GATE for `@ferrogate/storage`'s durable half on this Worker.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.1 recorded the defect this file
 * exists to make impossible again: `EnvBindingTenantDatabaseRouter`,
 * `ControlDatabaseTenantRegistry` and `D1ReferenceGuardedDeletes` were fully
 * implemented and fully tested inside `packages/storage`, and had **zero
 * importers under any app's `src`**. The package's own suite stayed green the
 * whole time, because it constructs its own router — which proves nothing about
 * what the deployed Worker does.
 *
 * So every assertion below drives the REAL exported Worker through `SELF.fetch`
 * and then reads the REAL per-tenant D1 database. Deleting the wiring in
 * `src/routes/tenant_hierarchy.ts` or `src/adapters.ts` turns this file red;
 * that is the whole point, and it was verified by mutation (see the slice
 * report).
 *
 * `store: "d1"` on every `arm()` call, deliberately: the in-memory store has no
 * database, so a test that armed `memory` would exercise the fallback and
 * silently prove nothing about the mount.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { rawTenantDocument } from "./tenant-object.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import {
  TENANT_A,
  TENANT_B,
  TENANT_UNROUTABLE,
  applyTenantSchema,
  projectIds,
  registerTenantDatabases,
  resetTenantD1,
  seedVirtualKey,
  tenantDbA,
  tenantDbB,
  workspaceIds,
} from "./tenant-db.js";

const OPERATOR = operatorKey.secret;
const A_KEY = "key-tenant-a";
const B_KEY = "key-tenant-b";
const UNROUTABLE_KEY = "key-tenant-unrouted";

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [
      tenantKey(A_KEY, TENANT_A),
      tenantKey(B_KEY, TENANT_B),
      tenantKey(UNROUTABLE_KEY, TENANT_UNROUTABLE),
    ],
  });
});

// ---------------------------------------------------------------------------
// The projection: an admin write reaches the tenant's OWN database
// ---------------------------------------------------------------------------

describe("per-tenant D1 projection", () => {
  it("writes a created project into the OWNING tenant's database and no other", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(A_KEY, "POST", { id: "proj_a", name: "Alpha" }),
    );
    expect(created.status).toBe(201);

    // The document is still the admin surface's record of truth...
    expect(await rawTenantDocument(TENANT_A, "projects", "proj_a")).toMatchObject({ tenant_id: TENANT_A });
    // ...and the typed row now exists, in tenant A's database ONLY. The second
    // assertion is what makes this a ROUTER test rather than a "some database
    // got written" test: a router that ignored its argument would satisfy the
    // first and fail this one.
    expect(await projectIds(tenantDbA())).toEqual(["proj_a"]);
    expect(await projectIds(tenantDbB())).toEqual([]);
  });

  it("routes to the ROW's tenant, not the caller's, for a platform operator", async () => {
    // An operator declares no tenancy of its own. Routing on the caller would
    // be an empty tenant id (a `runtime` refusal); routing on the row is the
    // only reading that can be right.
    const created = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(OPERATOR, "POST", { id: "proj_op", tenant_id: TENANT_B, name: "Beta" }),
    );
    expect(created.status).toBe(201);
    expect(await projectIds(tenantDbB())).toEqual(["proj_op"]);
    expect(await projectIds(tenantDbA())).toEqual([]);
  });

  it("writes a created workspace into the owning tenant's database", async () => {
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    const created = await SELF.fetch(
      `${BASE}/admin/v1/workspaces`,
      jsonRequest(A_KEY, "POST", { id: "ws_a", project_id: "proj_a", name: "Prod" }),
    );
    expect(created.status).toBe(201);
    expect(await workspaceIds(tenantDbA())).toEqual(["ws_a"]);
    expect(await workspaceIds(tenantDbB())).toEqual([]);
  });

  it("keeps the 409 on a duplicate id, and projects nothing for the refused create", async () => {
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    await tenantDbA().prepare("DELETE FROM projects").run();

    const again = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(A_KEY, "POST", { id: "proj_a" }),
    );
    // The DOCUMENT is the arbiter of identity — it is what returns the 409 —
    // and the tenant-row upsert must not be reached to paper over it.
    expect(again.status).toBe(409);
    expect(await projectIds(tenantDbA())).toEqual([]);
  });

  it("creates two same-named projects: the derived slug does not collide", async () => {
    // `projects.slug` is NOT NULL with `UNIQUE (tenant_id, slug)` and the admin
    // document carries no slug. A bare `slugify(name)` would make the second
    // "Staging" a UNIQUE violation — an admin surface rejecting a name it
    // accepted yesterday, over a column the operator never sees.
    const first = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(A_KEY, "POST", { id: "proj_1", name: "Staging" }),
    );
    const second = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(A_KEY, "POST", { id: "proj_2", name: "Staging" }),
    );
    expect([first.status, second.status]).toEqual([201, 201]);
    expect(await projectIds(tenantDbA())).toEqual(["proj_1", "proj_2"]);
  });
});

// ---------------------------------------------------------------------------
// §1.5.7 — the reference-guarded deletes, now reachable
// ---------------------------------------------------------------------------

describe("reference-guarded deletes (@ferrogate/storage §1.5.7)", () => {
  const seedProjectWithWorkspace = async (): Promise<void> => {
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    await SELF.fetch(
      `${BASE}/admin/v1/workspaces`,
      jsonRequest(A_KEY, "POST", { id: "ws_a", project_id: "proj_a" }),
    );
  };

  it("refuses to delete a project a workspace still references, and writes nothing", async () => {
    await seedProjectWithWorkspace();

    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(response.status).toBe(409);
    const body = (await response.json()) as { error: { message: string } };
    // The counts are in the message: "cannot delete" without "1 workspace is in
    // the way" leaves an operator with nothing to do next.
    expect(body.error.message).toContain("1 workspaces");

    // BOTH rows survive. A 409 that still deleted one leg would be worse than a
    // 200 that deleted both.
    expect(await rawTenantDocument(TENANT_A, "projects", "proj_a")).not.toBeNull();
    expect(await projectIds(tenantDbA())).toEqual(["proj_a"]);
  });

  it("refuses to delete a workspace a virtual API key still references", async () => {
    await seedProjectWithWorkspace();
    await seedVirtualKey(tenantDbA(), {
      id: "vk_1",
      tenantId: TENANT_A,
      projectId: "proj_a",
      workspaceId: "ws_a",
    });

    const response = await SELF.fetch(`${BASE}/admin/v1/workspaces/ws_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: { message: string } }).error.message).toContain(
      "1 virtual keys",
    );
    expect(await workspaceIds(tenantDbA())).toEqual(["ws_a"]);
  });

  it("allows the delete once the last reference is gone, clearing BOTH rows", async () => {
    await seedProjectWithWorkspace();

    const workspaceDelete = await SELF.fetch(`${BASE}/admin/v1/workspaces/ws_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(workspaceDelete.status).toBe(200);
    expect(await workspaceIds(tenantDbA())).toEqual([]);

    const projectDelete = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(projectDelete.status).toBe(200);
    expect(await projectIds(tenantDbA())).toEqual([]);
    expect(await rawTenantDocument(TENANT_A, "projects", "proj_a")).toBeNull();
  });

  it("does NOT let another tenant's workspace block the delete", async () => {
    // The decisive cross-tenant assertion. Tenant B creates a workspace whose
    // `project_id` is the literal string "proj_a" — the same id tenant A's
    // project has. Under the DB-per-tenant topology that row is in ANOTHER
    // database and is invisible to A's guard, so A's delete must succeed.
    //
    // On a shared database — which is what a `SharedDatabaseTenantRouter`, a
    // router that ignored its argument, or a `WHERE project_id = ?` guard
    // missing its tenant fence would all produce — B's row would be counted and
    // A would be refused. So this test fails for a router that resolves the
    // wrong handle, which no assertion inside `packages/storage` can see.
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    await SELF.fetch(
      `${BASE}/admin/v1/workspaces`,
      jsonRequest(B_KEY, "POST", { id: "ws_b", project_id: "proj_a" }),
    );
    expect(await workspaceIds(tenantDbB())).toEqual(["ws_b"]);
    expect(await workspaceIds(tenantDbA())).toEqual([]);

    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(response.status).toBe(200);
    expect(await projectIds(tenantDbA())).toEqual([]);
    // ...and B's workspace is untouched by A's delete.
    expect(await workspaceIds(tenantDbB())).toEqual(["ws_b"]);
  });

  it("still 404s another tenant's project before it ever routes", async () => {
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(B_KEY),
    });
    // The store's tenant fence decides first, so B never reaches A's database.
    expect(response.status).toBe(404);
    expect(await projectIds(tenantDbA())).toEqual(["proj_a"]);
  });
});

// ---------------------------------------------------------------------------
// The fail-closed split: "not provisioned" and "unroutable" are NOT the same
// ---------------------------------------------------------------------------

describe("tenant database resolution", () => {
  it("answers 503 — never a silent document-only write — for a registered but unroutable tenant", async () => {
    // `tenant_unrouted` names `TENANT_DB_NOT_DEPLOYED`, which this Worker does
    // not have. The operator asked for per-tenant isolation and the deployment
    // cannot deliver it; degrading to a document-only write here would leave the
    // isolation claim true on paper and false in the database.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(UNROUTABLE_KEY, "POST", { id: "proj_x" }),
    );
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("tenant_database_unavailable");
  });

  it("falls back to document-only for a tenant with NO registry row", async () => {
    // Every deployment that has not onboarded a tenant database is in this
    // state, including a fresh `wrangler dev --local`, so this is the branch
    // that must not regress. There are no typed rows anywhere, therefore no
    // references, therefore nothing for the guard to refuse.
    await db_deleteRegistry();
    const created = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(A_KEY, "POST", { id: "proj_a" }),
    );
    expect(created.status).toBe(201);
    expect(await projectIds(tenantDbA())).toEqual([]);

    const deleted = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(deleted.status).toBe(200);
    expect(await rawTenantDocument(TENANT_A, "projects", "proj_a")).toBeNull();
  });

  it("deletes a document that predates the projection, without inventing a 404", async () => {
    // A document created before this seam existed has no typed row. The guarded
    // delete reports `not_found` in the tenant database, which is NOT the
    // operator's answer: the document exists and is what they asked to remove.
    await SELF.fetch(`${BASE}/admin/v1/projects`, jsonRequest(A_KEY, "POST", { id: "proj_a" }));
    await tenantDbA().prepare("DELETE FROM projects").run();

    const deleted = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(A_KEY),
    });
    expect(deleted.status).toBe(200);
    expect(await rawTenantDocument(TENANT_A, "projects", "proj_a")).toBeNull();
  });
});

/** Drop every registry row, so no tenant resolves to a database. */
async function db_deleteRegistry(): Promise<void> {
  const { db } = await import("./d1.js");
  await db().prepare("DELETE FROM tenant_databases").run();
}
