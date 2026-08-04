/**
 * The WRITE half of `rbac`, driven end-to-end through the exported Worker
 * against a REAL D1 binding.
 *
 * ## Why this file exists, and why `rbac-d1.test.ts` did not catch it
 *
 * `rbac-d1.test.ts` proves the READER: it writes `roles` /
 * `tenant_role_bindings` with raw SQL and shows `D1RbacAuthorizer` authorizes on
 * them. That is the right shape for a reader test, and it is exactly why it
 * could not see this defect — it never once used the admin API to state a
 * grant.
 *
 * The wave-15 control-plane certification found the other half open: all eleven
 * `rbac` operations wrote a `control_plane_resources` DOCUMENT and nothing else,
 * while every RBAC reader in the fleet joins the TYPED tables. The consequence
 * named in the readiness doc is the one asserted below:
 *
 * > `DELETE /admin/v1/tenant-roles/{t}/{r}` answers **200** and revokes nothing.
 *
 * An operator revokes a role, is told `{"deleted": true}`, and the credential
 * keeps the permission on the very next request. The inverse is equally bad:
 * `POST /admin/v1/tenant-roles/{t}` answers 201 and grants nothing, so an
 * operator who follows the documented provisioning path ends up with a tenant
 * that can do nothing and no error anywhere to explain it.
 *
 * ## The rule every case here obeys
 *
 * **Provision ONLY through the admin API; assert the EFFECT, never the status.**
 * Every world below leaves `TENANT_RBAC_ACTIONS` EMPTY, so a 200 on the guarded
 * operation can only have come from a `tenant_role_bindings ⋈ roles` row, and
 * that row can only have come from the admin route under test. A test that
 * asserted `201` / `200` on the admin call is precisely what let this ship.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

/** `GET /admin/v1/guardrail-policies` declares `rbac_action` = this. */
const ACTION = "guardrails.policy.read";
const GUARDED_PATH = `${BASE}/admin/v1/guardrail-policies`;

function guarded(secret: string): Promise<Response> {
  return SELF.fetch(GUARDED_PATH, { headers: bearer(secret) });
}

/** `POST /admin/v1/roles` as the platform operator. */
function createRole(id: string, permissions: readonly string[]): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/roles`,
    jsonRequest(operatorKey.secret, "POST", { id, name: id, permissions }),
  );
}

/** `POST /admin/v1/tenant-roles/{tenant}` as the platform operator. */
function bindRole(tenantId: string, roleId: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/tenant-roles/${tenantId}`,
    jsonRequest(operatorKey.secret, "POST", { role_id: roleId }),
  );
}

/** `DELETE /admin/v1/tenant-roles/{tenant}/{role}` as the platform operator. */
function unbindRole(tenantId: string, roleId: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/tenant-roles/${tenantId}/${roleId}`, {
    method: "DELETE",
    headers: bearer(operatorKey.secret),
  });
}

function deleteRole(roleId: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/roles/${roleId}`, {
    method: "DELETE",
    headers: bearer(operatorKey.secret),
  });
}

function deletePermission(permissionId: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/permissions/${permissionId}`, {
    method: "DELETE",
    headers: bearer(operatorKey.secret),
  });
}

async function bindingRows(tenantId: string): Promise<readonly { role_id: string }[]> {
  const rows = await db()
    .prepare("SELECT role_id FROM tenant_role_bindings WHERE tenant_id = ?")
    .bind(tenantId)
    .all<{ role_id: string }>();
  return rows.results;
}

async function roleRow(roleId: string): Promise<{ permission_keys_json: string } | null> {
  return await db()
    .prepare("SELECT permission_keys_json FROM roles WHERE id = ?")
    .bind(roleId)
    .first<{ permission_keys_json: string }>();
}

async function clearRoleTables(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM tenant_role_bindings"),
    db().prepare("DELETE FROM roles"),
    db().prepare("DELETE FROM permissions"),
  ]);
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await clearRoleTables();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    // EMPTY on purpose: nothing below can be explained by the declarative map.
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The grant
// ---------------------------------------------------------------------------

describe("a grant made through the admin API authorizes a real request", () => {
  it("admits the tenant only AFTER POST /roles + POST /tenant-roles", async () => {
    // Denied first, so the 200 below is the admin API's doing and not a
    // permissive default.
    expect((await guarded("k-tenant")).status).toBe(403);

    await createRole("role_reader", [ACTION]);
    await bindRole("t-1", "role_reader");

    const after = await guarded("k-tenant");
    expect(after.status, await after.clone().text()).toBe(200);
  });

  it("projects the role's permissions onto the column the authorizer joins", async () => {
    await createRole("role_reader", [ACTION, "billing.read"]);

    const row = await roleRow("role_reader");
    expect(row).not.toBeNull();
    expect(JSON.parse(row?.permission_keys_json ?? "null")).toEqual([ACTION, "billing.read"]);
  });

  it("binds to the named tenant and to no other", async () => {
    await createRole("role_reader", [ACTION]);
    await bindRole("t-1", "role_reader");

    expect((await guarded("k-tenant")).status).toBe(200);
    expect((await guarded("k-other")).status).toBe(403);
  });

  /**
   * A role is REPLACED, never edited — `PUT`/`PATCH /admin/v1/roles/{id}` are
   * not in the contract (a mutable role is a privilege-escalation primitive),
   * so widening a role is delete-then-recreate. Both halves have to reach the
   * typed table or the operator's second `POST` is as inert as the first.
   */
  it("re-creating a role under the same id re-projects the widened permissions", async () => {
    await createRole("role_narrow", ["billing.read"]);
    await bindRole("t-1", "role_narrow");
    expect((await guarded("k-tenant")).status).toBe(403);

    expect((await deleteRole("role_narrow")).status).toBe(200);
    expect((await createRole("role_narrow", ["billing.read", ACTION])).status).toBe(201);

    // The binding was never touched, so this can only be the new role row.
    expect((await guarded("k-tenant")).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// The revocation — the headline defect
// ---------------------------------------------------------------------------

describe("a revocation made through the admin API actually revokes", () => {
  it("DELETE /tenant-roles/{t}/{r} stops authorizing on the very next request", async () => {
    await createRole("role_reader", [ACTION]);
    await bindRole("t-1", "role_reader");
    expect((await guarded("k-tenant")).status).toBe(200);

    const revoked = await unbindRole("t-1", "role_reader");
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ deleted: true });

    // The claim the 200 makes, tested: access is gone.
    expect((await guarded("k-tenant")).status).toBe(403);
  });

  it("leaves no binding row behind for the authorizer to find", async () => {
    await createRole("role_reader", [ACTION]);
    await bindRole("t-1", "role_reader");
    expect(await bindingRows("t-1")).toHaveLength(1);

    await unbindRole("t-1", "role_reader");

    expect(await bindingRows("t-1")).toHaveLength(0);
  });

  it("revokes only the named binding — the tenant's other roles survive", async () => {
    await createRole("role_billing", ["billing.read"]);
    await createRole("role_guardrails", [ACTION]);
    await bindRole("t-1", "role_billing");
    await bindRole("t-1", "role_guardrails");
    expect((await guarded("k-tenant")).status).toBe(200);

    await unbindRole("t-1", "role_billing");

    // `role_guardrails` still grants the action.
    expect((await guarded("k-tenant")).status).toBe(200);
    expect(await bindingRows("t-1")).toEqual([{ role_id: "role_guardrails" }]);
  });

  it("DELETE /roles/{id} de-authorizes every tenant bound to it", async () => {
    await createRole("role_reader", [ACTION]);
    await bindRole("t-1", "role_reader");
    expect((await guarded("k-tenant")).status).toBe(200);

    expect((await deleteRole("role_reader")).status).toBe(200);

    // The join now misses: the binding row may survive, the ROLE may not.
    expect((await guarded("k-tenant")).status).toBe(403);
    expect(await roleRow("role_reader")).toBeNull();
  });

  it("an unbind of a binding that was never made is a 404, not a cheerful 200", async () => {
    await createRole("role_reader", [ACTION]);

    expect((await unbindRole("t-1", "role_reader")).status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Permissions — the same defect, one table over
// ---------------------------------------------------------------------------

describe("permissions reach the typed table too", () => {
  it("POST then DELETE /permissions round-trips the typed row", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/permissions`,
      jsonRequest(operatorKey.secret, "POST", {
        id: "perm_read",
        name: "read guardrail policies",
        action: ACTION,
      }),
    );
    expect(created.status).toBe(201);

    const row = await db()
      .prepare("SELECT key, name FROM permissions WHERE id = ?")
      .bind("perm_read")
      .first<{ key: string; name: string }>();
    expect(row).toMatchObject({ key: ACTION });

    expect((await deletePermission("perm_read")).status).toBe(200);
    expect(
      await db().prepare("SELECT id FROM permissions WHERE id = ?").bind("perm_read").first(),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Tenancy: a tenant admin cannot grant itself, or anyone else, a role
// ---------------------------------------------------------------------------

/**
 * The heading above claimed both halves and these two cases only ever proved
 * the CROSS-tenant one. The `itself` half was open until #791 — a tenant-scoped
 * key could author `permissions: ["*"]` and bind it to its own tenant, and
 * nothing here looked. It is pinned in `rbac-self-grant.test.ts`, which is also
 * where the read/write split and the operator's surviving capability live.
 *
 * These two cases are kept unchanged and still assert what they always did (a
 * cross-tenant write is refused and writes nothing), but note what they no
 * longer DISTINGUISH: since #791 the refusal is `rbac_write_operator_only` from
 * the group's write fence rather than `tenant_scope_denied` from
 * `authorizeTenantPath`, because operator-only is checked first. Neither case
 * asserted the code, so both stayed green — the still-live coverage of
 * `authorizeTenantPath` is on the READ leg, in `rbac-self-grant.test.ts` and
 * `crud.test.ts`.
 */
describe("the tenant fence still holds over the typed rows", () => {
  it("a tenant-scoped caller cannot bind a role into ANOTHER tenant", async () => {
    await createRole("role_reader", [ACTION]);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/t-2`,
      jsonRequest("k-tenant", "POST", { role_id: "role_reader" }),
    );
    expect(response.status).toBe(403);

    // And nothing was written on the way to the refusal.
    expect(await bindingRows("t-2")).toHaveLength(0);
    expect((await guarded("k-other")).status).toBe(403);
  });

  it("a tenant-scoped caller cannot unbind ANOTHER tenant's role", async () => {
    await createRole("role_reader", [ACTION]);
    await bindRole("t-2", "role_reader");
    expect((await guarded("k-other")).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/t-2/role_reader`, {
      method: "DELETE",
      headers: bearer("k-tenant"),
    });
    expect(response.status).toBe(403);

    // The refusal did not take the grant down with it.
    expect((await guarded("k-other")).status).toBe(200);
  });
});
