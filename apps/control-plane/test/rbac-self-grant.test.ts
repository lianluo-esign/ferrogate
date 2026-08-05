/**
 * #791 — a tenant may READ the RBAC it is subject to and may not AUTHOR it.
 *
 * `authorizeTenantPath` was one fence for the `rbac` group's reads and its
 * writes, so a tenant-scoped `admin.write` key could mint its own authority:
 *
 * ```
 * POST /admin/v1/roles        {"id":"role_mine","permissions":["*"]}  -> 201
 * POST /admin/v1/tenant-roles/t-1 {"role_id":"role_mine"}             -> 201
 * GET  /admin/v1/guardrail-policies                                   -> 200
 * ```
 *
 * The last line is the defect: that operation declares
 * `rbac_action = guardrails.policy.read`, `TENANT_RBAC_ACTIONS` is empty in
 * every world below, and the tenant was `403` one request earlier. The 200 can
 * only have come from the `tenant_role_bindings ⋈ roles` row the tenant wrote
 * for itself, resolved by the REAL `D1RbacAuthorizer` against a REAL D1
 * binding. Nothing here asserts a status on an admin call and calls it a day —
 * every case asserts the EFFECT on a guarded operation, which is the rule
 * `rbac-write-half.test.ts` established and the reason that file exists.
 *
 * ## What is being pinned, and what is deliberately NOT allowed
 *
 * RBAC is the mechanism the other tenant fences are expressed in: a tenant that
 * can grant itself a role does not need any other escalation, it can mint the
 * authority every other check consults. So the fence is on the VERB — every
 * non-`GET` operation in the group is operator-only — and not on the VALUE.
 *
 * There is a tempting middle answer, "a tenant may author a role whose
 * permissions are a SUBSET of what it already holds", and the last two describes
 * below pin why it is refused rather than shipped:
 * `packages/identity/src/delegation/sign.ts::delegationScopeSubset` is a sound
 * subset predicate, but `tenant_role_bindings` has no subject columns and every
 * authorizer unions the permission keys of all roles bound to the TENANT, so a
 * subset binding is not a delegation — it is a second copy of the grant, owned
 * by the governed party, that survives the operator revoking the first.
 * `src/routes/rbac.ts::authorizeRbacWrite` carries the full argument.
 *
 * Every refusal case asserts the BINDING ROW DID NOT MOVE, because a 403 that
 * still writes is worse than an allow: the operator reads a refusal and the
 * grant changed anyway.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import {
  registerDurableObjectTenant,
  resetTenantObjectState,
  tenantObjectDb,
} from "./tenant-object.js";

/** `GET /admin/v1/guardrail-policies` declares `rbac_action` = this. */
const ACTION = "guardrails.policy.read";
const GUARDED = `${BASE}/admin/v1/guardrail-policies`;

const OPERATOR = operatorKey.secret;
const TENANT_KEY = "k-t1";
const TENANT = "t-1";

/** The RBAC-gated operation, exercised with a credential. 200 = granted. */
function guarded(secret: string): Promise<Response> {
  return SELF.fetch(GUARDED, { headers: bearer(secret) });
}

function roleIdsBoundTo(tenantId: string): Promise<readonly string[]> {
  return tenantObjectDb(tenantId)
    .prepare("SELECT role_id FROM tenant_role_bindings WHERE tenant_id = ? ORDER BY role_id")
    .bind(tenantId)
    .all<{ role_id: string }>()
    .then((rows) => rows.results.map((row) => row.role_id));
}

function roleRow(roleId: string): Promise<{ permission_keys_json: string } | null> {
  return db()
    .prepare("SELECT permission_keys_json FROM roles WHERE id = ?")
    .bind(roleId)
    .first<{ permission_keys_json: string }>();
}

/** `POST /admin/v1/roles` as the platform operator. */
function operatorCreatesRole(
  id: string,
  permissions: readonly string[],
  tenantId: string | null = TENANT,
): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/roles`,
    jsonRequest(OPERATOR, "POST", { id, name: id, tenant_id: tenantId, permissions }),
  );
}

function operatorBinds(tenantId: string, roleId: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/tenant-roles/${tenantId}`,
    jsonRequest(OPERATOR, "POST", { role_id: roleId }),
  );
}

async function expectRefused(response: Response): Promise<void> {
  expect(response.status, await response.clone().text()).toBe(403);
  expect((await response.json()) as { error: { code: string } }).toMatchObject({
    error: { code: "rbac_write_operator_only" },
  });
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await resetTenantObjectState([TENANT, "t-2"]);
  await registerDurableObjectTenant(TENANT);
  await registerDurableObjectTenant("t-2");
  await db().batch([db().prepare("DELETE FROM roles"), db().prepare("DELETE FROM permissions")]);
  arm({
    // The REAL store and the REAL authorizer: the escalation is a durable row,
    // and a memory-store world would prove nothing about the join that reads it.
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_KEY, TENANT), tenantKey("k-t2", "t-2")],
    // EMPTY on purpose: no 200 below can be explained by the declarative map.
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The headline escalation
// ---------------------------------------------------------------------------

describe("a tenant cannot mint itself a role", () => {
  it("refuses POST /roles from a tenant credential, and writes no role row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/roles`,
      jsonRequest(TENANT_KEY, "POST", { id: "role_mine", name: "mine", permissions: ["*"] }),
    );
    await expectRefused(response);

    // Not merely un-granted: the row the authorizers join against never existed.
    expect(await roleRow("role_mine")).toBeNull();
  });

  it("leaves the tenant unable to reach the guarded operation, end to end", async () => {
    expect((await guarded(TENANT_KEY)).status).toBe(403);

    // The exact two calls from the issue, in order.
    const minted = await SELF.fetch(
      `${BASE}/admin/v1/roles`,
      jsonRequest(TENANT_KEY, "POST", { id: "role_mine", name: "mine", permissions: ["*"] }),
    );
    await expectRefused(minted);
    const bound = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/${TENANT}`,
      jsonRequest(TENANT_KEY, "POST", {
        role_id: "role_mine",
        subject_kind: "user",
        subject_id: "u1",
      }),
    );
    await expectRefused(bound);

    // The assertion the whole issue is about.
    expect((await guarded(TENANT_KEY)).status).toBe(403);
    expect(await roleIdsBoundTo(TENANT)).toEqual([]);
  });

  it("refuses a role with a NAMED permission just as it refuses the wildcard", async () => {
    // `"*"` is the loudest case, not the only one: the fence is on the verb, so
    // a role naming exactly the verb the operator withheld is refused too. A
    // fence that only special-cased `"*"` would pass the case above and leave
    // the issue's actual blast radius — the twelve guardrail operations — open.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/roles`,
      jsonRequest(TENANT_KEY, "POST", {
        id: "role_activate",
        permissions: ["guardrails.policy.activate", "guardrails.policy.archive"],
      }),
    );
    await expectRefused(response);
    expect(await roleRow("role_activate")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The binding leg, including an operator-authored GLOBAL role
// ---------------------------------------------------------------------------

describe("a tenant cannot bind a role to itself", () => {
  it("refuses binding a role the OPERATOR authored for this tenant, row unmoved", async () => {
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await guarded(TENANT_KEY)).status).toBe(403);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/${TENANT}`,
      jsonRequest(TENANT_KEY, "POST", { role_id: "role_ops" }),
    );
    await expectRefused(response);

    expect(await roleIdsBoundTo(TENANT)).toEqual([]);
    expect((await guarded(TENANT_KEY)).status).toBe(403);
  });

  it("refuses binding an operator-authored GLOBAL role (tenant_id null)", async () => {
    // The issue's second reproduction. A global role is not the tenant's row at
    // all — `writableBy` never sees it, because the binding is a DIFFERENT
    // collection whose row the store stamps with the caller's own tenant. The
    // store fence therefore could not have caught this one; only the route can.
    expect((await operatorCreatesRole("role_global", [ACTION], null)).status).toBe(201);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/${TENANT}`,
      jsonRequest(TENANT_KEY, "POST", { role_id: "role_global" }),
    );
    await expectRefused(response);

    expect(await roleIdsBoundTo(TENANT)).toEqual([]);
    expect((await guarded(TENANT_KEY)).status).toBe(403);
  });

  it("refuses a tenant UNBINDING a grant, and the grant survives the refusal", async () => {
    // Unbinding is de-escalating for the caller, so it is fenced for a
    // different reason: the binding is the operator's configuration, and a
    // governed party silently dropping it is the same class of edit. The
    // load-bearing half is that the refusal wrote nothing — `unbindTenantRole`
    // deletes the AUTHORITY row before the document, so a fence that ran late
    // would revoke and then 403.
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_ops")).status).toBe(201);
    expect((await guarded(TENANT_KEY)).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}/role_ops`, {
      method: "DELETE",
      headers: bearer(TENANT_KEY),
    });
    await expectRefused(response);

    expect(await roleIdsBoundTo(TENANT)).toEqual(["role_ops"]);
    expect((await guarded(TENANT_KEY)).status).toBe(200);
  });

  it("refuses a tenant DELETING an operator-authored role attributed to it", async () => {
    // `deleteHandler` resolves the row through the store, and `writableBy` is
    // `record.tenant_id === scope.tenantId` — so this role IS writable by the
    // tenant as far as the store is concerned, and dropping the `roles` row
    // makes the authorizers' join miss. The store fence cannot see the
    // difference between "the tenant's row" and "the operator's row about the
    // tenant"; the route must.
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_ops")).status).toBe(201);
    expect((await guarded(TENANT_KEY)).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/admin/v1/roles/role_ops`, {
      method: "DELETE",
      headers: bearer(TENANT_KEY),
    });
    await expectRefused(response);

    expect(await roleRow("role_ops")).not.toBeNull();
    expect((await guarded(TENANT_KEY)).status).toBe(200);
  });

  it("refuses a tenant authoring a PERMISSION, the vocabulary roles draw from", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/permissions`,
      jsonRequest(TENANT_KEY, "POST", { id: "perm_mine", action: ACTION }),
    );
    await expectRefused(response);
    expect(
      await db().prepare("SELECT id FROM permissions WHERE id = ?").bind("perm_mine").first(),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The refusal happens BEFORE resolution and BEFORE body parse
// ---------------------------------------------------------------------------

describe("the fence refuses before it looks at anything", () => {
  it("refuses a body that would not even validate", async () => {
    // `tenantRoleBindingSchema` requires `role_id`. A 400 here would mean the
    // body was parsed first, which is how a refused caller learns the shape of
    // a request it is never allowed to make.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/${TENANT}`,
      jsonRequest(TENANT_KEY, "POST", { nonsense: true }),
    );
    await expectRefused(response);
  });

  it("refuses a role id that does not exist with the same code as one that does", async () => {
    // Otherwise the refusal is an existence oracle over the operator's role
    // catalogue: 404 for absent, 403 for present.
    expect((await operatorCreatesRole("role_real", [ACTION])).status).toBe(201);

    const present = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}/role_real`, {
      method: "DELETE",
      headers: bearer(TENANT_KEY),
    });
    const absent = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}/role_absent`, {
      method: "DELETE",
      headers: bearer(TENANT_KEY),
    });
    await expectRefused(present);
    await expectRefused(absent);
  });
});

// ---------------------------------------------------------------------------
// The other half of the split: reads, and the operator, still work
// ---------------------------------------------------------------------------

describe("the reads a tenant needs are untouched", () => {
  it("still lets a tenant LIST the bindings it is subject to", async () => {
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_ops")).status).toBe(201);

    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { role_id: string }[] }).data).toMatchObject([
      { role_id: "role_ops" },
    ]);
  });

  it("still lets a tenant READ a role attributed to it", async () => {
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);

    const response = await SELF.fetch(`${BASE}/admin/v1/roles/role_ops`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(200);
    expect((await response.json()) as { role: { permissions: string[] } }).toMatchObject({
      role: { permissions: [ACTION] },
    });
  });

  it("still answers tenant_scope_denied for a READ of ANOTHER tenant's bindings", async () => {
    // The #185 fence is not replaced by the write fence — a cross-tenant READ
    // is still refused, and with the code that says which failure it was.
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/t-2`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });

  it("leaves the operator's own grant and revocation working end to end", async () => {
    // The fence must not be "nobody may write", which would pass every case
    // above while removing the product.
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_ops")).status).toBe(201);
    expect((await guarded(TENANT_KEY)).status).toBe(200);

    const unbound = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}/role_ops`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(unbound.status).toBe(200);
    expect((await guarded(TENANT_KEY)).status).toBe(403);
    expect(await roleIdsBoundTo(TENANT)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Why NOT a subset carve-out — the two facts that decide it
// ---------------------------------------------------------------------------

describe("why the subset answer was refused, pinned as facts rather than prose", () => {
  it("a binding grants the whole TENANT: subject_kind/subject_id reach no authorizer", async () => {
    // If this ever fails, the subset rule becomes worth revisiting: a binding
    // that really is scoped to `user:u1` does not grant the calling credential,
    // and `delegationScopeSubset` is then the right fence for that leg.
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    const bound = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/${TENANT}`,
      jsonRequest(OPERATOR, "POST", {
        role_id: "role_ops",
        subject_kind: "user",
        subject_id: "someone-who-is-not-this-key",
      }),
    );
    expect(bound.status).toBe(201);

    // The API key `k-t1` is not `someone-who-is-not-this-key`, and is granted
    // anyway — the authorizers join on `tenant_id` alone.
    expect((await guarded(TENANT_KEY)).status).toBe(200);

    // And the durable row has nowhere to put a subject even if one were read.
    const columns = await tenantObjectDb(TENANT)
      .prepare("SELECT name FROM pragma_table_info('tenant_role_bindings')")
      .all<{ name: string }>();
    expect(columns.results.map((column) => column.name)).toEqual([
      "id",
      "tenant_id",
      "role_id",
      "created_at_unix",
    ]);
  });

  it("authority is the UNION of bound roles, so a duplicate grant outlives its revocation", async () => {
    // The scenario a subset-at-write-time rule would have legalised, driven
    // entirely with the OPERATOR credential so it is a statement about the
    // AUTHORIZER and not about the fence: two roles carrying the same verb, one
    // revoked, the verb survives. Had the tenant been allowed to author the
    // second role — legally, as an exact subset of what it then held — the
    // operator's revocation of the first would not have revoked anything.
    expect((await operatorCreatesRole("role_ops", [ACTION])).status).toBe(201);
    expect((await operatorCreatesRole("role_copy", [ACTION])).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_ops")).status).toBe(201);
    expect((await operatorBinds(TENANT, "role_copy")).status).toBe(201);
    expect((await guarded(TENANT_KEY)).status).toBe(200);

    const revoked = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/${TENANT}/role_ops`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(revoked.status).toBe(200);

    // Still granted. This is why a tenant-owned copy of a grant is not a
    // delegation — it is a revocation the operator cannot perform.
    expect((await guarded(TENANT_KEY)).status).toBe(200);
    expect(await roleIdsBoundTo(TENANT)).toEqual(["role_copy"]);
  });
});
