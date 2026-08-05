/**
 * The DURABLE RBAC authorizer (`D1RbacAuthorizer`), driven through the EXPORTED
 * Worker against a REAL D1 binding and the REAL control migration.
 *
 * ## Why this file exists
 *
 * `resolveRbac` is a composition-root wire, and until this file NOTHING held
 * it. The wave-11 mount-mutation sweep replaced
 *
 *     return new D1RbacAuthorizer(env.DB, declarative);
 *
 * with a bare `return declarative;` — deleting the durable authorizer from the
 * deployed Worker outright — and the entire `apps/control-plane` suite stayed
 * GREEN (428/428). Every existing RBAC assertion lives in `auth.test.ts` and
 * states its grants through `TENANT_RBAC_ACTIONS`, which is the FALLBACK; the
 * `roles` / `tenant_role_bindings` join that a real deployment authorizes on
 * had no reader in any test. That is this repo's dominant defect shape — a
 * fully-implemented port that nothing mounts, invisible because the fallback
 * looks identical from outside — and it is the third instance caught this way.
 *
 * So every case below states its world in the DATABASE and leaves the
 * declarative map EMPTY (or, in the override case, deliberately CONTRADICTORY):
 * a 200 here can only have come from a `tenant_role_bindings` row, and a 403
 * can only have come from the durable rows overruling the var.
 *
 * `CONTROL_PLANE_STORE` is left UNSET throughout (`store: "d1"`), so the Worker
 * takes its production default rather than a posture the test asked for.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import {
  privilegedTenantBatch,
  resetTenantObjectState,
  seedTenantRoleProjection,
  tenantObjectDb,
} from "./tenant-object.js";

/** `GET /admin/v1/guardrail-policies` declares `rbac_action` = this. */
const ACTION = "guardrails.policy.read";

/** An `admin.read` operation that declares NO `rbac_action`, as the control. */
const UNGUARDED_PATH = `${BASE}/admin/v1/plans`;
const GUARDED_PATH = `${BASE}/admin/v1/guardrail-policies`;

interface ErrorEnvelope {
  error: { message: string; code: string };
}

function guarded(secret: string): Promise<Response> {
  return SELF.fetch(GUARDED_PATH, { headers: bearer(secret) });
}

async function envelope(response: Response): Promise<ErrorEnvelope> {
  return (await response.json()) as ErrorEnvelope;
}

/**
 * Write a role and bind it to a tenant, with raw SQL rather than through the
 * admin routes: a fixture built with the code under test cannot show that the
 * code under test reads what is really in the table.
 */
async function grantRole(
  tenantId: string,
  roleId: string,
  permissionKeys: readonly string[] | string,
): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO roles (id, name, slug, permission_keys_json)
       VALUES (?, ?, ?, ?)`,
    )
    .bind(
      roleId,
      roleId,
      `${roleId}-${tenantId}`,
      typeof permissionKeys === "string" ? permissionKeys : JSON.stringify(permissionKeys),
    )
    .run();
  await seedTenantRoleProjection(tenantId, roleId, permissionKeys);
}

async function clearRoleTables(): Promise<void> {
  await db().prepare("DELETE FROM roles").run();
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantObjectState([
    "t-durable",
    "t-star",
    "t-union",
    "t-corrupt",
    "t-stale",
    "t-revoke",
    "t-a",
    "t-b",
    "t-fallback",
    "t-other",
    "t-none",
  ]);
  await clearRoleTables();
});

// ---------------------------------------------------------------------------
// The durable grant is the one the deployed Worker authorizes on
// ---------------------------------------------------------------------------

describe("the exported Worker authorizes on DURABLE role bindings", () => {
  it("admits a tenant whose grant exists ONLY in tenant_role_bindings", async () => {
    arm({
      store: "d1",
      nativeKeys: [tenantKey("k-durable", "t-durable")],
      // EMPTY on purpose: a 200 below cannot be explained by the var.
      rbac: {},
    });
    // Denied before the row exists — so the 200 that follows is the row's doing
    // and not a permissive default.
    const before = await guarded("k-durable");
    expect(before.status).toBe(403);
    expect((await envelope(before)).error.code).toBe("guardrail_rbac_denied");

    await grantRole("t-durable", "role_reader", [ACTION]);

    const after = await guarded("k-durable");
    expect(after.status, await after.clone().text()).toBe(200);
  });

  it("a durable role granting `*` is a wildcard, like the declarative one", async () => {
    arm({ store: "d1", nativeKeys: [tenantKey("k-star", "t-star")], rbac: {} });
    await grantRole("t-star", "role_admin", ["*"]);

    expect((await guarded("k-star")).status).toBe(200);
  });

  it("unions the permissions of every role bound to the tenant", async () => {
    arm({ store: "d1", nativeKeys: [tenantKey("k-union", "t-union")], rbac: {} });
    // Neither role alone grants the action; only the union does.
    await grantRole("t-union", "role_billing", ["billing.read"]);
    await grantRole("t-union", "role_guardrails", [ACTION]);

    expect((await guarded("k-union")).status).toBe(200);
  });

  it("a corrupt permission column does not take the other roles down with it", async () => {
    arm({ store: "d1", nativeKeys: [tenantKey("k-corrupt", "t-corrupt")], rbac: {} });
    await grantRole("t-corrupt", "role_broken", "{not json");
    await grantRole("t-corrupt", "role_good", [ACTION]);

    expect((await guarded("k-corrupt")).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Once durable rows exist they are AUTHORITATIVE — a stale var cannot re-grant
// ---------------------------------------------------------------------------

describe("durable rows overrule the declarative TENANT_RBAC_ACTIONS map", () => {
  it("refuses an action the durable roles do not grant, even though the VAR does", async () => {
    arm({
      store: "d1",
      nativeKeys: [tenantKey("k-stale", "t-stale")],
      // The stale var says yes. The database is what decides.
      rbac: { "t-stale": [ACTION] },
    });
    await grantRole("t-stale", "role_narrow", ["billing.read"]);

    const response = await guarded("k-stale");
    expect(response.status).toBe(403);
    const body = await envelope(response);
    expect(body.error.code).toBe("guardrail_rbac_denied");
    expect(body.error.message).toContain(ACTION);
  });

  it("REVOKING the binding takes effect on the very next request", async () => {
    arm({ store: "d1", nativeKeys: [tenantKey("k-revoke", "t-revoke")], rbac: {} });
    await grantRole("t-revoke", "role_reader", [ACTION]);
    expect((await guarded("k-revoke")).status).toBe(200);

    await privilegedTenantBatch("t-revoke", [
      { sql: "DELETE FROM tenant_role_bindings WHERE tenant_id = ?", params: ["t-revoke"] },
    ]);

    // No durable rows left ⇒ the declarative fallback answers, and it is empty.
    expect((await guarded("k-revoke")).status).toBe(403);
  });

  it("confines a grant to its own tenant — another tenant's role never applies", async () => {
    arm({
      store: "d1",
      nativeKeys: [tenantKey("k-a", "t-a"), tenantKey("k-b", "t-b")],
      rbac: {},
    });
    await grantRole("t-a", "role_reader", [ACTION]);

    expect((await guarded("k-a")).status).toBe(200);
    expect((await guarded("k-b")).status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// The documented fallbacks, so the durable path cannot be "proven" by a
// deployment that simply denies everything
// ---------------------------------------------------------------------------

describe("the fallbacks the durable authorizer keeps", () => {
  it("defers to the declarative map for a tenant with NO durable rows", async () => {
    arm({
      store: "d1",
      nativeKeys: [tenantKey("k-fallback", "t-fallback")],
      rbac: { "t-fallback": [ACTION] },
    });
    // Somebody else's rows must not count as this tenant's.
    await grantRole("t-other", "role_reader", [ACTION]);

    expect((await guarded("k-fallback")).status).toBe(200);
  });

  it("waves a platform operator through without consulting either source", async () => {
    arm({ store: "d1", staticKeys: [operatorKey], rbac: {} });

    expect((await guarded(operatorKey.secret)).status).toBe(200);
  });

  it("leaves an operation with no declared rbac_action alone", async () => {
    arm({ store: "d1", nativeKeys: [tenantKey("k-none", "t-none")], rbac: {} });

    const response = await SELF.fetch(UNGUARDED_PATH, { headers: bearer("k-none") });
    expect(response.status).toBe(200);
  });
});
