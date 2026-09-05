/**
 * Track A HARD-CUT for the typed `quota_policies` enforcement row, driven through
 * the EXPORTED Worker with the D1 store live so BOTH candidate write legs are
 * observable: the shared CONTROL facade (`db()`) and the owning tenant's OWN
 * object (`tenantObjectDb`).
 *
 * `quota_policies` is per-tenant data whose SOLE authoritative home is the
 * tenant's own object. The shared-CONTROL mirror leg has been removed ENTIRELY —
 * there is no `CONTROL_QUOTA_POLICY_SOURCE` flag and no dual-write. Every write
 * (create/replace/update/delete) touches the tenant object and NEVER the control
 * facade. These cases pin that topology: the control facade must hold no typed
 * row after any write, and the tenant object must be the enforcement authority.
 *
 * (Track A migration 0045 physically DROPS `quota_policies` from the control
 * facade, so the cases assert the facade has NO SUCH TABLE — a strictly stronger
 * guarantee than the row-absence they asserted while the table still existed.)
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "tenant-a-secret";
const POLICIES = `${BASE}/admin/v1/quota-policies`;
const SCOPE = { type: "tenant", id: "tenant_a" } as const;
const SCOPED = `${POLICIES}/${SCOPE.type}/${SCOPE.id}`;

/** The policy body the operator POSTs — attributed to the tenant it governs. */
const BODY = {
  scope_type: SCOPE.type,
  scope_id: SCOPE.id,
  tenant_id: SCOPE.id,
  rpm_limit: 60,
  monthly_token_budget: 1_000,
};

/** The typed enforcement row of the scope, straight out of a given handle. */
async function typedRow(handle: D1Database): Promise<Record<string, unknown> | null> {
  return handle
    .prepare("SELECT * FROM quota_policies WHERE scope_type = ? AND scope_id = ?")
    .bind(SCOPE.type, SCOPE.id)
    .first<Record<string, unknown>>();
}

/**
 * After 0045 the control facade has no `quota_policies` table at all — the
 * strongest form of "the mirror is gone". `sqlite_master` is the honest probe:
 * querying the table itself would throw `no such table`, which a row-absence
 * assertion cannot express.
 */
async function controlLacksQuotaPoliciesTable(): Promise<boolean> {
  const row = await db()
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'quota_policies'")
    .first<{ name: string }>();
  return row === null;
}
const objectRow = (): Promise<Record<string, unknown> | null> => typedRow(tenantObjectDb(SCOPE.id));

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_A_KEY, "tenant_a")],
  });
  await registerObjectTenants(["tenant_a"]);
});

describe("quota_policies writer is tenant-object-only (Track A hard-cut)", () => {
  it("create writes ONLY the tenant object — the control facade holds no typed row", async () => {
    const res = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(res.status).toBe(201);

    // THE RED LINE: the shared control facade holds NO typed row — the mirror the
    // dual-write used to keep is gone unconditionally.
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);
    // …and the owning tenant's own object is the sole enforcement authority.
    expect(await objectRow()).toMatchObject({ scope_id: "tenant_a", rpm_limit: 60 });
  });

  it("delete removes the tenant-object row and never touches the control facade", async () => {
    const created = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(created.status).toBe(201);
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);
    expect(await objectRow()).not.toBeNull();

    const deleted = await SELF.fetch(SCOPED, { method: "DELETE", headers: bearer(KEY) });
    expect(deleted.status).toBe(200);

    // The tenant object (sole authority) no longer bites…
    expect(await objectRow()).toBeNull();
    // …and the control facade never held a row to leave behind.
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);
  });
});
