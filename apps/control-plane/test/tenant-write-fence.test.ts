/**
 * The tenant WRITE fence, driven through the exported Worker against a REAL D1
 * binding — the HTTP half of the contract `store-conformance.test.ts` pins at
 * the store.
 *
 * ## What this holds
 *
 * The wave-15 control-plane certification found the read fence and the write
 * fence sharing ONE predicate:
 *
 * ```sql
 * AND (json_extract(document_json,'$.tenant_id') IS NULL
 *      OR json_extract(document_json,'$.tenant_id') = ?)
 * ```
 *
 * appended to `#update`, `remove` and the `atomic` batch as well as to every
 * SELECT — **wider than Rust's `filter_by_tenant_scope` (`auth.rs:428`), and
 * pinned by no test**. The `IS NULL` disjunct is deliberate for reads (a global
 * plan has to stay visible to the tenant it applies to). On the write side it
 * means a tenant administrator holding `admin.write` — an intended, documented
 * configuration — can `PUT`, `PATCH` or `DELETE` any un-attributed PLATFORM
 * row: a global `role`, a shared `policy`, a `plan` other tenants are billed
 * against. Rust makes that unreachable.
 *
 * The cases below therefore always assert the ROW, not just the status: a `404`
 * that still let the write land would be the same defect wearing a different
 * response.
 *
 * ## Why every case checks the READ too
 *
 * The lazy "fix" is to hide platform rows from tenants altogether, which would
 * pass every refusal here and break `resolved-defaults` in production. Each
 * refusal is paired with the read that must keep working.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, rawDocument, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

/** A `plans` row with NO `tenant_id`: the deployment's own platform data. */
const PLATFORM_PLAN = { id: "plan_platform", name: "platform", rpm_limit: 60 };

/** The same collection, attributed to `t-1` — the row that MAY be written. */
const TENANT_PLAN = { id: "plan_mine", name: "mine", tenant_id: "t-1" };

function url(id: string): string {
  return `${BASE}/admin/v1/plans/${id}`;
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await db().batch([db().prepare("DELETE FROM plans")]);
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1")],
  });
  // Seeded with raw SQL, so the fixture cannot have been shaped by the code
  // under test — and because a tenant caller could not create an un-attributed
  // row in the first place (`create` stamps its own tenant).
  await seedD1("plans", [PLATFORM_PLAN, TENANT_PLAN]);
});

describe("a tenant administrator may READ platform rows and may not WRITE them", () => {
  it("reads the un-attributed platform row", async () => {
    const response = await SELF.fetch(url(PLATFORM_PLAN.id), { headers: bearer("k-tenant") });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ plan: { name: "platform" } });
  });

  it("refuses a PATCH of it with 404, and the row is untouched", async () => {
    const response = await SELF.fetch(
      url(PLATFORM_PLAN.id),
      jsonRequest("k-tenant", "PATCH", { name: "hijacked", rpm_limit: 100000 }),
    );

    expect(response.status).toBe(404);
    expect(await rawDocument("plans", PLATFORM_PLAN.id)).toMatchObject({
      name: "platform",
      rpm_limit: 60,
    });
  });

  it("refuses a PUT of it with 404, and the row is untouched", async () => {
    const response = await SELF.fetch(
      url(PLATFORM_PLAN.id),
      jsonRequest("k-tenant", "PUT", { id: PLATFORM_PLAN.id, name: "hijacked" }),
    );

    expect(response.status).toBe(404);
    expect(await rawDocument("plans", PLATFORM_PLAN.id)).toMatchObject({ name: "platform" });
  });

  it("refuses a DELETE of it with 404, and the row survives", async () => {
    // `plans` has no DELETE by contract; `policies` is the same document store
    // through the same generic handler and does.
    await seedD1("policies", [{ id: "policy_platform", name: "platform" }]);

    const response = await SELF.fetch(`${BASE}/admin/v1/policies/policy_platform`, {
      method: "DELETE",
      headers: bearer("k-tenant"),
    });

    expect(response.status).toBe(404);
    expect(await rawDocument("policies", "policy_platform")).not.toBeNull();
  });

  it("the 404 is indistinguishable from a row that never existed", async () => {
    const platform = await SELF.fetch(
      url(PLATFORM_PLAN.id),
      jsonRequest("k-tenant", "PATCH", { name: "hijacked" }),
    );
    const ghost = await SELF.fetch(
      url("plan_never_existed"),
      jsonRequest("k-tenant", "PATCH", { name: "hijacked" }),
    );

    expect(platform.status).toBe(ghost.status);
    expect(((await platform.json()) as { error: { code: string } }).error.code).toBe(
      ((await ghost.json()) as { error: { code: string } }).error.code,
    );
  });
});

describe("the narrowing is a fence, not a blanket denial", () => {
  it("the tenant still writes its OWN row", async () => {
    const response = await SELF.fetch(
      url(TENANT_PLAN.id),
      jsonRequest("k-tenant", "PATCH", { name: "renamed" }),
    );

    expect(response.status, await response.clone().text()).toBe(200);
    expect(await rawDocument("plans", TENANT_PLAN.id)).toMatchObject({ name: "renamed" });
  });

  it("the platform operator still writes the platform row", async () => {
    const response = await SELF.fetch(
      url(PLATFORM_PLAN.id),
      jsonRequest(operatorKey.secret, "PATCH", { name: "renamed" }),
    );

    expect(response.status, await response.clone().text()).toBe(200);
    expect(await rawDocument("plans", PLATFORM_PLAN.id)).toMatchObject({ name: "renamed" });
  });

  it("another tenant's row is refused exactly as the platform row is", async () => {
    await seedD1("plans", [{ id: "plan_theirs", name: "theirs", tenant_id: "t-2" }]);

    const response = await SELF.fetch(
      url("plan_theirs"),
      jsonRequest("k-tenant", "PATCH", { name: "hijacked" }),
    );

    expect(response.status).toBe(404);
    expect(await rawDocument("plans", "plan_theirs")).toMatchObject({ name: "theirs" });
  });
});
