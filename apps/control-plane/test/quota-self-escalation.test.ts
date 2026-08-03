/**
 * #782 — a tenant-scoped credential may READ its own quota policy and may not
 * RAISE it.
 *
 * `authorizeScopedResource` was one fence for `GET` and for
 * `POST`/`PUT`/`PATCH`/`DELETE`. Its tenant branch resolves the owner of a
 * `scope_type=tenant` row as the scope id ITSELF, so "is this my row?" was the
 * only question asked, and for a write the answer being "yes" is precisely the
 * escalation: the holder of the quota editing the quota. `rpm_limit`,
 * `monthly_token_budget` and `asset_storage_quota_bytes` are the numbers the
 * gateway admits requests against; a ceiling its subject can lift is not a
 * ceiling.
 *
 * These cases pin BOTH halves of the deliberate split, because a fence is only
 * as good as the read it leaves alone:
 *
 *  - the tenant's own `GET` still answers 200 (a tenant must be able to see the
 *    limits it is being held to, or it cannot tell a 429 from a bug), and
 *  - every tenant-scoped write to its own row is refused AND THE ROW DOES NOT
 *    MOVE. The second assertion is the one that matters: a refusal that still
 *    writes is worse than an allow, because the operator reads a 403 and the
 *    state changed anyway.
 *
 * Lowering is refused too, and that is a judgement call rather than an
 * oversight — see the `authorizeScopedResource` docblock in
 * `src/routes/quota_policy.ts` for why a self-service tightening is not
 * distinguishable from a self-service loosening on this surface.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;
const TENANT_KEY = "k-t1";

/**
 * The operator-set ceiling every case below tries to move.
 *
 * `tenant_id: "t1"` is load-bearing in the FIXTURE, not decoration. The store
 * has a second, weaker fence of its own (`store/query.ts::writableBy`, pinned by
 * `tenant-write-fence.test.ts`): a tenant credential may write a row attributed
 * to its tenant and may not write an UN-attributed platform row. So an
 * operator-authored policy carrying no `tenant_id` happened to bounce with a
 * confusing `404`, and the escalation was only reachable on a policy attributed
 * to the tenant it governs — which is the normal shape (`adminRecordSchema`
 * accepts `tenant_id` on every collection, and a per-tenant policy is a
 * per-tenant row). Seeding the un-attributed shape instead would make these
 * cases pass for the store's reason and never exercise the route's fence at
 * all: green, and holding nothing.
 */
const SEEDED = {
  scope_type: "tenant",
  scope_id: "t1",
  tenant_id: "t1",
  rpm_limit: 60,
  monthly_token_budget: 1_000,
  asset_storage_quota_bytes: 10_000,
};

beforeEach(async () => {
  arm({ staticKeys: [operatorKey], nativeKeys: [tenantKey(TENANT_KEY, "t1")] });
  const created = await SELF.fetch(
    `${BASE}/admin/v1/quota-policies`,
    jsonRequest(OPERATOR, "POST", SEEDED),
  );
  expect(created.status).toBe(201);
});

/** What the operator's row says right now, read with the operator credential. */
async function readAsOperator(): Promise<Record<string, unknown>> {
  const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t1`, {
    headers: bearer(OPERATOR),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { quota_policy: Record<string, unknown> };
  return body.quota_policy;
}

describe("#782: a tenant may read its own quota policy but not write it", () => {
  it("still lets the tenant READ its own policy", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t1`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(200);
    expect((await response.json()) as { quota_policy: { rpm_limit: number } }).toMatchObject({
      quota_policy: { rpm_limit: 60, asset_storage_quota_bytes: 10_000 },
    });
  });

  it("refuses the tenant's PUT raising its own limits, and does not move the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/t1`,
      jsonRequest(TENANT_KEY, "PUT", {
        rpm_limit: 1_000_000,
        monthly_token_budget: 999_999_999,
        asset_storage_quota_bytes: 1_000_000_000_000,
      }),
    );
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "quota_policy_write_operator_only" },
    });

    // The load-bearing half: the ceiling is still the operator's.
    expect(await readAsOperator()).toMatchObject({
      rpm_limit: 60,
      monthly_token_budget: 1_000,
      asset_storage_quota_bytes: 10_000,
    });
  });

  it("refuses the tenant's PATCH of a single limit, and does not move the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/t1`,
      jsonRequest(TENANT_KEY, "PATCH", { asset_storage_quota_bytes: 1_000_000_000_000 }),
    );
    expect(response.status).toBe(403);
    expect(await readAsOperator()).toMatchObject({ asset_storage_quota_bytes: 10_000 });
  });

  it("refuses the tenant's DELETE — deleting the row is unlimited by another name", async () => {
    // `resolveEffectiveQuota` over an empty chain is NOT "the default limits";
    // it is no rpm cap, no monthly budget and no model allowlist. Deletion is
    // therefore the largest raise available on this surface.
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t1`, {
      method: "DELETE",
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(403);
    expect(await readAsOperator()).toMatchObject({ rpm_limit: 60 });
  });

  it("refuses the tenant's POST creating its own policy from nothing", async () => {
    // The create leg is the same escalation against a tenant with no row yet:
    // a policy the tenant authored is a policy the tenant chose.
    arm({ staticKeys: [operatorKey], nativeKeys: [tenantKey("k-t9", "t9")] });
    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies`,
      jsonRequest("k-t9", "POST", { scope_type: "tenant", scope_id: "t9", rpm_limit: 9_000_000 }),
    );
    expect(response.status).toBe(403);

    const readBack = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t9`, {
      headers: bearer(OPERATOR),
    });
    expect(readBack.status).toBe(404);
  });

  it("refuses a LOWERING write too, and says so in the refusal", async () => {
    // Deliberate: see the docblock. A tenant tightening its own ceiling is
    // indistinguishable, on this surface, from a tenant that will loosen it
    // again a second later, so the fence is on the verb and not on the value.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/t1`,
      jsonRequest(TENANT_KEY, "PATCH", { rpm_limit: 1 }),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("quota_policy_write_operator_only");
    expect(body.error.message).toContain("may read its own quota policy");
    expect(await readAsOperator()).toMatchObject({ rpm_limit: 60 });
  });

  it("leaves the operator's own write working", async () => {
    // The fence must not be "nobody can write", which would pass every case
    // above while breaking the product.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/t1`,
      jsonRequest(OPERATOR, "PATCH", { rpm_limit: 120 }),
    );
    expect(response.status).toBe(200);
    expect(await readAsOperator()).toMatchObject({ rpm_limit: 120 });
  });

  it("still refuses a tenant naming ANOTHER tenant's policy — the #185 fence stands", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t2`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });

  it("refuses a tenant's write to a PROJECT-scoped policy it owns", async () => {
    // The escalation is not specific to `scope_type=tenant`: a project row the
    // caller's own tenant owns resolves to the caller's tenant, so the read
    // fence admitted the write there too.
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_KEY, "t1")],
      seed: { projects: [{ id: "proj_mine", tenant_id: "t1" }] },
    });
    const created = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies`,
      jsonRequest(OPERATOR, "POST", {
        scope_type: "project",
        scope_id: "proj_mine",
        tenant_id: "t1",
        rpm_limit: 30,
      }),
    );
    expect(created.status).toBe(201);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/project/proj_mine`,
      jsonRequest(TENANT_KEY, "PATCH", { rpm_limit: 500_000 }),
    );
    expect(response.status).toBe(403);

    const readBack = await SELF.fetch(`${BASE}/admin/v1/quota-policies/project/proj_mine`, {
      headers: bearer(OPERATOR),
    });
    expect((await readBack.json()) as { quota_policy: { rpm_limit: number } }).toMatchObject({
      quota_policy: { rpm_limit: 30 },
    });
  });
});
