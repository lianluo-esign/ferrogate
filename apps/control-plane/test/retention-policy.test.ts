import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerDurableObjectTenant, tenantObjectDb } from "./tenant-object.js";

const TENANT = "tenant_retention_policy";
const TENANT_SECRET = "tenant-retention-policy-secret";
const ASSET_TYPE = "binaries";

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_SECRET, TENANT)],
  });
  await registerDurableObjectTenant(TENANT);
  await tenantObjectDb(TENANT).prepare("DELETE FROM retention_policies").run();
});

describe("asset retention policy admin routes", () => {
  it("lets a tenant write and read its own policy, and stores it in the tenant object", async () => {
    const path = `/admin/v1/retention-policies/${TENANT}/${ASSET_TYPE}`;
    const put = await SELF.fetch(
      `${BASE}${path}`,
      jsonRequest(TENANT_SECRET, "PUT", {
        keep_last_n: 3,
        max_age_secs: 86_400,
        min_age_secs: 60,
      }),
    );
    expect(put.status).toBe(200);
    expect(await put.json()).toMatchObject({
      object: "retention_policy",
      retention_policy: {
        tenant_id: TENANT,
        resource_type: "asset",
        scope: ASSET_TYPE,
        asset_type: ASSET_TYPE,
        keep_last_n: 3,
        max_age_secs: 86_400,
        min_age_secs: 60,
      },
    });

    const get = await SELF.fetch(`${BASE}${path}`, { headers: bearer(TENANT_SECRET) });
    expect(get.status).toBe(200);
    expect(await get.json()).toMatchObject({
      object: "retention_policy",
      retention_policy: {
        tenant_id: TENANT,
        scope: ASSET_TYPE,
        keep_last_n: 3,
        max_age_secs: 86_400,
        min_age_secs: 60,
      },
    });

    const row = await tenantObjectDb(TENANT)
      .prepare(
        "SELECT tenant_id, resource_type, scope, keep_last_n, max_age_secs, min_age_secs FROM retention_policies",
      )
      .first<Record<string, unknown>>();
    expect(row).toEqual({
      tenant_id: TENANT,
      resource_type: "asset",
      scope: ASSET_TYPE,
      keep_last_n: 3,
      max_age_secs: 86_400,
      min_age_secs: 60,
    });
  });

  it("lets a platform operator address another tenant but fences a tenant key", async () => {
    const otherTenant = "tenant_retention_other";
    await registerDurableObjectTenant(otherTenant);
    const otherPath = `/admin/v1/retention-policies/${otherTenant}/*`;

    const denied = await SELF.fetch(
      `${BASE}${otherPath}`,
      jsonRequest(TENANT_SECRET, "PUT", { keep_last_n: 1 }),
    );
    expect(denied.status).toBe(403);

    const allowed = await SELF.fetch(
      `${BASE}${otherPath}`,
      jsonRequest(operatorKey.secret, "PUT", { keep_last_n: 1 }),
    );
    expect(allowed.status).toBe(200);
    const row = await tenantObjectDb(otherTenant)
      .prepare("SELECT tenant_id, scope, keep_last_n FROM retention_policies")
      .first<Record<string, unknown>>();
    expect(row).toEqual({ tenant_id: otherTenant, scope: "*", keep_last_n: 1 });
  });
});
