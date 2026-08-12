/**
 * `GET /admin/v1/billing-fleet` route glue (#956 read side) — the paths
 * provable over the deployed Worker without the (unemulatable) Analytics Engine
 * read surface: the platform fence, the query validation, and the
 * unconfigured-⇒-503 posture. The aggregate math itself is pinned offline in
 * `billing-fleet.test.ts`.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import { TENANT_A } from "./tenant-db.js";

const OPERATOR = operatorKey.secret;
const TENANT_SECRET = "billing-fleet-tenant";

async function get(secret: string, path: string): Promise<{ status: number; body: unknown }> {
  const response = await SELF.fetch(`${BASE}${path}`, { headers: bearer(secret) });
  return { status: response.status, body: await response.json().catch(() => null) };
}

describe("GET /admin/v1/billing-fleet", () => {
  beforeAll(async () => {
    await applySchema();
  });

  beforeEach(() => {
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, TENANT_A, ["admin.read", "admin.write"])],
      rbac: { [TENANT_A]: ["*"] },
    });
  });

  it("fences a tenant-scoped caller with a leak-proof 404", async () => {
    // A tenant caller can never learn the fleet endpoint exists: 404, not 403.
    expect((await get(TENANT_SECRET, "/admin/v1/billing-fleet")).status).toBe(404);
  });

  it("answers 503 when the Analytics Engine query surface is unconfigured", async () => {
    // The test env binds no BILLING_ANALYTICS_{DATASET,ACCOUNT_ID,API_TOKEN},
    // so the service is null and the operator gets a retryable 503 — never a 500
    // and never a fabricated empty report.
    const res = await get(OPERATOR, "/admin/v1/billing-fleet");
    expect(res.status).toBe(503);
    expect((res.body as { error?: { code?: string } }).error?.code).toBe("analytics_unavailable");
  });

  it("rejects an unknown group_by with 400 before touching the query surface", async () => {
    const res = await get(OPERATOR, "/admin/v1/billing-fleet?group_by=nonsense");
    expect(res.status).toBe(400);
    expect((res.body as { error?: { code?: string } }).error?.code).toBe("invalid_request");
  });

  it("rejects since >= until with 400", async () => {
    const res = await get(OPERATOR, "/admin/v1/billing-fleet?since=2000&until=1000");
    expect(res.status).toBe(400);
  });

  it("accepts a valid group_by (reaching the 503, i.e. validation passed)", async () => {
    // A whitelisted dimension is NOT a 400; it falls through to the unconfigured
    // 503, proving the validation accepts every real dimension.
    const res = await get(OPERATOR, "/admin/v1/billing-fleet?group_by=logical_model&limit=5");
    expect(res.status).toBe(503);
  });
});
