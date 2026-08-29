import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { BASE, OPERATOR_KEY, arm, jsonRequest, tenantKey } from "./harness.js";

/**
 * `POST /admin/v1/tenant-teardown` guard coverage.
 *
 * These exercise the fences that short-circuit BEFORE the control-database read
 * (fence 5) — the ones reachable under the default in-memory harness, exactly as
 * the sibling operator route's coverage is. The deep cascade (DO wipe, control
 * sweep, roster removal, idempotent re-run) is verified against a real, deleted
 * TEST tenant on the deployed control plane, because it needs a provisioned
 * TenantDataObject plus seeded `tenants`/directory rows the memory store does
 * not expose.
 */
const KEEP_TENANT_ID = "tenant-9a03494f-728d-4871-bc9f-63baa0f48b24";
const PATH = `${BASE}/admin/v1/tenant-teardown`;
const ACK = "TEARDOWN_TENANT";

describe("tenant-teardown fences", () => {
  beforeEach(() => {
    arm({
      staticKeys: [
        { secret: OPERATOR_KEY, id: "static_operator", platform_operator: true, scopes: ["*"] },
      ],
      nativeKeys: [tenantKey("tenant-secret", "tenant_x")],
    });
  });

  test("fence 1: a missing key is 401", async () => {
    const res = await SELF.fetch(PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenant_id: "tenant_x", confirm: "tenant_x", acknowledge: ACK }),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "missing_api_key" } });
  });

  test("fence 1: a tenant-scoped key is 403 platform_operator_required", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest("tenant-secret", "POST", {
        tenant_id: "tenant_x",
        confirm: "tenant_x",
        acknowledge: ACK,
      }),
    );
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      error: { code: "platform_operator_required" },
    });
  });

  test("fence 2: confirm must equal tenant_id", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(OPERATOR_KEY, "POST", {
        tenant_id: "tenant_x",
        confirm: "tenant_y",
        acknowledge: ACK,
      }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "confirm_mismatch" } });
  });

  test("fence 3: acknowledge must be the literal TEARDOWN_TENANT", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(OPERATOR_KEY, "POST", {
        tenant_id: "tenant_x",
        confirm: "tenant_x",
        acknowledge: "PURGE_CONSUMPTION",
      }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "acknowledge_required" } });
  });

  test("fence 4: the keep tenant is refused unconditionally", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(OPERATOR_KEY, "POST", {
        tenant_id: KEEP_TENANT_ID,
        confirm: KEEP_TENANT_ID,
        acknowledge: ACK,
      }),
    );
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "tenant_protected" } });
  });

  test("a malformed body is 400 before any delete", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(OPERATOR_KEY, "POST", { confirm: "tenant_x", acknowledge: ACK }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "invalid_request_body" } });
  });
});
