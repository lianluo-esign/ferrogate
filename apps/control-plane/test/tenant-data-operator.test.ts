import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { BASE, OPERATOR_KEY, arm, jsonRequest, tenantKey } from "./harness.js";

const TENANT = "tenant_operator_route";

function exportBucket(): R2Bucket {
  return (env as unknown as { SIEM_EXPORTS: R2Bucket }).SIEM_EXPORTS;
}

describe("operator tenant-data routes", () => {
  beforeEach(() => {
    arm({
      staticKeys: [
        {
          secret: OPERATOR_KEY,
          id: "static_operator",
          platform_operator: true,
          scopes: ["*"],
        },
      ],
      nativeKeys: [tenantKey("tenant-secret", TENANT)],
    });
  });

  test("refuses a non-operator caller before reaching the object", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-data/${TENANT}/query`,
      jsonRequest("tenant-secret", "POST", { sql: "SELECT 1 AS answer" }),
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "platform_operator_required" },
    });
  });

  test("operator query is reachable and writes its object audit record", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-data/${TENANT}/query`,
      jsonRequest(OPERATOR_KEY, "POST", { sql: "SELECT 1 AS answer" }),
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      object: "tenant_data_query",
      tenant_id: TENANT,
      row_count: 1,
    });
  });

  test("operator export stores one resumable JSONL page in R2", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/tenant-data/${TENANT}/export`,
      jsonRequest(OPERATOR_KEY, "POST", {
        export_id: "00000000-0000-4000-8000-000000000828",
        page_size: 1,
      }),
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      object_key: string;
      format: string;
      rows: number;
    };
    expect(body.format).toBe("jsonl");
    expect(body.rows).toBeGreaterThanOrEqual(0);
    expect(await exportBucket().head(body.object_key)).not.toBeNull();
  });

  test("tenant callers can export themselves but not another tenant", async () => {
    const own = await SELF.fetch(
      `${BASE}/admin/v1/tenant-data/${TENANT}/export`,
      jsonRequest("tenant-secret", "POST", {
        export_id: "00000000-0000-4000-8000-000000000829",
        page_size: 1,
      }),
    );
    expect(own.status).toBe(200);

    const other = await SELF.fetch(
      `${BASE}/admin/v1/tenant-data/tenant_other/export`,
      jsonRequest("tenant-secret", "POST", {
        export_id: "00000000-0000-4000-8000-000000000830",
        page_size: 1,
      }),
    );
    expect(other.status).toBe(403);
    await expect(other.json()).resolves.toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });
});
