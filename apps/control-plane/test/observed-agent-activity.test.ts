import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, tenantKey } from "./harness.js";
import { tenantObjectDb } from "./tenant-object.js";

const TENANT = "activity_tenant";
const API_KEY = "activity_key";

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  const db = tenantObjectDb(TENANT);
  await db.batch([
    db.prepare("DELETE FROM request_logs"),
    db.prepare("DELETE FROM observed_agent_presence"),
    db.prepare("DELETE FROM usage_monthly_rollups"),
    db.prepare("DELETE FROM api_keys"),
  ]);
  arm({
    store: "d1",
    staticKeys: [],
    nativeKeys: [tenantKey("activity-secret", TENANT)],
    rbac: {},
  });
});

describe("GET /admin/v1/observed-agent-activity", () => {
  it("reads an unattributed virtual key from request logs and tenant presence", async () => {
    const now = Math.floor(Date.now() / 1000);
    const db = tenantObjectDb(TENANT);
    await db.batch([
      db
        .prepare(
          "INSERT INTO api_keys " +
            "(id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(
          API_KEY,
          "workspace_activity",
          TENANT,
          "project_activity",
          "CLI key",
          "fg_",
          "hash",
          "0000",
        ),
      db
        .prepare(
          "INSERT INTO request_logs " +
            "(request_id, tenant, api_key_id, started_at_unix, completed_at_unix, total_tokens) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("request_activity", TENANT, API_KEY, now - 10, now - 8, 12),
      db
        .prepare(
          "INSERT INTO observed_agent_presence " +
            "(tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(TENANT, API_KEY, now - 60, now - 5, 2, now),
    ]);

    const response = await SELF.fetch(`${BASE}/admin/v1/observed-agent-activity?limit=10`, {
      headers: bearer("activity-secret"),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as {
      data: Record<string, any>[];
      total: number;
      presence_feed: Record<string, unknown>;
    };
    expect(body.total).toBe(1);
    expect(body.presence_feed).toMatchObject({
      status: "available",
      rows_may_be_incomplete: false,
    });
    expect(body.data[0]).toMatchObject({
      id: `observed:${TENANT}:${API_KEY}`,
      source: "virtual_api_key",
      identity_status: "unattributed",
      display_name: "Unknown",
      status: "running",
      status_basis: "recent_api_key_activity",
      tenant_id: TENANT,
      api_key_id: API_KEY,
      credential_name: "CLI key",
      evidence: {
        evidence_source: "request_logs",
        request_count: 1,
        presence_feed_status: "available",
        durable_presence_backed: true,
        usage_evidence_available: true,
      },
    });
  });
});
