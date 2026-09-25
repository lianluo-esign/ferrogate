import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

const TENANT = "announcement-tenant";
const TENANT_KEY = "announcement-tenant-key";

async function request(method: string, path: string, body?: unknown, key = operatorKey.secret) {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/announcements${path}`,
    body === undefined ? { method, headers: bearer(key) } : jsonRequest(key, method, body),
  );
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

beforeAll(applySchema);
beforeEach(async () => {
  await resetD1();
  await db().batch([
    db().prepare("DELETE FROM platform_announcements"),
    db().prepare("DELETE FROM platform_announcement_revisions"),
  ]);
  await registerObjectTenants([TENANT]);
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_KEY, TENANT)],
  });
});

describe("announcements have one platform authority", () => {
  it("round-trips platform CRUD after all tenant mirror tables and the push cursor are removed", async () => {
    const mirrorTables = await tenantObjectDb(TENANT)
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN " +
          "('shared_announcements', 'shared_billing_groups', 'shared_config_cursor')",
      )
      .all();
    expect(mirrorTables.results).toEqual([]);
    expect(
      await db()
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'shared_config_push_state'",
        )
        .first(),
    ).toBeNull();

    const created = await request("POST", "", { id: "notice", title: "Before", body: "Body" });
    expect(created.status).toBe(201);
    expect(
      await db().prepare("SELECT title FROM platform_announcements WHERE id = 'notice'").first(),
    ).toEqual({ title: "Before" });
    expect((await request("GET", "/notice")).body).toMatchObject({
      announcement: { title: "Before" },
    });
    expect((await request("GET", "")).body).toMatchObject({ data: [{ id: "notice" }] });

    expect((await request("PATCH", "/notice", { title: "After" })).status).toBe(200);
    expect((await request("GET", "/notice")).body).toMatchObject({
      announcement: { title: "After" },
    });
    expect(
      await db().prepare("SELECT title FROM platform_announcements WHERE id = 'notice'").first(),
    ).toEqual({ title: "After" });

    expect((await request("DELETE", "/notice")).status).toBe(200);
    expect((await request("GET", "/notice")).status).toBe(404);
    expect(
      await db().prepare("SELECT id FROM platform_announcements WHERE id = 'notice'").first(),
    ).toBeNull();
    const audit = await db()
      .prepare(
        "SELECT count(*) AS count FROM audit_events WHERE json_extract(audit_json, '$.collection') = 'platform_announcements'",
      )
      .first<{ count: number }>();
    expect(audit?.count).toBe(3);
  });

  it("keeps the operator-only fence for every announcement operation", async () => {
    expect((await request("POST", "", { id: "notice", title: "Title", body: "Body" })).status).toBe(
      201,
    );
    for (const [method, path, body] of [
      ["GET", "", undefined],
      ["GET", "/notice", undefined],
      ["POST", "", { id: "forged", title: "Forged", body: "Body" }],
      ["PATCH", "/notice", { title: "Forged" }],
      ["DELETE", "/notice", undefined],
    ] as const) {
      expect((await request(method, path, body, TENANT_KEY)).status).toBe(404);
    }
    expect((await request("GET", "/notice")).body).toMatchObject({
      announcement: { title: "Title" },
    });
  });
});
