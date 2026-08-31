/**
 * `POST /admin/v1/quota-policy-backfill` driven through the EXPORTED Worker with
 * the D1 store live (production default), so the sweep reads the REAL control
 * `quota_policies` facade and writes the REAL tenant objects — the boundary the
 * deploy-ordering keystone actually crosses.
 *
 * The load-bearing proof is the VERBATIM column copy: a control row is seeded
 * DIRECTLY (never through the route, so it lands only on control, exactly as a
 * policy configured before the writer dual-write shipped would) carrying an
 * array column, a JSON-tag column and the two INTEGER-boolean flags
 * (`enabled = 0`, `require_zero_data_retention = 1`) that a document re-projection
 * would silently corrupt. The backfill must reproduce every one of them byte for
 * byte in the owning tenant object — which is why it copies columns rather than
 * re-running `projectQuotaPolicy`.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "tenant-a-secret";
const PATH = `${BASE}/admin/v1/quota-policy-backfill`;
const ACK = "BACKFILL_QUOTA_POLICIES";

/** The full typed enforcement row of a scope, straight out of a given handle. */
async function typedRow(
  handle: D1Database,
  scopeType: string,
  scopeId: string,
): Promise<Record<string, unknown> | null> {
  return handle
    .prepare("SELECT * FROM quota_policies WHERE scope_type = ? AND scope_id = ?")
    .bind(scopeType, scopeId)
    .first<Record<string, unknown>>();
}

/**
 * Seed a typed `quota_policies` row DIRECTLY onto the control facade — never
 * through the route — so it exists ONLY on control, the state of every policy
 * configured before the writer dual-write shipped. The columns chosen are the
 * ones a re-projection would lose or mis-copy.
 */
async function seedControlOnlyRow(scopeType: string, scopeId: string, rpm: number): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO quota_policies
         (id, scope_type, scope_id, model_allowlist_json, rpm_limit, enabled,
          require_zero_data_retention, required_tags_json,
          spend_anomaly_enabled, spend_anomaly_ratio)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      `${scopeType}:${scopeId}`,
      scopeType,
      scopeId,
      '["gpt-4"]',
      rpm,
      0, // disabled — `record.enabled !== false` would read this integer as TRUE
      1, // ZDR on — `record.require_zero_data_retention === true` would read it FALSE
      '["team"]',
      0, // detector opted OUT
      8, // ratio LOOSENED far above the tight default
    )
    .run();
}

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
  await registerObjectTenants(["tenant_a", "tenant_b"]);
});

describe("quota-policy-backfill fences", () => {
  it("fence 1: a missing key is 401", async () => {
    const res = await SELF.fetch(PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ acknowledge: ACK }),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "missing_api_key" } });
  });

  it("fence 1: a tenant-scoped key is 403 platform_operator_required", async () => {
    const res = await SELF.fetch(PATH, jsonRequest(TENANT_A_KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      error: { code: "platform_operator_required" },
    });
  });

  it("fence 2: acknowledge must be the literal BACKFILL_QUOTA_POLICIES", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: "PURGE_CONSUMPTION" }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "acknowledge_required" } });
  });

  it("a non-boolean dry_run is 400 before any write", async () => {
    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK, dry_run: "yes" }));
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "invalid_request_body" } });
  });
});

describe("quota-policy-backfill copies control rows into tenant objects", () => {
  it("copies a control-only row into the owning object VERBATIM, flags and all", async () => {
    await seedControlOnlyRow("tenant", "tenant_a", 90);
    // Precondition: the object has NOTHING yet — this is what a reader cutover
    // would meet without the backfill.
    expect(await typedRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toBeNull();

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as {
      dry_run: boolean;
      source_rows: number;
      written: Record<string, number>;
      total: number;
    };
    expect(report.dry_run).toBe(false);
    expect(report.source_rows).toBe(1);
    expect(report.written.tenant_a).toBe(1);
    expect(report.total).toBe(1);

    // THE assertion: every column landed byte-for-byte, including the two integer
    // booleans a document re-projection would have corrupted.
    const copied = await typedRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a");
    expect(copied).toMatchObject({
      id: "tenant:tenant_a",
      rpm_limit: 90,
      model_allowlist_json: '["gpt-4"]',
      enabled: 0,
      require_zero_data_retention: 1,
      required_tags_json: '["team"]',
      spend_anomaly_enabled: 0,
      spend_anomaly_ratio: 8,
    });
  });

  it("is idempotent: a second run overwrites and reports the same, no errors", async () => {
    await seedControlOnlyRow("tenant", "tenant_a", 55);

    const first = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(first.status).toBe(200);

    const second = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(second.status).toBe(200);
    const report = (await second.json()) as {
      written: Record<string, number>;
      total: number;
      errors?: Record<string, string>;
    };
    expect(report.total).toBe(1);
    expect(report.written.tenant_a).toBe(1);
    expect(report.errors).toBeUndefined();
    expect(await typedRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toMatchObject({
      rpm_limit: 55,
    });
  });

  it("dry_run reports the plan without writing anything", async () => {
    await seedControlOnlyRow("tenant", "tenant_a", 42);

    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, dry_run: true }),
    );
    expect(res.status).toBe(200);
    const report = (await res.json()) as {
      dry_run: boolean;
      written: Record<string, number>;
      total: number;
    };
    expect(report.dry_run).toBe(true);
    expect(report.written.tenant_a).toBe(1);
    expect(report.total).toBe(1);
    // Nothing was actually written.
    expect(await typedRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toBeNull();
  });

  it("reports an unresolvable owner as a residual, not a write", async () => {
    // A project-scoped policy whose owning project does not exist resolves to no
    // tenant, so it cannot be placed in any object.
    await seedControlOnlyRow("project", "ghost_project", 10);

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as {
      total: number;
      residuals?: { scope_id: string; reason: string }[];
    };
    expect(report.total).toBe(0);
    expect(report.residuals).toEqual([
      expect.objectContaining({ scope_id: "ghost_project", reason: "unresolved_owner" }),
    ]);
  });

  it("skips a policy whose owning tenant has no provisioned object", async () => {
    // `tenant_zzz` is a real tenant scope but was never registered in the roster,
    // so it has no object to backfill.
    await seedControlOnlyRow("tenant", "tenant_zzz", 30);

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as {
      total: number;
      skipped: { unprovisioned: number; non_durable_object: number };
    };
    expect(report.total).toBe(0);
    expect(report.skipped.unprovisioned).toBe(1);
    expect(await typedRow(tenantObjectDb("tenant_zzz"), "tenant", "tenant_zzz")).toBeNull();
  });
});
