import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { tenantObjectDb, registerDurableObjectTenant } from "./tenant-object.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

const TENANT = "tenant_a";
const TENANT_SECRET = "tenant-a-secret";

function eventJson(tenantId: string): string {
  return JSON.stringify({
    request_id: `req_${tenantId}`,
    tenant: { organization_id: tenantId },
    logical_model: "chat",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    cost_usd: 0.25,
  });
}

async function resetBillingState(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM billing_events"),
    db().prepare("DELETE FROM billing_report_outbox"),
  ]);
  for (const tenantId of [TENANT]) {
    await tenantObjectDb(tenantId).batch([
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_report_outbox"),
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_events"),
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_ledger"),
    ]);
  }
}

beforeAll(applySchema);

describe("billing admin reads use tenant billing authority", () => {
  beforeEach(async () => {
    await resetD1();
    await resetBillingState();
    await registerDurableObjectTenant(TENANT);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, TENANT)],
    });
    const tenantDb = tenantObjectDb(TENANT);
    await tenantDb.batch([
      tenantDb
        .prepare(
          `INSERT INTO billing_events
             (billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
           VALUES (?, ?, ?, 0, 1700, ?)`,
        )
        .bind("evt_tenant_a", TENANT, "req_tenant_a", eventJson(TENANT)),
      tenantDb
        .prepare(
          `INSERT INTO billing_report_outbox
             (id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix,
              created_at_unix, updated_at_unix, event_json)
           VALUES (?, ?, 4, 1700, 1800, 1700, 1700, ?)`,
        )
        .bind("report_tenant_a", TENANT, eventJson(TENANT)),
    ]);
  });

  it("serves canonical and compatibility metering feeds from the same tenant rows", async () => {
    const canonical = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(TENANT_SECRET),
    });
    const compat = await SELF.fetch(`${BASE}/admin/v1/billing-events`, {
      headers: bearer(TENANT_SECRET),
    });

    expect(canonical.status).toBe(200);
    const canonicalBody = await canonical.json();
    expect(canonicalBody).toEqual(await compat.json());
    expect(canonicalBody as { data: { id: string; tenant_id: string }[] }).toMatchObject({
      data: [{ id: "evt_tenant_a", tenant_id: TENANT }],
    });
  });

  it("serves a tenant dead-letter list from the tenant outbox", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters`, {
      headers: bearer(TENANT_SECRET),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      data: [{ id: "report_tenant_a", tenant_id: TENANT, dead_lettered_at_unix: 1800 }],
    });
  });

  it("lets a platform operator discover the tenant authority row", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      data: [{ id: "evt_tenant_a", tenant_id: TENANT }],
    });
  });
});
