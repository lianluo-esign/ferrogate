/**
 * `/usage-aggregates` reads the tenant accumulator through the object for a
 * tenant caller, and — for a platform caller — a bounded live fan-out over each
 * provisioned tenant's Durable Object. The control-side `usage_aggregate_rollups`
 * projection was DROPPED (control migration 0036); the authoritative rollups live
 * only in each tenant object, so neither path can touch a control projection —
 * there is no longer one to touch.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

const TENANT = "usage-read-tenant";
const TENANT_KEY = "usage-read-key";
const AGGREGATE_ID = "usage-context:model-object:provider-object";

async function tenantDatabase(): Promise<D1Database> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, NULL, 18, 'durable_object', 'ready', 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         storage_backend = 'durable_object', provisioning_status = 'ready', migration_state = 'done'`,
    )
    .bind(TENANT)
    .run();
  const handle = await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(
    TENANT,
  );
  expect(handle.source).toBe("durable_object");
  return handle.db;
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_KEY, TENANT)],
  });
  // The control `usage_aggregate_rollups` projection no longer exists (0036), so
  // there is nothing to clear on the control side — only the tenant roster row.
  await db().prepare("DELETE FROM tenant_databases").run();
  const tenant = await tenantDatabase();
  await tenant.batch([
    tenant.prepare("DELETE FROM usage_aggregate_rollups"),
    tenant.prepare("DELETE FROM tenant_contexts"),
  ]);
});

describe("usage aggregate authority and projection reads", () => {
  it("reads the tenant object for tenant callers and fans out over tenant objects for operators, never a control projection", async () => {
    const tenant = await tenantDatabase();
    await tenant.batch([
      tenant
        .prepare(
          `INSERT INTO tenant_contexts
             (id, organization_id, project_id, api_key_id)
           VALUES (?, ?, ?, ?)`,
        )
        .bind("usage-context", TENANT, "project-object", "key-object"),
      tenant
        .prepare(
          `INSERT INTO usage_aggregate_rollups
             (id, tenant_context_id, logical_model, provider, prompt_tokens,
              completion_tokens, total_tokens, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(AGGREGATE_ID, "usage-context", "model-object", "provider-object", 7, 3, 10, 20),
    ]);

    // No control-side decoy is possible any more: the `usage_aggregate_rollups`
    // control projection was dropped by migration 0036, so the only place a row
    // can live is the tenant object seeded above. Both reads below must return it.
    const tenantResponse = await SELF.fetch(`${BASE}/admin/v1/usage-aggregates`, {
      headers: bearer(TENANT_KEY),
    });
    expect(tenantResponse.status, await tenantResponse.clone().text()).toBe(200);
    const tenantBody = (await tenantResponse.json()) as {
      data: Record<string, unknown>[];
    };
    expect(tenantBody.data).toEqual([
      expect.objectContaining({
        id: AGGREGATE_ID,
        logical_model: "model-object",
        provider: "provider-object",
        usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
      }),
    ]);

    const operatorResponse = await SELF.fetch(`${BASE}/admin/v1/usage-aggregates`, {
      headers: bearer(operatorKey.secret),
    });
    expect(operatorResponse.status, await operatorResponse.clone().text()).toBe(200);
    const operatorBody = (await operatorResponse.json()) as Record<string, unknown> & {
      data: Record<string, unknown>[];
    };
    // The operator page is a Durable-Object fan-out: it returns the tenant OBJECT
    // row and pages the tenant roster. It advertises no control projection source
    // (the control `usage_aggregate_rollups` mirror was dropped by 0036).
    expect(operatorBody.source).toBeUndefined();
    expect(operatorBody.tenant_page).toEqual(
      expect.objectContaining({ offset: 0, total: expect.any(Number) }),
    );
    expect(operatorBody.data).toEqual([
      expect.objectContaining({
        id: AGGREGATE_ID,
        logical_model: "model-object",
        provider: "provider-object",
        usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
      }),
    ]);
  });
});
