/**
 * `/usage-aggregates` reads the tenant accumulator through the object for a
 * tenant caller and the replace-style control projection for a platform caller.
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
  const handle = await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(TENANT);
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
  await db().batch([
    db().prepare("DELETE FROM usage_aggregate_rollups"),
    db().prepare("DELETE FROM tenant_databases"),
  ]);
  const tenant = await tenantDatabase();
  await tenant.batch([
    tenant.prepare("DELETE FROM usage_aggregate_rollups"),
    tenant.prepare("DELETE FROM tenant_contexts"),
  ]);
});

describe("usage aggregate authority and projection reads", () => {
  it("reads a tenant object for tenant callers and control projection for operators", async () => {
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

    await db()
      .prepare(
        `INSERT INTO usage_aggregate_rollups
           (projection_key, id, tenant, tenant_context_id, organization_id,
            project_id, api_key_id, logical_model, provider, prompt_tokens,
            completion_tokens, total_tokens, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        `projection:${TENANT}`,
        "forged-control-id",
        TENANT,
        "forged-context",
        TENANT,
        "project-control",
        "key-control",
        "model-control",
        "provider-control",
        100,
        100,
        200,
        30,
      )
      .run();

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
    const operatorBody = (await operatorResponse.json()) as Record<string, unknown>;
    expect(operatorBody.source).toBe("derived_control_projection");
    expect(operatorBody.data).toEqual([
      expect.objectContaining({ id: "forged-control-id", logical_model: "model-control" }),
    ]);
  });
});
