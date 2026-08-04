/**
 * Tenant-authoritative request evidence reads (#859).
 *
 * This suite writes both the real TenantDataObject and the control-D1
 * compatibility projection, then mutates the projection. A read that still
 * treats control D1 as authoritative returns the forged values and fails.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, resetD1, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

const TENANT = "evidence-tenant";
const OTHER_TENANT = "evidence-other";
const REQUEST_ID = "evidence-request-1";
const RUN_ID = "evidence-run-1";

async function routeTenant(tenantId: string): Promise<D1Database> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, database_uuid, database_name, binding_name, schema_version,
          storage_backend, provisioning_status, provisioned_at_unix, updated_at_unix)
       VALUES (?, ?, ?, NULL, 12, 'durable_object', 'ready', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         storage_backend = 'durable_object', provisioning_status = 'ready'`,
    )
    .bind(tenantId, `uuid-${tenantId}`, `db-${tenantId}`)
    .run();
  const handle = await resolveTenantDatabases(
    env as unknown as ControlPlaneBindings,
  ).forTenant(tenantId);
  expect(handle.source).toBe("durable_object");
  return handle.db;
}

async function resetTenantEvidence(): Promise<void> {
  for (const tenantId of [TENANT, OTHER_TENANT]) {
    const tenant = await routeTenant(tenantId);
    await tenant.batch([
      tenant.prepare("DELETE FROM agent_run_events"),
      tenant.prepare("DELETE FROM agent_runs"),
      tenant.prepare("DELETE FROM request_logs"),
    ]);
  }
}

async function seedAuthoritativeEvidence(): Promise<void> {
  await seedObjectEvidence(TENANT, "tenant-object", "object-route");

  await seedRequestLogs([
    {
      requestId: REQUEST_ID,
      tenant: TENANT,
      startedAtUnix: 100,
      statusCode: 500,
      route: "control-route",
      document: { source: "control-projection" },
    },
  ]);
  await db().batch([
    db()
      .prepare(
        `INSERT INTO agent_runs
           (id, request_id, tenant, started_at_unix, completed_at_unix, run_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(RUN_ID, REQUEST_ID, TENANT, 100, 103, JSON.stringify({ source: "control-projection" })),
    db()
      .prepare(
        `INSERT INTO agent_run_events
           (id, run_id, request_id, tenant, occurred_at_unix, event_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "evidence-event-1",
        RUN_ID,
        REQUEST_ID,
        TENANT,
        101,
        JSON.stringify({ source: "control-projection" }),
      ),
  ]);

  // The compatibility mirror is mutable and intentionally forged after the
  // authoritative object has been populated.
  await db().batch([
    db()
      .prepare(
        "UPDATE request_logs SET route = 'forged-control-route', status_code = 418, request_json = ? WHERE request_id = ?",
      )
      .bind(JSON.stringify({ source: "forged-control" }), REQUEST_ID),
    db()
      .prepare("UPDATE agent_runs SET run_json = ? WHERE id = ?")
      .bind(JSON.stringify({ source: "forged-control" }), RUN_ID),
    db()
      .prepare("UPDATE agent_run_events SET event_json = ? WHERE id = ?")
      .bind(JSON.stringify({ source: "forged-control" }), "evidence-event-1"),
  ]);
}

async function seedObjectEvidence(tenantId: string, source: string, route: string): Promise<void> {
  const tenant = await routeTenant(tenantId);
  await tenant.batch([
    tenant
      .prepare(
        `INSERT INTO request_logs
           (request_id, trace_id, agent_run_id, tenant, route, status_code,
            guardrail_verdict, started_at_unix, request_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        REQUEST_ID,
        "trace-object",
        RUN_ID,
        tenantId,
        route,
        201,
        "allowed",
        100,
        JSON.stringify({ source }),
      ),
    tenant
      .prepare(
        `INSERT INTO agent_runs
           (id, request_id, tenant, started_at_unix, completed_at_unix, run_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(RUN_ID, REQUEST_ID, tenantId, 100, 103, JSON.stringify({ source })),
    tenant
      .prepare(
        `INSERT INTO agent_run_events
           (id, run_id, request_id, tenant, occurred_at_unix, event_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "evidence-event-1",
        RUN_ID,
        REQUEST_ID,
        tenantId,
        101,
        JSON.stringify({ source, sequence: 1 }),
      ),
  ]);
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("evidence-key", TENANT), tenantKey("other-evidence-key", OTHER_TENANT)],
    rbac: { [TENANT]: ["guardrails.evidence.read"] },
  });
  await db().batch([
    db().prepare("DELETE FROM agent_run_events"),
    db().prepare("DELETE FROM agent_runs"),
  ]);
  await resetTenantEvidence();
});

describe("tenant-authoritative request evidence reads", () => {
  it("lists request logs from the exact tenant object after the projection is mutated", async () => {
    await seedAuthoritativeEvidence();

    const response = await SELF.fetch(`${BASE}/admin/v1/request-logs`, {
      headers: bearer("evidence-key"),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as { data: Record<string, unknown>[] };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]).toMatchObject({
      request_id: REQUEST_ID,
      route: "object-route",
      status_code: 201,
      source: "tenant-object",
    });
  });

  it("uses exact tenant objects for investigation requests, runs, and ordered events", async () => {
    await seedAuthoritativeEvidence();

    const response = await SELF.fetch(
      `${BASE}/admin/v1/investigations?request_id=${REQUEST_ID}`,
      { headers: bearer("evidence-key") },
    );
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.requests).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ route: "object-route", source: "tenant-object" }),
      ]),
    );
    expect(body.agent_runs).toEqual(
      expect.arrayContaining([expect.objectContaining({ source: "tenant-object" })]),
    );
    expect(body.agent_events).toEqual(
      expect.arrayContaining([expect.objectContaining({ source: "tenant-object" })]),
    );
    expect(JSON.stringify(body)).not.toContain("forged-control");
  });

  it("reads the agent-run list and timeline from the exact tenant object", async () => {
    await seedAuthoritativeEvidence();

    const list = await SELF.fetch(`${BASE}/admin/v1/agent-runs`, {
      headers: bearer("evidence-key"),
    });
    expect(list.status, await list.clone().text()).toBe(200);
    const listBody = (await list.json()) as { data: Record<string, unknown>[] };
    expect(listBody.data).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: RUN_ID, source: "tenant-object" })]),
    );

    const timeline = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer("evidence-key"),
    });
    expect(timeline.status, await timeline.clone().text()).toBe(200);
    const timelineBody = (await timeline.json()) as { data: Record<string, unknown>[] };
    expect(timelineBody.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "evidence-event-1", source: "tenant-object" }),
      ]),
    );
  });

  it("keeps identical request and run ids isolated across two tenant objects", async () => {
    await seedAuthoritativeEvidence();
    await seedObjectEvidence(OTHER_TENANT, "other-tenant-object", "other-object-route");

    const tenantRequest = await SELF.fetch(`${BASE}/admin/v1/request-logs`, {
      headers: bearer("evidence-key"),
    });
    expect(tenantRequest.status, await tenantRequest.clone().text()).toBe(200);
    const tenantRequestBody = (await tenantRequest.json()) as {
      data: Record<string, unknown>[];
    };
    expect(tenantRequestBody.data).toEqual([
      expect.objectContaining({
        request_id: REQUEST_ID,
        tenant_id: TENANT,
        route: "object-route",
        source: "tenant-object",
      }),
    ]);

    const otherRequest = await SELF.fetch(`${BASE}/admin/v1/request-logs`, {
      headers: bearer("other-evidence-key"),
    });
    expect(otherRequest.status, await otherRequest.clone().text()).toBe(200);
    const otherRequestBody = (await otherRequest.json()) as {
      data: Record<string, unknown>[];
    };
    expect(otherRequestBody.data).toEqual([
      expect.objectContaining({
        request_id: REQUEST_ID,
        tenant_id: OTHER_TENANT,
        route: "other-object-route",
        source: "other-tenant-object",
      }),
    ]);

    const otherTimeline = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer("other-evidence-key"),
    });
    expect(otherTimeline.status, await otherTimeline.clone().text()).toBe(200);
    const otherTimelineBody = (await otherTimeline.json()) as {
      data: Record<string, unknown>[];
    };
    expect(otherTimelineBody.data).toEqual([
      expect.objectContaining({ id: "evidence-event-1", source: "other-tenant-object" }),
    ]);
  });

  it("labels platform projection-backed agent responses with source and as-of time", async () => {
    await seedAuthoritativeEvidence();

    const list = await SELF.fetch(`${BASE}/admin/v1/agent-runs`, {
      headers: bearer(operatorKey.secret),
    });
    const listBody = (await list.json()) as Record<string, unknown>;
    expect(listBody.source).toBe("derived_control_projection");
    expect(listBody.as_of_unix).toEqual(expect.any(Number));

    const timeline = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer(operatorKey.secret),
    });
    const timelineBody = (await timeline.json()) as Record<string, unknown>;
    expect(timelineBody.source).toBe("derived_control_projection");
    expect(timelineBody.as_of_unix).toEqual(expect.any(Number));
  });
});
