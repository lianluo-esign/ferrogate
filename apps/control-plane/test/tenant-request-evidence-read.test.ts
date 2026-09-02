/**
 * Tenant-authoritative request evidence reads (#859).
 *
 * This suite writes the real TenantDataObject and — for `request_logs`, whose
 * control compatibility projection still exists — the control projection too,
 * then mutates the projection. A read that still treats the control store as
 * authoritative returns the forged values and fails. The control `agent_runs` /
 * `agent_run_events` projections were DROPPED (control migration 0037), so for
 * agent evidence there is no longer a control decoy to forge: the tenant object
 * is the only place a run can live.
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
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, NULL, 12, 'durable_object', 'ready', 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         storage_backend = 'durable_object', provisioning_status = 'ready', migration_state = 'done'`,
    )
    .bind(tenantId)
    .run();
  const handle = await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(
    tenantId,
  );
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

  // The request-log compatibility mirror is mutable and intentionally forged
  // after the authoritative object has been populated. (No agent-run decoy is
  // possible any more: control 0037 dropped those projection tables.)
  await db()
    .prepare(
      "UPDATE request_logs SET route = 'forged-control-route', status_code = 418, request_json = ? WHERE request_id = ?",
    )
    .bind(JSON.stringify({ source: "forged-control" }), REQUEST_ID)
    .run();
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
  // The control `agent_runs` / `agent_run_events` projections no longer exist
  // (0037); only the tenant objects hold agent evidence.
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

    const response = await SELF.fetch(`${BASE}/admin/v1/investigations?request_id=${REQUEST_ID}`, {
      headers: bearer("evidence-key"),
    });
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

  it("serves the operator agent-run LIST from the tenant objects, not the forged control mirror", async () => {
    await seedAuthoritativeEvidence();

    const list = await SELF.fetch(`${BASE}/admin/v1/agent-runs`, {
      headers: bearer(operatorKey.secret),
    });
    expect(list.status, await list.clone().text()).toBe(200);
    const listBody = (await list.json()) as {
      data: Record<string, unknown>[];
      source?: unknown;
      as_of_unix?: unknown;
      tenant_page?: { offset: number; limit: number; total: number; has_more: boolean };
    };
    // The operator list is now a bounded live fan-out over the tenant objects:
    // the run is served from its OWNER's object (`tenant-object`), never the
    // forged control mirror (`forged-control`), and the envelope carries a
    // `tenant_page` roster cursor instead of the retired
    // `derived_control_projection` freshness label.
    expect(listBody.data).toEqual([
      expect.objectContaining({ id: RUN_ID, source: "tenant-object" }),
    ]);
    expect(JSON.stringify(listBody)).not.toContain("forged-control");
    expect(listBody.source).toBeUndefined();
    expect(listBody.as_of_unix).toBeUndefined();
    expect(listBody.tenant_page).toMatchObject({ has_more: false });
    expect(listBody.tenant_page?.total).toEqual(expect.any(Number));

    // The {run_id} TIMELINE is now the SAME DO fan-out: for a platform operator
    // naming no tenant it scans the roster, finds the single owning object
    // (TENANT), and serves that object's events — never the forged control
    // mirror, and with no `derived_control_projection` envelope.
    const timeline = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer(operatorKey.secret),
    });
    expect(timeline.status, await timeline.clone().text()).toBe(200);
    const timelineBody = (await timeline.json()) as Record<string, unknown> & {
      data: Record<string, unknown>[];
    };
    expect(timelineBody.data).toEqual([
      expect.objectContaining({ id: "evidence-event-1", source: "tenant-object" }),
    ]);
    expect(JSON.stringify(timelineBody)).not.toContain("forged-control");
    expect(timelineBody.source).toBeUndefined();
    expect(timelineBody.as_of_unix).toBeUndefined();
  });

  it("fences timeline events to the owning tenant even if a foreign-tenant row shares the run id", async () => {
    await seedAuthoritativeEvidence();
    // Defence in depth: even if the owning object somehow held an event row
    // stamped with ANOTHER tenant under the SAME run id, the timeline fences on
    // the owner's tenant (`AND tenant = ?`) and never serves the foreign row.
    const tenant = await routeTenant(TENANT);
    await tenant
      .prepare(
        `INSERT INTO agent_run_events
           (id, run_id, request_id, tenant, occurred_at_unix, event_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "foreign-event",
        RUN_ID,
        REQUEST_ID,
        OTHER_TENANT,
        101,
        JSON.stringify({ source: "foreign-tenant" }),
      )
      .run();

    const timeline = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer(operatorKey.secret),
    });
    expect(timeline.status, await timeline.clone().text()).toBe(200);
    const body = (await timeline.json()) as { data: Record<string, unknown>[] };
    expect(body.data).toEqual([
      expect.objectContaining({ id: "evidence-event-1", tenant: TENANT }),
    ]);
    expect(body.data).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "foreign-event" })]),
    );
  });

  it("rejects ambiguous platform timelines and supports an exact tenant selector", async () => {
    // Two DISTINCT tenant objects both own RUN_ID (a run id is unique only within
    // a tenant), so an operator naming no tenant hits the 409 collision — the
    // ambiguity is a real cross-object condition now, not a forged control row.
    await seedAuthoritativeEvidence();
    await seedObjectEvidence(OTHER_TENANT, "other-tenant-object", "other-object-route");

    const ambiguous = await SELF.fetch(`${BASE}/admin/v1/agent-runs/${RUN_ID}`, {
      headers: bearer(operatorKey.secret),
    });
    expect(ambiguous.status, await ambiguous.clone().text()).toBe(409);
    const ambiguousBody = (await ambiguous.json()) as {
      error: { code: string };
    };
    expect(ambiguousBody.error.code).toBe("ambiguous_agent_run_id");

    const selected = await SELF.fetch(
      `${BASE}/admin/v1/agent-runs/${RUN_ID}?tenant_id=${encodeURIComponent(OTHER_TENANT)}`,
      { headers: bearer(operatorKey.secret) },
    );
    expect(selected.status, await selected.clone().text()).toBe(200);
    const selectedBody = (await selected.json()) as {
      data: Record<string, unknown>[];
    };
    expect(selectedBody.data).toEqual([
      expect.objectContaining({ id: "evidence-event-1", source: "other-tenant-object" }),
    ]);
    expect((selectedBody as Record<string, unknown>).source).toBeUndefined();
  });
});
