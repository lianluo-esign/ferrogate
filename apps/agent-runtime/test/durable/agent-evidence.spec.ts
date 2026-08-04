import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { runStateStub } from "../../src/runs/addressing.js";
import { setupDurablePorts } from "./setup.js";

const TENANT_A = "tenant-evidence-a";
const TENANT_B = "tenant-evidence-b";
const RUN_ID = "run-evidence-authority";
const RETRY_TENANT = "tenant-evidence-retry";
const RETRY_RUN_ID = "run-evidence-retry";

function projectionKey(tenantId: string, logicalId: string): string {
  return `${tenantId.length}:${tenantId}:${logicalId}`;
}

function createInput(tenantId: string, runId: string) {
  return {
    runId,
    tenantId,
    workspaceId: "workspace-evidence",
    frameworkAdapter: "test",
    requiredCapabilities: [],
    workloadRef: null,
    idempotencyKey: `evidence-once-${tenantId}`,
    input: "hello",
    nowUnix: 100,
    requestId: "request-evidence",
    traceId: "trace-evidence",
    parentActionFingerprint: null,
    initialStatus: "queued" as const,
  };
}

function tenantDataNamespace(): NonNullable<typeof env.TENANT_DATA> {
  if (env.TENANT_DATA === undefined) throw new Error("TENANT_DATA binding is required");
  return env.TENANT_DATA;
}

beforeAll(async () => {
  await setupDurablePorts();
});
describe("agent evidence source of truth", () => {
  it("tenant-qualifies the control projection when tenants reuse run and event ids", async () => {
    const run = runStateStub(env, TENANT_A, RUN_ID);
    const runB = runStateStub(env, TENANT_B, RUN_ID);
    await Promise.all([run.create(createInput(TENANT_A, RUN_ID)), runB.create(createInput(TENANT_B, RUN_ID))]);
    await run.appendEvent(TENANT_A, {
      kind: "event.second",
      body: { value: 2 },
      nowUnix: 102,
      source: "control_plane",
      requestId: "request-evidence",
    });
    await runB.appendEvent(TENANT_B, {
      kind: "event.second",
      body: { value: 2 },
      nowUnix: 102,
      source: "control_plane",
      requestId: "request-evidence",
    });
    await run.appendEvent(TENANT_A, {
      kind: "event.first",
      body: { value: 1 },
      nowUnix: 101,
      source: "control_plane",
      requestId: "request-evidence",
    });

    const tenantData = tenantDataNamespace();
    const objectA = tenantData.get(tenantData.idFromName(TENANT_A));
    const objectB = tenantData.get(tenantData.idFromName(TENANT_B));
    const runsA = await objectA.query({
      tenantId: TENANT_A,
      sql: "SELECT id, tenant, run_json FROM agent_runs WHERE id = ?",
      params: [RUN_ID],
    });
    const eventsA = await objectA.query({
      tenantId: TENANT_A,
      sql: "SELECT id, tenant FROM agent_run_events WHERE run_id = ? ORDER BY occurred_at_unix, id",
      params: [RUN_ID],
    });
    const runsB = await objectB.query({
      tenantId: TENANT_B,
      sql: "SELECT id FROM agent_runs WHERE id = ?",
      params: [RUN_ID],
    });
    const controlRuns = await env.CONTROL_DB.prepare(
      "SELECT projection_key, id, tenant FROM agent_runs WHERE id = ? ORDER BY tenant",
    )
      .bind(RUN_ID)
      .all<{ projection_key: string; id: string; tenant: string }>();
    const controlEvents = await env.CONTROL_DB.prepare(
      "SELECT projection_key, id, tenant FROM agent_run_events " +
        "WHERE run_id = ? ORDER BY tenant, occurred_at_unix, id",
    )
      .bind(RUN_ID)
      .all<{ projection_key: string; id: string; tenant: string }>();

    expect(runsA.results).toHaveLength(1);
    expect(runsA.results[0]?.tenant).toBe(TENANT_A);
    expect(eventsA.results.map((row) => row.tenant)).toEqual([TENANT_A, TENANT_A, TENANT_A]);
    expect(eventsA.results.map((row) => row.id)).toEqual([
      `${RUN_ID}-evt-000001`,
      `${RUN_ID}-evt-000003`,
      `${RUN_ID}-evt-000002`,
    ]);
    expect(runsB.results).toHaveLength(1);
    expect(controlRuns.results).toEqual([
      { projection_key: projectionKey(TENANT_A, RUN_ID), id: RUN_ID, tenant: TENANT_A },
      { projection_key: projectionKey(TENANT_B, RUN_ID), id: RUN_ID, tenant: TENANT_B },
    ]);
    expect(controlEvents.results).toEqual([
      {
        projection_key: projectionKey(TENANT_A, `${RUN_ID}-evt-000001`),
        id: `${RUN_ID}-evt-000001`,
        tenant: TENANT_A,
      },
      {
        projection_key: projectionKey(TENANT_A, `${RUN_ID}-evt-000003`),
        id: `${RUN_ID}-evt-000003`,
        tenant: TENANT_A,
      },
      {
        projection_key: projectionKey(TENANT_A, `${RUN_ID}-evt-000002`),
        id: `${RUN_ID}-evt-000002`,
        tenant: TENANT_A,
      },
      {
        projection_key: projectionKey(TENANT_B, `${RUN_ID}-evt-000001`),
        id: `${RUN_ID}-evt-000001`,
        tenant: TENANT_B,
      },
      {
        projection_key: projectionKey(TENANT_B, `${RUN_ID}-evt-000002`),
        id: `${RUN_ID}-evt-000002`,
        tenant: TENANT_B,
      },
    ]);

    await env.CONTROL_DB.prepare("UPDATE agent_runs SET run_json = ? WHERE projection_key = ?")
      .bind('{"tenant_id":"forged"}', projectionKey(TENANT_A, RUN_ID))
      .run();
    const afterMirrorMutation = await objectA.query({
      tenantId: TENANT_A,
      sql: "SELECT run_json FROM agent_runs WHERE id = ?",
      params: [RUN_ID],
    });
    expect(JSON.parse(String(afterMirrorMutation.results[0]?.run_json)).tenant_id).toBe(TENANT_A);
  });

  it("replays the stored run and events when authoritative rows need repair", async () => {
    const run = runStateStub(env, RETRY_TENANT, RETRY_RUN_ID);
    const object = tenantDataNamespace().get(
      tenantDataNamespace().idFromName(RETRY_TENANT),
    );
    const input = createInput(RETRY_TENANT, RETRY_RUN_ID);

    await run.create(input);
    await run.appendEvent(RETRY_TENANT, {
      kind: "event.first-attempt",
      body: { attempt: 1 },
      nowUnix: 101,
      source: "control_plane",
      requestId: "request-evidence",
    });

    // Simulate an authoritative write that was lost after the run DO committed
    // its local state. The next idempotent create must replay the local run and
    // event rather than returning the existing row without repair.
    await object.query({
      tenantId: RETRY_TENANT,
      sql: "DELETE FROM agent_run_events",
    });
    await object.query({
      tenantId: RETRY_TENANT,
      sql: "DELETE FROM agent_runs",
    });
    const deduplicated = await run.create(input);
    expect(deduplicated.deduplicated).toBe(true);

    await run.appendEvent(RETRY_TENANT, {
      kind: "event.retry",
      body: { attempt: 2 },
      nowUnix: 102,
      source: "control_plane",
      requestId: "request-evidence",
    });

    const runs = await object.query({
      tenantId: RETRY_TENANT,
      sql: "SELECT id, tenant FROM agent_runs WHERE id = ?",
      params: [RETRY_RUN_ID],
    });
    const events = await object.query({
      tenantId: RETRY_TENANT,
      sql: "SELECT id, event_json FROM agent_run_events WHERE run_id = ? ORDER BY id",
      params: [RETRY_RUN_ID],
    });
    expect(runs.results).toEqual([{ id: RETRY_RUN_ID, tenant: RETRY_TENANT }]);
    expect(events.results.map((row) => row.id)).toEqual([
      `${RETRY_RUN_ID}-evt-000001`,
      `${RETRY_RUN_ID}-evt-000002`,
      `${RETRY_RUN_ID}-evt-000003`,
    ]);
    expect(events.results.map((row) => JSON.parse(String(row.event_json)).kind)).toEqual([
      "job_submitted",
      "event.first-attempt",
      "event.retry",
    ]);
  });
});
