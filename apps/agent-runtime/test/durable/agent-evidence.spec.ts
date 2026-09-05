import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { runStateStub } from "../../src/runs/addressing.js";
import { setupDurablePorts } from "./setup.js";

const TENANT_A = "tenant-evidence-a";
const TENANT_B = "tenant-evidence-b";
const RUN_ID = "run-evidence-authority";
const RETRY_TENANT = "tenant-evidence-retry";
const RETRY_RUN_ID = "run-evidence-retry";

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
    sessionId: `session-${runId}`,
    isolationGrant: {
      backend: "cloudflare_sandbox" as const,
      enableInternet: false as const,
      interceptHttps: true as const,
      allowedHosts: [] as const,
      snapshotSupported: false as const,
    },
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
    await Promise.all([
      run.create(createInput(TENANT_A, RUN_ID)),
      runB.create(createInput(TENANT_B, RUN_ID)),
    ]);
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
    const managedA = await objectA.query({
      tenantId: TENANT_A,
      sql:
        "SELECT i.id AS instance_id, s.id AS session_id, " +
        "e.id AS event_id, x.session_id AS selection_session_id, " +
        "p.session_id AS policy_session_id, w.id AS isolation_evidence_id " +
        "FROM agent_worker_instances i " +
        "LEFT JOIN managed_worker_sessions s ON s.session_json LIKE ? " +
        "LEFT JOIN managed_worker_lifecycle_events e ON e.id = ? " +
        "LEFT JOIN managed_worker_isolation_selections x ON x.session_id = s.id " +
        "LEFT JOIN managed_worker_isolation_policies p ON p.session_id = s.id " +
        "LEFT JOIN managed_worker_isolation_evidence w ON w.id = ? " +
        "WHERE i.id = ?",
      params: [
        `%${RUN_ID}%`,
        `${RUN_ID}-evt-000001`,
        `managed:session-${RUN_ID}:${RUN_ID}`,
        RUN_ID,
      ],
    });
    const runsB = await objectB.query({
      tenantId: TENANT_B,
      sql: "SELECT id FROM agent_runs WHERE id = ?",
      params: [RUN_ID],
    });

    expect(runsA.results).toHaveLength(1);
    expect(runsA.results[0]?.tenant).toBe(TENANT_A);
    expect(eventsA.results.map((row) => row.tenant)).toEqual([TENANT_A, TENANT_A, TENANT_A]);
    expect(eventsA.results.map((row) => row.id)).toEqual([
      `${RUN_ID}-evt-000001`,
      `${RUN_ID}-evt-000003`,
      `${RUN_ID}-evt-000002`,
    ]);
    expect(managedA.results).toEqual([
      {
        instance_id: RUN_ID,
        session_id: `session-${RUN_ID}`,
        event_id: `${RUN_ID}-evt-000001`,
        selection_session_id: `session-${RUN_ID}`,
        policy_session_id: `session-${RUN_ID}`,
        isolation_evidence_id: `managed:session-${RUN_ID}:${RUN_ID}`,
      },
    ]);
    expect(runsB.results).toHaveLength(1);
    const managedB = await objectB.query({
      tenantId: TENANT_B,
      sql: "SELECT id FROM agent_worker_instances WHERE id = ?",
      params: [RUN_ID],
    });
    expect(managedB.results).toEqual([{ id: RUN_ID }]);
    // Agent runs, run events, and managed isolation evidence are NO LONGER
    // mirrored to the control database — the per-tenant object is their sole
    // authority (agent family Track A: migration 0037 dropped the `agent_runs`
    // / `agent_run_events` control projections, 0041 dropped
    // `managed_worker_isolation_evidence`). This test's `TENANT_A` reuses the
    // same run/event ids as `TENANT_B`; the object-scoped reads above prove the
    // two never collide, which is the fence the removed control `projection_key`
    // once carried.
  });

  it("replays the stored run and events when authoritative rows need repair", async () => {
    const run = runStateStub(env, RETRY_TENANT, RETRY_RUN_ID);
    const object = tenantDataNamespace().get(tenantDataNamespace().idFromName(RETRY_TENANT));
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
