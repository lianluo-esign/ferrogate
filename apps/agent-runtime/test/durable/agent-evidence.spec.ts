import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { runStateStub } from "../../src/runs/addressing.js";
import { setupDurablePorts } from "./setup.js";

const TENANT_A = "tenant-evidence-a";
const TENANT_B = "tenant-evidence-b";
const RUN_ID = "run-evidence-authority";

function tenantDataNamespace(): NonNullable<typeof env.TENANT_DATA> {
  if (env.TENANT_DATA === undefined) throw new Error("TENANT_DATA binding is required");
  return env.TENANT_DATA;
}

beforeAll(async () => {
  await setupDurablePorts();
});
describe("agent evidence source of truth", () => {
  it("writes ordered evidence to one tenant object and ignores mirror mutations", async () => {
    const run = runStateStub(env, TENANT_A, RUN_ID);
    await run.create({
      runId: RUN_ID,
      tenantId: TENANT_A,
      workspaceId: "workspace-evidence",
      frameworkAdapter: "test",
      requiredCapabilities: [],
      workloadRef: null,
      idempotencyKey: "evidence-once",
      input: "hello",
      nowUnix: 100,
      requestId: "request-evidence",
      traceId: "trace-evidence",
      parentActionFingerprint: null,
      initialStatus: "queued",
    });
    await run.appendEvent(TENANT_A, {
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

    expect(runsA.results).toHaveLength(1);
    expect(runsA.results[0]?.tenant).toBe(TENANT_A);
    expect(eventsA.results.map((row) => row.tenant)).toEqual([
      TENANT_A,
      TENANT_A,
      TENANT_A,
    ]);
    expect(eventsA.results.map((row) => row.id)).toEqual([
      `${RUN_ID}-evt-000001`,
      `${RUN_ID}-evt-000003`,
      `${RUN_ID}-evt-000002`,
    ]);
    expect(runsB.results).toEqual([]);

    await env.CONTROL_DB.prepare("UPDATE agent_runs SET run_json = ? WHERE id = ?")
      .bind('{"tenant_id":"forged"}', RUN_ID)
      .run();
    const afterMirrorMutation = await objectA.query({
      tenantId: TENANT_A,
      sql: "SELECT run_json FROM agent_runs WHERE id = ?",
      params: [RUN_ID],
    });
    expect(JSON.parse(String(afterMirrorMutation.results[0]?.run_json)).tenant_id).toBe(TENANT_A);
  });
});
