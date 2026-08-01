/**
 * THE TOOL-SIDE WORKFLOW CATALOG, against a REAL migrated control database.
 *
 * `test/workflow-tool-gate.test.ts` proves the ladder itself, seeded from the
 * `AGENT_WORKFLOWS` operator var. This file proves the OTHER source: the
 * `control_plane_resources` documents of kind `agent-workflows` that
 * `apps/control-plane`'s `admin_agent_workflow` group writes and
 * `apps/gateway`'s model-side gate already reads.
 *
 * Proving it here matters because of the failure mode this project keeps
 * finding: a durable table nothing reads. If the tool-side gate read only the
 * var, an operator who configured a workflow through the admin API would have
 * it enforced on the MODEL path and silently ignored on the TOOL path — one
 * graph, two answers.
 *
 * Everything goes through `SELF.fetch` into the real `src/worker.ts` with
 * `CONTROL_DB` bound and migrated and the `FG_DEV_*` bundle absent
 * (`harness/wrangler.toml`).
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { KEY_LIVE, bearer, errorCode, post, setupDurablePorts } from "./setup.js";

const AGENT_WORKFLOW_COLLECTION = "agent-workflows";

/** Written the way the admin group writes it: one document per resource id. */
const DOCUMENT = {
  id: "durable-wf",
  version: 1,
  enabled: true,
  tenant_id: "tenant-a",
  organization_ids: ["tenant-a"],
  project_ids: [],
  api_key_ids: [],
  nodes: [
    { id: "think", kind: "model" },
    { id: "run", kind: "tool", tool: "tool.echo" },
  ],
  edges: [{ from: "think", to: "run" }],
};

/** A second tenant's document. It must be invisible to `tenant-a`. */
const OTHER_TENANT_DOCUMENT = {
  id: "not-yours",
  version: 1,
  enabled: true,
  tenant_id: "tenant-elsewhere",
  organization_ids: ["tenant-elsewhere"],
  project_ids: [],
  api_key_ids: [],
  nodes: [{ id: "n", kind: "tool" }],
  edges: [],
};

beforeAll(async () => {
  await setupDurablePorts();
  const insert =
    "INSERT OR REPLACE INTO control_plane_resources (resource_kind, resource_id, document_json) " +
    "VALUES (?, ?, ?)";
  await env.CONTROL_DB.prepare(insert)
    .bind(AGENT_WORKFLOW_COLLECTION, DOCUMENT.id, JSON.stringify(DOCUMENT))
    .run();
  await env.CONTROL_DB.prepare(insert)
    .bind(
      AGENT_WORKFLOW_COLLECTION,
      OTHER_TENANT_DOCUMENT.id,
      JSON.stringify(OTHER_TENANT_DOCUMENT),
    )
    .run();
});

let seq = 0;
function runId(label: string): string {
  seq += 1;
  return `durable-wf-${label}-${seq}`;
}

function step(options: {
  readonly workflowId: string;
  readonly nodeId: string;
  readonly runId: string;
  readonly toolCalls?: readonly Record<string, unknown>[];
}): Promise<Response> {
  return post(
    "/v1/agent-runs",
    {
      ...bearer(KEY_LIVE),
      "x-ferrogate-workflow-id": options.workflowId,
      "x-ferrogate-workflow-node-id": options.nodeId,
      "x-ferrogate-agent-run-id": options.runId,
    },
    {
      input: "work",
      required_capabilities: ["coding"],
      ...(options.toolCalls === undefined ? {} : { tool_calls: options.toolCalls }),
    },
  );
}

describe("the D1 workflow catalog gates the tool path", () => {
  it("enforces a document the operator wrote through the admin table", async () => {
    // `run` has an incoming edge, so a fresh run may not open there. Nothing in
    // this harness sets `AGENT_WORKFLOWS`, so the ONLY way this refusal can
    // happen is that the document was read out of `CONTROL_DB`.
    const response = await step({
      workflowId: DOCUMENT.id,
      nodeId: "run",
      runId: runId("edge"),
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("workflow_edge_not_allowed");
  });

  it("enforces the node's tool pin from that same document", async () => {
    const response = await step({
      workflowId: DOCUMENT.id,
      nodeId: "run",
      runId: runId("pin"),
      toolCalls: [{ name: "tool.other" }],
    });
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("workflow_tool_not_allowed");
  });

  it("admits the entry node — the positive half", async () => {
    const response = await step({
      workflowId: DOCUMENT.id,
      nodeId: "think",
      runId: runId("entry"),
    });
    expect(response.status).toBe(202);
  });

  it("does not show one tenant another tenant's workflow", async () => {
    // `tenant_id` is the document's own fence, applied in the SQL. A caller in
    // `tenant-a` naming `not-yours` must get "no such workflow", not a refusal
    // that confirms it exists somewhere.
    const response = await step({
      workflowId: OTHER_TENANT_DOCUMENT.id,
      nodeId: "n",
      runId: runId("fence"),
    });
    expect(response.status).toBe(400);
    expect(await errorCode(response)).toBe("workflow_not_found");
  });
});
