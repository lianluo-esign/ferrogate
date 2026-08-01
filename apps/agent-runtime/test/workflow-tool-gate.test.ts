/**
 * THE TOOL-SIDE WORKFLOW GRAPH GATE, ON THE WORKER THAT OWNS `/v1/agent-runs`.
 *
 * ## The finding (cutover HOLD item A2, `cert2-dataplane` §2.1)
 *
 * > `$ grep -rn "workflow" apps/agent-runtime/src/`
 * > `(no output)`
 * >
 * > The Worker that owns `/v1/agent-runs` — the operation on which Rust enforces
 * > node kind, tool pinning, edge transition and parallelism — reads no workflow
 * > at all.
 *
 * Wave 17 ported the MODEL-side half into `apps/gateway/src/inference/
 * workflow.ts`. Rust runs a SECOND, different ladder on the run path
 * (`crates/ferrogate-gateway/src/server/agent_runs.rs::agent_workflow_use`,
 * line 547) whose refusals are about TOOLS, not models. That ladder had no
 * implementation anywhere in this tree.
 *
 * ## Why every assertion here drives `SELF`
 *
 * Wave 18 found the model-side gate had been CORRECT and UNREACHABLE for months
 * — an earlier middleware answered `400 invalid_workflow_declaration` before
 * the gate ever ran, and no suite saw it because every workflow test built its
 * own router. So nothing in this file constructs a Hono app, a middleware chain
 * or a decision function directly: every case is an HTTP request to the app
 * `src/worker.ts` exports, through the SAME `contractAuth` / correlation /
 * admission chain a real caller meets. A gate that is right and unreachable
 * fails this file exactly as loudly as one that is wrong.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  TENANT_B_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  getEnvVar,
  post,
  setEnvVar,
} from "./fixtures.js";

const WORKFLOW_ID_HEADER = "x-ferrogate-workflow-id";
const WORKFLOW_VERSION_HEADER = "x-ferrogate-workflow-version";
const WORKFLOW_NODE_ID_HEADER = "x-ferrogate-workflow-node-id";
const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";

/**
 * The operator catalog, seeded through the same var `resolveDeps` reads.
 *
 * `organization_ids` is matched against the caller's TENANT (this Worker's
 * `AuthContext.tenancy.tenantId` is Rust's `organization_id`) and `api_key_ids`
 * against its `subject` — see `src/runs/workflow.ts::workflowCallerFrom`.
 */
const WORKFLOWS = [
  {
    // The graph. `plan` is an entry node; `act` is reachable only FROM `plan`
    // and is pinned to one tool; `open` is a second entry with no tool pin.
    id: "wf",
    version: 1,
    enabled: true,
    organization_ids: ["tenant-a"],
    project_ids: [],
    api_key_ids: [],
    nodes: [
      { id: "plan", kind: "model" },
      { id: "act", kind: "tool", tool: "tool.echo" },
      { id: "open", kind: "tool" },
    ],
    edges: [{ from: "plan", to: "act" }],
    max_parallelism: 1,
    max_tool_calls: 2,
  },
  {
    id: "off",
    version: 1,
    enabled: false,
    organization_ids: ["tenant-a"],
    project_ids: [],
    api_key_ids: [],
    nodes: [{ id: "n", kind: "tool" }],
    edges: [],
  },
  {
    id: "elsewhere",
    version: 1,
    enabled: true,
    organization_ids: ["tenant-z"],
    project_ids: [],
    api_key_ids: [],
    nodes: [{ id: "n", kind: "tool" }],
    edges: [],
  },
  {
    // Parallelism wide open, so the per-request TOOL-CALL cap is what refuses.
    id: "wide",
    version: 1,
    enabled: true,
    organization_ids: ["tenant-a"],
    project_ids: [],
    api_key_ids: [],
    nodes: [{ id: "n", kind: "tool" }],
    edges: [],
    max_parallelism: 9,
    max_tool_calls: 2,
  },
  {
    id: "iter",
    version: 1,
    enabled: true,
    organization_ids: ["tenant-a"],
    project_ids: [],
    api_key_ids: [],
    nodes: [{ id: "n", kind: "tool" }],
    edges: [],
    max_parallelism: 9,
    max_iterations: 2,
  },
  {
    id: "clock",
    version: 1,
    enabled: true,
    organization_ids: ["tenant-a"],
    project_ids: [],
    api_key_ids: [],
    nodes: [{ id: "n", kind: "tool" }],
    edges: [],
    timeout_millis: 1_000,
  },
];

const ORIGINAL = getEnvVar("AGENT_WORKFLOWS");

beforeEach(async () => {
  setEnvVar("AGENT_WORKFLOWS", JSON.stringify(WORKFLOWS));
  await drainPlane(WORKER_A);
});

afterAll(() => {
  setEnvVar("AGENT_WORKFLOWS", ORIGINAL);
});

let seq = 0;
/** A run id no other case in this file can reach. */
function freshRunId(label: string): string {
  seq += 1;
  return `wfgate-${label}-${Date.now()}-${seq}`;
}

function step(options: {
  readonly workflowId?: string;
  readonly version?: string;
  readonly nodeId?: string;
  readonly runId?: string;
  readonly key?: string;
  readonly toolCalls?: readonly Record<string, unknown>[];
  readonly path?: string;
}): Promise<Response> {
  const headers: Record<string, string> = { ...bearer(options.key ?? TENANT_A_KEY) };
  if (options.workflowId !== undefined) headers[WORKFLOW_ID_HEADER] = options.workflowId;
  if (options.version !== undefined) headers[WORKFLOW_VERSION_HEADER] = options.version;
  if (options.nodeId !== undefined) headers[WORKFLOW_NODE_ID_HEADER] = options.nodeId;
  if (options.runId !== undefined) headers[AGENT_RUN_ID_HEADER] = options.runId;
  return post(options.path ?? "/v1/agent-runs", headers, {
    input: "work",
    required_capabilities: ["coding"],
    ...(options.toolCalls === undefined ? {} : { tool_calls: options.toolCalls }),
  });
}

async function code(response: Response): Promise<string> {
  return ((await response.json()) as { error: { code: string } }).error.code;
}

describe("the gate is opt-in, and reachable", () => {
  it("a request declaring no workflow is untouched", async () => {
    // The negative control. If this ever fails, the gate is refusing traffic it
    // has no business seeing, and every refusal below is worthless.
    const response = await step({ runId: freshRunId("nogate") });
    expect(response.status).toBe(202);
  });

  it("a declared workflow really reaches the ladder through SELF", async () => {
    const response = await step({
      workflowId: "nope",
      nodeId: "n",
      runId: freshRunId("reach"),
    });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("workflow_not_found");
  });
});

describe("the header contract", () => {
  it("400 invalid_workflow_header when the version is set without the id", async () => {
    const response = await step({ version: "1", nodeId: "n", runId: freshRunId("hdr1") });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_workflow_header");
  });

  it("400 invalid_workflow_header for a blank id header", async () => {
    const response = await step({ workflowId: "   ", nodeId: "n", runId: freshRunId("hdr2") });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_workflow_header");
  });

  it.each([
    ["not a number", "abc"],
    ["zero", "0"],
  ])("400 invalid_workflow_header when the version is %s", async (_label, version) => {
    const response = await step({
      workflowId: "wf",
      version,
      nodeId: "open",
      runId: freshRunId("hdr3"),
    });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_workflow_header");
  });
});

describe("the catalog ladder", () => {
  it("403 workflow_disabled for a switched-off workflow", async () => {
    const response = await step({ workflowId: "off", nodeId: "n", runId: freshRunId("off") });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_disabled");
  });

  it("403 workflow_not_allowed for a workflow this tenant is not entitled to", async () => {
    const response = await step({
      workflowId: "elsewhere",
      nodeId: "n",
      runId: freshRunId("ent"),
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_not_allowed");
  });

  it("400 workflow_node_required when the id is set without a node", async () => {
    const response = await step({ workflowId: "wf", runId: freshRunId("noderq") });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("workflow_node_required");
  });

  it("400 workflow_node_not_found for a node outside the graph", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "ghost",
      runId: freshRunId("ghost"),
    });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("workflow_node_not_found");
  });

  it("an unreadable catalog REFUSES a declared step rather than admitting it", async () => {
    // Failure direction. An empty/undecodable table must remove workflows, not
    // remove refusals: a step naming a workflow the runtime cannot see is an
    // error, never a licence. (A step naming NO workflow is still untouched —
    // that asymmetry is Rust's and is asserted above.)
    setEnvVar("AGENT_WORKFLOWS", "{ this is not json");
    const declared = await step({ workflowId: "wf", nodeId: "open", runId: freshRunId("blind") });
    expect(declared.status).toBe(400);
    expect(await code(declared)).toBe("workflow_not_found");

    const undeclared = await step({ runId: freshRunId("blind-plain") });
    expect(undeclared.status).toBe(202);
  });
});

describe("the TOOL half — the refusals that had no implementation at all", () => {
  it("403 workflow_node_not_tool when a non-tool node dispatches tool traffic", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "plan",
      runId: freshRunId("notatool"),
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_node_not_tool");
  });

  it("403 workflow_tool_not_allowed when a pinned node calls another tool", async () => {
    // Also pins the ORDER: `act` is unreachable from a fresh run (it has an
    // incoming edge), so an implementation that ran the edge check first would
    // answer `workflow_edge_not_allowed` here. Rust checks the tool pin first,
    // and which code a client sees is a wire contract.
    const response = await step({
      workflowId: "wf",
      nodeId: "act",
      runId: freshRunId("wrongtool"),
      toolCalls: [{ name: "tool.other" }],
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_tool_not_allowed");
  });

  it("a node with NO tool pin accepts any tool", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "open",
      runId: freshRunId("openok"),
      toolCalls: [{ name: "anything.at.all" }],
    });
    expect(response.status).toBe(202);
  });
});

describe("the EDGE half — a run cannot skip into the middle of its graph", () => {
  it("403 workflow_edge_not_allowed for a node with incoming edges on a fresh run", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "act",
      runId: freshRunId("skip"),
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_edge_not_allowed");
  });

  it("admits the same node once the run has actually reached its predecessor", async () => {
    // The positive half, and the one that makes the refusal above meaningful: a
    // gate that refused every transition would pass the test before this one
    // and be useless. It also proves the step ledger is WRITTEN and READ by the
    // same path — the "durable but nobody writes it" gap this repo keeps
    // finding.
    const runId = freshRunId("walk");
    const first = await step({ workflowId: "wf", nodeId: "plan", runId });
    expect(first.status).toBe(202);

    const second = await step({
      workflowId: "wf",
      nodeId: "act",
      runId,
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(second.status).toBe(200);
  });

  it("still refuses an illegal transition after a legal one", async () => {
    const runId = freshRunId("walkbad");
    expect((await step({ workflowId: "wf", nodeId: "plan", runId })).status).toBe(202);
    const jump = await step({ workflowId: "wf", nodeId: "open", runId });
    expect(jump.status).toBe(403);
    expect(await code(jump)).toBe("workflow_edge_not_allowed");
  });
});

describe("the COUNTER half", () => {
  it("429 workflow_parallelism_limit_exceeded when the step declares too many calls at once", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "open",
      runId: freshRunId("par"),
      toolCalls: [{ name: "a" }, { name: "b" }],
    });
    expect(response.status).toBe(429);
    expect(await code(response)).toBe("workflow_parallelism_limit_exceeded");
  });

  it("429 workflow_tool_call_limit_exceeded on the per-request cap", async () => {
    const response = await step({
      workflowId: "wide",
      nodeId: "n",
      runId: freshRunId("tcl"),
      toolCalls: [{ name: "a" }, { name: "b" }, { name: "c" }],
    });
    expect(response.status).toBe(429);
    expect(await code(response)).toBe("workflow_tool_call_limit_exceeded");
  });

  it("429 workflow_iteration_limit_exceeded — one turn per call, plus the final one", async () => {
    const response = await step({
      workflowId: "iter",
      nodeId: "n",
      runId: freshRunId("iterlim"),
      toolCalls: [{ name: "a" }, { name: "b" }],
    });
    expect(response.status).toBe(429);
    expect(await code(response)).toBe("workflow_iteration_limit_exceeded");
  });

  it("402 workflow_budget_exceeded on the RUN-SPANNING envelope", async () => {
    // The per-request cap bounds ONE request; the budget bounds the whole run.
    // Two steps that each pass the per-request cap must still be stopped once
    // their cumulative spend breaches the graph's envelope — without this, a
    // caller loops a legal step forever.
    const runId = freshRunId("budget");
    const first = await step({
      workflowId: "wide",
      nodeId: "n",
      runId,
      toolCalls: [{ name: "a" }, { name: "b" }],
    });
    expect(first.status).toBe(202);

    const second = await step({
      workflowId: "wide",
      nodeId: "n",
      runId,
      toolCalls: [{ name: "c" }],
    });
    expect(second.status).toBe(402);
    expect(await code(second)).toBe("workflow_budget_exceeded");
  });

  it("429 workflow_timeout_exceeded once the run outlives the graph's wall clock", async () => {
    const runId = freshRunId("clock");
    expect((await step({ workflowId: "clock", nodeId: "n", runId })).status).toBe(202);
    // Elapsed is whole SECONDS (Rust: `saturating_sub` then `* 1_000`), so a
    // 1 000 ms ceiling needs two ticks to be exceeded rather than reached.
    await new Promise((resolve) => setTimeout(resolve, 2_200));
    const late = await step({ workflowId: "clock", nodeId: "n", runId });
    expect(late.status).toBe(429);
    expect(await code(late)).toBe("workflow_timeout_exceeded");
  }, 20_000);
});

describe("a refused step changes nothing", () => {
  it("does not create the run it was refused for", async () => {
    const runId = freshRunId("noside");
    const refused = await step({
      workflowId: "wf",
      nodeId: "act",
      runId,
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(refused.status).toBe(403);
    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    expect(status.status).toBe(404);
  });
});

describe("the async twin cannot be used to walk around the gate", () => {
  it("POST /v1/agent-jobs is gated by the same ladder", async () => {
    // Rust only gates `/v1/agent-runs`, because `/v1/agent-jobs` (#474) was
    // added later and never got the ladder. Both routes reach the SAME create
    // path here, so leaving the twin ungated would make the gate a formality: a
    // caller refused at `act` would simply submit the identical work one URL
    // over. The gate is opt-in by header, so this costs an undeclared caller
    // nothing.
    const response = await step({
      path: "/v1/agent-jobs",
      workflowId: "wf",
      nodeId: "plan",
      runId: freshRunId("twin"),
      toolCalls: [{ name: "tool.echo" }],
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_node_not_tool");
  });
});

describe("cross-tenant", () => {
  it("tenant B cannot use tenant A's workflow", async () => {
    const response = await step({
      workflowId: "wf",
      nodeId: "open",
      runId: freshRunId("tenantb"),
      key: TENANT_B_KEY,
    });
    expect(response.status).toBe(403);
    expect(await code(response)).toBe("workflow_not_allowed");
  });
});
