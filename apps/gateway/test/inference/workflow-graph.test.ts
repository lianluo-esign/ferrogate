/**
 * THE WORKFLOW GRAPH GATE — `chat.rs::enforce_ai_workflow_policy`, all thirteen
 * refusals, driven through the real inference router.
 *
 * ## The defect this file exists to hold (cutover certification D2)
 *
 * `[[agent_workflows]]` was parsed and validated by `packages/config` and read
 * by NOTHING: `grep -rn "agent_workflows\|agentWorkflows" apps/` returned no
 * output. So node pinning, edge transitions, the iteration limit, the
 * model-call limit and the workflow timeout were all unenforced while the
 * config document was cheerfully accepted and echoed back. Thirteen Rust
 * refusal codes existed nowhere in this tree.
 *
 * Every `it` below was RED before `src/inference/workflow.ts` existed — each
 * one answered `200` and relayed a provider completion.
 *
 * ## The header contract, decided and pinned here
 *
 * Rust reads `x-ferrogate-workflow-{id,version,node-id,iteration}` and takes the
 * RUN identity from `x-ferrogate-agent-run-id`. The TypeScript budget-envelope
 * slice (`src/ratelimit/workflow.ts`) had invented
 * `x-ferrogate-workflow-run-id` and left `node-id` / `iteration` with no reader
 * at all. The Rust names win — see the long note in `src/inference/workflow.ts`
 * — and `describe("the header contract")` pins that choice so it cannot drift
 * back.
 */
import type {
  WorkflowGraph,
  WorkflowGraphNode,
  WorkflowNodeKind,
  WorkflowRunFacts,
} from "@ferrogate/policy";
import { describe, expect, it } from "vitest";
import type { InferenceDeps, WorkflowRunHistory } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const COMPLETION = {
  id: "chatcmpl-wf",
  object: "chat.completion",
  model: "gpt-4o-mini-2024-07-18",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
};

const WF_ID = "x-ferrogate-workflow-id";
const WF_VERSION = "x-ferrogate-workflow-version";
const WF_NODE = "x-ferrogate-workflow-node-id";
const WF_ITERATION = "x-ferrogate-workflow-iteration";
const AGENT_RUN = "x-ferrogate-agent-run-id";

/** A node literal with every optional member spelled out. */
function node(id: string, extra: Partial<WorkflowGraphNode> = {}): WorkflowGraphNode {
  return { id, kind: "model" as WorkflowNodeKind, providers: [], ...extra };
}

/** The graph every case starts from; `patch` narrows it per case. */
function workflow(patch: Partial<WorkflowGraph> = {}): WorkflowGraph {
  return {
    id: "wf_review",
    version: 3,
    enabled: true,
    organization_ids: [],
    project_ids: [],
    api_key_ids: [],
    nodes: [
      node("start"),
      node("review", { model: "gpt-4o-mini" }),
      node("notify", { kind: "tool", tool: "slack" }),
      node("pinned", { model: "claude-logical" }),
      node("anthropic-only", { providers: ["anthropic-main"] }),
    ],
    edges: [{ from: "start", to: "review" }],
    ...patch,
  };
}

interface Facts {
  previousSuccessfulNodeId?: string;
  runStartedAtUnix?: number;
  modelCallCount?: number;
  tokensUsed?: number;
  nodeTokensUsed?: number;
}

/** Build a harness whose workflow catalog is `graphs` and history is `facts`. */
function workflowHarness(
  graphs: readonly WorkflowGraph[],
  facts: Facts = {},
  nowUnixSeconds = 1_800_000_000,
): ReturnType<typeof harness> {
  const history: WorkflowRunHistory = {
    async factsFor(): Promise<WorkflowRunFacts> {
      return {
        ...(facts.previousSuccessfulNodeId === undefined
          ? {}
          : { previousSuccessfulNodeId: facts.previousSuccessfulNodeId }),
        ...(facts.runStartedAtUnix === undefined
          ? {}
          : { runStartedAtUnix: facts.runStartedAtUnix }),
        modelCallCount: facts.modelCallCount ?? 0,
        tokensUsed: facts.tokensUsed ?? 0,
        nodeTokensUsed: facts.nodeTokensUsed ?? 0,
      };
    },
    async recordStep(): Promise<void> {
      // The ledger's own write path is exercised by `workflow-ledger.test.ts`
      // against a real migrated D1; here the facts are injected directly so a
      // single refusal is one HTTP call and not a fixture of prior calls.
    },
  };
  const deps: InferenceDeps = {
    workflows: { forTenant: async () => graphs },
    workflowHistory: history,
    nowUnixSeconds: () => nowUnixSeconds,
  };
  return harness(deps);
}

/** POST a chat completion declaring a workflow step. */
async function step(
  h: ReturnType<typeof harness>,
  headers: Record<string, string>,
  model = "gpt-4o-mini",
): Promise<Response> {
  return await h.post(
    "/v1/chat/completions",
    { model, messages: [{ role: "user", content: "hi" }] },
    { headers },
  );
}

/** The happy-path headers: a legal `start` step of `wf_review@3`. */
const LEGAL: Record<string, string> = {
  [WF_ID]: "wf_review",
  [WF_VERSION]: "3",
  [WF_NODE]: "start",
  [AGENT_RUN]: "run_1",
};

describe("the workflow graph gate — thirteen Rust refusals", () => {
  it("400 workflow_not_found for an unknown workflow id", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        ...LEGAL,
        [WF_ID]: "wf_ghost",
      });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("workflow_not_found");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("400 workflow_not_found for a known id at an unknown VERSION", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_VERSION]: "9" });
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_not_found");
      expect(body.error.message).toBe("agent workflow wf_review@9 was not found");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_disabled", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow({ enabled: false })]), LEGAL);
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("workflow_disabled");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_not_allowed when the caller is outside api_key_ids", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow({ api_key_ids: ["key_other"] })]), LEGAL);
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("workflow_not_allowed");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("400 workflow_node_required when workflow-id is set and node-id is not", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        [WF_ID]: "wf_review",
        [WF_VERSION]: "3",
        [AGENT_RUN]: "run_1",
      });
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_node_required");
      expect(body.error.message).toBe(
        "x-ferrogate-workflow-node-id is required when x-ferrogate-workflow-id is set",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("400 workflow_node_not_found — THE UNPINNED NODE", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_NODE]: "ghost" });
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_node_not_found");
      expect(body.error.message).toBe("agent workflow wf_review@3 does not contain node ghost");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_node_not_model — a tool node may not dispatch model traffic", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_NODE]: "notify" });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("workflow_node_not_model");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_model_not_allowed — a node pinned to another model", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_NODE]: "pinned" });
      expect(res.status).toBe(403);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_model_not_allowed");
      expect(body.error.message).toBe(
        "workflow node pinned is not allowed to use model gpt-4o-mini",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_provider_not_allowed — no candidate route survives the node allowlist", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        ...LEGAL,
        [WF_NODE]: "anthropic-only",
      });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("workflow_provider_not_allowed");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_edge_not_allowed — THE ILLEGAL EDGE TRANSITION", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // The run's last successful node is `review`; `review -> start` is not a
      // configured edge, so the step may not run.
      const h = workflowHarness([workflow()], { previousSuccessfulNodeId: "review" });
      const res = await step(h, LEGAL);
      expect(res.status).toBe(403);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_edge_not_allowed");
      expect(body.error.message).toBe(
        "agent workflow wf_review@3 cannot transition from node review to node start",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("403 workflow_edge_not_allowed — a node with incoming edges cannot OPEN a run", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_NODE]: "review" });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.message).toBe(
        "agent workflow wf_review@3 node review has incoming edges and cannot start this run",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("429 workflow_model_call_limit_exceeded — THE MODEL-CALL LIMIT", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow({ max_model_calls: 2 })], { modelCallCount: 2 });
      const res = await step(h, LEGAL);
      expect(res.status).toBe(429);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_model_call_limit_exceeded");
      expect(body.error.message).toBe("agent workflow wf_review@3 model call limit is exhausted");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("429 workflow_iteration_limit_exceeded — THE ITERATION LIMIT", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow({ max_iterations: 4 })]);
      const res = await step(h, { ...LEGAL, [WF_ITERATION]: "5" });
      expect(res.status).toBe(429);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_iteration_limit_exceeded");
      expect(body.error.message).toBe(
        "agent workflow wf_review@3 iteration 5 exceeds configured limit",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("429 workflow_timeout_exceeded — THE WORKFLOW TIMEOUT", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // Started 120s ago against a 60_000ms timeout.
      const h = workflowHarness([workflow({ timeout_millis: 60_000 })], {
        runStartedAtUnix: 1_799_999_880,
      });
      const res = await step(h, LEGAL);
      expect(res.status).toBe(429);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_timeout_exceeded");
      expect(body.error.message).toBe(
        "agent workflow wf_review@3 elapsed time exceeded configured timeout",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("429 workflow_token_budget_exceeded at the GRAPH level", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow({ token_budget: 10 })], { tokensUsed: 10 });
      const res = await step(h, LEGAL);
      expect(res.status).toBe(429);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_token_budget_exceeded");
      expect(body.error.message).toBe(
        "agent workflow wf_review@3 token budget cannot cover the estimated request usage",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("429 workflow_token_budget_exceeded at the NODE level, with the node message", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const graph = workflow({
        nodes: [node("start", { token_budget: 5 }), node("review", { model: "gpt-4o-mini" })],
        edges: [{ from: "start", to: "review" }],
      });
      const h = workflowHarness([graph], { nodeTokensUsed: 5 });
      const res = await step(h, LEGAL);
      expect(res.status).toBe(429);
      const body = await errorBody(res);
      expect(body.error.code).toBe("workflow_token_budget_exceeded");
      expect(body.error.message).toBe(
        "workflow node start token budget cannot cover the estimated request usage",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });
});

describe("the workflow graph gate — what it must NOT refuse", () => {
  it("admits a legal step and dispatches it", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), LEGAL);
      expect(res.status).toBe(200);
      expect(provider.requests.length).toBe(1);
    } finally {
      provider.restore();
    }
  });

  it("admits a step that re-enters the SAME node", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow()], { previousSuccessfulNodeId: "start" });
      expect((await step(h, LEGAL)).status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("admits a configured transition (start -> review)", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow()], { previousSuccessfulNodeId: "start" });
      const res = await step(h, { ...LEGAL, [WF_NODE]: "review" });
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("leaves a request that declares NO workflow completely ungated", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // The catalog holds a disabled workflow; a request that names none of it
      // must still be served. The gate is opt-in by header, exactly as in Rust.
      const res = await step(workflowHarness([workflow({ enabled: false })]), {});
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("selects the HIGHEST version when no version header is sent", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // v3 has `start`; v4 does not, so picking v4 (the max) is observable.
      const v4 = workflow({ version: 4, nodes: [node("review", { model: "gpt-4o-mini" })] });
      const h = workflowHarness([workflow(), v4]);
      const res = await step(h, {
        [WF_ID]: "wf_review",
        [WF_NODE]: "start",
        [AGENT_RUN]: "run_1",
      });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.message).toBe(
        "agent workflow wf_review@4 does not contain node start",
      );
    } finally {
      provider.restore();
    }
  });
});

describe("the provider pin NARROWS dispatch, it does not merely refuse", () => {
  // Two routes serve one logical model. Without the intersection reaching the
  // candidate list, the node's pin would be satisfied by "some route survived"
  // and the request would still be served by the UNPINNED provider — which is
  // the whole control, not a detail.
  const PRIMARY = {
    logicalModel: "dual",
    provider: "openai-main",
    providerModel: "gpt-4o-mini-2024-07-18",
    providerKind: "openai",
    baseUrl: "https://primary.example/v1/",
    apiKey: "sk-primary",
    enabled: true,
    priority: 1,
  } as const;
  const SECONDARY = {
    logicalModel: "dual",
    provider: "openai-backup",
    providerModel: "gpt-4o-mini-2024-07-18",
    providerKind: "openai",
    baseUrl: "https://secondary.example/v1/",
    apiKey: "sk-secondary",
    enabled: true,
    priority: 2,
  } as const;

  it("dispatches to the PINNED provider even though the unpinned one is first", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const pinned = workflow({
        nodes: [node("start", { providers: ["openai-backup"] })],
        edges: [],
      });
      const h = harness(
        {
          workflows: { forTenant: async () => [pinned] },
          workflowHistory: {
            async factsFor() {
              return { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 };
            },
            async recordStep() {
              /* no ledger needed for this assertion */
            },
          },
        } satisfies InferenceDeps,
        [PRIMARY, SECONDARY],
      );
      const res = await h.post(
        "/v1/chat/completions",
        { model: "dual", messages: [{ role: "user", content: "hi" }] },
        { headers: LEGAL },
      );
      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toBe("https://secondary.example/v1/chat/completions");
    } finally {
      provider.restore();
    }
  });

  it("without the pin, the same catalog serves the FIRST route", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const open = workflow({ nodes: [node("start")], edges: [] });
      const h = harness(
        {
          workflows: { forTenant: async () => [open] },
          workflowHistory: {
            async factsFor() {
              return { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 };
            },
            async recordStep() {
              /* no ledger needed for this assertion */
            },
          },
        } satisfies InferenceDeps,
        [PRIMARY, SECONDARY],
      );
      const res = await h.post(
        "/v1/chat/completions",
        { model: "dual", messages: [{ role: "user", content: "hi" }] },
        { headers: LEGAL },
      );
      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toBe("https://primary.example/v1/chat/completions");
    } finally {
      provider.restore();
    }
  });
});

describe("the header contract", () => {
  it("reads the RUST header names — node-id and iteration have a reader", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // If `x-ferrogate-workflow-node-id` had no reader this would be
      // `workflow_node_required`; if `-iteration` had none it would be 200.
      const h = workflowHarness([workflow({ max_iterations: 1 })]);
      const res = await step(h, { ...LEGAL, [WF_ITERATION]: "2" });
      expect((await errorBody(res)).error.code).toBe("workflow_iteration_limit_exceeded");
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_workflow_header for a non-integer version", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_VERSION]: "three" });
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("invalid_workflow_header");
      expect(body.error.message).toBe("x-ferrogate-workflow-version must be an unsigned integer");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_workflow_header for a zero version (Rust rejects 0)", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_VERSION]: "0" });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.message).toBe(
        "x-ferrogate-workflow-version must be greater than zero",
      );
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_workflow_header when node-id/iteration/version arrive without workflow-id", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        [WF_NODE]: "start",
        [AGENT_RUN]: "run_1",
      });
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("invalid_workflow_header");
      expect(body.error.message).toBe(
        "x-ferrogate-workflow-id is required when workflow version, node, or iteration headers are set",
      );
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("an ABSENT run id opens its OWN run — `run-{requestId}`, never a shared bucket", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      // `requested_agent_run_id` defaults to `run-{request_id}`. Leaving it
      // undefined instead would put every un-correlated step of every caller
      // into ONE bucket, where an unrelated request's last node licenses a
      // transition. The run id the gate actually queried is captured here
      // because that bucketing is not otherwise observable from outside.
      const queried: string[] = [];
      const h = harness({
        workflows: { forTenant: async () => [workflow()] },
        workflowHistory: {
          async factsFor(query) {
            queried.push(query.runId);
            return { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 };
          },
          async recordStep(step) {
            queried.push(step.runId);
          },
        },
        requestIds: { next: () => "fg-deadbeefdeadbeef" },
      } satisfies InferenceDeps);
      const res = await h.post(
        "/v1/chat/completions",
        { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
        {
          headers: {
            [WF_ID]: "wf_review",
            [WF_VERSION]: "3",
            [WF_NODE]: "start",
          },
        },
      );
      expect(res.status).toBe(200);
      expect(queried.length).toBeGreaterThan(0);
      expect(new Set(queried)).toEqual(new Set(["run-fg-deadbeefdeadbeef"]));
    } finally {
      provider.restore();
    }
  });

  it("a SUPPLIED run id is used verbatim", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const queried: string[] = [];
      const h = harness({
        workflows: { forTenant: async () => [workflow()] },
        workflowHistory: {
          async factsFor(query) {
            queried.push(query.runId);
            return { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 };
          },
          async recordStep() {
            /* the id under test is the one `factsFor` was asked for */
          },
        },
      } satisfies InferenceDeps);
      await h.post(
        "/v1/chat/completions",
        { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
        { headers: LEGAL },
      );
      expect(queried).toEqual(["run_1"]);
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_agent_run_id_header for a malformed run id", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = workflowHarness([workflow()]);
      const spaces = await step(h, { ...LEGAL, [AGENT_RUN]: "not a run id" });
      expect(spaces.status).toBe(400);
      expect((await errorBody(spaces)).error.code).toBe("invalid_agent_run_id_header");

      const tooLong = await step(h, { ...LEGAL, [AGENT_RUN]: "r".repeat(129) });
      expect(tooLong.status).toBe(400);
      expect((await errorBody(tooLong)).error.code).toBe("invalid_agent_run_id_header");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_agent_run_id_header when the two run headers DISAGREE", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        ...LEGAL,
        [AGENT_RUN]: "run_a",
        "x-ferrogate-workflow-run-id": "run_b",
      });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("invalid_agent_run_id_header");
      expect(provider.requests.length).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("accepts the TypeScript-only run header as an ALIAS when it is the only one", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), {
        [WF_ID]: "wf_review",
        [WF_VERSION]: "3",
        [WF_NODE]: "start",
        "x-ferrogate-workflow-run-id": "run_ts",
      });
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("400 invalid_workflow_header for a blank workflow-id", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const res = await step(workflowHarness([workflow()]), { ...LEGAL, [WF_ID]: "   " });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("invalid_workflow_header");
    } finally {
      provider.restore();
    }
  });
});

describe("the gate applies to EVERY dispatched inference operation", () => {
  const cases: readonly [string, string, unknown][] = [
    ["/v1/chat/completions", "gpt-4o-mini", { messages: [{ role: "user", content: "hi" }] }],
    ["/v1/responses", "gpt-4o-mini", { input: "hi" }],
    [
      "/v1/messages",
      "claude-logical",
      { messages: [{ role: "user", content: "hi" }], max_tokens: 16 },
    ],
    ["/v1/embeddings", "text-embed", { input: "hi" }],
    ["/v1/images/generations", "image-model", { prompt: "a cat" }],
  ];

  for (const [path, model, extra] of cases) {
    it(`${path} refuses an unpinned node`, async () => {
      const provider = interceptProviderFetch(() => providerJson(COMPLETION));
      try {
        const h = workflowHarness([workflow()]);
        const res = await h.post(
          path,
          { model, ...(extra as Record<string, unknown>) },
          { headers: { ...LEGAL, [WF_NODE]: "ghost" } },
        );
        expect(res.status).toBe(400);
        expect((await errorBody(res)).error.code).toBe("workflow_node_not_found");
        expect(provider.requests.length).toBe(0);
      } finally {
        provider.restore();
      }
    });
  }
});
