/**
 * The pure workflow-graph gate — `chat.rs::enforce_ai_workflow_policy`.
 *
 * The gateway suite (`apps/gateway/test/inference/workflow-graph.test.ts`)
 * drives this through the real router and is what proves it is MOUNTED. This
 * file holds the decision boundary itself: the predicates the ladder is built
 * from, the ORDER of the ladder (which decides which code a client sees when a
 * request violates two rules at once), and the boundary values of every
 * comparison. None of those is observable through the router without a
 * combinatorial number of HTTP cases.
 */
import { describe, expect, it } from "vitest";
import {
  WORKFLOW_GRAPH_REFUSAL_CODES,
  WORKFLOW_GRAPH_REFUSAL_STATUS,
  type WorkflowGraph,
  type WorkflowGraphNode,
  type WorkflowRunFacts,
  applyWorkflowProviderConstraint,
  canUseWorkflow,
  enforceWorkflowGraphPolicy,
  selectAgentWorkflow,
  workflowEdgeTransitionError,
} from "../src/workflow-graph.js";

function node(id: string, extra: Partial<WorkflowGraphNode> = {}): WorkflowGraphNode {
  return { id, kind: "model", providers: [], ...extra };
}

function graph(patch: Partial<WorkflowGraph> = {}): WorkflowGraph {
  return {
    id: "wf",
    version: 2,
    enabled: true,
    organization_ids: [],
    project_ids: [],
    api_key_ids: [],
    nodes: [node("a"), node("b"), node("t", { kind: "tool" })],
    edges: [{ from: "a", to: "b" }],
    ...patch,
  };
}

const NO_FACTS: WorkflowRunFacts = { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 };

function decide(
  workflows: readonly WorkflowGraph[],
  request: Partial<Parameters<typeof enforceWorkflowGraphPolicy>[1]> = {},
  facts: WorkflowRunFacts = NO_FACTS,
): ReturnType<typeof enforceWorkflowGraphPolicy> {
  return enforceWorkflowGraphPolicy(
    workflows,
    {
      caller: {},
      workflowId: "wf",
      workflowNodeId: "a",
      logicalModel: "m",
      estimatedTotalTokens: 0,
      nowUnixSeconds: 1000,
      ...request,
    },
    facts,
  );
}

function code(decision: ReturnType<typeof enforceWorkflowGraphPolicy>): string {
  return decision.ok ? "<admitted>" : decision.rejection.code;
}

describe("the refusal taxonomy", () => {
  it("names exactly the thirteen Rust codes, each with its Rust status", () => {
    expect([...WORKFLOW_GRAPH_REFUSAL_CODES].sort()).toEqual(
      [
        "workflow_disabled",
        "workflow_edge_not_allowed",
        "workflow_iteration_limit_exceeded",
        "workflow_model_call_limit_exceeded",
        "workflow_model_not_allowed",
        "workflow_node_not_found",
        "workflow_node_not_model",
        "workflow_node_required",
        "workflow_not_allowed",
        "workflow_not_found",
        "workflow_provider_not_allowed",
        "workflow_timeout_exceeded",
        "workflow_token_budget_exceeded",
      ].sort(),
    );
    expect(WORKFLOW_GRAPH_REFUSAL_CODES).toHaveLength(13);
    expect(WORKFLOW_GRAPH_REFUSAL_STATUS).toEqual({
      workflow_not_found: 400,
      workflow_disabled: 403,
      workflow_not_allowed: 403,
      workflow_node_required: 400,
      workflow_node_not_found: 400,
      workflow_node_not_model: 403,
      workflow_model_not_allowed: 403,
      workflow_provider_not_allowed: 403,
      workflow_edge_not_allowed: 403,
      workflow_model_call_limit_exceeded: 429,
      workflow_iteration_limit_exceeded: 429,
      workflow_timeout_exceeded: 429,
      workflow_token_budget_exceeded: 429,
    });
  });
});

describe("selectAgentWorkflow", () => {
  const v1 = graph({ version: 1 });
  const v3 = graph({ version: 3 });

  it("takes the HIGHEST version when none is requested", () => {
    expect(selectAgentWorkflow([v1, v3], "wf")?.version).toBe(3);
    // Declaration order must not decide it.
    expect(selectAgentWorkflow([v3, v1], "wf")?.version).toBe(3);
  });

  it("takes the exact version when one is requested", () => {
    expect(selectAgentWorkflow([v1, v3], "wf", 1)?.version).toBe(1);
  });

  it("is undefined for an unknown id or an unknown version", () => {
    expect(selectAgentWorkflow([v1, v3], "other")).toBeUndefined();
    expect(selectAgentWorkflow([v1, v3], "wf", 2)).toBeUndefined();
  });
});

describe("canUseWorkflow", () => {
  it("an EMPTY allowlist gates nothing", () => {
    expect(canUseWorkflow({}, graph())).toBe(true);
  });

  it("a NON-EMPTY allowlist refuses a caller carrying no such facet", () => {
    expect(canUseWorkflow({}, graph({ api_key_ids: ["k"] }))).toBe(false);
    expect(canUseWorkflow({}, graph({ organization_ids: ["o"] }))).toBe(false);
    expect(canUseWorkflow({}, graph({ project_ids: ["p"] }))).toBe(false);
  });

  it("matches per facet, and ALL populated facets must match", () => {
    const restricted = graph({ api_key_ids: ["k"], organization_ids: ["o"] });
    expect(canUseWorkflow({ apiKeyId: "k", organizationId: "o" }, restricted)).toBe(true);
    expect(canUseWorkflow({ apiKeyId: "k", organizationId: "other" }, restricted)).toBe(false);
    expect(canUseWorkflow({ apiKeyId: "other", organizationId: "o" }, restricted)).toBe(false);
  });
});

describe("workflowEdgeTransitionError", () => {
  it("a workflow with NO edges never denies", () => {
    const open = graph({ edges: [] });
    expect(workflowEdgeTransitionError(open, "b", undefined)).toBeNull();
    expect(workflowEdgeTransitionError(open, "b", "a")).toBeNull();
  });

  it("with no previous node, only a node with NO incoming edges may open the run", () => {
    expect(workflowEdgeTransitionError(graph(), "a", undefined)).toBeNull();
    expect(workflowEdgeTransitionError(graph(), "b", undefined)).toBe(
      "agent workflow wf@2 node b has incoming edges and cannot start this run",
    );
  });

  it("with a previous node, only a configured edge or a re-entry is legal", () => {
    expect(workflowEdgeTransitionError(graph(), "b", "a")).toBeNull();
    expect(workflowEdgeTransitionError(graph(), "a", "a")).toBeNull();
    expect(workflowEdgeTransitionError(graph(), "a", "b")).toBe(
      "agent workflow wf@2 cannot transition from node b to node a",
    );
  });

  it("an edge is DIRECTED — a -> b does not license b -> a", () => {
    expect(workflowEdgeTransitionError(graph(), "b", "a")).toBeNull();
    expect(workflowEdgeTransitionError(graph(), "a", "b")).not.toBeNull();
  });
});

describe("the ladder's ORDER", () => {
  it("refuses a disabled workflow BEFORE the entitlement check", () => {
    // Both rules are violated; a caller must not be able to tell "not yours"
    // from "switched off".
    const both = graph({ enabled: false, api_key_ids: ["someone-else"] });
    expect(code(decide([both]))).toBe("workflow_disabled");
  });

  it("refuses an unknown node BEFORE any counter", () => {
    const capped = graph({ max_model_calls: 1, timeout_millis: 1 });
    expect(
      code(decide([capped], { workflowNodeId: "ghost" }, { ...NO_FACTS, modelCallCount: 99 })),
    ).toBe("workflow_node_not_found");
  });

  it("refuses an illegal EDGE before the model-call and iteration limits", () => {
    const capped = graph({ max_model_calls: 1, max_iterations: 1 });
    expect(
      code(
        decide(
          [capped],
          { workflowNodeId: "a", workflowIteration: 9 },
          { ...NO_FACTS, modelCallCount: 5, previousSuccessfulNodeId: "b" },
        ),
      ),
    ).toBe("workflow_edge_not_allowed");
  });

  it("refuses a missing node id before looking the node up", () => {
    expect(code(decide([graph()], { workflowNodeId: undefined }))).toBe("workflow_node_required");
  });
});

describe("boundary values", () => {
  it("max_model_calls is >=, so the Nth call is refused when N have been made", () => {
    const capped = graph({ max_model_calls: 3 });
    expect(code(decide([capped], {}, { ...NO_FACTS, modelCallCount: 2 }))).toBe("<admitted>");
    expect(code(decide([capped], {}, { ...NO_FACTS, modelCallCount: 3 }))).toBe(
      "workflow_model_call_limit_exceeded",
    );
  });

  it("max_iterations is >, so an iteration EQUAL to the limit is admitted", () => {
    const capped = graph({ max_iterations: 4 });
    expect(code(decide([capped], { workflowIteration: 4 }))).toBe("<admitted>");
    expect(code(decide([capped], { workflowIteration: 5 }))).toBe(
      "workflow_iteration_limit_exceeded",
    );
  });

  it("an ABSENT iteration header skips the iteration check entirely", () => {
    expect(code(decide([graph({ max_iterations: 1 })], { workflowIteration: undefined }))).toBe(
      "<admitted>",
    );
  });

  it("the graph's max_iterations OVERRIDES the node's (Rust `or`, not `min`)", () => {
    const wide = graph({
      max_iterations: 10,
      nodes: [node("a", { max_iterations: 1 }), node("b")],
    });
    expect(code(decide([wide], { workflowIteration: 5 }))).toBe("<admitted>");
    // With no graph-level cap, the node's applies.
    const narrow = graph({ nodes: [node("a", { max_iterations: 1 }), node("b")] });
    expect(code(decide([narrow], { workflowIteration: 5 }))).toBe(
      "workflow_iteration_limit_exceeded",
    );
  });

  it("the timeout is > , measured in whole seconds, and skipped with no run start", () => {
    const timed = graph({ timeout_millis: 60_000 });
    expect(code(decide([timed], { nowUnixSeconds: 1000 }, NO_FACTS))).toBe("<admitted>");
    expect(
      code(decide([timed], { nowUnixSeconds: 1060 }, { ...NO_FACTS, runStartedAtUnix: 1000 })),
    ).toBe("<admitted>");
    expect(
      code(decide([timed], { nowUnixSeconds: 1061 }, { ...NO_FACTS, runStartedAtUnix: 1000 })),
    ).toBe("workflow_timeout_exceeded");
  });

  it("a run that claims to start in the FUTURE is not instantly timed out", () => {
    // `saturating_sub`: clock skew between the ledger writer and this reader
    // must clamp to zero elapsed, never wrap to an enormous positive.
    const timed = graph({ timeout_millis: 1 });
    expect(
      code(decide([timed], { nowUnixSeconds: 1000 }, { ...NO_FACTS, runStartedAtUnix: 9999 })),
    ).toBe("<admitted>");
  });

  it("the token budget compares used + ESTIMATE against the cap", () => {
    const budgeted = graph({ token_budget: 100 });
    expect(
      code(decide([budgeted], { estimatedTotalTokens: 40 }, { ...NO_FACTS, tokensUsed: 60 })),
    ).toBe("<admitted>");
    expect(
      code(decide([budgeted], { estimatedTotalTokens: 41 }, { ...NO_FACTS, tokensUsed: 60 })),
    ).toBe("workflow_token_budget_exceeded");
  });

  it("the NODE token budget is a separate counter with its own message", () => {
    const budgeted = graph({ nodes: [node("a", { token_budget: 10 }), node("b")] });
    const denied = decide(
      [budgeted],
      { estimatedTotalTokens: 11 },
      { ...NO_FACTS, nodeTokensUsed: 0, tokensUsed: 1_000_000 },
    );
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.rejection.code).toBe("workflow_token_budget_exceeded");
      expect(denied.rejection.message).toBe(
        "workflow node a token budget cannot cover the estimated request usage",
      );
    }
  });
});

describe("node model pinning", () => {
  it("an UNPINNED node accepts any model", () => {
    expect(code(decide([graph()], { logicalModel: "anything" }))).toBe("<admitted>");
  });

  it("a pinned node accepts only its model", () => {
    const pinned = graph({ nodes: [node("a", { model: "gpt" }), node("b")] });
    expect(code(decide([pinned], { logicalModel: "gpt" }))).toBe("<admitted>");
    expect(code(decide([pinned], { logicalModel: "claude" }))).toBe("workflow_model_not_allowed");
  });

  it("a non-model node may not dispatch model traffic, whatever its other fields", () => {
    for (const kind of ["tool", "router", "human", "checkpoint"] as const) {
      const g = graph({ nodes: [node("a", { kind }), node("b")], edges: [] });
      expect(code(decide([g]))).toBe("workflow_node_not_model");
    }
  });
});

describe("the provider constraint", () => {
  const routes = [{ provider: "openai-us" }, { provider: "openai-eu" }];

  it("is null when the node names no providers, and leaves routes untouched", () => {
    const admitted = decide([graph()]);
    expect(admitted.ok).toBe(true);
    if (admitted.ok) {
      expect(admitted.constraint).toBeNull();
      const narrowed = applyWorkflowProviderConstraint(admitted.constraint, "m", routes);
      expect(narrowed.ok).toBe(true);
      if (narrowed.ok) expect(narrowed.routes).toEqual(routes);
    }
  });

  it("retains only the pinned providers", () => {
    const pinned = graph({ nodes: [node("a", { providers: ["openai-eu"] }), node("b")] });
    const admitted = decide([pinned]);
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.constraint).toEqual({ nodeId: "a", providers: ["openai-eu"] });
    const narrowed = applyWorkflowProviderConstraint(admitted.constraint, "m", routes);
    expect(narrowed.ok).toBe(true);
    if (narrowed.ok) expect(narrowed.routes).toEqual([{ provider: "openai-eu" }]);
  });

  it("refuses 403 workflow_provider_not_allowed when nothing survives", () => {
    const narrowed = applyWorkflowProviderConstraint(
      { nodeId: "a", providers: ["anthropic"] },
      "m",
      routes,
    );
    expect(narrowed.ok).toBe(false);
    if (!narrowed.ok) {
      expect(narrowed.rejection.status).toBe(403);
      expect(narrowed.rejection.code).toBe("workflow_provider_not_allowed");
      expect(narrowed.rejection.message).toBe(
        "workflow node a is not allowed to use any configured provider route for model m",
      );
    }
  });

  it("matches the provider ROW name, not a family prefix", () => {
    // `openai-us` must not satisfy a pin on `openai`: the whole point of naming
    // providers on a node is per-row selection.
    const narrowed = applyWorkflowProviderConstraint(
      { nodeId: "a", providers: ["openai"] },
      "m",
      routes,
    );
    expect(narrowed.ok).toBe(false);
  });
});

describe("what the gate must NOT do", () => {
  it("a request declaring no workflow is admitted with no constraint", () => {
    const decision = decide([graph()], { workflowId: undefined });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.constraint).toBeNull();
  });

  it("an EMPTY workflow table still refuses a declared workflow", () => {
    // The safe direction: naming a workflow the gateway cannot see is an error,
    // not a licence to run ungated.
    expect(code(decide([]))).toBe("workflow_not_found");
  });

  it("the not-found message distinguishes a versioned request from an unversioned one", () => {
    const unversioned = decide([], { workflowVersion: undefined });
    const versioned = decide([], { workflowVersion: 7 });
    expect(unversioned.ok).toBe(false);
    expect(versioned.ok).toBe(false);
    if (!unversioned.ok) {
      expect(unversioned.rejection.message).toBe("agent workflow wf was not found");
    }
    if (!versioned.ok) {
      expect(versioned.rejection.message).toBe("agent workflow wf@7 was not found");
    }
  });
});
