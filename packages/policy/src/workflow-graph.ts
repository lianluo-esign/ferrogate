/**
 * The workflow GRAPH gate — clean-room port of
 * `crates/ferrogate-gateway/src/server/chat.rs::enforce_ai_workflow_policy`
 * (line 3310), `apply_workflow_provider_constraint` (3501), `can_use_workflow`
 * (3559) and `crates/ferrogate-gateway/src/state.rs::select_agent_workflow`
 * (1998) + `state_agent_runtime.rs::workflow_edge_transition_error` (183).
 *
 * ## Why this lives in `@ferrogate/policy` and not in a Worker
 *
 * Every one of the thirteen refusals is a pure function of three things: the
 * `[[agent_workflows]]` document, the caller's identity, and four FACTS about
 * the run so far (its last successful node, when it started, how many model
 * calls it has made, how many tokens it has spent). Rust reads those four facts
 * off `AppState`'s repositories inside `async` helpers; this module takes them
 * as DATA ({@link WorkflowRunFacts}) so the decision is synchronous, total and
 * testable without a database — the same shape `workflow-budget.ts` already
 * uses for the execution-budget envelope, and the same reason.
 *
 * That split matters for a second reason. The gate has to run in more than one
 * place eventually (`apps/gateway`'s inference path today; `apps/agent-runtime`
 * when it grows a workflow surface), and the failure mode this repository keeps
 * hitting is two implementations of one predicate that drift. There is exactly
 * one implementation of the refusal ladder, and it is here.
 *
 * ## What is NOT here
 *
 * The run BUDGET envelope (`workflow_budget_exceeded`, the durable
 * `workflow_run_budgets` ledger) is a different control and lives in
 * `workflow-budget.ts`. The graph gate decides whether a step is a legal move
 * in the graph; the budget decides whether the run can afford it. Rust runs
 * both, and so does the gateway.
 *
 * ## Refusal table — codes and statuses are Rust's, verbatim
 *
 * | code | status | what it stops |
 * |---|---|---|
 * | `workflow_not_found` | 400 | a step naming an unknown workflow/version |
 * | `workflow_disabled` | 403 | a step in a disabled workflow |
 * | `workflow_not_allowed` | 403 | a key/tenant not entitled to the workflow |
 * | `workflow_node_required` | 400 | `workflow-id` without `workflow-node-id` |
 * | `workflow_node_not_found` | 400 | a node id not in the graph |
 * | `workflow_node_not_model` | 403 | a non-model node dispatching model traffic |
 * | `workflow_model_not_allowed` | 403 | a node calling a model it is not pinned to |
 * | `workflow_edge_not_allowed` | 403 | an illegal transition from the run's last node |
 * | `workflow_model_call_limit_exceeded` | 429 | `max_model_calls` |
 * | `workflow_iteration_limit_exceeded` | 429 | `max_iterations` |
 * | `workflow_timeout_exceeded` | 429 | the workflow wall clock |
 * | `workflow_token_budget_exceeded` | 429 | the graph's or the node's token budget |
 * | `workflow_provider_not_allowed` | 403 | a node calling an unpinned provider |
 *
 * The last one is produced by {@link applyWorkflowProviderConstraint} rather
 * than by the ladder, because Rust produces it there too: the ladder returns a
 * CONSTRAINT and the caller intersects it with the resolved candidate routes,
 * so the refusal can only be decided once routing has run.
 *
 * ## Ordering is load-bearing and is reproduced exactly
 *
 * A disabled workflow is refused before the entitlement check, so a caller
 * cannot distinguish "not yours" from "switched off"; the node checks run
 * before every counter, so a caller cannot burn a limit by naming a node that
 * was never going to be allowed; and the edge check runs before the
 * model-call/iteration/timeout/token counters, because an illegal transition is
 * a graph error and must not be reported as a quota error. Re-ordering any of
 * these changes which code a client sees, which is a wire contract.
 */

// ---------------------------------------------------------------------------
// The configuration document, structurally
// ---------------------------------------------------------------------------

/**
 * `ferrogate_config::AgentWorkflowNodeKind`.
 *
 * Declared as a string union rather than imported from `@ferrogate/config`
 * because `@ferrogate/policy` does not depend on that package (nor does the
 * Rust `ferrogate-policy` crate depend on `ferrogate-config`). The types below
 * are structural, so a `@ferrogate/config` `AgentWorkflowPolicy` is assignable
 * to {@link WorkflowGraph} with no adapter and no second parse.
 */
export type WorkflowNodeKind = "model" | "tool" | "router" | "human" | "checkpoint";

/** `ferrogate_config::AgentWorkflowNode`. */
export interface WorkflowGraphNode {
  readonly id: string;
  readonly kind: WorkflowNodeKind;
  /** When set, the ONLY logical model this node may dispatch. */
  readonly model?: string | undefined;
  /** When non-empty, the only provider names this node's routes may use. */
  readonly providers: readonly string[];
  readonly tool?: string | undefined;
  readonly max_iterations?: number | undefined;
  readonly token_budget?: number | undefined;
}

/** `ferrogate_config::AgentWorkflowEdge`. */
export interface WorkflowGraphEdge {
  readonly from: string;
  readonly to: string;
  readonly condition?: string | undefined;
}

/** `ferrogate_config::AgentWorkflowPolicy`. */
export interface WorkflowGraph {
  readonly id: string;
  readonly version: number;
  readonly enabled: boolean;
  readonly organization_ids: readonly string[];
  readonly project_ids: readonly string[];
  readonly api_key_ids: readonly string[];
  readonly nodes: readonly WorkflowGraphNode[];
  readonly edges: readonly WorkflowGraphEdge[];
  readonly max_model_calls?: number | undefined;
  readonly max_iterations?: number | undefined;
  readonly timeout_millis?: number | undefined;
  readonly token_budget?: number | undefined;
}

// ---------------------------------------------------------------------------
// Request-side inputs
// ---------------------------------------------------------------------------

/**
 * The slice of `auth::AuthContext` `can_use_workflow` reads.
 *
 * All three are OPTIONAL because Rust's are `Option<String>`, and the
 * distinction is load-bearing: a workflow that lists `api_key_ids` is refused
 * to a caller whose `api_key_id` is `None`, because `is_some_and` on a `None`
 * is `false`. A caller with no key id is not "everyone", it is "nobody".
 */
export interface WorkflowCaller {
  readonly apiKeyId?: string | undefined;
  readonly organizationId?: string | undefined;
  readonly projectId?: string | undefined;
}

/** `chat.rs::AiWorkflowRequestContext`. */
export interface WorkflowGraphRequest {
  readonly caller: WorkflowCaller;
  /** `x-ferrogate-workflow-id`; absent ⇒ not a workflow step, nothing is gated. */
  readonly workflowId?: string | undefined;
  /** `x-ferrogate-workflow-version`; absent ⇒ the highest configured version. */
  readonly workflowVersion?: number | undefined;
  /** `x-ferrogate-workflow-node-id`. */
  readonly workflowNodeId?: string | undefined;
  /** `x-ferrogate-workflow-iteration`. */
  readonly workflowIteration?: number | undefined;
  readonly logicalModel: string;
  /** `BillingTokenUsage.total_tokens` of the PRE-DISPATCH estimate. */
  readonly estimatedTotalTokens: number;
  readonly nowUnixSeconds: number;
}

/**
 * The four facts about the run that Rust reads from storage.
 *
 * Supplying them as data is what keeps {@link enforceWorkflowGraphPolicy} pure.
 * Each maps to one Rust helper:
 *
 * | field | Rust |
 * |---|---|
 * | `previousSuccessfulNodeId` | `workflow_run_last_successful_node_id` |
 * | `runStartedAtUnix` | `workflow_run_started_at` |
 * | `modelCallCount` | `workflow_model_call_count` |
 * | `tokensUsed` | `workflow_token_usage(.., None)` |
 * | `nodeTokensUsed` | `workflow_token_usage(.., Some(node_id))` |
 *
 * `undefined` means "the run has no such record yet", which is Rust's `None`
 * and is NOT the same as zero: an absent `runStartedAtUnix` skips the timeout
 * check entirely (Rust's `if let Some(started_at_unix)`), while a zero one
 * would make every request look infinitely old.
 */
export interface WorkflowRunFacts {
  readonly previousSuccessfulNodeId?: string | undefined;
  readonly runStartedAtUnix?: number | undefined;
  readonly modelCallCount: number;
  readonly tokensUsed: number;
  readonly nodeTokensUsed: number;
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/** `chat.rs::AiWorkflowRejection`. */
export interface WorkflowGraphRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/** `chat.rs::AiWorkflowProviderConstraint`. */
export interface WorkflowProviderConstraint {
  readonly nodeId: string;
  readonly providers: readonly string[];
}

/**
 * Every code this module can produce, with its status.
 *
 * Exported as a frozen table so a consumer can assert the taxonomy without
 * re-listing it (and so a cross-Worker consistency test can compare tables
 * rather than prose). It is the single source of the status for each code:
 * nothing below writes a numeric status literal.
 */
export const WORKFLOW_GRAPH_REFUSAL_STATUS: Readonly<Record<string, number>> = Object.freeze({
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

/** All thirteen codes, in the order the Rust ladder can emit them. */
export const WORKFLOW_GRAPH_REFUSAL_CODES: readonly string[] = Object.freeze([
  "workflow_not_found",
  "workflow_disabled",
  "workflow_not_allowed",
  "workflow_node_required",
  "workflow_node_not_found",
  "workflow_node_not_model",
  "workflow_model_not_allowed",
  "workflow_edge_not_allowed",
  "workflow_model_call_limit_exceeded",
  "workflow_iteration_limit_exceeded",
  "workflow_timeout_exceeded",
  "workflow_token_budget_exceeded",
  "workflow_provider_not_allowed",
]);

function refuse(code: string, message: string): WorkflowGraphRejection {
  const status = WORKFLOW_GRAPH_REFUSAL_STATUS[code];
  if (status === undefined) {
    // Unreachable: every `refuse` call site below uses a key of the table. A
    // throw rather than a default keeps a typo from becoming a 200.
    throw new Error(`workflow graph refusal ${code} has no status`);
  }
  return { status, code, message };
}

/** `Result<Option<AiWorkflowProviderConstraint>, AiWorkflowRejection>`. */
export type WorkflowGraphDecision =
  | { readonly ok: true; readonly constraint: WorkflowProviderConstraint | null }
  | { readonly ok: false; readonly rejection: WorkflowGraphRejection };

// ---------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------

/**
 * `state.rs::select_agent_workflow` — the rows with this id, narrowed by an
 * explicit version, then the HIGHEST version of what remains.
 *
 * The `max_by_key` is not an optimisation: with no version header, a
 * deployment that has published `wf@1` and `wf@2` must gate against `wf@2`.
 * Taking the first match instead would pin every caller to whichever row the
 * config happened to list first, which is a silent downgrade of the graph.
 */
export function selectAgentWorkflow(
  workflows: readonly WorkflowGraph[],
  id: string,
  version?: number | undefined,
): WorkflowGraph | undefined {
  let selected: WorkflowGraph | undefined;
  for (const workflow of workflows) {
    if (workflow.id !== id) continue;
    if (version !== undefined && workflow.version !== version) continue;
    if (selected === undefined || workflow.version > selected.version) selected = workflow;
  }
  return selected;
}

/**
 * `chat.rs::can_use_workflow` — three independent allowlists, each of which
 * gates only when NON-EMPTY.
 *
 * An empty list is "no restriction on this facet"; a non-empty one requires the
 * caller to carry a matching value, and a caller carrying none fails it. Both
 * halves of that are the failure direction that matters: reading an empty list
 * as "matches nothing" would lock every caller out of every workflow, and
 * reading an absent caller facet as "matches" would hand a keyless credential
 * every restricted workflow in the deployment.
 */
export function canUseWorkflow(caller: WorkflowCaller, workflow: WorkflowGraph): boolean {
  if (workflow.api_key_ids.length > 0) {
    const id = caller.apiKeyId;
    if (id === undefined || !workflow.api_key_ids.includes(id)) return false;
  }
  if (workflow.organization_ids.length > 0) {
    const id = caller.organizationId;
    if (id === undefined || !workflow.organization_ids.includes(id)) return false;
  }
  if (workflow.project_ids.length > 0) {
    const id = caller.projectId;
    if (id === undefined || !workflow.project_ids.includes(id)) return false;
  }
  return true;
}

/**
 * `state_agent_runtime.rs::workflow_edge_transition_error` — the message, or
 * `null` when the transition is legal.
 *
 * Three rules, in Rust's order:
 *
 *  1. **A workflow with no edges never denies a transition.** The edge list is
 *     what makes a workflow a graph; without one it is a flat set of nodes and
 *     there is no ordering to enforce.
 *  2. **With a previous successful node**, the step is legal iff it re-enters
 *     the SAME node (a retry / a loop iteration) or a configured edge runs from
 *     the previous node to it.
 *  3. **With no previous node** (the run is opening), the step is legal only if
 *     the node has NO incoming edges — i.e. it is an entry point of the graph.
 *     Rule 3 is the one that stops a caller skipping straight to a late node by
 *     inventing a fresh run id.
 */
export function workflowEdgeTransitionError(
  workflow: WorkflowGraph,
  nodeId: string,
  previousSuccessfulNodeId?: string | undefined,
): string | null {
  if (workflow.edges.length === 0) return null;
  if (previousSuccessfulNodeId !== undefined) {
    if (previousSuccessfulNodeId === nodeId) return null;
    for (const edge of workflow.edges) {
      if (edge.from === previousSuccessfulNodeId && edge.to === nodeId) return null;
    }
    return (
      `agent workflow ${workflow.id}@${workflow.version} cannot transition from node ` +
      `${previousSuccessfulNodeId} to node ${nodeId}`
    );
  }
  for (const edge of workflow.edges) {
    if (edge.to === nodeId) {
      return (
        `agent workflow ${workflow.id}@${workflow.version} node ${nodeId} has incoming ` +
        "edges and cannot start this run"
      );
    }
  }
  return null;
}

/**
 * The names of the two headers the refusal messages quote.
 *
 * They are constants here — not in the Worker — because
 * `workflow_node_required`'s MESSAGE names both of them, and a message that
 * disagreed with the header the gateway actually reads would send an operator
 * to the wrong knob.
 */
export const WORKFLOW_ID_HEADER_NAME = "x-ferrogate-workflow-id";
export const WORKFLOW_NODE_ID_HEADER_NAME = "x-ferrogate-workflow-node-id";

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

/**
 * `chat.rs::enforce_ai_workflow_policy`, in full.
 *
 * Returns `{ ok: true, constraint: null }` for a request that declares no
 * workflow — the gate is opt-in by header, exactly as in Rust, so an ordinary
 * inference request is untouched.
 */
export function enforceWorkflowGraphPolicy(
  workflows: readonly WorkflowGraph[],
  request: WorkflowGraphRequest,
  facts: WorkflowRunFacts,
): WorkflowGraphDecision {
  const workflowId = request.workflowId;
  if (workflowId === undefined) return { ok: true, constraint: null };

  const workflow = selectAgentWorkflow(workflows, workflowId, request.workflowVersion);
  if (workflow === undefined) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_not_found",
        request.workflowVersion === undefined
          ? `agent workflow ${workflowId} was not found`
          : `agent workflow ${workflowId}@${request.workflowVersion} was not found`,
      ),
    };
  }

  if (!workflow.enabled) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_disabled",
        `agent workflow ${workflow.id}@${workflow.version} is disabled`,
      ),
    };
  }

  if (!canUseWorkflow(request.caller, workflow)) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_not_allowed",
        `API key or tenant is not allowed to use agent workflow ${workflow.id}@${workflow.version}`,
      ),
    };
  }

  const nodeId = request.workflowNodeId;
  if (nodeId === undefined) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_node_required",
        `${WORKFLOW_NODE_ID_HEADER_NAME} is required when ${WORKFLOW_ID_HEADER_NAME} is set`,
      ),
    };
  }

  const node = workflow.nodes.find((candidate) => candidate.id === nodeId);
  if (node === undefined) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_node_not_found",
        `agent workflow ${workflow.id}@${workflow.version} does not contain node ${nodeId}`,
      ),
    };
  }

  if (node.kind !== "model") {
    return {
      ok: false,
      rejection: refuse(
        "workflow_node_not_model",
        `workflow node ${nodeId} is not allowed to dispatch model traffic`,
      ),
    };
  }

  // `node.model.as_deref().is_some_and(|model| model != request.logical_model)`
  // — a node with NO pinned model accepts any model the caller is otherwise
  // allowed to use. Only a pin that disagrees refuses.
  if (node.model !== undefined && node.model !== request.logicalModel) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_model_not_allowed",
        `workflow node ${nodeId} is not allowed to use model ${request.logicalModel}`,
      ),
    };
  }

  const edgeError = workflowEdgeTransitionError(
    workflow,
    nodeId,
    facts.previousSuccessfulNodeId,
  );
  if (edgeError !== null) {
    return { ok: false, rejection: refuse("workflow_edge_not_allowed", edgeError) };
  }

  // `>=`, not `>`: the limit counts calls ALREADY made, so a workflow capped at
  // N refuses the (N+1)th. Using `>` would let N+1 through.
  if (workflow.max_model_calls !== undefined && facts.modelCallCount >= workflow.max_model_calls) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_model_call_limit_exceeded",
        `agent workflow ${workflow.id}@${workflow.version} model call limit is exhausted`,
      ),
    };
  }

  if (request.workflowIteration !== undefined) {
    // `workflow.max_iterations.or(node.max_iterations)` — the GRAPH's cap wins
    // when it is set, and the node's is consulted only when the graph declares
    // none. This is `or`, not `min`; reproducing it exactly matters because a
    // graph that deliberately widens a node's cap would otherwise stay narrow.
    const limit = workflow.max_iterations ?? node.max_iterations;
    if (limit !== undefined && request.workflowIteration > limit) {
      return {
        ok: false,
        rejection: refuse(
          "workflow_iteration_limit_exceeded",
          `agent workflow ${workflow.id}@${workflow.version} iteration ` +
            `${request.workflowIteration} exceeds configured limit`,
        ),
      };
    }
  }

  if (workflow.timeout_millis !== undefined && facts.runStartedAtUnix !== undefined) {
    // `saturating_sub` then `saturating_mul(1_000)`: a run whose recorded start
    // is in the FUTURE (clock skew between the writer and this reader) yields 0
    // elapsed, never a negative that would wrap to an enormous positive.
    const elapsedSeconds = Math.max(0, request.nowUnixSeconds - facts.runStartedAtUnix);
    if (elapsedSeconds * 1000 > workflow.timeout_millis) {
      return {
        ok: false,
        rejection: refuse(
          "workflow_timeout_exceeded",
          `agent workflow ${workflow.id}@${workflow.version} elapsed time exceeded configured timeout`,
        ),
      };
    }
  }

  if (
    workflow.token_budget !== undefined &&
    facts.tokensUsed + request.estimatedTotalTokens > workflow.token_budget
  ) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_token_budget_exceeded",
        `agent workflow ${workflow.id}@${workflow.version} token budget cannot cover the ` +
          "estimated request usage",
      ),
    };
  }

  // The SAME code with a different message — Rust does this deliberately, so a
  // client cannot tell the graph budget from the node budget while an operator
  // reading the message can.
  if (
    node.token_budget !== undefined &&
    facts.nodeTokensUsed + request.estimatedTotalTokens > node.token_budget
  ) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_token_budget_exceeded",
        `workflow node ${nodeId} token budget cannot cover the estimated request usage`,
      ),
    };
  }

  return {
    ok: true,
    constraint:
      node.providers.length === 0
        ? null
        : { nodeId: node.id, providers: [...node.providers] },
  };
}

/** A candidate route, as far as the provider constraint is concerned. */
export interface WorkflowConstrainedRoute {
  readonly provider: string;
}

/** `Result<(), AiWorkflowRejection>` with the surviving routes on success. */
export type WorkflowProviderNarrowing<R extends WorkflowConstrainedRoute> =
  | { readonly ok: true; readonly routes: readonly R[] }
  | { readonly ok: false; readonly rejection: WorkflowGraphRejection };

/**
 * `chat.rs::apply_workflow_provider_constraint` — retain only the routes whose
 * `provider` the node pins, and refuse when nothing survives.
 *
 * The comparison is against `ModelRoute.provider`, the PROVIDER-TABLE key, not
 * the provider FAMILY: a deployment with `openai-us` and `openai-eu` rows is
 * pinned per row, which is the entire point of naming providers on a node.
 *
 * Returns a new array rather than mutating (Rust takes `&mut Vec`); the caller
 * substitutes it for the candidate list, so the narrowing reaches dispatch.
 */
export function applyWorkflowProviderConstraint<R extends WorkflowConstrainedRoute>(
  constraint: WorkflowProviderConstraint | null,
  logicalModel: string,
  routes: readonly R[],
): WorkflowProviderNarrowing<R> {
  if (constraint === null) return { ok: true, routes };
  const retained = routes.filter((route) => constraint.providers.includes(route.provider));
  if (retained.length === 0) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_provider_not_allowed",
        `workflow node ${constraint.nodeId} is not allowed to use any configured provider ` +
          `route for model ${logicalModel}`,
      ),
    };
  }
  return { ok: true, routes: retained };
}
