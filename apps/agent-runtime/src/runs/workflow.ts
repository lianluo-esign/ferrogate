/**
 * THE TOOL-SIDE WORKFLOW GRAPH GATE — clean-room port of
 * `crates/ferrogate-gateway/src/server/agent_runs.rs::agent_workflow_use`
 * (line 547) and `workflow_node_tool_denial` (line 868).
 *
 * ## Why this file exists
 *
 * The wave-19 cutover certification (HOLD item A2, `cert2-dataplane` §2.1)
 * recorded that `grep -rn "workflow" apps/agent-runtime/src/` returned NOTHING:
 * the Worker that owns `POST /v1/agent-runs` — the one operation on which the
 * reference gateway enforces node kind, tool pinning, edge transition,
 * parallelism, tool-call and iteration limits, the graph wall clock and the
 * run-spanning execution budget — read no workflow at all. Wave 17 had ported
 * the MODEL-side ladder (`chat.rs::enforce_ai_workflow_policy`) into
 * `apps/gateway/src/inference/workflow.ts`; this is the OTHER ladder, and it is
 * a different function in Rust with a different refusal set.
 *
 * ## What is shared with the model-side gate, and what is not
 *
 * Three predicates are IDENTICAL in the reference and are imported from
 * `@ferrogate/policy` rather than reimplemented — `selectAgentWorkflow`,
 * `canUseWorkflow` and `workflowEdgeTransitionError`. The repository's standing
 * failure mode is two implementations of one predicate that drift, and the
 * edge rule in particular ("a run with no previous node may only open at a node
 * with no incoming edges") is the one that stops a caller skipping into the
 * middle of a graph by inventing a fresh run id. There is one copy of it.
 *
 * What is NOT shared is the ladder itself, because Rust's two ladders genuinely
 * differ:
 *
 * | | model side (`chat.rs`) | tool side (this file) |
 * |---|---|---|
 * | node kind | must be `model`, always | must be `tool`, **only when the step declares tool calls** |
 * | node pin | `node.model` vs the logical model | `node.tool` vs every declared call |
 * | counters | `max_model_calls`, `max_iterations` vs the ITERATION header | `max_parallelism`, `max_tool_calls`, `max_iterations` vs `tool_calls.len() + 1` |
 * | budget | token estimate vs `token_budget` | the durable run envelope, DEBITED here |
 * | version header | optional | optional |
 *
 * The asymmetry on node kind is Rust's and is load-bearing: a step that
 * declares NO tool calls is a plain turn, and a `model`/`router`/`checkpoint`
 * node is allowed to make it. Requiring `kind === "tool"` unconditionally would
 * refuse every legal opening step of every graph.
 *
 * ## Ordering is a wire contract
 *
 * Rust's order, reproduced exactly, and the reason for the two that are easy to
 * get wrong:
 *
 *   header shape → not_found → disabled → not_allowed → node_required →
 *   node_not_found → **node_not_tool → tool_not_allowed** → edge →
 *   parallelism → tool_call_limit → iteration → timeout → budget
 *
 *  * the TOOL checks come BEFORE the edge check, so a node that is both
 *    unreachable and mis-pinned reports the pin. `test/workflow-tool-gate.test.ts`
 *    pins that with a case that would answer `workflow_edge_not_allowed` under
 *    the other order.
 *  * `disabled` comes before `not_allowed`, so a caller cannot distinguish "not
 *    yours" from "switched off" and use the gate as a catalog oracle.
 *
 * ## The budget is the OTHER half of a marker this closes
 *
 * `packages/policy/src/workflow-budget.ts` carries a PORT-TODO naming this
 * slice by name: *"`cost` and `tool_calls` … the authority for them is the
 * atomic `debitWorkflowRunBudget`. Nothing calls that debit yet. The owner is
 * whoever settles a step — `apps/agent-runtime`'s run-step path, whose Rust
 * counterpart is `crates/ferrogate-gateway/src/server/agent_runs.rs`."* The
 * debit now happens, in {@link AgentRunState.admitWorkflowStep}, inside the
 * run's own Durable Object — single-threaded, so the check and the debit cannot
 * race the way a split check-then-act would.
 */
import {
  type WorkflowBudgetCaps,
  type WorkflowCaller,
  type WorkflowGraph,
  type WorkflowGraphNode,
  type WorkflowNodeKind,
  canUseWorkflow,
  resolveWorkflowBudgetEnvelope,
  selectAgentWorkflow,
  workflowEdgeTransitionError,
} from "@ferrogate/policy";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { controlDatabaseFrom } from "../control-data.js";

// ---------------------------------------------------------------------------
// Headers — Rust's names, verbatim (`agent_runs.rs:45-47`)
// ---------------------------------------------------------------------------

export const WORKFLOW_ID_HEADER = "x-ferrogate-workflow-id";
export const WORKFLOW_VERSION_HEADER = "x-ferrogate-workflow-version";
export const WORKFLOW_NODE_ID_HEADER = "x-ferrogate-workflow-node-id";

/** `agent_workflow_use` answers this for every malformed workflow header. */
export const INVALID_WORKFLOW_HEADER_CODE = "invalid_workflow_header";

/**
 * The tool-side refusal taxonomy, as a frozen code → status table.
 *
 * Exported so a consumer can assert the taxonomy without re-listing it, and so
 * nothing below writes a bare numeric status: a typo in a code becomes a throw
 * in {@link refuse} rather than a 200.
 */
export const WORKFLOW_TOOL_REFUSAL_STATUS: Readonly<Record<string, number>> = Object.freeze({
  invalid_workflow_header: 400,
  workflow_not_found: 400,
  workflow_disabled: 403,
  workflow_not_allowed: 403,
  workflow_node_required: 400,
  workflow_node_not_found: 400,
  workflow_node_not_tool: 403,
  workflow_tool_not_allowed: 403,
  workflow_edge_not_allowed: 403,
  workflow_parallelism_limit_exceeded: 429,
  workflow_tool_call_limit_exceeded: 429,
  workflow_iteration_limit_exceeded: 429,
  workflow_timeout_exceeded: 429,
  // Rust `StatusCode::PAYMENT_REQUIRED` — the run-spanning envelope, not a
  // rate limit. A 429 here would tell a client to retry something that can
  // never succeed until the budget is topped up.
  workflow_budget_exceeded: 402,
});

/** Every code this gate can produce, in the order the ladder can emit them. */
export const WORKFLOW_TOOL_REFUSAL_CODES: readonly string[] = Object.freeze([
  "invalid_workflow_header",
  "workflow_not_found",
  "workflow_disabled",
  "workflow_not_allowed",
  "workflow_node_required",
  "workflow_node_not_found",
  "workflow_node_not_tool",
  "workflow_tool_not_allowed",
  "workflow_edge_not_allowed",
  "workflow_parallelism_limit_exceeded",
  "workflow_tool_call_limit_exceeded",
  "workflow_iteration_limit_exceeded",
  "workflow_timeout_exceeded",
  "workflow_budget_exceeded",
]);

/** A refusal, rendered verbatim by the route. */
export interface WorkflowToolRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

function refuse(code: string, message: string): WorkflowToolRejection {
  const status = WORKFLOW_TOOL_REFUSAL_STATUS[code];
  if (status === undefined) {
    throw new Error(`workflow tool refusal ${code} has no status`);
  }
  return { status, code, message };
}

// ---------------------------------------------------------------------------
// The document — `WorkflowGraph` plus the two caps only the tool side reads
// ---------------------------------------------------------------------------

/**
 * `ferrogate_config::AgentWorkflowPolicy`, including the two fields the
 * model-side type has no use for.
 *
 * `max_tool_calls` and `max_parallelism` are real members of the Rust struct
 * (`ferrogate-config/src/config/types.rs:1731-1733`); `@ferrogate/policy`'s
 * {@link WorkflowGraph} omits them because `enforce_ai_workflow_policy` never
 * reads them. Declaring them structurally here keeps a config document
 * assignable to BOTH without an adapter and without a second parse.
 */
export interface ToolWorkflowGraph extends WorkflowGraph {
  readonly max_tool_calls?: number | undefined;
  readonly max_parallelism?: number | undefined;
}

// ---------------------------------------------------------------------------
// Header parsing — `requested_optional_id_header` / `requested_optional_u32_header`
// ---------------------------------------------------------------------------

export type WorkflowDeclaration =
  | { readonly kind: "absent" }
  | {
      readonly kind: "declared";
      readonly workflowId: string;
      readonly workflowVersion: number | undefined;
      readonly workflowNodeId: string | undefined;
    }
  | { readonly kind: "invalid"; readonly detail: string };

/** Rust's charset and length rule for every workflow id header. */
const ID_HEADER_CHARSET = /^[A-Za-z0-9_.:-]+$/;
const ID_HEADER_MAX_LENGTH = 128;

/**
 * `requested_optional_id_header`.
 *
 * `undefined` = absent. `null` = present but unusable — Rust treats a BLANK
 * header as absent (`if value.is_empty() { return Ok(None) }`) but refuses one
 * that is too long or carries a character outside the set, so the two cases are
 * distinguished by the caller rather than collapsed here.
 */
function optionalIdHeader(
  headers: Headers,
  name: string,
): { ok: true; value: string | undefined } | { ok: false; detail: string } {
  const raw = headers.get(name);
  if (raw === null) return { ok: true, value: undefined };
  const trimmed = raw.trim();
  // Rust reads a blank header as ABSENT for the version/node headers. This gate
  // refuses a blank WORKFLOW ID instead, and the difference is deliberate:
  // treating `x-ferrogate-workflow-id: ""` as "no workflow" silently ungates a
  // client that believes it declared one, which is the loudest possible form of
  // a gate that does not run. See `workflowHeadersFrom`.
  if (trimmed === "") return { ok: true, value: undefined };
  if (trimmed.length > ID_HEADER_MAX_LENGTH) {
    return { ok: false, detail: `${name} must be at most ${ID_HEADER_MAX_LENGTH} characters` };
  }
  if (!ID_HEADER_CHARSET.test(trimmed)) {
    return { ok: false, detail: `${name} may only contain letters, numbers, _, -, ., or :` };
  }
  return { ok: true, value: trimmed };
}

/**
 * `requested_optional_u32_header` — an unsigned integer, and NOT zero.
 *
 * Rust rejects `0` explicitly, so `@0` is a wire error rather than a sentinel
 * for "latest". `Number.parseInt` would accept `"3abc"`, so the whole trimmed
 * string must be digits.
 */
function optionalU32Header(
  headers: Headers,
  name: string,
): { ok: true; value: number | undefined } | { ok: false; detail: string } {
  const raw = headers.get(name);
  if (raw === null) return { ok: true, value: undefined };
  const trimmed = raw.trim();
  if (trimmed === "") return { ok: true, value: undefined };
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(Number(trimmed))) {
    return { ok: false, detail: `${name} must be an unsigned integer` };
  }
  const parsed = Number(trimmed);
  if (parsed === 0) return { ok: false, detail: `${name} must be greater than zero` };
  return { ok: true, value: parsed };
}

/**
 * The three `requested_*_header` reads plus the cross-header rule that follows
 * them in `agent_workflow_use`.
 *
 * The cross-header rule is why this is one function rather than three: a
 * request carrying a version or a node WITHOUT an id looks gated to whoever
 * wrote the client and is not, so Rust refuses it rather than ignoring it. A
 * BLANK id header is refused for the same reason — see {@link optionalIdHeader}.
 */
export function workflowHeadersFrom(headers: Headers): WorkflowDeclaration {
  const rawId = headers.get(WORKFLOW_ID_HEADER);
  const id = optionalIdHeader(headers, WORKFLOW_ID_HEADER);
  if (!id.ok) return { kind: "invalid", detail: id.detail };
  if (rawId !== null && id.value === undefined) {
    return { kind: "invalid", detail: `${WORKFLOW_ID_HEADER} must not be blank` };
  }

  const version = optionalU32Header(headers, WORKFLOW_VERSION_HEADER);
  if (!version.ok) return { kind: "invalid", detail: version.detail };
  const nodeId = optionalIdHeader(headers, WORKFLOW_NODE_ID_HEADER);
  if (!nodeId.ok) return { kind: "invalid", detail: nodeId.detail };

  if (id.value === undefined && (version.value !== undefined || nodeId.value !== undefined)) {
    return {
      kind: "invalid",
      detail: `${WORKFLOW_ID_HEADER} is required when workflow version or node headers are set`,
    };
  }
  if (id.value === undefined) return { kind: "absent" };
  return {
    kind: "declared",
    workflowId: id.value,
    workflowVersion: version.value,
    workflowNodeId: nodeId.value,
  };
}

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

/** One entry of the request's `tool_calls[]`, as far as the gate is concerned. */
export interface DeclaredToolCall {
  readonly name: string;
}

/** The run facts the ladder needs, supplied as DATA so the decision stays pure. */
export interface WorkflowToolRunFacts {
  /**
   * `workflow_run_last_successful_node_id`. `undefined` = the run has made no
   * step yet, which is NOT the same as "started at the graph's entry": it is
   * what makes rule 3 of {@link workflowEdgeTransitionError} apply.
   */
  readonly previousSuccessfulNodeId?: string | undefined;
  /** `workflow_run_started_at`. `undefined` SKIPS the timeout check entirely. */
  readonly runStartedAtUnix?: number | undefined;
}

/** What the gate was asked to decide. */
export interface WorkflowToolRequest {
  readonly caller: WorkflowCaller;
  readonly declaration: WorkflowDeclaration;
  readonly toolCalls: readonly DeclaredToolCall[];
  readonly nowUnixSeconds: number;
}

/**
 * A workflow step that PASSED the graph ladder — Rust `AgentWorkflowUse`, plus
 * the budget envelope the caller must still debit.
 */
export interface WorkflowUse {
  readonly id: string;
  readonly version: number;
  readonly nodeId: string;
  /**
   * `node.tool`, captured UNCONDITIONALLY — even when this step declared no
   * tool calls — so the dispatcher can enforce it against the tool that is
   * actually dispatched at runtime rather than the caller's metadata. Rust's
   * own comment on the field; {@link workflowNodeToolDenial} is the check.
   */
  readonly nodeTool: string | null;
  /** The composed graph ⊓ node envelope. Unbounded ⇒ no budget row is opened. */
  readonly caps: WorkflowBudgetCaps;
}

export type WorkflowToolDecision =
  | { readonly ok: true; readonly use: WorkflowUse | null }
  | { readonly ok: false; readonly rejection: WorkflowToolRejection };

/**
 * `workflow_graph_budget_caps` — the graph's execution-budget caps.
 *
 * Cost has no config knob in the reference either; the wall clock is enforced
 * by the separate `timeout_millis` gate, so leaving `wallClockMillis` unset
 * here avoids enforcing it twice with two different messages.
 */
function graphBudgetCaps(workflow: ToolWorkflowGraph): WorkflowBudgetCaps {
  return {
    ...(workflow.token_budget === undefined ? {} : { tokenBudget: workflow.token_budget }),
    ...(workflow.max_tool_calls === undefined ? {} : { toolCallBudget: workflow.max_tool_calls }),
  };
}

/** `workflow_node_budget_caps` — a node may TIGHTEN the envelope, never widen it. */
function nodeBudgetCaps(node: WorkflowGraphNode): WorkflowBudgetCaps {
  return node.token_budget === undefined ? {} : { tokenBudget: node.token_budget };
}

/**
 * `workflow_node_tool_denial` — fail-closed enforcement of a node's declared
 * tool against the tool ACTUALLY dispatched.
 *
 * Returns the denial message, or `null` when the dispatch is allowed. A
 * non-workflow dispatch (`use === null`) and a node with no declared tool are
 * both always allowed, which is what keeps this from refusing ordinary traffic.
 */
export function workflowNodeToolDenial(
  use: WorkflowUse | null,
  dispatchedTool: string,
): string | null {
  if (use === null || use.nodeTool === null) return null;
  if (dispatchedTool === use.nodeTool) return null;
  return (
    `scope_denied: workflow node ${use.nodeId} is restricted to tool ${use.nodeTool}; ` +
    `dispatch of tool ${dispatchedTool} is not allowed`
  );
}

/**
 * `agent_workflow_use`, in full and in order.
 *
 * `{ ok: true, use: null }` for a step that declares no workflow — the gate is
 * opt-in by header, exactly as in Rust, so an ordinary run submission is
 * untouched. That opt-in is also why mounting this on `POST /v1/agent-jobs` as
 * well as `POST /v1/agent-runs` costs an undeclared caller nothing; see the
 * note on the mount in `./lifecycle.ts`.
 */
export function enforceWorkflowToolPolicy(
  workflows: readonly ToolWorkflowGraph[],
  request: WorkflowToolRequest,
  facts: WorkflowToolRunFacts,
): WorkflowToolDecision {
  const declaration = request.declaration;
  if (declaration.kind === "invalid") {
    return { ok: false, rejection: refuse(INVALID_WORKFLOW_HEADER_CODE, declaration.detail) };
  }
  if (declaration.kind === "absent") return { ok: true, use: null };

  const workflow = selectAgentWorkflow(
    workflows,
    declaration.workflowId,
    declaration.workflowVersion,
  ) as ToolWorkflowGraph | undefined;
  if (workflow === undefined) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_not_found",
        declaration.workflowVersion === undefined
          ? `agent workflow ${declaration.workflowId} was not found`
          : `agent workflow ${declaration.workflowId}@${declaration.workflowVersion} was not found`,
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

  const nodeId = declaration.workflowNodeId;
  if (nodeId === undefined) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_node_required",
        `${WORKFLOW_NODE_ID_HEADER} is required when ${WORKFLOW_ID_HEADER} is set`,
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

  // The TOOL half. Guarded by `tool_calls` being non-empty, which is Rust's own
  // guard: a step that dispatches no tool is a plain turn and any node kind may
  // make it. Dropping the guard would refuse every graph's opening step.
  if (request.toolCalls.length > 0) {
    const toolKind: WorkflowNodeKind = "tool";
    if (node.kind !== toolKind) {
      return {
        ok: false,
        rejection: refuse(
          "workflow_node_not_tool",
          `workflow node ${nodeId} is not allowed to dispatch tool traffic`,
        ),
      };
    }
    const pinned = node.tool;
    if (pinned !== undefined && request.toolCalls.some((call) => call.name !== pinned)) {
      return {
        ok: false,
        rejection: refuse(
          "workflow_tool_not_allowed",
          `workflow node ${nodeId} is not allowed to use requested tool`,
        ),
      };
    }
  }

  const edgeError = workflowEdgeTransitionError(workflow, nodeId, facts.previousSuccessfulNodeId);
  if (edgeError !== null) {
    return { ok: false, rejection: refuse("workflow_edge_not_allowed", edgeError) };
  }

  const declaredCalls = request.toolCalls.length;

  // `tool_calls.len() > 1 && tool_calls.len() > limit` — the `> 1` guard is
  // Rust's and is not redundant: a graph declaring `max_parallelism = 0` (a
  // nonsensical but expressible config) must not refuse a single sequential
  // call, because one call is not parallelism.
  if (
    workflow.max_parallelism !== undefined &&
    declaredCalls > 1 &&
    declaredCalls > workflow.max_parallelism
  ) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_parallelism_limit_exceeded",
        `agent workflow ${workflow.id}@${workflow.version} declared ${declaredCalls} tool call(s), ` +
          "exceeding configured parallelism limit",
      ),
    };
  }

  if (workflow.max_tool_calls !== undefined && declaredCalls > workflow.max_tool_calls) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_tool_call_limit_exceeded",
        `agent workflow ${workflow.id}@${workflow.version} tool call limit is exhausted`,
      ),
    };
  }

  // One turn per scripted call, plus the final turn that consumes their results.
  const requiredTurns = declaredCalls + 1;
  // `workflow.max_iterations.or(node.max_iterations)` — `or`, NOT `min`. The
  // graph's cap wins when set and the node's is consulted only when the graph
  // declares none, so a graph that deliberately WIDENS a node's cap keeps that
  // effect.
  const iterationLimit = workflow.max_iterations ?? node.max_iterations;
  if (iterationLimit !== undefined && requiredTurns > iterationLimit) {
    return {
      ok: false,
      rejection: refuse(
        "workflow_iteration_limit_exceeded",
        `agent workflow ${workflow.id}@${workflow.version} requires ${requiredTurns} turn(s), ` +
          "exceeding configured iteration limit",
      ),
    };
  }

  if (workflow.timeout_millis !== undefined && facts.runStartedAtUnix !== undefined) {
    // `saturating_sub` then `saturating_mul(1_000)`: a recorded start in the
    // FUTURE (clock skew between the writer and this reader) yields 0 elapsed,
    // never a negative that would wrap.
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

  return {
    ok: true,
    use: {
      id: workflow.id,
      version: workflow.version,
      nodeId,
      nodeTool: node.tool ?? null,
      caps: resolveWorkflowBudgetEnvelope(graphBudgetCaps(workflow), nodeBudgetCaps(node)),
    },
  };
}

// ---------------------------------------------------------------------------
// The catalog seam
// ---------------------------------------------------------------------------

/** `control_plane_resources.resource_kind` the admin workflow group writes. */
export const AGENT_WORKFLOW_COLLECTION = "agent-workflows";
/** The generic document table, in the CONTROL database. */
export const RESOURCE_TABLE = "control_plane_resources";
/** The object-local document table for tenant-private resource kinds. */
export const TENANT_RESOURCE_TABLE = "tenant_resources";

/** The seam the gate codes against. */
export interface WorkflowCatalogPort {
  /**
   * The workflows visible to `tenantId`.
   *
   * A read FAILURE returns an empty table rather than throwing, and that
   * direction is safe HERE (unlike in `apps/gateway`, which answers
   * `503 workflow_catalog_unavailable`) for one reason: this gate is opt-in by
   * header. An empty table cannot un-gate anything — a step that declares a
   * workflow is answered `workflow_not_found`, which is a REFUSAL, and a step
   * that declares none was never gated. `test/workflow-tool-gate.test.ts` pins
   * both halves of that.
   */
  forTenant(tenantId: string | null): Promise<readonly ToolWorkflowGraph[]>;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown): readonly string[] | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return undefined;
  for (const entry of value) if (typeof entry !== "string") return undefined;
  return value as readonly string[];
}

function nonNegativeInt(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

const NODE_KINDS: readonly WorkflowNodeKind[] = ["model", "tool", "router", "human", "checkpoint"];

/**
 * Decode one workflow document.
 *
 * `undefined` REFUSES the document, and every refusal is in the safe direction
 * for a gate: an undecodable workflow is one a caller cannot name, so a step
 * declaring it is `workflow_not_found` rather than an ungated 202.
 *
 * An unrecognised node `kind` refuses the WHOLE document rather than defaulting.
 * Defaulting is the dangerous direction: a node typed `toool` would fall back to
 * `model` and a `tool` step at it would be refused with the wrong code, or —
 * worse, if the default were `tool` — a model node would silently gain the right
 * to dispatch tools, which is exactly what `workflow_node_not_tool` exists to
 * stop.
 */
export function decodeWorkflowDocument(value: unknown): ToolWorkflowGraph | undefined {
  if (!isObject(value)) return undefined;
  const id = value["id"];
  if (typeof id !== "string" || id === "") return undefined;

  const version = value["version"] === undefined ? 1 : nonNegativeInt(value["version"]);
  if (version === undefined) return undefined;

  const enabled = value["enabled"] === undefined ? true : value["enabled"];
  if (typeof enabled !== "boolean") return undefined;

  const organizationIds = stringList(value["organization_ids"]);
  const projectIds = stringList(value["project_ids"]);
  const apiKeyIds = stringList(value["api_key_ids"]);
  if (organizationIds === undefined || projectIds === undefined || apiKeyIds === undefined) {
    return undefined;
  }

  const rawNodes = value["nodes"];
  if (!Array.isArray(rawNodes)) return undefined;
  const nodes: WorkflowGraphNode[] = [];
  for (const raw of rawNodes) {
    if (!isObject(raw)) return undefined;
    const nodeId = raw["id"];
    if (typeof nodeId !== "string" || nodeId === "") return undefined;
    const kind = raw["kind"] === undefined ? "model" : raw["kind"];
    if (typeof kind !== "string" || !NODE_KINDS.includes(kind as WorkflowNodeKind)) {
      return undefined;
    }
    const providers = stringList(raw["providers"]);
    if (providers === undefined) return undefined;
    const model = raw["model"];
    if (model !== undefined && model !== null && typeof model !== "string") return undefined;
    const tool = raw["tool"];
    if (tool !== undefined && tool !== null && typeof tool !== "string") return undefined;
    nodes.push({
      id: nodeId,
      kind: kind as WorkflowNodeKind,
      ...(typeof model === "string" ? { model } : {}),
      providers,
      ...(typeof tool === "string" ? { tool } : {}),
      ...(nonNegativeInt(raw["max_iterations"]) === undefined
        ? {}
        : { max_iterations: nonNegativeInt(raw["max_iterations"]) }),
      ...(nonNegativeInt(raw["token_budget"]) === undefined
        ? {}
        : { token_budget: nonNegativeInt(raw["token_budget"]) }),
    });
  }

  const rawEdges = value["edges"];
  if (rawEdges !== undefined && rawEdges !== null && !Array.isArray(rawEdges)) return undefined;
  const edges: { from: string; to: string }[] = [];
  for (const raw of (rawEdges as unknown[] | undefined) ?? []) {
    if (!isObject(raw)) return undefined;
    const from = raw["from"];
    const to = raw["to"];
    if (typeof from !== "string" || typeof to !== "string") return undefined;
    edges.push({ from, to });
  }

  const cap = (key: string): number | undefined => nonNegativeInt(value[key]);

  return {
    id,
    version,
    enabled,
    organization_ids: organizationIds,
    project_ids: projectIds,
    api_key_ids: apiKeyIds,
    nodes,
    edges,
    ...(cap("max_model_calls") === undefined ? {} : { max_model_calls: cap("max_model_calls") }),
    ...(cap("max_tool_calls") === undefined ? {} : { max_tool_calls: cap("max_tool_calls") }),
    ...(cap("max_parallelism") === undefined ? {} : { max_parallelism: cap("max_parallelism") }),
    ...(cap("max_iterations") === undefined ? {} : { max_iterations: cap("max_iterations") }),
    ...(cap("timeout_millis") === undefined ? {} : { timeout_millis: cap("timeout_millis") }),
    ...(cap("token_budget") === undefined ? {} : { token_budget: cap("token_budget") }),
  };
}

/** Decode a JSON array of workflow documents, skipping the undecodable ones. */
export function decodeWorkflowTable(raw: string | undefined): readonly ToolWorkflowGraph[] {
  if (raw === undefined || raw.trim() === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: ToolWorkflowGraph[] = [];
  for (const entry of parsed) {
    const decoded = decodeWorkflowDocument(entry);
    if (decoded !== undefined) out.push(decoded);
  }
  return out;
}

/**
 * Merge a durable table with the operator's var table.
 *
 * `Config::materialize_skill_package_resources`' precedence, applied to the same
 * pair `apps/gateway/src/inference/workflow.ts` composes: the LATER table
 * upserts by `(id, version)`. The var is a per-deployment statement and wins
 * over a stored document, so an operator can pin a graph without a control-plane
 * round trip.
 */
export function mergeWorkflowTables(
  base: readonly ToolWorkflowGraph[],
  overlay: readonly ToolWorkflowGraph[],
): readonly ToolWorkflowGraph[] {
  const merged = [...base];
  for (const workflow of overlay) {
    const index = merged.findIndex(
      (existing) => existing.id === workflow.id && existing.version === workflow.version,
    );
    if (index === -1) merged.push(workflow);
    else merged[index] = workflow;
  }
  return merged;
}

/** Bindings the catalog reads. */
export interface WorkflowCatalogBindings {
  /** The CONTROL database: `control_plane_resources`. */
  readonly CONTROL_DB?: D1Database | undefined;
  /** The shared TenantDataObject namespace for tenant-private documents. */
  readonly TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
  /**
   * OPERATOR config: a JSON array of workflow documents.
   *
   * There is DELIBERATELY no `FG_DEV_*` twin. The var is not a test seam — the
   * workflow table was TOML configuration in the reference — and every other
   * dev twin in this Worker exists only because a real credential store had to
   * be stubbed offline. `test/workflow-tool-gate.test.ts` seeds this var
   * directly through `setEnvVar`, so a second name would buy nothing and add a
   * shadowing hazard of exactly the kind `AGENT_UPSTREAMS = "[]"` produced.
   */
  readonly AGENT_WORKFLOWS?: string | undefined;
}

/**
 * The catalog for a Worker `env`: the durable admin documents, with the
 * operator var materialised over them.
 *
 * With no `CONTROL_DB` the var alone is the table, so a deployment that
 * configures workflows through `[vars]` is gated with no database at all —
 * which is also the posture the offline harness runs in.
 */
export function workflowCatalogFromEnv(env: WorkflowCatalogBindings): WorkflowCatalogPort {
  const overlay = decodeWorkflowTable(env.AGENT_WORKFLOWS);
  const db = controlDatabaseFrom(env);
  if (db === undefined || typeof db.prepare !== "function") {
    return {
      async forTenant(): Promise<readonly ToolWorkflowGraph[]> {
        return overlay;
      },
    };
  }
  const router =
    env.TENANT_DATA === undefined
      ? undefined
      : new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, db);
  return {
    async forTenant(tenantId: string | null): Promise<readonly ToolWorkflowGraph[]> {
      if (router !== undefined && tenantId !== null && tenantId.trim() !== "") {
        try {
          const handle = await router.forTenant(tenantId);
          const objectRows = await handle.db
            .prepare(
              `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
                 WHERE resource_kind = ?
                 ORDER BY resource_id`,
            )
            .bind(AGENT_WORKFLOW_COLLECTION)
            .all<{ document_json: string }>();
          const base: ToolWorkflowGraph[] = [];
          const decode = (document: unknown): ToolWorkflowGraph | undefined => {
            if (!isObject(document) || document["tenant_id"] !== tenantId) return undefined;
            return decodeWorkflowDocument(document);
          };
          for (const row of objectRows.results) {
            let parsed: unknown;
            try {
              parsed = JSON.parse(row.document_json);
            } catch {
              continue;
            }
            const decoded = decode(parsed);
            if (decoded !== undefined) {
              base.push(decoded);
            }
          }
          return mergeWorkflowTables(base, overlay);
        } catch {
          return overlay;
        }
      }
      if (router !== undefined) {
        const base: ToolWorkflowGraph[] = [];
        try {
          for (const provisionedTenant of await router.provisionedTenants()) {
            const handle = await router.forTenant(provisionedTenant);
            const rows = await handle.db
              .prepare(
                `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
                   WHERE resource_kind = ?
                   ORDER BY resource_id`,
              )
              .bind(AGENT_WORKFLOW_COLLECTION)
              .all<{ document_json: string }>();
            for (const row of rows.results) {
              let parsed: unknown;
              try {
                parsed = JSON.parse(row.document_json);
              } catch {
                continue;
              }
              if (!isObject(parsed) || parsed["tenant_id"] !== provisionedTenant) continue;
              const decoded = decodeWorkflowDocument(parsed);
              if (decoded !== undefined) base.push(decoded);
            }
          }
          const projectionRows = await db
            .prepare(
              `SELECT document_json FROM ${RESOURCE_TABLE}
                 WHERE resource_kind = ?
                   AND json_extract(document_json, '$.tenant_id') IS NULL
                 ORDER BY resource_id`,
            )
            .bind(AGENT_WORKFLOW_COLLECTION)
            .all<{ document_json: string }>();
          const projection: ToolWorkflowGraph[] = [];
          for (const row of projectionRows.results) {
            let parsed: unknown;
            try {
              parsed = JSON.parse(row.document_json);
            } catch {
              continue;
            }
            const decoded = decodeWorkflowDocument(parsed);
            if (decoded !== undefined) projection.push(decoded);
          }
          return mergeWorkflowTables(mergeWorkflowTables(projection, base), overlay);
        } catch {
          return overlay;
        }
      }
      let rows: { results: { document_json: string }[] };
      try {
        rows = await db
          .prepare(
            `SELECT document_json FROM ${RESOURCE_TABLE}
               WHERE resource_kind = ?
                 AND ${
                   tenantId === null
                     ? "json_extract(document_json, '$.tenant_id') IS NULL"
                     : "(json_extract(document_json, '$.tenant_id') = ?" +
                       " OR json_extract(document_json, '$.tenant_id') IS NULL)"
                 }
               ORDER BY resource_id`,
          )
          .bind(
            ...(tenantId === null
              ? [AGENT_WORKFLOW_COLLECTION]
              : [AGENT_WORKFLOW_COLLECTION, tenantId]),
          )
          .all<{ document_json: string }>();
      } catch {
        // See {@link WorkflowCatalogPort.forTenant}: an unreadable table removes
        // WORKFLOWS, and since the gate is opt-in that can only produce a
        // refusal, never an admission.
        return overlay;
      }
      const base: ToolWorkflowGraph[] = [];
      for (const row of rows.results) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(row.document_json);
        } catch {
          continue;
        }
        const decoded = decodeWorkflowDocument(parsed);
        if (decoded !== undefined) base.push(decoded);
      }
      return mergeWorkflowTables(base, overlay);
    },
  };
}

/**
 * The caller identity `can_use_workflow` matches against.
 *
 * The mapping is stated here ONCE, because getting it wrong is silent: Rust's
 * `AuthContext.organization_id` is this Worker's `tenancy.tenantId`, and its
 * `api_key_id` is the resolved credential's `subject`. Every facet stays
 * `undefined` when the credential carries none — a caller with no key id is not
 * "everyone", it is "nobody", which is what makes a workflow's `api_key_ids`
 * allowlist mean anything.
 */
export function workflowCallerFrom(auth: {
  readonly subject: string | null;
  readonly tenancy: { readonly tenantId: string | null; readonly projectId?: string | null };
}): WorkflowCaller {
  return {
    ...(auth.subject === null ? {} : { apiKeyId: auth.subject }),
    ...(auth.tenancy.tenantId === null ? {} : { organizationId: auth.tenancy.tenantId }),
    ...(auth.tenancy.projectId === null || auth.tenancy.projectId === undefined
      ? {}
      : { projectId: auth.tenancy.projectId }),
  };
}
