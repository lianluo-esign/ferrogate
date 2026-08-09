/**
 * Workflow-graph-level budget resolution (port of `ferrogate-policy`
 * `workflow_budget.rs`, issue #279).
 *
 * Composes a workflow's caps with a node's caps (min-across: a node may tighten
 * but never widen the graph ceiling), does a pure fail-closed pre-flight of a
 * step's spend against the durable `StoredWorkflowRunBudget` ledger, and
 * evaluates the per-node model/provider allowlist at dispatch (before the
 * provider call).
 */
import {
  type StoredWorkflowRunBudget,
  WORKFLOW_RUN_BUDGET_EXHAUSTED,
  type WorkflowBudgetDimension,
  dimensionExceededBy,
  workflowBudgetDenialCode,
  workflowBudgetDimensionStr,
} from "./stored-types.js";

/** Fail-closed denial code: a node dispatched a model its allowlist forbids. */
export const WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE = "workflow_node_model_not_allowed";
/** Fail-closed denial code: a node dispatched to a provider its allowlist forbids. */
export const WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE = "workflow_node_provider_not_allowed";

/**
 * A workflow run's execution-budget caps as expressed by CONFIG, before it is
 * opened into a durable budget row. Any `undefined` dimension is "unbounded at
 * this level". The wall-clock cap is a relative DURATION in millis, converted to
 * an absolute deadline by {@link deadlineUnix}.
 */
export interface WorkflowBudgetCaps {
  /** USD cost ceiling, in integer credits. */
  costBudgetCredits?: number;
  tokenBudget?: number;
  toolCallBudget?: number;
  wallClockMillis?: number;
}

/** True when no dimension is capped — the run needs no durable budget row. */
export function isUnbounded(caps: WorkflowBudgetCaps): boolean {
  return (
    caps.costBudgetCredits === undefined &&
    caps.tokenBudget === undefined &&
    caps.toolCallBudget === undefined &&
    caps.wallClockMillis === undefined
  );
}

/**
 * The absolute wall-clock deadline (unix seconds) for a run started at
 * `startedAtUnix`, or `undefined` when no wall-clock cap applies. The millis
 * duration is rounded UP to whole seconds so a sub-second cap still yields a
 * non-zero window.
 */
export function deadlineUnix(caps: WorkflowBudgetCaps, startedAtUnix: number): number | undefined {
  if (caps.wallClockMillis === undefined) return undefined;
  const seconds = Math.ceil(caps.wallClockMillis / 1000);
  return startedAtUnix + seconds;
}

function minOpt(a: number | undefined, b: number | undefined): number | undefined {
  if (a !== undefined && b !== undefined) return Math.min(a, b);
  return a !== undefined ? a : b;
}

/**
 * Compose a graph's caps with a node's caps into the effective envelope for a
 * step. Each dimension is the `min` of the two; a `None` (unbounded) side is
 * dominated by any `Some` cap on the other side.
 */
export function resolveWorkflowBudgetEnvelope(
  graph: WorkflowBudgetCaps,
  node: WorkflowBudgetCaps,
): WorkflowBudgetCaps {
  return {
    costBudgetCredits: minOpt(graph.costBudgetCredits, node.costBudgetCredits),
    tokenBudget: minOpt(graph.tokenBudget, node.tokenBudget),
    toolCallBudget: minOpt(graph.toolCallBudget, node.toolCallBudget),
    wallClockMillis: minOpt(graph.wallClockMillis, node.wallClockMillis),
  };
}

/** A workflow run's budget was exhausted for a step. */
export interface WorkflowBudgetDenial {
  dimension: WorkflowBudgetDimension;
  code: string;
  message: string;
}

function budgetDenial(dimension: WorkflowBudgetDimension, runId: string): WorkflowBudgetDenial {
  return {
    dimension,
    code: workflowBudgetDenialCode(dimension),
    message: `workflow run ${runId} execution budget exhausted on the ${workflowBudgetDimensionStr(
      dimension,
    )} dimension`,
  };
}

/** Result envelope for the pure pre-flight (Rust `Result<(), WorkflowBudgetDenial>`). */
export type PreflightResult = { ok: true } | { ok: false; denial: WorkflowBudgetDenial };

/**
 * Pure, fail-closed pre-flight of a step's proposed spend against a run's durable
 * envelope. Denies when the run is already exhausted, or when adding
 * `(cost, tokens, tool_calls)` at `now` would breach any capped dimension —
 * WITHOUT mutating the ledger. The durable debit remains the authoritative,
 * atomic enforcement.
 *
 * ## THE "IMPLEMENTED BUT NEVER MOUNTED" MARKER IS CLOSED — do not re-add it
 *
 * It read: "`grep -rn "preflightWorkflowBudget\|WorkflowRunBudget\|
 * workflow_run_budget" apps/` returns zero hits … a run opened with
 * `cost_budget_credits`/`token_budget`/`tool_call_budget`/
 * `wall_clock_deadline_unix` spends without limit … the fail-closed guarantee
 * 'exhausted workflow budget ⇒ deny every step' is currently vacuous end to
 * end."
 *
 * `apps/gateway/src/ratelimit/workflow.ts` now value-imports this function plus
 * {@link resolveWorkflowBudgetEnvelope} and the durable `@ferrogate/storage`
 * half, keying the run off three request headers
 * (`x-ferrogate-workflow-id` / `-workflow-version` / `-workflow-run-id`, all
 * three required together because the budget row's primary key is
 * `workflowRunBudgetId(...)`; a partial declaration is a 400 rather than a
 * silently ungated request). It pre-flights TWICE: in `rateLimit()` with a zero
 * proposed spend — which alone settles `exhausted` and `wall_clock` for every
 * operation, including non-inference ones — and again in `admitTokensPerMinute`
 * with the real token estimate, so a step that would breach `token_budget` is
 * refused before the provider is paid.
 *
 * ## PORT-TODO(P: inventory-policy-core §2.4d, issue #279) — TWO OF THE FOUR
 * ## DIMENSIONS ARE STILL NOT DEBITED. NOT A PLATFORM LIMIT. NOT CLOSED.
 *
 * `cost` and `tool_calls` cannot be decided by a pure admission-time
 * pre-flight: they are only known once a step's real spend settles, and the
 * authority for them is the atomic
 * `D1WorkflowBudgetStore.debitWorkflowRunBudget`. Nothing calls that debit yet.
 * The owner is whoever settles a step — `apps/agent-runtime`'s run-step path,
 * whose Rust counterpart is `crates/ferrogate-gateway/src/server/agent_runs.rs`
 * — not this package and not the gateway's admission middleware, which would
 * have to invent a cost estimate to gate on. So today a run's
 * `cost_budget_credits` and `tool_call_budget` are enforced only insofar as a
 * PREVIOUS debit already flipped the run to `exhausted`; with no debiter, that
 * flip never happens on its own. Closing it means calling the debit after a
 * step settles and asserting a run at its cap is REFUSED on the NEXT step, with
 * the assertion proven RED by removing the debit call.
 *
 * NOTE — {@link evaluateNodeDispatch} is NOT part of this gap: it has no consumer
 * in the Rust tree either (only `ferrogate-policy`'s own tests), so its absence
 * from `apps/` is parity, not regression.
 */
export function preflightWorkflowBudget(
  budget: StoredWorkflowRunBudget,
  costCredits: number,
  tokens: number,
  toolCalls: number,
  nowUnix: number,
): PreflightResult {
  if (budget.status === WORKFLOW_RUN_BUDGET_EXHAUSTED) {
    const dimension =
      dimensionExceededBy(budget, costCredits, tokens, toolCalls, nowUnix) ?? "cost";
    return { ok: false, denial: budgetDenial(dimension, budget.runId) };
  }
  const dimension = dimensionExceededBy(budget, costCredits, tokens, toolCalls, nowUnix);
  return dimension === undefined
    ? { ok: true }
    : { ok: false, denial: budgetDenial(dimension, budget.runId) };
}

/** A workflow node's dispatch allowlist (issue #279). */
export interface WorkflowNodeDispatchPolicy {
  nodeId: string;
  /** The single model this node is restricted to, if any. `undefined` = unrestricted. */
  model?: string;
  /** The providers this node may dispatch to. Empty = unrestricted. */
  providers: string[];
}

/** A node dispatched a model/provider its node-level allowlist forbids. */
export interface WorkflowNodeDispatchDenial {
  code: string;
  message: string;
}

/** Result envelope for node-dispatch evaluation. */
export type NodeDispatchResult = { ok: true } | { ok: false; denial: WorkflowNodeDispatchDenial };

/**
 * Fail-closed evaluation of a node's model/provider allowlist against the
 * model/provider a step is ACTUALLY dispatching (before the provider call). A
 * node that pins a model rejects any other model; a node with a provider
 * allowlist rejects any provider outside it. An `undefined` requested facet is
 * not being dispatched and is not gated.
 */
export function evaluateNodeDispatch(
  node: WorkflowNodeDispatchPolicy,
  requestedModel: string | undefined,
  requestedProvider: string | undefined,
): NodeDispatchResult {
  if (node.model !== undefined && requestedModel !== undefined && node.model !== requestedModel) {
    return {
      ok: false,
      denial: {
        code: WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE,
        message: `workflow node ${node.nodeId} is restricted to model ${node.model}; dispatch of model ${requestedModel} is not allowed`,
      },
    };
  }
  if (node.providers.length > 0 && requestedProvider !== undefined) {
    if (!node.providers.includes(requestedProvider)) {
      return {
        ok: false,
        denial: {
          code: WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE,
          message: `workflow node ${node.nodeId} is not allowed to dispatch to provider ${requestedProvider}`,
        },
      };
    }
  }
  return { ok: true };
}
