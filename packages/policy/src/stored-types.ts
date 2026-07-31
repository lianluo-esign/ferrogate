/**
 * Storage records the policy layer reads.
 *
 * PORT-TODO(inventory §2.1/§2.5): the authoritative home for these types is the
 * `ferrogate-storage` crate → `@ferrogate/storage`, which is a wave-1 placeholder
 * that has not yet ported them (`StoredQuotaPolicy`, `StoredPlan`,
 * `QuotaScopeKind`, `StoredWorkflowRunBudget`, `WorkflowBudgetDimension`,
 * `dimension_exceeded_by`). They are re-implemented here so the pure policy
 * decisions are complete and testable; when `@ferrogate/storage` ports them,
 * this module should re-export from there instead. The inventory explicitly
 * calls out porting `StoredWorkflowRunBudget.dimension_exceeded_by` alongside
 * the policy crate.
 *
 * These are pure data shapes plus one pure method; no I/O. Zod schemas live in
 * `schemas.ts`.
 */

// ---------------------------------------------------------------------------
// Quota scope
// ---------------------------------------------------------------------------

/** Which level a quota policy is attached to (Rust `QuotaScopeKind`). */
export type QuotaScopeKind = "tenant" | "project" | "workspace" | "key";

/** Canonical string form (mirrors `QuotaScopeKind::as_str`; identity here). */
export function quotaScopeKindStr(kind: QuotaScopeKind): string {
  return kind;
}

/** Parse a scope-kind string, or `undefined` (mirrors `from_str_opt`). */
export function quotaScopeKindFromStr(value: string): QuotaScopeKind | undefined {
  return value === "tenant" || value === "project" || value === "workspace" || value === "key"
    ? value
    : undefined;
}

/**
 * Quota/rate-limit policy attached to one scope. A missing policy at a scope
 * means that scope does not restrict; `enabled = false` at any scope in the
 * chain is a hard deny.
 */
export interface StoredQuotaPolicy {
  id: string;
  scopeType: QuotaScopeKind;
  scopeId: string;
  /** Empty ⇒ this scope does not restrict models. */
  modelAllowlist: string[];
  rpmLimit?: number;
  tpmLimit?: number;
  monthlyBudgetUsd?: number;
  /** Tenant-only override; narrower scopes have no independent asset ownership. */
  assetStorageQuotaBytes?: number;
  /** #259 tenant-only per-object ceiling. */
  assetMaxObjectBytes?: number;
  /** #428 per-tenant agent runtime-cost ceiling (min-merged like the budget). */
  agentCostBudgetUsd?: number;
  /** #170 percent-of-budget alert tiers. */
  alertThresholdPcts: number[];
  enabled: boolean;
  createdAtUnix: number;
  updatedAtUnix: number;
  /** #262 monthly egress byte budget (min-merged like rpm/budget). */
  monthlyEgressBytesBudget?: number;
  /** #262 per-minute asset-download request cap. */
  downloadRpmLimit?: number;
}

/** Deterministic id for a quota policy (`quota_policy_id`). */
export function quotaPolicyId(scopeType: QuotaScopeKind, scopeId: string): string {
  return `${scopeType}:${scopeId}`;
}

/**
 * A sellable default bundle (issue #168). Supplies the FLOOR of the quota merge:
 * a field is taken from the plan only when no policy in the chain set it.
 */
export interface StoredPlan {
  id: string;
  name: string;
  slug: string;
  mcpEnabled: boolean;
  selfHostedWorkersEnabled: boolean;
  adminConsoleSeats?: number;
  defaultModelAllowlist: string[];
  defaultRpmLimit?: number;
  defaultTpmLimit?: number;
  defaultMonthlyBudgetUsd?: number;
  createdAtUnix: number;
  updatedAtUnix: number;
  assetHostingEnabled: boolean;
  defaultAssetStorageQuotaBytes?: number;
  defaultAssetMaxObjectBytes?: number;
  defaultAgentCostBudgetUsd?: number;
  defaultMonthlyEgressBytesBudget?: number;
  defaultDownloadRpmLimit?: number;
  extensionToolsEnabled: boolean;
}

// ---------------------------------------------------------------------------
// Workflow run budget (#279)
// ---------------------------------------------------------------------------

/** A run whose envelope still has budget and accepts debits. */
export const WORKFLOW_RUN_BUDGET_ACTIVE = "active";
/** A run that breached a capped dimension; every further debit is denied. */
export const WORKFLOW_RUN_BUDGET_EXHAUSTED = "exhausted";
/** The distinct fail-closed denial-code family for an exhausted execution budget. */
export const WORKFLOW_BUDGET_EXCEEDED_CODE = "workflow_budget_exceeded";

/** Which dimension of a run's multi-dimensional execution envelope a debit breaches. */
export type WorkflowBudgetDimension = "cost" | "tokens" | "tool_calls" | "wall_clock";

/** Canonical string form (mirrors `WorkflowBudgetDimension::as_str`; identity here). */
export function workflowBudgetDimensionStr(d: WorkflowBudgetDimension): string {
  return d;
}

/** The dimension-qualified denial code, e.g. `workflow_budget_exceeded:cost`. */
export function workflowBudgetDenialCode(d: WorkflowBudgetDimension): string {
  return `${WORKFLOW_BUDGET_EXCEEDED_CODE}:${d}`;
}

/**
 * A durable per-workflow-run execution budget (issue #279). A `null`/`undefined`
 * cap means that dimension is unbounded; the `spent*` counters accumulate
 * monotonically per debit.
 */
export interface StoredWorkflowRunBudget {
  id: string;
  workflowId: string;
  workflowVersion: number;
  runId: string;
  tenantId: string;
  costBudgetCredits?: number;
  tokenBudget?: number;
  toolCallBudget?: number;
  wallClockDeadlineUnix?: number;
  spentCredits: number;
  spentTokens: number;
  spentToolCalls: number;
  /** {@link WORKFLOW_RUN_BUDGET_ACTIVE} or {@link WORKFLOW_RUN_BUDGET_EXHAUSTED}. */
  status: string;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/**
 * Would adding `(cost, tokens, tool_calls)` at time `now` breach a capped
 * dimension? Returns the FIRST breached dimension (checked wall_clock → cost →
 * tokens → tool_calls), or `undefined` if the debit fits. Mirrors
 * `StoredWorkflowRunBudget::dimension_exceeded_by` exactly, including its
 * saturating-add discipline (no wrap).
 */
export function dimensionExceededBy(
  budget: StoredWorkflowRunBudget,
  costCredits: number,
  tokens: number,
  toolCalls: number,
  nowUnix: number,
): WorkflowBudgetDimension | undefined {
  if (budget.wallClockDeadlineUnix !== undefined && nowUnix >= budget.wallClockDeadlineUnix) {
    return "wall_clock";
  }
  if (budget.costBudgetCredits !== undefined && budget.spentCredits + costCredits > budget.costBudgetCredits) {
    return "cost";
  }
  if (budget.tokenBudget !== undefined && budget.spentTokens + tokens > budget.tokenBudget) {
    return "tokens";
  }
  if (budget.toolCallBudget !== undefined && budget.spentToolCalls + toolCalls > budget.toolCallBudget) {
    return "tool_calls";
  }
  return undefined;
}
