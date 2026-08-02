/**
 * Workflow-run execution budgets (ports `ferrogate-storage::workflow_budget`,
 * issue #279).
 *
 * Correctness proof (inventory §1.5.3): a multi-dimensional cumulative envelope
 * (cost / tokens / tool-calls / wall-clock) debited per step, fail-closed and
 * no-overspend across concurrent steps. A debit breaching ANY capped dimension
 * is rejected WITHOUT applying spend and flips the run to `exhausted`; a top-up
 * raises caps and flips back to `active`. The in-memory backend is serialized,
 * giving the same guarantee as the Postgres `FOR UPDATE` lock / D1 guarded CAS.
 */
import { StorageError } from "./errors.js";
import { workflowRunBudgetId } from "./ids.js";
import { saturatingAdd } from "./ids.js";

export const WORKFLOW_RUN_BUDGET_ACTIVE = "active";
export const WORKFLOW_RUN_BUDGET_EXHAUSTED = "exhausted";
export type WorkflowRunBudgetStatus = "active" | "exhausted";

/** The distinct fail-closed denial code family (#279). */
export const WORKFLOW_BUDGET_EXCEEDED_CODE = "workflow_budget_exceeded";

/** Which envelope dimension a debit would breach. */
export type WorkflowBudgetDimension = "cost" | "tokens" | "tool_calls" | "wall_clock";

/** The dimension-qualified denial code, e.g. `workflow_budget_exceeded:cost`. */
export function workflowBudgetDenialCode(dimension: WorkflowBudgetDimension): string {
  return `${WORKFLOW_BUDGET_EXCEEDED_CODE}:${dimension}`;
}

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
  status: WorkflowRunBudgetStatus;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** Caps to seed a run's envelope at `open`. Absent field ⇒ that dimension unbounded. */
export interface WorkflowRunBudgetCaps {
  costBudgetCredits?: number;
  tokenBudget?: number;
  toolCallBudget?: number;
  wallClockDeadlineUnix?: number;
}

/** Outcome of a debit. */
export type WorkflowBudgetDebit =
  | { kind: "applied"; budget: StoredWorkflowRunBudget }
  | { kind: "exceeded"; dimension: WorkflowBudgetDimension; budget: StoredWorkflowRunBudget };

/**
 * The FIRST dimension a `(cost, tokens, tool_calls)` spend at `now` would breach
 * (cost → tokens → tool_calls precedence, wall-clock checked first), or
 * `undefined` if it fits. Pure — exposed so a caller can pre-flight a step.
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
  if (
    budget.costBudgetCredits !== undefined &&
    saturatingAdd(budget.spentCredits, costCredits) > budget.costBudgetCredits
  ) {
    return "cost";
  }
  if (
    budget.tokenBudget !== undefined &&
    saturatingAdd(budget.spentTokens, tokens) > budget.tokenBudget
  ) {
    return "tokens";
  }
  if (
    budget.toolCallBudget !== undefined &&
    saturatingAdd(budget.spentToolCalls, toolCalls) > budget.toolCallBudget
  ) {
    return "tool_calls";
  }
  return undefined;
}

/**
 * Shared top-up arithmetic (ports `apply_topup`): add deltas to each capped
 * dimension (an unbounded cap stays unbounded), extend the deadline to the later
 * of current/requested, and reactivate. Mutates `budget` in place.
 */
export function applyTopup(
  budget: StoredWorkflowRunBudget,
  addCostCredits: number,
  addTokens: number,
  addToolCalls: number,
  extendDeadlineUnix: number | undefined,
  nowUnix: number,
): void {
  if (budget.costBudgetCredits !== undefined) {
    budget.costBudgetCredits = saturatingAdd(budget.costBudgetCredits, addCostCredits);
  }
  if (budget.tokenBudget !== undefined) {
    budget.tokenBudget = saturatingAdd(budget.tokenBudget, addTokens);
  }
  if (budget.toolCallBudget !== undefined) {
    budget.toolCallBudget = saturatingAdd(budget.toolCallBudget, addToolCalls);
  }
  if (extendDeadlineUnix !== undefined) {
    budget.wallClockDeadlineUnix =
      budget.wallClockDeadlineUnix !== undefined
        ? Math.max(budget.wallClockDeadlineUnix, extendDeadlineUnix)
        : extendDeadlineUnix;
  }
  budget.status = WORKFLOW_RUN_BUDGET_ACTIVE;
  budget.updatedAtUnix = nowUnix;
}

/** Reference in-memory backend for the durable workflow-run budget ledger. */
export class MemoryWorkflowBudgetStore {
  private readonly budgets = new Map<string, StoredWorkflowRunBudget>();

  /**
   * Idempotently open a run's envelope. Re-opening returns the existing envelope
   * UNCHANGED (caps are fixed at first step); a different tenant is a conflict.
   */
  openWorkflowRunBudget(
    workflowId: string,
    workflowVersion: number,
    runId: string,
    tenantId: string,
    caps: WorkflowRunBudgetCaps,
    nowUnix: number,
  ): StoredWorkflowRunBudget {
    const id = workflowRunBudgetId(workflowId, workflowVersion, runId);
    const existing = this.budgets.get(id);
    if (existing) {
      if (existing.tenantId !== tenantId) {
        throw StorageError.conflict(
          `workflow run budget ${id} already exists for another tenant`,
        );
      }
      return { ...existing };
    }
    const budget: StoredWorkflowRunBudget = {
      id,
      workflowId,
      workflowVersion,
      runId,
      tenantId,
      costBudgetCredits: caps.costBudgetCredits,
      tokenBudget: caps.tokenBudget,
      toolCallBudget: caps.toolCallBudget,
      wallClockDeadlineUnix: caps.wallClockDeadlineUnix,
      spentCredits: 0,
      spentTokens: 0,
      spentToolCalls: 0,
      status: WORKFLOW_RUN_BUDGET_ACTIVE,
      createdAtUnix: nowUnix,
      updatedAtUnix: nowUnix,
    };
    this.budgets.set(id, budget);
    return { ...budget };
  }

  /**
   * Atomically debit one step's spend, fail-closed and no-overspend. An
   * already-exhausted run rejects every debit; a debit breaching any dimension is
   * rejected without applying spend and marks the run exhausted.
   */
  debitWorkflowRunBudget(
    id: string,
    costCredits: number,
    tokens: number,
    toolCalls: number,
    nowUnix: number,
  ): WorkflowBudgetDebit {
    if (costCredits < 0 || tokens < 0 || toolCalls < 0) {
      throw StorageError.conflict(`workflow run budget ${id} debit amounts must be non-negative`);
    }
    const budget = this.budgets.get(id);
    if (!budget) {
      throw StorageError.notFound(`workflow run budget ${id} does not exist`);
    }
    const breach =
      budget.status === WORKFLOW_RUN_BUDGET_EXHAUSTED
        ? (dimensionExceededBy(budget, costCredits, tokens, toolCalls, nowUnix) ?? "cost")
        : dimensionExceededBy(budget, costCredits, tokens, toolCalls, nowUnix);
    if (breach !== undefined) {
      budget.status = WORKFLOW_RUN_BUDGET_EXHAUSTED;
      budget.updatedAtUnix = nowUnix;
      return { kind: "exceeded", dimension: breach, budget: { ...budget } };
    }
    budget.spentCredits = saturatingAdd(budget.spentCredits, costCredits);
    budget.spentTokens = saturatingAdd(budget.spentTokens, tokens);
    budget.spentToolCalls = saturatingAdd(budget.spentToolCalls, toolCalls);
    budget.updatedAtUnix = nowUnix;
    return { kind: "applied", budget: { ...budget } };
  }

  /** Raise an exhausted (or active) run's caps and reactivate it. */
  topupWorkflowRunBudget(
    id: string,
    addCostCredits: number,
    addTokens: number,
    addToolCalls: number,
    extendDeadlineUnix: number | undefined,
    nowUnix: number,
  ): StoredWorkflowRunBudget {
    const budget = this.budgets.get(id);
    if (!budget) {
      throw StorageError.notFound(`workflow run budget ${id} does not exist`);
    }
    applyTopup(budget, addCostCredits, addTokens, addToolCalls, extendDeadlineUnix, nowUnix);
    return { ...budget };
  }

  getWorkflowRunBudget(id: string): StoredWorkflowRunBudget | undefined {
    const b = this.budgets.get(id);
    return b ? { ...b } : undefined;
  }

  listWorkflowRunBudgets(tenantId: string): StoredWorkflowRunBudget[] {
    const out = [...this.budgets.values()]
      .filter((b) => b.tenantId === tenantId)
      .map((b) => ({ ...b }));
    out.sort((a, b) => b.createdAtUnix - a.createdAtUnix || a.id.localeCompare(b.id));
    return out;
  }
}
