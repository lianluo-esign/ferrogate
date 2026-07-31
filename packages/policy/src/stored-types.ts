/**
 * Storage records the policy layer reads.
 *
 * ## Relocation CLOSED
 *
 * These types previously had a second, hand-maintained definition here, because
 * `@ferrogate/storage` was a wave-1 placeholder that had not ported them yet.
 * It has since ported all of them, so this module is now a pure RE-EXPORT of
 * the authoritative definitions — matching the Rust tree, where
 * `ferrogate-policy` reads `ferrogate-storage`'s `StoredQuotaPolicy`,
 * `StoredPlan`, `QuotaScopeKind`, `StoredWorkflowRunBudget`,
 * `WorkflowBudgetDimension`, and `dimension_exceeded_by`.
 *
 * The duplication was not harmless: the two copies of `dimension_exceeded_by`
 * had already drifted (storage's saturates its adds, the copy here did not), and
 * a `StoredWorkflowRunBudget.status` typed `string` here versus a narrow union
 * there is exactly the kind of gap where an invalid status reaches a debit. One
 * definition cannot drift from itself.
 *
 * This package stays PURE: `@ferrogate/storage` pulls in `D1Database` as a TYPE
 * only, has no top-level side effect, and touches no binding at import time, so
 * importing it from a plain vitest suite or from the CLI is safe.
 *
 * Zod schemas for these shapes live in `schemas.ts`.
 */
export type {
  QuotaScopeKind,
  StoredPlan,
  StoredQuotaPolicy,
  StoredWorkflowRunBudget,
  WorkflowBudgetDimension,
  WorkflowRunBudgetStatus,
} from "@ferrogate/storage";
export {
  QUOTA_SCOPE_KINDS,
  WORKFLOW_BUDGET_EXCEEDED_CODE,
  WORKFLOW_RUN_BUDGET_ACTIVE,
  WORKFLOW_RUN_BUDGET_EXHAUSTED,
  dimensionExceededBy,
  quotaPolicyId,
  workflowBudgetDenialCode,
} from "@ferrogate/storage";

import {
  quotaScopeKindFromString,
  type QuotaScopeKind,
  type WorkflowBudgetDimension,
} from "@ferrogate/storage";

/**
 * Canonical string form (mirrors `QuotaScopeKind::as_str`). Identity in TS,
 * because the union members ARE the wire tags; kept as a named function so a
 * call site reads the same as the Rust it ports.
 */
export function quotaScopeKindStr(kind: QuotaScopeKind): string {
  return kind;
}

/**
 * Parse a scope-kind string, or `undefined` (mirrors `from_str_opt`).
 *
 * Alias of `@ferrogate/storage`'s `quotaScopeKindFromString`, kept under the
 * Rust-derived name this package and `apps/gateway` already import.
 */
export function quotaScopeKindFromStr(value: string): QuotaScopeKind | undefined {
  return quotaScopeKindFromString(value);
}

/** Canonical string form (mirrors `WorkflowBudgetDimension::as_str`; identity). */
export function workflowBudgetDimensionStr(d: WorkflowBudgetDimension): string {
  return d;
}
