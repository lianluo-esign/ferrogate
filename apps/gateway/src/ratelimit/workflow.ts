/**
 * Workflow-run execution budgets — `preflightWorkflowBudget`, mounted.
 *
 * ## What was wrong before this file existed
 *
 * `@ferrogate/policy` ports `preflightWorkflowBudget` +
 * `resolveWorkflowBudgetEnvelope`, `@ferrogate/storage` ports the durable half
 * (`D1WorkflowBudgetStore` + `dimensionExceededBy`), the tenant migration
 * creates `workflow_run_budgets` — and
 * `grep -rn "preflightWorkflowBudget\|workflow_run_budget" apps/` returned
 * nothing. Quoting the marker this file closes: "a run opened with
 * `cost_budget_credits`/`token_budget`/`tool_call_budget`/
 * `wall_clock_deadline_unix` spends without limit, and the
 * `status = 'exhausted'` flip never gates a subsequent step. The fail-closed
 * guarantee … is currently vacuous end to end."
 *
 * ## Where the run identity comes from
 *
 * Rust threads `workflow_id` / `workflow_version` / `workflow_node_id` on
 * `RequestContext` (`packages/core/src/context.ts` ports the same three fields),
 * and `agent_runs.rs` pre-flights on the run-creating path. A Worker's ingress
 * has no such struct, so the three values arrive as request headers, matching
 * the `x-ferrogate-agent-run-id` ingress `src/assets/handlers.ts` already uses
 * for the sibling correlation id (#522):
 *
 * | header | maps to |
 * |---|---|
 * | `x-ferrogate-workflow-id` | `RequestContext.workflow_id` |
 * | `x-ferrogate-workflow-version` | `RequestContext.workflow_version` |
 * | `x-ferrogate-workflow-run-id` | the run whose envelope is charged |
 *
 * All three are required together, because the budget row's primary key is
 * `workflowRunBudgetId(workflowId, workflowVersion, runId)` — a deterministic
 * id from `@ferrogate/storage`, called rather than re-derived. A request that
 * declares none of them is not a workflow step and is not gated. A request that
 * declares SOME of them is a malformed declaration and is refused (400), not
 * silently ungated: a caller that means to be inside a budget and is not is the
 * failure this file exists to stop.
 *
 * ## What the admission-time pre-flight can and cannot decide
 *
 * The pre-flight is pure and fail-closed, and it is evaluated TWICE for a
 * reason:
 *
 *  1. **In `rateLimit()`**, with a zero proposed spend. That still decides two
 *     dimensions completely: a run already flipped to `exhausted` denies every
 *     subsequent step (Rust: "exhausted workflow budget ⇒ deny every step"),
 *     and a run past its `wall_clock_deadline_unix` denies on `wall_clock`. It
 *     is the only place a NON-inference operation inside a run can be gated at
 *     all.
 *  2. **In `admitTokensPerMinute`**, with the real token estimate, so a step
 *     that would breach `token_budget` is refused BEFORE the provider is paid —
 *     the same placement as the TPM gate, and for the same reason.
 *
 * The `cost` and `tool_calls` dimensions are decided by the atomic DEBIT
 * (`D1WorkflowBudgetStore.debitWorkflowRunBudget`), which belongs to whoever
 * settles a step's real spend — `apps/agent-runtime`, not this slice. Stating
 * that boundary rather than pre-flighting a cost this module would have to
 * invent is deliberate: a made-up cost estimate would make the gate look
 * complete while denying on a number nothing produced.
 */
import {
  type PreflightResult,
  type StoredWorkflowRunBudget,
  preflightWorkflowBudget,
} from "@ferrogate/policy";
import { D1WorkflowBudgetStore, workflowRunBudgetId } from "@ferrogate/storage";
import { gatewayTenantHandle } from "./wallet.js";

/** Header carrying `RequestContext.workflow_id`. */
export const WORKFLOW_ID_HEADER = "x-ferrogate-workflow-id";
/** Header carrying `RequestContext.workflow_version`. */
export const WORKFLOW_VERSION_HEADER = "x-ferrogate-workflow-version";
/** Header carrying the run whose execution budget this request spends. */
export const WORKFLOW_RUN_ID_HEADER = "x-ferrogate-workflow-run-id";

/** Bindings this module reads. */
export interface WorkflowBudgetBindings {
  /** The TENANT database, holding `workflow_run_budgets`. */
  readonly DB?: D1Database | undefined;
}

/** A declared workflow step, as read off the request headers. */
export interface WorkflowStepDeclaration {
  readonly workflowId: string;
  readonly workflowVersion: number;
  readonly runId: string;
}

/** The three outcomes of reading the headers. */
export type WorkflowDeclarationResult =
  /** No workflow headers at all — not a workflow step. */
  | { readonly kind: "absent" }
  | { readonly kind: "declared"; readonly step: WorkflowStepDeclaration }
  /** Partial or unparseable declaration — 400, never "ungated". */
  | { readonly kind: "invalid"; readonly detail: string };

/**
 * Read the workflow declaration off a request's headers.
 *
 * Exported and pure so the partial-declaration rule is assertable without a
 * database.
 */
export function workflowDeclarationFrom(headers: Headers): WorkflowDeclarationResult {
  const workflowId = headers.get(WORKFLOW_ID_HEADER)?.trim() ?? "";
  const rawVersion = headers.get(WORKFLOW_VERSION_HEADER)?.trim() ?? "";
  const runId = headers.get(WORKFLOW_RUN_ID_HEADER)?.trim() ?? "";

  const present = [workflowId, rawVersion, runId].filter((value) => value !== "");
  if (present.length === 0) return { kind: "absent" };
  if (present.length < 3) {
    return {
      kind: "invalid",
      detail:
        `a workflow step must declare all three of ${WORKFLOW_ID_HEADER}, ` +
        `${WORKFLOW_VERSION_HEADER} and ${WORKFLOW_RUN_ID_HEADER}; ` +
        "a partial declaration would run outside the budget it names",
    };
  }

  const workflowVersion = Number(rawVersion);
  if (!Number.isInteger(workflowVersion) || workflowVersion < 0) {
    return {
      kind: "invalid",
      detail: `${WORKFLOW_VERSION_HEADER} must be a non-negative integer`,
    };
  }
  return { kind: "declared", step: { workflowId, workflowVersion, runId } };
}

/** What the durable lookup produced. */
export type WorkflowBudgetLookup =
  /** No envelope was opened for this run: nothing caps it (Rust `is_unbounded`). */
  | { readonly kind: "unbudgeted" }
  | { readonly kind: "found"; readonly budget: StoredWorkflowRunBudget }
  | { readonly kind: "unavailable"; readonly detail: string };

/** The seam `rateLimit()` codes against. */
export interface WorkflowBudgetSource {
  forStep(step: WorkflowStepDeclaration, tenantId: string): Promise<WorkflowBudgetLookup>;
}

/** A source for a deployment with no tenant database bound. Never denies. */
export const NO_WORKFLOW_BUDGETS: WorkflowBudgetSource = {
  async forStep(): Promise<WorkflowBudgetLookup> {
    return { kind: "unbudgeted" };
  },
};

/** The durable source: `D1WorkflowBudgetStore` on the tenant database. */
export function d1WorkflowBudgetSource(db: D1Database): WorkflowBudgetSource {
  return {
    async forStep(
      step: WorkflowStepDeclaration,
      tenantId: string,
    ): Promise<WorkflowBudgetLookup> {
      const store = new D1WorkflowBudgetStore(gatewayTenantHandle(db, tenantId));
      // The id is DERIVED by the storage package's own helper, never rebuilt
      // here: a second derivation that drifts by one separator would look up a
      // row that never matches, i.e. it would silently un-gate every run.
      const id = workflowRunBudgetId(step.workflowId, step.workflowVersion, step.runId);
      try {
        const budget = await store.getWorkflowRunBudget(id);
        if (budget === undefined) return { kind: "unbudgeted" };
        if (budget.tenantId !== tenantId) {
          // A run id belonging to another tenant is not this caller's budget to
          // spend, and answering "unbudgeted" would let it run ungated.
          return {
            kind: "unavailable",
            detail: `workflow run ${step.runId} belongs to another tenant`,
          };
        }
        return { kind: "found", budget };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { kind: "unavailable", detail: `workflow budget lookup failed: ${detail}` };
      }
    },
  };
}

/** `env.DB`, when it is really a D1 binding. */
function workflowDatabase(env: WorkflowBudgetBindings): D1Database | undefined {
  const candidate = env.DB;
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
}

/** D1 whenever the tenant database is bound, {@link NO_WORKFLOW_BUDGETS} otherwise. */
export function workflowBudgetSourceFromEnv(env: WorkflowBudgetBindings): WorkflowBudgetSource {
  const db = workflowDatabase(env);
  return db === undefined ? NO_WORKFLOW_BUDGETS : d1WorkflowBudgetSource(db);
}

/**
 * The pure pre-flight, re-exported through this module so every caller in the
 * gateway reaches `@ferrogate/policy`'s implementation and none is tempted to
 * restate the dimension precedence.
 */
export function preflightStep(
  budget: StoredWorkflowRunBudget,
  costCredits: number,
  tokens: number,
  toolCalls: number,
  nowUnixSeconds: number,
): PreflightResult {
  return preflightWorkflowBudget(budget, costCredits, tokens, toolCalls, nowUnixSeconds);
}
