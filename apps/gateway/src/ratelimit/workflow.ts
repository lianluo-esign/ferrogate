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
import {
  D1WorkflowBudgetStore,
  type TenantDatabaseHandle,
  workflowRunBudgetId,
} from "@ferrogate/storage";
import type { TenantDatabaseAccessor } from "../tenancy/ports.js";
import { gatewayTenantHandle } from "./wallet.js";

/**
 * PORT-TODO(`server/chat.rs::enforce_ai_workflow_policy`, `agent_runs.rs`):
 * the workflow GRAPH gate is not ported — only the run BUDGET envelope below.
 *
 * `packages/config` parses `[[agent_workflows]]` in full
 * (`schema/config.ts:72`, `validate/policies.ts:64` validates node/edge ids),
 * and `grep -rn "agent_workflows\|agentWorkflows" apps/` returns NOTHING. So a
 * declared workflow is a table the gateway loads, validates and then never
 * consults. Rust refuses a model call from a workflow step it does not
 * recognise, with thirteen distinct codes this tree has none of:
 *
 * | Rust code | status | what it stops |
 * |---|---|---|
 * | `workflow_not_found` | 400 | a step naming an unknown workflow/version |
 * | `workflow_disabled` | 403 | a step in a disabled workflow |
 * | `workflow_not_allowed` | 403 | a key/tenant not entitled to the workflow |
 * | `workflow_node_required` | 400 | `workflow-id` without `workflow-node-id` |
 * | `workflow_node_not_found` | 400 | a node id not in the graph |
 * | `workflow_node_not_model` | 403 | a non-model node dispatching model traffic |
 * | `workflow_model_not_allowed` | 403 | a node calling a model it is not pinned to |
 * | `workflow_provider_not_allowed` | 403 | a node calling an unpinned provider |
 * | `workflow_edge_not_allowed` | 403 | a step that is not a legal transition from the run's last node |
 * | `workflow_model_call_limit_exceeded` | 429 | `max_model_calls` |
 * | `workflow_iteration_limit_exceeded` | 429 | `max_iterations` |
 * | `workflow_timeout_exceeded` | 429 | the workflow wall clock |
 * | `workflow_token_budget_exceeded` | 429 | the workflow token budget |
 *
 * Two consequences beyond the missing refusals. First the HEADERS differ:
 * Rust reads `x-ferrogate-workflow-{id,version,node-id,iteration}` and rejects a
 * malformed set with `400 invalid_workflow_header`; this module reads
 * `x-ferrogate-workflow-{id,version,run-id}` and answers
 * `400 invalid_workflow_declaration`, so `node-id` and `iteration` have no
 * reader at all and a Rust-shaped client is refused. Second, the edge gate is
 * the only thing that makes a workflow a GRAPH rather than a budget: without it
 * a caller inside a legitimate run can call any node's model in any order.
 *
 * Not a platform limit — it is a pure function of the config document plus the
 * run's own event timeline, both of which are already available here
 * (`AgentRunState` holds the timeline in `apps/agent-runtime`). It needs a
 * cross-Worker read (or a Service Binding) for `workflow_edge_transition_error`,
 * which is why it did not fall out of the budget slice.
 */
/** Header carrying `RequestContext.workflow_id`. */
export const WORKFLOW_ID_HEADER = "x-ferrogate-workflow-id";
/** Header carrying `RequestContext.workflow_version`. */
export const WORKFLOW_VERSION_HEADER = "x-ferrogate-workflow-version";
/** Header carrying the run whose execution budget this request spends. */
export const WORKFLOW_RUN_ID_HEADER = "x-ferrogate-workflow-run-id";
/**
 * Rust's run identity — `build_ai_ingress_plan`'s `request.agent_run_id`, the
 * same correlation id `src/assets/handlers.ts` and `apps/mcp/src/protocol.ts`
 * read (#305/#522) and the one `src/inference/workflow.ts`'s graph gate keys
 * on. Accepted here as an ALIAS for {@link WORKFLOW_RUN_ID_HEADER}; see
 * {@link workflowDeclarationFrom}.
 */
export const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";

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
  // THE RUN-ID ALIAS (wave 17 integrate step, applied verbatim from the
  // recipe in `src/inference/workflow.ts`'s "One residue" note).
  //
  // The graph gate takes the run identity from Rust's
  // `x-ferrogate-agent-run-id`; this budget envelope invented
  // `x-ferrogate-workflow-run-id` and required it. A pure reference-shaped
  // client (`-id` + `-version` + `-node-id` + `-agent-run-id`) therefore met
  // THIS middleware first and was answered `400 invalid_workflow_declaration`
  // before the graph gate could run — the graph gate was unreachable for
  // exactly the clients it was ported for. Measured, not assumed: the
  // SELF-driven `test/inference/workflow-mount.test.ts` returned
  // `invalid_workflow_declaration` for every one of its cases before this line.
  //
  // Preferring the TypeScript header keeps every existing budget row's primary
  // key (`workflowRunBudgetId`) stable; falling back to the reference header
  // makes both controls measure ONE run rather than two.
  //
  // The `workflowId === ""` guard is LOAD-BEARING: a plain request carrying
  // `x-ferrogate-agent-run-id` purely for correlation (assets, MCP, #305/#522)
  // must stay `absent`, and an unguarded alias would turn every one of them
  // into a partial declaration, i.e. a 400.
  const workflowRunId = headers.get(WORKFLOW_RUN_ID_HEADER)?.trim() ?? "";
  const runId =
    workflowRunId !== "" || workflowId === ""
      ? workflowRunId
      : (headers.get(AGENT_RUN_ID_HEADER)?.trim() ?? "");

  const present = [workflowId, rawVersion, runId].filter((value) => value !== "");
  if (present.length === 0) return { kind: "absent" };
  if (present.length < 3) {
    return {
      kind: "invalid",
      detail: `a workflow step must declare all three of ${WORKFLOW_ID_HEADER}, ${WORKFLOW_VERSION_HEADER} and ${WORKFLOW_RUN_ID_HEADER}; a partial declaration would run outside the budget it names`,
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

/** The durable source: `D1WorkflowBudgetStore` on the shared `DB` — `"off"` mode. */
export function d1WorkflowBudgetSource(db: D1Database): WorkflowBudgetSource {
  return workflowBudgetSourceOverHandle(async (tenantId) => gatewayTenantHandle(db, tenantId));
}

/**
 * The durable source over the handle the TENANCY RESOLVER produced — the
 * tenant's own Durable Object under the `durable_object` default.
 *
 * The second production call site of `tenantDatabaseOf(c)` (#819), and it is
 * here rather than left for later because the alternative is worse than being
 * incomplete: admission step 3b would read the tenant's object for the wallet
 * while step 5 read the shared `DB` for the workflow budget, in the same
 * middleware, on the same request. Two storage topologies inside one admission
 * decision is how a budget gets enforced against rows nothing writes.
 *
 * `openWorkflowRunBudget` / `debitWorkflowRunBudget` / `topupWorkflowRunBudget`
 * are `requireAtomicBatch()` call sites #6, #7 and #8 of 13, so this moves
 * three more of the money paths onto storage that can actually run them.
 *
 * A resolution failure is `unavailable`, never `unbudgeted`: "the store could
 * not be reached" has not established that this run is uncapped, and answering
 * `unbudgeted` would let an over-budget run through — the same
 * outage-is-not-a-verdict split the wallet guard makes.
 */
export function routedWorkflowBudgetSource(accessor: TenantDatabaseAccessor): WorkflowBudgetSource {
  return workflowBudgetSourceOverHandle(async (tenantId) => {
    const handle = await accessor.handle();
    if (handle.tenantId !== tenantId) {
      throw new Error(
        `the routed tenant database is tenant ${handle.tenantId}'s but this workflow step is ` +
          `tenant ${tenantId}'s; refusing rather than reading another tenant's budget`,
      );
    }
    return handle;
  });
}

/**
 * The shared body of both sources. Extracted so the two differ ONLY in which
 * handle they hand over — the id derivation, the cross-tenant check and the
 * `unavailable` mapping are one implementation.
 */
function workflowBudgetSourceOverHandle(
  resolveHandle: (tenantId: string) => Promise<TenantDatabaseHandle>,
): WorkflowBudgetSource {
  return {
    async forStep(step: WorkflowStepDeclaration, tenantId: string): Promise<WorkflowBudgetLookup> {
      let store: D1WorkflowBudgetStore;
      try {
        store = new D1WorkflowBudgetStore(await resolveHandle(tenantId));
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { kind: "unavailable", detail: `workflow budget lookup failed: ${detail}` };
      }
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
