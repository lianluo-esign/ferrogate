/**
 * `D1WorkflowBudgetStore` — the per-run execution envelope against a REAL D1
 * database (inventory §1.5.3, issue #279).
 *
 * ## Why this one needs a CAS and the wallet does not
 *
 * The wallet's reserve could be expressed as a single conditional INSERT,
 * because "does this fit?" is pure SQL arithmetic over two columns. A workflow
 * debit cannot: the decision is a **multi-dimensional precedence rule**
 * (wall-clock, then cost, then tokens, then tool-calls; `dimensionExceededBy`
 * in `../workflow-budget.ts`) whose outcome is not just admit/refuse but WHICH
 * dimension broke — and a breach must additionally flip the run to `exhausted`
 * *without applying spend*. Encoding that as one SQL predicate would duplicate
 * the precedence rule in two languages, and the two copies would drift.
 *
 * So the decision stays in TypeScript, shared verbatim with the in-memory
 * store, and the *write* is made safe by an **optimistic compare-and-swap**:
 *
 *   1. read the row;
 *   2. run `dimensionExceededBy` on the snapshot;
 *   3. write with a guard asserting the row is still EXACTLY that snapshot —
 *      same status, same three `spent_*` counters, same four caps;
 *   4. an empty `RETURNING` set means somebody committed in between, so
 *      re-read and re-decide (bounded by
 *      {@link WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS}).
 *
 * Because the guarded UPDATE runs inside SQLite's per-database serialized
 * writer, and the increment is `spent_* = spent_* + delta` (not a client-side
 * computed absolute), N concurrent steps against a tool-call budget of K let
 * exactly K through — the same no-overspend property the Postgres `FOR UPDATE`
 * gave, with **no change to the `WorkflowBudgetDebit` contract** (still just
 * `applied` | `exceeded`; no new `conflict` variant leaks to callers).
 *
 * ## The caps are in the guard on purpose
 *
 * Guarding only the counters would be a subtle overspend bug. A debit that
 * decided `exceeded` against a cost cap of 100 must NOT write that verdict if a
 * concurrent top-up raised the cap to 500 in the meantime — the step would be
 * refused (and the run marked exhausted) against a budget that now affords it.
 * Including the four caps in the guard forces a re-decision instead.
 *
 * The cap guard uses `IS`, not `=`: a cap of NULL means "unbounded", and
 * `NULL = NULL` is NULL (never true) in SQL, so `=` would make every
 * unbounded-dimension CAS miss forever and every debit fail after exhausting
 * its retries. `IS` is SQLite's null-safe equality.
 */
import { StorageError } from "../errors.js";
import { workflowRunBudgetId } from "../ids.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import {
  type StoredWorkflowRunBudget,
  WORKFLOW_RUN_BUDGET_ACTIVE,
  WORKFLOW_RUN_BUDGET_EXHAUSTED,
  type WorkflowBudgetDebit,
  type WorkflowRunBudgetCaps,
  applyTopup,
  dimensionExceededBy,
} from "../workflow-budget.js";
import { bindOptional, d1Error, optionalNumber } from "./rows.js";

/**
 * Bounded optimistic-CAS retry ceiling for `debit`/`topup`. Each retry re-reads
 * COMMITTED state and SQLite serializes the writers, so a caller only loses the
 * guard to writers that actually committed; a realistic run has a handful of
 * concurrent steps. Exhausting the ceiling is a fail-closed transient error
 * with NO spend applied — never a lost or duplicated debit.
 *
 * Same value as the Rust `WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS`.
 */
export const WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS = 16;

const COLUMNS =
  "id, workflow_id, workflow_version, run_id, tenant_id, cost_budget_credits, token_budget, " +
  "tool_call_budget, wall_clock_deadline_unix, spent_credits, spent_tokens, spent_tool_calls, " +
  "status, created_at_unix, updated_at_unix";

/**
 * The null-safe guard fragment matching the four cap/deadline columns against
 * the read snapshot. See the module header for why `IS` and not `=`.
 */
const CAP_GUARD =
  "cost_budget_credits IS ? AND token_budget IS ? AND tool_call_budget IS ? " +
  "AND wall_clock_deadline_unix IS ?";

interface BudgetRow {
  id: string;
  workflow_id: string;
  workflow_version: number;
  run_id: string;
  tenant_id: string;
  cost_budget_credits: number | null;
  token_budget: number | null;
  tool_call_budget: number | null;
  wall_clock_deadline_unix: number | null;
  spent_credits: number;
  spent_tokens: number;
  spent_tool_calls: number;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

function budgetFromRow(row: BudgetRow): StoredWorkflowRunBudget {
  const cost = optionalNumber(row.cost_budget_credits);
  const tokens = optionalNumber(row.token_budget);
  const toolCalls = optionalNumber(row.tool_call_budget);
  const deadline = optionalNumber(row.wall_clock_deadline_unix);
  return {
    id: row.id,
    workflowId: row.workflow_id,
    workflowVersion: row.workflow_version,
    runId: row.run_id,
    tenantId: row.tenant_id,
    ...(cost === undefined ? {} : { costBudgetCredits: cost }),
    ...(tokens === undefined ? {} : { tokenBudget: tokens }),
    ...(toolCalls === undefined ? {} : { toolCallBudget: toolCalls }),
    ...(deadline === undefined ? {} : { wallClockDeadlineUnix: deadline }),
    spentCredits: row.spent_credits,
    spentTokens: row.spent_tokens,
    spentToolCalls: row.spent_tool_calls,
    status: row.status as StoredWorkflowRunBudget["status"],
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
  };
}

/** The four cap parameters, in the order {@link CAP_GUARD} binds them. */
function capParams(
  budget: StoredWorkflowRunBudget,
): [number | null, number | null, number | null, number | null] {
  return [
    bindOptional(budget.costBudgetCredits),
    bindOptional(budget.tokenBudget),
    bindOptional(budget.toolCallBudget),
    bindOptional(budget.wallClockDeadlineUnix),
  ];
}

export class D1WorkflowBudgetStore {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Idempotently open a run's envelope. Re-opening returns the existing
   * envelope UNCHANGED — a run's caps are fixed at its first step, so a second
   * `open` with different caps must not silently widen the budget. A different
   * tenant on the same id is a conflict.
   */
  async openWorkflowRunBudget(
    workflowId: string,
    workflowVersion: number,
    runId: string,
    tenantId: string,
    caps: WorkflowRunBudgetCaps,
    nowUnix: number,
  ): Promise<StoredWorkflowRunBudget> {
    requireAtomicBatch(this.handle, "open_workflow_run_budget");
    this.assertTenant(tenantId, "open_workflow_run_budget");
    const id = workflowRunBudgetId(workflowId, workflowVersion, runId);
    try {
      // `ON CONFLICT DO NOTHING` + an unconditional read-back in ONE batch: the
      // insert is idempotent and the read observes whichever row won, so two
      // concurrent opens agree on the same envelope.
      const results = await this.db.batch([
        this.db
          .prepare(
            "INSERT INTO workflow_run_budgets " +
              "(id, workflow_id, workflow_version, run_id, tenant_id, cost_budget_credits, " +
              " token_budget, tool_call_budget, wall_clock_deadline_unix, spent_credits, " +
              " spent_tokens, spent_tool_calls, status, created_at_unix, updated_at_unix) " +
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 'active', ?, ?) " +
              "ON CONFLICT (id) DO NOTHING",
          )
          .bind(
            id,
            workflowId,
            workflowVersion,
            runId,
            tenantId,
            bindOptional(caps.costBudgetCredits),
            bindOptional(caps.tokenBudget),
            bindOptional(caps.toolCallBudget),
            bindOptional(caps.wallClockDeadlineUnix),
            nowUnix,
            nowUnix,
          ),
        this.db.prepare(`SELECT ${COLUMNS} FROM workflow_run_budgets WHERE id = ?`).bind(id),
      ]);
      const row = ((results[1]?.results ?? []) as BudgetRow[])[0];
      if (row === undefined) {
        throw StorageError.runtime(`workflow run budget ${id} did not materialize`);
      }
      const budget = budgetFromRow(row);
      if (budget.tenantId !== tenantId) {
        throw StorageError.conflict(`workflow run budget ${id} already exists for another tenant`);
      }
      return budget;
    } catch (error) {
      if (error instanceof StorageError) throw error;
      throw d1Error("open_workflow_run_budget", error);
    }
  }

  /**
   * Atomically debit one step's spend, fail-closed and no-overspend.
   *
   * An already-exhausted run rejects every debit. A debit breaching any capped
   * dimension is rejected WITHOUT applying spend and marks the run exhausted.
   */
  async debitWorkflowRunBudget(
    id: string,
    costCredits: number,
    tokens: number,
    toolCalls: number,
    nowUnix: number,
  ): Promise<WorkflowBudgetDebit> {
    requireAtomicBatch(this.handle, "debit_workflow_run_budget");
    if (costCredits < 0 || tokens < 0 || toolCalls < 0) {
      throw StorageError.conflict(`workflow run budget ${id} debit amounts must be non-negative`);
    }

    for (let attempt = 0; attempt < WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS; attempt += 1) {
      const read = await this.getWorkflowRunBudget(id);
      if (!read) throw StorageError.notFound(`workflow run budget ${id} does not exist`);

      // An exhausted run rejects everything. `?? "cost"` mirrors the in-memory
      // store: if the exhausted row's numbers happen to fit again (a stale
      // exhaustion), the refusal still names a dimension rather than admitting.
      const breach =
        read.status === WORKFLOW_RUN_BUDGET_EXHAUSTED
          ? (dimensionExceededBy(read, costCredits, tokens, toolCalls, nowUnix) ?? "cost")
          : dimensionExceededBy(read, costCredits, tokens, toolCalls, nowUnix);

      if (breach !== undefined) {
        if (read.status === WORKFLOW_RUN_BUDGET_EXHAUSTED) {
          // Already terminal — nothing to flip, and no spend to apply.
          return { kind: "exceeded", dimension: breach, budget: read };
        }
        const flipped = await this.casFlipExhausted(read, nowUnix);
        if (flipped) return { kind: "exceeded", dimension: breach, budget: flipped };
        continue; // guard missed → re-read and re-decide
      }

      const applied = await this.casApplyDebit(read, costCredits, tokens, toolCalls, nowUnix);
      if (applied) return { kind: "applied", budget: applied };
      // guard missed → re-read and re-decide
    }

    // Fail closed. Exhausting the ceiling means every attempt lost the guard to
    // a writer that committed, so NO spend of ours was applied — this is a
    // transient contention error, not a lost or duplicated debit.
    throw StorageError.conflict(
      `workflow run budget ${id} could not be debited after ` +
        `${WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS} optimistic-CAS attempts under contention`,
    );
  }

  /**
   * Raise an exhausted (or active) run's caps and reactivate it.
   *
   * Guarded on the caps we read, so a concurrent top-up misses and both raises
   * COMPOSE on retry rather than one silently overwriting the other with a
   * stale absolute value.
   */
  async topupWorkflowRunBudget(
    id: string,
    addCostCredits: number,
    addTokens: number,
    addToolCalls: number,
    extendDeadlineUnix: number | undefined,
    nowUnix: number,
  ): Promise<StoredWorkflowRunBudget> {
    requireAtomicBatch(this.handle, "topup_workflow_run_budget");
    for (let attempt = 0; attempt < WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS; attempt += 1) {
      const read = await this.getWorkflowRunBudget(id);
      if (!read) throw StorageError.notFound(`workflow run budget ${id} does not exist`);

      // Compute the next ABSOLUTE caps with the same shared arithmetic the
      // in-memory store uses, so the two backends cannot drift.
      const next: StoredWorkflowRunBudget = { ...read };
      applyTopup(next, addCostCredits, addTokens, addToolCalls, extendDeadlineUnix, nowUnix);

      const written = await this.casWriteCaps(read, next, nowUnix);
      if (written) return written;
    }
    throw StorageError.conflict(
      `workflow run budget ${id} could not be topped up after ` +
        `${WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS} optimistic-CAS attempts under contention`,
    );
  }

  async getWorkflowRunBudget(id: string): Promise<StoredWorkflowRunBudget | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${COLUMNS} FROM workflow_run_budgets WHERE id = ?`)
        .bind(id)
        .first<BudgetRow>();
      return row ? budgetFromRow(row) : undefined;
    } catch (error) {
      throw d1Error("get_workflow_run_budget", error);
    }
  }

  async listWorkflowRunBudgets(tenantId: string): Promise<StoredWorkflowRunBudget[]> {
    try {
      const result = await this.db
        .prepare(
          `SELECT ${COLUMNS} FROM workflow_run_budgets WHERE tenant_id = ?
           ORDER BY created_at_unix DESC, id ASC`,
        )
        .bind(tenantId)
        .all<BudgetRow>();
      return result.results.map(budgetFromRow);
    } catch (error) {
      throw d1Error("list_workflow_run_budgets", error);
    }
  }

  // --- The three guarded CAS statements ------------------------------------

  /**
   * Apply the debit's spend iff the row is still `active` with the EXACT
   * counters and caps we read. The increment is relative (`spent_x + ?`) so
   * that when the guard does match, the value written is derived from the same
   * committed row the guard checked.
   */
  private async casApplyDebit(
    read: StoredWorkflowRunBudget,
    costCredits: number,
    tokens: number,
    toolCalls: number,
    nowUnix: number,
  ): Promise<StoredWorkflowRunBudget | undefined> {
    return this.casReturningBudget("debit_workflow_run_budget", {
      sql: `UPDATE workflow_run_budgets SET
              spent_credits = spent_credits + ?,
              spent_tokens = spent_tokens + ?,
              spent_tool_calls = spent_tool_calls + ?,
              updated_at_unix = ?
            WHERE id = ? AND status = 'active'
              AND spent_credits = ? AND spent_tokens = ? AND spent_tool_calls = ?
              AND ${CAP_GUARD}
            RETURNING ${COLUMNS}`,
      params: [
        costCredits,
        tokens,
        toolCalls,
        nowUnix,
        read.id,
        read.spentCredits,
        read.spentTokens,
        read.spentToolCalls,
        ...capParams(read),
      ],
    });
  }

  /** Mark the run `exhausted` iff it is still the row we read. No spend applied. */
  private async casFlipExhausted(
    read: StoredWorkflowRunBudget,
    nowUnix: number,
  ): Promise<StoredWorkflowRunBudget | undefined> {
    return this.casReturningBudget("debit_workflow_run_budget", {
      sql: `UPDATE workflow_run_budgets SET status = 'exhausted', updated_at_unix = ?
            WHERE id = ? AND status = 'active'
              AND spent_credits = ? AND spent_tokens = ? AND spent_tool_calls = ?
              AND ${CAP_GUARD}
            RETURNING ${COLUMNS}`,
      params: [
        nowUnix,
        read.id,
        read.spentCredits,
        read.spentTokens,
        read.spentToolCalls,
        ...capParams(read),
      ],
    });
  }

  /**
   * Write the recomputed ABSOLUTE caps and reactivate, guarded on the caps
   * still being the ones we read.
   *
   * Note the guard deliberately does NOT include the counters: a top-up must
   * compose with concurrent DEBITS (which move counters but not caps), and only
   * conflict with concurrent TOP-UPS (which move caps).
   */
  private async casWriteCaps(
    read: StoredWorkflowRunBudget,
    next: StoredWorkflowRunBudget,
    nowUnix: number,
  ): Promise<StoredWorkflowRunBudget | undefined> {
    return this.casReturningBudget("topup_workflow_run_budget", {
      sql: `UPDATE workflow_run_budgets SET
              cost_budget_credits = ?, token_budget = ?, tool_call_budget = ?,
              wall_clock_deadline_unix = ?, status = 'active', updated_at_unix = ?
            WHERE id = ? AND ${CAP_GUARD}
            RETURNING ${COLUMNS}`,
      params: [...capParams(next), nowUnix, read.id, ...capParams(read)],
    });
  }

  /** Run one guarded `UPDATE ... RETURNING`; `undefined` == the guard missed. */
  private async casReturningBudget(
    operation: string,
    statement: { sql: string; params: (string | number | null)[] },
  ): Promise<StoredWorkflowRunBudget | undefined> {
    try {
      const row = await this.db
        .prepare(statement.sql)
        .bind(...statement.params)
        .first<BudgetRow>();
      return row ? budgetFromRow(row) : undefined;
    } catch (error) {
      throw d1Error(operation, error);
    }
  }

  private assertTenant(tenantId: string, operation: string): void {
    if (tenantId !== this.handle.tenantId) {
      throw StorageError.runtime(
        `${operation}: tenant ${tenantId} routed to the database of tenant ` +
          `${this.handle.tenantId}; refusing to cross tenant isolation`,
      );
    }
  }
}

/** Re-exported so callers can assert on the same active/exhausted literals. */
export { WORKFLOW_RUN_BUDGET_ACTIVE, WORKFLOW_RUN_BUDGET_EXHAUSTED };
