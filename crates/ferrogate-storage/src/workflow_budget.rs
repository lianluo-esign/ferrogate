// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Workflow-graph-level execution budgets for multi-step agent
// runs (issue #279). Per-request quota (quota_policies) and per-run tool-call
// limits govern one HTTP request only; a multi-step agent run (a workflow graph
// identified by workflow_id@version + run_id) needs a cumulative envelope that
// spans every step's provider calls + tool executions. `workflow_run_budgets`
// is the durable, per-run ledger requests debit against. It mirrors the wallet
// reserve/hold primitive's "serialize on the row, fail-closed on exhaustion,
// idempotent open" shape (issue #281, `wallet.rs`), split into its own file per
// the "one business entity per file" convention.

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneState,
    RuntimeStorageRepositories, StorageError, StorageOperation,
};

/// A run whose envelope still has budget and accepts debits.
pub const WORKFLOW_RUN_BUDGET_ACTIVE: &str = "active";
/// A run that breached a capped dimension; every further debit is denied until
/// a top-up flips it back to [`WORKFLOW_RUN_BUDGET_ACTIVE`].
pub const WORKFLOW_RUN_BUDGET_EXHAUSTED: &str = "exhausted";

/// The distinct fail-closed denial code a caller surfaces when a workflow run's
/// execution budget is exhausted (issue #279). The breached
/// [`WorkflowBudgetDimension`] is the machine-readable detail.
pub const WORKFLOW_BUDGET_EXCEEDED_CODE: &str = "workflow_budget_exceeded";

/// Which dimension of a run's execution envelope a debit would breach. The
/// envelope is multi-dimensional (issue #279): a $-cost ceiling, a token cap, a
/// tool-call count, and a wall-clock deadline are each enforced independently so
/// a run stops on the *first* dimension it exhausts across mixed provider+tool
/// steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowBudgetDimension {
    /// USD-denominated cost, in integer credits (the same unit as the wallet's
    /// `balance_credits`, `ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD`).
    Cost,
    Tokens,
    ToolCalls,
    /// Elapsed wall-clock time: a debit at/after `wall_clock_deadline_unix` is
    /// rejected regardless of the spend counters.
    WallClock,
}

impl WorkflowBudgetDimension {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkflowBudgetDimension::Cost => "cost",
            WorkflowBudgetDimension::Tokens => "tokens",
            WorkflowBudgetDimension::ToolCalls => "tool_calls",
            WorkflowBudgetDimension::WallClock => "wall_clock",
        }
    }

    /// The dimension-qualified denial code, e.g. `workflow_budget_exceeded:cost`
    /// -- a single stable code family so callers can match the whole family or
    /// the exact breached dimension.
    pub fn denial_code(&self) -> String {
        format!("{WORKFLOW_BUDGET_EXCEEDED_CODE}:{}", self.as_str())
    }
}

/// A durable per-workflow-run execution budget (issue #279). One row per
/// (`workflow_id`@`workflow_version`, `run_id`); its `id` is
/// [`workflow_run_budget_id`], deterministic so `open` is idempotent and every
/// step's debit targets the same ledger row. A `None` cap means that dimension
/// is unbounded; the `spent_*` counters accumulate monotonically per debit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWorkflowRunBudget {
    pub id: String,
    pub workflow_id: String,
    pub workflow_version: u32,
    pub run_id: String,
    pub tenant_id: String,
    pub cost_budget_credits: Option<i64>,
    pub token_budget: Option<i64>,
    pub tool_call_budget: Option<i64>,
    pub wall_clock_deadline_unix: Option<i64>,
    pub spent_credits: i64,
    pub spent_tokens: i64,
    pub spent_tool_calls: i64,
    /// [`WORKFLOW_RUN_BUDGET_ACTIVE`] or [`WORKFLOW_RUN_BUDGET_EXHAUSTED`].
    pub status: String,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl StoredWorkflowRunBudget {
    /// Would adding `(cost, tokens, tool_calls)` at time `now` breach a capped
    /// dimension? Returns the FIRST breached dimension (checked cost -> tokens
    /// -> tool_calls -> wall_clock), or `None` if the debit fits. This is the
    /// authoritative fail-closed arithmetic the durable debit path applies under
    /// a row lock; it is also exposed so a caller can pre-flight a step without
    /// mutating the ledger.
    pub fn dimension_exceeded_by(
        &self,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Option<WorkflowBudgetDimension> {
        if let Some(deadline) = self.wall_clock_deadline_unix {
            if now_unix >= deadline {
                return Some(WorkflowBudgetDimension::WallClock);
            }
        }
        if let Some(cap) = self.cost_budget_credits {
            if self.spent_credits.saturating_add(cost_credits) > cap {
                return Some(WorkflowBudgetDimension::Cost);
            }
        }
        if let Some(cap) = self.token_budget {
            if self.spent_tokens.saturating_add(tokens) > cap {
                return Some(WorkflowBudgetDimension::Tokens);
            }
        }
        if let Some(cap) = self.tool_call_budget {
            if self.spent_tool_calls.saturating_add(tool_calls) > cap {
                return Some(WorkflowBudgetDimension::ToolCalls);
            }
        }
        None
    }
}

/// The caps to seed a run's envelope with at `open` time. A `None` field leaves
/// that dimension unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkflowRunBudgetCaps {
    pub cost_budget_credits: Option<i64>,
    pub token_budget: Option<i64>,
    pub tool_call_budget: Option<i64>,
    pub wall_clock_deadline_unix: Option<i64>,
}

/// Outcome of [`RuntimeStorageRepositories::debit_workflow_run_budget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowBudgetDebit {
    /// The step's spend fit; the returned budget reflects the applied debit.
    Applied(StoredWorkflowRunBudget),
    /// The step would breach `dimension`; NO spend was applied and the run is
    /// now `exhausted` (fail-closed). The returned budget is the unchanged
    /// counters plus the flipped status.
    Exceeded {
        dimension: WorkflowBudgetDimension,
        budget: StoredWorkflowRunBudget,
    },
}

/// Deterministic id for a run's budget row: idempotent `open` of the same
/// (workflow, run) is a no-op that returns the existing envelope, and every
/// step's debit resolves to the same row. Mirrors `payment_method_id`'s
/// compose-from-owning-entity id scheme.
pub fn workflow_run_budget_id(workflow_id: &str, workflow_version: u32, run_id: &str) -> String {
    format!("{workflow_id}:{workflow_version}:{run_id}")
}

/// Column list shared by every `workflow_run_budgets` read so the positional
/// [`workflow_run_budget_from_row`] indices stay in lockstep.
const WORKFLOW_RUN_BUDGET_COLUMNS: &str = "id, workflow_id, workflow_version, run_id, tenant_id, \
     cost_budget_credits, token_budget, tool_call_budget, wall_clock_deadline_unix, \
     spent_credits, spent_tokens, spent_tool_calls, status, created_at_unix, updated_at_unix";

fn workflow_run_budget_from_row(row: &PostgresRow) -> StoredWorkflowRunBudget {
    let workflow_version: i64 = row.get(2);
    StoredWorkflowRunBudget {
        id: row.get(0),
        workflow_id: row.get(1),
        workflow_version: workflow_version as u32,
        run_id: row.get(3),
        tenant_id: row.get(4),
        cost_budget_credits: row.get(5),
        token_budget: row.get(6),
        tool_call_budget: row.get(7),
        wall_clock_deadline_unix: row.get(8),
        spent_credits: row.get(9),
        spent_tokens: row.get(10),
        spent_tool_calls: row.get(11),
        status: row.get(12),
        created_at_unix: row.get(13),
        updated_at_unix: row.get(14),
    }
}

impl PostgresControlPlaneStore {
    fn workflow_budget_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    /// Idempotently opens a run's execution budget with `caps`. Re-opening the
    /// same (workflow, run) returns the existing envelope UNCHANGED -- a run's
    /// caps are fixed at its first step, so a later step re-declaring different
    /// caps can never widen (or narrow) an in-flight run's ceiling.
    pub(super) async fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        let id = workflow_run_budget_id(workflow_id, workflow_version, run_id);
        let operation = self.workflow_budget_operation("open workflow run budget");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) as the
        // FIRST statement so `workflow_run_budgets` resolves in the same schema
        // every other control-plane accessor uses (see `wallet.rs`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let workflow_version_i64 = workflow_version as i64;
        transaction
            .execute(
                "INSERT INTO workflow_run_budgets \
                 (id, workflow_id, workflow_version, run_id, tenant_id, cost_budget_credits, \
                  token_budget, tool_call_budget, wall_clock_deadline_unix, spent_credits, \
                  spent_tokens, spent_tool_calls, status, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 0, 0, 'active', $10, $10) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &id,
                    &workflow_id,
                    &workflow_version_i64,
                    &run_id,
                    &tenant_id,
                    &caps.cost_budget_credits,
                    &caps.token_budget,
                    &caps.tool_call_budget,
                    &caps.wall_clock_deadline_unix,
                    &now_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        let row = transaction
            .query_one(
                &format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets WHERE id = $1"
                ),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        let budget = workflow_run_budget_from_row(&row);
        transaction.commit().await.map_err(postgres_error)?;
        if budget.tenant_id != tenant_id {
            return Err(StorageError::Conflict(format!(
                "workflow run budget {id} already exists for another tenant"
            )));
        }
        Ok(budget)
    }

    /// Atomically debits one step's spend against a run's envelope (issue #279).
    /// Serializes concurrent steps for a run by taking a `SELECT ... FOR UPDATE`
    /// row lock before reading the counters, so N parallel debits against a
    /// tool-call budget of K let exactly K through -- no overspend, the wallet
    /// reservation no-oversell property (#281). Fail-closed: if the debit would
    /// breach a capped dimension (or the run is already `exhausted`), NO spend is
    /// applied, the run is marked `exhausted`, and `Exceeded { dimension }` is
    /// returned. `Err(NotFound)` if the run has no budget row (open first).
    pub(super) async fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        if cost_credits < 0 || tokens < 0 || tool_calls < 0 {
            return Err(StorageError::Conflict(format!(
                "workflow run budget {id} debit amounts must be non-negative"
            )));
        }
        let operation = self.workflow_budget_operation("debit workflow run budget");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets \
                     WHERE id = $1 FOR UPDATE"
                ),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };
        let mut budget = workflow_run_budget_from_row(&row);

        // Fail closed: an already-exhausted run rejects every debit until a
        // top-up reactivates it, and a debit that would breach any dimension is
        // rejected WITHOUT applying spend.
        let breach = if budget.status == WORKFLOW_RUN_BUDGET_EXHAUSTED {
            Some(
                budget
                    .dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix)
                    .unwrap_or(WorkflowBudgetDimension::Cost),
            )
        } else {
            budget.dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix)
        };
        if let Some(dimension) = breach {
            if budget.status != WORKFLOW_RUN_BUDGET_EXHAUSTED {
                transaction
                    .execute(
                        "UPDATE workflow_run_budgets SET status = 'exhausted', \
                         updated_at_unix = $2 WHERE id = $1",
                        &[&id, &now_unix],
                    )
                    .await
                    .map_err(postgres_error)?;
                budget.status = WORKFLOW_RUN_BUDGET_EXHAUSTED.to_string();
                budget.updated_at_unix = now_unix;
            }
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(WorkflowBudgetDebit::Exceeded { dimension, budget });
        }

        budget.spent_credits = budget.spent_credits.saturating_add(cost_credits);
        budget.spent_tokens = budget.spent_tokens.saturating_add(tokens);
        budget.spent_tool_calls = budget.spent_tool_calls.saturating_add(tool_calls);
        budget.updated_at_unix = now_unix;
        transaction
            .execute(
                "UPDATE workflow_run_budgets SET spent_credits = $2, spent_tokens = $3, \
                 spent_tool_calls = $4, updated_at_unix = $5 WHERE id = $1",
                &[
                    &id,
                    &budget.spent_credits,
                    &budget.spent_tokens,
                    &budget.spent_tool_calls,
                    &now_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(WorkflowBudgetDebit::Applied(budget))
    }

    /// Tops up an exhausted (or active) run's envelope: adds the provided
    /// deltas to each capped dimension and flips `status` back to `active`, so a
    /// run stopped on budget exhaustion resumes after the top-up (issue #279's
    /// resumable-after-top-up acceptance). Topping up an unbounded (`None`) cap
    /// is a no-op for that dimension. `Err(NotFound)` if the run is unknown.
    pub(super) async fn topup_workflow_run_budget(
        &self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        let operation = self.workflow_budget_operation("topup workflow run budget");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets \
                     WHERE id = $1 FOR UPDATE"
                ),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };
        let mut budget = workflow_run_budget_from_row(&row);
        apply_topup(
            &mut budget,
            add_cost_credits,
            add_tokens,
            add_tool_calls,
            extend_deadline_unix,
            now_unix,
        );
        transaction
            .execute(
                "UPDATE workflow_run_budgets SET cost_budget_credits = $2, token_budget = $3, \
                 tool_call_budget = $4, wall_clock_deadline_unix = $5, status = 'active', \
                 updated_at_unix = $6 WHERE id = $1",
                &[
                    &id,
                    &budget.cost_budget_credits,
                    &budget.token_budget,
                    &budget.tool_call_budget,
                    &budget.wall_clock_deadline_unix,
                    &now_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(budget)
    }

    pub(super) async fn get_workflow_run_budget(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let operation = self.workflow_budget_operation("get workflow run budget");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets WHERE id = $1"
                ),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(workflow_run_budget_from_row))
    }

    pub(super) async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        let operation = self.workflow_budget_operation("list workflow run budgets");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                &format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets \
                     WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(workflow_run_budget_from_row).collect())
    }
}

/// Shared top-up arithmetic used by both backends: add the deltas to each
/// capped dimension (a `None` cap stays unbounded), extend the deadline to the
/// later of the current and requested value, and reactivate the run.
fn apply_topup(
    budget: &mut StoredWorkflowRunBudget,
    add_cost_credits: i64,
    add_tokens: i64,
    add_tool_calls: i64,
    extend_deadline_unix: Option<i64>,
    now_unix: i64,
) {
    if let Some(cap) = budget.cost_budget_credits.as_mut() {
        *cap = cap.saturating_add(add_cost_credits);
    }
    if let Some(cap) = budget.token_budget.as_mut() {
        *cap = cap.saturating_add(add_tokens);
    }
    if let Some(cap) = budget.tool_call_budget.as_mut() {
        *cap = cap.saturating_add(add_tool_calls);
    }
    if let Some(deadline) = extend_deadline_unix {
        budget.wall_clock_deadline_unix = Some(match budget.wall_clock_deadline_unix {
            Some(existing) => existing.max(deadline),
            None => deadline,
        });
    }
    budget.status = WORKFLOW_RUN_BUDGET_ACTIVE.to_string();
    budget.updated_at_unix = now_unix;
}

impl RuntimeControlPlaneState {
    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::open_workflow_run_budget`] (issue #279).
    pub fn open_workflow_run_budget(
        &mut self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        let id = workflow_run_budget_id(workflow_id, workflow_version, run_id);
        if let Some(existing) = self.workflow_run_budgets.get(&id) {
            if existing.tenant_id != tenant_id {
                return Err(StorageError::Conflict(format!(
                    "workflow run budget {id} already exists for another tenant"
                )));
            }
            return Ok(existing);
        }
        let budget = StoredWorkflowRunBudget {
            id: id.clone(),
            workflow_id: workflow_id.to_string(),
            workflow_version,
            run_id: run_id.to_string(),
            tenant_id: tenant_id.to_string(),
            cost_budget_credits: caps.cost_budget_credits,
            token_budget: caps.token_budget,
            tool_call_budget: caps.tool_call_budget,
            wall_clock_deadline_unix: caps.wall_clock_deadline_unix,
            spent_credits: 0,
            spent_tokens: 0,
            spent_tool_calls: 0,
            status: WORKFLOW_RUN_BUDGET_ACTIVE.to_string(),
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
        };
        self.workflow_run_budgets.insert(id, budget.clone());
        Ok(budget)
    }

    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::debit_workflow_run_budget`] (issue #279).
    /// The `RuntimeStorageRepositories` mutex that guards this state serializes
    /// concurrent debiters -- the no-overspend guarantee the Postgres
    /// `FOR UPDATE` row lock provides.
    pub fn debit_workflow_run_budget(
        &mut self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        if cost_credits < 0 || tokens < 0 || tool_calls < 0 {
            return Err(StorageError::Conflict(format!(
                "workflow run budget {id} debit amounts must be non-negative"
            )));
        }
        let Some(mut budget) = self.workflow_run_budgets.get(id) else {
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };
        let breach = if budget.status == WORKFLOW_RUN_BUDGET_EXHAUSTED {
            Some(
                budget
                    .dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix)
                    .unwrap_or(WorkflowBudgetDimension::Cost),
            )
        } else {
            budget.dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix)
        };
        if let Some(dimension) = breach {
            budget.status = WORKFLOW_RUN_BUDGET_EXHAUSTED.to_string();
            budget.updated_at_unix = now_unix;
            self.workflow_run_budgets
                .insert(id.to_string(), budget.clone());
            return Ok(WorkflowBudgetDebit::Exceeded { dimension, budget });
        }
        budget.spent_credits = budget.spent_credits.saturating_add(cost_credits);
        budget.spent_tokens = budget.spent_tokens.saturating_add(tokens);
        budget.spent_tool_calls = budget.spent_tool_calls.saturating_add(tool_calls);
        budget.updated_at_unix = now_unix;
        self.workflow_run_budgets
            .insert(id.to_string(), budget.clone());
        Ok(WorkflowBudgetDebit::Applied(budget))
    }

    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::topup_workflow_run_budget`] (issue #279).
    pub fn topup_workflow_run_budget(
        &mut self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        let Some(mut budget) = self.workflow_run_budgets.get(id) else {
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };
        apply_topup(
            &mut budget,
            add_cost_credits,
            add_tokens,
            add_tool_calls,
            extend_deadline_unix,
            now_unix,
        );
        self.workflow_run_budgets
            .insert(id.to_string(), budget.clone());
        Ok(budget)
    }

    pub fn get_workflow_run_budget(&self, id: &str) -> Option<StoredWorkflowRunBudget> {
        self.workflow_run_budgets.get(id)
    }

    pub fn list_workflow_run_budgets(&self, tenant_id: &str) -> Vec<StoredWorkflowRunBudget> {
        let mut budgets: Vec<StoredWorkflowRunBudget> = self
            .workflow_run_budgets
            .list()
            .into_iter()
            .filter(|budget| budget.tenant_id == tenant_id)
            .collect();
        budgets.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        budgets
    }
}

impl RuntimeStorageRepositories {
    /// Idempotently opens a workflow run's durable execution budget (issue
    /// #279). Re-opening returns the existing envelope unchanged on both
    /// backends -- see [`PostgresControlPlaneStore::open_workflow_run_budget`].
    pub async fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.control_plane
            .store()
            .open_workflow_run_budget(
                workflow_id,
                workflow_version,
                run_id,
                tenant_id,
                caps,
                now_unix,
            )
            .await
    }

    /// Atomically debits one step's spend against a run's envelope, fail-closed
    /// and no-overspend across concurrent steps on both backends (issue #279).
    pub async fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        self.control_plane
            .store()
            .debit_workflow_run_budget(id, cost_credits, tokens, tool_calls, now_unix)
            .await
    }

    /// Raises an exhausted run's caps and reactivates it so it resumes after a
    /// budget top-up (issue #279).
    pub async fn topup_workflow_run_budget(
        &self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.control_plane
            .store()
            .topup_workflow_run_budget(
                id,
                add_cost_credits,
                add_tokens,
                add_tool_calls,
                extend_deadline_unix,
                now_unix,
            )
            .await
    }

    pub async fn get_workflow_run_budget(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        self.control_plane.store().get_workflow_run_budget(id).await
    }

    /// Lists a tenant's run budgets newest-first for the admin budget view
    /// (issue #279's "budget state visible in the Admin API").
    pub async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        self.control_plane
            .store()
            .list_workflow_run_budgets(tenant_id)
            .await
    }
}
