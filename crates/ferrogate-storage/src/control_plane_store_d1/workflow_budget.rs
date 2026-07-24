// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped workflow-run execution budgets (issue #456/#279).

//! D1 backend: tenant-scoped workflow-run execution budgets (issue #456/#279).
//!
//! The durable per-workflow-run execution envelope (issue #279) on the
//! database-per-tenant D1 topology. Like the wallet/usage/asset families
//! (issues #455/#456), a run's budget row lives in its OWNING tenant's own D1
//! database — never the control database — so every op routes through the
//! proxy-Worker binding (issue #450) selected onto a per-tenant
//! `[[d1_databases]]` binding (`tenant_database_binding`). A REST-only
//! deployment leaves the atomic `debit`/`topup` fail-closed with the typed
//! unimplemented-surface error, exactly like the sibling atomic families.
//!
//! ## The concurrency contract — optimistic CAS, [`WorkflowBudgetDebit`] UNCHANGED
//!
//! The Postgres backend serializes concurrent steps of a run with
//! `SELECT ... FOR UPDATE` (`workflow_budget.rs`). D1/SQLite has **no row lock**,
//! so `debit_workflow_run_budget` instead uses an **internal bounded
//! optimistic-CAS retry**: it reads the counters, decides `Applied`/`Exceeded`
//! exactly as Postgres does (via the SHARED [`StoredWorkflowRunBudget::
//! dimension_exceeded_by`] arithmetic), then issues a guarded
//! `UPDATE ... WHERE <every field the decision read is unchanged> RETURNING`
//! through the proxy `/d1/query` binding. Because the write only lands when the
//! guard still matches the read, and `spent_* = spent_* + delta` runs inside
//! SQLite's per-database serialized writer, a debit can NEVER be lost or
//! overspend: an EMPTY `RETURNING` set means a concurrent debit/top-up committed
//! between the read and the guarded update (the lost-update signal the REST query
//! API cannot give), on which the impl re-reads the committed state and retries.
//! So N concurrent steps against a tool-call budget of K let exactly K through —
//! the same no-overspend property the Postgres row lock provides — while the
//! public [`WorkflowBudgetDebit`] contract stays `Applied`/`Exceeded` with ZERO
//! caller changes (no new `Conflict` variant, so no non-exhaustive-match hazard
//! across crates, the issue #415 regression rule). Contention is resolved
//! INTERNALLY into `Applied`/`Exceeded`; the bounded loop's exhaustion branch is
//! a fail-closed backstop (a transient error, never a lost or duplicated debit)
//! that is practically unreachable because each retry re-reads a committed state
//! and SQLite serializes the writers — it is NOT a normal outcome.
//!
//! The CAS guard covers the FULL decision read-set — `status`, the three
//! `spent_*` counters, AND the four cap/deadline columns — because a debit's
//! fail-closed branch flips ONLY `status` (not counters), a concurrent top-up
//! raises ONLY caps (not counters), and the fit/breach decision depends on all
//! three groups; guarding every one forces a faithful re-evaluation against fresh
//! committed state on any concurrent mutation. `top-up` reuses the SAME shared
//! [`apply_topup`](crate::workflow_budget::apply_topup) arithmetic as Postgres/memory under its own
//! caps-guarded CAS-retry, so the raised envelope is row-for-row identical across
//! backends.
//!
//! ## Routing / divergence (database-per-tenant)
//!
//! - `open`/`list` carry a `tenant_id`, so they route straight to that tenant's
//!   own binding. `open` is a tenant-DB WRITE (an INSERT), so an UNPROVISIONED
//!   tenant is a typed `NotFound` — the same divergence `reserve`/`persist`
//!   make, where Postgres would just insert. `list` is an opt-in READ: an
//!   unprovisioned tenant is EMPTY, not an error (matching `list_wallets`-style
//!   reads).
//! - `debit`/`topup`/`get` carry only the run's `id` (no tenant), so they FAN OUT
//!   over the provisioned tenant bindings to locate the database holding the row
//!   (the established id-only-read locate the wallet family uses), then act on it.
//!   An unknown id is `NotFound` (`debit`/`topup`) or `Ok(None)` (`get`).
//!
//! ## Numeric affinity (issue #455 lesson)
//!
//! The proxy binds ALL params as TEXT. Every bound numeric param that enters an
//! ARITHMETIC comparison or sum against an INTEGER column is wrapped
//! `CAST(? AS INTEGER)` (the debit fit-guard counters, the increment/top-up
//! sums, the deadline `max`), and nullable-cap guards use
//! `col IS CAST(NULLIF(?, '') AS INTEGER)` for null-safe, affinity-correct
//! comparison. Stored cap writes ride `NULLIF(?, '')` (column affinity coerces
//! the TEXT on write, so no CAST is needed there — same as `upsert_wallet`).

use serde::de::DeserializeOwned;

use super::*;

/// Column list shared by every `workflow_run_budgets` read, kept in lockstep with
/// [`WorkflowRunBudgetD1Row`] and the Postgres `WORKFLOW_RUN_BUDGET_COLUMNS`
/// projection order.
const WORKFLOW_RUN_BUDGET_COLUMNS: &str = "id, workflow_id, workflow_version, run_id, tenant_id, \
     cost_budget_credits, token_budget, tool_call_budget, wall_clock_deadline_unix, \
     spent_credits, spent_tokens, spent_tool_calls, status, created_at_unix, updated_at_unix";

/// Bounded optimistic-CAS retry ceiling for `debit`/`topup`. Each retry re-reads a
/// COMMITTED state and SQLite serializes the writers, so a given caller loses the
/// guard only to writers that actually committed; a realistic workflow run has a
/// handful of concurrent steps, so this ceiling is never approached in practice.
/// Exhausting it is a fail-closed transient error (no spend applied), not a lost
/// or duplicated debit.
const WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS: usize = 16;

/// One `workflow_run_budgets` row (SQLite integer affinities decoded back to the
/// `Stored*` shape, mirroring the Postgres `workflow_run_budget_from_row`).
#[derive(serde::Deserialize)]
struct WorkflowRunBudgetD1Row {
    id: String,
    workflow_id: String,
    workflow_version: i64,
    run_id: String,
    tenant_id: String,
    cost_budget_credits: Option<i64>,
    token_budget: Option<i64>,
    tool_call_budget: Option<i64>,
    wall_clock_deadline_unix: Option<i64>,
    spent_credits: i64,
    spent_tokens: i64,
    spent_tool_calls: i64,
    status: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<WorkflowRunBudgetD1Row> for StoredWorkflowRunBudget {
    fn from(row: WorkflowRunBudgetD1Row) -> Self {
        Self {
            id: row.id,
            workflow_id: row.workflow_id,
            workflow_version: row.workflow_version as u32,
            run_id: row.run_id,
            tenant_id: row.tenant_id,
            cost_budget_credits: row.cost_budget_credits,
            token_budget: row.token_budget,
            tool_call_budget: row.tool_call_budget,
            wall_clock_deadline_unix: row.wall_clock_deadline_unix,
            spent_credits: row.spent_credits,
            spent_tokens: row.spent_tokens,
            spent_tool_calls: row.spent_tool_calls,
            status: row.status,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// Deserialize one D1 result row (`serde_json::Value` keyed by column) into a
/// typed DTO.
fn decode_row<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, StorageError> {
    serde_json::from_value(value.clone())
        .map_err(|error| StorageError::Serialization(error.to_string()))
}

/// The four nullable cap/deadline columns as bound params (`""` = SQL NULL), in
/// the fixed order the CAS guards and the top-up write bind them.
fn cap_params(budget: &StoredWorkflowRunBudget) -> [String; 4] {
    [
        optional_number_param(budget.cost_budget_credits),
        optional_number_param(budget.token_budget),
        optional_number_param(budget.tool_call_budget),
        optional_number_param(budget.wall_clock_deadline_unix),
    ]
}

/// The null-safe, affinity-correct guard fragment matching the four cap/deadline
/// columns against the read snapshot (`col IS CAST(NULLIF(?, '') AS INTEGER)`).
/// A concurrent top-up that changed any cap makes this miss, forcing a re-read.
const CAP_GUARD_SQL: &str = "cost_budget_credits IS CAST(NULLIF(?, '') AS INTEGER) \
     AND token_budget IS CAST(NULLIF(?, '') AS INTEGER) \
     AND tool_call_budget IS CAST(NULLIF(?, '') AS INTEGER) \
     AND wall_clock_deadline_unix IS CAST(NULLIF(?, '') AS INTEGER)";

impl D1ControlPlaneStore {
    // --- Workflow-run execution budgets over the proxy binding, tenant-DB routed
    // (issue #456/#279) ---

    /// Idempotently open a run's execution budget with `caps` on the OWNING
    /// tenant's D1 database (issue #279). Re-opening the same (workflow, run)
    /// returns the existing envelope UNCHANGED — a run's caps are fixed at its
    /// first step. Runs as one atomic `/d1/batch`: an `INSERT ... ON CONFLICT DO
    /// NOTHING` (the deterministic id makes a replay a no-op) followed by a
    /// read-back for the durable row, mirroring the Postgres insert-then-reload.
    ///
    /// Divergence: an UNPROVISIONED tenant (no tenant DB to write) is a typed
    /// `NotFound` — the database-per-tenant divergence the tenant-scoped writes
    /// (`reserve`, `persist_usage_aggregate`) make, where Postgres would insert.
    pub(super) async fn open_workflow_run_budget_d1_async(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        let proxy = self.proxy_client("open_workflow_run_budget")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        let id = workflow_run_budget_id(workflow_id, workflow_version, run_id);
        let now = now_unix.to_string();

        let statements = vec![
            // S0: idempotent open. Caps are STORED values (column affinity coerces
            // the bound TEXT to INTEGER on write), so `NULLIF(?, '')` needs no CAST
            // — same as `upsert_wallet`; `spent_*` seed to literal 0.
            D1ProxyStatement::with_params(
                "INSERT INTO workflow_run_budgets \
                 (id, workflow_id, workflow_version, run_id, tenant_id, cost_budget_credits, \
                  token_budget, tool_call_budget, wall_clock_deadline_unix, spent_credits, \
                  spent_tokens, spent_tool_calls, status, created_at_unix, updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), \
                  NULLIF(?, ''), 0, 0, 0, 'active', ?, ?) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    id.clone(),
                    workflow_id.to_string(),
                    i64::from(workflow_version).to_string(),
                    run_id.to_string(),
                    tenant_id.to_string(),
                    optional_number_param(caps.cost_budget_credits),
                    optional_number_param(caps.token_budget),
                    optional_number_param(caps.tool_call_budget),
                    optional_number_param(caps.wall_clock_deadline_unix),
                    now.clone(),
                    now.clone(),
                ],
            ),
            // S1: read back the durable row (ours, or the pre-existing envelope on
            // an idempotent replay) inside the same implicit transaction.
            D1ProxyStatement::with_params(
                format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets WHERE id = ?"
                ),
                vec![id.clone()],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: open_workflow_run_budget batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        let Some(row) = results[1].results.first() else {
            return Err(StorageError::Runtime(format!(
                "cloudflare d1: workflow run budget {id} vanished inside its open batch"
            )));
        };
        let budget: StoredWorkflowRunBudget = decode_row::<WorkflowRunBudgetD1Row>(row)?.into();
        if budget.tenant_id != tenant_id {
            return Err(StorageError::Conflict(format!(
                "workflow run budget {id} already exists for another tenant"
            )));
        }
        Ok(budget)
    }

    /// Atomically debit one step's spend against a run's envelope, fail-closed and
    /// no-overspend across concurrent steps (issue #279), via the internal bounded
    /// optimistic-CAS retry documented on this module. Fans out to locate the
    /// tenant database holding the run, then read-decides-`Applied`/`Exceeded`
    /// exactly as Postgres does and commits it with a guarded `UPDATE ...
    /// RETURNING`. `Err(NotFound)` if the run has no budget row (open first).
    pub(super) async fn debit_workflow_run_budget_d1_async(
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
        // Fail closed BEFORE any network round trip when no proxy is bound (the
        // atomic CAS cannot be served over the REST query API).
        self.proxy_client("debit_workflow_run_budget")?;
        let Some((binding, mut budget)) = self
            .locate_workflow_run_budget("debit_workflow_run_budget", id)
            .await?
        else {
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };

        for _ in 0..WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS {
            // Fail closed: an already-exhausted run rejects every debit until a
            // top-up reactivates it, and a debit that would breach any dimension
            // is rejected WITHOUT applying spend. This is the SHARED Postgres/
            // memory arithmetic, so the outcome is identical across backends.
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
                // An already-exhausted run needs no write: return the read row.
                // Reading a committed-exhausted state and returning `Exceeded`
                // without writing is a valid serialization (debit-before-topup)
                // and, crucially, never clobbers a concurrent reactivation.
                if budget.status == WORKFLOW_RUN_BUDGET_EXHAUSTED {
                    return Ok(WorkflowBudgetDebit::Exceeded { dimension, budget });
                }
                // Guarded flip active -> exhausted. The FULL-field guard makes a
                // concurrent top-up (which raises caps, keeping counters + active)
                // miss, so a debit that would now FIT re-reads and applies instead
                // of clobbering the raise.
                match self
                    .cas_flip_workflow_run_budget_exhausted(&binding, &budget, now_unix)
                    .await?
                {
                    Some(flipped) => {
                        return Ok(WorkflowBudgetDebit::Exceeded {
                            dimension,
                            budget: flipped,
                        })
                    }
                    None => {
                        budget = self.reload_or_vanished(&binding, id).await?;
                        continue;
                    }
                }
            }

            // No breach: guarded increment. `spent_* = spent_* + CAST(?)` inside
            // the serialized writer plus the counters+status+caps guard = the
            // no-lost-debit / no-overspend commit.
            match self
                .cas_apply_workflow_run_budget_debit(
                    &binding,
                    &budget,
                    cost_credits,
                    tokens,
                    tool_calls,
                    now_unix,
                )
                .await?
            {
                Some(applied) => return Ok(WorkflowBudgetDebit::Applied(applied)),
                None => {
                    budget = self.reload_or_vanished(&binding, id).await?;
                    continue;
                }
            }
        }

        // Practically unreachable (see the module docs): a fail-closed transient
        // error after exhausting the retry budget, NOT a lost or duplicated debit.
        Err(StorageError::Runtime(format!(
            "workflow run budget {id} debit could not commit after \
             {WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS} optimistic-CAS attempts under contention"
        )))
    }

    /// Raise an exhausted (or active) run's caps and reactivate it so it resumes
    /// after a budget top-up (issue #279). Fans out to locate the tenant database,
    /// then applies the SHARED [`apply_topup`](crate::workflow_budget::apply_topup) arithmetic under
    /// a caps-guarded CAS-retry so a concurrent top-up composes instead of being
    /// lost. `Err(NotFound)` if the run is unknown.
    pub(super) async fn topup_workflow_run_budget_d1_async(
        &self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.proxy_client("topup_workflow_run_budget")?;
        let Some((binding, mut budget)) = self
            .locate_workflow_run_budget("topup_workflow_run_budget", id)
            .await?
        else {
            return Err(StorageError::NotFound(format!(
                "workflow run budget {id} does not exist"
            )));
        };

        for _ in 0..WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS {
            let mut next = budget.clone();
            crate::workflow_budget::apply_topup(
                &mut next,
                add_cost_credits,
                add_tokens,
                add_tool_calls,
                extend_deadline_unix,
                now_unix,
            );
            // Guard on the READ caps unchanged: a concurrent top-up (the only op
            // that mutates caps) misses and forces a re-read so both raises
            // compose; a concurrent debit touches only counters/status, which the
            // top-up rewrites regardless, so those are not guarded.
            match self
                .cas_write_workflow_run_budget_caps(&binding, &budget, &next, now_unix)
                .await?
            {
                Some(written) => return Ok(written),
                None => {
                    budget = self.reload_or_vanished(&binding, id).await?;
                    continue;
                }
            }
        }

        Err(StorageError::Runtime(format!(
            "workflow run budget {id} top-up could not commit after \
             {WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS} optimistic-CAS attempts under contention"
        )))
    }

    /// Read one run's budget by id (issue #279). The signature carries no tenant,
    /// so this FANS OUT over the provisioned tenant bindings and returns the first
    /// match (the deterministic id keeps the row globally unique, so at most one
    /// binding answers); `Ok(None)` when none does. Fails closed without a proxy.
    pub(super) async fn get_workflow_run_budget_d1_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        self.proxy_client("get_workflow_run_budget")?;
        Ok(self
            .locate_workflow_run_budget("get_workflow_run_budget", id)
            .await?
            .map(|(_binding, budget)| budget))
    }

    /// List a tenant's run budgets newest-first (issue #279's admin budget view).
    /// The signature carries the `tenant_id`, so this routes straight to that
    /// tenant's own database and orders `created_at_unix DESC, id ASC` to match
    /// Postgres row-for-row. Opt-in: an unprovisioned tenant is EMPTY (matching
    /// `list_wallets`-style reads), not an error. Fails closed without a proxy.
    pub(super) async fn list_workflow_run_budgets_d1_async(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        let proxy = self.proxy_client("list_workflow_run_budgets")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = D1ProxyStatement::with_params(
            format!(
                "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets \
                 WHERE tenant_id = ? ORDER BY created_at_unix DESC, id ASC"
            ),
            vec![tenant_id.to_string()],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<WorkflowRunBudgetD1Row>(row).map(StoredWorkflowRunBudget::from))
            .collect()
    }

    // --- tenant-DB helpers ---

    /// Fan out over the provisioned tenant bindings to find the database holding
    /// `id`, returning `(binding, budget)` or `None`.
    async fn locate_workflow_run_budget(
        &self,
        method: &'static str,
        id: &str,
    ) -> Result<Option<(String, StoredWorkflowRunBudget)>, StorageError> {
        let proxy = self.proxy_client(method)?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!(
                    "SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets WHERE id = ?"
                ),
                vec![id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if let Some(row) = result.results.first() {
                let budget: StoredWorkflowRunBudget =
                    decode_row::<WorkflowRunBudgetD1Row>(row)?.into();
                return Ok(Some((binding, budget)));
            }
        }
        Ok(None)
    }

    /// Re-read the run's row on a known binding after a guard miss. A workflow
    /// budget is never deleted, so a `None` here means the row vanished under an
    /// operator action; surface it as `NotFound` rather than spinning.
    async fn reload_or_vanished(
        &self,
        binding: &str,
        id: &str,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.load_workflow_run_budget_on(binding, id)
            .await?
            .ok_or_else(|| {
                StorageError::NotFound(format!("workflow run budget {id} does not exist"))
            })
    }

    /// Single-row read on a specific tenant binding.
    async fn load_workflow_run_budget_on(
        &self,
        binding: &str,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let proxy = self.proxy_client("debit_workflow_run_budget")?;
        let statement = D1ProxyStatement::with_params(
            format!("SELECT {WORKFLOW_RUN_BUDGET_COLUMNS} FROM workflow_run_budgets WHERE id = ?"),
            vec![id.to_string()],
        );
        let result = proxy
            .query_on(Some(binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WorkflowRunBudgetD1Row>(row).map(StoredWorkflowRunBudget::from))
            .transpose()
    }

    /// The guarded increment CAS: apply the debit's spend iff the row is still
    /// `active` with the exact counters + caps we read. `Some(row)` when the CAS
    /// matched (the returned row carries the applied counters); `None` when a
    /// concurrent debit/top-up moved the guard (retry).
    async fn cas_apply_workflow_run_budget_debit(
        &self,
        binding: &str,
        read: &StoredWorkflowRunBudget,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let proxy = self.proxy_client("debit_workflow_run_budget")?;
        let caps = cap_params(read);
        let statement = D1ProxyStatement::with_params(
            format!(
                "UPDATE workflow_run_budgets SET \
                 spent_credits = spent_credits + CAST(? AS INTEGER), \
                 spent_tokens = spent_tokens + CAST(? AS INTEGER), \
                 spent_tool_calls = spent_tool_calls + CAST(? AS INTEGER), \
                 updated_at_unix = ? \
                 WHERE id = ? AND status = 'active' \
                 AND spent_credits = CAST(? AS INTEGER) \
                 AND spent_tokens = CAST(? AS INTEGER) \
                 AND spent_tool_calls = CAST(? AS INTEGER) \
                 AND {CAP_GUARD_SQL} \
                 RETURNING {WORKFLOW_RUN_BUDGET_COLUMNS}"
            ),
            vec![
                cost_credits.to_string(),
                tokens.to_string(),
                tool_calls.to_string(),
                now_unix.to_string(),
                read.id.clone(),
                read.spent_credits.to_string(),
                read.spent_tokens.to_string(),
                read.spent_tool_calls.to_string(),
                caps[0].clone(),
                caps[1].clone(),
                caps[2].clone(),
                caps[3].clone(),
            ],
        );
        self.query_returning_budget(proxy, binding, &statement)
            .await
    }

    /// The guarded fail-closed flip CAS: mark the run `exhausted` iff it is still
    /// `active` with the exact counters + caps we read (no spend applied).
    /// `Some(row)` when the CAS matched (status now `exhausted`, counters
    /// unchanged); `None` on a guard miss (retry).
    async fn cas_flip_workflow_run_budget_exhausted(
        &self,
        binding: &str,
        read: &StoredWorkflowRunBudget,
        now_unix: i64,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let proxy = self.proxy_client("debit_workflow_run_budget")?;
        let caps = cap_params(read);
        let statement = D1ProxyStatement::with_params(
            format!(
                "UPDATE workflow_run_budgets SET status = 'exhausted', updated_at_unix = ? \
                 WHERE id = ? AND status = 'active' \
                 AND spent_credits = CAST(? AS INTEGER) \
                 AND spent_tokens = CAST(? AS INTEGER) \
                 AND spent_tool_calls = CAST(? AS INTEGER) \
                 AND {CAP_GUARD_SQL} \
                 RETURNING {WORKFLOW_RUN_BUDGET_COLUMNS}"
            ),
            vec![
                now_unix.to_string(),
                read.id.clone(),
                read.spent_credits.to_string(),
                read.spent_tokens.to_string(),
                read.spent_tool_calls.to_string(),
                caps[0].clone(),
                caps[1].clone(),
                caps[2].clone(),
                caps[3].clone(),
            ],
        );
        self.query_returning_budget(proxy, binding, &statement)
            .await
    }

    /// The guarded top-up CAS: write the recomputed ABSOLUTE caps + reactivate iff
    /// the row's caps are still those we read (a concurrent top-up misses, so both
    /// raises compose on retry). `Some(row)` on a match; `None` on a guard miss.
    async fn cas_write_workflow_run_budget_caps(
        &self,
        binding: &str,
        read: &StoredWorkflowRunBudget,
        next: &StoredWorkflowRunBudget,
        now_unix: i64,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let proxy = self.proxy_client("topup_workflow_run_budget")?;
        let write_caps = cap_params(next);
        let read_caps = cap_params(read);
        let statement = D1ProxyStatement::with_params(
            format!(
                "UPDATE workflow_run_budgets SET \
                 cost_budget_credits = NULLIF(?, ''), token_budget = NULLIF(?, ''), \
                 tool_call_budget = NULLIF(?, ''), wall_clock_deadline_unix = NULLIF(?, ''), \
                 status = 'active', updated_at_unix = ? \
                 WHERE id = ? AND {CAP_GUARD_SQL} \
                 RETURNING {WORKFLOW_RUN_BUDGET_COLUMNS}"
            ),
            vec![
                write_caps[0].clone(),
                write_caps[1].clone(),
                write_caps[2].clone(),
                write_caps[3].clone(),
                now_unix.to_string(),
                read.id.clone(),
                read_caps[0].clone(),
                read_caps[1].clone(),
                read_caps[2].clone(),
                read_caps[3].clone(),
            ],
        );
        self.query_returning_budget(proxy, binding, &statement)
            .await
    }

    /// Run one guarded `UPDATE ... RETURNING` on a tenant binding and decode the
    /// (at most one) returned row; an empty `RETURNING` set is the guard-missed
    /// signal (`None`).
    async fn query_returning_budget(
        &self,
        proxy: &D1ProxyClient,
        binding: &str,
        statement: &D1ProxyStatement,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        let result = proxy
            .query_on(Some(binding), statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WorkflowRunBudgetD1Row>(row).map(StoredWorkflowRunBudget::from))
            .transpose()
    }
}
