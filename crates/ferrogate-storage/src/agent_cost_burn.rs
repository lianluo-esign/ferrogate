// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Durable, atomically-accumulating per-agent cost-burn ledger
// (#428, slice B-storage). The persistent backing for the slice-A in-memory
// `AgentBurnLedger` (ferrogate-runtime `cloudflare_agent_cost.rs`): one durable
// row per (tenant_id, agent_key, period) whose `accumulated_usd` total is bumped
// by a single atomic conditional upsert that RETURNS the new total. So a
// per-agent budget survives a restart and concurrent adds for the same key can
// never lose an increment. Split into its own file per the "one business entity
// per file" convention (mirrors `observed_agent_presence.rs`).

use super::{
    now_unix_seconds, postgres_error, saturating_i64, PostgresControlPlaneStore, PostgresRow,
    Repository, RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
    StorageOperation,
};

/// A durable per-agent burn row, keyed by `(tenant_id, agent_key, period)`.
///
/// `agent_key` is a STABLE per-agent identity (the agent/deployment key), NOT the
/// ephemeral per-run id: every run of the same agent inside `period` folds into
/// this one accumulating `accumulated_usd` total, which is exactly what a
/// per-agent budget bounds. `period` reuses the `usage_monthly_rollups`
/// `YYYY-MM` billing-window convention. `accumulated_usd` reuses the crate's
/// `DOUBLE PRECISION` monetary type (as `cost_usd` / `monthly_budget_usd`).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredAgentCostBurn {
    pub tenant_id: String,
    pub agent_key: String,
    pub period: String,
    pub accumulated_usd: f64,
    pub first_seen_unix: i64,
    pub updated_at_unix: i64,
}

/// Composite in-memory identity for a burn row. Length-prefixed on each variable
/// segment so a crafted `(tenant, agent, period)` triple can never alias another
/// -- the same collision-safety trick as [`crate::observed_agent_presence_key`].
pub fn agent_cost_burn_key(tenant_id: &str, agent_key: &str, period: &str) -> String {
    format!(
        "{}:{tenant_id}:{}:{agent_key}:{}:{period}",
        tenant_id.len(),
        agent_key.len(),
        period.len()
    )
}

// Full column list + row mapper back the #428 slice-B-surface list read
// (`list_agent_cost_burn`); the atomic add/get paths only touch
// `accumulated_usd`.
const AGENT_COST_BURN_COLUMNS: &str =
    "tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix";

fn agent_cost_burn_from_row(row: &PostgresRow) -> StoredAgentCostBurn {
    StoredAgentCostBurn {
        tenant_id: row.get::<_, String>(0),
        agent_key: row.get::<_, String>(1),
        period: row.get::<_, String>(2),
        accumulated_usd: row.get::<_, f64>(3),
        first_seen_unix: row.get::<_, i64>(4),
        updated_at_unix: row.get::<_, i64>(5),
    }
}

impl PostgresControlPlaneStore {
    fn agent_cost_burn_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    /// Atomically add `delta_usd` to the `(tenant_id, agent_key, period)` burn
    /// total and RETURN the new accumulated total, as ONE conditional upsert on
    /// the composite primary key. The `ON CONFLICT ... DO UPDATE SET
    /// accumulated_usd = agent_cost_burn.accumulated_usd + EXCLUDED.accumulated_usd
    /// ... RETURNING accumulated_usd` folds the increment in and reads the new
    /// total in the SAME statement, so concurrent adds for one key can never lose
    /// an increment (the add is done inside the row-locked upsert, not via a
    /// read-modify-write) and the caller always sees the post-add total. On the
    /// insert path the row is seeded with `accumulated_usd = delta`,
    /// `first_seen_unix = updated_at_unix = now`.
    pub(super) async fn add_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
        delta_usd: f64,
    ) -> Result<f64, StorageError> {
        let now = saturating_i64(now_unix_seconds());
        let operation = self.agent_cost_burn_operation("add agent burn");
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
            .query_one(
                "INSERT INTO agent_cost_burn \
                 (tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $5) \
                 ON CONFLICT (tenant_id, agent_key, period) DO UPDATE SET \
                     accumulated_usd = agent_cost_burn.accumulated_usd + EXCLUDED.accumulated_usd, \
                     updated_at_unix = EXCLUDED.updated_at_unix \
                 RETURNING accumulated_usd",
                &[&tenant_id, &agent_key, &period, &delta_usd, &now],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.get::<_, f64>(0))
    }

    /// Read the current accumulated burn total for `(tenant_id, agent_key,
    /// period)`, or `Ok(None)` when no burn has ever been recorded for it.
    pub(super) async fn get_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
    ) -> Result<Option<f64>, StorageError> {
        let operation = self.agent_cost_burn_operation("get agent burn");
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
                "SELECT accumulated_usd FROM agent_cost_burn \
                 WHERE tenant_id = $1 AND agent_key = $2 AND period = $3",
                &[&tenant_id, &agent_key, &period],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(|row| row.get::<_, f64>(0)))
    }

    /// List the durable per-agent burn rows for `period`, biggest accumulated
    /// total first, optionally scoped to one tenant (#428 slice B-surface). The
    /// `$1::TEXT IS NULL OR tenant_id = $1` filter serves both the tenant-scoped
    /// admin read (a bound tenant) and the platform-operator cross-tenant view
    /// (a NULL scope) from one prepared statement, mirroring the guardrail
    /// evidence list. Read-only: it never writes or fabricates a row.
    pub(super) async fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> Result<Vec<StoredAgentCostBurn>, StorageError> {
        let operation = self.agent_cost_burn_operation("list agent cost burn");
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
                    "SELECT {AGENT_COST_BURN_COLUMNS} FROM agent_cost_burn \
                     WHERE ($1::TEXT IS NULL OR tenant_id = $1) AND period = $2 \
                     ORDER BY accumulated_usd DESC, tenant_id ASC, agent_key ASC"
                ),
                &[&tenant_scope, &period],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(agent_cost_burn_from_row).collect())
    }
}

impl RuntimeControlPlaneState {
    /// In-memory analogue of the atomic accumulate. Serialized by the
    /// control-plane mutex the facade holds, so concurrent adds for the same key
    /// fold into the single row without losing an increment (mirrors the Postgres
    /// `accumulated_usd + EXCLUDED.accumulated_usd` conflict clause). Returns the
    /// new accumulated total.
    pub(super) fn add_agent_burn(
        &mut self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
        delta_usd: f64,
    ) -> f64 {
        let now = saturating_i64(now_unix_seconds());
        let key = agent_cost_burn_key(tenant_id, agent_key, period);
        match self.agent_cost_burn.get(&key) {
            Some(mut existing) => {
                existing.accumulated_usd += delta_usd;
                existing.updated_at_unix = now;
                let total = existing.accumulated_usd;
                self.agent_cost_burn.insert(key, existing);
                total
            }
            None => {
                let row = StoredAgentCostBurn {
                    tenant_id: tenant_id.to_string(),
                    agent_key: agent_key.to_string(),
                    period: period.to_string(),
                    accumulated_usd: delta_usd,
                    first_seen_unix: now,
                    updated_at_unix: now,
                };
                let total = row.accumulated_usd;
                self.agent_cost_burn.insert(key, row);
                total
            }
        }
    }

    pub(super) fn get_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
    ) -> Option<f64> {
        self.agent_cost_burn
            .get(&agent_cost_burn_key(tenant_id, agent_key, period))
            .map(|row| row.accumulated_usd)
    }

    /// In-memory analogue of [`PostgresControlPlaneStore::list_agent_cost_burn`]:
    /// filter the burn map to `period` (and `tenant_scope` when set), biggest
    /// accumulated total first. The tenant-scope filter is the isolation
    /// boundary -- a tenant-scoped caller can never observe another tenant's row.
    pub(super) fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> Vec<StoredAgentCostBurn> {
        let mut rows: Vec<_> = self
            .agent_cost_burn
            .list()
            .into_iter()
            .filter(|row| row.period == period)
            .filter(|row| tenant_scope.is_none_or(|scope| row.tenant_id == scope))
            .collect();
        rows.sort_by(|left, right| {
            right
                .accumulated_usd
                .partial_cmp(&left.accumulated_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.tenant_id.cmp(&right.tenant_id))
                .then_with(|| left.agent_key.cmp(&right.agent_key))
        });
        rows
    }
}

impl RuntimeStorageRepositories {
    /// Atomically add `delta_usd` to the durable per-agent burn total for
    /// `(tenant_id, agent_key, period)` and return the new accumulated total.
    /// Durable backing for the slice-A `AgentBurnLedger` (#428). See
    /// [`PostgresControlPlaneStore::add_agent_burn`] for the atomicity contract.
    pub async fn add_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
        delta_usd: f64,
    ) -> Result<f64, StorageError> {
        self.control_plane
            .store()
            .add_agent_burn(tenant_id, agent_key, period, delta_usd)
            .await
    }

    /// Read the current durable per-agent burn total for `(tenant_id, agent_key,
    /// period)`, or `None` when nothing has been recorded for it.
    pub async fn get_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
    ) -> Result<Option<f64>, StorageError> {
        self.control_plane
            .store()
            .get_agent_burn(tenant_id, agent_key, period)
            .await
    }

    /// List the durable per-agent burn rows for `period`, biggest accumulated
    /// total first, optionally scoped to one tenant (#428 slice B-surface).
    /// `tenant_scope = Some(tenant_id)` restricts to that tenant so a
    /// tenant-scoped admin surface never sees another tenant's burn; `None` is
    /// the platform-operator cross-tenant view. Read-only surfacing for the
    /// observability/billing admin API.
    pub async fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> Result<Vec<StoredAgentCostBurn>, StorageError> {
        self.control_plane
            .store()
            .list_agent_cost_burn(tenant_scope, period)
            .await
    }
}

#[cfg(test)]
#[path = "agent_cost_burn_test.rs"]
mod agent_cost_burn_test;
