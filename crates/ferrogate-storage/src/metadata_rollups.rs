// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Per-calendar-month usage/cost rollups keyed by an arbitrary
// caller-supplied metadata key/value pair (issue #171), aggregated
// alongside (not instead of) the existing tenant/project/workspace/key
// `usage_monthly_rollups` -- lets a reseller platform slice spend by its
// own end-customer id, feature flag, or experiment arm without provisioning
// one API key per attribution unit. Split into its own file per the "one
// business entity per file" convention -- see `budget_alerts.rs`/`rbac.rs`
// for the pattern this mirrors.

use std::collections::BTreeMap;

use super::{
    nonnegative_u64, postgres_error, saturating_i64, PostgresControlPlaneStore, PostgresRow,
    Repository, RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
    StorageOperation, TenantContext, UsageMonthlyDelta,
};

/// The tenant (organization) a metadata rollup belongs to, derived from the
/// settling request's tenant context. `usage_metadata_rollups` is otherwise
/// tenant-agnostic, which let a tenant-scoped caller read every tenant's
/// per-metadata cost/customer-id via `group_by=metadata` (issue #185 gap, closed
/// by commit ea1040b's containment). Scoping each rollup to its originating
/// organization restores a per-tenant breakdown while keeping tenants isolated
/// (issue #226). An empty string means "no organization" (a platform/unscoped
/// request, or a row written before this column existed) -- such rows are only
/// visible to platform-operator callers.
pub(super) fn metadata_rollup_organization_id(tenant: &TenantContext) -> String {
    tenant.organization_id.clone().unwrap_or_default()
}

/// One calendar month's aggregated usage/cost for every settled request
/// that carried `metadata_key: metadata_value` somewhere in its request
/// metadata (issue #171). A single event with N metadata pairs increments
/// N of these rows, exactly mirroring how one event fans out into up to
/// four `usage_monthly_rollups` rows (one per scope level).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredUsageMetadataRollup {
    pub id: String,
    /// Calendar month in `YYYY-MM` form, UTC.
    pub period_month: String,
    /// The originating tenant/organization ("" = none/legacy). Scopes the
    /// breakdown so a tenant admin sees only their own rows (issue #226).
    pub organization_id: String,
    pub metadata_key: String,
    pub metadata_value: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub request_count: u64,
    pub error_count: u64,
    pub updated_at_unix: i64,
}

/// Deterministic id for a metadata rollup row, mirroring
/// `usage_monthly_rollup_id`. Includes `organization_id` so two tenants using
/// the same metadata key/value in the same month get distinct rows (issue #226).
pub fn usage_metadata_rollup_id(
    period_month: &str,
    organization_id: &str,
    metadata_key: &str,
    metadata_value: &str,
) -> String {
    format!("{period_month}:{organization_id}:{metadata_key}:{metadata_value}")
}

fn usage_metadata_rollup_from_row(row: &PostgresRow) -> StoredUsageMetadataRollup {
    StoredUsageMetadataRollup {
        id: row.get(0),
        period_month: row.get(1),
        organization_id: row.get(2),
        metadata_key: row.get(3),
        metadata_value: row.get(4),
        prompt_tokens: nonnegative_u64(row.get(5)),
        completion_tokens: nonnegative_u64(row.get(6)),
        total_tokens: nonnegative_u64(row.get(7)),
        cost_usd: row.get(8),
        request_count: nonnegative_u64(row.get(9)),
        error_count: nonnegative_u64(row.get(10)),
        updated_at_unix: row.get(11),
    }
}

/// Fans a settled request's usage/cost delta out into one
/// `usage_metadata_rollups` increment per metadata key/value pair on the
/// event (issue #171). Called from within `append_billing_event`'s
/// transaction, right alongside `increment_usage_monthly_rollups`, so a
/// request's usage/cost lands in every applicable rollup atomically or not
/// at all. A no-op when the event carries no metadata (the common case,
/// fully backward compatible).
pub(super) async fn increment_usage_metadata_rollups(
    transaction: &deadpool_postgres::Transaction<'_>,
    tenant: &TenantContext,
    metadata: &BTreeMap<String, String>,
    period_month: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), StorageError> {
    let organization_id = metadata_rollup_organization_id(tenant);
    for (metadata_key, metadata_value) in metadata {
        upsert_usage_metadata_rollup_delta(
            transaction,
            &organization_id,
            period_month,
            metadata_key,
            metadata_value,
            delta,
        )
        .await?;
    }
    Ok(())
}

async fn upsert_usage_metadata_rollup_delta(
    transaction: &deadpool_postgres::Transaction<'_>,
    organization_id: &str,
    period_month: &str,
    metadata_key: &str,
    metadata_value: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), StorageError> {
    let id = usage_metadata_rollup_id(period_month, organization_id, metadata_key, metadata_value);
    let prompt_tokens = saturating_i64(delta.prompt_tokens);
    let completion_tokens = saturating_i64(delta.completion_tokens);
    let total_tokens = saturating_i64(delta.total_tokens);
    let cost_usd = delta.cost_usd;
    let error_increment: i64 = i64::from(delta.is_error);
    // Dedup on the primary key `id` (which encodes period/org/key/value), so the
    // upsert does not depend on the pre-#226 (period, key, value) unique
    // constraint that the migration drops.
    transaction
        .execute(
            "INSERT INTO usage_metadata_rollups \
             (id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens, \
              completion_tokens, total_tokens, cost_usd, request_count, error_count, \
              updated_at_unix) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, EXTRACT(EPOCH FROM NOW())::BIGINT) \
             ON CONFLICT (id) DO UPDATE SET \
             prompt_tokens = usage_metadata_rollups.prompt_tokens + EXCLUDED.prompt_tokens, \
             completion_tokens = \
                 usage_metadata_rollups.completion_tokens + EXCLUDED.completion_tokens, \
             total_tokens = usage_metadata_rollups.total_tokens + EXCLUDED.total_tokens, \
             cost_usd = usage_metadata_rollups.cost_usd + EXCLUDED.cost_usd, \
             request_count = usage_metadata_rollups.request_count + 1, \
             error_count = usage_metadata_rollups.error_count + EXCLUDED.error_count, \
             updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
            &[
                &id,
                &period_month,
                &organization_id,
                &metadata_key,
                &metadata_value,
                &prompt_tokens,
                &completion_tokens,
                &total_tokens,
                &cost_usd,
                &error_increment,
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

impl PostgresControlPlaneStore {
    /// Lists metadata rollups for `metadata_key`, optionally narrowed to a
    /// single `organization_id`. A tenant-scoped caller passes `Some(<its org>)`
    /// to see only its own breakdown; a platform operator passes `None` for the
    /// global cross-tenant view (issue #226).
    pub(super) async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        let operation = StorageOperation::new(
            "list usage metadata rollups",
            self.async_pool.statement_timeout(),
        );
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `usage_metadata_rollups` in the same schema the settlement
        // transaction writes to (`increment_usage_metadata_rollups`), not the
        // connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let base = "SELECT id, period_month, organization_id, metadata_key, metadata_value, \
             prompt_tokens, completion_tokens, total_tokens, cost_usd, request_count, \
             error_count, updated_at_unix \
             FROM usage_metadata_rollups WHERE metadata_key = $1";
        let order = " ORDER BY period_month ASC, metadata_value ASC";
        let rows = match organization_id {
            Some(organization_id) => {
                let sql = format!("{base} AND organization_id = $2{order}");
                transaction
                    .query(sql.as_str(), &[&metadata_key, &organization_id])
                    .await
            }
            None => {
                let sql = format!("{base}{order}");
                transaction.query(sql.as_str(), &[&metadata_key]).await
            }
        }
        .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(usage_metadata_rollup_from_row).collect())
    }
}

impl RuntimeControlPlaneState {
    /// In-memory counterpart of `increment_usage_metadata_rollups`
    /// (Postgres): keeps the default/dev backend's usage-report surface
    /// consistent with the durable one.
    pub(crate) fn increment_usage_metadata_rollups(
        &mut self,
        tenant: &TenantContext,
        metadata: &BTreeMap<String, String>,
        period_month: &str,
        delta: &UsageMonthlyDelta,
    ) {
        let organization_id = metadata_rollup_organization_id(tenant);
        for (metadata_key, metadata_value) in metadata {
            let id = usage_metadata_rollup_id(
                period_month,
                &organization_id,
                metadata_key,
                metadata_value,
            );
            let mut rollup =
                self.usage_metadata_rollups
                    .get(&id)
                    .unwrap_or_else(|| StoredUsageMetadataRollup {
                        id: id.clone(),
                        period_month: period_month.to_string(),
                        organization_id: organization_id.clone(),
                        metadata_key: metadata_key.clone(),
                        metadata_value: metadata_value.clone(),
                        prompt_tokens: 0,
                        completion_tokens: 0,
                        total_tokens: 0,
                        cost_usd: 0.0,
                        request_count: 0,
                        error_count: 0,
                        updated_at_unix: 0,
                    });
            rollup.prompt_tokens += delta.prompt_tokens;
            rollup.completion_tokens += delta.completion_tokens;
            rollup.total_tokens += delta.total_tokens;
            rollup.cost_usd += delta.cost_usd;
            rollup.request_count += 1;
            rollup.error_count += u64::from(delta.is_error);
            self.usage_metadata_rollups.insert(id, rollup);
        }
    }

    pub(crate) fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Vec<StoredUsageMetadataRollup> {
        let mut rollups: Vec<_> = self
            .usage_metadata_rollups
            .list()
            .into_iter()
            .filter(|rollup| rollup.metadata_key == metadata_key)
            .filter(|rollup| {
                organization_id
                    .is_none_or(|organization_id| rollup.organization_id == organization_id)
            })
            .collect();
        rollups.sort_by(|a, b| {
            a.period_month
                .cmp(&b.period_month)
                .then_with(|| a.metadata_value.cmp(&b.metadata_value))
        });
        rollups
    }
}

impl RuntimeStorageRepositories {
    /// Per-`metadata_key` usage/cost breakdown for the P1-4 usage-report
    /// surface's `group_by=metadata.<key>` option (issue #171).
    pub async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        self.control_plane
            .store()
            .list_usage_metadata_rollups(metadata_key, organization_id)
            .await
    }
}
