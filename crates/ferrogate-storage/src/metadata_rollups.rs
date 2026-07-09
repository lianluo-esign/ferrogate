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

use postgres::Transaction as PostgresTransaction;

use super::{
    nonnegative_u64, saturating_i64, PostgresControlPlaneStore, PostgresRow, Repository,
    RuntimeControlPlaneBackend, RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
    UsageMonthlyDelta,
};

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
/// `usage_monthly_rollup_id`.
pub fn usage_metadata_rollup_id(
    period_month: &str,
    metadata_key: &str,
    metadata_value: &str,
) -> String {
    format!("{period_month}:{metadata_key}:{metadata_value}")
}

fn usage_metadata_rollup_from_row(row: &PostgresRow) -> StoredUsageMetadataRollup {
    StoredUsageMetadataRollup {
        id: row.get(0),
        period_month: row.get(1),
        metadata_key: row.get(2),
        metadata_value: row.get(3),
        prompt_tokens: nonnegative_u64(row.get(4)),
        completion_tokens: nonnegative_u64(row.get(5)),
        total_tokens: nonnegative_u64(row.get(6)),
        cost_usd: row.get(7),
        request_count: nonnegative_u64(row.get(8)),
        error_count: nonnegative_u64(row.get(9)),
        updated_at_unix: row.get(10),
    }
}

/// Fans a settled request's usage/cost delta out into one
/// `usage_metadata_rollups` increment per metadata key/value pair on the
/// event (issue #171). Called from within `append_billing_event`'s
/// transaction, right alongside `increment_usage_monthly_rollups`, so a
/// request's usage/cost lands in every applicable rollup atomically or not
/// at all. A no-op when the event carries no metadata (the common case,
/// fully backward compatible).
pub(super) fn increment_usage_metadata_rollups(
    transaction: &mut PostgresTransaction<'_>,
    metadata: &BTreeMap<String, String>,
    period_month: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), postgres::Error> {
    for (metadata_key, metadata_value) in metadata {
        upsert_usage_metadata_rollup_delta(
            transaction,
            period_month,
            metadata_key,
            metadata_value,
            delta,
        )?;
    }
    Ok(())
}

fn upsert_usage_metadata_rollup_delta(
    transaction: &mut PostgresTransaction<'_>,
    period_month: &str,
    metadata_key: &str,
    metadata_value: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), postgres::Error> {
    let id = usage_metadata_rollup_id(period_month, metadata_key, metadata_value);
    let prompt_tokens = saturating_i64(delta.prompt_tokens);
    let completion_tokens = saturating_i64(delta.completion_tokens);
    let total_tokens = saturating_i64(delta.total_tokens);
    let cost_usd = delta.cost_usd;
    let error_increment: i64 = i64::from(delta.is_error);
    transaction.execute(
        "INSERT INTO usage_metadata_rollups \
         (id, period_month, metadata_key, metadata_value, prompt_tokens, completion_tokens, \
          total_tokens, cost_usd, request_count, error_count, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (period_month, metadata_key, metadata_value) DO UPDATE SET \
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
            &metadata_key,
            &metadata_value,
            &prompt_tokens,
            &completion_tokens,
            &total_tokens,
            &cost_usd,
            &error_increment,
        ],
    )?;
    Ok(())
}

impl PostgresControlPlaneStore {
    pub(super) fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, period_month, metadata_key, metadata_value, prompt_tokens, \
                 completion_tokens, total_tokens, cost_usd, request_count, error_count, \
                 updated_at_unix \
                 FROM usage_metadata_rollups WHERE metadata_key = $1 \
                 ORDER BY period_month ASC, metadata_value ASC",
                &[&metadata_key],
            )
        })?;
        Ok(rows.iter().map(usage_metadata_rollup_from_row).collect())
    }
}

impl RuntimeControlPlaneState {
    /// In-memory counterpart of `increment_usage_metadata_rollups`
    /// (Postgres): keeps the default/dev backend's usage-report surface
    /// consistent with the durable one.
    pub(crate) fn increment_usage_metadata_rollups(
        &mut self,
        metadata: &BTreeMap<String, String>,
        period_month: &str,
        delta: &UsageMonthlyDelta,
    ) {
        for (metadata_key, metadata_value) in metadata {
            let id = usage_metadata_rollup_id(period_month, metadata_key, metadata_value);
            let mut rollup =
                self.usage_metadata_rollups
                    .get(&id)
                    .unwrap_or_else(|| StoredUsageMetadataRollup {
                        id: id.clone(),
                        period_month: period_month.to_string(),
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
    ) -> Vec<StoredUsageMetadataRollup> {
        let mut rollups: Vec<_> = self
            .usage_metadata_rollups
            .list()
            .into_iter()
            .filter(|rollup| rollup.metadata_key == metadata_key)
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
    pub fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_usage_metadata_rollups(metadata_key))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_usage_metadata_rollups(metadata_key)
            }
        }
    }
}
