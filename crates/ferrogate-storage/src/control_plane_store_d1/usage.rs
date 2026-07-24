// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped usage rollups + the persist_usage_aggregate RMW (issue #456).

//! D1 backend: tenant-scoped usage rollups + `persist_usage_aggregate` (issue #456).
//!
//! The usage-report read surface (`get_usage_monthly_rollup`,
//! `list_usage_monthly_rollups`, `list_usage_metadata_rollups`) plus the durable
//! half of the usage-aggregate upsert (`persist_usage_aggregate`), all routed
//! through the proxy-Worker binding (issue #450) onto per-tenant
//! `[[d1_databases]]` bindings (issue #455). Like the wallet family, these are
//! TENANT-SCOPED: in the database-per-tenant topology a tenant's monthly rollups
//! (across every scope level it owns), its per-metadata rollups, and its usage
//! aggregate rollups + `tenant_contexts` live in THAT tenant's own D1 database,
//! never the control database. The Postgres backend keeps ONE physical table per
//! kind; this backend fans out / routes per tenant and re-merges, so the read
//! output is row-for-row identical to Postgres (same `ORDER BY`).
//!
//! ## persist_usage_aggregate — the durable settlement RMW as one `/d1/batch`
//!
//! Mirrors the Postgres `upsert_usage_aggregate` transaction EXACTLY: an
//! `INSERT ... ON CONFLICT DO NOTHING` on `tenant_contexts` (the
//! `upsert_tenant_context_parts` half) followed by a REPLACE-upsert
//! (`INSERT ... ON CONFLICT (id) DO UPDATE SET ... = excluded ...`) on
//! `usage_aggregate_rollups` (the `replace_usage_rollup` half). The two run as
//! ONE `/d1/batch` — a single implicit transaction (SQLite serializes writers
//! per database) — so a concurrent persist of the same aggregate id can never
//! leave the `tenant_contexts` row missing or half-write the rollup: both land
//! together or neither does. No lost updates.
//!
//! ## Divergence (database-per-tenant)
//!
//! `persist_usage_aggregate` routes by the aggregate's organization (its
//! tenant); an org-less aggregate, or a tenant with no provisioned database, is a
//! typed `NotFound` — the same divergence `settle_wallet_balance` makes, where
//! Postgres would still record the row under a null-org `tenant_context`. The
//! reads are opt-in: `list_usage_metadata_rollups(_, Some(org))` and every
//! fan-out read answer EMPTY for an unprovisioned/empty org rather than erroring
//! (matching `list_wallets` / `get_wallet`). Every op fails closed with the typed
//! unimplemented-surface error when no proxy Worker is bound.

use serde::de::DeserializeOwned;

use super::*;

/// Column list shared by every `usage_monthly_rollups` read, kept in lockstep
/// with [`UsageMonthlyRollupD1Row`] and the Postgres
/// `usage_monthly_rollup_from_row` projection order.
const USAGE_MONTHLY_ROLLUP_COLUMNS: &str =
    "id, period_month, scope_type, scope_id, prompt_tokens, \
     completion_tokens, total_tokens, cost_usd, request_count, error_count, updated_at_unix";

/// Column list shared by every `usage_metadata_rollups` read, matching
/// [`UsageMetadataRollupD1Row`] and the Postgres `usage_metadata_rollup_from_row`
/// projection order.
const USAGE_METADATA_ROLLUP_COLUMNS: &str = "id, period_month, organization_id, metadata_key, \
     metadata_value, prompt_tokens, completion_tokens, total_tokens, cost_usd, request_count, \
     error_count, updated_at_unix";

/// One `usage_monthly_rollups` row (SQLite integer/real affinities decoded back
/// to the `Stored*` shape). `scope_type` decodes as TEXT then maps to
/// [`QuotaScopeKind`], mirroring the Postgres `usage_monthly_rollup_from_row`.
#[derive(serde::Deserialize)]
struct UsageMonthlyRollupD1Row {
    id: String,
    period_month: String,
    scope_type: String,
    scope_id: String,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    cost_usd: f64,
    request_count: i64,
    error_count: i64,
    updated_at_unix: i64,
}

impl UsageMonthlyRollupD1Row {
    fn into_stored(self) -> Result<StoredUsageMonthlyRollup, StorageError> {
        let scope_type = QuotaScopeKind::from_str_opt(&self.scope_type).ok_or_else(|| {
            StorageError::Runtime(format!(
                "unknown usage_monthly_rollups.scope_type {}",
                self.scope_type
            ))
        })?;
        Ok(StoredUsageMonthlyRollup {
            id: self.id,
            period_month: self.period_month,
            scope_type,
            scope_id: self.scope_id,
            prompt_tokens: nonnegative_u64(self.prompt_tokens),
            completion_tokens: nonnegative_u64(self.completion_tokens),
            total_tokens: nonnegative_u64(self.total_tokens),
            cost_usd: self.cost_usd,
            request_count: nonnegative_u64(self.request_count),
            error_count: nonnegative_u64(self.error_count),
            updated_at_unix: self.updated_at_unix,
        })
    }
}

/// One `usage_metadata_rollups` row.
#[derive(serde::Deserialize)]
struct UsageMetadataRollupD1Row {
    id: String,
    period_month: String,
    organization_id: String,
    metadata_key: String,
    metadata_value: String,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    cost_usd: f64,
    request_count: i64,
    error_count: i64,
    updated_at_unix: i64,
}

impl From<UsageMetadataRollupD1Row> for StoredUsageMetadataRollup {
    fn from(row: UsageMetadataRollupD1Row) -> Self {
        Self {
            id: row.id,
            period_month: row.period_month,
            organization_id: row.organization_id,
            metadata_key: row.metadata_key,
            metadata_value: row.metadata_value,
            prompt_tokens: nonnegative_u64(row.prompt_tokens),
            completion_tokens: nonnegative_u64(row.completion_tokens),
            total_tokens: nonnegative_u64(row.total_tokens),
            cost_usd: row.cost_usd,
            request_count: nonnegative_u64(row.request_count),
            error_count: nonnegative_u64(row.error_count),
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

impl D1ControlPlaneStore {
    // --- Usage rollups over the proxy binding, tenant-DB routed (issue #456) ---

    /// Read one per-scope monthly rollup (issue #339 overview + monthly-budget
    /// enforcement). The row for `(scope_type, scope_id, period_month)` lives in
    /// exactly ONE tenant's database — the tenant that owns that scope — and the
    /// signature carries no tenant id for project/workspace/key scopes, so this
    /// FANS OUT over the provisioned tenant bindings and returns the first match
    /// (the same id-only locate pattern `settle`/`release` use). The
    /// deterministic id keeps the row globally unique, so at most one binding
    /// answers; `Ok(None)` when none does (or the registry is empty). Fails
    /// closed (typed unimplemented-surface) without a proxy Worker.
    pub(super) async fn get_usage_monthly_rollup_d1_async(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        let proxy = self.proxy_client("get_usage_monthly_rollup")?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!(
                    "SELECT {USAGE_MONTHLY_ROLLUP_COLUMNS} FROM usage_monthly_rollups \
                     WHERE scope_type = ? AND scope_id = ? AND period_month = ?"
                ),
                vec![
                    scope_type.as_str().to_string(),
                    scope_id.to_string(),
                    period_month.to_string(),
                ],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if let Some(row) = result.results.first() {
                return Ok(Some(
                    decode_row::<UsageMonthlyRollupD1Row>(row)?.into_stored()?,
                ));
            }
        }
        Ok(None)
    }

    /// List EVERY provisioned tenant's monthly rollups (the #339 overview source).
    /// Fans out over the provisioned tenant bindings (each tenant's rows live in
    /// its own database), then re-sorts the union to the Postgres order
    /// `period_month DESC, scope_type ASC, scope_id ASC` so the list is
    /// row-for-row identical across backends. Empty registry -> empty; fails
    /// closed without a proxy Worker.
    pub(super) async fn list_usage_monthly_rollups_d1_async(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        let proxy = self.proxy_client("list_usage_monthly_rollups")?;
        let mut rollups = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::new(format!(
                "SELECT {USAGE_MONTHLY_ROLLUP_COLUMNS} FROM usage_monthly_rollups"
            ));
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                rollups.push(decode_row::<UsageMonthlyRollupD1Row>(row)?.into_stored()?);
            }
        }
        // Postgres `ORDER BY period_month DESC, scope_type ASC, scope_id ASC`;
        // scope_type is compared by its stored TEXT form (`as_str`) so the union
        // order matches the SQL column sort exactly.
        rollups.sort_by(|left, right| {
            right
                .period_month
                .cmp(&left.period_month)
                .then_with(|| left.scope_type.as_str().cmp(right.scope_type.as_str()))
                .then_with(|| left.scope_id.cmp(&right.scope_id))
        });
        Ok(rollups)
    }

    /// Per-`metadata_key` usage/cost breakdown (issue #171/#226). A tenant-scoped
    /// caller passes `Some(<its org>)` and this routes to that org's own database
    /// (opt-in: an unprovisioned or empty/legacy org has no tenant DB, so
    /// EMPTY — matching Postgres returning no rows for a nonexistent org, and the
    /// wallet `get_wallet` opt-in contract). A platform operator passes `None`
    /// and this fans out over every provisioned tenant DB. Both paths order
    /// `period_month ASC, metadata_value ASC` to match Postgres; the fan-out
    /// re-sorts the union to that order. Fails closed without a proxy Worker.
    pub(super) async fn list_usage_metadata_rollups_d1_async(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        let proxy = self.proxy_client("list_usage_metadata_rollups")?;
        match organization_id {
            Some(org) => {
                // Empty/legacy org ("" = platform/pre-#226 rows) has no tenant
                // database in the per-tenant topology, so no rows to route to.
                if org.is_empty() {
                    return Ok(Vec::new());
                }
                let Some(binding) = self.tenant_proxy_binding_optional(org)? else {
                    return Ok(Vec::new());
                };
                let statement = D1ProxyStatement::with_params(
                    format!(
                        "SELECT {USAGE_METADATA_ROLLUP_COLUMNS} FROM usage_metadata_rollups \
                         WHERE metadata_key = ? AND organization_id = ? \
                         ORDER BY period_month ASC, metadata_value ASC"
                    ),
                    vec![metadata_key.to_string(), org.to_string()],
                );
                let result = proxy
                    .query_on(Some(&binding), &statement)
                    .await
                    .map_err(d1_error)?;
                result
                    .results
                    .iter()
                    .map(|row| {
                        decode_row::<UsageMetadataRollupD1Row>(row)
                            .map(StoredUsageMetadataRollup::from)
                    })
                    .collect()
            }
            None => {
                let mut rollups = Vec::new();
                for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
                    let statement = D1ProxyStatement::with_params(
                        format!(
                            "SELECT {USAGE_METADATA_ROLLUP_COLUMNS} FROM usage_metadata_rollups \
                             WHERE metadata_key = ? ORDER BY period_month ASC, metadata_value ASC"
                        ),
                        vec![metadata_key.to_string()],
                    );
                    let result = proxy
                        .query_on(Some(&binding), &statement)
                        .await
                        .map_err(d1_error)?;
                    for row in &result.results {
                        rollups.push(
                            decode_row::<UsageMetadataRollupD1Row>(row)
                                .map(StoredUsageMetadataRollup::from)?,
                        );
                    }
                }
                rollups.sort_by(|left, right| {
                    left.period_month
                        .cmp(&right.period_month)
                        .then_with(|| left.metadata_value.cmp(&right.metadata_value))
                });
                Ok(rollups)
            }
        }
    }

    /// Durable write-through half of the usage-aggregate upsert (issue #339's
    /// store-of-record write) as ONE atomic `/d1/batch` on the owning tenant's
    /// database. Mirrors the Postgres `upsert_usage_aggregate` transaction: a
    /// `tenant_contexts` `INSERT ... ON CONFLICT DO NOTHING` (the
    /// `upsert_tenant_context_parts` half) and a REPLACE-upsert of
    /// `usage_aggregate_rollups` (the `replace_usage_rollup` half), both in one
    /// implicit transaction so a concurrent persist of the same aggregate id
    /// cannot half-write it.
    ///
    /// Divergence: routes by the aggregate's organization (its tenant). An
    /// org-less aggregate, or a tenant with no provisioned database, is a typed
    /// `NotFound` — the database-per-tenant divergence `settle_wallet_balance`
    /// makes, where Postgres records the row under a null-org `tenant_context`.
    pub(super) async fn persist_usage_aggregate_d1_async(
        &self,
        aggregate: &StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("persist_usage_aggregate")?;
        let tenant_id = aggregate
            .organization_id
            .as_deref()
            .filter(|org| !org.is_empty())
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "usage aggregate {} has no organization; the cloudflare_d1 backend has no \
                     tenant database to persist it into",
                    aggregate.id
                ))
            })?;
        let binding = self.tenant_proxy_binding(tenant_id)?;

        // Deterministic tenant-context id, identical to the Postgres key so the
        // durable row lands under the same identity across backends.
        let tenant_context_id = tenant_parts_storage_key(
            aggregate.organization_id.as_deref(),
            None,
            aggregate.project_id.as_deref(),
            None,
            None,
            aggregate.api_key_id.as_deref(),
        );
        // Tokens are STORED values (SQLite column-affinity coerces the bound TEXT
        // to INTEGER on write) and the REPLACE reads them back via `excluded.*`,
        // never summing a bound param against an INTEGER column in an expression,
        // so no `CAST` is needed here — same as `upsert_wallet` (contrast the
        // arithmetic `settle`/`reserve` guards, which do CAST; the #455 lesson).
        let prompt_tokens = saturating_i64(aggregate.usage.prompt_tokens).to_string();
        let completion_tokens = saturating_i64(aggregate.usage.completion_tokens).to_string();
        let total_tokens = saturating_i64(aggregate.usage.total_tokens).to_string();

        let statements = vec![
            // S0: ensure the tenant_contexts row (INSERT ... ON CONFLICT DO
            // NOTHING), mirroring `upsert_tenant_context_parts`. `NULLIF(?, '')`
            // stores SQL NULL for absent parts, matching the Postgres NULLs;
            // team/workspace/user are always absent on this path.
            D1ProxyStatement::with_params(
                "INSERT INTO tenant_contexts \
                 (id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) \
                 VALUES (?, NULLIF(?, ''), NULL, NULLIF(?, ''), NULL, NULL, NULLIF(?, '')) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    tenant_context_id.clone(),
                    aggregate.organization_id.clone().unwrap_or_default(),
                    aggregate.project_id.clone().unwrap_or_default(),
                    aggregate.api_key_id.clone().unwrap_or_default(),
                ],
            ),
            // S1: REPLACE the aggregate rollup, mirroring `replace_usage_rollup`
            // (ON CONFLICT DO UPDATE SET ... = excluded ...). `unixepoch()` stands
            // in for the Postgres `EXTRACT(EPOCH FROM NOW())::BIGINT` default.
            D1ProxyStatement::with_params(
                "INSERT INTO usage_aggregate_rollups \
                 (id, tenant_context_id, logical_model, provider, prompt_tokens, \
                  completion_tokens, total_tokens, updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch()) \
                 ON CONFLICT (id) DO UPDATE SET \
                 tenant_context_id = excluded.tenant_context_id, \
                 logical_model = excluded.logical_model, \
                 provider = excluded.provider, \
                 prompt_tokens = excluded.prompt_tokens, \
                 completion_tokens = excluded.completion_tokens, \
                 total_tokens = excluded.total_tokens, \
                 updated_at_unix = unixepoch()",
                vec![
                    aggregate.id.clone(),
                    tenant_context_id.clone(),
                    aggregate.logical_model.clone(),
                    aggregate.provider.clone(),
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                ],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: persist_usage_aggregate batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
