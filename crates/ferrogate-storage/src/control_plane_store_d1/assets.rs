// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped assets + channels + retention family (issue #456).

//! D1 backend: tenant-scoped assets + channels + retention (issue #456).
//!
//! The hosted-asset storage family (issues #176/#260/#263/#366/#371), routed
//! through the proxy-Worker binding (issue #450) onto per-tenant
//! `[[d1_databases]]` bindings (issue #455). Like the wallet/usage families,
//! these are TENANT-SCOPED: in the database-per-tenant topology a tenant's
//! assets, its channel pointers, and its retention policies live in THAT
//! tenant's own D1 database, never the control database. The Postgres backend
//! keeps ONE physical table per kind; this backend routes per tenant (for
//! ops that carry a tenant id / entity) or fans out over the provisioned tenant
//! bindings (for id-only reads/deletes and the operator cross-tenant lists),
//! re-merging so the read output is row-for-row identical to Postgres.
//!
//! ## The five hard-won invariants (mirrored behaviorally onto the lock-free D1)
//!
//! 1. **`create_asset_within_quota` quota guard (#371)** — a guarded conditional
//!    insert that admits only when the new object fits under the per-tenant
//!    quota, mirroring the wallet reserve. The size param enters an arithmetic
//!    comparison against the INTEGER `size_bytes` column, and the proxy binds
//!    params as TEXT, so it MUST be `CAST(? AS INTEGER)` — without the cast
//!    SQLite ranks TEXT above every INTEGER and the guard never admits (the
//!    #455 lesson). A pre-state read + the guarded insert run as ONE atomic
//!    `/d1/batch` (SQLite serializes writers per database, and a batch is one
//!    implicit transaction), so N racing pushes that jointly overshoot admit
//!    exactly the fitting set — no over-quota.
//! 2. **Dual-unique-constraint conflict (the #369 fix)** — `stored_assets` has
//!    TWO unique constraints (the `id` PK + `(tenant, asset_type, name, version,
//!    variant)`). A bare `ON CONFLICT DO NOTHING` (no target) suppresses BOTH,
//!    so a concurrent first-push loser (same id OR same composite tuple under a
//!    different id) is a no-op `RETURNING`-empty rather than a raised error; the
//!    pre-state read classifies it to `AlreadyExists` / `Ok(false)` exactly like
//!    the Postgres 23505 catch — never a raw error the gateway maps to a 503. A
//!    surfaced SQLite `UNIQUE constraint failed` (defense in depth) is mapped the
//!    same way ([`is_d1_unique_violation`]).
//! 3. **`move_asset_channel_if_resolvable` atomicity (the #367 invariant)** — the
//!    move commits ONLY when the target version is durably resolvable (present,
//!    no yanked variant). D1 has no row lock, but the resolvability guard and the
//!    channel upsert live in ONE guarded statement inside a single `/d1/batch`
//!    transaction, so a concurrent yank/delete can never interleave between the
//!    check and the write — the behavioral mirror of the Postgres `FOR UPDATE`
//!    lock. `set_asset_version_yank` / `delete_asset_variant_if_unreferenced`
//!    close the same write-skew hazard from the opposite direction, guarding on
//!    the channel-reference set inside one atomic batch.
//! 4. **Inline BYTEA round-trip** — asset bytes are stored inline. The proxy
//!    binds params as TEXT, so `content` is a base64 TEXT column: encoded on
//!    write, decoded on read, byte-for-byte faithful. `size_bytes` stays a real
//!    INTEGER column (the quota SUM does arithmetic on it), independent of the
//!    encoded blob.
//! 5. **`promote_pending_asset_visibility` fail-closed (#366/#378)** — the CAS
//!    fires only from `pending_scan`; an unknown/invalid visibility token
//!    resolves to `Quarantined` ([`AssetVisibility::from_stored`]), never
//!    silently downloadable.
//!
//! Every op fails closed with the typed unimplemented-surface error when no
//! proxy Worker is bound, exactly like the other tenant-scoped atomic families.

use base64::Engine as _;
use serde::de::DeserializeOwned;

use super::*;

/// Base64 engine for the inline-BYTEA `content` round trip (invariant 4).
const CONTENT_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Column list shared by every `stored_assets` read, kept in lockstep with
/// [`StoredAssetD1Row`] and the Postgres `asset_from_row` projection.
const STORED_ASSET_COLUMNS: &str = "id, tenant_id, project_id, asset_type, name, version, \
     content_type, content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
     storage_uri, variant, yanked, visibility";

/// The 16-value INSERT projection (usable both as `VALUES (...)` and as the
/// body of an `INSERT ... SELECT ...`). `NULLIF(?, '')` restores SQL NULL for
/// the absent optional columns, matching the Postgres NULLs.
const STORED_ASSET_INSERT_VALUES: &str =
    "?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?";

/// The DO UPDATE assignment list shared by `upsert_asset` (mirrors the Postgres
/// upsert: identity + immutable columns are never touched).
const STORED_ASSET_ON_CONFLICT_UPDATE: &str = "content_type = excluded.content_type, \
     content_hash = excluded.content_hash, size_bytes = excluded.size_bytes, \
     content = excluded.content, updated_at_unix = excluded.updated_at_unix, \
     storage_uri = excluded.storage_uri, yanked = excluded.yanked, \
     visibility = excluded.visibility";

/// Column list shared by every `asset_channels` read, matching
/// [`AssetChannelD1Row`] and the Postgres `asset_channel_from_row` projection.
const ASSET_CHANNEL_COLUMNS: &str =
    "id, tenant_id, asset_type, name, channel, version, updated_at_unix";

/// Column list shared by every `retention_policies` read, matching
/// [`RetentionPolicyD1Row`] and the Postgres `retention_policy_from_row`.
const RETENTION_POLICY_COLUMNS: &str = "id, tenant_id, resource_type, scope, keep_last_n, \
     max_age_secs, min_age_secs, created_at_unix, updated_at_unix";

/// One `stored_assets` row. SQLite integer/text affinities decode back to the
/// `Stored*` shape: `yanked` as 0/1, `visibility` fail-closed via
/// [`AssetVisibility::from_stored`], and `content` base64-decoded (invariant 4).
#[derive(serde::Deserialize)]
struct StoredAssetD1Row {
    id: String,
    tenant_id: String,
    project_id: Option<String>,
    asset_type: String,
    name: String,
    version: String,
    content_type: String,
    content_hash: String,
    size_bytes: i64,
    content: String,
    created_at_unix: i64,
    updated_at_unix: i64,
    storage_uri: Option<String>,
    variant: String,
    yanked: i64,
    visibility: String,
}

impl StoredAssetD1Row {
    fn into_stored(self) -> Result<StoredAsset, StorageError> {
        let content = CONTENT_ENGINE
            .decode(self.content.as_bytes())
            .map_err(|error| {
                StorageError::Serialization(format!(
                    "cloudflare d1: stored asset {} content is not valid base64: {error}",
                    self.id
                ))
            })?;
        Ok(StoredAsset {
            id: self.id,
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            asset_type: self.asset_type,
            name: self.name,
            version: self.version,
            content_type: self.content_type,
            content_hash: self.content_hash,
            size_bytes: nonnegative_u64(self.size_bytes),
            content,
            storage_uri: self.storage_uri,
            variant: self.variant,
            yanked: self.yanked != 0,
            visibility: AssetVisibility::from_stored(&self.visibility),
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

/// One `asset_channels` row.
#[derive(serde::Deserialize)]
struct AssetChannelD1Row {
    id: String,
    tenant_id: String,
    asset_type: String,
    name: String,
    channel: String,
    version: String,
    updated_at_unix: i64,
}

impl From<AssetChannelD1Row> for StoredAssetChannel {
    fn from(row: AssetChannelD1Row) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            asset_type: row.asset_type,
            name: row.name,
            channel: row.channel,
            version: row.version,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// One `retention_policies` row. `keep_last_n` is clamped non-negative like the
/// Postgres `retention_policy_from_row`.
#[derive(serde::Deserialize)]
struct RetentionPolicyD1Row {
    id: String,
    tenant_id: String,
    resource_type: String,
    scope: String,
    keep_last_n: Option<i64>,
    max_age_secs: Option<i64>,
    min_age_secs: i64,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<RetentionPolicyD1Row> for StoredRetentionPolicy {
    fn from(row: RetentionPolicyD1Row) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_type: row.resource_type,
            scope: row.scope,
            keep_last_n: row.keep_last_n.map(|value| value.max(0) as u64),
            max_age_secs: row.max_age_secs,
            min_age_secs: row.min_age_secs,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// The pre-insert guard state read alongside `create_asset_within_quota`: does
/// the id / composite tuple already exist, and how many bytes does the tenant
/// already hold.
#[derive(serde::Deserialize)]
struct AssetQuotaStateRow {
    id_exists: i64,
    tuple_exists: i64,
    used_bytes: i64,
}

/// Just the `visibility` token a promote CAS / state read returns.
#[derive(serde::Deserialize)]
struct VisibilityRow {
    visibility: String,
}

/// Just the `version` an `asset_channels` prior-target read returns.
#[derive(serde::Deserialize)]
struct ChannelVersionRow {
    version: String,
}

/// The version existence + channel-reference state read alongside
/// `set_asset_version_yank`.
#[derive(serde::Deserialize)]
struct YankStateRow {
    variant_count: i64,
    referenced_count: i64,
}

/// The variant existence + remaining-resolvable + channel-reference state read
/// alongside `delete_asset_variant_if_unreferenced`.
#[derive(serde::Deserialize)]
struct VariantDeleteStateRow {
    id_present: i64,
    other_resolvable: i64,
    referenced_count: i64,
}

/// Just the scalar `used_bytes` a tenant storage-usage SUM returns.
#[derive(serde::Deserialize)]
struct UsedBytesRow {
    used_bytes: i64,
}

/// Deserialize one D1 result row (`serde_json::Value` keyed by column) into a
/// typed DTO.
fn decode_row<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, StorageError> {
    serde_json::from_value(value.clone())
        .map_err(|error| StorageError::Serialization(error.to_string()))
}

/// The 16 positional INSERT binds for a `stored_assets` row (identical order to
/// [`STORED_ASSET_INSERT_VALUES`]). `content` is base64-encoded (invariant 4);
/// `size_bytes` is a stored value (SQLite INTEGER affinity coerces the bound
/// TEXT on write), so it needs no CAST here — the CAST lives in the quota
/// ARITHMETIC guard (invariant 1).
fn asset_insert_params(asset: &StoredAsset) -> Vec<String> {
    vec![
        asset.id.clone(),
        asset.tenant_id.clone(),
        asset.project_id.clone().unwrap_or_default(),
        asset.asset_type.clone(),
        asset.name.clone(),
        asset.version.clone(),
        asset.content_type.clone(),
        asset.content_hash.clone(),
        saturating_i64(asset.size_bytes).to_string(),
        CONTENT_ENGINE.encode(&asset.content),
        asset.created_at_unix.to_string(),
        asset.updated_at_unix.to_string(),
        asset.storage_uri.clone().unwrap_or_default(),
        asset.variant.clone(),
        bool_param(asset.yanked),
        asset.visibility.as_str().to_string(),
    ]
}

/// True when `error` carries a surfaced SQLite `UNIQUE constraint failed` — the
/// D1 proxy equivalent of Postgres SQLSTATE 23505 (the Worker wraps a
/// rolled-back constraint failure as a code-5001 API error whose message
/// preserves the SQLite text). Used as defense in depth for the create ops,
/// which primarily map the conflict via the pre-state read + bare
/// `ON CONFLICT DO NOTHING` (invariant 2).
fn is_d1_unique_violation(error: &StorageError) -> bool {
    matches!(error, StorageError::Runtime(message) if message.contains("UNIQUE constraint failed"))
}

impl D1ControlPlaneStore {
    // --- Assets + channels + retention over the proxy binding, tenant-DB
    // routed (issue #456) ---

    /// Upsert an asset into its tenant's D1 database (a single statement, no
    /// CAS, routed through the proxy binding so the whole family shares one
    /// routing path). Immutable identity/version columns are never touched on
    /// conflict, mirroring the Postgres `upsert_asset`. Fails closed without a
    /// proxy.
    pub(super) async fn upsert_asset_d1_async(
        &self,
        asset: &StoredAsset,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("upsert_asset")?;
        let binding = self.tenant_proxy_binding(&asset.tenant_id)?;
        let statement = D1ProxyStatement::with_params(
            format!(
                "INSERT INTO stored_assets ({STORED_ASSET_COLUMNS}) \
                 VALUES ({STORED_ASSET_INSERT_VALUES}) \
                 ON CONFLICT (id) DO UPDATE SET {STORED_ASSET_ON_CONFLICT_UPDATE}"
            ),
            asset_insert_params(asset),
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// Create an asset only if absent (issue #369). A single guarded
    /// `INSERT ... ON CONFLICT DO NOTHING RETURNING id`: a returned row means
    /// this call wrote it (`Ok(true)`); an empty set means a rival first push of
    /// the SAME immutable version won (either the id OR the composite tuple —
    /// the bare `ON CONFLICT DO NOTHING` suppresses BOTH constraints), so this
    /// is the idempotent loser (`Ok(false)`), never a raw error. Fails closed
    /// without a proxy.
    pub(super) async fn create_asset_if_absent_d1_async(
        &self,
        asset: &StoredAsset,
    ) -> Result<bool, StorageError> {
        let proxy = self.proxy_client("create_asset_if_absent")?;
        let binding = self.tenant_proxy_binding(&asset.tenant_id)?;
        let statement = D1ProxyStatement::with_params(
            format!(
                "INSERT INTO stored_assets ({STORED_ASSET_COLUMNS}) \
                 VALUES ({STORED_ASSET_INSERT_VALUES}) \
                 ON CONFLICT DO NOTHING RETURNING id"
            ),
            asset_insert_params(asset),
        );
        match proxy.query_on(Some(&binding), &statement).await {
            Ok(result) => Ok(!result.results.is_empty()),
            // Defense in depth: a surfaced UNIQUE violation is the same
            // idempotent loser the guard already models (invariant 2).
            Err(error) => {
                let mapped = d1_error(error);
                if is_d1_unique_violation(&mapped) {
                    return Ok(false);
                }
                Err(mapped)
            }
        }
    }

    /// Atomically admit a push against the tenant asset-storage quota AND
    /// publish it (issue #371), as ONE `/d1/batch` on the tenant's database. A
    /// pre-state read (id/composite existence + the tenant's used bytes) then a
    /// GUARDED conditional insert whose `WHERE` enforces the quota with
    /// `CAST(? AS INTEGER)` on the size and bound (invariant 1: the size enters
    /// arithmetic against an INTEGER column, and the proxy binds TEXT), plus a
    /// bare `ON CONFLICT DO NOTHING` so a first-push loser (id or composite) is
    /// suppressed rather than raised (invariant 2). The insert's `RETURNING`
    /// row, the pre-state existence, and the recomputed `quota_ok` feed the
    /// shared [`classify_asset_quota_admission`] so the Admitted / AlreadyExists
    /// / OverQuota truth table can never drift from Postgres/memory. Fails
    /// closed without a proxy.
    pub(super) async fn create_asset_within_quota_d1_async(
        &self,
        asset: &StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        let proxy = self.proxy_client("create_asset_within_quota")?;
        let binding = self.tenant_proxy_binding(&asset.tenant_id)?;
        let size = saturating_i64(asset.size_bytes).to_string();
        // Empty string = unlimited: the SQL quota guard is a no-op (`? = ''`).
        let quota_param = quota_bytes
            .map(saturating_i64)
            .map(|q| q.to_string())
            .unwrap_or_default();

        let mut insert_params = asset_insert_params(asset);
        insert_params.extend([
            quota_param.clone(),
            asset.tenant_id.clone(),
            size.clone(),
            quota_param.clone(),
        ]);

        let statements = vec![
            // S0: pre-state — id/composite existence + the tenant's used bytes.
            D1ProxyStatement::with_params(
                "SELECT \
                 (SELECT COUNT(*) FROM stored_assets WHERE id = ?) AS id_exists, \
                 (SELECT COUNT(*) FROM stored_assets \
                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? \
                    AND variant = ?) AS tuple_exists, \
                 COALESCE((SELECT SUM(size_bytes) FROM stored_assets WHERE tenant_id = ?), 0) \
                     AS used_bytes",
                vec![
                    asset.id.clone(),
                    asset.tenant_id.clone(),
                    asset.asset_type.clone(),
                    asset.name.clone(),
                    asset.version.clone(),
                    asset.variant.clone(),
                    asset.tenant_id.clone(),
                ],
            ),
            // S1: the guarded quota-admitting insert. CAST the size + bound: they
            // enter arithmetic against the INTEGER `size_bytes` column and the
            // proxy binds TEXT (invariant 1). Bare `ON CONFLICT DO NOTHING`
            // suppresses BOTH unique constraints (invariant 2).
            D1ProxyStatement::with_params(
                format!(
                    "INSERT INTO stored_assets ({STORED_ASSET_COLUMNS}) \
                     SELECT {STORED_ASSET_INSERT_VALUES} \
                     WHERE (? = '' OR \
                            COALESCE((SELECT SUM(size_bytes) FROM stored_assets \
                                      WHERE tenant_id = ?), 0) + CAST(? AS INTEGER) \
                                <= CAST(? AS INTEGER)) \
                     ON CONFLICT DO NOTHING \
                     RETURNING 1"
                ),
                insert_params,
            ),
        ];

        let results = match proxy.batch_on(Some(&binding), &statements).await {
            Ok(results) => results,
            // Defense in depth: a surfaced UNIQUE violation is the AlreadyExists
            // loser the guard already models (invariant 2).
            Err(error) => {
                let mapped = d1_error(error);
                if is_d1_unique_violation(&mapped) {
                    return Ok(AssetQuotaAdmission::AlreadyExists);
                }
                return Err(mapped);
            }
        };
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: create_asset_within_quota batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }

        let state: AssetQuotaStateRow =
            decode_row(results[0].results.first().ok_or_else(|| {
                StorageError::Runtime(
                    "cloudflare d1: create_asset_within_quota pre-state read returned no row"
                        .to_string(),
                )
            })?)?;
        let inserted = !results[1].results.is_empty();
        let id_or_tuple_exists = state.id_exists != 0 || state.tuple_exists != 0;
        let used_bytes = nonnegative_u64(state.used_bytes);
        let quota_ok = match quota_bytes {
            None => true,
            Some(quota) => used_bytes.saturating_add(asset.size_bytes) <= quota,
        };
        Ok(classify_asset_quota_admission(
            inserted,
            id_or_tuple_exists,
            quota_ok,
            used_bytes,
            asset.size_bytes,
            quota_bytes,
        ))
    }

    /// Read one asset by id. The signature carries no tenant, so this FANS OUT
    /// over the provisioned tenant bindings (asset ids are globally unique, so
    /// at most one binding answers) — the id-only locate pattern the wallet
    /// `settle`/`release` use. `Ok(None)` when no binding holds it. Fails closed
    /// without a proxy.
    pub(super) async fn get_asset_d1_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredAsset>, StorageError> {
        let proxy = self.proxy_client("get_asset")?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!("SELECT {STORED_ASSET_COLUMNS} FROM stored_assets WHERE id = ?"),
                vec![id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if let Some(row) = result.results.first() {
                return Ok(Some(decode_row::<StoredAssetD1Row>(row)?.into_stored()?));
            }
        }
        Ok(None)
    }

    /// List a tenant's assets, optionally narrowed to one `asset_type`, ordered
    /// identically to Postgres. Opt-in: an unprovisioned tenant has no database,
    /// so EMPTY (matching `list_wallets`/`get_wallet`). Fails closed without a
    /// proxy.
    pub(super) async fn list_assets_d1_async(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        let proxy = self.proxy_client("list_assets")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = match asset_type {
            Some(asset_type) => D1ProxyStatement::with_params(
                format!(
                    "SELECT {STORED_ASSET_COLUMNS} FROM stored_assets \
                     WHERE tenant_id = ? AND asset_type = ? \
                     ORDER BY name ASC, version ASC"
                ),
                vec![tenant_id.to_string(), asset_type.to_string()],
            ),
            None => D1ProxyStatement::with_params(
                format!(
                    "SELECT {STORED_ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ? \
                     ORDER BY asset_type ASC, name ASC, version ASC"
                ),
                vec![tenant_id.to_string()],
            ),
        };
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<StoredAssetD1Row>(row)?.into_stored())
            .collect()
    }

    /// The withheld-asset inverse of [`Self::list_assets_d1_async`] (issue #379):
    /// the non-`visible` (`pending_scan`/`quarantined`) rows an operator needs to
    /// inspect, ordered identically to Postgres. Opt-in empty for an
    /// unprovisioned tenant; fails closed without a proxy.
    pub(super) async fn list_withheld_assets_d1_async(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        let proxy = self.proxy_client("list_withheld_assets")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = match asset_type {
            Some(asset_type) => D1ProxyStatement::with_params(
                format!(
                    "SELECT {STORED_ASSET_COLUMNS} FROM stored_assets \
                     WHERE tenant_id = ? AND asset_type = ? AND visibility <> 'visible' \
                     ORDER BY name ASC, version ASC, variant ASC"
                ),
                vec![tenant_id.to_string(), asset_type.to_string()],
            ),
            None => D1ProxyStatement::with_params(
                format!(
                    "SELECT {STORED_ASSET_COLUMNS} FROM stored_assets \
                     WHERE tenant_id = ? AND visibility <> 'visible' \
                     ORDER BY asset_type ASC, name ASC, version ASC, variant ASC"
                ),
                vec![tenant_id.to_string()],
            ),
        };
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<StoredAssetD1Row>(row)?.into_stored())
            .collect()
    }

    /// The tenant's total stored asset bytes (a metadata-only SUM over
    /// `size_bytes`, never loading `content`), mirroring the Postgres
    /// `tenant_asset_storage_bytes_used`. Opt-in: an unprovisioned tenant is
    /// `Ok(0)`. Fails closed without a proxy.
    pub(super) async fn tenant_asset_storage_bytes_used_d1_async(
        &self,
        tenant_id: &str,
    ) -> Result<u64, StorageError> {
        let proxy = self.proxy_client("tenant_asset_storage_bytes_used")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(0);
        };
        let statement = D1ProxyStatement::with_params(
            "SELECT COALESCE(SUM(size_bytes), 0) AS used_bytes FROM stored_assets \
             WHERE tenant_id = ?",
            vec![tenant_id.to_string()],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        match result.results.first() {
            None => Ok(0),
            Some(row) => Ok(nonnegative_u64(decode_row::<UsedBytesRow>(row)?.used_bytes)),
        }
    }

    /// Delete an asset by id. The signature carries no tenant, so this FANS OUT
    /// over the provisioned tenant bindings and deletes wherever the globally
    /// unique id lives; `Ok(true)` when a binding reported a change. Fails closed
    /// without a proxy.
    pub(super) async fn delete_asset_d1_async(&self, id: &str) -> Result<bool, StorageError> {
        let proxy = self.proxy_client("delete_asset")?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                "DELETE FROM stored_assets WHERE id = ?",
                vec![id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// List EVERY provisioned tenant's assets (issue #175 admin cross-tenant
    /// read). Fans out over the provisioned tenant bindings, then re-sorts the
    /// union to the Postgres `ORDER BY tenant_id, asset_type, name, version` so
    /// the list is row-for-row identical. Empty registry -> empty; fails closed
    /// without a proxy.
    pub(super) async fn list_all_assets_d1_async(&self) -> Result<Vec<StoredAsset>, StorageError> {
        let proxy = self.proxy_client("list_all_assets")?;
        let mut assets = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement =
                D1ProxyStatement::new(format!("SELECT {STORED_ASSET_COLUMNS} FROM stored_assets"));
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                assets.push(decode_row::<StoredAssetD1Row>(row)?.into_stored()?);
            }
        }
        assets.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.asset_type.cmp(&right.asset_type))
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.version.cmp(&right.version))
        });
        Ok(assets)
    }

    /// Upsert a channel pointer into its tenant's database, mirroring the
    /// Postgres `upsert_asset_channel` (move-by-upsert on the id). Fails closed
    /// without a proxy.
    pub(super) async fn upsert_asset_channel_d1_async(
        &self,
        channel: &StoredAssetChannel,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("upsert_asset_channel")?;
        let binding = self.tenant_proxy_binding(&channel.tenant_id)?;
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO asset_channels \
             (id, tenant_id, asset_type, name, channel, version, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             version = excluded.version, updated_at_unix = excluded.updated_at_unix",
            vec![
                channel.id.clone(),
                channel.tenant_id.clone(),
                channel.asset_type.clone(),
                channel.name.clone(),
                channel.channel.clone(),
                channel.version.clone(),
                channel.updated_at_unix.to_string(),
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// List a `{tenant, asset_type, name}`'s channel pointers, ordered by channel
    /// like Postgres. Opt-in empty for an unprovisioned tenant; fails closed
    /// without a proxy.
    pub(super) async fn list_asset_channels_d1_async(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        let proxy = self.proxy_client("list_asset_channels")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = D1ProxyStatement::with_params(
            format!(
                "SELECT {ASSET_CHANNEL_COLUMNS} FROM asset_channels \
                 WHERE tenant_id = ? AND asset_type = ? AND name = ? \
                 ORDER BY channel ASC"
            ),
            vec![
                tenant_id.to_string(),
                asset_type.to_string(),
                name.to_string(),
            ],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<AssetChannelD1Row>(row).map(StoredAssetChannel::from))
            .collect()
    }

    /// Delete a channel pointer by id (fan-out over provisioned tenant bindings,
    /// the globally unique id). Fails closed without a proxy.
    pub(super) async fn delete_asset_channel_d1_async(
        &self,
        id: &str,
    ) -> Result<bool, StorageError> {
        let proxy = self.proxy_client("delete_asset_channel")?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                "DELETE FROM asset_channels WHERE id = ?",
                vec![id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// List EVERY provisioned tenant's channels (admin cross-tenant read). Fans
    /// out then re-sorts to the Postgres `ORDER BY tenant_id, asset_type, name`.
    /// Empty registry -> empty; fails closed without a proxy.
    pub(super) async fn list_all_asset_channels_d1_async(
        &self,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        let proxy = self.proxy_client("list_all_asset_channels")?;
        let mut channels = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::new(format!(
                "SELECT {ASSET_CHANNEL_COLUMNS} FROM asset_channels"
            ));
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                channels.push(decode_row::<AssetChannelD1Row>(row).map(StoredAssetChannel::from)?);
            }
        }
        channels.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.asset_type.cmp(&right.asset_type))
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(channels)
    }

    /// Move a channel to a version ONLY when that version is durably resolvable
    /// (present, no yanked variant) — the #367 atomicity invariant. As ONE
    /// `/d1/batch` on the tenant's database: read the prior target for audit,
    /// then a GUARDED upsert whose `WHERE EXISTS(version) AND NOT EXISTS(yanked
    /// variant)` and the channel write share one transaction, so a concurrent
    /// yank/delete can never strand the channel (the behavioral mirror of the
    /// Postgres `FOR UPDATE` lock on the version rows). An empty `RETURNING` set
    /// means the target was not resolvable at commit time. Fails closed without
    /// a proxy.
    pub(super) async fn move_asset_channel_if_resolvable_d1_async(
        &self,
        channel: &StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        let proxy = self.proxy_client("move_asset_channel_if_resolvable")?;
        let binding = self.tenant_proxy_binding(&channel.tenant_id)?;

        let statements = vec![
            // S0: the prior target (for audit evidence), read before the move.
            D1ProxyStatement::with_params(
                "SELECT version FROM asset_channels WHERE id = ?",
                vec![channel.id.clone()],
            ),
            // S1: the guarded resolvable upsert. The resolvability check and the
            // channel write are one statement in one transaction.
            D1ProxyStatement::with_params(
                "INSERT INTO asset_channels \
                 (id, tenant_id, asset_type, name, channel, version, updated_at_unix) \
                 SELECT ?, ?, ?, ?, ?, ?, ? \
                 WHERE EXISTS(SELECT 1 FROM stored_assets \
                              WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) \
                   AND NOT EXISTS(SELECT 1 FROM stored_assets \
                                  WHERE tenant_id = ? AND asset_type = ? AND name = ? \
                                    AND version = ? AND yanked = 1) \
                 ON CONFLICT (id) DO UPDATE SET \
                 version = excluded.version, updated_at_unix = excluded.updated_at_unix \
                 RETURNING version",
                vec![
                    channel.id.clone(),
                    channel.tenant_id.clone(),
                    channel.asset_type.clone(),
                    channel.name.clone(),
                    channel.channel.clone(),
                    channel.version.clone(),
                    channel.updated_at_unix.to_string(),
                    channel.tenant_id.clone(),
                    channel.asset_type.clone(),
                    channel.name.clone(),
                    channel.version.clone(),
                    channel.tenant_id.clone(),
                    channel.asset_type.clone(),
                    channel.name.clone(),
                    channel.version.clone(),
                ],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: move_asset_channel batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        if results[1].results.is_empty() {
            return Ok(ChannelMoveOutcome::TargetNotResolvable);
        }
        let prior_version = results[0]
            .results
            .first()
            .map(decode_row::<ChannelVersionRow>)
            .transpose()?
            .map(|row| row.version);
        Ok(ChannelMoveOutcome::Moved { prior_version })
    }

    /// Yank/unyank every variant row of a version (issue #367). As ONE
    /// `/d1/batch`: a state read (version existence + channel reference), then a
    /// GUARDED update that yanks only when the version is NOT referenced by a
    /// channel (unyank skips the guard — it can never strand a channel). Both
    /// touch `stored_assets`/`asset_channels` in one transaction, closing the
    /// write-skew hazard the move guards from the other side. Fails closed
    /// without a proxy.
    pub(super) async fn set_asset_version_yank_d1_async(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError> {
        let proxy = self.proxy_client("set_asset_version_yank")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        let yank_flag = bool_param(yanked);

        let statements = vec![
            // S0: version existence + channel-reference state.
            D1ProxyStatement::with_params(
                "SELECT \
                 (SELECT COUNT(*) FROM stored_assets \
                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) \
                     AS variant_count, \
                 (SELECT COUNT(*) FROM asset_channels \
                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) \
                     AS referenced_count",
                vec![
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                ],
            ),
            // S1: guarded yank/unyank. The `? = '0'` term short-circuits the
            // channel-reference guard for an UNyank (always safe).
            D1ProxyStatement::with_params(
                "UPDATE stored_assets SET yanked = ?, updated_at_unix = ? \
                 WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? \
                   AND (? = '0' OR NOT EXISTS(SELECT 1 FROM asset_channels \
                       WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?)) \
                 RETURNING id",
                vec![
                    yank_flag.clone(),
                    now_unix.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                    yank_flag,
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                ],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: set_asset_version_yank batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        let state: YankStateRow = decode_row(results[0].results.first().ok_or_else(|| {
            StorageError::Runtime(
                "cloudflare d1: set_asset_version_yank state read returned no row".to_string(),
            )
        })?)?;
        if state.variant_count == 0 {
            return Ok(VersionYankOutcome::NotFound);
        }
        if yanked && state.referenced_count > 0 {
            return Ok(VersionYankOutcome::ReferencedByChannel);
        }
        Ok(VersionYankOutcome::Applied {
            variants: results[1].results.len(),
        })
    }

    /// Delete one variant row, rejecting the delete when it would strip the last
    /// resolvable variant of a channel-referenced version (issue #367). As ONE
    /// `/d1/batch`: a state read (variant existence + remaining-resolvable +
    /// channel reference), then a GUARDED delete admitting only when a resolvable
    /// sibling remains OR no channel references the version. Fails closed without
    /// a proxy.
    pub(super) async fn delete_asset_variant_if_unreferenced_d1_async(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        let proxy = self.proxy_client("delete_asset_variant_if_unreferenced")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;

        let statements = vec![
            // S0: variant existence + a resolvable sibling? + channel reference.
            D1ProxyStatement::with_params(
                "SELECT \
                 (SELECT COUNT(*) FROM stored_assets WHERE id = ?) AS id_present, \
                 (SELECT COUNT(*) FROM stored_assets \
                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? \
                    AND id <> ? AND yanked = 0) AS other_resolvable, \
                 (SELECT COUNT(*) FROM asset_channels \
                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) \
                     AS referenced_count",
                vec![
                    id.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                    id.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                ],
            ),
            // S1: guarded delete — admitted iff a resolvable sibling remains OR no
            // channel references the version.
            D1ProxyStatement::with_params(
                "DELETE FROM stored_assets WHERE id = ? \
                 AND (EXISTS(SELECT 1 FROM stored_assets \
                            WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? \
                              AND id <> ? AND yanked = 0) \
                      OR NOT EXISTS(SELECT 1 FROM asset_channels \
                            WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?)) \
                 RETURNING id",
                vec![
                    id.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                    id.to_string(),
                    tenant_id.to_string(),
                    asset_type.to_string(),
                    name.to_string(),
                    version.to_string(),
                ],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: delete_asset_variant batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        let state: VariantDeleteStateRow =
            decode_row(results[0].results.first().ok_or_else(|| {
                StorageError::Runtime(
                    "cloudflare d1: delete_asset_variant state read returned no row".to_string(),
                )
            })?)?;
        if state.id_present == 0 {
            return Ok(VariantDeleteOutcome::NotFound);
        }
        if state.other_resolvable == 0 && state.referenced_count > 0 {
            return Ok(VariantDeleteOutcome::BlockedByChannel);
        }
        Ok(if results[1].results.is_empty() {
            VariantDeleteOutcome::NotFound
        } else {
            VariantDeleteOutcome::Deleted
        })
    }

    /// Promote a `pending_scan` asset to its terminal `visible`/`quarantined`
    /// state (issue #378). The signature carries no tenant, so this LOCATES the
    /// holding tenant database (fan-out probe), then runs a GUARDED CAS +
    /// classify as ONE `/d1/batch`: the `UPDATE ... WHERE visibility =
    /// 'pending_scan' RETURNING visibility` fires only from pending, and a
    /// sibling state read distinguishes an already-terminal row (`NotPending`)
    /// from an absent one (`NotFound`). An unknown persisted token fails closed
    /// to `Quarantined` (invariant 5). Fails closed without a proxy.
    pub(super) async fn promote_pending_asset_visibility_d1_async(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        let proxy = self.proxy_client("promote_pending_asset_visibility")?;
        let Some(binding) = self
            .locate_asset_binding("promote_pending_asset_visibility", id)
            .await?
        else {
            return Ok(AssetVisibilityPromotionOutcome::NotFound);
        };
        let target_token = target.visibility().as_str();

        let statements = vec![
            // S0: the CAS — fire only from pending_scan, RETURNING the new state.
            D1ProxyStatement::with_params(
                "UPDATE stored_assets SET visibility = ?, updated_at_unix = ? \
                 WHERE id = ? AND visibility = 'pending_scan' RETURNING visibility",
                vec![
                    target_token.to_string(),
                    now_unix.to_string(),
                    id.to_string(),
                ],
            ),
            // S1: post-state read to classify the zero-row CAS (terminal vs gone).
            D1ProxyStatement::with_params(
                "SELECT visibility FROM stored_assets WHERE id = ?",
                vec![id.to_string()],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: promote_pending_asset_visibility batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        // S0 RETURNING a row -> the CAS fired; carry the exact new terminal state.
        if let Some(row) = results[0].results.first() {
            let promoted = decode_row::<VisibilityRow>(row)?.visibility;
            return Ok(AssetVisibilityPromotionOutcome::Promoted {
                to: AssetVisibility::from_stored(&promoted),
            });
        }
        // The CAS did not fire: the row is terminal, or it vanished.
        match results[1].results.first() {
            Some(row) => {
                let current = decode_row::<VisibilityRow>(row)?.visibility;
                Ok(AssetVisibilityPromotionOutcome::NotPending {
                    current: AssetVisibility::from_stored(&current),
                })
            }
            None => Ok(AssetVisibilityPromotionOutcome::NotFound),
        }
    }

    /// Upsert a retention policy into its tenant's database, mirroring the
    /// Postgres `upsert_retention_policy` (identity columns never touched on
    /// conflict). Fails closed without a proxy.
    pub(super) async fn upsert_retention_policy_d1_async(
        &self,
        policy: &StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("upsert_retention_policy")?;
        let binding = self.tenant_proxy_binding(&policy.tenant_id)?;
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO retention_policies \
             (id, tenant_id, resource_type, scope, keep_last_n, max_age_secs, min_age_secs, \
              created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             keep_last_n = excluded.keep_last_n, max_age_secs = excluded.max_age_secs, \
             min_age_secs = excluded.min_age_secs, updated_at_unix = excluded.updated_at_unix",
            vec![
                policy.id.clone(),
                policy.tenant_id.clone(),
                policy.resource_type.clone(),
                policy.scope.clone(),
                optional_number_param(policy.keep_last_n.map(saturating_i64)),
                optional_number_param(policy.max_age_secs),
                policy.min_age_secs.to_string(),
                policy.created_at_unix.to_string(),
                policy.updated_at_unix.to_string(),
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// List a tenant's retention policies for one `resource_type`, ordered by
    /// scope like Postgres. Opt-in empty for an unprovisioned tenant; fails
    /// closed without a proxy.
    pub(super) async fn list_retention_policies_d1_async(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        let proxy = self.proxy_client("list_retention_policies")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = D1ProxyStatement::with_params(
            format!(
                "SELECT {RETENTION_POLICY_COLUMNS} FROM retention_policies \
                 WHERE tenant_id = ? AND resource_type = ? ORDER BY scope ASC"
            ),
            vec![tenant_id.to_string(), resource_type.to_string()],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<RetentionPolicyD1Row>(row).map(StoredRetentionPolicy::from))
            .collect()
    }

    // --- tenant-DB helpers ---

    /// Fan out over the provisioned tenant bindings to find the database holding
    /// asset `id`, returning its binding or `None`.
    async fn locate_asset_binding(
        &self,
        method: &'static str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        let proxy = self.proxy_client(method)?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                "SELECT id FROM stored_assets WHERE id = ?",
                vec![id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if !result.results.is_empty() {
                return Ok(Some(binding));
            }
        }
        Ok(None)
    }
}
