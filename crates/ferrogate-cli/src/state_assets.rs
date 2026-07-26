// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the static asset hosting registry
// (issue #176/#177/#179) -- CRUD, tenant storage-quota accounting, and the
// S3-compatible asset-bucket client resolver.

use super::*;

use ferrogate_storage::sha256_hex;

/// Typed failure modes for reading an asset's verified bytes, so every read
/// surface (`handle_asset_pull`, MCP `resources/read`, the `fetch_asset`
/// built-in tool) maps them to the same status/code instead of re-deriving the
/// bucket-fetch + integrity-verify logic independently.
pub(crate) enum AssetReadError {
    /// No `stored_assets` row for this id.
    NotFound,
    /// The resolved bytes' sha256 does not match the recorded `content_hash`
    /// (storage corruption or tampering) -- fail closed rather than serve it.
    Integrity,
    /// The object is above the gateway's in-memory budget
    /// (`[asset_bucket].max_gateway_buffer_bytes`), so this surface refuses to
    /// materialize it (issue #259). The caller is pointed at the presigned
    /// direct download, which does not put the gateway in the data path.
    TooLarge(String),
    /// The asset is bucket-backed but the bucket is unconfigured or unreachable.
    BucketUnavailable(String),
    /// The registry (Postgres/in-memory) itself was unavailable.
    Storage(String),
}

impl AppState {
    pub(crate) async fn upsert_asset(&self, asset: StoredAsset) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_asset(asset).await?)
    }

    /// Atomic tenant asset-storage quota admission + immutable publication
    /// (issue #371). One conditional storage mutation reserves quota for this
    /// push ONLY when the tenant's remaining capacity suffices and the id does
    /// not already exist, returning a typed [`AssetQuotaAdmission`]. Replaces the
    /// read (`tenant_asset_storage_bytes_used`) then separate `create_asset_if_absent`
    /// admission, whose read-then-write gap let two commits for two different
    /// asset ids jointly overshoot the quota.
    pub(crate) async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        self.repositories
            .create_asset_within_quota(asset, quota_bytes)
            .await
    }

    /// Load an asset and its verified bytes: resolves bucket-backed content
    /// (issue #176) from the configured bucket, then re-verifies the sha256 on
    /// every read (#176/#179). Shared by the MCP asset read surfaces -- the
    /// `fetch_asset` built-in tool and `resources/read` -- so they agree on
    /// integrity, on the gateway memory bound, and on error mapping.
    ///
    /// The bucket fetch goes through [`read_object_bounded`], the one bounded
    /// buffering read (issue #259 round 2): this helper used to call
    /// `get_object` directly with no size gate, so an agent holding
    /// `assets.read` could pull a 5 GiB presign-committed object into gateway
    /// memory -- and then into a ~1.33x base64 copy -- through either surface.
    pub(crate) async fn read_asset_content(
        &self,
        id: &str,
        request_id: &str,
    ) -> Result<(StoredAsset, Vec<u8>), AssetReadError> {
        let asset = match self.get_asset(id).await {
            Ok(Some(asset)) => asset,
            Ok(None) => return Err(AssetReadError::NotFound),
            Err(error) => return Err(AssetReadError::Storage(error.to_string())),
        };
        // #366: a pending/quarantined asset is withheld from EVERY read surface
        // that routes through this shared chokepoint -- the REST pull, the MCP
        // `resources/read`, and the `fetch_asset` built-in tool. Reported as
        // NotFound so an unproven object is indistinguishable from absent, the
        // same disposition the REST resolution and presigned download paths use.
        if !asset.is_downloadable() {
            return Err(AssetReadError::NotFound);
        }
        let content = if let Some(storage_uri) = asset.storage_uri.as_deref() {
            // The declared size is refused before the bucket client is even
            // resolved: there is no work worth doing for an object the gateway
            // will not hold, and the refusal must not be masked by an unrelated
            // "no bucket configured" 503.
            let buffer_limit = self.asset_max_gateway_buffer_bytes();
            if asset.size_bytes > buffer_limit {
                return Err(AssetReadError::TooLarge(
                    crate::gateway::asset_bucket::asset_too_large_for_buffering_message(
                        &asset.asset_type,
                        &asset.name,
                        &asset.version,
                        asset.size_bytes,
                        buffer_limit,
                    ),
                ));
            }
            let Some(bucket) = self.asset_bucket_client() else {
                return Err(AssetReadError::BucketUnavailable(
                    "this asset is bucket-backed but no asset_bucket is configured".to_string(),
                ));
            };
            match crate::gateway::asset_bucket::read_object_bounded(
                &bucket,
                storage_uri,
                asset.size_bytes,
                buffer_limit,
                id,
                request_id,
            )
            .await
            {
                Ok(content) => content,
                Err(crate::gateway::asset_bucket::BufferedReadRefusal::TooLarge {
                    size_bytes,
                    limit_bytes,
                }) => {
                    return Err(AssetReadError::TooLarge(
                        crate::gateway::asset_bucket::asset_too_large_for_buffering_message(
                            &asset.asset_type,
                            &asset.name,
                            &asset.version,
                            size_bytes,
                            limit_bytes,
                        ),
                    ))
                }
                Err(crate::gateway::asset_bucket::BufferedReadRefusal::Transport) => {
                    return Err(AssetReadError::BucketUnavailable(
                        crate::gateway::asset_bucket::BUCKET_READ_UNAVAILABLE_MESSAGE.to_string(),
                    ))
                }
            }
        } else {
            asset.content.clone()
        };
        if sha256_hex(&content) != asset.content_hash {
            return Err(AssetReadError::Integrity);
        }
        Ok((asset, content))
    }

    pub(crate) async fn get_asset(&self, id: &str) -> anyhow::Result<Option<StoredAsset>> {
        Ok(self.repositories.get_asset(id).await?)
    }

    pub(crate) async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> anyhow::Result<Vec<StoredAsset>> {
        Ok(self.repositories.list_assets(tenant_id, asset_type).await?)
    }

    /// Operator-only listing of the tenant's WITHHELD (`pending_scan`/
    /// `quarantined`) assets (issue #379). The consumer [`Self::list_assets`]
    /// path deliberately hides these (#366); this is the inverse view the
    /// operator surface reads. Filtering happens in storage so only the withheld
    /// rows are loaded.
    pub(crate) async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> anyhow::Result<Vec<StoredAsset>> {
        Ok(self
            .repositories
            .list_withheld_assets(tenant_id, asset_type)
            .await?)
    }

    /// Unconditionally upsert a channel pointer, bypassing the #367 resolvability
    /// guard. Test-only: fixtures use it to pin a version (including deliberately
    /// dangling states) that production code can only reach through the atomic
    /// [`Self::move_asset_channel_if_resolvable`]. Production channel moves must
    /// go through that guarded path.
    #[cfg(test)]
    pub(crate) async fn upsert_asset_channel(
        &self,
        channel: ferrogate_storage::StoredAssetChannel,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_asset_channel(channel).await?)
    }

    pub(crate) async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> anyhow::Result<Vec<ferrogate_storage::StoredAssetChannel>> {
        Ok(self
            .repositories
            .list_asset_channels(tenant_id, asset_type, name)
            .await?)
    }

    pub(crate) async fn delete_asset_channel(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_asset_channel(id).await?)
    }

    /// Atomically move a channel pointer only when its target version is durably
    /// resolvable (issue #367). Replaces the former read-then-upsert pair whose
    /// gap let a concurrent yank/delete strand the channel; the resolvability
    /// check and the channel write now happen under one serialization point.
    pub(crate) async fn move_asset_channel_if_resolvable(
        &self,
        channel: ferrogate_storage::StoredAssetChannel,
    ) -> Result<ferrogate_storage::ChannelMoveOutcome, StorageError> {
        self.repositories
            .move_asset_channel_if_resolvable(channel)
            .await
    }

    /// Atomically set/clear the yank flag on every variant of a version (issue
    /// #367). Yank is rejected while a channel references the version.
    pub(crate) async fn set_asset_version_yank(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<ferrogate_storage::VersionYankOutcome, StorageError> {
        self.repositories
            .set_asset_version_yank(tenant_id, asset_type, name, version, yanked, now_unix)
            .await
    }

    /// Atomically promote a `pending_scan` asset row to a terminal visibility
    /// after an out-of-band scan completes (issue #378). The flip fires only
    /// from the `pending_scan` state (one short conditional CAS); a missing or
    /// already-terminal row is rejected fail-closed. This is the only path that
    /// moves an asset out of `pending_scan` -- the push screening (#366) only
    /// ever admits INTO it.
    pub(crate) async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: ferrogate_storage::AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<ferrogate_storage::AssetVisibilityPromotionOutcome, StorageError> {
        self.repositories
            .promote_pending_asset_visibility(id, target, now_unix)
            .await
    }

    /// Atomically delete one variant row unless it would strand a channel on an
    /// absent version (issue #367).
    pub(crate) async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<ferrogate_storage::VariantDeleteOutcome, StorageError> {
        self.repositories
            .delete_asset_variant_if_unreferenced(id, tenant_id, asset_type, name, version)
            .await
    }

    /// Binds (or re-binds) a custom hostname to a `{tenant}/{site}` static
    /// site (#265). The caller audits the change via the admin audit-event
    /// path and normalizes/validates the hostname first.
    pub(crate) async fn upsert_site_domain(
        &self,
        domain: ferrogate_storage::StoredSiteDomain,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_site_domain(domain).await?)
    }

    pub(crate) async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> anyhow::Result<Option<ferrogate_storage::StoredSiteDomain>> {
        Ok(self.repositories.get_site_domain(hostname).await?)
    }

    /// Lists bindings; `None` is the platform-operator all-tenants view (also
    /// used at startup to merge bound hostnames into the ACME domain set).
    pub(crate) async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> anyhow::Result<Vec<ferrogate_storage::StoredSiteDomain>> {
        Ok(self.repositories.list_site_domains(tenant_id).await?)
    }

    pub(crate) async fn delete_site_domain(&self, hostname: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_site_domain(hostname).await?)
    }

    /// Writes (or refreshes) the DNS ownership proof / challenge for
    /// `(tenant_id, hostname)` (#488). A `StoredSiteDomain` is intent; this is
    /// the evidence the serve gate requires.
    pub(crate) async fn upsert_site_domain_verification(
        &self,
        verification: ferrogate_storage::StoredSiteDomainVerification,
    ) -> anyhow::Result<()> {
        Ok(self
            .repositories
            .upsert_site_domain_verification(verification)
            .await?)
    }

    /// Reads the proof for exactly `(tenant_id, hostname)`. `Ok(None)` means no
    /// proof exists at all, which the serve gate treats as NOT servable.
    pub(crate) async fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> anyhow::Result<Option<ferrogate_storage::StoredSiteDomainVerification>> {
        Ok(self
            .repositories
            .get_site_domain_verification(tenant_id, hostname)
            .await?)
    }

    /// Lists proofs; `None` is the platform-operator view used by the #488
    /// startup migration backfill.
    pub(crate) async fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> anyhow::Result<Vec<ferrogate_storage::StoredSiteDomainVerification>> {
        Ok(self
            .repositories
            .list_site_domain_verifications(tenant_id)
            .await?)
    }

    pub(crate) async fn delete_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .repositories
            .delete_site_domain_verification(tenant_id, hostname)
            .await?)
    }

    /// Cumulative stored bytes for a tenant across all asset types, used to
    /// enforce `StoredPlan::default_asset_storage_quota_bytes` at push time.
    pub(crate) async fn tenant_asset_storage_bytes_used(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<u64> {
        Ok(self
            .repositories
            .tenant_asset_storage_bytes_used(tenant_id)
            .await?)
    }

    /// Resolves the S3-compatible bucket client for `/v1/assets/*` content
    /// (issue #176) from `[asset_bucket]`. `None` when disabled or any
    /// required piece is missing -- the same opt-in, fail-closed-only-when
    /// -misconfigured-while-enabled shape `aws_provider_credentials`/
    /// `gcp_provider_credentials` already use, except config validation
    /// (`validate_asset_bucket`) already rejects an incomplete `enabled =
    /// true` section at load time, so a `None` here in practice only ever
    /// means "bucket storage isn't configured, use the inline path".
    /// TTL (seconds) for gateway-issued presigned asset URLs (issue #259),
    /// read from `[asset_bucket].presign_ttl_secs` and bounded to `[1,
    /// 604800]` (S3's 7-day maximum). Defaults to 900s (15 minutes).
    pub(crate) fn asset_presign_ttl_secs(&self) -> u64 {
        const DEFAULT_TTL_SECS: u64 = 900;
        const MAX_TTL_SECS: u64 = 604_800;
        self.config
            .asset_bucket
            .presign_ttl_secs
            .unwrap_or(DEFAULT_TTL_SECS)
            .clamp(1, MAX_TTL_SECS)
    }

    /// Per-object size ceiling (bytes) for the presigned large-file path
    /// (issue #259), read from `[asset_bucket].presign_max_object_bytes`.
    /// Defaults to 5 GiB. This is a per-object cap layered on top of the
    /// tenant-wide cumulative `asset_storage_quota_bytes`.
    pub(crate) fn asset_presign_max_object_bytes(&self) -> u64 {
        const DEFAULT_MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
        self.config
            .asset_bucket
            .presign_max_object_bytes
            .unwrap_or(DEFAULT_MAX_OBJECT_BYTES)
    }

    /// The largest object the gateway will hold in memory for an asset
    /// operation (issue #259), read from
    /// `[asset_bucket].max_gateway_buffer_bytes`.
    ///
    /// This is the memory bound that `presign_max_object_bytes` is NOT: the
    /// per-object ceiling caps how large an object may be, this caps how much
    /// of one the gateway may resident-hold. Above it the presigned commit
    /// verifies and copies in a bounded streaming pass, and every buffering
    /// bucket-backed read refuses rather than materializing the object (the
    /// caller uses the presigned direct download instead). Defaults to
    /// `INLINE_ASSET_MAX_BYTES` so an inline-stored asset -- which is already
    /// in memory, having come from the registry row -- is never affected by the
    /// bound.
    ///
    /// Scope, stated exactly, because round 1 of #259 claimed this bound
    /// universally while three read surfaces ignored it. It applies to: the
    /// presigned commit's verify-and-copy leg, the registry pull
    /// (`GET /v1/assets/...`), the `fetch_asset` built-in tool, MCP
    /// `resources/read`, and the static-site serve -- because all of them now
    /// route their bucket read through
    /// [`read_object_bounded`](crate::gateway::asset_bucket::read_object_bounded),
    /// and the transport cannot be called without a budget. It does NOT bound
    /// aggregate concurrency: peak gateway memory for asset reads is this
    /// value times the number of in-flight requests, and nothing yet caps that
    /// multiplier (honestly disclosed on the issue; admission control is a
    /// follow-up, not a claim made here).
    pub(crate) fn asset_max_gateway_buffer_bytes(&self) -> u64 {
        self.config
            .asset_bucket
            .max_gateway_buffer_bytes
            .unwrap_or(crate::gateway::assets::INLINE_ASSET_MAX_BYTES)
    }

    /// Resolves the object-storage backend for `/v1/assets/*` content behind
    /// the [`AssetObjectStore`](crate::gateway::asset_bucket::AssetObjectStore)
    /// trait (issue #411). Defaults to the S3/R2 SigV4 client; the
    /// `workers-static-assets` backend selects a Cloudflare-native publish
    /// target instead. `None` when disabled or any required piece is missing,
    /// the same opt-in, fail-closed-only-when-misconfigured shape as before.
    pub(crate) fn asset_bucket_client(
        &self,
    ) -> Option<Box<dyn crate::gateway::asset_bucket::AssetObjectStore>> {
        let bucket = &self.config.asset_bucket;
        match bucket.backend {
            crate::config::AssetBucketBackend::S3 => {
                // The S3-only load-time guards (`validate_asset_bucket`'s
                // credential rules, `validate_asset_bucket_r2`'s host/region
                // rules) gate on this same predicate (issue #485) rather than
                // on a second copy of `enabled && backend == S3`, so they can
                // never fire for a client this never builds.
                if !bucket.builds_s3_client() {
                    return None;
                }
                let endpoint = bucket.endpoint.clone()?;
                let bucket_name = bucket.bucket.clone()?;
                let region = bucket.region.clone()?;
                let access_key_id = bucket.access_key_id.clone()?;
                let secret_access_key = std::env::var(bucket.secret_access_key_env.as_deref()?)
                    .ok()
                    .filter(|value| !value.is_empty())?;
                Some(Box::new(
                    crate::gateway::asset_bucket::AssetBucketClient::new(
                        crate::gateway::asset_bucket::AssetBucketConfig {
                            endpoint,
                            bucket: bucket_name,
                            region,
                            access_key_id,
                            secret_access_key,
                        },
                    ),
                ))
            }
            crate::config::AssetBucketBackend::WorkersStaticAssets => {
                if !bucket.enabled {
                    return None;
                }
                let account_id = bucket.cf_account_id.clone()?;
                let api_token = bucket.cf_api_token.clone()?;
                let script_name = bucket.cf_script_name.clone()?;
                let cf_config = ferrogate_cloudflare::CloudflareConfig::new(account_id, api_token);
                let resolver =
                    std::sync::Arc::new(ferrogate_cloudflare::EnvTokenResolver::from_process_env());
                let client =
                    ferrogate_cloudflare::CloudflareClient::new(cf_config, resolver).ok()?;
                Some(Box::new(
                    crate::gateway::asset_bucket::WorkersStaticAssetsStore::new(
                        std::sync::Arc::new(client),
                        script_name,
                    ),
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "state_assets_test.rs"]
mod state_assets_test;
