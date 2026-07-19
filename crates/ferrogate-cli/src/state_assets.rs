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
    /// The asset is bucket-backed but the bucket is unconfigured or unreachable.
    BucketUnavailable(String),
    /// The registry (Postgres/in-memory) itself was unavailable.
    Storage(String),
}

impl AppState {
    pub(crate) async fn upsert_asset(&self, asset: StoredAsset) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_asset(asset).await?)
    }

    /// Load an asset and its verified bytes: resolves bucket-backed content
    /// (issue #176) from the configured bucket, then re-verifies the sha256 on
    /// every read (#176/#179). Shared by the REST pull path and the MCP asset
    /// read surfaces so they agree on integrity and error mapping.
    pub(crate) async fn read_asset_content(
        &self,
        id: &str,
    ) -> Result<(StoredAsset, Vec<u8>), AssetReadError> {
        let asset = match self.get_asset(id).await {
            Ok(Some(asset)) => asset,
            Ok(None) => return Err(AssetReadError::NotFound),
            Err(error) => return Err(AssetReadError::Storage(error.to_string())),
        };
        let content = if let Some(storage_uri) = asset.storage_uri.as_deref() {
            let Some(bucket) = self.asset_bucket_client() else {
                return Err(AssetReadError::BucketUnavailable(
                    "this asset is bucket-backed but no asset_bucket is configured".to_string(),
                ));
            };
            match bucket.get_object(storage_uri).await {
                Ok(content) => content,
                Err(error) => return Err(AssetReadError::BucketUnavailable(error.to_string())),
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

    pub(crate) async fn delete_asset(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_asset(id).await?)
    }

    /// Cumulative stored bytes for a tenant across all asset types, used to
    /// enforce `StoredPlan::default_asset_storage_quota_bytes` at push time.
    pub(crate) async fn tenant_asset_storage_bytes_used(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<u64> {
        Ok(self
            .repositories
            .list_assets(tenant_id, None)
            .await?
            .iter()
            .map(|asset| asset.size_bytes)
            .sum())
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

    pub(crate) fn asset_bucket_client(
        &self,
    ) -> Option<crate::gateway::asset_bucket::AssetBucketClient> {
        let bucket = &self.config.asset_bucket;
        if !bucket.enabled {
            return None;
        }
        let endpoint = bucket.endpoint.clone()?;
        let bucket_name = bucket.bucket.clone()?;
        let region = bucket.region.clone()?;
        let access_key_id = bucket.access_key_id.clone()?;
        let secret_access_key = std::env::var(bucket.secret_access_key_env.as_deref()?)
            .ok()
            .filter(|value| !value.is_empty())?;
        Some(crate::gateway::asset_bucket::AssetBucketClient::new(
            crate::gateway::asset_bucket::AssetBucketConfig {
                endpoint,
                bucket: bucket_name,
                region,
                access_key_id,
                secret_access_key,
            },
        ))
    }
}
