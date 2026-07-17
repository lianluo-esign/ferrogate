// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the static asset hosting registry
// (issue #176/#177/#179) -- CRUD, tenant storage-quota accounting, and the
// S3-compatible asset-bucket client resolver.

use super::*;

impl AppState {
    pub(crate) async fn upsert_asset(&self, asset: StoredAsset) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_asset(asset).await?)
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
