// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Unified static-asset hosting surface (issue #176/#177):
// /v1/assets/* -- push/pull/list CLI tool packages, MCP connection
// manifests, Skill bundles, static sites, and config files through the
// same virtual-key auth and StoredPlan entitlement gating as inference
// traffic. Part of the agent-asset hosting epic (#175).

use bytes::Bytes;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use ferrogate_storage::{sha256_hex, stored_asset_id, StoredAsset};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::sites::is_zip_archive;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_cacheable_response, write_json_error, write_json_error_and_close,
        write_json_response, AdminDeleteResponse, AdminList, AssetCacheHeaders,
        AssetMutationResponse, AssetSummary,
    },
    state::AssetReadError,
};

/// Default `Cache-Control` for authenticated `/v1/assets/*` pulls (issue
/// #258): private and always revalidated, so an agent re-pulling a tool gets a
/// cheap `304` via the strong `ETag` without a shared cache ever storing a
/// tenant's asset.
const DEFAULT_ASSET_CACHE_CONTROL: &str = "private, max-age=0, must-revalidate";

/// A storage-layer failure while reading or writing asset bytes, carrying the
/// HTTP error the gateway should return. Lets the bucket-fetch/bucket-put
/// helpers be shared between the pull path and the static-site serve/publish
/// paths (issue #258) without each call site re-deriving the error response.
pub(super) struct AssetError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl AssetError {
    pub(super) async fn write(self, session: &mut Session, request_id: &str) -> PingoraResult<()> {
        write_json_error(session, self.status, self.code, self.message, request_id).await
    }
}

/// Largest object the inline (in-memory, Pingora hot-path) push will
/// buffer. Objects at or below this stay on the simple inline path;
/// larger objects must use the presigned direct path (issue #259,
/// `gateway/asset_presign.rs`), which streams straight to the bucket so
/// bytes never buffer in the gateway. The tenant's cumulative
/// `asset_storage_quota_bytes` is enforced separately, on top of this.
const INLINE_ASSET_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Per-request byte ceiling for an inline push: the inline buffering cap,
/// further tightened to the tenant's cumulative asset storage quota when
/// that is smaller (a single object can never exceed the whole quota).
/// Replaces the former hard `MAX_ASSET_BYTES` constant with a
/// plan/quota-driven limit (issue #259).
fn inline_push_byte_limit(asset_storage_quota_bytes: Option<u64>) -> usize {
    let limit = asset_storage_quota_bytes.map_or(INLINE_ASSET_MAX_BYTES, |quota| {
        quota.min(INLINE_ASSET_MAX_BYTES)
    });
    usize::try_from(limit).unwrap_or(usize::MAX)
}

impl FerroGateway {
    pub(super) async fn handle_assets(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let Some(rest) = path.strip_prefix("/v1/assets") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "asset endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        let segments: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();

        match segments.as_slice() {
            [] => match *method {
                Method::GET => self.handle_asset_list(session, ctx, headers, None).await,
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "/v1/assets supports GET",
                        &ctx.request_id,
                    )
                    .await
                }
            },
            [asset_type] => match *method {
                Method::GET => {
                    self.handle_asset_list(session, ctx, headers, Some(asset_type))
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "/v1/assets/{asset_type} supports GET",
                        &ctx.request_id,
                    )
                    .await
                }
            },
            [asset_type, name, version] => match *method {
                Method::PUT => {
                    self.handle_asset_push(session, ctx, headers, asset_type, name, version)
                        .await
                }
                Method::GET => {
                    self.handle_asset_pull(session, ctx, headers, asset_type, name, version)
                        .await
                }
                Method::DELETE => {
                    self.handle_asset_delete(session, ctx, headers, asset_type, name, version)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "/v1/assets/{asset_type}/{name}/{version} supports GET, PUT, DELETE",
                        &ctx.request_id,
                    )
                    .await
                }
            },
            _ => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "expected /v1/assets, /v1/assets/{asset_type}, or \
                     /v1/assets/{asset_type}/{name}/{version}",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_asset_list(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(tenant_id) = auth.organization_id.clone() else {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "tenant_required",
                "assets require a tenant-attributed API key",
                &ctx.request_id,
            )
            .await;
        };
        match state.list_assets(&tenant_id, asset_type).await {
            Ok(assets) => {
                let body = AdminList::new(assets.iter().map(asset_summary).collect());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_asset_push(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(tenant_id) = auth.organization_id.clone() else {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "tenant_required",
                "assets require a tenant-attributed API key",
                &ctx.request_id,
            )
            .await;
        };

        // Two independent paths can grant this capability (issue #182): the
        // tenant's StoredPlan boolean (#176/#177, the original mechanism)
        // or the tenant holding a role bundling the "assets.host" permission
        // (the general RBAC entitlement system) -- either is sufficient.
        // New capabilities should prefer the permission path going forward
        // since it needs no StoredPlan schema change; asset_hosting_enabled
        // stays supported so existing plan-gated tenants are unaffected.
        let plan = state.resolve_tenant_plan(&tenant_id).await.ok().flatten();
        let plan_grants_access = plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled);
        let role_grants_access = state.tenant_has_permission(&tenant_id, "assets.host").await;
        if !plan_grants_access && !role_grants_access {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "asset_hosting_disabled",
                "the tenant's plan does not enable asset hosting and no bound role grants \
                 the assets.host permission",
                &ctx.request_id,
            )
            .await;
        }

        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let inline_limit = inline_push_byte_limit(auth.effective_quota.asset_storage_quota_bytes);
        let content = match read_request_body(session, inline_limit).await? {
            Ok(body) => body,
            Err(limit) => {
                write_json_error_and_close(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "asset content exceeds the maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        // Supply-chain hardening (issue #179): content-type allowlist,
        // malware-signature scan, and mcp_manifest stdio-transport block --
        // FerroGate is the origin server vouching for this content once
        // stored, not just proxying it, so this runs before anything is
        // durably written.
        if let Err(message) =
            super::asset_security::validate_asset_content(asset_type, &content_type, &content)
        {
            return write_json_error(
                session,
                StatusCode::UNPROCESSABLE_ENTITY,
                "asset_rejected",
                message,
                &ctx.request_id,
            )
            .await;
        }

        // Site bundles (issue #258): a `static_site` pushed as a zip archive is
        // unpacked into per-file objects and a site manifest, published under
        // the `/sites/{tenant}/{name}` serve surface, rather than stored as a
        // single opaque blob.
        if asset_type == "static_site" && is_zip_archive(&content) {
            return self
                .publish_site_bundle(
                    session, ctx, &auth, headers, &tenant_id, name, version, &content,
                )
                .await;
        }

        // Authentication already resolved the complete tenant -> project ->
        // workspace -> key quota chain and failed closed on repository errors.
        // Reading that same value here is the write-path == runtime-read-path
        // contract. Asset quotas are tenant-only because asset ownership and
        // usage are tenant-owned; narrower-scope writes fail at the API/DB
        // boundary instead of becoming ignored runtime configuration.
        let effective_quota = auth.effective_quota.asset_storage_quota_bytes;

        if let Some(default_quota) = effective_quota {
            let existing = match state
                .get_asset(&stored_asset_id(&tenant_id, asset_type, name, version))
                .await
            {
                Ok(existing) => existing,
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "storage_unavailable",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            };
            let used_by_others = match state.tenant_asset_storage_bytes_used(&tenant_id).await {
                Ok(used) => {
                    used.saturating_sub(existing.map(|asset| asset.size_bytes).unwrap_or(0))
                }
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "storage_unavailable",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            };
            if used_by_others.saturating_add(content.len() as u64) > default_quota {
                return write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "asset_storage_quota_exceeded",
                    format!(
                        "pushing this asset would exceed the tenant's {default_quota}-byte asset storage quota"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        }

        let now = now_unix_seconds();
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        let created_at_unix = state
            .get_asset(&id)
            .await
            .ok()
            .flatten()
            .map_or(now, |existing| existing.created_at_unix);

        // Bucket-backed storage (issue #176): when configured, the real
        // bytes go to the bucket and only a reference (`storage_uri`) is
        // persisted in Postgres, instead of duplicating them inline. A
        // bucket PUT failure fails the whole push (not a silent fallback
        // to inline storage) -- an operator who configured a bucket
        // expects assets to actually land there.
        let (stored_content, storage_uri) =
            match self.store_asset_bytes(&id, &content, &content_type).await {
                Ok(pair) => pair,
                Err(error) => return error.write(session, &ctx.request_id).await,
            };

        let asset = StoredAsset {
            id: id.clone(),
            tenant_id: tenant_id.clone(),
            project_id: auth.project_id.clone(),
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            content_type,
            content_hash: sha256_hex(&content),
            size_bytes: content.len() as u64,
            content: stored_content,
            storage_uri,
            created_at_unix,
            updated_at_unix: now,
        };
        match state.upsert_asset(asset.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "committed",
                    format!("asset {id} pushed ({} bytes)", asset.size_bytes),
                ));
                let body = AssetMutationResponse {
                    object: "asset",
                    asset: asset_summary(&asset),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_asset_pull(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(tenant_id) = auth.organization_id.clone() else {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "tenant_required",
                "assets require a tenant-attributed API key",
                &ctx.request_id,
            )
            .await;
        };
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        // Bucket resolution and per-read sha256 re-verification (#176/#179) live
        // in `AppState::read_asset_content` (#257), shared with the MCP
        // `resources/read` ingress and the `fetch_asset` built-in tool so every
        // asset-read surface fails closed identically.
        match state.read_asset_content(&id).await {
            Ok((asset, content)) => {
                // HTTP caching semantics (issue #258): strong ETag from the
                // stored sha256, Last-Modified, Cache-Control, and Range/304/206
                // handling shared with the static-site serve mode.
                let cache = AssetCacheHeaders {
                    content_type: &asset.content_type,
                    etag: format!("\"{}\"", asset.content_hash),
                    last_modified_unix: asset.updated_at_unix,
                    cache_control: DEFAULT_ASSET_CACHE_CONTROL,
                };
                write_cacheable_response(
                    session,
                    headers,
                    &Method::GET,
                    Bytes::from(content),
                    &cache,
                    &ctx.request_id,
                )
                .await?;
                Ok(())
            }
            Err(AssetReadError::NotFound) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_not_found",
                    format!("no asset at {asset_type}/{name}/{version}"),
                    &ctx.request_id,
                )
                .await
            }
            Err(AssetReadError::Integrity) => {
                write_json_error(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "asset_integrity_check_failed",
                    "stored asset content hash does not match recorded hash",
                    &ctx.request_id,
                )
                .await
            }
            Err(AssetReadError::BucketUnavailable(message)) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "asset_bucket_unavailable",
                    message,
                    &ctx.request_id,
                )
                .await
            }
            Err(AssetReadError::Storage(message)) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_asset_delete(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(tenant_id) = auth.organization_id.clone() else {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "tenant_required",
                "assets require a tenant-attributed API key",
                &ctx.request_id,
            )
            .await;
        };
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        // Bucket-backed storage (issue #176): best-effort delete the
        // bucket object before the DB row -- a failure here is logged but
        // doesn't block the delete, since an orphaned bucket object is a
        // lesser problem than a `stored_assets` row the operator can never
        // remove because the bucket happens to be unreachable.
        if let Ok(Some(existing)) = state.get_asset(&id).await {
            if let Some(storage_uri) = existing.storage_uri.as_deref() {
                if let Some(bucket) = state.asset_bucket_client() {
                    if let Err(error) = bucket.delete_object(storage_uri).await {
                        tracing::warn!(
                            asset_id = %id,
                            error = %error,
                            "failed to delete bucket object for asset; deleting the stored_assets row anyway"
                        );
                    }
                }
            }
        }
        match state.delete_asset(&id).await {
            Ok(true) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.delete",
                    &id,
                    "committed",
                    format!("asset {id} deleted"),
                ));
                let body = AdminDeleteResponse {
                    object: "asset",
                    id,
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(false) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_not_found",
                    format!("no asset at {asset_type}/{name}/{version}"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

impl FerroGateway {
    /// Reads an asset's real bytes, fetching from the object-storage bucket
    /// when the row is bucket-backed (`storage_uri`) and returning the inline
    /// `content` otherwise. Shared by the pull path and the static-site serve
    /// mode (issue #258); integrity re-verification stays with the caller.
    pub(super) async fn load_asset_content(
        &self,
        asset: &StoredAsset,
    ) -> Result<Vec<u8>, AssetError> {
        let Some(storage_uri) = asset.storage_uri.as_deref() else {
            return Ok(asset.content.clone());
        };
        let Some(bucket) = self.state.current().asset_bucket_client() else {
            return Err(AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "asset_bucket_unavailable",
                message: "this asset is bucket-backed but no asset_bucket is configured"
                    .to_string(),
            });
        };
        bucket
            .get_object(storage_uri)
            .await
            .map_err(|error| AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "asset_bucket_unavailable",
                message: error.to_string(),
            })
    }

    /// Persists asset bytes to the configured object-storage bucket, returning
    /// the `(inline_content, storage_uri)` pair to store on the row: empty
    /// inline content plus the bucket key when bucket-backed, or the inline
    /// bytes with no `storage_uri` otherwise. Shared by the push path and the
    /// static-site publish path (issue #258).
    pub(super) async fn store_asset_bytes(
        &self,
        id: &str,
        content: &[u8],
        content_type: &str,
    ) -> Result<(Vec<u8>, Option<String>), AssetError> {
        let Some(bucket) = self.state.current().asset_bucket_client() else {
            return Ok((content.to_vec(), None));
        };
        bucket
            .put_object(id, content, content_type)
            .await
            .map_err(|error| AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "asset_bucket_unavailable",
                message: error.to_string(),
            })?;
        Ok((Vec::new(), Some(id.to_string())))
    }
}

fn asset_summary(asset: &StoredAsset) -> AssetSummary {
    AssetSummary {
        id: asset.id.clone(),
        asset_type: asset.asset_type.clone(),
        name: asset.name.clone(),
        version: asset.version.clone(),
        content_type: asset.content_type.clone(),
        content_hash: asset.content_hash.clone(),
        size_bytes: asset.size_bytes,
        storage_backed: asset.storage_uri.is_some(),
        created_at_unix: asset.created_at_unix,
        updated_at_unix: asset.updated_at_unix,
    }
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{inline_push_byte_limit, INLINE_ASSET_MAX_BYTES};

    #[test]
    fn inline_push_byte_limit_is_the_buffering_cap_when_quota_is_unset_or_larger() {
        // No quota configured: the inline path buffers up to its own cap.
        assert_eq!(
            inline_push_byte_limit(None),
            INLINE_ASSET_MAX_BYTES as usize
        );
        // A quota larger than the inline cap can't loosen the inline cap.
        assert_eq!(
            inline_push_byte_limit(Some(INLINE_ASSET_MAX_BYTES * 100)),
            INLINE_ASSET_MAX_BYTES as usize
        );
    }

    #[test]
    fn inline_push_byte_limit_tightens_to_a_smaller_plan_quota() {
        // A per-plan quota smaller than the inline cap drives the limit --
        // this is the plan/quota-driven replacement for the old hard
        // MAX_ASSET_BYTES constant (issue #259).
        assert_eq!(inline_push_byte_limit(Some(4_096)), 4_096);
        assert_eq!(inline_push_byte_limit(Some(0)), 0);
    }
}
