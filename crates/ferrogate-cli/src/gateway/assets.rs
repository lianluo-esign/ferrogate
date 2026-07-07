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
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_error_and_close, write_raw_response, write_json_response,
        AdminDeleteResponse, AdminList, AssetMutationResponse, AssetSummary,
    },
};

/// Hard per-request body ceiling, matching the `stored_assets.size_bytes`
/// CHECK constraint (`sql/001_init_postgres.sql`) -- a tenant's
/// `default_asset_storage_quota_bytes` is enforced separately, on top of
/// this, as the cumulative-across-all-assets cap.
const MAX_ASSET_BYTES: usize = 10 * 1024 * 1024;

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
        match state.list_assets(&tenant_id, asset_type) {
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

        let plan = state.resolve_tenant_plan(&tenant_id).ok().flatten();
        if !plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled) {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "asset_hosting_disabled",
                "the tenant's plan does not enable asset hosting",
                &ctx.request_id,
            )
            .await;
        }

        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let content = match read_request_body(session, MAX_ASSET_BYTES).await? {
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

        if let Some(default_quota) = plan.as_ref().and_then(|plan| plan.default_asset_storage_quota_bytes) {
            let existing = match state.get_asset(&stored_asset_id(&tenant_id, asset_type, name, version)) {
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
            let used_by_others = match state.tenant_asset_storage_bytes_used(&tenant_id) {
                Ok(used) => used.saturating_sub(existing.map(|asset| asset.size_bytes).unwrap_or(0)),
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
            .ok()
            .flatten()
            .map_or(now, |existing| existing.created_at_unix);
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
            content: content.to_vec(),
            created_at_unix,
            updated_at_unix: now,
        };
        match state.upsert_asset(asset.clone()) {
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
        match state.get_asset(&id) {
            Ok(Some(asset)) => {
                // Re-verify content integrity on every read (#176/#179):
                // a mismatch means storage-layer corruption or tampering,
                // not a client error, so fail closed rather than serve it.
                if sha256_hex(&asset.content) != asset.content_hash {
                    return write_json_error(
                        session,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "asset_integrity_check_failed",
                        "stored asset content hash does not match recorded hash",
                        &ctx.request_id,
                    )
                    .await;
                }
                write_raw_response(
                    session,
                    StatusCode::OK,
                    &asset.content_type,
                    Bytes::from(asset.content),
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
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
        match state.delete_asset(&id) {
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

fn asset_summary(asset: &StoredAsset) -> AssetSummary {
    AssetSummary {
        id: asset.id.clone(),
        asset_type: asset.asset_type.clone(),
        name: asset.name.clone(),
        version: asset.version.clone(),
        content_type: asset.content_type.clone(),
        content_hash: asset.content_hash.clone(),
        size_bytes: asset.size_bytes,
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
