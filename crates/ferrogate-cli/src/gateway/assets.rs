// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Unified static-asset hosting surface (issue #176/#177):
// /v1/assets/* -- push/pull/list CLI tool packages, MCP connection
// manifests, Skill bundles, static sites, and config files through the
// same virtual-key auth and StoredPlan entitlement gating as inference
// traffic. Part of the agent-asset hosting epic (#175). Issue #260 layered
// artifact-registry semantics on top: channels (latest/stable/canary + tags),
// semver-range resolution, platform/arch variants, immutability + yank, and a
// self-serve manifest -- resolution rules live in `asset_registry.rs`.

use bytes::Bytes;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use ferrogate_storage::{
    asset_channel_id, sha256_hex, stored_asset_id, stored_asset_variant_id, ChannelMoveOutcome,
    StoredAsset, StoredAssetChannel, VariantDeleteOutcome, VersionYankOutcome,
};

use super::asset_registry::{resolve_version, select_variant, VariantChoice};
use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::sites::is_zip_archive;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_cacheable_response, write_json_error, write_json_error_and_close,
        write_json_response, AdminDeleteResponse, AdminList, AssetCacheHeaders,
        AssetChannelMutationResponse, AssetChannelSummary, AssetManifest, AssetManifestVariant,
        AssetManifestVersion, AssetMutationResponse, AssetPresignedUploadConstraints,
        AssetStorageSummary, AssetSummary,
    },
};

/// A storage-layer failure while reading or writing asset bytes, carrying the
/// HTTP error the gateway should return. Lets the bucket-fetch/bucket-put
/// helpers be shared between the pull path and the static-site serve/publish
/// paths (issue #258) without each call site re-deriving the error response.
pub(super) struct AssetError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
}

enum ChannelMoveError {
    TargetNotFound,
    Storage(String),
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
pub(crate) const INLINE_ASSET_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Default `Cache-Control` for a pulled asset (issues #258/#301): assets are
/// tenant-private and content-addressed, so clients must revalidate against the
/// strong `ETag` rather than serve a stale cached copy. Re-added on the
/// registry pull path so a conditional re-pull can short-circuit to `304`.
const DEFAULT_ASSET_CACHE_CONTROL: &str = "private, max-age=0, must-revalidate";

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
        query: Option<&str>,
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
                _ => method_not_allowed(session, ctx, "/v1/assets supports GET").await,
            },
            // This literal operator view must be matched before the generic
            // asset path segments so `storage/summary` can never be treated as
            // an asset identity.
            ["storage", "summary"] => match *method {
                Method::GET => {
                    self.handle_asset_storage_summary(session, ctx, headers)
                        .await
                }
                _ => {
                    method_not_allowed(session, ctx, "/v1/assets/storage/summary supports GET")
                        .await
                }
            },
            [asset_type] => match *method {
                Method::GET => {
                    self.handle_asset_list(session, ctx, headers, Some(asset_type))
                        .await
                }
                _ => method_not_allowed(session, ctx, "/v1/assets/{asset_type} supports GET").await,
            },
            // Manifest: the single self-serve document for one asset (#260).
            [asset_type, name, "manifest"] => match *method {
                Method::GET => {
                    self.handle_asset_manifest(session, ctx, headers, asset_type, name)
                        .await
                }
                _ => {
                    method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/manifest supports GET",
                    )
                    .await
                }
            },
            // Channel listing (#260).
            [asset_type, name, "channels"] => match *method {
                Method::GET => {
                    self.handle_channel_list(session, ctx, headers, asset_type, name)
                        .await
                }
                _ => {
                    method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/channels supports GET",
                    )
                    .await
                }
            },
            // Channel move / delete (#260).
            [asset_type, name, "channels", channel] => {
                match *method {
                    Method::PUT => {
                        self.handle_channel_move(
                            session, ctx, headers, asset_type, name, channel, query,
                        )
                        .await
                    }
                    Method::DELETE => {
                        self.handle_channel_delete(session, ctx, headers, asset_type, name, channel)
                            .await
                    }
                    _ => method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/channels/{channel} supports PUT, DELETE",
                    )
                    .await,
                }
            }
            // Yank / unyank a concrete version (#260).
            [asset_type, name, version, "yank"] => match *method {
                Method::POST => {
                    self.handle_asset_yank(session, ctx, headers, asset_type, name, version, true)
                        .await
                }
                Method::DELETE => {
                    self.handle_asset_yank(session, ctx, headers, asset_type, name, version, false)
                        .await
                }
                _ => {
                    method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/{version}/yank supports POST, DELETE",
                    )
                    .await
                }
            },
            [asset_type, name, reference] => match *method {
                Method::PUT => {
                    self.handle_asset_push(
                        session, ctx, headers, asset_type, name, reference, query,
                    )
                    .await
                }
                Method::GET => {
                    self.handle_asset_pull(
                        session, ctx, headers, asset_type, name, reference, query,
                    )
                    .await
                }
                Method::DELETE => {
                    self.handle_asset_delete(
                        session, ctx, headers, asset_type, name, reference, query,
                    )
                    .await
                }
                _ => {
                    method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/{version} supports GET, PUT, DELETE",
                    )
                    .await
                }
            },
            _ => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "expected /v1/assets, /v1/assets/{asset_type}, \
                     /v1/assets/{asset_type}/{name}/{version}, \
                     /v1/assets/{asset_type}/{name}/manifest, or \
                     /v1/assets/{asset_type}/{name}/channels/{channel}",
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
            return tenant_required(session, ctx).await;
        };
        match state.list_assets(&tenant_id, asset_type).await {
            Ok(assets) => {
                let body = AdminList::new(assets.iter().map(asset_summary).collect());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_asset_storage_summary(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
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
        let Some(tenant_id) = auth.organization_id.as_deref() else {
            return tenant_required(session, ctx).await;
        };
        let used_bytes = match state.tenant_asset_storage_bytes_used(tenant_id).await {
            Ok(used_bytes) => used_bytes,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        let presigned_limits = state.asset_bucket_client().map(|_| {
            (
                state.asset_presign_max_object_bytes(),
                state.asset_presign_ttl_secs(),
            )
        });
        let body = build_asset_storage_summary(
            used_bytes,
            auth.effective_quota.asset_storage_quota_bytes,
            presigned_limits,
        );
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_asset_push(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
        query: Option<&str>,
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
            return tenant_required(session, ctx).await;
        };
        if !self.tenant_can_host(&state, &tenant_id).await {
            return asset_hosting_disabled(session, ctx).await;
        }

        // Platform/arch variant (#260): one logical version can carry several
        // per-target-triple artifacts, each its own immutable row.
        let variant = query_param(query, "platform").unwrap_or_default();

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

        // Supply-chain trust (issues #179 + #261): the synchronous content
        // gates, a pluggable malware scan (default offline EICAR; opt-in
        // ClamAV/hosted-HTTP), detached publisher-signature verification, and
        // a cross-tenant publish approval gate all run here, before anything
        // is durably written -- FerroGate vouches for this content once stored,
        // not just proxying it.
        let security = super::asset_security::AssetSecurityContext::from_env();
        let signature_input = headers
            .get("x-asset-signature")
            .and_then(|value| value.to_str().ok())
            .map(|material| super::asset_signature::AssetSignatureInput {
                format: headers
                    .get("x-asset-signature-format")
                    .and_then(|value| value.to_str().ok())
                    .and_then(super::asset_signature::SignatureFormat::parse)
                    .unwrap_or(super::asset_signature::SignatureFormat::Minisign),
                material: material.to_string(),
                key_id: headers
                    .get("x-asset-signature-key-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            });
        let visibility = headers
            .get("x-asset-visibility")
            .and_then(|value| value.to_str().ok())
            .and_then(super::asset_publish_gate::PublishVisibility::parse)
            .unwrap_or(super::asset_publish_gate::PublishVisibility::TenantPrivate);
        // Reuse the existing tool_approvals machinery: the approval id names a
        // durable approval record whose status the gate reads (never a
        // client-asserted status).
        let approval = headers
            .get("x-asset-approval-id")
            .and_then(|value| value.to_str().ok())
            .and_then(|id| {
                state
                    .tool_approval(id)
                    .map(|record| (id.to_string(), record.status))
            });
        let screen_id = stored_asset_id(&tenant_id, asset_type, name, version);
        let screen_hash = sha256_hex(&content);
        let screening = match super::asset_security::screen_asset_push(
            &security,
            super::asset_security::AssetPushScreeningRequest {
                asset_id: &screen_id,
                tenant_id: &tenant_id,
                asset_type,
                content_type: &content_type,
                content: &content,
                content_sha256: &screen_hash,
                signature: signature_input,
                visibility,
                approval,
                now_unix: now_unix_seconds(),
            },
        )
        .await
        {
            Ok(screening) => screening,
            Err(rejection) => {
                return write_json_error(
                    session,
                    rejection.status(),
                    rejection.code,
                    rejection.message,
                    &ctx.request_id,
                )
                .await;
            }
        };

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

        let id = stored_asset_variant_id(&tenant_id, asset_type, name, version, &variant);

        // Immutability (#260): a published `{name}/{version}` (per variant) is
        // frozen. Overwriting it silently would break every agent that pinned
        // the old hash, so a re-PUT is rejected -- the operator must DELETE the
        // version first to republish.
        match state.get_asset(&id).await {
            Ok(Some(_)) => {
                return write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "asset_version_immutable",
                    format!(
                        "{asset_type}/{name}/{version}{} already exists and is immutable; \
                         delete it before republishing",
                        variant_suffix(&variant)
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        }

        // Authentication already resolved the complete tenant -> project ->
        // workspace -> key quota chain and failed closed on repository errors.
        // Asset quotas are tenant-only because asset ownership and usage are
        // tenant-owned.
        let effective_quota = auth.effective_quota.asset_storage_quota_bytes;
        if let Some(default_quota) = effective_quota {
            let used = match state.tenant_asset_storage_bytes_used(&tenant_id).await {
                Ok(used) => used,
                Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
            };
            if used.saturating_add(content.len() as u64) > default_quota {
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
            variant: variant.clone(),
            yanked: false,
            created_at_unix: now,
            updated_at_unix: now,
        };
        if let Err(error) = state.upsert_asset(asset.clone()).await {
            return storage_unavailable(session, ctx, error.to_string()).await;
        }
        // Immutable trust evidence (#261): the scan/signature/approval outcome
        // and the verification manifest are recorded on the push audit event,
        // retrievable via the Admin audit API.
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "asset.push",
            &id,
            "committed",
            format!(
                "asset {id} pushed ({} bytes); {}; manifest={}",
                asset.size_bytes,
                screening.audit_detail(),
                screening.manifest_json(),
            ),
        ));

        // Optional channel move in the same request (#260): `?channel=stable`
        // points that channel at the just-pushed version.
        if let Some(channel) = query_param(query, "channel") {
            if let Err(error) = self
                .move_channel(&state, ctx, &auth, asset_type, name, &channel, version)
                .await
            {
                return write_channel_move_error(session, ctx, error, asset_type, name, version)
                    .await;
            }
        }

        let body = AssetMutationResponse {
            object: "asset",
            asset: asset_summary(&asset),
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_asset_pull(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        reference: &str,
        query: Option<&str>,
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
            return tenant_required(session, ctx).await;
        };

        let assets = match self
            .asset_versions(&state, &tenant_id, asset_type, name)
            .await
        {
            Ok(assets) => assets,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        let channels = match state
            .list_asset_channels(&tenant_id, asset_type, name)
            .await
        {
            Ok(channels) => channels,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };

        // Resolve the reference (exact / channel / semver range) to a concrete
        // version (#260).
        let Some(resolved) = resolve_version(&assets, &channels, reference) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "asset_not_found",
                format!("no asset resolves for {asset_type}/{name}/{reference}"),
                &ctx.request_id,
            )
            .await;
        };

        // Platform/arch variant selection (#260): explicit `?platform=` query
        // param, or the `x-ferrogate-platform` hint header.
        let requested_platform = query_param(query, "platform").or_else(|| {
            headers
                .get("x-ferrogate-platform")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });
        let version_rows: Vec<&StoredAsset> = assets
            .iter()
            .filter(|asset| asset.version == resolved.version)
            .collect();
        let selected = match select_variant(&version_rows, requested_platform.as_deref()) {
            VariantChoice::Selected(asset) => asset,
            VariantChoice::NotFound => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_variant_not_found",
                    format!(
                        "{asset_type}/{name}/{} has no{} variant",
                        resolved.version,
                        requested_platform
                            .as_deref()
                            .map(|platform| format!(" {platform}"))
                            .unwrap_or_default()
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            VariantChoice::Ambiguous => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "asset_variant_required",
                    format!(
                        "{asset_type}/{name}/{} carries multiple platform variants; \
                         specify one with ?platform=",
                        resolved.version
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        };

        // Resolution metadata + yank deprecation headers (#260).
        let mut extra_headers: Vec<(&'static str, String)> = vec![
            (
                "x-ferrogate-asset-resolved",
                resolved.how.header_value(&resolved.version),
            ),
            ("x-ferrogate-asset-version", resolved.version.clone()),
        ];
        if !selected.variant.is_empty() {
            extra_headers.push(("x-ferrogate-asset-variant", selected.variant.clone()));
        }
        if resolved.yanked {
            extra_headers.push((
                "warning",
                format!(
                    "299 ferrogate \"asset {asset_type}/{name}/{} is yanked\"",
                    resolved.version
                ),
            ));
            extra_headers.push(("x-ferrogate-asset-yanked", "true".to_string()));
        }

        // #262 egress quota: fail-closed deny gate (monthly egress byte budget +
        // download RPM) before serving, using the resolved object size.
        if let Some((code, message)) =
            super::asset_egress::asset_egress_quota_denial(&state, &auth, selected.size_bytes)
        {
            return write_json_error(
                session,
                StatusCode::TOO_MANY_REQUESTS,
                code,
                message,
                &ctx.request_id,
            )
            .await;
        }
        // #262 egress metering: meter the download bytes through the existing
        // billing outbox + wallet-debit path and emit the pull audit event.
        super::asset_egress::record_asset_egress(
            &state,
            ctx,
            &auth,
            asset_type,
            name,
            &resolved.version,
            selected.size_bytes,
        )
        .await;

        self.write_asset_body(session, ctx, headers, selected.clone(), &extra_headers)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_asset_delete(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
        query: Option<&str>,
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
            return tenant_required(session, ctx).await;
        };
        let variant = query_param(query, "platform").unwrap_or_default();
        let id = stored_asset_variant_id(&tenant_id, asset_type, name, version, &variant);
        // Delete one variant row atomically (issue #367): reject a delete that
        // would remove the last resolvable variant of a version a channel still
        // references, so a live channel can never be stranded on an absent
        // version. Multi-variant versions and unreferenced versions delete freely.
        // The DB row is deleted FIRST; the bucket object is reaped only after a
        // committed row delete, so a rejected delete never orphans the bucket
        // object away from a still-live row.
        let existing_storage_uri = match state.get_asset(&id).await {
            Ok(existing) => existing.and_then(|asset| asset.storage_uri),
            Err(_) => None,
        };
        match state
            .delete_asset_variant_if_unreferenced(&id, &tenant_id, asset_type, name, version)
            .await
        {
            Ok(VariantDeleteOutcome::Deleted) => {
                // Best-effort reap of the bucket object now that the row is gone
                // (issue #176): an orphaned bucket object is a lesser problem than
                // a stored_assets row that outlives its bytes, and the #263 GC
                // sweeper reclaims any object left behind by a failure here.
                if let Some(storage_uri) = existing_storage_uri.as_deref() {
                    if let Some(bucket) = state.asset_bucket_client() {
                        if let Err(error) = bucket.delete_object(storage_uri).await {
                            tracing::warn!(
                                asset_id = %id,
                                error = %error,
                                "deleted stored_assets row but failed to delete its bucket object; GC will reclaim it"
                            );
                        }
                    }
                }
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
            Ok(VariantDeleteOutcome::NotFound) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_not_found",
                    format!(
                        "no asset at {asset_type}/{name}/{version}{}",
                        variant_suffix(&variant)
                    ),
                    &ctx.request_id,
                )
                .await
            }
            Ok(VariantDeleteOutcome::BlockedByChannel) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.delete",
                    &id,
                    "rejected",
                    format!(
                        "asset {id} delete rejected: last resolvable variant of a \
                         channel-referenced version"
                    ),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "asset_version_referenced",
                    format!(
                        "{asset_type}/{name}/{version} is the last resolvable variant of a \
                         channel-referenced version; move or delete the channel first"
                    ),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_asset_yank(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
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
            return tenant_required(session, ctx).await;
        };
        if !self.tenant_can_host(&state, &tenant_id).await {
            return asset_hosting_disabled(session, ctx).await;
        }

        // Yank/unyank the whole logical version atomically (issue #367). A yank
        // is rejected while a channel still references the version, so the
        // lifecycle invariant (no channel points at a yanked version) holds as
        // one step instead of a read-then-write race with a concurrent move.
        let now = now_unix_seconds();
        let action = if yanked { "asset.yank" } else { "asset.unyank" };
        let target = format!("{tenant_id}:{asset_type}:{name}:{version}");
        match state
            .set_asset_version_yank(&tenant_id, asset_type, name, version, yanked, now)
            .await
        {
            Ok(VersionYankOutcome::Applied { .. }) => {}
            Ok(VersionYankOutcome::NotFound) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_not_found",
                    format!("no asset at {asset_type}/{name}/{version}"),
                    &ctx.request_id,
                )
                .await;
            }
            Ok(VersionYankOutcome::ReferencedByChannel) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    action,
                    target,
                    "rejected",
                    format!(
                        "asset {asset_type}/{name}/{version} yank rejected: still referenced \
                         by a channel; move the channel off this version first"
                    ),
                ));
                return write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "asset_version_referenced",
                    format!(
                        "{asset_type}/{name}/{version} is still referenced by a channel; \
                         move the channel off this version before yanking"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        }
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            action,
            target,
            "committed",
            format!(
                "asset {asset_type}/{name}/{version} {}",
                if yanked { "yanked" } else { "unyanked" }
            ),
        ));
        // Re-read the version's rows for the response body only (not to prove the
        // mutation, which already committed durably above).
        let summary: Vec<AssetSummary> = match self
            .asset_versions(&state, &tenant_id, asset_type, name)
            .await
        {
            Ok(assets) => assets
                .into_iter()
                .filter(|asset| asset.version == version)
                .map(|asset| asset_summary(&asset))
                .collect(),
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        write_json_response(
            session,
            StatusCode::OK,
            &AdminList::new(summary),
            &ctx.request_id,
        )
        .await
    }

    async fn handle_channel_list(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
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
            return tenant_required(session, ctx).await;
        };
        match state
            .list_asset_channels(&tenant_id, asset_type, name)
            .await
        {
            Ok(channels) => {
                let body = AdminList::new(channels.iter().map(channel_summary).collect());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_channel_move(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        channel: &str,
        query: Option<&str>,
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
            return tenant_required(session, ctx).await;
        };
        if !self.tenant_can_host(&state, &tenant_id).await {
            return asset_hosting_disabled(session, ctx).await;
        }
        let Some(version) = query_param(query, "version") else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "channel_target_required",
                "a channel move requires ?version={version}",
                &ctx.request_id,
            )
            .await;
        };
        let record = match self
            .move_channel(&state, ctx, &auth, asset_type, name, channel, &version)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return write_channel_move_error(session, ctx, error, asset_type, name, &version)
                    .await;
            }
        };
        let body = AssetChannelMutationResponse {
            object: "asset_channel",
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            channel: channel_summary(&record),
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    async fn handle_channel_delete(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        channel: &str,
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
            return tenant_required(session, ctx).await;
        };
        if !self.tenant_can_host(&state, &tenant_id).await {
            return asset_hosting_disabled(session, ctx).await;
        }
        let id = asset_channel_id(&tenant_id, asset_type, name, channel);
        match state.delete_asset_channel(&id).await {
            Ok(true) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.channel.delete",
                    &id,
                    "committed",
                    format!("asset channel {asset_type}/{name}/{channel} deleted"),
                ));
                let body = AdminDeleteResponse {
                    object: "asset_channel",
                    id,
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(false) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "channel_not_found",
                    format!("no channel {asset_type}/{name}/{channel}"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_asset_manifest(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
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
            return tenant_required(session, ctx).await;
        };
        let assets = match self
            .asset_versions(&state, &tenant_id, asset_type, name)
            .await
        {
            Ok(assets) => assets,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        if assets.is_empty() {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "asset_not_found",
                format!("no asset {asset_type}/{name}"),
                &ctx.request_id,
            )
            .await;
        }
        let channels = match state
            .list_asset_channels(&tenant_id, asset_type, name)
            .await
        {
            Ok(channels) => channels,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        let manifest = build_manifest(asset_type, name, &assets, &channels);
        write_json_response(session, StatusCode::OK, &manifest, &ctx.request_id).await
    }

    // --- shared helpers ---

    /// Whether the tenant may host assets: either its StoredPlan enables asset
    /// hosting (#176/#177) or a bound role grants the `assets.host` permission
    /// (#182). Either is sufficient.
    async fn tenant_can_host(&self, state: &crate::state::AppState, tenant_id: &str) -> bool {
        let plan = state.resolve_tenant_plan(tenant_id).await.ok().flatten();
        let plan_grants = plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled);
        let role_grants = state.tenant_has_permission(tenant_id, "assets.host").await;
        plan_grants || role_grants
    }

    /// All variant rows across every version of one `{asset_type}/{name}`.
    async fn asset_versions(
        &self,
        state: &crate::state::AppState,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> anyhow::Result<Vec<StoredAsset>> {
        let assets = state.list_assets(tenant_id, Some(asset_type)).await?;
        Ok(assets
            .into_iter()
            .filter(|asset| asset.name == name)
            .collect())
    }

    /// Atomically move a channel pointer, succeeding only when the target
    /// version is durably resolvable under one serialization point (issue #367,
    /// replacing the former read-then-upsert pair whose gap let a concurrent
    /// yank/delete strand the channel). Audit evidence records the prior target,
    /// the requested target, and the outcome for both commit and rejection.
    #[allow(clippy::too_many_arguments)]
    async fn move_channel(
        &self,
        state: &crate::state::AppState,
        ctx: &super::ProxyContext,
        auth: &crate::auth::AuthContext,
        asset_type: &str,
        name: &str,
        channel: &str,
        version: &str,
    ) -> Result<StoredAssetChannel, ChannelMoveError> {
        let tenant_id = auth_tenant(auth);
        let channel_id = asset_channel_id(&tenant_id, asset_type, name, channel);
        let record = StoredAssetChannel {
            id: channel_id.clone(),
            tenant_id,
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            channel: channel.to_string(),
            version: version.to_string(),
            updated_at_unix: now_unix_seconds(),
        };
        match state
            .move_asset_channel_if_resolvable(record.clone())
            .await
            .map_err(|error| ChannelMoveError::Storage(error.to_string()))?
        {
            ChannelMoveOutcome::Moved { prior_version } => {
                let prior = prior_version.as_deref().unwrap_or("none");
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    auth,
                    "asset.channel.move",
                    &channel_id,
                    "committed",
                    format!("channel {asset_type}/{name}/{channel} {prior} -> {version}"),
                ));
                Ok(record)
            }
            ChannelMoveOutcome::TargetNotResolvable => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    auth,
                    "asset.channel.move",
                    &channel_id,
                    "rejected",
                    format!(
                        "channel {asset_type}/{name}/{channel} -> {version} rejected: \
                         target version is absent or yanked"
                    ),
                ));
                Err(ChannelMoveError::TargetNotFound)
            }
        }
    }

    /// Fetch content (bucket or inline), re-verify its hash, and serve it with
    /// full HTTP caching (304/Range, issue #258) while carrying the caller's
    /// registry-resolution metadata + yank `warning` as extra response headers
    /// (issue #301). `req_headers` supplies the client's conditional/range
    /// headers.
    async fn write_asset_body(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        req_headers: &http::HeaderMap,
        asset: StoredAsset,
        extra_headers: &[(&'static str, String)],
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let content = if let Some(storage_uri) = asset.storage_uri.as_deref() {
            let Some(bucket) = state.asset_bucket_client() else {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "asset_bucket_unavailable",
                    "this asset is bucket-backed but no asset_bucket is configured",
                    &ctx.request_id,
                )
                .await;
            };
            match bucket.get_object(storage_uri).await {
                Ok(content) => content,
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "asset_bucket_unavailable",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            }
        } else {
            asset.content
        };
        // Re-verify content integrity on every read (#176/#179): a mismatch is
        // storage-layer corruption or tampering, not a client error.
        if sha256_hex(&content) != asset.content_hash {
            return write_json_error(
                session,
                StatusCode::INTERNAL_SERVER_ERROR,
                "asset_integrity_check_failed",
                "stored asset content hash does not match recorded hash",
                &ctx.request_id,
            )
            .await;
        }
        // HTTP caching semantics (issue #258): a strong ETag from the stored
        // sha256, Last-Modified, Cache-Control, and 304/206 handling shared with
        // the static-site serve mode -- restored on the registry pull path
        // (issue #301) while still carrying the #260 resolution/yank headers.
        let cache = AssetCacheHeaders {
            content_type: &asset.content_type,
            etag: format!("\"{}\"", asset.content_hash),
            last_modified_unix: asset.updated_at_unix,
            cache_control: DEFAULT_ASSET_CACHE_CONTROL,
        };
        write_cacheable_response(
            session,
            req_headers,
            &Method::GET,
            Bytes::from(content),
            &cache,
            &ctx.request_id,
            extra_headers,
        )
        .await?;
        Ok(())
    }
}

fn auth_tenant(auth: &crate::auth::AuthContext) -> String {
    auth.organization_id.clone().unwrap_or_default()
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

fn build_asset_storage_summary(
    used_bytes: u64,
    quota_bytes: Option<u64>,
    presigned_limits: Option<(u64, u64)>,
) -> AssetStorageSummary {
    let (enabled, max_object_bytes, url_ttl_seconds) = match presigned_limits {
        Some((max_object_bytes, url_ttl_seconds)) => {
            (true, Some(max_object_bytes), Some(url_ttl_seconds))
        }
        None => (false, None, None),
    };
    AssetStorageSummary {
        object: "asset_storage_summary",
        used_bytes,
        quota_bytes,
        remaining_bytes: quota_bytes.map(|quota| quota.saturating_sub(used_bytes)),
        inline_upload_max_bytes: inline_push_byte_limit(quota_bytes) as u64,
        presigned_upload: AssetPresignedUploadConstraints {
            enabled,
            max_object_bytes,
            url_ttl_seconds,
        },
    }
}

fn channel_summary(channel: &StoredAssetChannel) -> AssetChannelSummary {
    AssetChannelSummary {
        channel: channel.channel.clone(),
        version: channel.version.clone(),
        updated_at_unix: channel.updated_at_unix,
    }
}

/// The canonical channel-target resolvability predicate (issue #367): a version
/// is resolvable when it has at least one variant row and none of its variants
/// is yanked. The atomic move/yank/delete coordination in `ferrogate-storage`
/// enforces exactly this invariant under a serialization point; this pure
/// mirror is retained as the test oracle both backends must agree with.
#[cfg(test)]
fn channel_target_is_resolvable(assets: &[StoredAsset], version: &str) -> bool {
    let mut found = false;
    for asset in assets.iter().filter(|asset| asset.version == version) {
        found = true;
        // Resolution treats the whole logical version as yanked when any one
        // of its variants is yanked, so a channel must reject that state too.
        if asset.yanked {
            return false;
        }
    }
    found
}

/// Build the self-serve manifest: channels + every version with its variants
/// (each with hash/size), newest semver version first.
fn build_manifest(
    asset_type: &str,
    name: &str,
    assets: &[StoredAsset],
    channels: &[StoredAssetChannel],
) -> AssetManifest {
    let mut versions: Vec<AssetManifestVersion> = Vec::new();
    for asset in assets {
        let variant = AssetManifestVariant {
            variant: asset.variant.clone(),
            content_type: asset.content_type.clone(),
            content_hash: asset.content_hash.clone(),
            size_bytes: asset.size_bytes,
            storage_backed: asset.storage_uri.is_some(),
        };
        if let Some(entry) = versions
            .iter_mut()
            .find(|entry| entry.version == asset.version)
        {
            entry.yanked = entry.yanked || asset.yanked;
            entry.variants.push(variant);
        } else {
            versions.push(AssetManifestVersion {
                version: asset.version.clone(),
                yanked: asset.yanked,
                variants: vec![variant],
            });
        }
    }
    // Newest first: semver-parseable versions sort by semver desc; the rest
    // fall back to reverse-lexical, kept after the semver ones.
    versions.sort_by(|a, b| {
        match (
            semver::Version::parse(&a.version),
            semver::Version::parse(&b.version),
        ) {
            (Ok(a), Ok(b)) => b.cmp(&a),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => b.version.cmp(&a.version),
        }
    });
    for entry in &mut versions {
        entry.variants.sort_by(|a, b| a.variant.cmp(&b.variant));
    }
    let mut channels: Vec<AssetChannelSummary> = channels.iter().map(channel_summary).collect();
    channels.sort_by(|a, b| a.channel.cmp(&b.channel));
    AssetManifest {
        object: "asset_manifest",
        asset_type: asset_type.to_string(),
        name: name.to_string(),
        channels,
        versions,
    }
}

/// Minimal `key=value&...` query lookup. Values in this surface (platform
/// triples, channel names, versions) are URL-safe, so no percent-decoding is
/// needed.
fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn variant_suffix(variant: &str) -> String {
    if variant.is_empty() {
        String::new()
    } else {
        format!(" ({variant})")
    }
}

async fn method_not_allowed(
    session: &mut Session,
    ctx: &super::ProxyContext,
    message: &str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        message,
        &ctx.request_id,
    )
    .await
}

async fn tenant_required(session: &mut Session, ctx: &super::ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::FORBIDDEN,
        "tenant_required",
        "assets require a tenant-attributed API key",
        &ctx.request_id,
    )
    .await
}

async fn asset_hosting_disabled(
    session: &mut Session,
    ctx: &super::ProxyContext,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::FORBIDDEN,
        "asset_hosting_disabled",
        "the tenant's plan does not enable asset hosting and no bound role grants \
         the assets.host permission",
        &ctx.request_id,
    )
    .await
}

async fn storage_unavailable(
    session: &mut Session,
    ctx: &super::ProxyContext,
    message: String,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::SERVICE_UNAVAILABLE,
        "storage_unavailable",
        message,
        &ctx.request_id,
    )
    .await
}

async fn write_channel_move_error(
    session: &mut Session,
    ctx: &super::ProxyContext,
    error: ChannelMoveError,
    asset_type: &str,
    name: &str,
    version: &str,
) -> PingoraResult<()> {
    match error {
        ChannelMoveError::TargetNotFound => {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "channel_target_not_found",
                format!("no non-yanked asset at {asset_type}/{name}/{version}"),
                &ctx.request_id,
            )
            .await
        }
        ChannelMoveError::Storage(message) => storage_unavailable(session, ctx, message).await,
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

#[cfg(test)]
#[path = "assets_test.rs"]
mod assets_test;
