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
    asset_channel_id, sha256_hex, stored_asset_id, stored_asset_variant_id, AssetPromotionTarget,
    AssetVisibilityPromotionOutcome, ChannelMoveOutcome, StoredAsset, StoredAssetChannel,
    VariantDeleteOutcome, VersionYankOutcome,
};

use super::admin_list_query::{list_response, matches_search, query_value};
use super::asset_admission::{BufferedObject, ReadResidency};
use super::asset_bucket::{
    asset_too_large_for_buffering_message, gateway_buffer_budget_exhausted_message,
    read_object_bounded, BufferedReadRefusal, ASSET_TOO_LARGE_FOR_INLINE_PULL_CODE,
    BUCKET_READ_UNAVAILABLE_MESSAGE, GATEWAY_BUFFER_BUDGET_EXHAUSTED_CODE,
};
use super::asset_inline_publish;
use super::asset_registry::{resolve_version, select_variant, VariantChoice};
use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::sites::{is_zip_archive, SITE_ASSET_TYPE};
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_cacheable_response, write_json_error, write_json_error_and_close,
        write_json_response, AdminDeleteResponse, AdminList, AssetCacheHeaders,
        AssetChannelMutationResponse, AssetChannelSummary, AssetManifest, AssetManifestVariant,
        AssetManifestVersion, AssetMutationResponse, AssetPresignedUploadConstraints,
        AssetStorageSummary, AssetSummary, AssetVisibilityPromotionRequest,
        AssetVisibilityPromotionResponse, WithheldAssetSummary,
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
/// `gateway/asset_presign.rs`).
///
/// On that path the client's bytes travel **directly** between the client and
/// the bucket over presigned URLs, and never traverse the gateway. The
/// gateway's own commit-time leg -- it must read the staged object back to
/// verify its SHA-256 and screen it before publishing -- is bounded rather
/// than absent: objects above `[asset_bucket].max_gateway_buffer_bytes`
/// (default: this constant) are verified and copied to their final key in a
/// single streaming pass whose resident cost is one HTTP chunk, and objects at
/// or below it are buffered so the whole-file controls (detached-signature
/// verification, out-of-process malware scanning, `mcp_manifest` transport
/// parsing) still get their bytes.
///
/// What the memory bound covers, enumerated rather than asserted -- the first
/// two rounds of #259 each wrote a universal here that a read surface
/// contradicted, so this list is the claim:
///
/// - the presigned commit's verify-and-copy leg (streams, never buffers);
/// - `GET /v1/assets/{type}/{name}/{version}` (`write_asset_body`);
/// - the static-site serve (`serve_site_file`);
/// - the `fetch_asset` built-in tool and MCP `resources/read`
///   (`AppState::read_asset_content`).
///
/// The last three are bucket reads that buffer by nature -- they re-verify the
/// hash and answer conditional/Range requests -- so above the budget they
/// return a typed `413 asset_too_large_for_inline_pull` naming the presigned
/// download instead of materializing the object. They share ONE bound, in
/// `asset_bucket::read_object_bounded`, and the transport cannot be called
/// without one; a read surface added later inherits it rather than needing its
/// own copy.
///
/// Aggregate concurrency is covered too, since issue #529: every one of those
/// reads is charged what it will actually hold against
/// `[asset_bucket].max_total_gateway_buffer_bytes` -- its declared size for the
/// pull and the site serve, and ~3.7x that for the two surfaces that inline the
/// object into a JSON response and therefore hold three copies of it -- and
/// holds the charge until those bytes are dropped by the code that WRITES them.
/// Peak asset-read memory is that ceiling rather than this constant times an
/// unbounded in-flight count. Over-budget concurrency is shed with a typed
/// `503 gateway_buffer_budget_exhausted`.
///
/// The tenant's cumulative `asset_storage_quota_bytes` is enforced separately,
/// on top of this.
pub(crate) const INLINE_ASSET_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Default `Cache-Control` for a pulled asset (issues #258/#301): assets are
/// tenant-private and content-addressed, so clients must revalidate against the
/// strong `ETag` rather than serve a stale cached copy. Re-added on the
/// registry pull path so a conditional re-pull can short-circuit to `304`.
const DEFAULT_ASSET_CACHE_CONTROL: &str = "private, max-age=0, must-revalidate";

/// Per-request byte ceiling for an inline push: the inline buffering cap,
/// tightened to BOTH the tenant's dedicated per-object ceiling
/// (`asset_max_object_bytes`, #259) and its cumulative asset storage quota
/// whenever either is smaller (a single object can never exceed the whole
/// quota, and the dedicated per-object cap binds individual object size
/// independently). Keeps the inline path consistent with the presigned path's
/// `effective_max_object_bytes`. Replaces the former hard `MAX_ASSET_BYTES`
/// constant with a plan/quota-driven limit (issue #259). A `None` bound does
/// not tighten anything.
fn inline_push_byte_limit(
    per_object_ceiling: Option<u64>,
    asset_storage_quota_bytes: Option<u64>,
) -> usize {
    let limit = INLINE_ASSET_MAX_BYTES
        .min(per_object_ceiling.unwrap_or(u64::MAX))
        .min(asset_storage_quota_bytes.unwrap_or(u64::MAX));
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
            // Operator-only inverse listing (#379): the WITHHELD (pending_scan/
            // quarantined) assets the ordinary list/manifest/resolution paths
            // hide (#366). Matched as a reserved literal BEFORE the generic
            // `[asset_type]` arm so `withheld` can never be treated as an asset
            // family, mirroring how `storage/summary` is reserved above.
            ["withheld"] => match *method {
                Method::GET => {
                    self.handle_withheld_asset_list(session, ctx, headers, query)
                        .await
                }
                _ => method_not_allowed(session, ctx, "/v1/assets/withheld supports GET").await,
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
            // Out-of-band scan promotion (#378): flip a `pending_scan` version
            // to `visible`/`quarantined` after a completed async scan.
            [asset_type, name, version, "visibility"] => match *method {
                Method::POST => {
                    self.handle_asset_visibility_promotion(
                        session, ctx, headers, asset_type, name, version, query,
                    )
                    .await
                }
                _ => {
                    method_not_allowed(
                        session,
                        ctx,
                        "/v1/assets/{asset_type}/{name}/{version}/visibility supports POST",
                    )
                    .await
                }
            },
            [asset_type, name, reference] => {
                // #398: this `{version}` segment carries the per-file static-site
                // address, which encodes a (possibly deeply-nested) file path --
                // its slashes arrive as `%2F`. Decode the segment back to the
                // slashed object key the publish/unpack path stored so a nested
                // per-file download/unpublish resolves; URL-safe references
                // (semver, channels, the reserved `__site_*__` keys) contain no
                // `%` and pass through unchanged. Decoding here, AFTER the raw-`/`
                // split above, is why an encoded slash survives routing as one
                // segment instead of being mis-split.
                let reference = percent_decode_segment(reference);
                match *method {
                    Method::PUT => {
                        self.handle_asset_push(
                            session, ctx, headers, asset_type, name, &reference, query,
                        )
                        .await
                    }
                    Method::GET => {
                        self.handle_asset_pull(
                            session, ctx, headers, asset_type, name, &reference, query,
                        )
                        .await
                    }
                    Method::DELETE => {
                        self.handle_asset_delete(
                            session, ctx, headers, asset_type, name, &reference, query,
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
                }
            }
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
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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
                // #366: the ordinary tenant listing withholds pending/quarantined
                // rows; they are surfaced only through the dedicated screening
                // audit evidence, never as ordinary resolvable assets.
                let body = AdminList::new(
                    assets
                        .iter()
                        .filter(|asset| asset.is_downloadable())
                        .map(asset_summary)
                        .collect(),
                );
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
    }

    /// Operator-only inverse of [`Self::handle_asset_list`] (issue #379,
    /// follow-up to #366): list the WITHHELD (`pending_scan`/`quarantined`)
    /// assets that the ordinary list/manifest/resolution paths deliberately hide
    /// from consumers, each row carrying its durable `visibility` state and the
    /// screening evidence (scan/signature/approval + verification manifest)
    /// recorded on its push/commit audit event at #366 push time. Read-only --
    /// the promote/quarantine ACTION is the separate #378 endpoint. Tenant-scoped
    /// and paginated (search/offset/limit) via the shared admin-list helpers, and
    /// gated on the same `assets.read` scope as the other admin asset reads.
    async fn handle_withheld_asset_list(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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

        // Optional `?asset_type=` narrows the operator's view to one family; the
        // storage read filters to non-`visible` rows server-side either way.
        let asset_type_filter = query_value(query, "asset_type");
        let withheld = match state
            .list_withheld_assets(&tenant_id, asset_type_filter.as_deref())
            .await
        {
            Ok(withheld) => withheld,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };

        // Correlate each withheld row with the screening evidence recorded on its
        // push/commit audit event (#366): action `asset.push`, outcome
        // `committed`, target = asset id, same tenant. The audit `message` is the
        // durable scan/signature/approval verdict + verification manifest. This
        // is a best-effort correlation -- `None` when that audit row is no longer
        // retained -- never a fabricated verdict; the authoritative withholding
        // reason is the durable `visibility` on the row itself.
        let evidence_by_asset = self.withheld_screening_evidence(&state, &tenant_id);

        let search = query_value(query, "search");
        let rows: Vec<WithheldAssetSummary> = withheld
            .into_iter()
            .filter(|asset| {
                matches_search(
                    search.as_deref(),
                    &[
                        &asset.id,
                        &asset.name,
                        &asset.version,
                        &asset.asset_type,
                        asset.visibility.as_str(),
                    ],
                )
            })
            .map(|asset| WithheldAssetSummary {
                visibility: asset.visibility.as_str(),
                screening_evidence: evidence_by_asset.get(&asset.id).cloned(),
                asset: asset_summary(&asset),
            })
            .collect();

        let body = list_response(rows, query, state.admin_pagination(query));
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    /// Build the `asset_id -> screening evidence` map for the withheld listing
    /// (#379). Scans the tenant's push/commit audit events (`asset.push` /
    /// `committed`) and keeps the latest evidence `message` per asset id, so the
    /// operator sees the scan/signature/approval verdict captured at push time
    /// (#366) alongside the withheld row. Tenant-scoped: only this tenant's audit
    /// rows are consulted, so one tenant's evidence can never leak into another's
    /// listing.
    fn withheld_screening_evidence(
        &self,
        state: &crate::state::AppState,
        tenant_id: &str,
    ) -> std::collections::HashMap<String, String> {
        let mut latest: std::collections::HashMap<String, (u64, String)> =
            std::collections::HashMap::new();
        for event in state.audit_events() {
            if event.action != "asset.push" || event.outcome != "committed" {
                continue;
            }
            if event.tenant.organization_id.as_deref() != Some(tenant_id) {
                continue;
            }
            let occurred_at = event.occurred_at_unix.unwrap_or(0);
            match latest.get(&event.target) {
                Some((seen_at, _)) if *seen_at >= occurred_at => {}
                _ => {
                    latest.insert(event.target.clone(), (occurred_at, event.message.clone()));
                }
            }
        }
        latest
            .into_iter()
            .map(|(target, (_, message))| (target, message))
            .collect()
    }

    async fn handle_asset_storage_summary(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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
            auth.effective_quota.asset_max_object_bytes,
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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

        let inline_limit = inline_push_byte_limit(
            auth.effective_quota.asset_max_object_bytes,
            auth.effective_quota.asset_storage_quota_bytes,
        );
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
                content: super::asset_security::ScreenedContent::Buffered(&content),
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
        // single opaque blob. #366: only take this serve-publishing path when
        // the bundle screened clean; a pending/quarantined verdict must be
        // stored withheld (fall through to the ordinary blob store below) so
        // the site is never served before it is proven clean.
        if asset_type == "static_site" && is_zip_archive(&content) && screening.is_visible() {
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
        //
        // #371: the tenant asset-storage quota is admitted ATOMICALLY, folded
        // into the publication mutation below (`create_asset_within_quota`), NOT
        // as a separate read-then-write here. The former `tenant_asset_storage_bytes_used`
        // read + create let two concurrent pushes of two DIFFERENT ids both
        // observe the same remaining capacity, both pass, and jointly overshoot
        // the quota. The reservation now happens in the same conditional
        // statement that inserts the row, so exactly the fitting set is admitted.
        let effective_quota = auth.effective_quota.asset_storage_quota_bytes;

        let now = now_unix_seconds();

        // Bucket-backed storage (issue #176): when configured, the real bytes go
        // to the bucket and only a reference (`storage_uri`) is persisted, rather
        // than duplicated inline. A bucket PUT failure fails the whole push (not
        // a silent fallback to inline storage) -- an operator who configured a
        // bucket expects assets to actually land there.
        //
        // Atomic first-push publication (#369): the bytes go to a UNIQUE
        // per-attempt candidate key so two concurrent first pushes of this same
        // version can never overwrite each other's object -- the winner's
        // metadata references only the bytes IT wrote. The former deterministic
        // key (= `id`) let the losing push clobber the winner's bytes. Pure
        // inline (no bucket) needs no candidate: the bytes live in the row and
        // the atomic row create is the whole invariant.
        let candidate_key = if state.asset_bucket_client().is_some() {
            match asset_inline_publish::inline_candidate_object_key(&id) {
                Ok(key) => Some(key),
                Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
            }
        } else {
            None
        };
        let write_key = candidate_key.clone().unwrap_or_else(|| id.clone());
        let (stored_content, storage_uri) = match self
            .store_asset_bytes(&write_key, &content, &content_type)
            .await
        {
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
            storage_uri: storage_uri.clone(),
            variant: variant.clone(),
            yanked: false,
            // #366: persist the screening verdict so a pending/quarantined push
            // is durably withheld from every read path, not merely labeled on
            // the (transient) response.
            visibility: screening.visibility(),
            created_at_unix: now,
            updated_at_unix: now,
        };

        // Publish with the CREATE-IF-ABSENT primitive, never an immutable-version
        // upsert (#369). The candidate to reclaim on a loss is exactly the bucket
        // key this attempt wrote (`storage_uri`); a losing/failed attempt cleans
        // ONLY its own unreferenced candidate and an outcome-unknown create
        // preserves every candidate.
        let sink: Box<dyn asset_inline_publish::AssetCandidateSink> =
            match state.asset_bucket_client() {
                Some(bucket) => Box::new(asset_inline_publish::BucketCandidateSink::new(bucket)),
                None => Box::new(asset_inline_publish::NoCandidateSink),
            };
        match asset_inline_publish::publish_inline_asset(
            &state,
            sink.as_ref(),
            asset.clone(),
            storage_uri.as_deref(),
            effective_quota,
        )
        .await
        {
            asset_inline_publish::InlinePublishOutcome::Published => {}
            asset_inline_publish::InlinePublishOutcome::OverQuota {
                used_bytes,
                attempted_bytes,
                quota_bytes,
            } => {
                // #371/#368: the atomic admission definitively rejected this push
                // (nothing reserved or published). Audit the rejection with the
                // tenant/request/asset identity and the observed usage, mirroring
                // the presigned commit's `rejected_commit` event.
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "rejected_commit",
                    format!(
                        "asset {id} inline push rejected: reserving {attempted_bytes} bytes on top of \
                         {used_bytes} used would exceed the tenant's {quota_bytes}-byte asset storage quota"
                    ),
                ));
                return write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "asset_storage_quota_exceeded",
                    format!(
                        "pushing this asset would exceed the tenant's {quota_bytes}-byte asset storage quota"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            asset_inline_publish::InlinePublishOutcome::Conflict => {
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
            asset_inline_publish::InlinePublishOutcome::OutcomeUnknown => {
                // The create may have committed even though its result was lost.
                // Preserve every candidate and report unknown; a retry of the
                // identical push resolves it (create-if-absent is idempotent for
                // the same winner). Never delete a possibly-referenced winner.
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "outcome_unknown",
                    format!(
                        "asset {id} inline push has an unknown durable create outcome; \
                         the candidate object was preserved"
                    ),
                ));
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "asset_commit_outcome_unknown",
                    "asset publish outcome is unknown; retry the identical push before cleanup",
                    &ctx.request_id,
                )
                .await;
            }
            asset_inline_publish::InlinePublishOutcome::StorageFailed(message)
            | asset_inline_publish::InlinePublishOutcome::ReconcileFailed(message) => {
                return storage_unavailable(session, ctx, message).await;
            }
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
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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

        // #402: the admin console addresses per-file static-site objects by bare
        // path (`/v1/assets/static_site/{site}/{path}`), but a #397-published
        // bundle keys them under `__site_file__:{serving_version}:{path}`. Map the
        // bare path onto the active bundle's prefixed key so a per-file download
        // resolves for #397-era sites; legacy bare-path rows, reserved keys, and
        // every other asset family pass through unchanged (preserving #398).
        let resolved_reference: String;
        let reference = if asset_type == SITE_ASSET_TYPE {
            resolved_reference = self
                .resolve_site_asset_version(&tenant_id, name, reference)
                .await;
            resolved_reference.as_str()
        } else {
            reference
        };

        let assets = match self
            .asset_versions(&state, &tenant_id, asset_type, name)
            .await
        {
            Ok(assets) => assets,
            Err(error) => return storage_unavailable(session, ctx, error.to_string()).await,
        };
        // #366: withhold pending/quarantined rows from resolution entirely, so a
        // still-unproven asset is absent from exact/channel/range resolution and
        // can never be selected for download -- the read half of the persisted
        // screening state (write-path == read-path, #188).
        let assets: Vec<StoredAsset> = assets
            .into_iter()
            .filter(StoredAsset::is_downloadable)
            .collect();
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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
        // #402: mirror the pull path -- a #397 site's per-file object lives under
        // `__site_file__:{serving_version}:{path}`, so remap the bare per-file
        // path the console DELETEs by onto that key so unpublish resolves. The
        // reserved `__site_manifest__` marker and legacy bare-path rows pass
        // through unchanged (preserving the #398 decode path).
        let resolved_version: String;
        let version = if asset_type == SITE_ASSET_TYPE {
            resolved_version = self
                .resolve_site_asset_version(&tenant_id, name, version)
                .await;
            resolved_version.as_str()
        } else {
            version
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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

    /// Promote a `pending_scan` asset version to `visible`/`quarantined` after
    /// an out-of-band scan completes (issue #378, follow-up to #366). The
    /// operator supplies the completed-scan verdict and durable evidence; the
    /// gateway maps the verdict to a terminal target, runs the fail-closed CAS
    /// (which flips ONLY from `pending_scan`), and emits a durable audit event
    /// linking the promotion to the scan outcome, asset id, tenant, and
    /// request/trace id. An unknown verdict, missing evidence, or a
    /// non-`pending_scan` asset is rejected -- nothing is ever silently
    /// promoted.
    #[allow(clippy::too_many_arguments)]
    async fn handle_asset_visibility_promotion(
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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

        let request: AssetVisibilityPromotionRequest =
            match self.read_control_body(session, ctx).await? {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(()),
                Err(()) => return Ok(()),
            };

        // Map the completed-scan verdict to a terminal target. An unknown token
        // is rejected fail-closed: a promotion NEVER defaults to `visible`, so a
        // malformed or unexpected verdict can never publish unscanned bytes.
        let target = match request.scan_outcome.as_str() {
            "clean" | "visible" => AssetPromotionTarget::Visible,
            "quarantined" | "quarantine" | "infected" => AssetPromotionTarget::Quarantined,
            other => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_scan_outcome",
                    format!(
                        "scan_outcome must be one of clean|quarantined (got {other:?}); \
                         an unknown verdict is rejected fail-closed and never promotes"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        };
        // Evidence is mandatory: a durable promotion must carry the
        // justification that links it to the scan result. No evidence, no flip.
        let evidence = request.evidence.trim();
        if evidence.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "missing_scan_evidence",
                "evidence is required: supply the completed-scan justification \
                 (scanner id, verdict detail, or ticket) to promote an asset",
                &ctx.request_id,
            )
            .await;
        }

        let variant = query_param(query, "platform").unwrap_or_default();
        let id = stored_asset_variant_id(&tenant_id, asset_type, name, version, &variant);
        let scanner = request.scanner.as_deref().unwrap_or("out-of-band");
        // The audit message is the durable evidence the issue requires: it ties
        // the promotion to the scan outcome, the resulting visibility, the
        // scanner, and the operator-supplied justification. request/trace id,
        // tenant, and actor ride the AdminAuditEventDraft itself.
        let evidence_detail = format!(
            "scan_outcome={} target_visibility={} scanner={scanner} evidence={evidence}",
            target.as_str(),
            target.visibility().as_str(),
        );

        let now = now_unix_seconds();
        match state
            .promote_pending_asset_visibility(&id, target, now)
            .await
        {
            Ok(AssetVisibilityPromotionOutcome::Promoted { to }) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.visibility.promote",
                    &id,
                    "committed",
                    format!(
                        "asset {id} promoted pending_scan -> {} ({evidence_detail})",
                        to.as_str()
                    ),
                ));
                // Re-read for the response body only (the CAS already committed
                // the mutation durably above; this read does not prove it).
                let asset = match state.get_asset(&id).await {
                    Ok(Some(asset)) => asset,
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "asset_not_found",
                            format!("no asset at {asset_type}/{name}/{version}"),
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) => {
                        return storage_unavailable(session, ctx, error.to_string()).await;
                    }
                };
                let body = AssetVisibilityPromotionResponse {
                    object: "asset.visibility_promotion",
                    id: id.clone(),
                    visibility: to.as_str(),
                    scan_outcome: target.as_str(),
                    asset: asset_summary(&asset),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(AssetVisibilityPromotionOutcome::NotFound) => {
                // A scan verdict arriving for an absent asset is security-
                // relevant: record the rejected attempt as durable evidence.
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.visibility.promote",
                    &id,
                    "rejected",
                    format!("asset {id} promotion rejected: no such asset ({evidence_detail})"),
                ));
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
            Ok(AssetVisibilityPromotionOutcome::NotPending { current }) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.visibility.promote",
                    &id,
                    "rejected",
                    format!(
                        "asset {id} promotion rejected: not pending_scan (current={}); \
                         {evidence_detail}",
                        current.as_str()
                    ),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "asset_not_pending_scan",
                    format!(
                        "{asset_type}/{name}/{version}{} is {}, not pending_scan; \
                         only a pending_scan asset can be promoted",
                        variant_suffix(&variant),
                        current.as_str()
                    ),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_unavailable(session, ctx, error.to_string()).await,
        }
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
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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
        let auth = match authenticate(&state, headers, "assets.write", &ctx.request_id).await {
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
        let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
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
        // #366: the self-serve manifest advertises resolvable versions; a
        // pending/quarantined row must be absent from it just as it is absent
        // from resolution and download.
        let assets: Vec<StoredAsset> = assets
            .into_iter()
            .filter(StoredAsset::is_downloadable)
            .collect();
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
        // Issue #259: the registry pull serves from a full in-memory copy (it
        // re-verifies the hash and supports conditional/Range replies), so it
        // MUST NOT be reachable for an object the gateway refuses to hold.
        // `load_asset_content` owns that bound -- shared with the static-site
        // serve rather than duplicated here, which is how round 1 left the
        // site path unbounded.
        let content = match self.load_asset_content(&asset, &ctx.request_id).await {
            Ok(content) => content,
            Err(error) => return error.write(session, &ctx.request_id).await,
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
        // #529: the admission permit is held until this function returns, i.e.
        // across the response write, because that is how long these bytes are
        // resident. Releasing it when the bucket read returned would let the
        // budget admit a fresh read for every buffer still being written out.
        let (content, _budget) = content.into_parts();
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
    ///
    /// This is the gateway-side half of the single gateway memory bound (issue
    /// #259 round 2). Round 1 put the bound in `write_asset_body`, which left
    /// the static-site serve reaching this helper with no bound at all; the
    /// bound now lives here, so `write_asset_body` and `serve_site_file` share
    /// one refusal instead of one of them having a copy. The size the registry
    /// row declares is refused BEFORE the bucket client is even resolved --
    /// there is no work worth doing for an object the gateway will not hold.
    pub(super) async fn load_asset_content(
        &self,
        asset: &StoredAsset,
        request_id: &str,
    ) -> Result<BufferedObject, AssetError> {
        let Some(storage_uri) = asset.storage_uri.as_deref() else {
            // Inline content is resident because the registry row is; it never
            // went near the bucket, so it is not charged the buffering budget
            // (issue #529).
            return Ok(BufferedObject::unbudgeted(asset.content.clone()));
        };
        let state = self.state.current();
        let buffer_limit = state.asset_max_gateway_buffer_bytes();
        if asset.size_bytes > buffer_limit {
            return Err(AssetError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: ASSET_TOO_LARGE_FOR_INLINE_PULL_CODE,
                message: asset_too_large_for_buffering_message(
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    asset.size_bytes,
                    buffer_limit,
                ),
            });
        }
        let Some(bucket) = state.asset_bucket_client() else {
            return Err(AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "asset_bucket_unavailable",
                message: "this asset is bucket-backed but no asset_bucket is configured"
                    .to_string(),
            });
        };
        read_object_bounded(
            &bucket,
            storage_uri,
            asset.size_bytes,
            buffer_limit,
            state.asset_buffer_admission(),
            // The pull and the site serve write the buffer itself into the
            // response, so one copy is the whole residency.
            ReadResidency::BufferOnly,
            &asset.id,
            request_id,
        )
        .await
        .map_err(|refusal| match refusal {
            // Unreachable in practice -- the declared size was already checked
            // above -- but mapped rather than collapsed so the transport's own
            // over-budget stop (a bucket whose object exceeds what the row
            // claims) surfaces as the same typed refusal instead of a 503 that
            // reads like an outage.
            BufferedReadRefusal::TooLarge {
                size_bytes,
                limit_bytes,
            } => AssetError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: ASSET_TOO_LARGE_FOR_INLINE_PULL_CODE,
                message: asset_too_large_for_buffering_message(
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    size_bytes,
                    limit_bytes,
                ),
            },
            // #529: a load condition, not a fault of the object or the caller
            // -- so a 503 that says so, with the numbers that explain it and
            // the endpoint that does not draw on this budget.
            BufferedReadRefusal::Overloaded {
                requested_bytes,
                budget_bytes,
                waited_ms,
            } => AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: GATEWAY_BUFFER_BUDGET_EXHAUSTED_CODE,
                message: gateway_buffer_budget_exhausted_message(
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    requested_bytes,
                    budget_bytes,
                    waited_ms,
                ),
            },
            BufferedReadRefusal::Transport => AssetError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "asset_bucket_unavailable",
                message: BUCKET_READ_UNAVAILABLE_MESSAGE.to_string(),
            },
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
            .map_err(|error| {
                // The bucket error's Display embeds the request URL, i.e. the
                // internal object key and the bucket endpoint (issue #259
                // review finding 4). Log it, do not serialize it.
                tracing::warn!(
                    asset_id = %id,
                    error = %error,
                    "failed to write an asset object to the bucket"
                );
                AssetError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "asset_bucket_unavailable",
                    message: BUCKET_READ_UNAVAILABLE_MESSAGE.to_string(),
                }
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
    per_object_ceiling: Option<u64>,
    presigned_limits: Option<(u64, u64)>,
) -> AssetStorageSummary {
    let (enabled, max_object_bytes, url_ttl_seconds) = match presigned_limits {
        Some((global_max_object_bytes, url_ttl_seconds)) => {
            // Report the plan/quota-driven effective per-object ceiling (issue
            // #259), not the raw global operator constant: the advertised limit
            // is tightened to BOTH the tenant's dedicated per-object ceiling
            // (`asset_max_object_bytes`) and its cumulative asset-storage quota
            // when either is smaller, matching what the presigned upload-intent
            // path enforces via `effective_max_object_bytes`.
            let effective_max_object_bytes = global_max_object_bytes
                .min(per_object_ceiling.unwrap_or(u64::MAX))
                .min(quota_bytes.unwrap_or(u64::MAX));
            (
                true,
                Some(effective_max_object_bytes),
                Some(url_ttl_seconds),
            )
        }
        None => (false, None, None),
    };
    AssetStorageSummary {
        object: "asset_storage_summary",
        used_bytes,
        quota_bytes,
        remaining_bytes: quota_bytes.map(|quota| quota.saturating_sub(used_bytes)),
        inline_upload_max_bytes: inline_push_byte_limit(per_object_ceiling, quota_bytes) as u64,
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

/// Percent-decodes a single URL path segment (`%XX` -> byte). Used only for the
/// `{version}` segment of `/v1/assets/{asset_type}/{name}/{version}` (#398): the
/// per-file static-site addressing encodes a possibly deeply-nested file path
/// into that segment, so its slashes arrive as `%2F` (and any other reserved
/// byte as `%XX`). Decoding reconstitutes the slashed object key the
/// publish/unpack path stored, so a nested per-file download/unpublish resolves
/// exactly as a top-level one does.
///
/// This is guarded and unambiguous for every pre-#398 reference: URL-safe
/// versions (semver like `1.0.0`/`^1.2.0`, channel names, the reserved
/// `__site_manifest__` / `__site_file__:` keys) contain no `%`, so they pass
/// through byte-for-byte -- the decode is a no-op for them. A `%` not followed
/// by two hex digits is left literal, so a stray `%` in a reference can never
/// truncate or corrupt it. Decoding happens AFTER the router split on raw `/`,
/// so an encoded slash stays a single segment through routing and is only turned
/// back into `/` here, at the point the segment becomes an object-key lookup.
fn percent_decode_segment(segment: &str) -> String {
    if !segment.contains('%') {
        return segment.to_string();
    }
    let bytes = segment.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
        // No per-object ceiling and no cumulative quota: the inline path
        // buffers up to its own cap.
        assert_eq!(
            inline_push_byte_limit(None, None),
            INLINE_ASSET_MAX_BYTES as usize
        );
        // A cumulative quota larger than the inline cap can't loosen the cap.
        assert_eq!(
            inline_push_byte_limit(None, Some(INLINE_ASSET_MAX_BYTES * 100)),
            INLINE_ASSET_MAX_BYTES as usize
        );
    }

    #[test]
    fn inline_push_byte_limit_tightens_to_a_smaller_cumulative_quota() {
        // A cumulative quota smaller than the inline cap drives the limit --
        // this is the plan/quota-driven replacement for the old hard
        // MAX_ASSET_BYTES constant (issue #259).
        assert_eq!(inline_push_byte_limit(None, Some(4_096)), 4_096);
        assert_eq!(inline_push_byte_limit(None, Some(0)), 0);
    }

    #[test]
    fn inline_push_byte_limit_tightens_to_a_dedicated_per_object_ceiling() {
        // #259: the dedicated per-object ceiling caps the inline path too, and
        // can bind TIGHTER than the cumulative quota independently of it.
        assert_eq!(inline_push_byte_limit(Some(2_048), None), 2_048);
        assert_eq!(inline_push_byte_limit(Some(2_048), Some(8_192)), 2_048);
        // A None per-object ceiling is a no-op: the cumulative quota still binds.
        assert_eq!(inline_push_byte_limit(None, Some(8_192)), 8_192);
    }
}

#[cfg(test)]
#[path = "assets_test.rs"]
mod assets_test;
