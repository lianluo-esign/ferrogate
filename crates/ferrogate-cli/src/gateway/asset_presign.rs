// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Large-file asset path (issue #259) -- presigned S3
// upload/download so object bytes bypass the Pingora hot path, per-object
// size ceilings layered on the tenant asset-storage quota, and a
// private-bucket read path (all reads go through gateway-issued presigned
// GETs, never the public bucket URL). Split into its own module (rather
// than growing assets.rs, which another change touches concurrently): the
// three endpoints here reuse the exact virtual-key auth + StoredPlan/role
// entitlement + tenant scoping the inline `/v1/assets/*` handlers use.
//
// Push flow: register-intent (authorize + meter/audit + quota preflight,
// return a short-TTL presigned PUT for a unique staging object) -> client PUTs
// bytes straight to the bucket -> commit (gateway verifies size, sha256, and
// the built-in content rules against the fetched staging bytes, copies those
// verified bytes to a private immutable object key, then atomically publishes
// the `stored_assets` row). A replayed client PUT can only replace staging;
// it can never mutate the object referenced by an already-published version.
//
// #368: the presigned staging PUT is *bound* to the declared size +
// SHA-256. `content-length` and `x-amz-content-sha256` are SigV4 signed
// headers of the presigned URL (payload hash = the declared checksum, not
// UNSIGNED-PAYLOAD), and the intent response returns the exact
// `required_headers` the client must send verbatim -- so an upload whose
// size or bytes differ from what the gateway approved is rejected at the
// bucket boundary itself, and staging capacity can no longer be burned
// beyond the approved object. Scope: a single PUT only -- multipart
// uploads are out of scope (the per-object ceiling keeps single-PUT
// objects within what S3-compatible services accept in one request).
//
// #368 orphan/abort: an intent that is never uploaded can be released
// explicitly through `POST /v1/assets/presign/abort/...`, which *attempts*
// to delete the staging object immediately instead of waiting for the
// asset-lifecycle GC (`state_asset_lifecycle.rs`, audit action
// `asset.gc.delete`), which remains the backstop for clients that simply
// vanish -- and for aborts whose own delete failed. That attempt can fail
// (bucket 5xx/403), so its three real outcomes are reported as they
// happened: `not_staged`, `removed`, `removal_failed`. A failed reclamation
// is never rendered as a successful one; it is audited as
// `aborted_reclaim_failed` and counted in
// `ferrogate_asset_presign_abort_reclaim_failed_total`, mirroring
// `asset_lifecycle_failed_total` on the GC path.
//
// #368 rejection evidence, stated precisely because the boundary matters:
// the gateway never sees the direct PUT, so it cannot observe a bucket
// refusal first-hand. Three classes are gateway-observed (`rejected_intent`
// at preflight, `rejected_commit` over staged bytes, `aborted` at the abort
// surface). The fourth, `rejected_bucket`, is client-reported at abort and
// then *corroborated*: the gateway confirms no object exists under the
// staging key only it can derive. A commit that simply finds nothing staged
// is audited as `staging_missing`, NOT as a bucket rejection -- absence
// alone conflates never-attempted, expired-URL and bucket-refused, and
// calling it a bucket rejection would overstate the evidence. Fully
// independent proof would require bucket access logs, which no configured
// S3-compatible backend exposes to the gateway today.
//
// Private-bucket operator runbook: docs/assets/private-bucket-migration.md.
//
// Honest scope note: like asset_bucket.rs, tested against a local mock
// S3-compatible endpoint (request shape + fail-closed behavior), not a
// live Supabase Storage bucket -- no live bucket credentials are available
// in this environment and no live bucket is flipped here.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_storage::{
    sha256_hex, stored_asset_id, AssetQuotaAdmission, StorageError, StoredAsset,
};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::{authenticate, AuthContext},
    responses::{write_json_error, write_json_response, AssetMutationResponse, AssetSummary},
};

/// Small ceiling for the intent/commit JSON control bodies -- these carry
/// only a size + sha256 + content-type, never object bytes (those go
/// straight to the bucket via the presigned URL).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresignUploadIntentRequest {
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresignCommitRequest {
    upload_id: String,
    size_bytes: u64,
    sha256: String,
    #[serde(default)]
    content_type: Option<String>,
    // #366: the trust-screening inputs the presigned commit must carry so the
    // SAME signature/approval/scanner/content-policy service the inline path
    // runs is applied over the final verified bytes. Every field is optional
    // (an unsigned tenant-private publish sends none), typed here so a malformed
    // request fails with a `deny_unknown_fields` / type error rather than
    // silently skipping a control. These mirror the inline path's
    // `x-asset-signature*` / `x-asset-visibility` / `x-asset-approval-id`
    // headers one-for-one -- one shared contract, two transports.
    /// Detached minisign file or base64 Ed25519 signature material.
    #[serde(default)]
    signature: Option<String>,
    /// Detached signature encoding; defaults to minisign when a signature is
    /// present but no format is given (matches the inline default).
    #[serde(default)]
    signature_format: Option<String>,
    /// Publisher key hint for bare Ed25519 signatures.
    #[serde(default)]
    signature_key_id: Option<String>,
    /// Publish visibility; cross-tenant values require a durable approval.
    /// Omission defaults to tenant-private, same as the inline path.
    #[serde(default)]
    visibility: Option<String>,
    /// Durable tool-approval record id used for cross-tenant publication.
    #[serde(default)]
    approval_id: Option<String>,
}

/// #368: release an intent whose direct PUT will never be committed. The
/// staging key is server-derived from `id|upload_id|size_bytes|sha256`, so the
/// same three declarations the intent registered are required to name it --
/// a caller cannot abort an upload it did not register.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresignAbortRequest {
    upload_id: String,
    size_bytes: u64,
    sha256: String,
    /// Why the intent is being released. Typed, because it decides which
    /// rejection class the audit trail and metrics record; an absent or
    /// unrecognized value degrades to `abandoned` (the claim that costs the
    /// least evidence), never up to `bucket_rejected`.
    #[serde(default)]
    reason: Option<String>,
}

/// The two reasons a client can give for releasing an intent (#368).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbortReason {
    /// The direct PUT was refused by the bucket (typically a 403 from the
    /// SigV4 size/checksum binding). Only ever *recorded* as a bucket
    /// rejection when the gateway corroborates it by finding no staged object.
    BucketRejected,
    /// The client simply gave up; no claim about the bucket is made.
    Abandoned,
}

impl AbortReason {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("bucket_rejected") => Self::BucketRejected,
            _ => Self::Abandoned,
        }
    }
}

/// #368: what this abort actually did to the staging object. Three real
/// outcomes, kept apart because collapsing them is how a swallowed delete
/// error becomes a confident lie: the client is told the bytes were reclaimed
/// while they sit in the bucket consuming the tenant's quota until the
/// lifecycle sweep. `head_object` says whether bytes were there;
/// `delete_object` says whether they are gone. Only the second answers the
/// question the response field asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagingReclamation {
    /// No object existed under the staging key; there was nothing to reclaim.
    NotStaged,
    /// A staging object existed and the bucket confirmed its deletion.
    Removed,
    /// A staging object existed and the delete failed. The bytes are still
    /// there; the lifecycle GC is now the only thing that will reclaim them.
    RemovalFailed,
}

impl StagingReclamation {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotStaged => "not_staged",
            Self::Removed => "removed",
            Self::RemovalFailed => "removal_failed",
        }
    }

    /// The `staging_object_removed` boolean, which must answer "are the bytes
    /// gone?" -- not "were there bytes?".
    fn removed(self) -> bool {
        matches!(self, Self::Removed)
    }
}

#[derive(Debug, Serialize)]
struct PresignAbortResponse {
    object: &'static str,
    upload_id: String,
    /// True ONLY when a staging object existed and the bucket confirmed its
    /// deletion. A delete the bucket refused reports `false` here with
    /// `staging_reclamation: "removal_failed"` -- the bytes are still
    /// occupying quota and the client is told so.
    staging_object_removed: bool,
    /// The tri-state `staging_object_removed` cannot express: nothing was
    /// staged, the staged bytes were reclaimed, or the reclamation failed and
    /// the object survives until the lifecycle GC.
    staging_reclamation: &'static str,
    /// The outcome actually recorded in the audit trail and metrics. This is
    /// NOT an echo of the requested `reason`: a `bucket_rejected` claim that
    /// the gateway contradicts (bytes *are* staged) is downgraded to
    /// `aborted`, and the response says so. A failed reclamation is reported
    /// as `aborted_reclaim_failed`.
    outcome: &'static str,
}

impl PresignCommitRequest {
    /// Build the detached-signature input for screening, mirroring the inline
    /// `x-asset-signature*` header parsing. `None` means an unsigned publish.
    fn signature_input(&self) -> Option<super::asset_signature::AssetSignatureInput> {
        self.signature
            .as_ref()
            .map(|material| super::asset_signature::AssetSignatureInput {
                format: self
                    .signature_format
                    .as_deref()
                    .and_then(super::asset_signature::SignatureFormat::parse)
                    .unwrap_or(super::asset_signature::SignatureFormat::Minisign),
                material: material.clone(),
                key_id: self.signature_key_id.clone(),
            })
    }

    /// Resolve the requested publish visibility, defaulting to tenant-private
    /// exactly as the inline path does for an absent/unparsable value.
    fn publish_visibility(&self) -> super::asset_publish_gate::PublishVisibility {
        self.visibility
            .as_deref()
            .and_then(super::asset_publish_gate::PublishVisibility::parse)
            .unwrap_or(super::asset_publish_gate::PublishVisibility::TenantPrivate)
    }
}

#[derive(Debug, Serialize)]
struct PresignUploadIntentResponse {
    object: &'static str,
    key: String,
    upload_id: String,
    upload_url: String,
    method: &'static str,
    /// URL validity window; after it elapses the bucket rejects the PUT
    /// (`X-Amz-Expires` is signed) and the client must register a new intent.
    expires_in_seconds: u64,
    size_bytes: u64,
    sha256: String,
    /// #368: header name -> value the client MUST send verbatim on the
    /// direct PUT. These are SigV4 signed headers of `upload_url`, so
    /// omitting or changing any of them -- or uploading bytes whose size or
    /// SHA-256 differ from the declared intent -- invalidates the upload at
    /// the bucket boundary.
    required_headers: std::collections::BTreeMap<&'static str, String>,
    /// The per-object ceiling the intent was checked against, echoed so
    /// clients can fail fast without a rejected round-trip.
    max_object_bytes: u64,
    /// Wire protocol for the direct upload; always `single_put` today. Typed
    /// as a named protocol rather than a `multipart: false` boolean so adding
    /// multipart later is an additive enum value instead of a semantic flip.
    /// Multipart is deliberately unsupported: S3 signs each part separately,
    /// so one presigned authorization cannot bind the whole object's size and
    /// checksum -- exactly the invariant this endpoint exists to enforce. The
    /// per-object ceiling keeps objects inside what a single PUT accepts.
    upload_protocol: &'static str,
}

#[derive(Debug, Serialize)]
struct PresignDownloadResponse {
    object: &'static str,
    download_url: String,
    method: &'static str,
    expires_in_seconds: u64,
    sha256: String,
    size_bytes: u64,
    content_type: String,
}

impl FerroGateway {
    /// Dispatches the presigned large-file endpoints (issue #259). Returns
    /// `Ok(true)` once a response has been written, `Ok(false)` when the
    /// path is not a presign path (so the caller falls through to the
    /// inline `/v1/assets/*` handler). Kept separate from `handle_assets`'s
    /// 3-segment matcher so the inline module stays untouched.
    ///
    /// Routes (all under the `presign/` prefix so they can never collide
    /// with an `{asset_type}` segment):
    /// - `POST /v1/assets/presign/upload/{asset_type}/{name}/{version}`
    /// - `POST /v1/assets/presign/commit/{asset_type}/{name}/{version}`
    /// - `POST /v1/assets/presign/abort/{asset_type}/{name}/{version}`
    /// - `GET  /v1/assets/presign/download/{asset_type}/{name}/{version}`
    pub(super) async fn try_asset_presign_routes(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        req: &super::route_groups::RequestParts,
    ) -> PingoraResult<bool> {
        let Some(rest) = req.path.strip_prefix("/v1/assets/presign/") else {
            return Ok(false);
        };
        let segments: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
        let [action, asset_type, name, version] = segments.as_slice() else {
            return Ok(false);
        };
        match (*action, &req.method) {
            ("upload", &Method::POST) => {
                self.handle_asset_upload_intent(
                    session,
                    ctx,
                    &req.headers,
                    asset_type,
                    name,
                    version,
                )
                .await?;
                Ok(true)
            }
            ("commit", &Method::POST) => {
                self.handle_asset_commit(session, ctx, &req.headers, asset_type, name, version)
                    .await?;
                Ok(true)
            }
            ("abort", &Method::POST) => {
                self.handle_asset_upload_abort(
                    session,
                    ctx,
                    &req.headers,
                    asset_type,
                    name,
                    version,
                )
                .await?;
                Ok(true)
            }
            ("download", &Method::GET) => {
                self.handle_asset_download_url(
                    session,
                    ctx,
                    &req.headers,
                    asset_type,
                    name,
                    version,
                )
                .await?;
                Ok(true)
            }
            ("upload", _) | ("commit", _) | ("abort", _) => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    format!(
                        "/v1/assets/presign/{action}/{{asset_type}}/{{name}}/{{version}} supports POST"
                    ),
                    &ctx.request_id,
                )
                .await?;
                Ok(true)
            }
            ("download", _) => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "/v1/assets/presign/download/{asset_type}/{name}/{version} supports GET",
                    &ctx.request_id,
                )
                .await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn handle_asset_upload_intent(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some((auth, tenant_id)) = self
            .authorize_asset(session, ctx, headers, "assets.write", true)
            .await?
        else {
            return Ok(());
        };

        let intent: PresignUploadIntentRequest = match self.read_control_body(session, ctx).await? {
            Ok(Some(intent)) => intent,
            Ok(None) => return Ok(()),
            Err(()) => return Ok(()),
        };
        if intent.size_bytes == 0 || !is_hex_sha256(&intent.sha256) {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_upload_intent",
                "upload intent requires a non-zero size_bytes and a 64-char hex sha256",
                &ctx.request_id,
            )
            .await;
        }

        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        match state.get_asset(&id).await {
            Ok(Some(_)) => {
                return write_asset_version_immutable(session, ctx, asset_type, name, version)
                    .await;
            }
            Ok(None) => {}
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
        }

        let Some(bucket) = state.asset_bucket_client() else {
            return write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "asset_bucket_unavailable",
                "the presigned large-file path requires an [asset_bucket] to be configured",
                &ctx.request_id,
            )
            .await;
        };

        // Per-object ceiling (issue #259) -- layered on top of, and checked
        // before, the cumulative tenant quota. The operator's global
        // `[asset_bucket].presign_max_object_bytes` is tightened to BOTH the
        // tenant's DEDICATED per-object ceiling (`asset_max_object_bytes`, a
        // first-class plan/quota-policy cap on individual object size) and its
        // cumulative `asset_storage_quota_bytes` (an object can never exceed the
        // whole tenant quota), whichever is smallest. The dedicated per-object
        // ceiling can bind tighter than the cumulative quota independently of
        // it. The value is echoed to the client so it can fail fast.
        let max_object_bytes = effective_max_object_bytes(
            state.asset_presign_max_object_bytes(),
            auth.effective_quota.asset_max_object_bytes,
            auth.effective_quota.asset_storage_quota_bytes,
        );
        if intent.size_bytes > max_object_bytes {
            // #368: outcome `rejected_intent` distinguishes this preflight
            // rejection from bucket-boundary (`rejected_bucket`) and
            // commit-time (`rejected_commit`) rejections, and from orphan
            // GC (`asset.gc.delete`). The matching counter makes the same
            // distinction available to alerting without log scraping.
            state.record_asset_presign_outcome(crate::state::AssetPresignOutcome::IntentRejected);
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "asset.presign_upload_intent",
                &id,
                "rejected_intent",
                format!(
                    "rejected upload intent for asset {id}: {} bytes exceeds the {max_object_bytes}-byte per-object ceiling",
                    intent.size_bytes
                ),
            ));
            return write_json_error(
                session,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!(
                    "object size {} exceeds the per-object ceiling of {max_object_bytes} bytes",
                    intent.size_bytes
                ),
                &ctx.request_id,
            )
            .await;
        }

        // Quota preflight so an obviously over-quota upload is rejected
        // before we hand out a presigned URL; the authoritative accounting
        // still happens at commit (below), when the real bytes exist.
        match self
            .asset_quota_status(
                &state,
                &tenant_id,
                &id,
                auth.effective_quota.asset_storage_quota_bytes,
                intent.size_bytes,
            )
            .await
        {
            QuotaStatus::Ok => {}
            QuotaStatus::Exceeded(quota) => {
                state.record_asset_presign_outcome(
                    crate::state::AssetPresignOutcome::IntentRejected,
                );
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.presign_upload_intent",
                    &id,
                    "rejected_intent",
                    format!(
                        "rejected upload intent for asset {id}: {} bytes would exceed the tenant's {quota}-byte asset storage quota",
                        intent.size_bytes
                    ),
                ));
                return write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "asset_storage_quota_exceeded",
                    format!(
                        "uploading this asset would exceed the tenant's {quota}-byte asset storage quota"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            QuotaStatus::StorageError(message) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        }

        let expected_sha256 = intent.sha256.to_ascii_lowercase();
        let upload_id = match new_upload_id() {
            Ok(upload_id) => upload_id,
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
        };
        let staging_key = staging_object_key(&id, &upload_id, intent.size_bytes, &expected_sha256);
        let ttl = state.asset_presign_ttl_secs();
        // #368: the URL is bound to the declared size + checksum -- the
        // bucket independently recomputes the signature over those signed
        // headers, so a PUT with different values (or bytes) fails there.
        let upload = match bucket.presign_put(
            &staging_key,
            ttl,
            now_unix_seconds_u64(),
            intent.size_bytes,
            &expected_sha256,
        ) {
            Ok(upload) => upload,
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
        };

        state.record_asset_presign_outcome(crate::state::AssetPresignOutcome::IntentIssued);
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "asset.presign_upload_intent",
            &id,
            "issued",
            format!(
                "issued upload {upload_id} with a {ttl}s presigned staging URL for asset {id} ({} bytes)",
                intent.size_bytes,
            ),
        ));

        let body = PresignUploadIntentResponse {
            object: "asset_upload_intent",
            key: id,
            upload_id,
            upload_url: upload.url,
            method: "PUT",
            expires_in_seconds: ttl,
            size_bytes: intent.size_bytes,
            sha256: expected_sha256,
            required_headers: upload.required_headers.into_iter().collect(),
            max_object_bytes,
            upload_protocol: SINGLE_PUT_UPLOAD_PROTOCOL,
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    async fn handle_asset_commit(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some((auth, tenant_id)) = self
            .authorize_asset(session, ctx, headers, "assets.write", true)
            .await?
        else {
            return Ok(());
        };

        let commit: PresignCommitRequest = match self.read_control_body(session, ctx).await? {
            Ok(Some(commit)) => commit,
            Ok(None) => return Ok(()),
            Err(()) => return Ok(()),
        };
        if commit.size_bytes == 0
            || !is_hex_sha256(&commit.sha256)
            || !is_upload_id(&commit.upload_id)
        {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_commit",
                "commit requires a valid upload_id, non-zero size_bytes, and 64-char hex sha256",
                &ctx.request_id,
            )
            .await;
        }
        let expected_sha256 = commit.sha256.to_ascii_lowercase();
        let content_type = commit
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        let staging_key =
            staging_object_key(&id, &commit.upload_id, commit.size_bytes, &expected_sha256);
        match state.get_asset(&id).await {
            Ok(Some(existing)) => {
                if existing_asset_matches_commit(
                    &existing,
                    &id,
                    &commit.upload_id,
                    commit.size_bytes,
                    &expected_sha256,
                    &content_type,
                ) {
                    let body = AssetMutationResponse {
                        object: "asset",
                        asset: asset_summary(&existing),
                    };
                    return write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                        .await;
                }
                if !existing_asset_uses_upload(&existing, &id, &commit.upload_id) {
                    if let Some(bucket) = state.asset_bucket_client() {
                        let _ = best_effort_delete(&bucket, &staging_key).await;
                    }
                }
                return write_asset_version_immutable(session, ctx, asset_type, name, version)
                    .await;
            }
            Ok(None) => {}
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
        }
        let Some(bucket) = state.asset_bucket_client() else {
            return write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "asset_bucket_unavailable",
                "the presigned large-file path requires an [asset_bucket] to be configured",
                &ctx.request_id,
            )
            .await;
        };

        // The private immutable destination is named before verification
        // because the streaming path fuses the copy with the verification: one
        // bounded pass reads staging, hashes and screens every byte, and writes
        // those same bytes here. The name is fresh 128-bit randomness under an
        // intent-derived prefix, so nothing can reference it until the
        // `stored_assets` row is created below.
        let final_key = match new_final_object_key(&id, &commit.upload_id) {
            Ok(final_key) => final_key,
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
        };

        // Verify the staging object. Below the gateway's in-memory budget the
        // exact verified bytes are retained and re-PUT here, so a replay of the
        // client-facing staging URL cannot race a different payload into the
        // durable object. Above it, the same guarantee holds without the buffer:
        // the copy is driven from the verified stream itself.
        let verification = verify_committed_object(
            &bucket,
            &CommitVerificationRequest {
                staging_key: &staging_key,
                final_key: &final_key,
                expected_size: commit.size_bytes,
                expected_sha256: &expected_sha256,
                asset_type,
                content_type: &content_type,
                // Same plan/quota-driven per-object ceiling the intent was
                // checked against (issue #259): the commit-time size
                // verification tightens the global ceiling to BOTH the tenant's
                // dedicated per-object ceiling and its cumulative asset-storage
                // quota, so a committed object can never exceed either even if a
                // stale intent was issued under a larger prior ceiling.
                max_object_bytes: effective_max_object_bytes(
                    state.asset_presign_max_object_bytes(),
                    auth.effective_quota.asset_max_object_bytes,
                    auth.effective_quota.asset_storage_quota_bytes,
                ),
                buffer_limit: state.asset_max_gateway_buffer_bytes(),
                admission: state.asset_buffer_admission(),
            },
        )
        .await;
        let verified = match verification {
            Ok(CommitVerification::Verified {
                bytes,
                sha256,
                budget,
            }) => VerifiedCommit::Buffered {
                actual_size: bytes.len() as u64,
                bytes,
                sha256,
                budget,
            },
            Ok(CommitVerification::VerifiedStreamed {
                size_bytes,
                sha256,
                eicar_found,
            }) => VerifiedCommit::Streamed {
                actual_size: size_bytes,
                sha256,
                eicar_found,
            },
            verification_failure => {
                // A concurrent identical commit can publish metadata and
                // remove staging after our early lookup. Reconcile every
                // verification failure against that durable winner before
                // returning a stale 404/422/503.
                match reconcile_commit_winner(
                    &state,
                    &id,
                    &commit.upload_id,
                    commit.size_bytes,
                    &expected_sha256,
                    &content_type,
                )
                .await
                {
                    Ok(CommitWinner::Matching(existing)) => {
                        let body = AssetMutationResponse {
                            object: "asset",
                            asset: asset_summary(&existing),
                        };
                        return write_json_response(
                            session,
                            StatusCode::OK,
                            &body,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Ok(CommitWinner::Conflict) => {
                        let _ = best_effort_delete(&bucket, &staging_key).await;
                        return write_asset_version_immutable(
                            session, ctx, asset_type, name, version,
                        )
                        .await;
                    }
                    Ok(CommitWinner::Missing) => {}
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
                }

                match verification_failure {
                    Ok(CommitVerification::NotUploaded) => {
                        // #368: outcome `staging_missing`, NOT `rejected_bucket`.
                        // Absence at commit time proves only that no bytes are
                        // staged -- it cannot distinguish never-attempted from
                        // expired-URL from bucket-refused, and the gateway never
                        // observes the direct PUT. Claiming a bucket rejection
                        // here would be an inference dressed as evidence; a real
                        // bucket rejection is recorded only via the abort surface,
                        // where the client's report is corroborated by this same
                        // staging lookup.
                        state.record_asset_presign_outcome(
                            crate::state::AssetPresignOutcome::StagingMissing,
                        );
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "asset.push",
                            &id,
                            "staging_missing",
                            format!(
                                "asset {id} upload {} has no staged object at commit; the direct PUT was never attempted, its URL expired, or the bucket refused it (indistinguishable from here -- see POST /v1/assets/presign/abort)",
                                commit.upload_id
                            ),
                        ));
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "asset_not_uploaded",
                            "no object was uploaded to the presigned URL for this asset",
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Ok(CommitVerification::Rejected(rejection)) => {
                        // #368: outcome `rejected_commit` -- the staged
                        // object existed but failed the gateway's commit
                        // verification (size, sha256, or content rules).
                        state.record_asset_presign_outcome(
                            crate::state::AssetPresignOutcome::CommitRejected,
                        );
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "asset.push",
                            &id,
                            "rejected_commit",
                            format!(
                                "asset {id} upload {} failed commit verification ({}): {}",
                                commit.upload_id, rejection.code, rejection.message
                            ),
                        ));
                        return write_json_error(
                            session,
                            StatusCode::UNPROCESSABLE_ENTITY,
                            rejection.code,
                            rejection.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) => {
                        // Honesty fix (#259 review): a bucket transport failure
                        // is NOT serialized to the caller. `reqwest::Error`'s
                        // Display embeds the request URL, which would leak the
                        // internal `.ferrogate/objects/<digest>/obj_<rand>` key
                        // and the bucket endpoint into a 503 body -- exactly
                        // what the private-bucket runbook promises never
                        // happens. The detail goes to the operator log instead.
                        tracing::warn!(
                            request_id = %ctx.request_id,
                            asset_id = %id,
                            upload_id = %commit.upload_id,
                            staging_key = %staging_key,
                            final_key = %final_key,
                            error = %error,
                            "asset commit verification failed against the object bucket"
                        );
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "asset_bucket_unavailable",
                            BUCKET_TRANSPORT_ERROR_MESSAGE,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    // #529: the aggregate buffering budget was exhausted. A
                    // typed 503 that names the condition -- not the
                    // bucket-unavailable 503 above, which would send an
                    // operator to look at a bucket that is perfectly healthy.
                    Ok(CommitVerification::Overloaded {
                        requested_bytes,
                        budget_bytes,
                        waited_ms,
                    }) => {
                        tracing::warn!(
                            request_id = %ctx.request_id,
                            asset_id = %id,
                            upload_id = %commit.upload_id,
                            requested_bytes,
                            budget_bytes,
                            waited_ms,
                            "shed a presigned commit: the gateway's aggregate buffering budget \
                             is exhausted; staging is preserved for the retry"
                        );
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            super::asset_bucket::GATEWAY_BUFFER_BUDGET_EXHAUSTED_CODE,
                            format!(
                                "the gateway's aggregate in-memory budget for buffered asset \
                                 work ([asset_bucket].max_total_gateway_buffer_bytes = \
                                 {budget_bytes} bytes) is fully committed; this \
                                 {requested_bytes}-byte commit waited {waited_ms}ms for capacity \
                                 and was shed rather than queued indefinitely. The staged object \
                                 is preserved -- retry with the same upload_id"
                            ),
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Ok(CommitVerification::Verified { .. })
                    | Ok(CommitVerification::VerifiedStreamed { .. }) => unreachable!(),
                }
            }
        };
        let actual_size = verified.actual_size();
        let actual_sha256 = verified.sha256().to_string();

        // #366: full trust screening over the FINAL verified bytes -- the exact
        // signature/approval/scanner/content-policy service the inline path runs
        // (`asset_security::screen_asset_push`). Before #366 this path applied
        // only size/SHA-256 + built-in content validation, so a presigned upload
        // silently bypassed the signature requirement, cross-tenant approval
        // gate, pluggable malware scanner, and the pending/quarantined
        // withholding the inline path enforced. Screening runs before the
        // durable publish so a rejection fails closed: the staging object is
        // best-effort deleted and no asset row is created.
        let security = super::asset_security::AssetSecurityContext::from_env();
        let signature_input = commit.signature_input();
        let visibility = commit.publish_visibility();
        // The approval id names a durable tool-approval record whose status the
        // gate reads (never a client-asserted status), same as the inline path.
        let approval = commit.approval_id.as_deref().and_then(|id| {
            state
                .tool_approval(id)
                .map(|record| (id.to_string(), record.status))
        });
        let screening = match super::asset_security::screen_asset_push(
            &security,
            super::asset_security::AssetPushScreeningRequest {
                asset_id: &id,
                tenant_id: &tenant_id,
                asset_type,
                content_type: &content_type,
                content: verified.screened_content(),
                content_sha256: &actual_sha256,
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
                // Fail closed on BOTH shapes. The streamed path has already
                // written the final candidate (the copy is fused with the
                // verification pass), so a screening rejection must reclaim it
                // too -- otherwise a rejected large object would leave full-size
                // bytes in the bucket until the lifecycle GC. Nothing references
                // it, so the delete is unconditionally safe here.
                if verified.final_object_written() {
                    let _ = best_effort_delete(&bucket, &final_key).await;
                }
                let _ = best_effort_delete(&bucket, &staging_key).await;
                state.record_asset_presign_outcome(
                    crate::state::AssetPresignOutcome::CommitRejected,
                );
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "rejected_commit",
                    format!(
                        "asset {id} upload {} failed trust screening ({}): {}",
                        commit.upload_id, rejection.code, rejection.message
                    ),
                ));
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

        // #371: the tenant asset-storage quota is NO LONGER admitted here with a
        // separate read (`asset_quota_status`) before the publish. That
        // read-then-write gap let two commits for two DIFFERENT asset ids both
        // observe the same remaining capacity, both pass, and jointly overshoot
        // the quota. Admission is now folded into the publication mutation below
        // (`create_asset_within_quota`), so the quota reservation and the row
        // insert share one conditional statement. The commit-time quota rejection
        // (#368) is unchanged in shape -- it is just now atomic with publication.
        let now = now_unix_seconds();
        // The buffered path still owes the final PUT; the streamed path already
        // wrote it from the same pass that verified it.
        // `budget` is bound (not `..`-ed away) so the #529 admission permit
        // lives until the bytes have been handed to the final PUT -- the whole
        // window in which they are resident.
        if let VerifiedCommit::Buffered { bytes, budget, .. } = verified {
            let _budget = budget;
            if let Err(error) = bucket
                .put_object_owned(&final_key, bytes, &content_type)
                .await
            {
                // A transport failure does not prove the object PUT failed before
                // commit. Preserve both candidates for a retry or the grace-based
                // orphan reconciler instead of deleting possibly-written bytes.
                tracing::warn!(
                    request_id = %ctx.request_id,
                    asset_id = %id,
                    upload_id = %commit.upload_id,
                    staging_key = %staging_key,
                    final_key = %final_key,
                    error = %error,
                    "private asset object PUT failed with an unknown object outcome; preserving candidates"
                );
                // Honesty fix (#259 review): the bucket error's Display embeds
                // the request URL, so returning it verbatim published the
                // internal final key and the bucket endpoint in a 503 body.
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "asset_bucket_unavailable",
                    BUCKET_TRANSPORT_ERROR_MESSAGE,
                    &ctx.request_id,
                )
                .await;
            }
        }

        // Publish with a create-only repository primitive. A normal upsert is
        // correct for yank/channel mutations but would let concurrent commits
        // replace the immutable version's final object reference.
        let asset = StoredAsset {
            id: id.clone(),
            tenant_id: tenant_id.clone(),
            project_id: auth.project_id.clone(),
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            content_type: content_type.clone(),
            content_hash: actual_sha256,
            size_bytes: actual_size,
            content: Vec::new(),
            storage_uri: Some(final_key.clone()),
            variant: String::new(),
            yanked: false,
            // #366: persist the same screening verdict the inline path persists,
            // so a pending/quarantined presigned commit is durably withheld.
            visibility: screening.visibility(),
            created_at_unix: now,
            updated_at_unix: now,
        };
        match state
            .create_asset_within_quota(
                asset.clone(),
                auth.effective_quota.asset_storage_quota_bytes,
            )
            .await
        {
            Ok(AssetQuotaAdmission::OverQuota {
                used_bytes: _,
                attempted_bytes: _,
                quota_bytes,
            }) => {
                // #371/#368: quota is a commit-time verification failure, now
                // decided ATOMICALLY with publication -- nothing was reserved or
                // published, so the final candidate is provably unreferenced and
                // is reclaimed here; the staging object is reclaimed by
                // reject_staging_object. Same typed rejection shape as before.
                state.record_asset_presign_outcome(
                    crate::state::AssetPresignOutcome::CommitRejected,
                );
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "rejected_commit",
                    format!(
                        "asset {id} upload {} rejected at commit: {actual_size} bytes would exceed the tenant's {quota_bytes}-byte asset storage quota",
                        commit.upload_id
                    ),
                ));
                let _ = best_effort_delete(&bucket, &final_key).await;
                self.reject_staging_object(
                    session,
                    ctx,
                    &bucket,
                    &staging_key,
                    "asset_storage_quota_exceeded",
                    format!(
                        "committing this asset would exceed the tenant's {quota_bytes}-byte asset storage quota"
                    ),
                )
                .await
            }
            Ok(AssetQuotaAdmission::Admitted) => {
                // #366: the committed audit event carries the full trust
                // evidence -- scan/signature/approval outcome + verification
                // manifest -- linked to the asset id, tenant, and request id,
                // exactly as the inline push event does.
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "asset.push",
                    &id,
                    "committed",
                    format!(
                        "asset {id} committed via presigned upload {} ({actual_size} bytes); {}; manifest={}",
                        commit.upload_id,
                        screening.audit_detail(),
                        screening.manifest_json(),
                    ),
                ));
                let _ = best_effort_delete(&bucket, &staging_key).await;
                let body = AssetMutationResponse {
                    object: "asset",
                    asset: asset_summary(&asset),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(AssetQuotaAdmission::AlreadyExists) => {
                let winner = match state.get_asset(&id).await {
                    Ok(Some(winner)) => winner,
                    Ok(None) => {
                        let _ = best_effort_delete(&bucket, &final_key).await;
                        let _ = best_effort_delete(&bucket, &staging_key).await;
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            "the conflicting asset disappeared before it could be reconciled",
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) => {
                        // The staging object can never be a durable asset
                        // reference. Preserve the final candidate because an
                        // unreadable winner could theoretically reference it.
                        let _ = best_effort_delete(&bucket, &staging_key).await;
                        tracing::warn!(
                            request_id = %ctx.request_id,
                            asset_id = %id,
                            upload_id = %commit.upload_id,
                            final_key = %final_key,
                            error = %error,
                            "failed to read the winner after an immutable asset create conflict"
                        );
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
                let _ = best_effort_delete(&bucket, &staging_key).await;
                if winner.storage_uri.as_deref() != Some(final_key.as_str()) {
                    let _ = best_effort_delete(&bucket, &final_key).await;
                }
                if existing_asset_matches_commit(
                    &winner,
                    &id,
                    &commit.upload_id,
                    commit.size_bytes,
                    &expected_sha256,
                    &content_type,
                ) {
                    let body = AssetMutationResponse {
                        object: "asset",
                        asset: asset_summary(&winner),
                    };
                    write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                } else {
                    write_asset_version_immutable(session, ctx, asset_type, name, version).await
                }
            }
            Err(error) => {
                match asset_create_failure_disposition(&error) {
                    AssetCreateFailureDisposition::OutcomeUnknown => {
                        // The transaction may have committed even though its
                        // result was lost. Preserve every candidate until a
                        // same-upload retry or grace-based reconciliation.
                        tracing::warn!(
                            request_id = %ctx.request_id,
                            asset_id = %id,
                            upload_id = %commit.upload_id,
                            staging_key = %staging_key,
                            final_key = %final_key,
                            error = %error,
                            "immutable asset create returned an unknown commit outcome; preserving objects"
                        );
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "asset.push",
                            &id,
                            "outcome_unknown",
                            format!(
                                "asset {id} upload {} has an unknown durable create outcome; staging and final candidates were preserved",
                                commit.upload_id
                            ),
                        ));
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "asset_commit_outcome_unknown",
                            "asset commit outcome is unknown; retry the same upload_id before cleanup",
                            &ctx.request_id,
                        )
                        .await
                    }
                    AssetCreateFailureDisposition::DefinitelyNotPublished => {
                        // Every error before the commit fence is a definitive
                        // non-publication. Remove only the private final copy;
                        // staging remains available for the same-upload retry.
                        let _ = best_effort_delete(&bucket, &final_key).await;
                        tracing::warn!(
                            request_id = %ctx.request_id,
                            asset_id = %id,
                            upload_id = %commit.upload_id,
                            staging_key = %staging_key,
                            final_key = %final_key,
                            error = %error,
                            "immutable asset create failed before transaction commit"
                        );
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
    }

    /// #368 abort/cancel surface for an intent that will never be committed.
    ///
    /// Two jobs, deliberately in one endpoint because they share the same
    /// server-derived staging key:
    ///
    /// 1. **Reclaim now.** If a staging object exists, deleting it is
    ///    *attempted* here, so a client that knows it failed does not leave
    ///    bytes occupying bucket capacity until the lifecycle GC's next sweep.
    ///    The attempt can fail, and then it says so: `staging_object_removed`
    ///    comes from the DELETE's own result, the response carries the
    ///    tri-state `staging_reclamation`, and a refused delete is audited
    ///    `aborted_reclaim_failed` with its own counter. Reporting the HEAD
    ///    result instead would tell a tenant its quota was freed while the
    ///    bytes sat in the bucket -- the exact class of dishonest output this
    ///    endpoint exists to remove.
    /// 2. **Give the bucket-rejection class a surface.** A client whose direct
    ///    PUT was refused (the 403 the SigV4 size/checksum binding produces)
    ///    can say so, and the gateway applies a negative consistency check
    ///    against the staging key before recording it. A `bucket_rejected`
    ///    report that the gateway contradicts -- bytes ARE staged, so the
    ///    bucket accepted the PUT -- is recorded as an `aborted`, never as a
    ///    bucket rejection.
    ///
    /// The residual limit is stated rather than papered over: `rejected_bucket`
    /// is **caller-asserted** with a server-side consistency check, not an
    /// independent observation, and must not be read as a security signal on
    /// its own. Absence under the staging key is the same ambiguity the commit
    /// path refuses to call a bucket rejection (it audits `staging_missing`),
    /// so any caller with `assets.write` can register an intent, upload
    /// nothing, and abort with `bucket_rejected` to mint one. The gateway is
    /// not in the direct PUT's path; a client that is simply refused and walks
    /// away contributes at most a `staging_missing` at commit.
    async fn handle_asset_upload_abort(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some((auth, tenant_id)) = self
            .authorize_asset(session, ctx, headers, "assets.write", true)
            .await?
        else {
            return Ok(());
        };

        let abort: PresignAbortRequest = match self.read_control_body(session, ctx).await? {
            Ok(Some(abort)) => abort,
            Ok(None) => return Ok(()),
            Err(()) => return Ok(()),
        };
        if abort.size_bytes == 0 || !is_hex_sha256(&abort.sha256) || !is_upload_id(&abort.upload_id)
        {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_abort",
                "abort requires a valid upload_id, non-zero size_bytes, and 64-char hex sha256",
                &ctx.request_id,
            )
            .await;
        }
        let reason = AbortReason::parse(abort.reason.as_deref());
        let expected_sha256 = abort.sha256.to_ascii_lowercase();
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
        let staging_key =
            staging_object_key(&id, &abort.upload_id, abort.size_bytes, &expected_sha256);

        // A published version is immutable: aborting its upload must not be a
        // back door to deleting anything the commit already promoted.
        match state.get_asset(&id).await {
            Ok(Some(existing)) => {
                if existing_asset_uses_upload(&existing, &id, &abort.upload_id) {
                    return write_json_error(
                        session,
                        StatusCode::CONFLICT,
                        "asset_upload_already_committed",
                        format!(
                            "upload {} for {asset_type}/{name}/{version} is already committed and cannot be aborted",
                            abort.upload_id
                        ),
                        &ctx.request_id,
                    )
                    .await;
                }
            }
            Ok(None) => {}
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
        }

        let Some(bucket) = state.asset_bucket_client() else {
            return write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "asset_bucket_unavailable",
                "the presigned large-file path requires an [asset_bucket] to be configured",
                &ctx.request_id,
            )
            .await;
        };

        // The corroboration step. A HEAD transport failure is NOT treated as
        // "nothing staged" -- an unknown bucket state must never be laundered
        // into evidence of a bucket rejection, so it fails the request instead.
        let staged = match bucket.head_object(&staging_key).await {
            Ok(staged) => staged.is_some(),
            Err(error) => {
                // Generic body, detailed log: the bucket error embeds the
                // request URL, i.e. the internal staging key + endpoint.
                tracing::warn!(
                    request_id = %ctx.request_id,
                    asset_id = %id,
                    upload_id = %abort.upload_id,
                    staging_key = %staging_key,
                    error = %error,
                    "failed to corroborate an abort against the staging object"
                );
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "asset_bucket_unavailable",
                    BUCKET_TRANSPORT_ERROR_MESSAGE,
                    &ctx.request_id,
                )
                .await;
            }
        };
        // The reclamation is reported from the DELETE's own result, never from
        // the HEAD that preceded it. `best_effort_delete` swallows bucket
        // errors into a warn! so the abort still answers; what it must not do
        // is let the response claim bytes were reclaimed when the bucket
        // refused to remove them.
        let reclamation = if staged {
            if best_effort_delete(&bucket, &staging_key).await {
                StagingReclamation::Removed
            } else {
                StagingReclamation::RemovalFailed
            }
        } else {
            StagingReclamation::NotStaged
        };

        let record = classify_abort(reason, reclamation);
        let staging_state = match reclamation {
            StagingReclamation::NotStaged => "no staging object existed",
            StagingReclamation::Removed => "its staging object was reclaimed",
            StagingReclamation::RemovalFailed => {
                "its staging object could NOT be deleted and still occupies bucket capacity until the lifecycle GC collects it"
            }
        };
        let claim = match (reason, reclamation) {
            (AbortReason::BucketRejected, StagingReclamation::NotStaged) => {
                "was reported rejected by the bucket; the report is consistent with the gateway finding nothing under its staging key"
            }
            (AbortReason::BucketRejected, _) => {
                "claimed a bucket rejection but its staging object existed, so the claim is contradicted and recorded as an abort instead"
            }
            (AbortReason::Abandoned, _) => "was abandoned by the client",
        };
        let detail = format!(
            "asset {id} upload {} {claim}; {staging_state}",
            abort.upload_id
        );
        for metric in record.metrics {
            state.record_asset_presign_outcome(*metric);
        }
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "asset.presign_upload_abort",
            &id,
            record.outcome,
            detail,
        ));

        let body = PresignAbortResponse {
            object: "asset_upload_abort",
            upload_id: abort.upload_id,
            staging_object_removed: reclamation.removed(),
            staging_reclamation: reclamation.as_str(),
            outcome: record.outcome,
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    async fn handle_asset_download_url(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some((auth, tenant_id)) = self
            .authorize_asset(session, ctx, headers, "assets.read", false)
            .await?
        else {
            return Ok(());
        };
        let id = stored_asset_id(&tenant_id, asset_type, name, version);
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

        // #366: a pending/quarantined asset is withheld from the presigned
        // download path exactly as it is from the inline pull path -- the
        // persisted screening state gates both. Report the same 404 a missing
        // asset gets so an unproven object is indistinguishable from absent.
        if !asset.is_downloadable() {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "asset_not_found",
                format!("no asset at {asset_type}/{name}/{version}"),
                &ctx.request_id,
            )
            .await;
        }

        // The private-bucket read path (issue #259): a presigned GET is only
        // meaningful for a bucket-backed object. Inline-stored assets have
        // no bucket object; the caller fetches those via the inline
        // `GET /v1/assets/{asset_type}/{name}/{version}` endpoint.
        let Some(storage_uri) = asset.storage_uri.as_deref() else {
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "asset_not_bucket_backed",
                "this asset is stored inline; fetch it via GET /v1/assets/{asset_type}/{name}/{version}",
                &ctx.request_id,
            )
            .await;
        };
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

        let ttl = state.asset_presign_ttl_secs();
        let download_url = match bucket.presign_get(storage_uri, ttl, now_unix_seconds_u64()) {
            Ok(url) => url,
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
        };

        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "asset.presign_download",
            &id,
            "issued",
            format!("issued a {ttl}s presigned download URL for asset {id}"),
        ));

        // #262 egress metering: the presigned direct path bills at URL issuance
        // using the object size, since the bytes leave the bucket directly and
        // never traverse the gateway hot path.
        super::asset_egress::record_asset_egress(
            &state,
            ctx,
            &auth,
            asset_type,
            name,
            version,
            asset.size_bytes,
        )
        .await;

        // sha256 is returned alongside the URL so the agent can verify the
        // bytes it fetched directly from the bucket.
        let body = PresignDownloadResponse {
            object: "asset_download_url",
            download_url,
            method: "GET",
            expires_in_seconds: ttl,
            sha256: asset.content_hash,
            size_bytes: asset.size_bytes,
            content_type: asset.content_type,
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    /// Attempts to delete the rejected staging object and writes a 422 -- the
    /// single exit used whenever a committed object fails size, sha256, built-in
    /// content, or quota validation. The rejected object never becomes a visible
    /// asset even if best-effort bucket cleanup fails.
    async fn reject_staging_object(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        bucket: &dyn super::asset_bucket::AssetObjectStore,
        staging_key: &str,
        code: &'static str,
        message: String,
    ) -> PingoraResult<()> {
        if let Err(error) = bucket.delete_object(staging_key).await {
            tracing::warn!(
                staging_key = %staging_key,
                error = %error,
                "failed to delete a rejected presigned-upload object; it may be orphaned in the bucket"
            );
        }
        write_json_error(
            session,
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message,
            &ctx.request_id,
        )
        .await
    }

    /// Reuses the exact virtual-key auth + tenant scoping (+ optional
    /// StoredPlan/role asset-hosting entitlement) the inline handlers use.
    /// Returns `None` after writing the error response, so the caller
    /// simply `return Ok(())`s.
    async fn authorize_asset(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        scope: &'static str,
        require_hosting: bool,
    ) -> PingoraResult<Option<(AuthContext, String)>> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, scope, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(None);
            }
        };
        let Some(tenant_id) = auth.organization_id.clone() else {
            write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "tenant_required",
                "assets require a tenant-attributed API key",
                &ctx.request_id,
            )
            .await?;
            return Ok(None);
        };
        if require_hosting {
            // Same dual entitlement as handle_asset_push: the tenant's
            // StoredPlan boolean OR a bound role granting `assets.host`.
            let plan = state.resolve_tenant_plan(&tenant_id).await.ok().flatten();
            let plan_grants = plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled);
            let role_grants = state.tenant_has_permission(&tenant_id, "assets.host").await;
            if !plan_grants && !role_grants {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "asset_hosting_disabled",
                    "the tenant's plan does not enable asset hosting and no bound role grants \
                     the assets.host permission",
                    &ctx.request_id,
                )
                .await?;
                return Ok(None);
            }
        }
        Ok(Some((auth, tenant_id)))
    }

    /// Cumulative tenant-quota check mirroring handle_asset_push: the
    /// candidate object's bytes plus everything the tenant already stores
    /// (excluding a same-id object being replaced) must fit under
    /// `asset_storage_quota_bytes`. `None` quota means unlimited.
    async fn asset_quota_status(
        &self,
        state: &crate::state::AppState,
        tenant_id: &str,
        id: &str,
        quota: Option<u64>,
        additional_bytes: u64,
    ) -> QuotaStatus {
        let Some(quota) = quota else {
            return QuotaStatus::Ok;
        };
        let existing_size = match state.get_asset(id).await {
            Ok(existing) => existing.map(|asset| asset.size_bytes).unwrap_or(0),
            Err(error) => return QuotaStatus::StorageError(error.to_string()),
        };
        let used_by_others = match state.tenant_asset_storage_bytes_used(tenant_id).await {
            Ok(used) => used.saturating_sub(existing_size),
            Err(error) => return QuotaStatus::StorageError(error.to_string()),
        };
        if used_by_others.saturating_add(additional_bytes) > quota {
            QuotaStatus::Exceeded(quota)
        } else {
            QuotaStatus::Ok
        }
    }

    pub(super) async fn read_control_body<T: for<'de> Deserialize<'de>>(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
    ) -> PingoraResult<Result<Option<T>, ()>> {
        let body = match read_request_body(
            session,
            self.state.current().limits().asset_control_body_max_bytes(),
        )
        .await?
        {
            Ok(body) => body,
            Err(limit) => {
                write_json_error(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "control body exceeds the maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await?;
                return Ok(Err(()));
            }
        };
        match serde_json::from_slice::<T>(body.as_ref()) {
            Ok(value) => Ok(Ok(Some(value))),
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    format!("request body is not valid JSON: {error}"),
                    &ctx.request_id,
                )
                .await?;
                Ok(Ok(None))
            }
        }
    }
}

/// #368: how one abort is recorded -- its audit/response outcome plus every
/// metric class it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbortRecord {
    outcome: &'static str,
    /// More than one when the abort both released an intent and failed to
    /// reclaim its bytes: the release is still an abort, and the failure is
    /// separately alertable.
    metrics: &'static [crate::state::AssetPresignOutcome],
}

/// #368: the audit outcome + metric classes an abort is recorded under.
///
/// The whole decision is here, in one pure function, because it is the point
/// where a client's *claim* becomes the gateway's *evidence*. The only way a
/// `bucket_rejected` claim survives is if the gateway's own staging lookup
/// agrees with it; a claim contradicted by a staged object is downgraded to a
/// plain abort. There is deliberately no path that upgrades an unknown or
/// absent reason into a bucket rejection.
///
/// A reclamation the bucket refused outranks the plain-abort label, because
/// the operator-visible consequence (bytes still held) is the more important
/// fact and must be filterable by audit `outcome`, not buried in prose. It can
/// only ever coincide with a staged object, so it never suppresses a
/// corroborated `rejected_bucket` -- that class requires the opposite.
fn classify_abort(reason: AbortReason, reclamation: StagingReclamation) -> AbortRecord {
    match (reason, reclamation) {
        (AbortReason::BucketRejected, StagingReclamation::NotStaged) => AbortRecord {
            outcome: "rejected_bucket",
            metrics: &[crate::state::AssetPresignOutcome::BucketRejected],
        },
        (_, StagingReclamation::RemovalFailed) => AbortRecord {
            outcome: "aborted_reclaim_failed",
            metrics: &[
                crate::state::AssetPresignOutcome::Aborted,
                crate::state::AssetPresignOutcome::AbortReclaimFailed,
            ],
        },
        _ => AbortRecord {
            outcome: "aborted",
            metrics: &[crate::state::AssetPresignOutcome::Aborted],
        },
    }
}

/// #368: the only upload protocol the presigned path issues. Named (not a
/// `multipart: false` boolean) so multipart support, if it is ever justified,
/// arrives as an additive enum value in the published contract.
const SINGLE_PUT_UPLOAD_PROTOCOL: &str = "single_put";

/// The single message a caller ever sees for an object-bucket transport
/// failure (issue #259 review finding 4).
///
/// Bucket errors used to be serialized verbatim via `error.to_string()`.
/// `reqwest::Error`'s `Display` embeds the request URL, so a 503 body could
/// carry the internal `.ferrogate/objects/<digest>/obj_<rand>` final key and
/// the bucket endpoint straight back to the client -- contradicting the
/// private-bucket runbook's promise that the final key is never serialized in
/// a response, and handing an attacker the storage topology for free. The
/// diagnostic detail is logged with the request id instead, where the operator
/// (and only the operator) can correlate it.
const BUCKET_TRANSPORT_ERROR_MESSAGE: &str =
    "the asset object bucket is unavailable; retry the same upload_id (see the gateway logs for \
     the correlated request_id)";

/// A staged object that passed commit verification, in the shape the rest of
/// the publish flow needs -- which differs by how it was verified.
enum VerifiedCommit {
    /// Small enough for the gateway's in-memory budget: the exact verified
    /// bytes are held, and the final PUT has NOT happened yet.
    Buffered {
        bytes: Vec<u8>,
        actual_size: u64,
        sha256: String,
        /// The aggregate-budget permit (issue #529), carried so it is released
        /// when the bytes are consumed by the final PUT rather than when the
        /// verification returned.
        budget: super::asset_admission::BufferPermit,
    },
    /// Above the budget: verified and copied to the final key in one bounded
    /// pass, so the gateway holds facts about the object rather than the object.
    Streamed {
        actual_size: u64,
        sha256: String,
        eicar_found: bool,
    },
}

impl VerifiedCommit {
    fn actual_size(&self) -> u64 {
        match self {
            Self::Buffered { actual_size, .. } | Self::Streamed { actual_size, .. } => *actual_size,
        }
    }

    fn sha256(&self) -> &str {
        match self {
            Self::Buffered { sha256, .. } | Self::Streamed { sha256, .. } => sha256,
        }
    }

    /// Whether the private final object already exists in the bucket. Decides
    /// whether a later rejection has a final candidate to reclaim.
    fn final_object_written(&self) -> bool {
        matches!(self, Self::Streamed { .. })
    }

    fn screened_content(&self) -> super::asset_security::ScreenedContent<'_> {
        match self {
            Self::Buffered { bytes, .. } => super::asset_security::ScreenedContent::Buffered(bytes),
            Self::Streamed {
                actual_size,
                eicar_found,
                ..
            } => super::asset_security::ScreenedContent::Streamed {
                size_bytes: *actual_size,
                eicar_found: *eicar_found,
            },
        }
    }
}

enum QuotaStatus {
    Ok,
    Exceeded(u64),
    StorageError(String),
}

/// A staging object that failed size, sha256, or built-in content validation;
/// best-effort bucket deletion has already been attempted.
struct CommitRejection {
    code: &'static str,
    message: String,
}

enum CommitVerification {
    /// The object fit the gateway's in-memory budget: the verified bytes are
    /// in hand and the caller still owes the final PUT.
    Verified {
        bytes: Vec<u8>,
        sha256: String,
        /// The aggregate-budget permit these bytes were admitted under (issue
        /// #529). Held, not dropped, until the final PUT has consumed them.
        budget: super::asset_admission::BufferPermit,
    },
    /// The object fit the per-operation budget, but the gateway's aggregate
    /// buffering budget was committed for the whole bounded wait (issue #529).
    /// Nothing was fetched and staging is untouched, so the same `upload_id`
    /// retries cleanly.
    Overloaded {
        requested_bytes: u64,
        budget_bytes: u64,
        waited_ms: u64,
    },
    /// The object exceeded the in-memory budget: it was verified AND copied to
    /// the final key in a single bounded pass, so the caller owes no PUT. The
    /// gateway never held it, which is why the screening evidence travels here
    /// as facts rather than as bytes.
    VerifiedStreamed {
        size_bytes: u64,
        sha256: String,
        /// Always `false` on this variant (a match is rejected before it is
        /// built); carried so the trust screening is handed real evidence from
        /// the pass rather than a hardcoded assumption.
        eicar_found: bool,
    },
    /// No object was uploaded to the presigned URL (bucket 404).
    NotUploaded,
    /// The object existed but failed validation; cleanup has been attempted.
    Rejected(CommitRejection),
}

enum CommitWinner {
    Missing,
    Matching(Box<StoredAsset>),
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetCreateFailureDisposition {
    DefinitelyNotPublished,
    OutcomeUnknown,
}

fn asset_create_failure_disposition(error: &StorageError) -> AssetCreateFailureDisposition {
    if matches!(error, StorageError::OperationCommitOutcomeUnknown { .. }) {
        AssetCreateFailureDisposition::OutcomeUnknown
    } else {
        AssetCreateFailureDisposition::DefinitelyNotPublished
    }
}

async fn reconcile_commit_winner(
    state: &crate::state::AppState,
    asset_id: &str,
    upload_id: &str,
    expected_size: u64,
    expected_sha256: &str,
    requested_content_type: &str,
) -> anyhow::Result<CommitWinner> {
    let Some(existing) = state.get_asset(asset_id).await? else {
        return Ok(CommitWinner::Missing);
    };
    if existing_asset_matches_commit(
        &existing,
        asset_id,
        upload_id,
        expected_size,
        expected_sha256,
        requested_content_type,
    ) {
        Ok(CommitWinner::Matching(Box::new(existing)))
    } else {
        Ok(CommitWinner::Conflict)
    }
}

fn existing_asset_matches_commit(
    asset: &StoredAsset,
    asset_id: &str,
    upload_id: &str,
    expected_size: u64,
    expected_sha256: &str,
    requested_content_type: &str,
) -> bool {
    asset.id == asset_id
        && existing_asset_uses_upload(asset, asset_id, upload_id)
        && asset.size_bytes == expected_size
        && asset.content_hash == expected_sha256
        && asset.content_type == requested_content_type
}

fn existing_asset_uses_upload(asset: &StoredAsset, asset_id: &str, upload_id: &str) -> bool {
    asset
        .storage_uri
        .as_deref()
        .is_some_and(|key| key.starts_with(&final_object_prefix(asset_id, upload_id)))
}

async fn write_asset_version_immutable(
    session: &mut Session,
    ctx: &super::ProxyContext,
    asset_type: &str,
    name: &str,
    version: &str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::CONFLICT,
        "asset_version_immutable",
        format!(
            "{asset_type}/{name}/{version} already exists and is immutable; \
             delete it before republishing"
        ),
        &ctx.request_id,
    )
    .await
}

/// Everything the commit-time verification needs to decide about one staged
/// object. Grouped into a struct because the decision has two independent
/// dimensions -- what the intent registered, and what the gateway is willing
/// to hold in memory -- and threading eight positional arguments through the
/// call is how one of them ends up silently transposed.
struct CommitVerificationRequest<'a> {
    /// The server-derived key the client's direct PUT targeted.
    staging_key: &'a str,
    /// The private immutable key verified bytes are copied to. Used only by
    /// the streaming path, which fuses the copy with the verification; the
    /// buffered path leaves the copy to the caller.
    final_key: &'a str,
    expected_size: u64,
    expected_sha256: &'a str,
    asset_type: &'a str,
    content_type: &'a str,
    /// The plan/quota-derived per-object ceiling (issue #259).
    max_object_bytes: u64,
    /// The largest object the gateway will hold in memory
    /// (`[asset_bucket].max_gateway_buffer_bytes`). At or below it, the
    /// object is buffered and screened at full fidelity; above it, it is
    /// verified and copied in a single bounded-memory pass.
    buffer_limit: u64,
    /// The process-wide aggregate buffering budget (issue #529).
    ///
    /// Only the **buffered** leg draws on it, and it draws exactly what it will
    /// hold. The streamed leg is deliberately not admitted: its resident cost
    /// is one HTTP chunk regardless of object size, so charging it the object's
    /// size would reserve memory it never uses and would let large commits
    /// crowd out the reads that do buffer. This is the "confirm the streaming
    /// commit path does not consume the buffering budget" decision, made here
    /// rather than left implicit -- see
    /// `the_streaming_commit_leg_consumes_no_buffering_budget`.
    admission: &'a super::asset_admission::GatewayBufferBudget,
}

/// Verifies a presigned-uploaded staging object against its registered intent
/// and the built-in type/EICAR/manifest content checks, then hands the caller
/// what it needs to publish.
///
/// Two paths, chosen by [`CommitVerificationRequest::buffer_limit`]:
///
/// - **Buffered** (object at or below the limit) -- the object is fetched
///   once, one-shot hashed, and content-validated. Unchanged from before
///   issue #259's streaming work, and still the path that gives whole-file
///   signature verification and out-of-process malware scanning their bytes.
/// - **Streamed** (object above the limit) -- the object is read in chunks
///   that feed an incremental SHA-256 and an incremental content screen and
///   are forwarded straight into the final PUT, so peak resident memory is one
///   HTTP chunk regardless of object size. This is what makes a 100 MB (or 5
///   GiB) commit safe: before it, peak RSS per commit was the object size,
///   with no cap on concurrent commits.
///
/// Fails closed identically on both paths: on any size, sha256,
/// per-object-ceiling, or content violation it attempts to delete the orphaned
/// staging object -- plus, on the streamed path, the final candidate it had
/// already written -- before returning [`CommitVerification::Rejected`]. The
/// final key is a fresh 128-bit-random name nothing can reference until the
/// `stored_assets` row is created, so unverified bytes are never reachable.
///
/// The outer `Err` is reserved for bucket-infrastructure failures (HEAD/GET/PUT
/// transport errors) which the caller maps to 503; validation failures are the
/// inner `Rejected` variant (mapped to 422).
async fn verify_committed_object(
    bucket: &dyn super::asset_bucket::AssetObjectStore,
    request: &CommitVerificationRequest<'_>,
) -> anyhow::Result<CommitVerification> {
    // 1. HEAD gates the object's size before we transfer a single byte.
    let Some(actual_size) = bucket.head_object(request.staging_key).await? else {
        return Ok(CommitVerification::NotUploaded);
    };
    if actual_size != request.expected_size || actual_size > request.max_object_bytes {
        let _ = best_effort_delete(bucket, request.staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_size_mismatch",
            message: format!(
                "committed object size {actual_size} does not match the registered {} bytes",
                request.expected_size
            ),
        }));
    }

    if actual_size > request.buffer_limit {
        // The streamed leg holds one chunk, so it takes no admission permit at
        // all (issue #529). Returning here, above the `admit` call below, is
        // that decision in code.
        return verify_and_copy_committed_object(bucket, request).await;
    }

    // 2a. Admit the buffer against the gateway's aggregate budget (issue #529)
    // before asking for the bytes. The permit is held for as long as the
    // verified buffer is -- it travels out on `CommitVerification::Verified`
    // and is only dropped after the final PUT has consumed the bytes.
    let budget = match request.admission.admit(actual_size).await {
        Ok(permit) => permit,
        Err(refusal) => {
            // Staging is left INTACT: this commit never started, and the
            // client's retry with the same upload_id must still find its
            // object. Deleting here would turn a load shed into data loss.
            return Ok(CommitVerification::Overloaded {
                requested_bytes: refusal.requested_bytes,
                budget_bytes: refusal.budget_bytes,
                waited_ms: refusal.waited_ms,
            });
        }
    };

    // 2b. Fetch to verify sha256 and run built-in content checks on real bytes.
    // The branch above already established `actual_size <= buffer_limit`; the
    // HEAD-confirmed size is handed to the transport too (issue #259 round 2,
    // tightened by #529 from the budget to the size actually admitted) so a
    // bucket whose GET body disagrees with its own HEAD cannot buffer past what
    // this commit was charged for.
    let Some(content) = bucket
        .get_object_if_present(request.staging_key, actual_size)
        .await?
    else {
        return Ok(CommitVerification::NotUploaded);
    };
    let actual_sha256 = sha256_hex(&content);
    if actual_sha256 != request.expected_sha256 || content.len() as u64 != request.expected_size {
        let _ = best_effort_delete(bucket, request.staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_hash_mismatch",
            message: "committed object sha256/size does not match the registered intent"
                .to_string(),
        }));
    }
    if let Err(message) = super::asset_security::validate_asset_content(
        request.asset_type,
        request.content_type,
        &content,
    ) {
        let _ = best_effort_delete(bucket, request.staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_rejected",
            message,
        }));
    }

    Ok(CommitVerification::Verified {
        bytes: content,
        sha256: actual_sha256,
        budget,
    })
}

/// The bounded-memory half of [`verify_committed_object`]: one pass that
/// hashes, screens, and copies the staged object to its final key without ever
/// holding it.
///
/// The copy runs *before* the verdict is known, which is safe and deliberate:
/// the destination is a fresh `obj_<128-bit-random>` under an intent-derived
/// prefix that no published row references, so a rejection simply deletes it.
/// The alternative -- a verify pass followed by a copy pass -- would double the
/// bucket egress for every large object and still not hold the bytes.
async fn verify_and_copy_committed_object(
    bucket: &dyn super::asset_bucket::AssetObjectStore,
    request: &CommitVerificationRequest<'_>,
) -> anyhow::Result<CommitVerification> {
    let copy = super::asset_stream::copy_object_with_incremental_screen(
        bucket,
        request.staging_key,
        request.final_key,
        request.expected_size,
        request.expected_sha256,
        request.content_type,
    )
    .await?;
    let verdict = match copy {
        super::asset_stream::StreamedCopy::SourceMissing => {
            return Ok(CommitVerification::NotUploaded);
        }
        super::asset_stream::StreamedCopy::RejectedByPayloadMismatch(verdict)
        | super::asset_stream::StreamedCopy::Copied(verdict) => verdict,
    };
    if !verdict.matches(request.expected_size, request.expected_sha256) {
        let _ = best_effort_delete(bucket, request.final_key).await;
        let _ = best_effort_delete(bucket, request.staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_hash_mismatch",
            message: "committed object sha256/size does not match the registered intent"
                .to_string(),
        }));
    }
    if let Err(message) = super::asset_security::validate_streamed_asset_content(
        request.asset_type,
        request.content_type,
        verdict.eicar_found,
    ) {
        let _ = best_effort_delete(bucket, request.final_key).await;
        let _ = best_effort_delete(bucket, request.staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_rejected",
            message,
        }));
    }
    Ok(CommitVerification::VerifiedStreamed {
        size_bytes: verdict.size_bytes,
        sha256: verdict.sha256,
        eicar_found: verdict.eicar_found,
    })
}

/// Deletes an object without failing the caller's request, returning whether
/// the bucket actually accepted the delete. Callers that *report* the
/// reclamation to a client or an operator (the #368 abort surface) MUST use
/// the return value: a warn-logged failure rendered as a successful delete is
/// how a tenant is told bytes were freed that are still consuming its quota.
#[must_use]
async fn best_effort_delete(
    bucket: &dyn super::asset_bucket::AssetObjectStore,
    object_key: &str,
) -> bool {
    match bucket.delete_object(object_key).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                object_key = %object_key,
                error = %error,
                "failed to delete a presigned-upload object; it may be orphaned in the bucket"
            );
            false
        }
    }
}

fn new_upload_id() -> anyhow::Result<String> {
    Ok(format!("upl_{}", random_hex_128()?))
}

fn new_final_object_key(asset_id: &str, upload_id: &str) -> anyhow::Result<String> {
    Ok(format!(
        "{}obj_{}",
        final_object_prefix(asset_id, upload_id),
        random_hex_128()?
    ))
}

fn staging_object_key(asset_id: &str, upload_id: &str, size_bytes: u64, sha256: &str) -> String {
    let material =
        format!("ferrogate-asset-staging-v1\0{asset_id}\0{upload_id}\0{size_bytes}\0{sha256}");
    format!(".ferrogate/staging/{}", sha256_hex(material.as_bytes()))
}

fn final_object_prefix(asset_id: &str, upload_id: &str) -> String {
    let material = format!("ferrogate-asset-final-v1\0{asset_id}\0{upload_id}");
    format!(".ferrogate/objects/{}/", sha256_hex(material.as_bytes()))
}

fn random_hex_128() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("operating-system random source unavailable: {error}"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

fn is_upload_id(value: &str) -> bool {
    value.strip_prefix("upl_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The effective per-object upload ceiling for a tenant (issue #259): the
/// tightest of three independent bounds --
/// 1. the operator's global `[asset_bucket].presign_max_object_bytes`,
/// 2. the tenant's DEDICATED per-object ceiling
///    (`EffectiveQuota.asset_max_object_bytes`, resolved from the tenant's
///    `StoredPlan` / quota-policy), a first-class cap on individual object
///    size that is NOT the cumulative storage budget, and
/// 3. the tenant's cumulative `asset_storage_quota_bytes` (a single object can
///    never exceed the whole tenant quota).
///
/// Each of (2) and (3) is optional; a `None` bound contributes `u64::MAX`
/// (i.e. does not tighten anything), so a tenant with no dedicated per-object
/// ceiling and no cumulative quota keeps exactly the pre-#259 behavior (the
/// global ceiling alone), and a dedicated per-object ceiling can bind TIGHTER
/// than the cumulative quota independently of it.
fn effective_max_object_bytes(
    global_ceiling: u64,
    per_object_ceiling: Option<u64>,
    cumulative_quota: Option<u64>,
) -> u64 {
    global_ceiling
        .min(per_object_ceiling.unwrap_or(u64::MAX))
        .min(cumulative_quota.unwrap_or(u64::MAX))
}

/// True for a canonical 64-character lowercase-or-uppercase hex SHA-256.
fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn now_unix_seconds_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "asset_presign_test.rs"]
mod asset_presign_test;
