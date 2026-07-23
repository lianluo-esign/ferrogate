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
// objects within what S3-compatible services accept in one request), and
// orphaned staging objects remain the existing asset-lifecycle GC's job
// (`state_asset_lifecycle.rs`, audit action `asset.gc.delete`).
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
    /// clients can fail fast without a rejected round-trip. Single PUT
    /// only: multipart uploads are out of scope.
    max_object_bytes: u64,
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
            ("upload", _) | ("commit", _) => {
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
        // `[asset_bucket].presign_max_object_bytes` is further tightened to the
        // tenant's plan-derived cumulative `asset_storage_quota_bytes` when that
        // is smaller, so the per-object limit is plan/quota-driven (mirroring
        // the inline path's `inline_push_byte_limit`) rather than a single fixed
        // operator constant. A single object can never exceed the whole tenant
        // quota, and the value is echoed to the client so it can fail fast.
        let max_object_bytes = effective_max_object_bytes(
            state.asset_presign_max_object_bytes(),
            auth.effective_quota.asset_storage_quota_bytes,
        );
        if intent.size_bytes > max_object_bytes {
            // #368: outcome `rejected_intent` distinguishes this preflight
            // rejection from bucket-boundary (`rejected_bucket`) and
            // commit-time (`rejected_commit`) rejections, and from orphan
            // GC (`asset.gc.delete`).
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
                        best_effort_delete(&bucket, &staging_key).await;
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

        // Verify the staging object and retain the exact verified bytes. The
        // later private PUT uses this buffer, so a replay of the client-facing
        // staging URL cannot race a different payload into the durable object.
        let verification = verify_and_fetch_committed_object(
            &bucket,
            &staging_key,
            commit.size_bytes,
            &expected_sha256,
            asset_type,
            &content_type,
            // Same plan/quota-driven per-object ceiling the intent was checked
            // against (issue #259): the commit-time size verification tightens
            // the global ceiling to the tenant's cumulative asset-storage quota,
            // so a committed object can never exceed the whole tenant quota even
            // if a stale intent was issued under a larger prior ceiling.
            effective_max_object_bytes(
                state.asset_presign_max_object_bytes(),
                auth.effective_quota.asset_storage_quota_bytes,
            ),
        )
        .await;
        let (verified_bytes, actual_sha256) = match verification {
            Ok(CommitVerification::Verified { bytes, sha256 }) => (bytes, sha256),
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
                        best_effort_delete(&bucket, &staging_key).await;
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
                        // #368: outcome `rejected_bucket` -- no staged object
                        // exists, meaning the direct PUT never succeeded at
                        // the bucket boundary (never attempted, URL expired,
                        // or rejected by the signed size/checksum binding).
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "asset.push",
                            &id,
                            "rejected_bucket",
                            format!(
                                "asset {id} upload {} has no staged object; the direct PUT never succeeded at the bucket boundary",
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
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "asset_bucket_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Ok(CommitVerification::Verified { .. }) => unreachable!(),
                }
            }
        };
        let actual_size = verified_bytes.len() as u64;

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
                content: &verified_bytes,
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
                best_effort_delete(&bucket, &staging_key).await;
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
        if let Err(error) = bucket
            .put_object_owned(&final_key, verified_bytes, &content_type)
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
            return write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "asset_bucket_unavailable",
                error.to_string(),
                &ctx.request_id,
            )
            .await;
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
                best_effort_delete(&bucket, &final_key).await;
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
                best_effort_delete(&bucket, &staging_key).await;
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
                        best_effort_delete(&bucket, &final_key).await;
                        best_effort_delete(&bucket, &staging_key).await;
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
                        best_effort_delete(&bucket, &staging_key).await;
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
                best_effort_delete(&bucket, &staging_key).await;
                if winner.storage_uri.as_deref() != Some(final_key.as_str()) {
                    best_effort_delete(&bucket, &final_key).await;
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
                        best_effort_delete(&bucket, &final_key).await;
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
        bucket: &super::asset_bucket::AssetBucketClient,
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
        let auth = match authenticate(&state, headers, scope, &ctx.request_id) {
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
    Verified {
        bytes: Vec<u8>,
        sha256: String,
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

/// Verifies a presigned-uploaded staging object against its registered intent and
/// built-in type/EICAR/manifest content checks, fetching the bytes once (the
/// intended commit-side cost for large objects; the upload/download data path
/// itself never touches the gateway). Fails closed: on any size, sha256,
/// per-object-ceiling, or `asset_security` violation it attempts to delete the
/// orphaned object before returning [`CommitVerification::Rejected`].
///
/// The outer `Err` is reserved for bucket-infrastructure failures (HEAD/GET
/// transport errors) which the caller maps to 503; validation failures are
/// the inner `Rejected` variant (mapped to 422).
async fn verify_and_fetch_committed_object(
    bucket: &super::asset_bucket::AssetBucketClient,
    staging_key: &str,
    expected_size: u64,
    expected_sha256: &str,
    asset_type: &str,
    content_type: &str,
    max_object_bytes: u64,
) -> anyhow::Result<CommitVerification> {
    // 1. HEAD gates the object's size before we download it.
    let Some(actual_size) = bucket.head_object(staging_key).await? else {
        return Ok(CommitVerification::NotUploaded);
    };
    if actual_size != expected_size || actual_size > max_object_bytes {
        best_effort_delete(bucket, staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_size_mismatch",
            message: format!(
                "committed object size {actual_size} does not match the registered {expected_size} bytes"
            ),
        }));
    }

    // 2. Fetch to verify sha256 and run built-in content checks on real bytes.
    let Some(content) = bucket.get_object_if_present(staging_key).await? else {
        return Ok(CommitVerification::NotUploaded);
    };
    let actual_sha256 = sha256_hex(&content);
    if actual_sha256 != expected_sha256 || content.len() as u64 != expected_size {
        best_effort_delete(bucket, staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_hash_mismatch",
            message: "committed object sha256/size does not match the registered intent"
                .to_string(),
        }));
    }
    if let Err(message) =
        super::asset_security::validate_asset_content(asset_type, content_type, &content)
    {
        best_effort_delete(bucket, staging_key).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_rejected",
            message,
        }));
    }

    Ok(CommitVerification::Verified {
        bytes: content,
        sha256: actual_sha256,
    })
}

async fn best_effort_delete(bucket: &super::asset_bucket::AssetBucketClient, object_key: &str) {
    if let Err(error) = bucket.delete_object(object_key).await {
        tracing::warn!(
            object_key = %object_key,
            error = %error,
            "failed to delete a presigned-upload object; it may be orphaned in the bucket"
        );
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
/// operator's global `[asset_bucket].presign_max_object_bytes` ceiling,
/// further tightened to the tenant's plan-derived cumulative
/// `asset_storage_quota_bytes` when that quota is smaller. A single object can
/// never exceed the whole tenant quota, so folding the quota in makes the
/// per-object size limit plan/quota-driven (the quota resolves from the
/// tenant's `StoredPlan` / quota-policy) rather than a single fixed operator
/// constant -- the presigned-path analogue of the inline path's
/// `inline_push_byte_limit`. A `None` quota (unlimited storage) leaves the
/// global ceiling as the sane default.
fn effective_max_object_bytes(global_ceiling: u64, tenant_quota: Option<u64>) -> u64 {
    match tenant_quota {
        Some(quota) => global_ceiling.min(quota),
        None => global_ceiling,
    }
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
