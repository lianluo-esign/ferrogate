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
// return a short-TTL presigned PUT) -> client PUTs bytes straight to the
// bucket -> commit (gateway verifies size via HEAD and sha256 by fetching
// the committed object, re-runs the asset_security supply-chain checks
// against that object, and fails closed by deleting it on any violation
// before the `stored_assets` row -- and thus the asset -- becomes visible).
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

use ferrogate_storage::{sha256_hex, stored_asset_id, StoredAsset};

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
struct PresignUploadIntentRequest {
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct PresignCommitRequest {
    size_bytes: u64,
    sha256: String,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct PresignUploadIntentResponse {
    object: &'static str,
    key: String,
    upload_url: String,
    method: &'static str,
    expires_in_seconds: u64,
    size_bytes: u64,
    sha256: String,
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
        // before, the cumulative tenant quota.
        let max_object_bytes = state.asset_presign_max_object_bytes();
        if intent.size_bytes > max_object_bytes {
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

        let id = stored_asset_id(&tenant_id, asset_type, name, version);
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

        let ttl = state.asset_presign_ttl_secs();
        let upload_url = match bucket.presign_put(&id, ttl, now_unix_seconds_u64()) {
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
            "asset.presign_upload_intent",
            &id,
            "issued",
            format!(
                "issued a {ttl}s presigned upload URL for asset {id} ({} bytes)",
                intent.size_bytes
            ),
        ));

        let body = PresignUploadIntentResponse {
            object: "asset_upload_intent",
            key: id,
            upload_url,
            method: "PUT",
            expires_in_seconds: ttl,
            size_bytes: intent.size_bytes,
            sha256: intent.sha256,
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
        if commit.size_bytes == 0 || !is_hex_sha256(&commit.sha256) {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_commit",
                "commit requires the registered size_bytes and 64-char hex sha256",
                &ctx.request_id,
            )
            .await;
        }
        let expected_sha256 = commit.sha256.to_ascii_lowercase();
        let content_type = commit
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());

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

        let id = stored_asset_id(&tenant_id, asset_type, name, version);

        // Verify the committed object end-to-end (size via HEAD, sha256 +
        // supply-chain checks against the fetched bytes) and fail closed by
        // deleting it on any violation, all before the asset becomes
        // visible. Extracted so it is unit-testable against the mock bucket.
        let verification = match verify_and_fetch_committed_object(
            &bucket,
            &id,
            commit.size_bytes,
            &expected_sha256,
            asset_type,
            &content_type,
            state.asset_presign_max_object_bytes(),
        )
        .await
        {
            Ok(verification) => verification,
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
        let (actual_size, actual_sha256) = match verification {
            CommitVerification::Verified { size_bytes, sha256 } => (size_bytes, sha256),
            CommitVerification::NotUploaded => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "asset_not_uploaded",
                    "no object was uploaded to the presigned URL for this asset",
                    &ctx.request_id,
                )
                .await;
            }
            CommitVerification::Rejected(rejection) => {
                // The orphaned object was already deleted inside the verify
                // step (fail closed) -- just report the violation.
                return write_json_error(
                    session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    rejection.code,
                    rejection.message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        // Quota is counted at commit, when the real object exists.
        match self
            .asset_quota_status(
                &state,
                &tenant_id,
                &id,
                auth.effective_quota.asset_storage_quota_bytes,
                actual_size,
            )
            .await
        {
            QuotaStatus::Ok => {}
            QuotaStatus::Exceeded(quota) => {
                return self
                    .reject_committed_object(
                        session,
                        ctx,
                        &bucket,
                        &id,
                        "asset_storage_quota_exceeded",
                        format!(
                            "committing this asset would exceed the tenant's {quota}-byte asset storage quota"
                        ),
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

        let now = now_unix_seconds();
        let created_at_unix = state
            .get_asset(&id)
            .await
            .ok()
            .flatten()
            .map_or(now, |existing| existing.created_at_unix);

        // The bytes stay in the bucket; only a reference is persisted. The
        // `stored_assets` row is what makes the asset visible, so it is
        // written last, only after every check above passed.
        let asset = StoredAsset {
            id: id.clone(),
            tenant_id: tenant_id.clone(),
            project_id: auth.project_id.clone(),
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            content_type,
            content_hash: actual_sha256,
            size_bytes: actual_size,
            content: Vec::new(),
            storage_uri: Some(id.clone()),
            variant: String::new(),
            yanked: false,
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
                    format!("asset {id} committed via presigned upload ({actual_size} bytes)"),
                ));
                let body = AssetMutationResponse {
                    object: "asset",
                    asset: asset_summary(&asset),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                // The object is already verified/clean; a row-write failure
                // leaves it orphaned in the bucket, which delete-on-push
                // re-commit or an operator sweep reconciles -- the same
                // failure mode the inline push has on its final DB write.
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

    /// Deletes the orphaned bucket object (fail-closed) and writes a 422 --
    /// the single exit used whenever a committed object fails size, sha256,
    /// supply-chain, or quota validation, so a rejected object never lingers.
    async fn reject_committed_object(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        bucket: &super::asset_bucket::AssetBucketClient,
        id: &str,
        code: &'static str,
        message: String,
    ) -> PingoraResult<()> {
        if let Err(error) = bucket.delete_object(id).await {
            tracing::warn!(
                asset_id = %id,
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

    async fn read_control_body<T: for<'de> Deserialize<'de>>(
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

/// A committed object that failed size/sha256/supply-chain validation and
/// has already been deleted from the bucket (fail closed).
struct CommitRejection {
    code: &'static str,
    message: String,
}

enum CommitVerification {
    Verified {
        size_bytes: u64,
        sha256: String,
    },
    /// No object was uploaded to the presigned URL (bucket 404).
    NotUploaded,
    /// The object existed but failed validation; it has been deleted.
    Rejected(CommitRejection),
}

/// Verifies a presigned-uploaded object against its registered intent and
/// the supply-chain checks, fetching the bytes once (the intended
/// commit-side cost for large objects; the upload/download data path
/// itself never touches the gateway). Fails closed: on any size, sha256,
/// per-object-ceiling, or `asset_security` violation it best-effort
/// deletes the orphaned object before returning [`CommitVerification::Rejected`].
///
/// The outer `Err` is reserved for bucket-infrastructure failures (HEAD/GET
/// transport errors) which the caller maps to 503; validation failures are
/// the inner `Rejected` variant (mapped to 422).
async fn verify_and_fetch_committed_object(
    bucket: &super::asset_bucket::AssetBucketClient,
    id: &str,
    expected_size: u64,
    expected_sha256: &str,
    asset_type: &str,
    content_type: &str,
    max_object_bytes: u64,
) -> anyhow::Result<CommitVerification> {
    // 1. HEAD gates the object's size before we download it.
    let Some(actual_size) = bucket.head_object(id).await? else {
        return Ok(CommitVerification::NotUploaded);
    };
    if actual_size != expected_size || actual_size > max_object_bytes {
        best_effort_delete(bucket, id).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_size_mismatch",
            message: format!(
                "committed object size {actual_size} does not match the registered {expected_size} bytes"
            ),
        }));
    }

    // 2. Fetch to verify sha256 and run supply-chain checks on real bytes.
    let content = bucket.get_object(id).await?;
    let actual_sha256 = sha256_hex(&content);
    if actual_sha256 != expected_sha256 || content.len() as u64 != expected_size {
        best_effort_delete(bucket, id).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_commit_hash_mismatch",
            message: "committed object sha256/size does not match the registered intent"
                .to_string(),
        }));
    }
    if let Err(message) =
        super::asset_security::validate_asset_content(asset_type, content_type, &content)
    {
        best_effort_delete(bucket, id).await;
        return Ok(CommitVerification::Rejected(CommitRejection {
            code: "asset_rejected",
            message,
        }));
    }

    Ok(CommitVerification::Verified {
        size_bytes: actual_size,
        sha256: actual_sha256,
    })
}

async fn best_effort_delete(bucket: &super::asset_bucket::AssetBucketClient, id: &str) {
    if let Err(error) = bucket.delete_object(id).await {
        tracing::warn!(
            asset_id = %id,
            error = %error,
            "failed to delete a rejected presigned-upload object; it may be orphaned in the bucket"
        );
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
