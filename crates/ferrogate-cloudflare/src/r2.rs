// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare R2 bucket-provisioning REST surface (create/list/delete + idempotent ensure) for issue #461.

//! Cloudflare R2 bucket-provisioning REST endpoints (issue #461, follow-up to
//! #410).
//!
//! A thin R2 bucket-management surface added directly to the shared
//! [`CloudflareClient`] (issue #405), covering the account `client/v4` R2
//! bucket lifecycle:
//!
//! - `POST   /accounts/{account_id}/r2/buckets` — create a bucket.
//! - `GET    /accounts/{account_id}/r2/buckets` — list buckets.
//! - `DELETE /accounts/{account_id}/r2/buckets/{name}` — delete a bucket.
//!
//! Auth, `{account_id}` templating, envelope decoding, typed error mapping, and
//! retry/backoff all come from the shared client, so this module is pure
//! endpoint shape: request/response DTOs, thin methods on [`CloudflareClient`],
//! and a create-if-absent provisioning helper.
//!
//! ## Idempotent create
//!
//! [`CloudflareClient::create_r2_bucket`] is idempotent: when the bucket already
//! exists and is owned by this account, Cloudflare answers `success: false` with
//! error code `10004` ("The bucket you tried to create already exists, and you
//! own it."; the S3-compatible sibling is `10073`/`BucketConflict`, HTTP 409).
//! That case is mapped to [`R2BucketCreation::AlreadyExists`] rather than an
//! error, so onboarding can provision unconditionally. See
//! [`R2_BUCKET_ALREADY_EXISTS_CODES`].
//!
//! ## Credential / scope
//!
//! Bucket management uses the account API token (Bearer), which must carry the
//! **Workers R2 Storage** permission group (`Read, Edit`; see
//! [`crate::scopes`]). This is distinct from R2's S3-style Access Key ID /
//! Secret, which is a data-plane credential form for the SigV4 object path — not
//! used here.
//!
//! ## Deferred (not in this module)
//!
//! - Scoped R2 **token** creation (the R2 create-token API + permission groups).
//! - Onboarding-lifecycle wiring: the auto-provision trigger belongs at tenant
//!   creation (call [`CloudflareClient::ensure_tenant_r2_bucket`] from the
//!   onboarding path), out of scope for this crate.

use serde::{Deserialize, Serialize};

use crate::client::{CloudflareClient, HttpMethod};
use crate::error::CloudflareError;

/// The account-relative path to the R2 buckets collection.
const R2_BUCKETS_PATH: &str = "accounts/{account_id}/r2/buckets";

/// Cloudflare error codes that mean "the bucket you asked to create already
/// exists and is owned by this account" — the idempotent-create success case.
///
/// `10004` is what the account REST API (`client/v4`) returns on a duplicate
/// `POST .../r2/buckets` ("The bucket you tried to create already exists, and
/// you own it."). `10073` is the S3-compatible `BucketConflict` sibling
/// (HTTP 409). Either code — or a bare HTTP 409 on the create path — is treated
/// as success by [`CloudflareClient::create_r2_bucket`].
pub const R2_BUCKET_ALREADY_EXISTS_CODES: &[i64] = &[10004, 10073];

/// Request body for `POST /accounts/{account_id}/r2/buckets`.
#[derive(Debug, Clone, Serialize)]
pub struct R2CreateBucketRequest {
    /// Bucket name (3–63 chars, lowercase alphanumeric + hyphens).
    pub name: String,
    /// Optional placement hint (`apac`/`eeur`/`enam`/`weur`/`wnam`/`oc`).
    /// Serialized as camelCase `locationHint` per the REST schema.
    #[serde(rename = "locationHint", skip_serializing_if = "Option::is_none")]
    pub location_hint: Option<String>,
    /// Optional storage class (`Standard`/`InfrequentAccess`). Serialized as
    /// camelCase `storageClass` per the REST schema.
    #[serde(rename = "storageClass", skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

impl R2CreateBucketRequest {
    /// A plain create request with no placement/storage-class constraints.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            location_hint: None,
            storage_class: None,
        }
    }
}

/// An R2 bucket descriptor as returned by the create/list endpoints. All fields
/// are optional in Cloudflare's schema (response fields are snake_case).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct R2Bucket {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub storage_class: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
}

/// The `result` shape of `GET /accounts/{account_id}/r2/buckets`: a `buckets`
/// array (unlike D1's bare-array list result).
#[derive(Debug, Clone, Default, Deserialize)]
struct R2BucketList {
    #[serde(default)]
    buckets: Vec<R2Bucket>,
}

/// Outcome of an idempotent [`CloudflareClient::create_r2_bucket`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum R2BucketCreation {
    /// The bucket did not exist and was created; carries CF's descriptor.
    Created(R2Bucket),
    /// The bucket already existed and is owned by this account — the create was
    /// a no-op (idempotent success).
    AlreadyExists,
}

impl R2BucketCreation {
    /// `true` when this call actually created the bucket (vs. found it present).
    pub fn was_created(&self) -> bool {
        matches!(self, R2BucketCreation::Created(_))
    }

    /// The created bucket's descriptor, if this call created it.
    pub fn bucket(&self) -> Option<&R2Bucket> {
        match self {
            R2BucketCreation::Created(bucket) => Some(bucket),
            R2BucketCreation::AlreadyExists => None,
        }
    }
}

/// The result of [`CloudflareClient::ensure_tenant_r2_bucket`]: the bucket's
/// name, the account's R2 S3 endpoint (for wiring an S3-compatible client), and
/// whether this call created it (`false` = it already existed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R2BucketProvision {
    /// The (derived) bucket name that now exists.
    pub name: String,
    /// The account R2 S3 endpoint, e.g. `https://<account_id>.r2.cloudflarestorage.com`.
    pub s3_endpoint: String,
    /// `true` when this call created the bucket; `false` when it already existed.
    pub created: bool,
}

impl CloudflareClient {
    /// Create an R2 bucket.
    ///
    /// **Idempotent**: an already-exists response (the bucket is present and
    /// owned by this account) maps to [`R2BucketCreation::AlreadyExists`] rather
    /// than an error, so callers can provision unconditionally. Any other
    /// failure surfaces as a typed [`CloudflareError`]. See
    /// [`R2_BUCKET_ALREADY_EXISTS_CODES`] for how the idempotent case is
    /// detected.
    pub async fn create_r2_bucket(
        &self,
        request: &R2CreateBucketRequest,
    ) -> Result<R2BucketCreation, CloudflareError> {
        let body = serde_json::to_vec(request).map_err(|error| {
            CloudflareError::Config(format!(
                "failed to encode R2 create-bucket request: {error}"
            ))
        })?;
        match self
            .request_json::<R2Bucket>(HttpMethod::Post, R2_BUCKETS_PATH, Some(body), None)
            .await
        {
            Ok(bucket) => Ok(R2BucketCreation::Created(bucket)),
            Err(error) if is_bucket_already_exists(&error) => Ok(R2BucketCreation::AlreadyExists),
            Err(error) => Err(error),
        }
    }

    /// List the account's R2 buckets. The list `result` wraps the rows in a
    /// `buckets` array; this returns that array.
    pub async fn list_r2_buckets(&self) -> Result<Vec<R2Bucket>, CloudflareError> {
        let list: R2BucketList = self.get_json(R2_BUCKETS_PATH, None).await?;
        Ok(list.buckets)
    }

    /// Delete an R2 bucket by name. Ack-style (the endpoint returns a null
    /// `result`). The bucket must be empty; a non-empty bucket surfaces as a
    /// typed [`CloudflareError::Api`] (`BucketNotEmpty`).
    pub async fn delete_r2_bucket(&self, name: &str) -> Result<(), CloudflareError> {
        let path = r2_bucket_path(name)?;
        self.request_ack(HttpMethod::Delete, &path, None, None)
            .await
    }

    /// Ensure a tenant's R2 bucket exists (create-if-absent) and return its name
    /// plus the account R2 S3 endpoint.
    ///
    /// Idempotent — safe to call on every onboarding attempt. The bucket name
    /// follows [`r2_bucket_name_for_tenant`]. The returned
    /// [`R2BucketProvision::created`] distinguishes a fresh create from a bucket
    /// that already existed.
    pub async fn ensure_tenant_r2_bucket(
        &self,
        tenant: &str,
    ) -> Result<R2BucketProvision, CloudflareError> {
        let name = r2_bucket_name_for_tenant(tenant);
        let outcome = self
            .create_r2_bucket(&R2CreateBucketRequest::named(name.clone()))
            .await?;
        Ok(R2BucketProvision {
            name,
            s3_endpoint: self.config().r2_s3_endpoint(),
            created: outcome.was_created(),
        })
    }
}

/// Whether a create-bucket failure is really the idempotent "already exists and
/// you own it" case (see [`R2_BUCKET_ALREADY_EXISTS_CODES`]). A bare HTTP 409 on
/// the create path is treated as the same case.
fn is_bucket_already_exists(error: &CloudflareError) -> bool {
    matches!(
        error,
        CloudflareError::Api { status, errors }
            if *status == 409
                || errors
                    .iter()
                    .any(|e| R2_BUCKET_ALREADY_EXISTS_CODES.contains(&e.code))
    )
}

/// Derive a deterministic, R2-valid bucket name for a tenant.
///
/// Convention: `ferrogate-<tenant-slug>`, where the tenant id is lowercased and
/// any character outside `[a-z0-9]` becomes `-`. R2 bucket names must be 3–63
/// chars, lowercase alphanumeric + hyphens, starting/ending alphanumeric; the
/// `ferrogate-` prefix guarantees a valid start and the >= 3 length, and the
/// result is capped at 63 chars and trimmed of any trailing hyphen.
pub fn r2_bucket_name_for_tenant(tenant: &str) -> String {
    let mut name = String::from("ferrogate-");
    for c in tenant.chars() {
        name.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        });
    }
    // All pushed bytes are ASCII, so truncating at a byte index is char-safe.
    name.truncate(63);
    name.trim_end_matches('-').to_string()
}

/// Build the `r2/buckets/{name}` path, rejecting names that could escape the
/// path segment. R2 bucket names are lowercase alphanumeric + hyphens; anything
/// else is a caller bug surfaced as a config error before any request is sent.
fn r2_bucket_path(name: &str) -> Result<String, CloudflareError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(CloudflareError::Config(format!(
            "invalid R2 bucket name {name:?}: expected lowercase alphanumeric and hyphens"
        )));
    }
    Ok(format!("accounts/{{account_id}}/r2/buckets/{name}"))
}
