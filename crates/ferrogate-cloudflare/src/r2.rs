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
//! ## Tenant bucket naming — isolation, not cosmetics (issue #490)
//!
//! [`r2_bucket_name_for_tenant`] must be **injective**: the bucket name is the
//! per-tenant asset boundary, so two tenants sharing a name share their
//! objects. R2 names cannot carry a raw tenant id (`[a-z0-9-]`, 3–63 chars), so
//! the name is `ferrogate-{cosmetic-slug}-{sha256-of-length-prefixed-tenant}`
//! and *all* of the collision resistance lives in the digest. The pre-#490
//! slug-only derivation is retained as
//! [`r2_legacy_bucket_name_for_tenant`] for migration lookups only.
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
use sha2::{Digest, Sha256};

use crate::client::{CloudflareClient, HttpMethod};
use crate::error::CloudflareError;

/// The account-relative path to the R2 buckets collection.
const R2_BUCKETS_PATH: &str = "accounts/{account_id}/r2/buckets";

/// R2's hard bucket-name bounds: 3–63 characters, lowercase letters/digits/
/// hyphens, never starting or ending with a hyphen. (Cloudflare R2 docs,
/// "Create new buckets".) Every name minted by
/// [`r2_bucket_name_for_tenant`] satisfies all three by construction.
pub const R2_BUCKET_NAME_MAX_LEN: usize = 63;
/// See [`R2_BUCKET_NAME_MAX_LEN`].
pub const R2_BUCKET_NAME_MIN_LEN: usize = 3;

/// Readable leading tag of every FerroGate-minted tenant bucket name. Also what
/// guarantees the name starts with a letter (R2 forbids a leading hyphen).
const R2_TENANT_BUCKET_PREFIX: &str = "ferrogate-";

/// Domain-separation tag mixed into the hashed tenant identity, so the digest
/// for a tenant can never coincide with a digest this repo mints for some other
/// purpose over the same bytes. Bump the `v1` suffix only with a migration
/// (see [`r2_legacy_bucket_name_for_tenant`]).
const R2_TENANT_BUCKET_DIGEST_DOMAIN: &str = "ferrogate.r2.bucket.v1";

/// Hex characters of SHA-256 kept in the bucket name: 32 hex chars = **128
/// bits**, i.e. a ~2^64 birthday bound. This — not the readable slug — is what
/// makes the derivation collision-safe.
const R2_TENANT_BUCKET_DIGEST_HEX_LEN: usize = 32;

/// Characters of the *readable* (lossy, purely cosmetic) tenant slug kept in
/// the name. Sized so `prefix(10) + slug(20) + '-'(1) + digest(32) == 63`, R2's
/// exact maximum.
const R2_TENANT_BUCKET_SLUG_MAX_LEN: usize = 20;

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
    /// follows [`r2_bucket_name_for_tenant`], which is injective per #490 (an
    /// earlier, non-injective derivation could hand two tenants one bucket).
    /// The returned [`R2BucketProvision::created`] distinguishes a fresh create
    /// from a bucket that already existed.
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

/// Derive a deterministic, R2-valid, **collision-safe** bucket name for a
/// tenant.
///
/// Shape: `ferrogate-{slug}-{digest}` (the `{slug}-` part is dropped when the
/// tenant id carries no alphanumerics at all, e.g. `""`).
///
/// ## Why this is not the obvious "slugify the tenant id" (issue #490)
///
/// A tenant's bucket **is** its asset-isolation boundary: two tenants that
/// derive the same bucket name read and overwrite each other's objects, and
/// #462's per-tenant scoped credential would then be correctly scoped to a
/// *shared* bucket. So the derivation must be injective. R2 bucket names cannot
/// carry a raw tenant id — they are limited to `[a-z0-9-]` and 63 characters —
/// so any direct embedding must fold characters and truncate, and folding plus
/// truncation are exactly the two ways to lose injectivity. The pre-#490
/// derivation lost it both ways (see [`r2_legacy_bucket_name_for_tenant`]).
///
/// Collision-safety therefore comes **only** from `{digest}`:
///
/// - The tenant identity is canonicalised **length-prefixed** as
///   `"{domain}:{len}:{tenant}"` — the same trick as
///   `ferrogate_storage::agent_cost_burn_key` /
///   `observed_agent_presence_key` — so the encoding stays unambiguous if a
///   second component (jurisdiction, realm, …) is ever appended.
/// - `{digest}` is the lowercase hex SHA-256 of that canonical string,
///   truncated to [`R2_TENANT_BUCKET_DIGEST_HEX_LEN`] hex chars (128 bits,
///   ~2^64 birthday bound). Distinct tenant ids therefore map to distinct
///   names short of a 128-bit SHA-256 collision — in particular no amount of
///   case-folding, separator folding, or length can be *crafted* into an
///   alias, which is the property the old derivation lacked.
///
/// `{slug}` is a lossy, purely **cosmetic** lowercase-alphanumeric rendering of
/// the tenant id (hyphen-joined, capped at [`R2_TENANT_BUCKET_SLUG_MAX_LEN`])
/// so an operator can eyeball which bucket belongs to whom. Two tenants may
/// well share a slug; they cannot share a digest.
///
/// The result always satisfies R2's constraints: `[a-z0-9-]` only, starts with
/// `f` and ends with a hex digit, and length between
/// `10 + 32 = 42` and `10 + 20 + 1 + 32 =` [`R2_BUCKET_NAME_MAX_LEN`].
///
/// **Migration:** this is NOT the pre-#490 name. See
/// [`r2_legacy_bucket_name_for_tenant`].
pub fn r2_bucket_name_for_tenant(tenant: &str) -> String {
    let slug = tenant_bucket_slug(tenant);
    let digest = tenant_bucket_digest(tenant);
    if slug.is_empty() {
        format!("{R2_TENANT_BUCKET_PREFIX}{digest}")
    } else {
        format!("{R2_TENANT_BUCKET_PREFIX}{slug}-{digest}")
    }
}

/// The **pre-#490** bucket-name derivation, kept ONLY as a migration/lookup
/// helper — never call it to provision.
///
/// It lowercased the tenant id, folded every non-alphanumeric character to `-`,
/// truncated at 63 characters, and trimmed trailing hyphens, which is not
/// injective:
///
/// ```text
/// legacy("Acme_Corp") == legacy("acme-corp") == legacy("acme corp")
///                     == legacy("ACME.CORP") == "ferrogate-acme-corp"
/// ```
///
/// plus any two ids agreeing on their first 53 post-fold characters. Two such
/// tenants shared one bucket — a cross-tenant asset read/write.
///
/// Nothing in the tree provisioned through it (onboarding wiring is still
/// deferred; only tests and the live probe touched the R2 surface), so there is
/// no known live bucket under a legacy name. If a deployment *did* provision
/// one out-of-band, its objects live under this name and must be copied to
/// [`r2_bucket_name_for_tenant`]'s name before the old bucket is deleted — this
/// function is how a migration tool computes the source name.
pub fn r2_legacy_bucket_name_for_tenant(tenant: &str) -> String {
    let mut name = String::from(R2_TENANT_BUCKET_PREFIX);
    for c in tenant.chars() {
        name.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        });
    }
    // All pushed bytes are ASCII, so truncating at a byte index is char-safe.
    name.truncate(R2_BUCKET_NAME_MAX_LEN);
    name.trim_end_matches('-').to_string()
}

/// Lowercase-hex SHA-256 of the length-prefixed, domain-separated tenant
/// identity, truncated to [`R2_TENANT_BUCKET_DIGEST_HEX_LEN`] chars. This is
/// the whole of the name's collision resistance.
fn tenant_bucket_digest(tenant: &str) -> String {
    let canonical = format!("{R2_TENANT_BUCKET_DIGEST_DOMAIN}:{}:{tenant}", tenant.len());
    let hex: String = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // 64 ASCII hex chars, so a byte-index slice is char-safe.
    hex[..R2_TENANT_BUCKET_DIGEST_HEX_LEN].to_string()
}

/// Cosmetic, deliberately lossy tenant rendering for the readable middle of the
/// bucket name: runs of `[a-z0-9]` (lowercased) joined by a single `-`, capped
/// at [`R2_TENANT_BUCKET_SLUG_MAX_LEN`] and never leading/trailing with `-` or
/// containing `--`. Carries NO isolation guarantee — collisions here are fine
/// and expected.
fn tenant_bucket_slug(tenant: &str) -> String {
    let mut slug = String::with_capacity(R2_TENANT_BUCKET_SLUG_MAX_LEN);
    for c in tenant.chars() {
        if slug.len() == R2_TENANT_BUCKET_SLUG_MAX_LEN {
            break;
        }
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_end_matches('-').to_string()
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
