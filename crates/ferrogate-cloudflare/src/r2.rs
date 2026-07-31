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
//! - `GET    /accounts/{account_id}/r2/buckets` — list buckets (cursor-paginated;
//!   [`CloudflareClient::list_r2_buckets`] walks every page, issue #490).
//! - `DELETE /accounts/{account_id}/r2/buckets/{name}` — delete a bucket.
//!
//! Auth, `{account_id}` templating, envelope decoding, typed error mapping, and
//! retry/backoff all come from the shared client, so this module is pure
//! endpoint shape: request/response DTOs, thin methods on [`CloudflareClient`],
//! and a create-if-absent provisioning helper.
//!
//! ## Idempotent create
//!
//! [`CloudflareClient::create_r2_bucket`] is idempotent: when the name is
//! already taken, Cloudflare answers `success: false` with error code `10073`
//! (`BucketConflict`, HTTP 409, "Bucket name already exists."). Because R2
//! bucket names are unique *within an account*, a `10073` on this account's own
//! create is exactly "we have already provisioned it". That — and **only** that
//! — is mapped to [`R2BucketCreation::AlreadyExists`] rather than an error, so
//! onboarding can provision unconditionally. Any other conflict, including a
//! 409 carrying no recognised code, surfaces as a typed error instead of a
//! phantom "provisioned" bucket (issue #490). See
//! [`R2_BUCKET_ALREADY_EXISTS_CODES`].
//!
//! ## Tenant bucket naming — isolation, not cosmetics (issue #490)
//!
//! [`r2_bucket_name_for_tenant`] must be **injective**: the bucket name is the
//! per-tenant asset boundary, so two tenants sharing a name share their
//! objects. R2 names cannot carry a raw tenant id (`[a-z0-9-]`, 3–63 chars), so
//! the name is `ferrogate-{cosmetic-slug}-{sha256-of-length-prefixed-tenant}`
//! and *all* of the collision resistance lives in the digest.
//!
//! ## No legacy-name compatibility surface (issue #496)
//!
//! #490 changed every derived name, and this module deliberately offers **no**
//! way to compute the pre-#490 name and **no** dual-read fallback. A fallback
//! would resolve two tenants that folded to one legacy name back onto that one
//! shared bucket — reintroducing exactly the cross-tenant read/write #490
//! fixed.
//!
//! The reason no migration is needed is not "nobody kept the old function": it
//! is that **no bucket has ever been provisioned under a tenant-derived name
//! by this tree, under either derivation**.
//! [`CloudflareClient::ensure_tenant_r2_bucket`] — the only code path that
//! turns a tenant id into a bucket — has, across the whole repository history,
//! exactly one caller ([`CloudflareClient::ensure_tenant_r2_credentials`]),
//! which itself has no non-test caller; the onboarding auto-provision trigger
//! is still deferred (see "Deferred" below). The two live probes create only
//! ad-hoc, timestamp-named buckets (`ferrogate-gate-probe-…`) and delete them
//! unconditionally in the same run. So there is nothing under a legacy name to
//! migrate, and #496 removed the legacy derivation from this crate's public
//! surface rather than shipping a migration entry point with no caller. The
//! pre-#490 algorithm and its collision families survive as a private fixture
//! in `r2_test.rs` — that is the record of *why* the derivation changed.
//!
//! **If a legacy bucket is ever found** (a `ferrogate-*` bucket in a live
//! account whose name is not `ferrogate-[{slug}-]{32 hex}`), the migration this
//! module does not implement would have to:
//!
//! 1. reconstruct the source name with the pre-#490 rule — lowercase the
//!    tenant id, fold every non-ASCII-alphanumeric character to `-`, truncate
//!    to [`R2_BUCKET_NAME_MAX_LEN`], trim trailing `-`, all after the
//!    `ferrogate-` prefix (the fixture in `r2_test.rs` is the executable copy);
//! 2. **refuse to run when that name is ambiguous** — if more than one known
//!    tenant id folds to it, the objects cannot be attributed to a tenant and
//!    merging them is the collision, not the cure;
//! 3. copy every object to [`r2_bucket_name_for_tenant`]'s name over the R2
//!    **S3-compatible data plane**. The REST surface in this module is control
//!    plane only — it creates, lists and deletes buckets and cannot move a
//!    single object. This crate has no S3 client and no SigV4 signer, so that
//!    is new work, not a wiring change;
//! 4. verify the copy (object count + per-object size/etag) *before* deleting
//!    the source with [`CloudflareClient::delete_r2_bucket`], never after;
//! 5. skip probe leftovers — an aborted probe run can leave a
//!    `ferrogate-gate-probe-{unix-secs}` bucket, which is also not #490-shaped
//!    and must not be treated as a tenant's assets.
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
use crate::envelope::CloudflareResultInfo;
use crate::error::CloudflareError;

/// The account-relative path to the R2 buckets collection.
const R2_BUCKETS_PATH: &str = "accounts/{account_id}/r2/buckets";

/// Rows requested per page of the bucket list. Cloudflare defaults `per_page`
/// to 20 and caps it at 1,000; asking for the cap keeps the page count (and so
/// the request count against the ~1,200 req / 5 min global limit) minimal. If
/// the server clamps the value, correctness is unaffected — the cursor is
/// followed either way.
const R2_BUCKETS_PER_PAGE: usize = 1000;

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
/// purpose over the same bytes. Bumping the `v1` suffix renames every tenant's
/// bucket, so it is a migration (see the module docs' "No legacy-name
/// compatibility surface"), never a refactor.
const R2_TENANT_BUCKET_DIGEST_DOMAIN: &str = "ferrogate.r2.bucket.v1";

/// Hex characters of SHA-256 kept in the bucket name: 32 hex chars = **128
/// bits**, i.e. a ~2^64 birthday bound. This — not the readable slug — is what
/// makes the derivation collision-safe.
const R2_TENANT_BUCKET_DIGEST_HEX_LEN: usize = 32;

/// Characters of the *readable* (lossy, purely cosmetic) tenant slug kept in
/// the name. Sized so `prefix(10) + slug(20) + '-'(1) + digest(32) == 63`, R2's
/// exact maximum.
const R2_TENANT_BUCKET_SLUG_MAX_LEN: usize = 20;

/// Cloudflare error codes that mean "the bucket name you asked to create is
/// already taken" — the idempotent-create success case.
///
/// `10073` (`BucketConflict`, HTTP 409, "Bucket name already exists.") is the
/// only conflict code in Cloudflare's published R2 error table, and R2 bucket
/// names are unique within an account, so a `10073` on this account's create
/// means this account already owns the bucket.
///
/// Membership here is load-bearing, not decorative: it is what turns a *failed*
/// create into a reported provision, and #462 then mints a read+write
/// credential scoped to that name. A code that Cloudflare never sends is
/// therefore not harmless — an earlier revision also listed `10004` with a
/// verbatim quoted message, but no such code exists in R2's error table and no
/// live observation of it was ever recorded, so it was removed (issue #461
/// gate). Add a code only with a citation or a recorded live response.
///
/// The HTTP status alone is not sufficient (issue #490); see
/// `is_bucket_already_exists`.
pub const R2_BUCKET_ALREADY_EXISTS_CODES: &[i64] = &[10073];

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

    /// List **all** of the account's R2 buckets, following the cursor beyond
    /// the first page (issue #490).
    ///
    /// The list `result` wraps the rows in a `buckets` array and the envelope's
    /// `result_info.cursor` carries the continuation token. Without walking it
    /// the caller silently receives page 1 (Cloudflare's default `per_page` is
    /// 20) with no way to learn more exist — an "absent" answer that is really
    /// "not on page 1", which is exactly how the `#461` live probe could pass
    /// vacuously after a delete. This mirrors the sibling `D1Client::
    /// list_databases` walk (issue #440); R2 is cursor-paginated rather than
    /// page-numbered, so the cursor is echoed back instead of a page index.
    ///
    /// Termination: the loop stops on the first page whose `result_info` has no
    /// (or an empty) cursor, on an empty page, and on a cursor the server
    /// repeats verbatim — the last is a server-side no-progress bug that would
    /// otherwise spin forever.
    pub async fn list_r2_buckets(&self) -> Result<Vec<R2Bucket>, CloudflareError> {
        let mut buckets = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let path = match &cursor {
                Some(cursor) => format!(
                    "{R2_BUCKETS_PATH}?per_page={R2_BUCKETS_PER_PAGE}&cursor={}",
                    percent_encode_query_value(cursor)
                ),
                None => format!("{R2_BUCKETS_PATH}?per_page={R2_BUCKETS_PER_PAGE}"),
            };
            let (list, info): (R2BucketList, Option<CloudflareResultInfo>) =
                self.get_json_paged(&path, None).await?;
            let page_was_empty = list.buckets.is_empty();
            buckets.extend(list.buckets);

            let next = info
                .as_ref()
                .and_then(CloudflareResultInfo::next_cursor)
                .map(str::to_string);
            match next {
                Some(next) if !page_was_empty && Some(&next) != cursor.as_ref() => {
                    cursor = Some(next);
                }
                _ => return Ok(buckets),
            }
        }
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
    ///
    /// A tenant id that names no identity (empty / no ASCII alphanumerics) is
    /// rejected as a [`CloudflareError::Config`] before any request is sent —
    /// see `validate_tenant_id`. This is the entry point
    /// [`Self::ensure_tenant_r2_credentials`] also provisions through, so the
    /// #462 credential path inherits the same guard.
    pub async fn ensure_tenant_r2_bucket(
        &self,
        tenant: &str,
    ) -> Result<R2BucketProvision, CloudflareError> {
        validate_tenant_id(tenant)?;
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
/// you own it" case — the ONLY failure this module absorbs into a success
/// (issue #490).
///
/// Narrowed from "any HTTP 409" to "carries a documented already-exists code"
/// (see [`R2_BUCKET_ALREADY_EXISTS_CODES`]). A swallowed error must not be
/// indistinguishable from success: `AlreadyExists` is reported to the caller as
/// a provisioned bucket, and #462 then mints a read+write credential scoped to
/// that name. Absorbing a *bare* 409 — or any other conflict Cloudflare may
/// return on this path (a bucket mid-deletion, a jurisdiction conflict, a name
/// held elsewhere) — would claim a bucket exists that does not, so every 409
/// without one of these codes now surfaces as
/// [`CloudflareError::Api`]`{ status: 409, .. }`.
///
/// The check is status-agnostic on purpose. R2 does document a status per
/// code, but the status is the coarser of the two: 409 alone covers both
/// `10073`/`BucketConflict` and `10008`/`BucketNotEmpty`, so it cannot
/// distinguish the case that is safe to absorb — keying on it is exactly what
/// #490 had to remove. This is a statement about which field is authoritative,
/// not a claim that `10073` has been observed at any status other than 409.
fn is_bucket_already_exists(error: &CloudflareError) -> bool {
    matches!(
        error,
        CloudflareError::Api { errors, .. }
            if errors
                .iter()
                .any(|e| R2_BUCKET_ALREADY_EXISTS_CODES.contains(&e.code))
    )
}

/// Percent-encode a query-parameter value, keeping only the RFC 3986 unreserved
/// set literal. Cloudflare's pagination cursor is an opaque token that can carry
/// `+`, `/` and `=`; splicing it raw into the query string would corrupt it.
/// Dependency-free (the crate has no URL-encoding dep) and only ever applied to
/// server-issued cursors.
fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Reject a tenant id that cannot name a tenant (issue #490).
///
/// [`r2_bucket_name_for_tenant`] is deliberately infallible — it maps *any*
/// string to an R2-legal, injective name, including `""` (which derives
/// `ferrogate-8785c455…`). That is right for a derivation but wrong for a
/// provisioning entry point: an empty or punctuation-only tenant id is a caller
/// bug, and silently minting real storage (plus, via #462, a real credential)
/// for it hides that bug behind a success. The sibling D1 path takes the same
/// position — `ferrogate_storage::control_plane_store_d1`'s `validate_tenant_id`
/// rejects an empty id before it can name a database.
///
/// The rule is deliberately narrower than that D1 charset check: this crate is
/// a transport client and does not own tenant-id policy, so it only requires an
/// id that carries a real identity (at least one ASCII alphanumeric). Callers
/// that need a stricter charset gate it upstream.
fn validate_tenant_id(tenant: &str) -> Result<(), CloudflareError> {
    if !tenant.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(CloudflareError::Config(format!(
            "invalid tenant id {tenant:?} for R2 provisioning: expected at least one ASCII \
             alphanumeric character"
        )));
    }
    Ok(())
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
/// derivation lost it both ways; the families it collapsed are pinned in
/// `r2_test.rs`.
///
/// Collision-safety therefore comes **only** from `{digest}`:
///
/// - The tenant identity is canonicalised **length-prefixed** as
///   `"{domain}:{len}:{tenant}"` — the same trick as
///   `ferrogate_storage::agent_cost_burn_key` /
///   `observed_agent_presence_key` — so the encoding stays unambiguous if a
///   second component (jurisdiction, realm, …) is ever appended.
/// - `{digest}` is the lowercase hex SHA-256 of that canonical string,
///   truncated to `R2_TENANT_BUCKET_DIGEST_HEX_LEN` hex chars (128 bits,
///   ~2^64 birthday bound). Distinct tenant ids therefore map to distinct
///   names short of a 128-bit SHA-256 collision — in particular no amount of
///   case-folding, separator folding, or length can be *crafted* into an
///   alias, which is the property the old derivation lacked.
///
/// `{slug}` is a lossy, purely **cosmetic** lowercase-alphanumeric rendering of
/// the tenant id (hyphen-joined, capped at `R2_TENANT_BUCKET_SLUG_MAX_LEN`)
/// so an operator can eyeball which bucket belongs to whom. Two tenants may
/// well share a slug; they cannot share a digest.
///
/// The result always satisfies R2's constraints: `[a-z0-9-]` only, starts with
/// `f` and ends with a hex digit, and length between
/// `10 + 32 = 42` and `10 + 20 + 1 + 32 =` [`R2_BUCKET_NAME_MAX_LEN`].
///
/// **Migration:** this is NOT the pre-#490 name, and no helper computes that
/// name any more — see the module docs' "No legacy-name compatibility surface"
/// (issue #496) for why, and for what a migration would owe if one is ever
/// needed.
pub fn r2_bucket_name_for_tenant(tenant: &str) -> String {
    let slug = tenant_bucket_slug(tenant);
    let digest = tenant_bucket_digest(tenant);
    if slug.is_empty() {
        format!("{R2_TENANT_BUCKET_PREFIX}{digest}")
    } else {
        format!("{R2_TENANT_BUCKET_PREFIX}{slug}-{digest}")
    }
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
