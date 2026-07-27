// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare scoped per-tenant R2 API-token creation (bucket-restricted) for issue #462.

//! Scoped per-tenant R2 API-token creation (issue #462, follow-up to #461/#410).
//!
//! #461 added R2 *bucket* CRUD to [`CloudflareClient`]; this module adds the
//! security piece of multi-tenant R2 isolation: minting a Cloudflare API token
//! **restricted to a single tenant bucket**, then deriving the S3-style
//! credential the existing #410 SigV4 asset-bucket client consumes.
//!
//! ## Which Cloudflare API (verified, not guessed)
//!
//! R2 has **no separate "create R2 token" REST endpoint** — the R2 dashboard's
//! "Manage R2 API Tokens" is a UI over Cloudflare's generic **account-owned API
//! tokens** API, restricted with R2 permission groups + a bucket resource scope.
//! We therefore mint via:
//!
//! - `POST   /accounts/{account_id}/tokens` — create an account-owned token
//!   carrying a single `allow` policy scoped to one bucket resource.
//! - `DELETE /accounts/{account_id}/tokens/{token_id}` — revoke it.
//!
//! **Account-owned** (not `POST /user/tokens`) is deliberate: the token is a
//! durable service principal owned by the FerroGate account, it survives the
//! creating user, and it is consistent with this crate's account-scoped
//! `accounts/{account_id}/…` surface.
//!
//! ## The R2 credential shape (why this yields a usable Access Key ID / Secret)
//!
//! Cloudflare derives the R2 S3 credential from the created token:
//!
//! - **Access Key ID** = the token's `id`.
//! - **Secret Access Key** = the lowercase hex **SHA-256 of the token `value`**
//!   (the plaintext secret CF returns exactly once, at creation).
//!
//! That is precisely the `{ access_key_id, secret_access_key }` pair the #410
//! `AssetBucketConfig` SigV4 client (in `ferrogate-cli`) signs with against
//! `https://<account_id>.r2.cloudflarestorage.com`, so a tenant's minted
//! credential works unchanged with the existing R2 S3 path.
//!
//! ## Bucket scoping
//!
//! The policy `resources` map keys the single bucket by Cloudflare's R2 resource
//! id `com.cloudflare.edge.r2.bucket.{account_id}_{jurisdiction}_{bucket}` mapped
//! to `"*"`; the `permission_groups` carry the R2 **Bucket Item** group
//! (Read, or Read+Write) — see [`R2TokenAccess`]. A token minted this way cannot
//! touch any other bucket.
//!
//! ## Not idempotent (by construction)
//!
//! Unlike [`CloudflareClient::create_r2_bucket`], minting a token is **not**
//! create-if-absent: Cloudflare returns a fresh secret `value` **once** per
//! create and never lets it be read back, so there is no way to recover an
//! existing token's secret. [`CloudflareClient::ensure_tenant_r2_credentials`]
//! keeps the *bucket* idempotent (reusing #461's ensure) and mints a fresh
//! scoped token each call; the caller owns storing it. Dedup/rotation are
//! deferred, and so is writing the minted token INTO Secrets Store -- note
//! that is a different deferral from the `cf://` resolver itself, which
//! landed under #417; this one is about who persists a freshly minted R2
//! credential.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client::{CloudflareClient, HttpMethod};
use crate::error::CloudflareError;
use crate::r2::R2BucketProvision;

/// The account-owned API tokens collection endpoint.
const ACCOUNT_TOKENS_PATH: &str = "accounts/{account_id}/tokens";

/// The default R2 jurisdiction segment of a bucket resource scope. Buckets not
/// created in a specific data-localization jurisdiction use `default`.
pub const R2_DEFAULT_JURISDICTION: &str = "default";

/// Cloudflare permission-group id for **Workers R2 Storage Bucket Item Read**
/// (read + list objects within the scoped bucket). Verified against the R2
/// authentication docs' Access-Policy example.
pub const R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID: &str = "6a018a9f2fc74eb6b293b0c548f38b39";

/// Cloudflare permission-group id for **Workers R2 Storage Bucket Item Write**
/// (read + write + list objects within the scoped bucket). Verified against
/// Cloudflare's R2 Data Catalog documentation, which is where the *Write* group
/// id is published — the R2 authentication docs' Access-Policy example carries
/// only the *Read* id above, so it is not a source for this constant (#489).
pub const R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID: &str = "2efd5506f9c8494dacb1fa10a3e7d5b6";

/// The access level a scoped R2 token grants over its single bucket.
///
/// Selects the R2 **Bucket Item** permission group attached to the token's
/// policy. A tenant that owns its bucket typically wants [`Self::ReadWrite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R2TokenAccess {
    /// Read + list objects (Workers R2 Storage Bucket Item Read).
    ReadOnly,
    /// Read + write + list objects (Workers R2 Storage Bucket Item Write).
    ReadWrite,
}

impl R2TokenAccess {
    /// The Cloudflare permission-group id this access level attaches.
    pub fn permission_group_id(self) -> &'static str {
        match self {
            R2TokenAccess::ReadOnly => R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID,
            R2TokenAccess::ReadWrite => R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
        }
    }

    /// The Cloudflare dashboard name of the attached permission group.
    pub fn permission_group_name(self) -> &'static str {
        match self {
            R2TokenAccess::ReadOnly => "Workers R2 Storage Bucket Item Read",
            R2TokenAccess::ReadWrite => "Workers R2 Storage Bucket Item Write",
        }
    }
}

/// A request to mint an R2 API token scoped to exactly one bucket.
#[derive(Debug, Clone)]
pub struct R2ScopedTokenRequest {
    /// Human-readable token name recorded on the Cloudflare side (dashboard /
    /// audit). Not the credential.
    pub token_name: String,
    /// The single bucket the token may access.
    pub bucket: String,
    /// The bucket's data-localization jurisdiction segment (`default` for
    /// non-jurisdictional buckets). See [`R2_DEFAULT_JURISDICTION`].
    pub jurisdiction: String,
    /// Read-only vs. read-write (which R2 Bucket Item permission group).
    pub access: R2TokenAccess,
}

impl R2ScopedTokenRequest {
    /// A read+write token scoped to a single default-jurisdiction bucket.
    pub fn read_write(token_name: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            token_name: token_name.into(),
            bucket: bucket.into(),
            jurisdiction: R2_DEFAULT_JURISDICTION.to_string(),
            access: R2TokenAccess::ReadWrite,
        }
    }

    /// A read-only token scoped to a single default-jurisdiction bucket.
    pub fn read_only(token_name: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            token_name: token_name.into(),
            bucket: bucket.into(),
            jurisdiction: R2_DEFAULT_JURISDICTION.to_string(),
            access: R2TokenAccess::ReadOnly,
        }
    }
}

/// A minted, bucket-scoped R2 credential.
///
/// [`Self::access_key_id`] and [`Self::secret_access_key`] plug straight into
/// the #410 R2 SigV4 asset-bucket client; [`Self::token_id`] (equal to the
/// access key id) is retained for later revocation via
/// [`CloudflareClient::revoke_r2_token`]. `Debug` is hand-written so the secret
/// never lands in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct R2ScopedToken {
    /// The Cloudflare token id — used to revoke the token later. Equal to
    /// [`Self::access_key_id`].
    pub token_id: String,
    /// The S3 **Access Key ID**: the Cloudflare token `id`.
    pub access_key_id: String,
    /// The S3 **Secret Access Key**: lowercase hex SHA-256 of the token `value`.
    pub secret_access_key: String,
}

impl fmt::Debug for R2ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("R2ScopedToken")
            .field("token_id", &self.token_id)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// The result of [`CloudflareClient::ensure_tenant_r2_credentials`]: the tenant's
/// (idempotently ensured) bucket plus a freshly minted scoped credential for it.
#[derive(Debug, Clone)]
pub struct R2CredentialProvision {
    /// The ensured bucket (see #461's [`R2BucketProvision`]).
    pub bucket: R2BucketProvision,
    /// A bucket-scoped credential minted for `bucket`.
    pub token: R2ScopedToken,
}

/// Request body for `POST /accounts/{account_id}/tokens`.
#[derive(Debug, Serialize)]
struct CreateTokenBody {
    name: String,
    policies: Vec<TokenPolicy>,
}

/// One access policy attached to a token.
#[derive(Debug, Serialize)]
struct TokenPolicy {
    effect: &'static str,
    /// Resource-scope map: `{ "com.cloudflare.edge.r2.bucket.<...>": "*" }`.
    resources: BTreeMap<String, &'static str>,
    permission_groups: Vec<PermissionGroupRef>,
}

/// A permission-group reference inside a policy (id is sufficient; the name is
/// optional and echoed by Cloudflare).
#[derive(Debug, Serialize)]
struct PermissionGroupRef {
    id: &'static str,
}

/// The `result` of a create-token response. Cloudflare returns the plaintext
/// `value` exactly once, here.
///
/// `Debug` is hand-written (issue #492, same treatment as [`R2ScopedToken`]
/// above and #489's `client::HttpResponse` one frame earlier on this same
/// path). `value` is a `String`, so a derived `Debug` renders the one-time
/// token as *readable plaintext* — strictly worse than the `Vec<u8>` body
/// #489 closed. Whether the value was present still renders (`Some(..)` vs
/// `None`), because that is the distinction
/// [`CloudflareClient::create_scoped_r2_token`] turns into a `Decode` error.
#[derive(Deserialize)]
pub(crate) struct CreateTokenResult {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) value: Option<String>,
}

impl fmt::Debug for CreateTokenResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateTokenResult")
            .field("id", &self.id)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CloudflareClient {
    /// Create an R2 API token restricted to a single bucket and return the
    /// derived S3 credential (`{ access_key_id, secret_access_key }`) plus the
    /// token id (for [`Self::revoke_r2_token`]).
    ///
    /// The token carries one `allow` policy whose `resources` names exactly the
    /// requested bucket (`com.cloudflare.edge.r2.bucket.{account}_{jurisdiction}_
    /// {bucket}` → `"*"`) and whose permission group is the R2 Bucket Item group
    /// for the requested [`R2TokenAccess`]. The returned secret is the lowercase
    /// hex SHA-256 of Cloudflare's one-time token value.
    ///
    /// **Not idempotent** — each call mints a fresh secret (see module docs).
    pub async fn create_scoped_r2_token(
        &self,
        request: &R2ScopedTokenRequest,
    ) -> Result<R2ScopedToken, CloudflareError> {
        validate_bucket_name(&request.bucket)?;
        validate_jurisdiction(&request.jurisdiction)?;
        if request.token_name.trim().is_empty() {
            return Err(CloudflareError::Config(
                "R2 scoped-token request requires a non-empty token name".to_string(),
            ));
        }

        let resource =
            r2_bucket_resource_scope(self.account_id(), &request.jurisdiction, &request.bucket);
        let mut resources = BTreeMap::new();
        resources.insert(resource, "*");

        let body = CreateTokenBody {
            name: request.token_name.clone(),
            policies: vec![TokenPolicy {
                effect: "allow",
                resources,
                permission_groups: vec![PermissionGroupRef {
                    id: request.access.permission_group_id(),
                }],
            }],
        };
        let bytes = serde_json::to_vec(&body).map_err(|error| {
            CloudflareError::Config(format!("failed to encode R2 create-token request: {error}"))
        })?;

        let result: CreateTokenResult = self
            .request_json(HttpMethod::Post, ACCOUNT_TOKENS_PATH, Some(bytes), None)
            .await?;
        let value = result.value.ok_or_else(|| {
            CloudflareError::Decode(
                "Cloudflare create-token response omitted the token value (required to derive the \
                 R2 secret access key)"
                    .to_string(),
            )
        })?;

        Ok(R2ScopedToken {
            access_key_id: result.id.clone(),
            secret_access_key: sha256_hex(value.as_bytes()),
            token_id: result.id,
        })
    }

    /// Revoke (delete) a previously minted API token by its id. Ack-style (the
    /// endpoint returns a null/`{ "id": .. }` result). Idempotent-friendly for
    /// cleanup: any non-2xx surfaces as a typed [`CloudflareError`].
    pub async fn revoke_r2_token(&self, token_id: &str) -> Result<(), CloudflareError> {
        let path = account_token_path(token_id)?;
        self.request_ack(HttpMethod::Delete, &path, None, None)
            .await
    }

    /// Ensure a tenant's R2 bucket exists (create-if-absent, via #461's
    /// [`Self::ensure_tenant_r2_bucket`]) **and** mint a read+write credential
    /// scoped to just that bucket.
    ///
    /// The bucket step is idempotent; the token step mints a fresh scoped
    /// credential each call (tokens are not create-if-absent — see module docs),
    /// which the caller is responsible for storing. This is additive over #461:
    /// it does not change [`Self::ensure_tenant_r2_bucket`] or
    /// [`R2BucketProvision`].
    pub async fn ensure_tenant_r2_credentials(
        &self,
        tenant: &str,
    ) -> Result<R2CredentialProvision, CloudflareError> {
        let bucket = self.ensure_tenant_r2_bucket(tenant).await?;
        let request = R2ScopedTokenRequest::read_write(
            format!("ferrogate-r2-{}", bucket.name),
            bucket.name.clone(),
        );
        let token = self.create_scoped_r2_token(&request).await?;
        Ok(R2CredentialProvision { bucket, token })
    }
}

/// Build Cloudflare's R2 bucket resource-scope id:
/// `com.cloudflare.edge.r2.bucket.{account_id}_{jurisdiction}_{bucket}`.
fn r2_bucket_resource_scope(account_id: &str, jurisdiction: &str, bucket: &str) -> String {
    format!("com.cloudflare.edge.r2.bucket.{account_id}_{jurisdiction}_{bucket}")
}

/// Lowercase hex SHA-256 of the input — R2's secret-access-key derivation.
/// Dependency-free hex to match the workspace's existing SigV4 hex idiom.
fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Reject a bucket name that could break out of the `_`-delimited resource-scope
/// id (or escape a path). R2 bucket names are lowercase alphanumeric + hyphens;
/// anything else — including the `_` separator — is a caller bug surfaced before
/// any request is sent.
fn validate_bucket_name(bucket: &str) -> Result<(), CloudflareError> {
    if bucket.is_empty()
        || !bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(CloudflareError::Config(format!(
            "invalid R2 bucket name {bucket:?}: expected lowercase alphanumeric and hyphens"
        )));
    }
    Ok(())
}

/// Reject a jurisdiction segment that is not a bare lowercase-alpha token (e.g.
/// `default`, `eu`, `fedramp`), keeping the `_`-delimited resource id
/// unambiguous.
fn validate_jurisdiction(jurisdiction: &str) -> Result<(), CloudflareError> {
    if jurisdiction.is_empty() || !jurisdiction.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(CloudflareError::Config(format!(
            "invalid R2 jurisdiction {jurisdiction:?}: expected a lowercase-alpha token like \
             \"default\" or \"eu\""
        )));
    }
    Ok(())
}

/// Build the `accounts/{account_id}/tokens/{token_id}` revocation path, rejecting
/// a token id that could escape the path segment. Cloudflare token ids are hex,
/// so only ASCII alphanumerics are accepted.
fn account_token_path(token_id: &str) -> Result<String, CloudflareError> {
    if token_id.is_empty() || !token_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(CloudflareError::Config(format!(
            "invalid Cloudflare token id {token_id:?}: expected an alphanumeric id"
        )));
    }
    Ok(format!("accounts/{{account_id}}/tokens/{token_id}"))
}
