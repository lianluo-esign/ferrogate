// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: S3-compatible object-storage bucket client for `/v1/assets/*`
// content (issue #176) -- Supabase Storage exposes an S3-compatible API
// (same SigV4 auth AWS S3 uses), so this reuses the SigV4 signer already
// built and verified for the Bedrock adapter (`ferrogate-providers::sigv4`)
// rather than a second hand-rolled implementation. Content stays inline in
// `stored_assets.content` (the original #176 design) unless a bucket is
// configured via `[asset_bucket]`; when it is, `push`/`pull`/`delete`
// switch to this client and `stored_assets.storage_uri` records the
// object key instead of duplicating bytes in Postgres.
//
// Honest scope note: tested against a local mock S3-compatible HTTP
// server (asserting request shape: path-style URL, SigV4 headers,
// signed x-amz-content-sha256), the same testing philosophy as every
// other externally-facing adapter in this codebase (Bedrock, Vertex,
// Stripe) -- no live Supabase Storage bucket credentials were available
// to verify end-to-end against the real service, including its
// Row-Level Security tenant-isolation policies. That remains open on
// issue #176.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ferrogate_cloudflare::{CloudflareClient, HttpMethod};
use ferrogate_providers::{
    presign_sigv4_query, presign_sigv4_query_bound, sign_sigv4_with_content_hash_header,
    AwsCredentials, PresignBoundPayload, PresignRequest, SigningRequest,
};

use super::dispatch::provider_http_client;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetBucketConfig {
    /// `scheme://host[:port]`, no trailing slash and no bucket/key suffix
    /// -- e.g. `https://<project>.supabase.co/storage/v1/s3` for Supabase
    /// Storage's S3-compatible endpoint, or `http://127.0.0.1:PORT` for a
    /// local mock in tests.
    ///
    /// Cloudflare R2 (issue #410) is S3-compatible and slots in here with no
    /// client change: point this at the account's R2 S3 host
    /// `https://<account_id>.r2.cloudflarestorage.com` (or the jurisdiction
    /// hosts `<account_id>.eu.r2.cloudflarestorage.com` /
    /// `<account_id>.fedramp.r2.cloudflarestorage.com`), set `region` to R2's
    /// fixed [`R2_REGION`] (`auto`), and use an R2 Access Key ID + Secret
    /// (created via R2's Create-Token API) through the same `access_key_id` +
    /// `secret_access_key` pair. R2 buckets are addressed path-style
    /// (`/{bucket}/{key}`), which is exactly how this client already builds its
    /// object paths, and R2 accepts the real `x-amz-content-sha256` payload
    /// hash this client sends. `[asset_bucket]` targeting an R2 host is
    /// auto-detected and validated (see `validate_asset_bucket_r2`); no extra
    /// config marker is needed. NOTE: R2 buckets are private by default -- for
    /// *public* static serving you must attach a custom domain to the bucket
    /// (the `r2.dev` subdomain is rate-limited/dev-only); the gateway's
    /// presigned-GET path serves private objects without a public bucket.
    pub(crate) endpoint: String,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

/// The DNS suffix every Cloudflare R2 S3-API host ends with (issue #410).
/// The per-account host is `<account_id>.r2.cloudflarestorage.com`; the
/// jurisdiction hosts insert a `.eu.` / `.fedramp.` label before it.
pub(crate) const R2_ENDPOINT_SUFFIX: &str = "r2.cloudflarestorage.com";

/// R2's required SigV4 region. R2 ignores geographic regions and mandates the
/// literal `auto` in the credential scope (`.../auto/s3/aws4_request`); the
/// existing signer folds whatever region string it is given into the scope, so
/// setting this value is the only R2-specific config the SigV4 path needs.
pub(crate) const R2_REGION: &str = "auto";

/// A parsed Cloudflare R2 S3 endpoint (issue #410): the account id and the
/// optional data-residency jurisdiction (`eu` / `fedramp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct R2Endpoint {
    pub(crate) account_id: String,
    /// `None` for the default global host; `Some("eu")` / `Some("fedramp")`
    /// for the jurisdiction hosts.
    pub(crate) jurisdiction: Option<&'static str>,
}

/// Reduces `endpoint` to its bare host (drops scheme, any `:port`, and any
/// path suffix). Shared by the R2 detection/parsing helpers so they agree on
/// what "the host" is.
fn endpoint_host(endpoint: &str) -> &str {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    host.split(':').next().unwrap_or(host)
}

/// True when `endpoint`'s host is under the R2 S3 domain (any account /
/// jurisdiction), used to decide whether the R2-specific validation applies.
/// This is a permissive detector: it matches even a malformed R2 host (e.g. a
/// missing account label) so `validate_asset_bucket_r2` can reject that with a
/// clear error rather than silently treating it as a generic S3 endpoint.
pub(crate) fn endpoint_targets_r2(endpoint: &str) -> bool {
    let host = endpoint_host(endpoint);
    host == R2_ENDPOINT_SUFFIX || host.ends_with(&format!(".{R2_ENDPOINT_SUFFIX}"))
}

/// Strictly parses an R2 S3 endpoint of the form
/// `https://<account_id>.r2.cloudflarestorage.com` (optionally with a
/// `.eu.` / `.fedramp.` jurisdiction label). Returns `None` when the host is
/// not R2 *or* is malformed (empty / multi-label account id). The account id
/// must be a single DNS label (no dots), matching R2's 32-hex-char account id.
pub(crate) fn parse_r2_endpoint(endpoint: &str) -> Option<R2Endpoint> {
    let host = endpoint_host(endpoint);
    // `<...>.r2.cloudflarestorage.com` -> `<...>` (with its trailing dot).
    let prefix = host.strip_suffix(R2_ENDPOINT_SUFFIX)?.strip_suffix('.')?; // reject the bare suffix domain (empty account)
    let (account_id, jurisdiction) = if let Some(account) = prefix.strip_suffix(".eu") {
        (account, Some("eu"))
    } else if let Some(account) = prefix.strip_suffix(".fedramp") {
        (account, Some("fedramp"))
    } else {
        (prefix, None)
    };
    // A valid account id is a single, non-empty DNS label.
    if account_id.is_empty() || account_id.contains('.') {
        return None;
    }
    Some(R2Endpoint {
        account_id: account_id.to_string(),
        jurisdiction,
    })
}

pub(crate) struct AssetBucketClient {
    config: AssetBucketConfig,
}

/// A bound presigned upload (issue #368): the URL plus the exact request
/// headers the holder must send verbatim on the direct PUT. The headers are
/// inside the URL's SigV4 signature, so they are a contract, not a hint.
pub(crate) struct PresignedUpload {
    pub(crate) url: String,
    /// `(header name, value)` pairs; `host` is also signed but derives from
    /// the URL itself.
    pub(crate) required_headers: Vec<(&'static str, String)>,
}

/// The object-storage backend seam for `/v1/assets/*` content (issue #411).
///
/// Extracted from [`AssetBucketClient`]'s inherent methods so the asset
/// pipeline funnels every read/write through one `dyn` boundary instead of a
/// single concrete S3 client. The existing S3/R2 client implements it with NO
/// behavior change (the trait methods forward to the same inherent SigV4/R2
/// methods); a Cloudflare-native publish backend
/// ([`WorkersStaticAssetsStore`]) implements the same seam for a
/// non-S3-shaped target and returns a clear `Unsupported`-style error for the
/// S3-only operations (presign, arbitrary GET/HEAD/LIST) it cannot serve.
///
/// Method signatures are byte-for-byte the current [`AssetBucketClient`]
/// signatures so the accessor swap is the only call-site change.
#[async_trait]
pub(crate) trait AssetObjectStore: Send + Sync {
    async fn put_object(&self, key: &str, body: &[u8], content_type: &str) -> anyhow::Result<()>;
    async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()>;
    async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>>;
    async fn get_object_if_present(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn delete_object(&self, key: &str) -> anyhow::Result<()>;
    async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>>;
    async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>>;
    fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
        size_bytes: u64,
        content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload>;
    fn presign_get(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String>;
}

/// Forwarding impl so a `Box<dyn AssetObjectStore>` (what the accessor hands
/// out) is itself an [`AssetObjectStore`] — this lets the helper functions
/// that take `&dyn AssetObjectStore` be called with a plain `&boxed_client`
/// (deref/unsize) without every call site spelling out `.as_ref()`.
#[async_trait]
impl AssetObjectStore for Box<dyn AssetObjectStore> {
    async fn put_object(&self, key: &str, body: &[u8], content_type: &str) -> anyhow::Result<()> {
        self.as_ref().put_object(key, body, content_type).await
    }
    async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        self.as_ref()
            .put_object_owned(key, body, content_type)
            .await
    }
    async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        self.as_ref().get_object(key).await
    }
    async fn get_object_if_present(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.as_ref().get_object_if_present(key).await
    }
    async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        self.as_ref().delete_object(key).await
    }
    async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>> {
        self.as_ref().head_object(key).await
    }
    async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        self.as_ref().list_objects().await
    }
    fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
        size_bytes: u64,
        content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        self.as_ref().presign_put(
            key,
            expires_secs,
            timestamp_unix,
            size_bytes,
            content_sha256_hex,
        )
    }
    fn presign_get(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        self.as_ref().presign_get(key, expires_secs, timestamp_unix)
    }
}

/// The S3/R2 backend behind the trait (issue #411). Every method forwards to
/// the identically-named inherent method, so the SigV4/R2 request shaping is
/// unchanged — the trait is a pure indirection layer over the existing client.
#[async_trait]
impl AssetObjectStore for AssetBucketClient {
    async fn put_object(&self, key: &str, body: &[u8], content_type: &str) -> anyhow::Result<()> {
        AssetBucketClient::put_object(self, key, body, content_type).await
    }
    async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        AssetBucketClient::put_object_owned(self, key, body, content_type).await
    }
    async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        AssetBucketClient::get_object(self, key).await
    }
    async fn get_object_if_present(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        AssetBucketClient::get_object_if_present(self, key).await
    }
    async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        AssetBucketClient::delete_object(self, key).await
    }
    async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>> {
        AssetBucketClient::head_object(self, key).await
    }
    async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        AssetBucketClient::list_objects(self).await
    }
    fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
        size_bytes: u64,
        content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        AssetBucketClient::presign_put(
            self,
            key,
            expires_secs,
            timestamp_unix,
            size_bytes,
            content_sha256_hex,
        )
    }
    fn presign_get(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        AssetBucketClient::presign_get(self, key, expires_secs, timestamp_unix)
    }
}

impl AssetBucketClient {
    pub(crate) fn new(config: AssetBucketConfig) -> Self {
        Self { config }
    }

    pub(crate) async fn put_object(
        &self,
        key: &str,
        body: &[u8],
        content_type: &str,
    ) -> anyhow::Result<()> {
        self.put_object_owned(key, body.to_vec(), content_type)
            .await
    }

    /// PUTs an owned object buffer without cloning it for the HTTP request.
    /// The presigned commit path already owns the verified bytes and may hold
    /// up to the configured multi-gigabyte ceiling, so a second full copy is
    /// not acceptable there.
    pub(crate) async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("PUT", &path, &host, &body);
        let client = provider_http_client()?;
        let mut request = client
            .put(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone())
            .header("content-type", content_type)
            .body(body);
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket PUT failed (HTTP {status}): {text}");
        }
        Ok(())
    }

    pub(crate) async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        self.get_object_if_present(key).await?.ok_or_else(|| {
            anyhow::anyhow!("asset bucket GET failed (HTTP 404 Not Found): object does not exist")
        })
    }

    /// GETs an object while preserving a missing-key result for commit-race
    /// reconciliation. Other bucket failures remain explicit errors.
    pub(crate) async fn get_object_if_present(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("GET", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .get(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket GET failed (HTTP {status}): {text}");
        }
        Ok(Some(response.bytes().await?.to_vec()))
    }

    pub(crate) async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("DELETE", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .delete(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        // A 404 on delete is not an error here: the caller already knows
        // the `stored_assets` row existed (it's deleting the DB row in
        // the same operation), so a missing bucket object is at worst a
        // prior inconsistency, not something to fail the whole delete on.
        if !status.is_success() && status.as_u16() != 404 {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket DELETE failed (HTTP {status}): {text}");
        }
        Ok(())
    }

    /// HEAD the object, returning its size (`Content-Length`) or `None`
    /// when it does not exist (404). The large-file commit path (issue
    /// #259) uses this to gate the object's size against the registered
    /// intent *before* downloading it for the sha256 + supply-chain checks.
    pub(crate) async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("HEAD", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .head(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket HEAD failed (HTTP {status}): {text}");
        }
        let size = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("asset bucket HEAD returned no valid Content-Length"))?;
        Ok(Some(size))
    }

    /// Lists every object in the bucket (following continuation tokens) as
    /// `(key, last_modified_unix)` pairs -- the #263 unreferenced-blob GC
    /// reconcile pass compares these against the registry's `storage_uri`s.
    /// Signs a `ListObjectsV2` (`GET /{bucket}?list-type=2&...`) with the query
    /// folded into the SigV4 signature (unlike object PUT/GET/DELETE, whose
    /// query is empty). The `LastModified` timestamp is parsed to unix seconds;
    /// an unparseable one yields `0`, which the GC planner treats as
    /// too-new-to-delete (fail-safe KEEP).
    pub(crate) async fn list_objects(
        &self,
    ) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = format!("/{}", self.config.bucket);
        let client = provider_http_client()?;
        let mut objects = Vec::new();
        let mut continuation_token: Option<String> = None;
        // Bound the pagination loop so a pathological bucket can never spin
        // forever; 1000 keys/page * 1000 pages is 1M objects per pass.
        for _ in 0..1_000 {
            let mut params: Vec<(&str, &str)> = vec![("list-type", "2")];
            if let Some(token) = continuation_token.as_deref() {
                params.push(("continuation-token", token));
            }
            let canonical_query = ferrogate_providers::sigv4_canonical_query_string(&params);
            let timestamp_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let signed = ferrogate_providers::sign_sigv4_with_content_hash_header_and_query(
                &SigningRequest {
                    method: "GET",
                    path: &path,
                    host: &host,
                    region: &self.config.region,
                    service: "s3",
                    body: b"",
                    timestamp_unix,
                },
                &AwsCredentials {
                    access_key_id: self.config.access_key_id.clone(),
                    secret_access_key: self.config.secret_access_key.clone(),
                    session_token: None,
                },
                &canonical_query,
            );
            let mut request = client
                .get(format!("{scheme}://{host}{path}?{canonical_query}"))
                .header("host", host.clone())
                .header("x-amz-date", signed.x_amz_date.clone())
                .header("authorization", signed.authorization.clone());
            if let Some(content_sha256) = &signed.x_amz_content_sha256 {
                request = request.header("x-amz-content-sha256", content_sha256.clone());
            }
            let response = request.send().await?;
            let status = response.status();
            if !status.is_success() {
                let text = response.text().await.unwrap_or_default();
                anyhow::bail!("asset bucket LIST failed (HTTP {status}): {text}");
            }
            let body = response.text().await?;
            objects.extend(parse_list_objects_v2(&body));
            match next_continuation_token(&body) {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }
        Ok(objects)
    }

    /// Issues a short-TTL SigV4 query-string presigned upload URL (issue
    /// #259), *bound* to the declared payload size + SHA-256 (issue #368):
    /// `content-length` and `x-amz-content-sha256` are SigV4 signed headers
    /// and the canonical request's payload-hash line carries the declared
    /// checksum instead of `UNSIGNED-PAYLOAD`. The holder PUTs the object
    /// bytes straight to the bucket (bypassing the gateway hot path) but
    /// MUST send `required_headers` verbatim -- changing the size, the
    /// checksum, or the bytes invalidates the upload authorization at the
    /// bucket boundary itself, before the gateway's commit-time
    /// verification ever runs.
    pub(crate) fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
        size_bytes: u64,
        content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let bound = presign_sigv4_query_bound(
            &PresignRequest {
                method: "PUT",
                path: &path,
                host: &host,
                region: &self.config.region,
                service: "s3",
                expires_secs,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
            &PresignBoundPayload {
                content_length: size_bytes,
                content_sha256_hex,
            },
        );
        Ok(PresignedUpload {
            url: format!("{scheme}://{host}{path}?{}", bound.query),
            required_headers: bound.required_headers,
        })
    }

    /// Issues a short-TTL SigV4 query-string presigned download URL (issue
    /// #259) so reads never require the bucket to be public.
    pub(crate) fn presign_get(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        self.presign_url("GET", key, expires_secs, timestamp_unix)
    }

    fn presign_url(
        &self,
        method: &'static str,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let query = presign_sigv4_query(
            &PresignRequest {
                method,
                path: &path,
                host: &host,
                region: &self.config.region,
                service: "s3",
                expires_secs,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
        );
        Ok(format!("{scheme}://{host}{path}?{query}"))
    }

    fn object_path(&self, key: &str) -> String {
        format!("/{}/{key}", self.config.bucket)
    }

    fn sign(
        &self,
        method: &'static str,
        path: &str,
        host: &str,
        body: &[u8],
    ) -> ferrogate_providers::SignedHeaders {
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        sign_sigv4_with_content_hash_header(
            &SigningRequest {
                method,
                path,
                host,
                region: &self.config.region,
                service: "s3",
                body,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
        )
    }

    /// Extracts `(scheme, host[:port])` from `config.endpoint` -- mirrors
    /// `bedrock.rs::extract_host`'s http-preserved-for-tests /
    /// https-otherwise convention, duplicated here rather than shared
    /// since it's a trivial ~10-line helper and the two crates don't
    /// otherwise need a shared utilities module for it.
    fn scheme_and_host(&self) -> anyhow::Result<(&'static str, String)> {
        let trimmed = self.config.endpoint.trim_end_matches('/');
        let scheme = if trimmed.starts_with("http://") {
            "http"
        } else {
            "https"
        };
        let host = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);
        if host.is_empty() {
            anyhow::bail!("asset_bucket.endpoint {} has no host", self.config.endpoint);
        }
        Ok((scheme, host.to_string()))
    }
}

// ---- Cloudflare Workers Static Assets backend (issue #411) ------------------

/// One entry in a Workers Static Assets upload manifest: the content hash the
/// direct-upload session is keyed on plus the file's byte length.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct AssetManifestEntry {
    hash: String,
    size: u64,
}

/// A Workers Static Assets upload manifest: `path -> (hash, size)`.
///
/// This is the body Cloudflare's `assets-upload-session` endpoint negotiates
/// against — it replies with which content hashes still need their bytes
/// uploaded. Paths are site-root-relative and always start with `/`.
#[derive(Debug, Clone, Default)]
pub(crate) struct AssetUploadManifest {
    files: BTreeMap<String, AssetManifestEntry>,
}

/// Cloudflare's manifest hash width. CF keys the direct-upload session on a
/// 32-hex-char content hash (a SHA-256 prefix); the exact CF hashing recipe is
/// pinned by the live publish test-agent, but the request-construction seam
/// here computes a deterministic SHA-256 prefix so the manifest shape and the
/// bucket-negotiation round-trip are unit-testable offline.
const CF_ASSET_HASH_HEX_LEN: usize = 32;

impl AssetUploadManifest {
    /// A single-file manifest for `path` holding `body` — the shape a
    /// per-object publish negotiates. `path` is normalized to a leading `/`.
    pub(crate) fn single(path: &str, body: &[u8]) -> Self {
        let mut files = BTreeMap::new();
        files.insert(
            normalize_asset_path(path),
            AssetManifestEntry::for_bytes(body),
        );
        Self { files }
    }

    /// The number of files described. (Kept small on purpose — the manifest is
    /// a plan, not the bytes.)
    pub(crate) fn len(&self) -> usize {
        self.files.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The `{ "manifest": { ... } }` JSON body the upload-session endpoint
    /// expects.
    fn request_body(&self) -> serde_json::Value {
        serde_json::json!({ "manifest": self.files })
    }
}

impl AssetManifestEntry {
    fn for_bytes(body: &[u8]) -> Self {
        let mut hash = ferrogate_storage::sha256_hex(body);
        hash.truncate(CF_ASSET_HASH_HEX_LEN);
        Self {
            hash,
            size: body.len() as u64,
        }
    }
}

/// Normalizes an asset key to a Workers-Static-Assets site path (leading `/`,
/// no duplicate slashes at the root).
fn normalize_asset_path(key: &str) -> String {
    let trimmed = key.trim_start_matches('/');
    format!("/{trimmed}")
}

/// The decoded `result` of a Workers Static Assets upload-session negotiation:
/// a JWT authorizing the follow-up file upload and the buckets of content
/// hashes whose bytes CF still needs. Empty `buckets` means every asset is
/// already present server-side.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(crate) struct UploadSession {
    #[serde(default)]
    pub(crate) jwt: Option<String>,
    #[serde(default)]
    pub(crate) buckets: Vec<Vec<String>>,
}

/// A Cloudflare-native static-asset publish backend built on Workers Static
/// Assets (issue #411). NOT S3-shaped: it publishes a bundle through the CF
/// direct-upload flow rather than exposing arbitrary object GET/HEAD/LIST or
/// SigV4 presign. Wired through the shared [`CloudflareClient`] so the publish
/// request construction is unit-testable against a mocked transport.
///
/// Publish is a 3-step flow: (1) negotiate an upload session against a file
/// manifest, (2) upload the pending file bytes referencing the session JWT,
/// (3) PUT the Worker script referencing the completion token. Only step 1 is
/// a plain JSON request the shared client models today; steps 2-3 use the
/// multipart direct-upload transport and are the live-publish path owned by
/// the #411 test-agent. This backend therefore constructs and issues step 1
/// (mock-tested) and refuses to claim a durable publish it has not completed.
pub(crate) struct WorkersStaticAssetsStore {
    client: Arc<CloudflareClient>,
    script_name: String,
}

impl WorkersStaticAssetsStore {
    pub(crate) fn new(client: Arc<CloudflareClient>, script_name: String) -> Self {
        Self {
            client,
            script_name,
        }
    }

    /// Step 1 of the Workers Static Assets direct upload: negotiate an upload
    /// session for `manifest`. Issues
    /// `POST /accounts/{account_id}/workers/scripts/{script}/assets-upload-session`
    /// through the shared client and decodes the `{ jwt, buckets }` result.
    pub(crate) async fn create_upload_session(
        &self,
        manifest: &AssetUploadManifest,
    ) -> anyhow::Result<UploadSession> {
        let path = format!(
            "accounts/{{account_id}}/workers/scripts/{}/assets-upload-session",
            self.script_name
        );
        let body = serde_json::to_vec(&manifest.request_body())?;
        let session = self
            .client
            .request_json::<UploadSession>(HttpMethod::Post, &path, Some(body), None)
            .await
            .map_err(|error| {
                anyhow::anyhow!("workers-static-assets upload-session negotiation failed: {error}")
            })?;
        Ok(session)
    }

    /// The publish path for a single asset. Negotiates the upload session
    /// (step 1) and then reports honestly that the direct byte upload + Worker
    /// script deploy (steps 2-3) are not yet wired for a live publish — it does
    /// NOT fake a durable publish from a negotiated session alone.
    async fn publish_object(&self, key: &str, body: &[u8]) -> anyhow::Result<()> {
        let manifest = AssetUploadManifest::single(key, body);
        if manifest.is_empty() {
            anyhow::bail!("workers-static-assets: refusing to publish an empty manifest");
        }
        let session = self.create_upload_session(&manifest).await?;
        // The negotiation succeeded; the completion JWT authorizes steps 2-3.
        let jwt_state = if session.jwt.is_some() {
            "a completion JWT was issued"
        } else {
            "no completion JWT was returned"
        };
        anyhow::bail!(
            "workers-static-assets: negotiated an upload session for {} file(s) ({jwt_state}, {} \
             bucket(s) pending upload), but the direct byte upload and Worker script deploy (steps \
             2-3 of the Cloudflare direct-upload flow) are not yet wired for live publish (issue \
             #411 test-agent follow-up); this backend does not claim a durable publish it has not \
             completed",
            manifest.len(),
            session.buckets.len(),
        )
    }
}

/// The clear error the CF-native backend returns for an S3-only operation it
/// structurally cannot serve (arbitrary GET/HEAD/LIST/DELETE by key, or SigV4
/// presign). CF Workers Static Assets serves published bundles from the edge
/// under a route/custom domain, not as a keyed private object store.
fn workers_static_assets_unsupported(operation: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "workers-static-assets backend does not support {operation}: it is a static-site publish \
         target served from Cloudflare's edge, not an S3-style keyed object store or a SigV4 \
         presign source"
    )
}

#[async_trait]
impl AssetObjectStore for WorkersStaticAssetsStore {
    async fn put_object(&self, key: &str, body: &[u8], _content_type: &str) -> anyhow::Result<()> {
        self.publish_object(key, body).await
    }
    async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        _content_type: &str,
    ) -> anyhow::Result<()> {
        self.publish_object(key, &body).await
    }
    async fn get_object(&self, _key: &str) -> anyhow::Result<Vec<u8>> {
        Err(workers_static_assets_unsupported("object GET by key"))
    }
    async fn get_object_if_present(&self, _key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Err(workers_static_assets_unsupported("object GET by key"))
    }
    async fn delete_object(&self, _key: &str) -> anyhow::Result<()> {
        Err(workers_static_assets_unsupported("object DELETE by key"))
    }
    async fn head_object(&self, _key: &str) -> anyhow::Result<Option<u64>> {
        Err(workers_static_assets_unsupported("object HEAD by key"))
    }
    async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        Err(workers_static_assets_unsupported("object listing"))
    }
    fn presign_put(
        &self,
        _key: &str,
        _expires_secs: u64,
        _timestamp_unix: u64,
        _size_bytes: u64,
        _content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        Err(workers_static_assets_unsupported("SigV4 presigned upload"))
    }
    fn presign_get(
        &self,
        _key: &str,
        _expires_secs: u64,
        _timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        Err(workers_static_assets_unsupported(
            "SigV4 presigned download",
        ))
    }
}

/// Extracts `<Contents>` entries from a `ListObjectsV2` XML body as
/// `(Key, last_modified_unix)`. Deliberately a tiny, dependency-free tag
/// scanner rather than a full XML parser: the S3 `ListObjectsV2` shape is
/// fixed and shallow, and every other externally-facing adapter here parses
/// only the fields it needs. An entry missing/holding an unparseable
/// `LastModified` gets `0`, which the GC planner treats as unknown-age =>
/// KEEP (fail-safe).
fn parse_list_objects_v2(xml: &str) -> Vec<ferrogate_storage::BucketObject> {
    let mut objects = Vec::new();
    for contents in extract_tags(xml, "Contents") {
        let Some(key) = extract_tag(&contents, "Key") else {
            continue;
        };
        let last_modified_unix = extract_tag(&contents, "LastModified")
            .and_then(|value| parse_rfc3339_unix(&value))
            .unwrap_or(0);
        objects.push(ferrogate_storage::BucketObject {
            key,
            last_modified_unix,
        });
    }
    objects
}

/// The truncation continuation token, present only when the listing is paged.
fn next_continuation_token(xml: &str) -> Option<String> {
    let truncated = extract_tag(xml, "IsTruncated")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !truncated {
        return None;
    }
    extract_tag(xml, "NextContinuationToken").filter(|token| !token.is_empty())
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml_unescape(&xml[start..end]))
}

fn extract_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(rel_start) = xml[cursor..].find(&open) {
        let start = cursor + rel_start + open.len();
        let Some(rel_end) = xml[start..].find(&close) else {
            break;
        };
        let end = start + rel_end;
        out.push(xml[start..end].to_string());
        cursor = end + close.len();
    }
    out
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Parses an S3 `LastModified` RFC3339/ISO-8601 timestamp to unix seconds.
fn parse_rfc3339_unix(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|datetime| datetime.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        body: Vec<u8>,
        has_authorization: bool,
        content_sha256_header: Option<String>,
    }

    /// A one-shot mock S3-compatible endpoint: accepts exactly one
    /// request, records its shape, and replies with a fixed status/body.
    /// Mirrors `payments.rs`'s `spawn_stripe_mock` pattern.
    fn spawn_bucket_mock(
        response_status: &'static str,
        response_body: &'static [u8],
    ) -> (String, Arc<Mutex<Option<CapturedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let server_captured = Arc::clone(&captured);

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
            }
            let body = raw[header_end..header_end + content_length].to_vec();
            let request_line = head.lines().next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            let has_authorization = head
                .to_lowercase()
                .contains("authorization: aws4-hmac-sha256");
            let content_sha256_header = head.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("x-amz-content-sha256")
                        .then(|| value.trim().to_string())
                })
            });
            *server_captured.lock().unwrap() = Some(CapturedRequest {
                method,
                path,
                body,
                has_authorization,
                content_sha256_header,
            });

            let response = format!(
                "HTTP/1.1 {response_status}\r\nContent-Length: {}\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(response_body).unwrap();
        });

        (endpoint, captured)
    }

    fn client(endpoint: String) -> AssetBucketClient {
        AssetBucketClient::new(AssetBucketConfig {
            endpoint,
            bucket: "ferrogate-assets".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        })
    }

    #[tokio::test]
    async fn put_object_sends_a_signed_path_style_request_with_the_body() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let bucket = client(endpoint);

        bucket
            .put_object(
                "tenant-a:cli_tool:hello:1.0.0",
                b"asset bytes",
                "text/plain",
            )
            .await
            .unwrap();

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "PUT");
        assert_eq!(
            request.path,
            "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0"
        );
        assert_eq!(request.body, b"asset bytes");
        assert!(request.has_authorization);
        assert!(request.content_sha256_header.is_some());
        assert!(!format!("{request:?}").contains("wJalrXUtnFEMI"));
    }

    #[tokio::test]
    async fn get_object_returns_the_response_body() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"fetched bytes");
        let bucket = client(endpoint);

        let bytes = bucket
            .get_object("tenant-a:cli_tool:hello:1.0.0")
            .await
            .unwrap();
        assert_eq!(bytes, b"fetched bytes");

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.has_authorization);
    }

    #[tokio::test]
    async fn get_object_errors_on_a_non_success_status() {
        let (endpoint, _captured) = spawn_bucket_mock("404 Not Found", b"no such key");
        let bucket = client(endpoint);

        let error = bucket
            .get_object("tenant-a:cli_tool:missing:1.0.0")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("404"));
    }

    #[tokio::test]
    async fn delete_object_treats_404_as_success() {
        let (endpoint, captured) = spawn_bucket_mock("404 Not Found", b"");
        let bucket = client(endpoint);

        bucket
            .delete_object("tenant-a:cli_tool:already-gone:1.0.0")
            .await
            .unwrap();

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "DELETE");
    }

    #[test]
    fn presign_put_builds_a_bound_path_style_sigv4_query_string_url_with_a_bounded_ttl() {
        let bucket = client("https://project.supabase.co/storage/v1/s3".into());
        let sha = "a".repeat(64);
        let upload = bucket
            .presign_put(
                "tenant-a:cli_tool:hello:1.0.0",
                900,
                1_440_938_160,
                42,
                &sha,
            )
            .unwrap();

        // Path-style URL against the configured endpoint host + bucket/key.
        assert!(upload.url.starts_with(
            "https://project.supabase.co/storage/v1/s3/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0?"
        ));
        // SigV4 query-string presign markers, bounded TTL, and a signature.
        assert!(upload.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(upload.url.contains("X-Amz-Expires=900"));
        // #368: the declared size + checksum headers join `host` in the
        // signed set, so the URL only authorizes the exact approved payload.
        assert!(upload
            .url
            .contains("X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256"));
        assert!(upload.url.contains("X-Amz-Signature="));
        assert_eq!(
            upload.required_headers,
            vec![
                ("content-length", "42".to_string()),
                ("x-amz-content-sha256", sha),
            ]
        );
        // The secret key never leaks into the URL.
        assert!(!upload.url.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn presign_put_signature_depends_on_the_declared_size_and_checksum() {
        // #368: a different declared size or checksum is a different signed
        // capability -- the bucket rejects a URL replayed against either.
        let bucket = client("http://127.0.0.1:9999".into());
        let sig = |size: u64, sha: &str| {
            bucket
                .presign_put("k", 300, 1_440_938_160, size, sha)
                .unwrap()
                .url
                .rsplit("X-Amz-Signature=")
                .next()
                .unwrap()
                .to_string()
        };
        let base = sig(42, &"a".repeat(64));
        assert_ne!(base, sig(43, &"a".repeat(64)), "size is signed");
        assert_ne!(base, sig(42, &"b".repeat(64)), "checksum is signed");
        assert_eq!(
            base,
            sig(42, &"a".repeat(64)),
            "same declaration re-signs identically"
        );
    }

    #[test]
    fn presign_get_and_presign_put_sign_the_same_key_differently() {
        let bucket = client("http://127.0.0.1:9999".into());
        let put = bucket
            .presign_put("k", 300, 1_440_938_160, 42, &"a".repeat(64))
            .unwrap()
            .url;
        let get = bucket.presign_get("k", 300, 1_440_938_160).unwrap();
        assert!(put.starts_with("http://127.0.0.1:9999/ferrogate-assets/k?"));
        let put_sig = put.rsplit("X-Amz-Signature=").next().unwrap();
        let get_sig = get.rsplit("X-Amz-Signature=").next().unwrap();
        assert_ne!(
            put_sig, get_sig,
            "PUT and GET presigns of the same key must differ (method and header set are signed)"
        );
    }

    #[tokio::test]
    async fn head_object_returns_the_content_length() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let bucket = client(endpoint);

        let size = bucket
            .head_object("tenant-a:cli_tool:hello:1.0.0")
            .await
            .unwrap();
        // The mock echoes the request body length as Content-Length (0 here).
        assert_eq!(size, Some(0));
        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "HEAD");
        assert!(request.has_authorization);
    }

    #[tokio::test]
    async fn head_object_returns_none_on_404() {
        let (endpoint, _captured) = spawn_bucket_mock("404 Not Found", b"");
        let bucket = client(endpoint);
        let size = bucket
            .head_object("tenant-a:cli_tool:missing:1.0.0")
            .await
            .unwrap();
        assert_eq!(size, None);
    }

    #[tokio::test]
    async fn list_objects_parses_signed_list_v2_contents() {
        // #263: a ListObjectsV2 XML body maps to (key, last_modified_unix)
        // pairs; the request is a signed GET carrying the list-type=2 query.
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <IsTruncated>false</IsTruncated>\
            <Contents><Key>t1:cli_tool:rg:1.0.0</Key>\
            <LastModified>2026-07-19T12:00:00.000Z</LastModified></Contents>\
            <Contents><Key>t1:cli_tool:orphan:9.9.9</Key>\
            <LastModified>2020-01-01T00:00:00Z</LastModified></Contents>\
            </ListBucketResult>";
        let (endpoint, captured) = spawn_bucket_mock("200 OK", xml.as_bytes());
        let bucket = client(endpoint);

        let objects = bucket.list_objects().await.unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].key, "t1:cli_tool:rg:1.0.0");
        assert_eq!(objects[0].last_modified_unix, 1_784_462_400);
        assert_eq!(objects[1].key, "t1:cli_tool:orphan:9.9.9");
        assert_eq!(objects[1].last_modified_unix, 1_577_836_800);

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.path.starts_with("/ferrogate-assets?"));
        assert!(request.path.contains("list-type=2"));
        assert!(request.has_authorization);
    }

    #[test]
    fn parse_list_objects_v2_defaults_unparseable_timestamps_to_zero() {
        let xml = "<Contents><Key>k</Key><LastModified>not-a-date</LastModified></Contents>";
        let objects = parse_list_objects_v2(xml);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "k");
        assert_eq!(objects[0].last_modified_unix, 0);
    }

    #[test]
    fn next_continuation_token_only_when_truncated() {
        let truncated =
            "<IsTruncated>true</IsTruncated><NextContinuationToken>abc</NextContinuationToken>";
        assert_eq!(next_continuation_token(truncated), Some("abc".to_string()));
        let done =
            "<IsTruncated>false</IsTruncated><NextContinuationToken>abc</NextContinuationToken>";
        assert_eq!(next_continuation_token(done), None);
    }

    #[test]
    fn scheme_and_host_preserves_http_for_local_mocks_and_defaults_to_https() {
        let http_bucket = client("http://127.0.0.1:9999".into());
        assert_eq!(
            http_bucket.scheme_and_host().unwrap(),
            ("http", "127.0.0.1:9999".to_string())
        );

        let https_bucket = client("https://project.supabase.co/storage/v1/s3".into());
        assert_eq!(
            https_bucket.scheme_and_host().unwrap(),
            ("https", "project.supabase.co/storage/v1/s3".to_string())
        );
    }

    // ---- Cloudflare R2 (issue #410) -----------------------------------------

    /// SHA-256 of the empty string -- the payload hash the signer emits for a
    /// bodyless GET/DELETE/HEAD. R2 requires this real hash (not a stub) in the
    /// signed `x-amz-content-sha256`, so asserting it here pins the quirk.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn r2_client(endpoint: &str) -> AssetBucketClient {
        AssetBucketClient::new(AssetBucketConfig {
            endpoint: endpoint.to_string(),
            bucket: "ferrogate-assets".into(),
            region: R2_REGION.into(),
            access_key_id: "R2ACCESSKEYID".into(),
            secret_access_key: "0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
        })
    }

    #[test]
    fn parse_r2_endpoint_accepts_the_default_and_jurisdiction_hosts() {
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.r2.cloudflarestorage.com"),
            Some(R2Endpoint {
                account_id: "abc123def456".into(),
                jurisdiction: None,
            })
        );
        // Trailing slash and virtual-host-irrelevant path suffixes are ignored;
        // R2 addresses buckets path-style.
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.r2.cloudflarestorage.com/"),
            Some(R2Endpoint {
                account_id: "abc123def456".into(),
                jurisdiction: None,
            })
        );
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.eu.r2.cloudflarestorage.com"),
            Some(R2Endpoint {
                account_id: "abc123def456".into(),
                jurisdiction: Some("eu"),
            })
        );
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.fedramp.r2.cloudflarestorage.com"),
            Some(R2Endpoint {
                account_id: "abc123def456".into(),
                jurisdiction: Some("fedramp"),
            })
        );
    }

    #[test]
    fn parse_r2_endpoint_rejects_non_r2_and_malformed_hosts() {
        // Not an R2 host at all.
        assert_eq!(
            parse_r2_endpoint("https://project.supabase.co/storage/v1/s3"),
            None
        );
        assert_eq!(parse_r2_endpoint("http://127.0.0.1:9999"), None);
        // The bare suffix domain with no account label.
        assert_eq!(parse_r2_endpoint("https://r2.cloudflarestorage.com"), None);
        assert_eq!(parse_r2_endpoint("https://.r2.cloudflarestorage.com"), None);
    }

    #[test]
    fn endpoint_targets_r2_detects_r2_even_when_the_account_label_is_malformed() {
        assert!(endpoint_targets_r2(
            "https://abc123def456.r2.cloudflarestorage.com"
        ));
        assert!(endpoint_targets_r2(
            "https://abc123def456.eu.r2.cloudflarestorage.com"
        ));
        // Malformed-but-clearly-R2 so validation can reject it with a clear error.
        assert!(endpoint_targets_r2("https://.r2.cloudflarestorage.com"));
        // Non-R2 endpoints must not trip the R2-specific validation.
        assert!(!endpoint_targets_r2(
            "https://project.supabase.co/storage/v1/s3"
        ));
        assert!(!endpoint_targets_r2("http://127.0.0.1:9999"));
    }

    #[test]
    fn r2_scheme_and_host_yields_the_account_host_for_the_signed_host_header() {
        let bucket = r2_client("https://abc123def456.r2.cloudflarestorage.com");
        assert_eq!(
            bucket.scheme_and_host().unwrap(),
            ("https", "abc123def456.r2.cloudflarestorage.com".to_string())
        );
    }

    #[test]
    fn r2_put_signs_host_region_auto_and_a_real_payload_hash() {
        // The three SigV4 quirks R2 cares about, on a non-presigned PUT:
        //   * `host` header = the account R2 host (signed),
        //   * region `auto` in the credential scope,
        //   * a real `x-amz-content-sha256` (not UNSIGNED-PAYLOAD), path-style.
        let bucket = r2_client("https://abc123def456.r2.cloudflarestorage.com");
        let (_scheme, host) = bucket.scheme_and_host().unwrap();
        let path = bucket.object_path("tenant-a:cli_tool:hello:1.0.0");
        assert_eq!(path, "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0");

        let signed = bucket.sign("PUT", &path, &host, b"asset bytes");
        assert!(
            signed.authorization.contains("/auto/s3/aws4_request"),
            "credential scope must carry region `auto`: {}",
            signed.authorization
        );
        assert!(signed
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // A concrete body hash, not a stub or UNSIGNED-PAYLOAD -- R2 verifies
        // it. A 64-char lowercase-hex digest that differs from the empty-body
        // hash proves the real payload was hashed.
        let hash = signed.x_amz_content_sha256.expect("content hash header");
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(hash, EMPTY_SHA256);
    }

    #[test]
    fn r2_get_signs_the_empty_payload_hash() {
        let bucket = r2_client("https://abc123def456.eu.r2.cloudflarestorage.com");
        let (_scheme, host) = bucket.scheme_and_host().unwrap();
        let signed = bucket.sign("GET", "/ferrogate-assets/k", &host, b"");
        assert_eq!(signed.x_amz_content_sha256.as_deref(), Some(EMPTY_SHA256));
        assert!(signed.authorization.contains("/auto/s3/aws4_request"));
    }

    #[test]
    fn r2_presign_get_is_well_formed_path_style_with_region_auto() {
        let bucket = r2_client("https://abc123def456.r2.cloudflarestorage.com");
        let url = bucket
            .presign_get("tenant-a:cli_tool:hello:1.0.0", 900, 1_440_938_160)
            .unwrap();
        assert!(url.starts_with(
            "https://abc123def456.r2.cloudflarestorage.com/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0?"
        ));
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Expires=900"));
        // The credential scope (URL-encoded) pins region `auto` + service `s3`.
        assert!(url.contains("%2Fauto%2Fs3%2Faws4_request"));
        assert!(url.contains("X-Amz-Signature="));
        // The secret never leaks into the URL.
        assert!(!url.contains("0000000000000000"));
    }

    #[test]
    fn r2_presign_put_binds_size_and_checksum_against_the_r2_host() {
        let bucket = r2_client("https://abc123def456.r2.cloudflarestorage.com");
        let sha = "a".repeat(64);
        let upload = bucket
            .presign_put(
                "tenant-a:cli_tool:hello:1.0.0",
                900,
                1_440_938_160,
                42,
                &sha,
            )
            .unwrap();
        assert!(upload.url.starts_with(
            "https://abc123def456.r2.cloudflarestorage.com/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0?"
        ));
        assert!(upload.url.contains("%2Fauto%2Fs3%2Faws4_request"));
        assert!(upload
            .url
            .contains("X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256"));
        assert_eq!(
            upload.required_headers,
            vec![
                ("content-length", "42".to_string()),
                ("x-amz-content-sha256", sha),
            ]
        );
    }

    // ---- #411 AssetObjectStore trait extraction (S3/R2 behind the trait) ----

    #[tokio::test]
    async fn s3_impl_shapes_a_put_identically_through_the_trait() {
        // The extracted trait must be a pure indirection over the existing
        // client: a PUT issued through `&dyn AssetObjectStore` produces the
        // same signed path-style request the inherent method does.
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let concrete = client(endpoint);
        let store: &dyn AssetObjectStore = &concrete;

        store
            .put_object(
                "tenant-a:cli_tool:hello:1.0.0",
                b"asset bytes",
                "text/plain",
            )
            .await
            .unwrap();

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "PUT");
        assert_eq!(
            request.path,
            "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0"
        );
        assert_eq!(request.body, b"asset bytes");
        assert!(request.has_authorization);
        assert!(request.content_sha256_header.is_some());
    }

    #[test]
    fn s3_presign_is_byte_for_byte_identical_through_the_trait() {
        // Behavior-identical: the inherent presign and the trait presign of the
        // same key at the same instant must produce the same URL.
        let concrete = client("http://127.0.0.1:9999".into());
        let inherent = AssetBucketClient::presign_get(&concrete, "k", 300, 1_440_938_160).unwrap();
        let via_trait = <AssetBucketClient as AssetObjectStore>::presign_get(
            &concrete,
            "k",
            300,
            1_440_938_160,
        )
        .unwrap();
        assert_eq!(inherent, via_trait);

        let sha = "a".repeat(64);
        let inherent_put = AssetBucketClient::presign_put(&concrete, "k", 300, 1, 42, &sha)
            .unwrap()
            .url;
        let via_trait_put =
            <AssetBucketClient as AssetObjectStore>::presign_put(&concrete, "k", 300, 1, 42, &sha)
                .unwrap()
                .url;
        assert_eq!(inherent_put, via_trait_put);
    }

    // ---- #411 Cloudflare Workers Static Assets backend --------------------

    /// A CloudflareClient transport that records the request it was handed and
    /// replays a fixed envelope — no network. Mirrors the crate's own
    /// `ScriptedTransport`, but captures the request so the publish request
    /// construction is assertable.
    struct CapturingCfTransport {
        last: Arc<Mutex<Option<ferrogate_cloudflare::HttpRequest>>>,
        status: u16,
        body: Vec<u8>,
    }

    #[async_trait]
    impl ferrogate_cloudflare::HttpTransport for CapturingCfTransport {
        async fn execute(
            &self,
            request: ferrogate_cloudflare::HttpRequest,
        ) -> Result<ferrogate_cloudflare::HttpResponse, ferrogate_cloudflare::CloudflareError>
        {
            *self.last.lock().unwrap() = Some(request);
            Ok(ferrogate_cloudflare::HttpResponse {
                status: self.status,
                retry_after: None,
                body: self.body.clone(),
            })
        }
    }

    fn cf_store(
        status: u16,
        body: &str,
    ) -> (
        WorkersStaticAssetsStore,
        Arc<Mutex<Option<ferrogate_cloudflare::HttpRequest>>>,
    ) {
        let last = Arc::new(Mutex::new(None));
        let transport = Arc::new(CapturingCfTransport {
            last: Arc::clone(&last),
            status,
            body: body.as_bytes().to_vec(),
        });
        let cf = CloudflareClient::from_parts(
            ferrogate_cloudflare::CloudflareConfig::new("acct-123", "plaintext-token"),
            Arc::new(ferrogate_cloudflare::EnvTokenResolver::from_process_env()),
            transport,
            Arc::new(ferrogate_cloudflare::TokioClock),
            ferrogate_cloudflare::RetryPolicy::default(),
        );
        let store = WorkersStaticAssetsStore::new(Arc::new(cf), "my-worker".to_string());
        (store, last)
    }

    const UPLOAD_SESSION_OK: &str = r#"{"success":true,"errors":[],"messages":[],"result":{"jwt":"upload-jwt","buckets":[["deadbeef"]]}}"#;

    #[test]
    fn asset_upload_manifest_is_a_leading_slash_path_map() {
        let empty = AssetUploadManifest::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let manifest = AssetUploadManifest::single("index.html", b"abc");
        assert!(!manifest.is_empty());
        assert_eq!(manifest.len(), 1);

        let body = manifest.request_body();
        // The key is normalized to a site-root-relative leading-slash path.
        let entry = &body["manifest"]["/index.html"];
        assert!(entry.is_object());
        assert_eq!(entry["size"], 3);
        // CF keys the session on a 32-hex-char content hash.
        assert_eq!(entry["hash"].as_str().unwrap().len(), CF_ASSET_HASH_HEX_LEN);
    }

    #[tokio::test]
    async fn workers_static_assets_constructs_the_upload_session_request() {
        // #411: the publish request (step 1 of the 3-step direct upload) is
        // constructed correctly against a MOCKED CloudflareClient transport.
        let (store, last) = cf_store(200, UPLOAD_SESSION_OK);
        let manifest = AssetUploadManifest::single("/index.html", b"<html>hi</html>");

        let session = store.create_upload_session(&manifest).await.unwrap();
        assert_eq!(session.jwt.as_deref(), Some("upload-jwt"));
        assert_eq!(session.buckets, vec![vec!["deadbeef".to_string()]]);

        let request = last.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(
            request.url,
            "https://api.cloudflare.com/client/v4/accounts/acct-123/workers/scripts/my-worker/assets-upload-session"
        );
        let sent: serde_json::Value =
            serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
        let entry = &sent["manifest"]["/index.html"];
        assert_eq!(entry["size"], 15);
        assert_eq!(entry["hash"].as_str().unwrap().len(), CF_ASSET_HASH_HEX_LEN);
    }

    #[tokio::test]
    async fn workers_static_assets_put_negotiates_but_does_not_fake_a_publish() {
        // #411 honesty guard: put issues the real negotiation request but must
        // NOT claim a durable publish it has not completed (steps 2-3 are the
        // live-publish path).
        let (store, last) = cf_store(200, UPLOAD_SESSION_OK);
        let store_dyn: &dyn AssetObjectStore = &store;

        let error = store_dyn
            .put_object("/index.html", b"bytes", "text/html")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not yet wired for live publish"),
            "unexpected error: {error}"
        );
        // It did issue the step-1 negotiation request.
        assert!(last.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn workers_static_assets_reports_s3_only_operations_unsupported() {
        // #411: presign + arbitrary keyed GET/HEAD/LIST/DELETE are structurally
        // unsupported on this CF-native publish target and return a clear error.
        let (store, _last) = cf_store(200, UPLOAD_SESSION_OK);
        let store_dyn: &dyn AssetObjectStore = &store;

        assert!(store_dyn
            .get_object("k")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not support"));
        assert!(store_dyn
            .head_object("k")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not support"));
        assert!(store_dyn
            .list_objects()
            .await
            .unwrap_err()
            .to_string()
            .contains("does not support"));
        assert!(store_dyn
            .delete_object("k")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not support"));

        let presign_get_err = store_dyn.presign_get("k", 300, 1).unwrap_err().to_string();
        assert!(presign_get_err.contains("presign"), "{presign_get_err}");
        // `PresignedUpload` is not `Debug`, so match rather than `unwrap_err`.
        let presign_put_err = match store_dyn.presign_put("k", 300, 1, 5, &"a".repeat(64)) {
            Ok(_) => panic!("expected presign_put to be unsupported on the CF backend"),
            Err(error) => error.to_string(),
        };
        assert!(presign_put_err.contains("presign"), "{presign_put_err}");
    }

    #[tokio::test]
    async fn workers_static_assets_maps_a_cloudflare_api_error() {
        // A non-2xx CF envelope surfaces as a clear negotiation failure, not a
        // silent success.
        let error_body = r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}"#;
        let (store, _last) = cf_store(403, error_body);
        let manifest = AssetUploadManifest::single("/index.html", b"x");
        let error = store.create_upload_session(&manifest).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("upload-session negotiation failed"),
            "unexpected error: {error}"
        );
    }
}
