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
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use ferrogate_cloudflare::{CloudflareClient, HttpMethod};
// The endpoint decomposition moved to `ferrogate-config` in #553 stage 3a:
// `Config::validate_asset_bucket_r2` is its other caller, and validation now
// lives there. It is still the SAME decomposition the signer below uses, which
// is the whole point of #485.
use ferrogate_config::parse_endpoint;
use ferrogate_providers::{
    presign_sigv4_query, presign_sigv4_query_bound, sign_sigv4_streamed_with_content_hash_header,
    sign_sigv4_with_content_hash_header, AwsCredentials, PresignBoundPayload, PresignRequest,
    SigningRequest, StreamedSigningRequest,
};
use futures_util::TryStreamExt;

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
    /// fixed [`ferrogate_config::R2_REGION`] (`auto`), and use an R2 Access Key ID + Secret
    /// (created via R2's Create-Token API) through the same `access_key_id` +
    /// `secret_access_key` pair. R2 buckets are addressed path-style
    /// (`/{bucket}/{key}`), which is exactly how this client already builds its
    /// object paths, and R2 accepts the real `x-amz-content-sha256` payload
    /// hash this client sends. `[asset_bucket]` targeting an R2 host is
    /// auto-detected and validated (see `validate_asset_bucket_r2`); no extra
    /// config marker is needed. An R2 endpoint must be the bare account host:
    /// a `:port` or a path suffix is NOT ignored, because R2 does not serve
    /// account endpoints behind an extra base path (issue #485). NOTE: R2
    /// buckets are private by default -- for
    /// *public* static serving you must attach a custom domain to the bucket
    /// (the `r2.dev` subdomain is rate-limited/dev-only); the gateway's
    /// presigned-GET path serves private objects without a public bucket.
    pub(crate) endpoint: String,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

pub(crate) struct AssetBucketClient {
    config: AssetBucketConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssetBucketEndpoint {
    scheme: &'static str,
    host: String,
    base_path: String,
}

impl AssetBucketEndpoint {
    fn object_path(&self, bucket: &str, key: &str) -> String {
        self.prefixed_path(&format!("/{bucket}/{key}"))
    }

    fn bucket_path(&self, bucket: &str) -> String {
        self.prefixed_path(&format!("/{bucket}"))
    }

    fn url(&self, path: &str) -> String {
        format!("{}://{}{}", self.scheme, self.host, path)
    }

    fn prefixed_path(&self, suffix: &str) -> String {
        debug_assert!(suffix.starts_with('/'));
        format!("{}{}", self.base_path, suffix)
    }
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

/// A bounded-memory stream of an object's bytes (issue #259).
///
/// The unit of transfer is one HTTP body chunk, so a holder of this stream
/// never has more than a single chunk resident regardless of object size —
/// which is the whole point: the presigned commit path used to materialize the
/// entire staged object (up to `presign_max_object_bytes`, default 5 GiB) in
/// gateway memory to hash and re-PUT it, making N concurrent commits an OOM on
/// the Pingora process.
pub(crate) type ObjectByteStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = anyhow::Result<Bytes>> + Send>>;

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
    /// Buffering read of `key`, refusing to hold more than `max_bytes`.
    ///
    /// `max_bytes` is NOT optional and NOT advisory (issue #259 round 2): the
    /// first round bounded the registry pull at its own call site, and three
    /// other bucket-backed reads (`fetch_asset`, MCP `resources/read`, the
    /// static-site serve) kept buffering whole objects because nothing in the
    /// type forced them to say how much memory they were willing to spend. A
    /// read surface added tomorrow cannot compile without naming a bound, and
    /// the bound is enforced against the bytes that actually arrive rather than
    /// against a size the registry row merely claims.
    async fn get_object(&self, key: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>>;
    async fn get_object_if_present(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    /// Opens a *streaming* read of `key` — the bounded-memory counterpart of
    /// [`get_object_if_present`](Self::get_object_if_present). `Ok(None)` is
    /// the same 404-means-absent result, preserved so the commit-race
    /// reconciliation reads identically on both paths (issue #259).
    async fn get_object_stream(&self, key: &str) -> anyhow::Result<Option<ObjectByteStream>>;
    /// PUTs an object from a byte stream instead of a buffer (issue #259).
    ///
    /// `content_length` and `content_sha256_hex` must describe the bytes
    /// `body` will yield: SigV4 signs the payload hash *before* the body is
    /// sent, so the hash is supplied rather than computed. An S3-compatible
    /// bucket recomputes it and refuses a mismatch, which is the intended
    /// fail-closed layer — the caller additionally verifies the hash
    /// incrementally as the same bytes flow past.
    async fn put_object_stream(
        &self,
        key: &str,
        content_type: &str,
        content_length: u64,
        content_sha256_hex: &str,
        body: ObjectByteStream,
    ) -> anyhow::Result<()>;
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

/// Why a buffering read was refused (issue #259 round 2).
pub(crate) enum BufferedReadRefusal {
    /// The object is larger than the gateway's in-memory budget. The caller
    /// must be told to use the presigned direct download instead — never
    /// served a truncated body, and never quietly buffered anyway.
    TooLarge { size_bytes: u64, limit_bytes: u64 },
    /// This object fits the per-operation budget, but the gateway's AGGREGATE
    /// budget for buffered reads was fully committed and stayed committed for
    /// the whole bounded admission wait (issue #529).
    ///
    /// Distinct from [`Self::TooLarge`] because the disposition is different in
    /// kind: nothing is wrong with the object or the request, the gateway is
    /// out of memory budget right now, and the same request will succeed on
    /// retry. That is a 503 (with a `Retry-After`-shaped message), not a 413.
    Overloaded {
        requested_bytes: u64,
        budget_bytes: u64,
        waited_ms: u64,
    },
    /// The bucket could not be reached or refused the read. The diagnostic
    /// detail has already been logged against the request id; the caller only
    /// ever sees [`BUCKET_READ_UNAVAILABLE_MESSAGE`].
    Transport,
}

/// The error code every read surface returns when an object is above the
/// gateway's in-memory budget. One constant so the REST pull, the `fetch_asset`
/// built-in tool, MCP `resources/read` and the static-site serve cannot drift
/// into three different names for one refusal.
pub(crate) const ASSET_TOO_LARGE_FOR_INLINE_PULL_CODE: &str = "asset_too_large_for_inline_pull";

/// The single message a caller ever sees when a bucket-backed *read* fails at
/// the transport (issue #259 review finding 4).
///
/// `reqwest::Error`'s `Display` embeds the request URL, so returning it
/// verbatim published the internal `.ferrogate/objects/<digest>/obj_<rand>` key
/// and the bucket endpoint — the exact thing the private-bucket runbook
/// promises is never serialized into a response. Round 1 fixed the four
/// presigned-commit exits and the registry pull; this constant closes the three
/// that were left (`AppState::read_asset_content`,
/// `FerroGateway::load_asset_content`, `FerroGateway::store_asset_bytes`),
/// which surfaced verbatim through `fetch_asset`, MCP `resources/read` and the
/// static-site serve.
pub(crate) const BUCKET_READ_UNAVAILABLE_MESSAGE: &str =
    "the asset object bucket is unavailable; retry, or fetch the object through GET \
     /v1/assets/presign/download/{asset_type}/{name}/{version} (see the gateway logs for the \
     correlated request_id)";

/// The refusal an over-budget object earns, worded so the caller knows which
/// endpoint does work instead of merely that this one does not.
pub(crate) fn asset_too_large_for_buffering_message(
    asset_type: &str,
    name: &str,
    version: &str,
    size_bytes: u64,
    limit_bytes: u64,
) -> String {
    format!(
        "asset {asset_type}/{name}/{version} is {size_bytes} bytes, above the gateway's \
         {limit_bytes}-byte in-memory limit; fetch it with GET \
         /v1/assets/presign/download/{asset_type}/{name}/{version} and download the returned \
         presigned URL directly"
    )
}

/// The error code every read surface returns when the gateway's AGGREGATE
/// buffering budget is exhausted (issue #529). One constant, for the same
/// reason [`ASSET_TOO_LARGE_FOR_INLINE_PULL_CODE`] is one: four surfaces, one
/// name for one condition.
pub(crate) const GATEWAY_BUFFER_BUDGET_EXHAUSTED_CODE: &str = "gateway_buffer_budget_exhausted";

/// The shed message: it names the condition, the enforced ceiling, how long the
/// request actually waited, and the endpoint that does not consume the budget.
///
/// Deliberately explicit about being a load condition rather than a fault of
/// the request: "retry" is real advice here (the same call succeeds once
/// in-flight reads finish), which is not true of the 413 an over-large object
/// earns.
pub(crate) fn gateway_buffer_budget_exhausted_message(
    asset_type: &str,
    name: &str,
    version: &str,
    requested_bytes: u64,
    budget_bytes: u64,
    waited_ms: u64,
) -> String {
    format!(
        "the gateway's aggregate in-memory budget for bucket-backed reads \
         ([asset_bucket].max_total_gateway_buffer_bytes = {budget_bytes} bytes) is fully \
         committed; this {requested_bytes}-byte read of {asset_type}/{name}/{version} waited \
         {waited_ms}ms for capacity and was shed rather than queued indefinitely or truncated. \
         Retry, or fetch the object with GET \
         /v1/assets/presign/download/{asset_type}/{name}/{version}, which streams from the \
         bucket and does not use this budget"
    )
}

fn object_over_buffer_budget(size_bytes: u64, limit_bytes: u64) -> String {
    format!(
        "asset bucket GET refused: the object is at least {size_bytes} bytes, above the \
         {limit_bytes}-byte in-memory budget this read was given"
    )
}

/// **The** buffering, bucket-backed read in the gateway (issue #259 round 2).
///
/// Round 1 bounded `write_asset_body` at its own call site and left
/// `AppState::read_asset_content` (reached by the `fetch_asset` built-in tool
/// and MCP `resources/read`) and `FerroGateway::load_asset_content` (reached by
/// the static-site serve) buffering objects of up to `presign_max_object_bytes`
/// — 5 GiB by default — for any caller holding `assets.read`. Adding a second
/// and third copy of the same check would have left the same hole open for the
/// fourth surface, so the check lives here, on the one path all of them take:
///
/// 1. the size the registry row declares is refused before a byte is requested,
///    which is what turns into the caller's typed 413; and
/// 2. `max_bytes` is handed to the transport, which enforces it against the
///    bytes that actually arrive — so a row that under-reports its object (or a
///    bucket that lies about `Content-Length`) still cannot make the gateway
///    hold more than the budget.
///
/// The transport's error never reaches the caller; it is logged against
/// `request_id` and collapsed to [`BufferedReadRefusal::Transport`].
///
/// Issue #529 added the third step this function now performs: the read is
/// **admitted** against the process-wide aggregate budget before it starts, and
/// the permit it takes travels back inside the returned [`BufferedObject`], so
/// it is held for as long as the bytes are. A per-operation bound with no
/// aggregate bound made peak memory `max_gateway_buffer_bytes x in-flight
/// reads`; this is what bounds the second factor.
///
/// Note that the transport's ceiling is the *declared* size, not the
/// per-operation budget. It has to be: the budget arithmetic is only exact if
/// the bytes a read may hold are the bytes it was charged for. A bucket whose
/// object exceeds what its registry row claims is refused here rather than
/// being allowed to hold up to the (larger) per-operation bound uncharged.
///
/// `residency` is how the caller will hold those bytes, and therefore what it
/// is charged. A surface that inlines the object into a JSON response holds up
/// to three copies of it at once and says so
/// ([`ReadResidency::InlinedInJsonResponse`](super::asset_admission::ReadResidency::InlinedInJsonResponse));
/// one that writes the buffer straight out holds one.
// Each parameter is a distinct, load-bearing input (store handle, key, two size
// bounds, budget, residency, and two ids for accounting); bundling them into a
// struct would add churn without clarifying the call sites.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_object_bounded(
    bucket: &dyn AssetObjectStore,
    key: &str,
    declared_size_bytes: u64,
    max_buffer_bytes: u64,
    admission: &super::asset_admission::GatewayBufferBudget,
    residency: super::asset_admission::ReadResidency,
    asset_id: &str,
    request_id: &str,
) -> Result<super::asset_admission::BufferedObject, BufferedReadRefusal> {
    if declared_size_bytes > max_buffer_bytes {
        return Err(BufferedReadRefusal::TooLarge {
            size_bytes: declared_size_bytes,
            limit_bytes: max_buffer_bytes,
        });
    }
    let permit = match admission.admit(residency, declared_size_bytes).await {
        Ok(permit) => permit,
        Err(refusal) => {
            tracing::warn!(
                request_id = %request_id,
                asset_id = %asset_id,
                requested_bytes = refusal.requested_bytes,
                budget_bytes = refusal.budget_bytes,
                waited_ms = refusal.waited_ms,
                "shed a bucket-backed asset read: the gateway's aggregate buffering budget is \
                 exhausted"
            );
            return Err(BufferedReadRefusal::Overloaded {
                requested_bytes: refusal.requested_bytes,
                budget_bytes: refusal.budget_bytes,
                waited_ms: refusal.waited_ms,
            });
        }
    };
    match bucket.get_object(key, declared_size_bytes).await {
        Ok(bytes) => Ok(super::asset_admission::BufferedObject::new(bytes, permit)),
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                asset_id = %asset_id,
                error = %error,
                "failed to read a bucket-backed asset object within the gateway memory budget"
            );
            Err(BufferedReadRefusal::Transport)
        }
    }
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
    async fn get_object(&self, key: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        self.as_ref().get_object(key, max_bytes).await
    }
    async fn get_object_if_present(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.as_ref().get_object_if_present(key, max_bytes).await
    }
    async fn get_object_stream(&self, key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
        self.as_ref().get_object_stream(key).await
    }
    async fn put_object_stream(
        &self,
        key: &str,
        content_type: &str,
        content_length: u64,
        content_sha256_hex: &str,
        body: ObjectByteStream,
    ) -> anyhow::Result<()> {
        self.as_ref()
            .put_object_stream(key, content_type, content_length, content_sha256_hex, body)
            .await
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
    async fn get_object(&self, key: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        AssetBucketClient::get_object(self, key, max_bytes).await
    }
    async fn get_object_if_present(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        AssetBucketClient::get_object_if_present(self, key, max_bytes).await
    }
    async fn get_object_stream(&self, key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
        AssetBucketClient::get_object_stream(self, key).await
    }
    async fn put_object_stream(
        &self,
        key: &str,
        content_type: &str,
        content_length: u64,
        content_sha256_hex: &str,
        body: ObjectByteStream,
    ) -> anyhow::Result<()> {
        AssetBucketClient::put_object_stream(
            self,
            key,
            content_type,
            content_length,
            content_sha256_hex,
            body,
        )
        .await
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
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let signed = self.sign("PUT", &path, &endpoint.host, &body);
        let client = provider_http_client()?;
        let mut request = client
            .put(endpoint.url(&path))
            .header("host", endpoint.host.clone())
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

    pub(crate) async fn get_object(&self, key: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        self.get_object_if_present(key, max_bytes)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "asset bucket GET failed (HTTP 404 Not Found): object does not exist"
                )
            })
    }

    /// GETs an object while preserving a missing-key result for commit-race
    /// reconciliation. Other bucket failures remain explicit errors.
    ///
    /// The body is accumulated under `max_bytes` rather than with a single
    /// `response.bytes()` (issue #259 round 2). Both the advertised
    /// `Content-Length` and the bytes that actually arrive are checked, so a
    /// bucket that under-reports (or omits) the length cannot make the gateway
    /// hold more than the caller budgeted for.
    pub(crate) async fn get_object_if_present(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let signed = self.sign("GET", &path, &endpoint.host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .get(endpoint.url(&path))
            .header("host", endpoint.host.clone())
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
        if let Some(declared) = response.content_length() {
            anyhow::ensure!(
                declared <= max_bytes,
                "{}",
                object_over_buffer_budget(declared, max_bytes)
            );
        }
        let mut body: Vec<u8> = Vec::with_capacity(
            usize::try_from(response.content_length().unwrap_or(0).min(max_bytes))
                .unwrap_or_default(),
        );
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.try_next().await? {
            let would_hold = body.len() as u64 + chunk.len() as u64;
            anyhow::ensure!(
                would_hold <= max_bytes,
                "{}",
                object_over_buffer_budget(would_hold, max_bytes)
            );
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    /// Opens a streaming GET so the caller can verify and copy an object of
    /// arbitrary size without materializing it (issue #259). The response
    /// headers are consumed here (so a 404/5xx is still a normal
    /// `Ok(None)`/`Err` before any byte flows); the body is handed back as a
    /// chunk stream.
    pub(crate) async fn get_object_stream(
        &self,
        key: &str,
    ) -> anyhow::Result<Option<ObjectByteStream>> {
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let signed = self.sign("GET", &path, &endpoint.host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .get(endpoint.url(&path))
            .header("host", endpoint.host.clone())
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
        Ok(Some(Box::pin(
            response.bytes_stream().map_err(anyhow::Error::from),
        )))
    }

    /// PUTs an object straight from a byte stream (issue #259).
    ///
    /// `Content-Length` is set explicitly rather than left to the body's size
    /// hint: a streamed reqwest body has no known length, and hyper would fall
    /// back to `Transfer-Encoding: chunked`, which S3-compatible endpoints
    /// reject unless it is the `aws-chunked` framing (which this is not).
    pub(crate) async fn put_object_stream(
        &self,
        key: &str,
        content_type: &str,
        content_length: u64,
        content_sha256_hex: &str,
        body: ObjectByteStream,
    ) -> anyhow::Result<()> {
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let signed = sign_sigv4_streamed_with_content_hash_header(
            &StreamedSigningRequest {
                method: "PUT",
                path: &path,
                host: &endpoint.host,
                region: &self.config.region,
                service: "s3",
                payload_sha256_hex: content_sha256_hex,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
        );
        let client = provider_http_client()?;
        let mut request = client
            .put(endpoint.url(&path))
            .header("host", endpoint.host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone())
            .header("content-type", content_type)
            .header(http::header::CONTENT_LENGTH, content_length)
            .body(reqwest::Body::wrap_stream(body));
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

    pub(crate) async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let signed = self.sign("DELETE", &path, &endpoint.host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .delete(endpoint.url(&path))
            .header("host", endpoint.host.clone())
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
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let signed = self.sign("HEAD", &path, &endpoint.host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .head(endpoint.url(&path))
            .header("host", endpoint.host.clone())
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
        let endpoint = self.endpoint()?;
        let path = endpoint.bucket_path(&self.config.bucket);
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
                    host: &endpoint.host,
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
                .get(format!("{}?{canonical_query}", endpoint.url(&path)))
                .header("host", endpoint.host.clone())
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
    /// while the canonical request's payload-hash line remains
    /// `UNSIGNED-PAYLOAD` for Supabase Storage S3 compatibility. The holder
    /// PUTs the object bytes straight to the bucket (bypassing the gateway hot
    /// path) but MUST send `required_headers` verbatim -- changing the declared
    /// size or checksum invalidates the upload authorization at the bucket
    /// boundary itself, before the gateway's commit-time verification ever
    /// runs. Same-size byte substitution is additionally refused by backends
    /// that re-hash the body against `x-amz-content-sha256`.
    pub(crate) fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
        size_bytes: u64,
        content_sha256_hex: &str,
    ) -> anyhow::Result<PresignedUpload> {
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let bound = presign_sigv4_query_bound(
            &PresignRequest {
                method: "PUT",
                path: &path,
                host: &endpoint.host,
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
            url: format!("{}?{}", endpoint.url(&path), bound.query),
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
        let endpoint = self.endpoint()?;
        let path = endpoint.object_path(&self.config.bucket, key);
        let query = presign_sigv4_query(
            &PresignRequest {
                method,
                path: &path,
                host: &endpoint.host,
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
        Ok(format!("{}?{query}", endpoint.url(&path)))
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

    /// Extracts `(scheme, signed host)` from `config.endpoint` -- mirrors
    /// `bedrock.rs::extract_host`'s http-preserved-for-tests /
    /// https-otherwise convention. Path-prefixed S3 endpoints keep their base
    /// path out of this value; the prefix is part of the canonical URI instead
    /// (issue #573). The decomposition itself lives in [`parse_endpoint`]
    /// because the config-load guards (`validate_asset_bucket_r2`) must reason
    /// about the same endpoint this signs; issue #485 was two decompositions
    /// drifting apart.
    #[cfg(test)]
    fn scheme_and_host(&self) -> anyhow::Result<(&'static str, String)> {
        let endpoint = self.endpoint()?;
        Ok((endpoint.scheme, endpoint.host))
    }

    fn endpoint(&self) -> anyhow::Result<AssetBucketEndpoint> {
        let parts = parse_endpoint(&self.config.endpoint)?;
        anyhow::ensure!(
            parts.path_prefix.is_empty() || parts.path_prefix.starts_with('/'),
            "asset_bucket.endpoint {} must not contain a query or fragment suffix",
            self.config.endpoint
        );
        Ok(AssetBucketEndpoint {
            scheme: parts.scheme,
            host: parts.signing_host(),
            base_path: parts.path_prefix,
        })
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
/// 32-hex-char content hash: `SHA-256(base64(file bytes) + extension)`
/// truncated to 32 hex chars (see [`cf_asset_hash`]). This is the exact recipe
/// the Cloudflare direct-upload flow expects, so the same hash the manifest
/// declares is the field name the step-2 byte upload posts under and the key
/// Cloudflare dedups + serves against.
const CF_ASSET_HASH_HEX_LEN: usize = 32;

impl AssetUploadManifest {
    /// A single-file manifest for `path` holding `body` — the shape a
    /// per-object publish negotiates. `path` is normalized to a leading `/`.
    pub(crate) fn single(path: &str, body: &[u8]) -> Self {
        let mut files = BTreeMap::new();
        let normalized = normalize_asset_path(path);
        let entry = AssetManifestEntry::for_file(&normalized, body);
        files.insert(normalized, entry);
        Self { files }
    }

    /// The number of files described. (Kept small on purpose — the manifest is
    /// a plan, not the bytes.) Retained as part of the manifest's public shape
    /// and asserted by the manifest tests, though the single-object publish path
    /// gates on [`is_empty`](Self::is_empty).
    #[allow(dead_code)]
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
    /// The manifest entry for `body` published at `path`. The hash uses
    /// Cloudflare's recipe ([`cf_asset_hash`]) so it agrees with the byte-upload
    /// field name and CF's server-side dedup/serve key.
    fn for_file(path: &str, body: &[u8]) -> Self {
        Self {
            hash: cf_asset_hash(path, body),
            size: body.len() as u64,
        }
    }
}

/// Cloudflare's Workers Static Assets content hash: the SHA-256 of the
/// base64-encoded file bytes concatenated with the file **extension** (without
/// the dot), truncated to 32 hex chars. Matching this exactly matters — the
/// upload-session negotiation, the step-2 byte-upload field name, and CF's
/// edge dedup/serve all key on this same value, so a divergent hash would make
/// the deploy serve stale or missing bytes.
fn cf_asset_hash(path: &str, body: &[u8]) -> String {
    let mut input = BASE64_STANDARD.encode(body).into_bytes();
    input.extend_from_slice(asset_extension(path).as_bytes());
    let mut hash = ferrogate_storage::sha256_hex(&input);
    hash.truncate(CF_ASSET_HASH_HEX_LEN);
    hash
}

/// The file extension of `path` without the leading dot (`"/a/index.html"` ->
/// `"html"`), or `""` when the final path segment has none / is a dotfile —
/// matching Node's `path.extname` semantics Cloudflare's tooling uses.
fn asset_extension(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => ext,
        _ => "",
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
/// already present server-side and `jwt` is directly the completion token.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(crate) struct UploadSession {
    #[serde(default)]
    pub(crate) jwt: Option<String>,
    #[serde(default)]
    pub(crate) buckets: Vec<Vec<String>>,
}

/// The decoded `result` of a Workers Static Assets byte-upload batch (step 2).
/// The `jwt` is the **completion token** Cloudflare returns once the final
/// pending batch lands; it is redeemed in the step-3 script deploy.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct AssetUploadAck {
    #[serde(default)]
    jwt: Option<String>,
}

/// The decoded `result` of the Worker script deploy (step 3). Only the echoed
/// id is consumed (mirrors the sibling Worker deployers); its presence in a
/// `success: true` envelope is what marks the publish durable.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct ScriptDeployResult {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
}

/// Fixed multipart boundary for the step-2 byte upload. A constant (not random)
/// boundary keeps the constructed request deterministic so tests assert the
/// exact bytes — the same discipline the sibling Worker deployers use.
const WSA_UPLOAD_BOUNDARY: &str = "----FerroGateWorkersAssetsUploadBoundary";

/// Fixed multipart boundary for the step-3 Worker script deploy.
const WSA_DEPLOY_BOUNDARY: &str = "----FerroGateWorkersAssetsDeployBoundary";

/// The `main_module` filename referenced by the deploy metadata.
const WSA_MAIN_MODULE_FILENAME: &str = "main.js";

/// Worker compatibility date for the static-assets Worker deploy.
const WSA_COMPATIBILITY_DATE: &str = "2025-06-01";

/// The minimal main module for an assets-only static Worker. When a Worker has
/// an `assets` binding and no `run_worker_first`, Cloudflare serves matching
/// static assets from the edge *before* invoking the script, so this handler
/// only runs for non-asset paths, where it 404s. It exists because the Workers
/// Script API deploy requires a `main_module`.
const WSA_STATIC_MAIN_MODULE: &str =
    "export default { async fetch() { return new Response(\"Not Found\", { status: 404 }); } };\n";

/// The `multipart/form-data; boundary=…` content-type header value.
fn multipart_content_type(boundary: &str) -> String {
    format!("multipart/form-data; boundary={boundary}")
}

/// Build the step-2 byte-upload `multipart/form-data` body. Each part is keyed
/// (field name + filename) by the file's content hash, carries the serving
/// `Content-Type` Cloudflare echoes when the asset is later fetched, and holds
/// the **base64-encoded** file bytes (the request uses `?base64=true`).
fn build_assets_upload_body(parts: &[UploadPart]) -> Vec<u8> {
    let b = WSA_UPLOAD_BOUNDARY;
    let mut body = String::new();
    for part in parts {
        body.push_str(&format!("--{b}\r\n"));
        body.push_str(&format!(
            "Content-Disposition: form-data; name=\"{0}\"; filename=\"{0}\"\r\n",
            part.hash
        ));
        body.push_str(&format!("Content-Type: {}\r\n\r\n", part.content_type));
        body.push_str(&part.base64_body);
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{b}--\r\n"));
    body.into_bytes()
}

/// One `(hash, base64 bytes, serving content-type)` part of a byte-upload batch.
struct UploadPart {
    hash: String,
    base64_body: String,
    content_type: String,
}

/// The step-3 deploy metadata JSON: registers the minimal main module and
/// attaches the uploaded bundle via the `assets` binding (the completion token
/// plus routing config).
fn deploy_metadata_json(completion_token: &str) -> serde_json::Value {
    serde_json::json!({
        "main_module": WSA_MAIN_MODULE_FILENAME,
        "compatibility_date": WSA_COMPATIBILITY_DATE,
        "assets": {
            "jwt": completion_token,
            "config": {
                "html_handling": "auto-trailing-slash",
                "not_found_handling": "none",
            },
        },
    })
}

/// Build the step-3 script-deploy `multipart/form-data` body: a `metadata` JSON
/// part attaching the assets binding + a minimal ES-module part.
fn build_deploy_body(completion_token: &str) -> Vec<u8> {
    let metadata = serde_json::to_string(&deploy_metadata_json(completion_token))
        .expect("deploy metadata JSON is always serializable");
    let b = WSA_DEPLOY_BOUNDARY;
    let mut body = String::new();
    // metadata part
    body.push_str(&format!("--{b}\r\n"));
    body.push_str(
        "Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n",
    );
    body.push_str("Content-Type: application/json\r\n\r\n");
    body.push_str(&metadata);
    body.push_str("\r\n");
    // module part
    body.push_str(&format!("--{b}\r\n"));
    body.push_str(&format!(
        "Content-Disposition: form-data; name=\"{WSA_MAIN_MODULE_FILENAME}\"; \
         filename=\"{WSA_MAIN_MODULE_FILENAME}\"\r\n"
    ));
    body.push_str("Content-Type: application/javascript+module\r\n\r\n");
    body.push_str(WSA_STATIC_MAIN_MODULE);
    body.push_str("\r\n");
    // closing boundary
    body.push_str(&format!("--{b}--\r\n"));
    body.into_bytes()
}

/// A Cloudflare-native static-asset publish backend built on Workers Static
/// Assets (issue #411). NOT S3-shaped: it publishes a bundle through the CF
/// direct-upload flow rather than exposing arbitrary object GET/HEAD/LIST or
/// SigV4 presign. Wired through the shared [`CloudflareClient`] so the whole
/// publish is unit-testable against a mocked transport.
///
/// Publish is a 3-step flow, all issued through [`CloudflareClient`]:
/// 1. **Negotiate** an upload session against a file manifest
///    (`POST …/workers/scripts/{script}/assets-upload-session`) — a JSON
///    request that returns an upload JWT plus the `buckets` of content hashes
///    whose bytes CF still needs (dedup happens server-side).
/// 2. **Upload** the pending file bytes, base64-encoded, as `multipart/form-data`
///    to `POST …/workers/assets/upload?base64=true`, authenticated with the
///    session JWT, until Cloudflare returns the **completion token**. When
///    `buckets` is empty every asset was already present and the session JWT is
///    itself the completion token (step 2 is skipped).
/// 3. **Deploy** the Worker script (`PUT …/workers/scripts/{script}`) as
///    `multipart/form-data`: a metadata part attaching the assets binding
///    (`assets: { jwt: <completion-token>, config }`) plus a minimal main
///    module, which durably associates the uploaded bundle with the Worker.
///
/// The publish only reports success on a `success: true` step-3 envelope; a
/// failed or partial upload/deploy surfaces the underlying error and never
/// claims a durable publish it did not complete.
///
/// Live caveat: the production multipart upload requires a transport that
/// honors the request `content_type` — [`ReqwestTransport`] now does (it
/// defaults to JSON but sends the explicit `multipart/form-data` type this flow
/// sets). The live publish-and-serve proof against a real account is env-gated
/// and owned by the #411 gate (see `live_workers_static_assets_*`).
///
/// [`ReqwestTransport`]: ferrogate_cloudflare::ReqwestTransport
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

    /// The full publish path for a single asset: negotiate (step 1), upload the
    /// pending bytes (step 2), and deploy the Worker script that redeems the
    /// completion token (step 3). Only a `success: true` deploy marks the
    /// publish durable; any failure along the way surfaces as an error and does
    /// NOT claim a publish that did not complete.
    async fn publish_object(
        &self,
        key: &str,
        body: &[u8],
        content_type: &str,
    ) -> anyhow::Result<()> {
        let path = normalize_asset_path(key);
        let manifest = AssetUploadManifest::single(&path, body);
        if manifest.is_empty() {
            anyhow::bail!("workers-static-assets: refusing to publish an empty manifest");
        }
        let session = self.create_upload_session(&manifest).await?;
        let completion_token = self
            .resolve_completion_token(&path, body, content_type, &session)
            .await?;
        self.deploy_static_worker(&completion_token).await
    }

    /// Resolve the assets **completion token** to redeem at deploy. When the
    /// session negotiated no pending buckets (everything deduped server-side),
    /// the session JWT is already the completion token; otherwise the pending
    /// bytes are uploaded (step 2) and Cloudflare's returned completion token is
    /// used.
    async fn resolve_completion_token(
        &self,
        path: &str,
        body: &[u8],
        content_type: &str,
        session: &UploadSession,
    ) -> anyhow::Result<String> {
        let pending_count = session
            .buckets
            .iter()
            .filter(|bucket| !bucket.is_empty())
            .count();
        if pending_count == 0 {
            // Nothing to upload: the session JWT is itself the completion token.
            return session.jwt.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "workers-static-assets: upload session reported nothing to upload but returned \
                     no completion token"
                )
            });
        }
        let session_jwt = session.jwt.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "workers-static-assets: upload session returned {pending_count} bucket(s) to \
                 upload but no jwt to authorize the byte upload"
            )
        })?;
        self.upload_pending_buckets(path, body, content_type, session, session_jwt)
            .await
    }

    /// Step 2: upload the pending file bytes referenced by `session.buckets`,
    /// authenticated with the session JWT, returning the completion token
    /// Cloudflare hands back once the final batch lands. A single-object publish
    /// carries exactly one file, so its hash is the only one the buckets may
    /// reference — a bucket naming any other hash is a protocol violation and is
    /// rejected rather than silently uploaded.
    async fn upload_pending_buckets(
        &self,
        path: &str,
        body: &[u8],
        content_type: &str,
        session: &UploadSession,
        session_jwt: &str,
    ) -> anyhow::Result<String> {
        let hash = cf_asset_hash(path, body);
        let base64_body = BASE64_STANDARD.encode(body);
        let mut completion_token: Option<String> = None;
        for bucket in session.buckets.iter().filter(|bucket| !bucket.is_empty()) {
            let mut parts = Vec::with_capacity(bucket.len());
            for pending_hash in bucket {
                anyhow::ensure!(
                    pending_hash == &hash,
                    "workers-static-assets: upload session referenced hash {pending_hash} which is \
                     not in the published manifest"
                );
                parts.push(UploadPart {
                    hash: pending_hash.clone(),
                    base64_body: base64_body.clone(),
                    content_type: content_type.to_string(),
                });
            }
            let ack: AssetUploadAck = self
                .client
                .request_json_with(
                    HttpMethod::Post,
                    "accounts/{account_id}/workers/assets/upload?base64=true",
                    build_assets_upload_body(&parts),
                    &multipart_content_type(WSA_UPLOAD_BOUNDARY),
                    Some(session_jwt),
                    None,
                )
                .await
                .map_err(|error| {
                    anyhow::anyhow!("workers-static-assets byte upload failed: {error}")
                })?;
            if ack.jwt.is_some() {
                completion_token = ack.jwt;
            }
        }
        completion_token.ok_or_else(|| {
            anyhow::anyhow!(
                "workers-static-assets: byte upload completed but Cloudflare returned no completion \
                 token to deploy with"
            )
        })
    }

    /// Step 3: deploy the Worker script referencing the completion token. A
    /// `success: true` envelope is the point at which the publish is durable.
    async fn deploy_static_worker(&self, completion_token: &str) -> anyhow::Result<()> {
        let path = format!(
            "accounts/{{account_id}}/workers/scripts/{}",
            self.script_name
        );
        let _deployed: ScriptDeployResult = self
            .client
            .request_json_with(
                HttpMethod::Put,
                &path,
                build_deploy_body(completion_token),
                &multipart_content_type(WSA_DEPLOY_BOUNDARY),
                None,
                None,
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("workers-static-assets script deploy failed: {error}")
            })?;
        Ok(())
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
    async fn put_object(&self, key: &str, body: &[u8], content_type: &str) -> anyhow::Result<()> {
        self.publish_object(key, body, content_type).await
    }
    async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        self.publish_object(key, &body, content_type).await
    }
    async fn get_object(&self, _key: &str, _max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        Err(workers_static_assets_unsupported("object GET by key"))
    }
    async fn get_object_if_present(
        &self,
        _key: &str,
        _max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Err(workers_static_assets_unsupported("object GET by key"))
    }
    async fn get_object_stream(&self, _key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
        Err(workers_static_assets_unsupported("streaming object GET"))
    }
    async fn put_object_stream(
        &self,
        _key: &str,
        _content_type: &str,
        _content_length: u64,
        _content_sha256_hex: &str,
        _body: ObjectByteStream,
    ) -> anyhow::Result<()> {
        Err(workers_static_assets_unsupported("streaming object PUT"))
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
    // The rest of the #485 endpoint decomposition; only `parse_endpoint` is
    // reached by the runtime signer above, so the others are imported here
    // rather than left unused at module scope.
    use ferrogate_config::{
        endpoint_targets_r2, parse_r2_endpoint, R2Endpoint, R2_ENDPOINT_SUFFIX, R2_REGION,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Read budget for the tests whose subject is NOT the memory bound (request
    /// shaping, SigV4, round-trips). Deliberately a small, finite number rather
    /// than `u64::MAX`: a test that accidentally starts depending on an
    /// unbounded read should fail here rather than pass quietly.
    const TEST_READ_BUDGET: u64 = 16 * 1024 * 1024;

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        host: Option<String>,
        body: Vec<u8>,
        authorization: Option<String>,
        x_amz_date: Option<String>,
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
            let host = captured_header(&head, "host");
            let authorization = captured_header(&head, "authorization");
            let x_amz_date = captured_header(&head, "x-amz-date");
            let has_authorization = authorization
                .as_deref()
                .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256"));
            let content_sha256_header = head.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("x-amz-content-sha256")
                        .then(|| value.trim().to_string())
                })
            });
            *server_captured.lock().unwrap() = Some(CapturedRequest {
                method,
                path,
                host,
                body,
                authorization,
                x_amz_date,
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

    fn captured_header(head: &str, header_name: &str) -> Option<String> {
        head.lines().find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case(header_name)
                    .then(|| value.trim().to_string())
            })
        })
    }

    fn sigv4_timestamp_unix(x_amz_date: &str) -> u64 {
        chrono::NaiveDateTime::parse_from_str(x_amz_date, "%Y%m%dT%H%M%SZ")
            .expect("captured x-amz-date is a SigV4 timestamp")
            .and_utc()
            .timestamp()
            .try_into()
            .expect("SigV4 timestamp is after the Unix epoch")
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

    fn test_credentials(bucket: &AssetBucketClient) -> AwsCredentials {
        AwsCredentials {
            access_key_id: bucket.config.access_key_id.clone(),
            secret_access_key: bucket.config.secret_access_key.clone(),
            session_token: None,
        }
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
        let expected_host = bucket.scheme_and_host().unwrap().1;
        assert_eq!(request.host.as_deref(), Some(expected_host.as_str()));
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
    async fn path_prefixed_s3_endpoint_signs_host_and_canonical_uri_separately() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let endpoint_host = endpoint
            .strip_prefix("http://")
            .expect("mock endpoint is http")
            .to_string();
        let bucket = client(format!("{endpoint}/storage/v1/s3"));

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
        assert_eq!(request.host.as_deref(), Some(endpoint_host.as_str()));
        assert_eq!(
            request.path,
            "/storage/v1/s3/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0"
        );
        assert!(request.has_authorization);

        let endpoint = bucket.endpoint().unwrap();
        let fixed_path =
            endpoint.object_path(&bucket.config.bucket, "tenant-a:cli_tool:hello:1.0.0");
        let timestamp_unix = sigv4_timestamp_unix(
            request
                .x_amz_date
                .as_deref()
                .expect("runtime sent x-amz-date"),
        );
        let credentials = test_credentials(&bucket);
        let fixed = sign_sigv4_with_content_hash_header(
            &SigningRequest {
                method: "PUT",
                path: &fixed_path,
                host: &endpoint.host,
                region: &bucket.config.region,
                service: "s3",
                body: b"asset bytes",
                timestamp_unix,
            },
            &credentials,
        );
        let old_host = format!("{endpoint_host}/storage/v1/s3");
        let old_path = "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0";
        let old = sign_sigv4_with_content_hash_header(
            &SigningRequest {
                method: "PUT",
                path: old_path,
                host: &old_host,
                region: &bucket.config.region,
                service: "s3",
                body: b"asset bytes",
                timestamp_unix,
            },
            &credentials,
        );
        assert_eq!(
            request.authorization.as_deref(),
            Some(fixed.authorization.as_str())
        );
        assert_ne!(
            request.authorization.as_deref(),
            Some(old.authorization.as_str()),
            "restoring the old host/path split would sign the prefix as Host and omit it from the canonical URI"
        );
    }

    // ---- the one bounded buffering read (issue #259 round 2) ---------------

    /// A bucket that answers a GET with an arbitrary number of bytes over
    /// `Transfer-Encoding: chunked`, i.e. with NO `Content-Length`. This is the
    /// case the declared-size gate cannot see: the only thing standing between
    /// the gateway and an unbounded body is the accumulation check.
    fn spawn_chunked_bucket_mock(total_bytes: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let mut raw = Vec::new();
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    return;
                }
                raw.extend_from_slice(&buffer[..read]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let chunk = vec![b'x'; 4096];
            let mut sent = 0;
            while sent < total_bytes {
                let size = chunk.len().min(total_bytes - sent);
                if stream
                    .write_all(format!("{size:x}\r\n").as_bytes())
                    .and_then(|()| stream.write_all(&chunk[..size]))
                    .and_then(|()| stream.write_all(b"\r\n"))
                    .is_err()
                {
                    return;
                }
                sent += size;
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        endpoint
    }

    /// A store whose reads always fail with an error shaped exactly like
    /// `reqwest::Error`'s `Display` -- the URL embedded in the message is the
    /// leak issue #259 review finding 4 is about.
    struct LeakyStore {
        reads: Arc<Mutex<usize>>,
    }

    const LEAKY_STORE_URL: &str = "https://acct.r2.cloudflarestorage.com/ferrogate-private/\
                                   .ferrogate/objects/deadbeefcafe/obj_0123456789abcdef";

    #[async_trait]
    impl AssetObjectStore for LeakyStore {
        async fn put_object(
            &self,
            _key: &str,
            _body: &[u8],
            _content_type: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn put_object_owned(
            &self,
            _key: &str,
            _body: Vec<u8>,
            _content_type: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_object(&self, _key: &str, _max_bytes: u64) -> anyhow::Result<Vec<u8>> {
            *self.reads.lock().unwrap() += 1;
            anyhow::bail!("error sending request for url ({LEAKY_STORE_URL})")
        }
        async fn get_object_if_present(
            &self,
            _key: &str,
            _max_bytes: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unimplemented!()
        }
        async fn get_object_stream(&self, _key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
            unimplemented!()
        }
        async fn put_object_stream(
            &self,
            _key: &str,
            _content_type: &str,
            _content_length: u64,
            _content_sha256_hex: &str,
            _body: ObjectByteStream,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_object(&self, _key: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn head_object(&self, _key: &str) -> anyhow::Result<Option<u64>> {
            unimplemented!()
        }
        async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
            unimplemented!()
        }
        fn presign_put(
            &self,
            _key: &str,
            _expires_secs: u64,
            _timestamp_unix: u64,
            _size_bytes: u64,
            _content_sha256_hex: &str,
        ) -> anyhow::Result<PresignedUpload> {
            unimplemented!()
        }
        fn presign_get(
            &self,
            _key: &str,
            _expires_secs: u64,
            _timestamp_unix: u64,
        ) -> anyhow::Result<String> {
            unimplemented!()
        }
    }

    /// A store that actually serves bytes, and reports what the aggregate
    /// budget looked like at the instant the transport was called. That
    /// observation is the difference between "the charge is taken" and "the
    /// charge is taken before the object is in memory".
    struct ServingStore {
        body: Vec<u8>,
        budget: &'static super::super::asset_admission::GatewayBufferBudget,
        free_bytes_during_get: Arc<Mutex<Option<u64>>>,
    }

    #[async_trait]
    impl AssetObjectStore for ServingStore {
        async fn put_object(
            &self,
            _key: &str,
            _body: &[u8],
            _content_type: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn put_object_owned(
            &self,
            _key: &str,
            _body: Vec<u8>,
            _content_type: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_object(&self, _key: &str, _max_bytes: u64) -> anyhow::Result<Vec<u8>> {
            *self.free_bytes_during_get.lock().unwrap() = Some(self.budget.available_bytes());
            Ok(self.body.clone())
        }
        async fn get_object_if_present(
            &self,
            _key: &str,
            _max_bytes: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unimplemented!()
        }
        async fn get_object_stream(&self, _key: &str) -> anyhow::Result<Option<ObjectByteStream>> {
            unimplemented!()
        }
        async fn put_object_stream(
            &self,
            _key: &str,
            _content_type: &str,
            _content_length: u64,
            _content_sha256_hex: &str,
            _body: ObjectByteStream,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_object(&self, _key: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn head_object(&self, _key: &str) -> anyhow::Result<Option<u64>> {
            unimplemented!()
        }
        async fn list_objects(&self) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
            unimplemented!()
        }
        fn presign_put(
            &self,
            _key: &str,
            _expires_secs: u64,
            _timestamp_unix: u64,
            _size_bytes: u64,
            _content_sha256_hex: &str,
        ) -> anyhow::Result<PresignedUpload> {
            unimplemented!()
        }
        fn presign_get(
            &self,
            _key: &str,
            _expires_secs: u64,
            _timestamp_unix: u64,
        ) -> anyhow::Result<String> {
            unimplemented!()
        }
    }

    /// A leaked enforcing budget, because [`ServingStore`] needs a `'static`
    /// handle to observe it from inside the transport. One per test, so no
    /// test can be perturbed by another's charges.
    fn enforcing_budget(
        total_bytes: u64,
        per_read_bytes: u64,
    ) -> &'static super::super::asset_admission::GatewayBufferBudget {
        Box::leak(Box::new(
            super::super::asset_admission::GatewayBufferBudget::new(
                total_bytes,
                per_read_bytes,
                std::time::Duration::ZERO,
            ),
        ))
    }

    /// Issue #529 review finding 2: the whole feature was pinned only through a
    /// hand-built `BufferedObject::new(vec![...], permit)`. Nothing asserted
    /// that THE CHOKEPOINT takes a charge and keeps it, and every landed
    /// `read_object_bounded` test passed a *disabled* budget -- so
    /// `Ok(bytes) => { drop(permit); Ok(BufferedObject::unbudgeted(bytes)) }`
    /// survived the entire suite, demoting a memory ceiling to a bucket-GET
    /// rate limiter without a single failure.
    ///
    /// Three separate claims, because they fail separately:
    ///
    /// 1. the charge is taken BEFORE the transport is asked for bytes (observed
    ///    from inside `get_object`, so it cannot be satisfied by charging after
    ///    the object is already resident);
    /// 2. the charge is STILL HELD when the call returns, i.e. for as long as
    ///    the caller holds the buffer; and
    /// 3. it comes back when, and only when, the buffer is dropped.
    #[tokio::test]
    async fn the_chokepoint_takes_the_charge_before_the_read_and_holds_it_after() {
        const OBJECT_BYTES: u64 = 64 * 1024;
        let budget = enforcing_budget(1024 * 1024, OBJECT_BYTES);
        let free_bytes_during_get = Arc::new(Mutex::new(None));
        let store = ServingStore {
            body: vec![7_u8; OBJECT_BYTES as usize],
            budget,
            free_bytes_during_get: Arc::clone(&free_bytes_during_get),
        };
        assert!(
            budget.is_enforced(),
            "a disabled budget would make every assertion below vacuous"
        );
        let free_before = budget.available_bytes();

        let object = read_object_bounded(
            &store,
            "any-key",
            OBJECT_BYTES,
            OBJECT_BYTES,
            budget,
            super::super::asset_admission::ReadResidency::BufferOnly,
            "id",
            "req",
        )
        .await
        .map_err(|_| ())
        .expect("an in-budget read against an idle budget must be admitted");
        assert_eq!(object.len(), OBJECT_BYTES as usize);

        assert_eq!(
            free_bytes_during_get
                .lock()
                .unwrap()
                .expect("the transport must have been called"),
            free_before - OBJECT_BYTES,
            "the charge must be taken BEFORE the bucket GET: admitting after the bytes are \
             already in memory bounds nothing"
        );
        assert_eq!(
            budget.available_bytes(),
            free_before - OBJECT_BYTES,
            "the charge must still be held when the read RETURNS -- releasing it here is the \
             difference between a memory ceiling and a rate limiter on bucket GETs"
        );

        drop(object);
        assert_eq!(
            budget.available_bytes(),
            free_before,
            "dropping the buffer -- and only that -- returns the charge"
        );
    }

    /// The other half of the same property: a read that never produces bytes
    /// must not keep the capacity it reserved for them. Without this, a bucket
    /// outage would leak the whole budget one failed read at a time and the
    /// gateway would shed everything until restart.
    #[tokio::test]
    async fn a_failed_chokepoint_read_returns_its_charge() {
        let budget = enforcing_budget(1024 * 1024, 64 * 1024);
        let store = LeakyStore {
            reads: Arc::new(Mutex::new(0)),
        };
        let free_before = budget.available_bytes();

        let refusal = read_object_bounded(
            &store,
            "any-key",
            64 * 1024,
            64 * 1024,
            budget,
            super::super::asset_admission::ReadResidency::BufferOnly,
            "id",
            "req",
        )
        .await
        .expect_err("a failing bucket cannot produce bytes");

        assert!(matches!(refusal, BufferedReadRefusal::Transport));
        assert_eq!(
            budget.available_bytes(),
            free_before,
            "a transport failure must return the charge it reserved"
        );
    }

    /// A read the chokepoint sheds must cost the budget nothing at all -- the
    /// permit is never taken, so a shed cannot itself contribute to the
    /// condition that caused it.
    #[tokio::test]
    async fn a_shed_chokepoint_read_takes_no_charge_and_no_bucket_round_trip() {
        const OBJECT_BYTES: u64 = 64 * 1024;
        let budget = enforcing_budget(OBJECT_BYTES, OBJECT_BYTES);
        let reads = Arc::new(Mutex::new(0));
        let store = LeakyStore {
            reads: Arc::clone(&reads),
        };
        let _committed = budget
            .admit(
                super::super::asset_admission::ReadResidency::BufferOnly,
                OBJECT_BYTES,
            )
            .await
            .map_err(|_| ())
            .expect("the first read commits the whole budget");
        assert_eq!(budget.available_bytes(), 0);

        let refusal = read_object_bounded(
            &store,
            "any-key",
            OBJECT_BYTES,
            OBJECT_BYTES,
            budget,
            super::super::asset_admission::ReadResidency::BufferOnly,
            "id",
            "req",
        )
        .await
        .expect_err("a read against a fully committed budget must be shed");

        assert!(matches!(
            refusal,
            BufferedReadRefusal::Overloaded {
                requested_bytes: 65_536,
                ..
            }
        ));
        assert_eq!(
            *reads.lock().unwrap(),
            0,
            "a shed read must not issue a bucket GET"
        );
        assert_eq!(budget.available_bytes(), 0, "and must not take a charge");
    }

    /// The declared size is refused BEFORE the bucket is touched: an
    /// over-budget object costs the gateway one comparison, not a request.
    #[tokio::test]
    async fn an_over_budget_object_is_refused_without_a_bucket_round_trip() {
        let reads = Arc::new(Mutex::new(0));
        let store = LeakyStore {
            reads: Arc::clone(&reads),
        };

        let refusal = read_object_bounded(
            &store,
            "any-key",
            100 * 1024 * 1024,
            1024,
            super::super::asset_admission::GatewayBufferBudget::disabled(),
            super::super::asset_admission::ReadResidency::BufferOnly,
            "id",
            "req",
        )
        .await
        .expect_err("an over-budget object must be refused");
        assert!(matches!(
            refusal,
            BufferedReadRefusal::TooLarge {
                size_bytes: 104_857_600,
                limit_bytes: 1024
            }
        ));
        assert_eq!(
            *reads.lock().unwrap(),
            0,
            "the refusal must not cost a bucket round trip"
        );
    }

    /// Issue #259 review finding 4: the transport's error must never reach the
    /// caller, because its `Display` carries the internal object key and the
    /// bucket endpoint.
    #[tokio::test]
    async fn a_transport_failure_is_collapsed_and_never_carries_the_bucket_location() {
        let store = LeakyStore {
            reads: Arc::new(Mutex::new(0)),
        };

        let refusal = read_object_bounded(
            &store,
            "any-key",
            10,
            1024,
            super::super::asset_admission::GatewayBufferBudget::disabled(),
            super::super::asset_admission::ReadResidency::BufferOnly,
            "id",
            "req",
        )
        .await
        .expect_err("a failing bucket cannot produce bytes");
        assert!(
            matches!(refusal, BufferedReadRefusal::Transport),
            "the caller gets an opaque transport refusal, not the bucket's words"
        );
        // The single message every read surface renders for that refusal.
        for fragment in [
            "r2.cloudflarestorage.com",
            ".ferrogate/objects",
            "obj_",
            "ferrogate-private",
        ] {
            assert!(
                !BUCKET_READ_UNAVAILABLE_MESSAGE.contains(fragment),
                "the caller-visible message must not carry {fragment}"
            );
        }
        assert!(
            LEAKY_STORE_URL.contains(".ferrogate/objects"),
            "the fixture must actually contain what we are asserting is withheld, \
             or this test proves nothing"
        );
    }

    /// The budget binds the bytes that ARRIVE, not just the size the registry
    /// row claims. A chunked response has no `Content-Length`, so this is the
    /// accumulation guard on its own.
    #[tokio::test]
    async fn a_chunked_response_cannot_exceed_the_budget_it_was_given() {
        let endpoint = spawn_chunked_bucket_mock(256 * 1024);
        let bucket = client(endpoint);

        // Matched rather than `expect_err`'d so a regression reports the
        // failure instead of dumping the whole over-budget body.
        let error = match bucket
            .get_object("tenant-a:cli_tool:liar:1.0.0", 64 * 1024)
            .await
        {
            Ok(body) => panic!(
                "a body larger than the budget must not be buffered, but {} bytes were held",
                body.len()
            ),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("in-memory budget"),
            "unexpected error: {error}"
        );
    }

    /// A `Content-Length` above the budget is refused before the body is read.
    #[tokio::test]
    async fn a_declared_content_length_above_the_budget_is_refused() {
        let (endpoint, _captured) = spawn_bucket_mock("200 OK", b"0123456789ABCDEF");
        let bucket = client(endpoint);

        let error = bucket
            .get_object("tenant-a:cli_tool:big:1.0.0", 8)
            .await
            .expect_err("a declared length above the budget must be refused");
        assert!(
            error.to_string().contains("in-memory budget"),
            "unexpected error: {error}"
        );
    }

    /// The #529 shed message is a contract, not prose: an operator reading it
    /// must learn which knob refused them, and a client must learn which
    /// endpoint still works. Both are asserted here so a reword cannot quietly
    /// drop either -- the e2e burst test asserts the same two fragments over
    /// the wire.
    #[test]
    fn the_aggregate_shed_message_names_the_knob_and_the_endpoint_that_works() {
        let message = gateway_buffer_budget_exhausted_message(
            "cli_tool", "rg", "1.0.0", 4_194_304, 8_388_608, 250,
        );

        assert!(
            message.contains("max_total_gateway_buffer_bytes"),
            "{message}"
        );
        assert!(
            message.contains("/v1/assets/presign/download/cli_tool/rg/1.0.0"),
            "{message}"
        );
        assert!(
            message.contains("4194304") && message.contains("8388608"),
            "{message}"
        );
        assert!(message.contains("250ms"), "{message}");
    }

    /// Assert that every path a structural guard exempts names a real file.
    ///
    /// The four scans below exempt files BY PATH, relative to this crate's
    /// `src`. An exemption that points at nothing is not a harmless no-op: it
    /// silently widens the guard, because the file it was meant to exempt is
    /// now scanned like any other. #553 stage 3b moved this tree from
    /// `ferrogate-cli/src/gateway/` to `ferrogate-gateway/src/server/` and the
    /// allow-lists did not move; three guards went red and one, the
    /// `into_parts` scan, stayed GREEN with a self-exemption pointing at a
    /// path that had not existed for days -- purely because its own source
    /// happened not to carry the needle in a flagged form.
    ///
    /// So the guards' paths get a floor of their own. Nothing else here can
    /// tell "this exemption is load-bearing" from "this exemption resolves to
    /// nothing", and that is the difference the whole #553 window hid.
    fn assert_every_exemption_resolves(source_root: &std::path::Path, allowed: &[&str]) {
        for relative in allowed {
            assert!(
                source_root.join(relative).is_file(),
                "the exemption {relative:?} names no file under {}. An exemption that \
                 resolves to nothing does not fail this guard by itself -- it just stops \
                 exempting, so either the file moved (fix the path) or the exemption is \
                 dead (delete it), but it may not sit here meaning neither.",
                source_root.display()
            );
        }
    }

    /// The structural half of the #259 round-2 fix, and the answer to "what
    /// happens when someone adds a fifth read surface".
    ///
    /// Round 1 bounded ONE of four bucket-backed reads because the check lived
    /// at a call site. Two guards now replace that: the transport cannot be
    /// invoked without a byte budget (a compile error, not a review catch), and
    /// this test pins WHERE the buffering read may be invoked from. A new
    /// surface that reaches for `get_object` directly -- rather than going
    /// through `read_object_bounded` / `read_asset_content` /
    /// `load_asset_content`, which supply the budget from configuration --
    /// fails here by name.
    #[test]
    fn the_buffering_bucket_read_is_only_called_from_the_bounded_chokepoint() {
        /// Files allowed to invoke the buffering reads directly.
        ///
        /// - `asset_bucket.rs` defines them and hosts `read_object_bounded`.
        /// - `asset_presign.rs` calls `get_object_if_present` on the commit's
        ///   buffered leg, which is only reached after `actual_size <=
        ///   buffer_limit` and passes that same limit to the transport.
        // Paths are relative to this crate's `src`. They said `gateway/...`
        // until #561: #553 stage 3b moved the whole gateway trunk from
        // `ferrogate-cli/src/gateway/` to `ferrogate-gateway/src/server/`, and
        // the allow-list did not move with it, so every entry stopped matching
        // and the two files this guard exists to exempt became its only
        // offenders. Nothing ran the crate's suite, so the guard sat failing.
        const ALLOWED: [&str; 2] = ["server/asset_bucket.rs", "server/asset_presign.rs"];

        let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_every_exemption_resolves(&source_root, &ALLOWED);
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0_usize;
        let mut pending = vec![source_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable source directory") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                // Test modules legitimately drive the raw reads with an
                // explicit budget; the invariant is about production paths.
                if !name.ends_with(".rs")
                    || name.ends_with("_test.rs")
                    || name.ends_with("_tests.rs")
                {
                    continue;
                }
                let relative = path
                    .strip_prefix(&source_root)
                    .expect("path under src")
                    .to_string_lossy()
                    .replace('\\', "/");
                if ALLOWED.contains(&relative.as_str()) {
                    continue;
                }
                scanned += 1;
                let body = std::fs::read_to_string(&path).expect("readable source file");
                for (index, line) in body.lines().enumerate() {
                    if line.contains(".get_object(") || line.contains(".get_object_if_present(") {
                        offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
                    }
                }
            }
        }

        assert!(
            scanned > 50,
            "the scan found only {scanned} source files, so it is not actually looking at the \
             crate and would pass vacuously"
        );
        assert!(
            offenders.is_empty(),
            "these call the buffering bucket read outside the bounded chokepoint -- route them \
             through asset_bucket::read_object_bounded (or AppState::read_asset_content / \
             FerroGateway::load_asset_content, which do) so they inherit the gateway memory \
             bound instead of adding a copy of the check:\n{}",
            offenders.join("\n")
        );
    }

    /// The #529 counterpart of the guard above, closing the escape hatch the
    /// aggregate budget would otherwise have.
    ///
    /// `read_object_bounded` charges every bucket read, but a new surface could
    /// still mint an UNCHARGED buffer by calling
    /// `BufferedObject::unbudgeted(...)` -- which exists for genuinely
    /// uncharged bytes (inline `stored_assets.content`, which is resident
    /// because the registry row is). This names any other caller by file and
    /// line, so "the aggregate ceiling is enforced" cannot quietly become "the
    /// aggregate ceiling is enforced except over there".
    #[test]
    fn uncharged_buffers_are_only_minted_on_the_inline_content_paths() {
        /// Files allowed to mint an uncharged buffer.
        ///
        /// - `asset_admission.rs` defines it.
        /// - `assets.rs` (`load_asset_content`) and `state_assets.rs`
        ///   (`read_asset_content`) return inline registry content through it,
        ///   which never came from the bucket.
        /// - `asset_bucket.rs` hosts this scan, whose own source carries the
        ///   needle it searches for.
        //
        // The `server/` prefixes are the #553 stage 3b location; see the
        // allow-list above for why they were stale. Three of these four moved,
        // not all of them -- `state_assets.rs` is top level and kept matching
        // throughout, which is worth saying precisely, because "the whole list
        // broke" and "most of the list broke, so the guard's message named the
        // wrong offenders" are different failures and only the second happened
        // here.
        const ALLOWED: [&str; 4] = [
            "server/asset_admission.rs",
            "server/asset_bucket.rs",
            "server/assets.rs",
            "state_assets.rs",
        ];

        let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_every_exemption_resolves(&source_root, &ALLOWED);
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0_usize;
        let mut pending = vec![source_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable source directory") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !name.ends_with(".rs")
                    || name.ends_with("_test.rs")
                    || name.ends_with("_tests.rs")
                {
                    continue;
                }
                let relative = path
                    .strip_prefix(&source_root)
                    .expect("path under src")
                    .to_string_lossy()
                    .replace('\\', "/");
                if ALLOWED.contains(&relative.as_str()) {
                    continue;
                }
                scanned += 1;
                let body = std::fs::read_to_string(&path).expect("readable source file");
                for (index, line) in body.lines().enumerate() {
                    if line.contains("BufferedObject::unbudgeted(")
                        || line.contains("BufferPermit::unbudgeted(")
                    {
                        offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
                    }
                }
            }
        }

        assert!(
            scanned > 50,
            "the scan found only {scanned} source files, so it is not actually looking at the \
             crate and would pass vacuously"
        );
        assert!(
            offenders.is_empty(),
            "these mint an asset buffer that is never charged against \
             [asset_bucket].max_total_gateway_buffer_bytes -- take the bytes through \
             asset_bucket::read_object_bounded, which charges them:\n{}",
            offenders.join("\n")
        );
    }

    /// The third structural guard, and the one issue #529's review named
    /// directly: on the surfaces that write their own response, the entire
    /// aggregate-residency guarantee is the difference between
    ///
    /// ```ignore
    /// let (content, _budget) = content.into_parts();  // charge held across the write
    /// let (content, _)       = content.into_parts();  // charge dropped right here
    /// ```
    ///
    /// Nothing but a comment stood between those two spellings. Both compile,
    /// both pass every behavioral test in the suite (the e2e's contention
    /// window sits inside the bucket GET, so an early release hides there), and
    /// one of them silently converts the ceiling into a rate limiter. This scan
    /// makes the second spelling fail by file and line.
    #[test]
    fn the_admission_permit_is_never_discarded_at_a_split() {
        /// This file hosts the scan, so its own source carries the needle; the
        /// same exemption the two guards above take. It read
        /// `gateway/asset_bucket.rs` from #553 stage 3b until #561 -- and this
        /// guard stayed GREEN throughout, which is why nothing found it. That
        /// is what `assert_every_exemption_resolves` is for.
        const SELF_EXEMPTION: &str = "server/asset_bucket.rs";

        let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_every_exemption_resolves(&source_root, &[SELF_EXEMPTION]);
        let mut offenders: Vec<String> = Vec::new();
        let mut splits = 0_usize;
        let mut scanned = 0_usize;
        let mut pending = vec![source_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable source directory") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !name.ends_with(".rs")
                    || name.ends_with("_test.rs")
                    || name.ends_with("_tests.rs")
                {
                    continue;
                }
                let relative = path
                    .strip_prefix(&source_root)
                    .expect("path under src")
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative == SELF_EXEMPTION {
                    continue;
                }
                scanned += 1;
                let body = std::fs::read_to_string(&path).expect("readable source file");
                for (index, line) in body.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") || trimmed.starts_with("///") {
                        continue;
                    }
                    if !trimmed.contains(".into_parts()") {
                        continue;
                    }
                    splits += 1;
                    if trimmed.contains(", _)") || trimmed.contains(",_)") {
                        offenders.push(format!("{relative}:{}: {}", index + 1, trimmed));
                    }
                }
            }
        }

        assert!(
            scanned > 50,
            "the scan found only {scanned} source files, so it is not actually looking at the \
             crate and would pass vacuously"
        );
        assert!(
            splits > 0,
            "the scan found no BufferedObject::into_parts call at all; either the read surfaces \
             stopped splitting their buffers (in which case delete this guard deliberately) or \
             the needle no longer matches the code"
        );
        assert!(
            offenders.is_empty(),
            "these split a BufferedObject and throw the admission permit away, releasing the \
             aggregate charge while the bytes are still resident and still being written. Bind \
             it to a named `_budget` local that outlives the response write:\n{}",
            offenders.join("\n")
        );
    }

    /// The same guard for the other half of the four surfaces. `fetch_asset`
    /// and MCP `resources/read` do not write bytes; they inline a JSON copy of
    /// the object into a response value somebody else serializes. The charge
    /// must be forwarded ONTO that value
    /// ([`InlinedAssetEntry::budget`](crate::builtin_tools::InlinedAssetEntry)),
    /// and a caller that uses `entry.value` and quietly drops `entry` compiles,
    /// passes, and reintroduces exactly the bug this rework fixes.
    #[test]
    fn every_inlined_asset_entry_forwards_its_charge_to_the_response() {
        /// How many lines after the call the forwarding may appear on. Small
        /// on purpose: both call sites destructure the entry on the spot, and
        /// a forwarding that drifts further than this from the call is one a
        /// reader can no longer see is there.
        const WINDOW: usize = 3;
        /// This file hosts the scan, so its own source carries the needle; the
        /// same exemption the guards above take.
        const SELF_EXEMPTION: &str = "server/asset_bucket.rs";

        let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_every_exemption_resolves(&source_root, &[SELF_EXEMPTION]);
        let mut offenders: Vec<String> = Vec::new();
        let mut call_sites = 0_usize;
        let mut pending = vec![source_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable source directory") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !name.ends_with(".rs")
                    || name.ends_with("_test.rs")
                    || name.ends_with("_tests.rs")
                {
                    continue;
                }
                let relative = path
                    .strip_prefix(&source_root)
                    .expect("path under src")
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative == SELF_EXEMPTION {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("readable source file");
                let lines: Vec<&str> = body.lines().collect();
                for (index, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();
                    // The definition itself, and doc comments naming it, are
                    // not call sites.
                    if trimmed.starts_with("//")
                        || trimmed.starts_with("///")
                        || trimmed.contains("pub(crate) fn asset_resource_content_entry")
                    {
                        continue;
                    }
                    if !trimmed.contains("asset_resource_content_entry(") {
                        continue;
                    }
                    call_sites += 1;
                    let window = lines[index..lines.len().min(index + WINDOW)].join("\n");
                    if !window.contains("budget") {
                        offenders.push(format!("{relative}:{}: {}", index + 1, trimmed));
                    }
                }
            }
        }

        assert!(
            call_sites >= 2,
            "the scan found {call_sites} inlining call sites; issue #529 names two \
             (`fetch_asset` and MCP `resources/read`), so the needle has stopped matching and \
             this guard is passing vacuously"
        );
        assert!(
            offenders.is_empty(),
            "these inline a full copy of an asset into a response without forwarding the \
             admission charge that copy is holding, so the charge is released while the copy is \
             still resident and still being written:\n{}",
            offenders.join("\n")
        );
    }

    #[tokio::test]
    async fn get_object_returns_the_response_body() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"fetched bytes");
        let bucket = client(endpoint);

        let bytes = bucket
            .get_object("tenant-a:cli_tool:hello:1.0.0", TEST_READ_BUDGET)
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
            .get_object("tenant-a:cli_tool:missing:1.0.0", TEST_READ_BUDGET)
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
        assert_eq!(
            upload.url.matches("/storage/v1/s3").count(),
            1,
            "the endpoint base path must be included exactly once in the presigned URL: {}",
            upload.url
        );
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

    #[tokio::test]
    async fn path_prefixed_s3_endpoint_lists_with_prefixed_canonical_uri_and_host() {
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <IsTruncated>false</IsTruncated>\
            </ListBucketResult>";
        let (endpoint, captured) = spawn_bucket_mock("200 OK", xml.as_bytes());
        let endpoint_host = endpoint
            .strip_prefix("http://")
            .expect("mock endpoint is http")
            .to_string();
        let bucket = client(format!("{endpoint}/storage/v1/s3"));

        let objects = bucket.list_objects().await.unwrap();
        assert!(objects.is_empty());

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.host.as_deref(), Some(endpoint_host.as_str()));
        assert!(request.path.starts_with("/storage/v1/s3/ferrogate-assets?"));
        assert!(request.path.contains("list-type=2"));
        assert_eq!(
            request.path.matches("/storage/v1/s3").count(),
            1,
            "the endpoint base path must be included exactly once in the LIST request target: {}",
            request.path
        );
        assert!(request.has_authorization);

        let (fixed_path, host) = {
            let endpoint = bucket.endpoint().unwrap();
            (
                endpoint.bucket_path(&bucket.config.bucket),
                endpoint.host.clone(),
            )
        };
        let canonical_query = request
            .path
            .split_once('?')
            .map(|(_, query)| query)
            .expect("LIST request carries a query");
        let timestamp_unix = sigv4_timestamp_unix(
            request
                .x_amz_date
                .as_deref()
                .expect("runtime sent x-amz-date"),
        );
        let credentials = test_credentials(&bucket);
        let fixed = ferrogate_providers::sign_sigv4_with_content_hash_header_and_query(
            &SigningRequest {
                method: "GET",
                path: &fixed_path,
                host: &host,
                region: &bucket.config.region,
                service: "s3",
                body: b"",
                timestamp_unix,
            },
            &credentials,
            canonical_query,
        );
        let old_host = format!("{endpoint_host}/storage/v1/s3");
        let old_path = "/ferrogate-assets";
        let old = ferrogate_providers::sign_sigv4_with_content_hash_header_and_query(
            &SigningRequest {
                method: "GET",
                path: old_path,
                host: &old_host,
                region: &bucket.config.region,
                service: "s3",
                body: b"",
                timestamp_unix,
            },
            &credentials,
            canonical_query,
        );
        assert_eq!(
            request.authorization.as_deref(),
            Some(fixed.authorization.as_str())
        );
        assert_ne!(
            request.authorization.as_deref(),
            Some(old.authorization.as_str()),
            "restoring the old LIST split would sign the prefix as Host and omit it from the canonical URI"
        );
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
            ("https", "project.supabase.co".to_string())
        );
        let endpoint = https_bucket.endpoint().unwrap();
        assert_eq!(
            endpoint.object_path(&https_bucket.config.bucket, "tenant-a:cli_tool:hello:1.0.0"),
            "/storage/v1/s3/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0"
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
        // A bare trailing slash is ignored -- and only because the shared
        // parser trims it too (`parse_endpoint`). A real path suffix is NOT
        // ignored: it would become a base path before the bucket/key path, so
        // the strict parse rejects it. See
        // `r2_validation_and_the_runtime_signer_agree_on_every_endpoint`.
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.r2.cloudflarestorage.com/"),
            Some(R2Endpoint {
                account_id: "abc123def456".into(),
                jurisdiction: None,
            })
        );
        // Upper case is a legal spelling of the same DNS host and parses to
        // the same (normalized) account id.
        assert_eq!(
            parse_r2_endpoint("https://ABC123DEF456.R2.CloudflareStorage.com"),
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
        // A path suffix or an explicit port would be signed into the `host`
        // header verbatim, so neither is a well-formed R2 endpoint (#485).
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.r2.cloudflarestorage.com/x"),
            None
        );
        assert_eq!(
            parse_r2_endpoint("https://abc123def456.r2.cloudflarestorage.com:8443"),
            None
        );
    }

    /// The #485 contract, as a table: for every endpoint shape, the load-time
    /// R2 guard's verdict is checked against the host the runtime signer
    /// actually builds.
    ///
    /// Two directions are asserted, and together they are what makes the two
    /// paths unable to drift apart:
    ///   * ACCEPTED => the signed host is *exactly* the R2 host reassembled
    ///     from the parse result (account id + optional jurisdiction +
    ///     suffix). No port, no path, lower case -- nothing the guard didn't
    ///     see.
    ///   * REJECTED-but-detected => the signed host is demonstrably something
    ///     R2 cannot serve, and the guard says so at load time instead of
    ///     letting it become a `SignatureDoesNotMatch` at request time.
    ///
    /// Before #485 the rows marked `signed_host` containing `/`, `:8443`, or
    /// mixed case were the bugs: the first two were accepted by the guard and
    /// silently signed a broken host; the mixed-case one was not detected as
    /// R2 at all, so neither the host-shape nor the `region = auto` rule ran.
    #[test]
    fn r2_validation_and_the_runtime_signer_agree_on_every_endpoint() {
        // (endpoint, detected as R2, accepted by the strict guard, signed host
        // when the runtime can build one)
        let cases: &[(&str, bool, bool, &str)] = &[
            (
                "https://abc123def456.r2.cloudflarestorage.com",
                true,
                true,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://abc123def456.r2.cloudflarestorage.com/",
                true,
                true,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "  https://abc123def456.r2.cloudflarestorage.com  ",
                true,
                true,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://ABC123DEF456.R2.CloudflareStorage.com",
                true,
                true,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "HTTPS://ABC123DEF456.R2.CloudflareStorage.com",
                true,
                true,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "http://abc123def456.r2.cloudflarestorage.com",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://abc123def456.eu.r2.cloudflarestorage.com",
                true,
                true,
                "abc123def456.eu.r2.cloudflarestorage.com",
            ),
            (
                "https://abc123def456.fedramp.r2.cloudflarestorage.com",
                true,
                true,
                "abc123def456.fedramp.r2.cloudflarestorage.com",
            ),
            // Detected as R2 but the runtime target carries a shape R2 cannot
            // serve.
            (
                "https://abc123def456.r2.cloudflarestorage.com/x",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://abc123def456.r2.cloudflarestorage.com:8443",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com:8443",
            ),
            (
                "https://abc123def456.r2.cloudflarestorage.com?x=1",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://abc123def456.r2.cloudflarestorage.com#fragment",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://user:pass@abc123def456.r2.cloudflarestorage.com",
                true,
                false,
                "abc123def456.r2.cloudflarestorage.com",
            ),
            (
                "https://.r2.cloudflarestorage.com",
                true,
                false,
                ".r2.cloudflarestorage.com",
            ),
            (
                "https://r2.cloudflarestorage.com",
                true,
                false,
                "r2.cloudflarestorage.com",
            ),
            (
                // Multi-label account id: not an R2 account host.
                "https://abc.def.r2.cloudflarestorage.com",
                true,
                false,
                "abc.def.r2.cloudflarestorage.com",
            ),
            // Not R2 at all: the R2 rules must not apply, and the signer's
            // host is unchanged from pre-#485 behavior.
            (
                "https://project.supabase.co/storage/v1/s3",
                false,
                false,
                "project.supabase.co",
            ),
            ("http://127.0.0.1:9999", false, false, "127.0.0.1:9999"),
        ];

        for (endpoint, targets_r2, well_formed, signed_host) in cases {
            let bucket = r2_client(endpoint);
            let (scheme, host) = match bucket.scheme_and_host() {
                Ok(parts) => parts,
                Err(error) => {
                    assert!(
                        !well_formed,
                        "{endpoint}: a well-formed R2 endpoint must be runtime-signable: {error}"
                    );
                    assert!(
                        error
                            .to_string()
                            .contains("must not contain a query or fragment suffix"),
                        "{endpoint}: runtime rejected the endpoint before signing for an unexpected reason: {error}"
                    );
                    assert_eq!(
                        endpoint_targets_r2(endpoint),
                        *targets_r2,
                        "{endpoint}: R2 detection disagrees with the table"
                    );
                    assert_eq!(
                        parse_r2_endpoint(endpoint).is_some(),
                        *well_formed,
                        "{endpoint}: the strict R2 guard disagrees with the table"
                    );
                    continue;
                }
            };
            assert_eq!(
                &host, signed_host,
                "{endpoint}: the signer's host header drifted"
            );
            assert_eq!(
                endpoint_targets_r2(endpoint),
                *targets_r2,
                "{endpoint}: R2 detection disagrees with the table"
            );
            let parsed = parse_r2_endpoint(endpoint);
            assert_eq!(
                parsed.is_some(),
                *well_formed,
                "{endpoint}: the strict R2 guard disagrees with the table"
            );
            // Ask the production parser whether the literal signed host is a
            // valid R2 endpoint under the runtime scheme, then combine it with
            // the no-base-path/no-userinfo/no-port constraints exposed by the
            // same endpoint decomposition the runtime uses. Restating the
            // account/jurisdiction grammar here created a third policy
            // implementation that could drift in lock step with the test while
            // production remained wrong.
            let parts = parse_endpoint(endpoint).unwrap();
            let runtime_target_is_bare_r2 = parts.path_prefix.is_empty()
                && parts.host_name().len() == parts.authority.len()
                && parse_r2_endpoint(&format!("{scheme}://{host}")).is_some();
            assert_eq!(
                parsed.is_some(),
                runtime_target_is_bare_r2,
                "{endpoint}: validation verdict disagrees with the signed endpoint {scheme}://{host}"
            );
        }
    }

    /// The signed `host` header is byte-for-byte
    /// [`EndpointParts::signing_host`], so the value the guard inspects is the
    /// value that lands in the SigV4 canonical request (#485).
    #[test]
    fn the_signed_host_header_is_the_shared_parse_result() {
        for endpoint in [
            "https://abc123def456.r2.cloudflarestorage.com",
            "https://ABC123DEF456.R2.CloudflareStorage.com",
            "HTTPS://ABC123DEF456.R2.CloudflareStorage.com",
            "https://project.supabase.co/storage/v1/s3",
            "http://127.0.0.1:9999",
        ] {
            let parts = parse_endpoint(endpoint).unwrap();
            let bucket = r2_client(endpoint);
            assert_eq!(
                bucket.scheme_and_host().unwrap(),
                (parts.scheme, parts.signing_host()),
                "{endpoint}"
            );
        }
        // An endpoint with no host is rejected identically by both.
        assert!(parse_endpoint("https://").is_err());
        assert!(r2_client("https://").scheme_and_host().is_err());
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
        let endpoint = bucket.endpoint().unwrap();
        let path = endpoint.object_path(&bucket.config.bucket, "tenant-a:cli_tool:hello:1.0.0");
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

    // ---- #410 live-R2 parity proof (gate-owned) -----------------------------

    /// The four env vars the gate sets to run the live-R2 parity proof. There
    /// is no live Cloudflare R2 in the dev sandbox, so every local run of this
    /// test SKIPS cleanly (see [`live_r2_env`]); the gate, which has a real R2
    /// account, sets these and runs the full round trip against the actual R2
    /// SigV4 surface:
    ///
    ///   * `FERROGATE_R2_ACCOUNT_ID`        — 32-hex R2 account id; the endpoint
    ///     is derived as `https://<id>.r2.cloudflarestorage.com`.
    ///   * `FERROGATE_R2_ENDPOINT`          — OPTIONAL full endpoint override for
    ///     the `.eu.`/`.fedramp.` jurisdiction hosts; wins over the derived one.
    ///   * `FERROGATE_R2_BUCKET`            — an existing R2 bucket to round-trip
    ///     objects in (this test creates + deletes its own probe keys only).
    ///   * `FERROGATE_R2_ACCESS_KEY_ID`     — R2 Access Key ID (S3 credential,
    ///     *not* the account API bearer token).
    ///   * `FERROGATE_R2_SECRET_ACCESS_KEY` — the matching R2 Secret Access Key.
    struct LiveR2Env {
        endpoint: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
    }

    /// Reads the live-R2 creds, returning `None` (skip) unless every required
    /// var is present and non-empty. `FERROGATE_R2_ENDPOINT` overrides the
    /// account-id-derived host so the same test can target a jurisdiction host.
    fn live_r2_env() -> Option<LiveR2Env> {
        let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        let endpoint = var("FERROGATE_R2_ENDPOINT").or_else(|| {
            var("FERROGATE_R2_ACCOUNT_ID")
                .map(|account_id| format!("https://{account_id}.{R2_ENDPOINT_SUFFIX}"))
        })?;
        Some(LiveR2Env {
            endpoint,
            bucket: var("FERROGATE_R2_BUCKET")?,
            access_key_id: var("FERROGATE_R2_ACCESS_KEY_ID")?,
            secret_access_key: var("FERROGATE_R2_SECRET_ACCESS_KEY")?,
        })
    }

    /// The full live round trip, factored out so the caller can ALWAYS clean up
    /// both probe keys (operator directive: no lingering R2 objects) before
    /// surfacing any failure — mirrors the D1 live probes' cleanup-then-assert
    /// shape.
    async fn live_r2_exercise(
        bucket: &AssetBucketClient,
        key: &str,
        presign_key: &str,
        body: &[u8],
    ) -> anyhow::Result<()> {
        // 1. Signed PUT (region `auto`, path-style, real payload hash), then
        //    HEAD + GET the exact bytes back.
        bucket
            .put_object(key, body, "application/octet-stream")
            .await?;
        let size = bucket.head_object(key).await?;
        anyhow::ensure!(
            size == Some(body.len() as u64),
            "HEAD size mismatch: {size:?} != {}",
            body.len()
        );
        let fetched = bucket.get_object(key, TEST_READ_BUDGET).await?;
        anyhow::ensure!(fetched == body, "GET bytes must match the PUT bytes");

        // 2. Signed ListObjectsV2 must observe the just-written key.
        let listed = bucket.list_objects().await?;
        anyhow::ensure!(
            listed.iter().any(|object| object.key == key),
            "LIST did not include the just-written key {key}"
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let http = reqwest::Client::new();

        // 3. Presigned GET: an external holder downloads via the signed URL
        //    alone (no bucket-private auth), proving R2 accepts the query-signed
        //    credential scope.
        let get_url = bucket.presign_get(key, 900, now)?;
        let response = http.get(&get_url).send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "presigned GET failed: HTTP {}",
            response.status()
        );
        let presigned_bytes = response.bytes().await?.to_vec();
        anyhow::ensure!(presigned_bytes == body, "presigned GET bytes must match");

        // 4. Bound presigned PUT (#368): the holder uploads directly and MUST
        //    send `required_headers` verbatim. `content-length` is derived from
        //    the body by the HTTP client (exactly as a real uploader does), so
        //    only the remaining signed header(s) are attached explicitly.
        let sha = ferrogate_storage::sha256_hex(body);
        let upload = bucket.presign_put(presign_key, 900, now, body.len() as u64, &sha)?;
        let mut request = http.put(&upload.url).body(body.to_vec());
        for (name, value) in upload
            .required_headers
            .iter()
            .filter(|(name, _)| *name != "content-length")
        {
            request = request.header(*name, value);
        }
        let put_response = request.send().await?;
        anyhow::ensure!(
            put_response.status().is_success(),
            "presigned PUT failed: HTTP {} ({})",
            put_response.status(),
            put_response.text().await.unwrap_or_default()
        );
        let round_tripped = bucket.get_object(presign_key, TEST_READ_BUDGET).await?;
        anyhow::ensure!(
            round_tripped == body,
            "presigned-PUT object bytes must match the declared payload"
        );

        // 5. DELETE removes the object; a follow-up GET sees it gone.
        bucket.delete_object(key).await?;
        anyhow::ensure!(
            bucket
                .get_object_if_present(key, TEST_READ_BUDGET)
                .await?
                .is_none(),
            "object must be gone after DELETE"
        );
        Ok(())
    }

    #[tokio::test]
    async fn live_r2_round_trips_put_get_head_list_delete_and_presigned_put_get() {
        let Some(env) = live_r2_env() else {
            eprintln!(
                "skipping live_r2_round_trips_put_get_head_list_delete_and_presigned_put_get: set \
                 FERROGATE_R2_ACCOUNT_ID (or FERROGATE_R2_ENDPOINT), FERROGATE_R2_BUCKET, \
                 FERROGATE_R2_ACCESS_KEY_ID and FERROGATE_R2_SECRET_ACCESS_KEY to run the live R2 \
                 parity proof (gate-owned; no live R2 in the dev sandbox)"
            );
            return;
        };
        // The gate must hand us a well-formed R2 host: this proves parity
        // against the REAL R2 SigV4 surface (region `auto`, real payload hash,
        // path-style addressing), not some other S3 endpoint.
        assert!(
            parse_r2_endpoint(&env.endpoint).is_some(),
            "live R2 endpoint {} is not a well-formed R2 host",
            env.endpoint
        );

        let bucket = AssetBucketClient::new(AssetBucketConfig {
            endpoint: env.endpoint.clone(),
            bucket: env.bucket.clone(),
            region: R2_REGION.into(),
            access_key_id: env.access_key_id.clone(),
            secret_access_key: env.secret_access_key.clone(),
        });

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let key = format!("ferrogate-r2-live-probe/{stamp}-a");
        let presign_key = format!("ferrogate-r2-live-probe/{stamp}-b");
        let body = format!("ferrogate r2 live parity body {stamp}").into_bytes();

        let result = live_r2_exercise(&bucket, &key, &presign_key, &body).await;
        // Best-effort cleanup of BOTH probe keys regardless of outcome
        // (delete treats a 404 as success), then surface any failure.
        let _ = bucket.delete_object(&key).await;
        let _ = bucket.delete_object(&presign_key).await;
        result.unwrap();
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
        let expected_host = concrete.scheme_and_host().unwrap().1;
        assert_eq!(request.host.as_deref(), Some(expected_host.as_str()));
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

    /// A CloudflareClient transport that records EVERY request it is handed and
    /// replays a scripted sequence of `(status, body)` responses in order — the
    /// shape the multi-request publish flow (session -> upload -> deploy) needs
    /// so each leg can be asserted independently.
    struct ScriptedCfTransport {
        requests: Arc<Mutex<Vec<ferrogate_cloudflare::HttpRequest>>>,
        responses: Mutex<std::collections::VecDeque<(u16, Vec<u8>)>>,
    }

    #[async_trait]
    impl ferrogate_cloudflare::HttpTransport for ScriptedCfTransport {
        async fn execute(
            &self,
            request: ferrogate_cloudflare::HttpRequest,
        ) -> Result<ferrogate_cloudflare::HttpResponse, ferrogate_cloudflare::CloudflareError>
        {
            self.requests.lock().unwrap().push(request);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("ScriptedCfTransport received more requests than scripted responses");
            Ok(ferrogate_cloudflare::HttpResponse {
                status,
                retry_after: None,
                body,
            })
        }
    }

    #[allow(clippy::type_complexity)]
    fn cf_store_scripted(
        responses: Vec<(u16, String)>,
    ) -> (
        WorkersStaticAssetsStore,
        Arc<Mutex<Vec<ferrogate_cloudflare::HttpRequest>>>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(ScriptedCfTransport {
            requests: Arc::clone(&requests),
            responses: Mutex::new(
                responses
                    .into_iter()
                    .map(|(status, body)| (status, body.into_bytes()))
                    .collect(),
            ),
        });
        let cf = CloudflareClient::from_parts(
            ferrogate_cloudflare::CloudflareConfig::new("acct-123", "plaintext-token"),
            Arc::new(ferrogate_cloudflare::EnvTokenResolver::from_process_env()),
            transport,
            Arc::new(ferrogate_cloudflare::TokioClock),
            ferrogate_cloudflare::RetryPolicy::default(),
        );
        let store = WorkersStaticAssetsStore::new(Arc::new(cf), "my-worker".to_string());
        (store, requests)
    }

    /// A `success: true` envelope wrapping `result`.
    fn cf_ok(result: &str) -> String {
        format!(r#"{{"success":true,"errors":[],"messages":[],"result":{result}}}"#)
    }

    /// A session `result` declaring `hash` as the one pending bucket + `jwt`.
    fn session_result(jwt: &str, hash: &str) -> String {
        cf_ok(&format!(r#"{{"jwt":"{jwt}","buckets":[["{hash}"]]}}"#))
    }

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

    #[test]
    fn cf_asset_hash_matches_cloudflares_base64_plus_extension_recipe() {
        // CF hashes SHA-256(base64(bytes) + extension)[0..32]. Pin the recipe so
        // the manifest hash agrees with the upload field name and CF's dedup key.
        let body = b"<html>hi</html>";
        let mut expected = ferrogate_storage::sha256_hex(
            &[BASE64_STANDARD.encode(body).as_bytes(), b"html"].concat(),
        );
        expected.truncate(CF_ASSET_HASH_HEX_LEN);
        assert_eq!(cf_asset_hash("/index.html", body), expected);
        assert_eq!(expected.len(), CF_ASSET_HASH_HEX_LEN);
        // Extension changes the hash; a missing/dotfile extension folds in "".
        assert_ne!(
            cf_asset_hash("/index.html", body),
            cf_asset_hash("/index.txt", body)
        );
        assert_eq!(asset_extension("/a/b/index.html"), "html");
        assert_eq!(asset_extension("/foo.min.js"), "js");
        assert_eq!(asset_extension("/noext"), "");
        assert_eq!(asset_extension("/.gitignore"), "");
    }

    #[tokio::test]
    async fn workers_static_assets_publishes_through_all_three_steps() {
        // #411: put drives the full 3-step direct upload — session negotiation,
        // JWT-authenticated byte upload of the pending bucket, and the Worker
        // script deploy redeeming the completion token — all through the mocked
        // CloudflareClient transport.
        let body = b"<html>hi</html>";
        let hash = cf_asset_hash("/index.html", body);
        let (store, requests) = cf_store_scripted(vec![
            (200, session_result("session-jwt", &hash)),
            (201, cf_ok(r#"{"jwt":"completion-token"}"#)),
            (200, cf_ok(r#"{"id":"my-worker"}"#)),
        ]);
        let store_dyn: &dyn AssetObjectStore = &store;
        store_dyn
            .put_object("/index.html", body, "text/html")
            .await
            .unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3, "session + upload + deploy");

        // Step 1: JSON session negotiation under the account token.
        let session = &requests[0];
        assert_eq!(session.method, HttpMethod::Post);
        assert!(session
            .url
            .ends_with("/workers/scripts/my-worker/assets-upload-session"));

        // Step 2: multipart byte upload to /workers/assets/upload?base64=true,
        // authenticated with the SESSION JWT (not the account token).
        let upload = &requests[1];
        assert_eq!(upload.method, HttpMethod::Post);
        assert!(upload.url.ends_with("/workers/assets/upload?base64=true"));
        assert_eq!(upload.bearer_token, "session-jwt");
        assert_ne!(
            upload.bearer_token, session.bearer_token,
            "step 2 must use the session JWT, not the account token"
        );
        assert_eq!(
            upload.content_type.as_deref(),
            Some(multipart_content_type(WSA_UPLOAD_BOUNDARY).as_str())
        );
        let upload_body = String::from_utf8(upload.body.clone().unwrap()).unwrap();
        // The part is keyed by the file hash and carries the base64 bytes + type.
        assert!(upload_body.contains(&format!("name=\"{hash}\"; filename=\"{hash}\"")));
        assert!(upload_body.contains("Content-Type: text/html"));
        assert!(upload_body.contains(&BASE64_STANDARD.encode(body)));

        // Step 3: multipart Worker script PUT under the account token, carrying
        // the completion token in the assets binding + a main module.
        let deploy = &requests[2];
        assert_eq!(deploy.method, HttpMethod::Put);
        assert!(deploy.url.ends_with("/workers/scripts/my-worker"));
        assert_eq!(deploy.bearer_token, session.bearer_token);
        assert!(deploy
            .content_type
            .as_deref()
            .unwrap()
            .starts_with("multipart/form-data; boundary="));
        let deploy_body = String::from_utf8(deploy.body.clone().unwrap()).unwrap();
        assert!(deploy_body.contains(r#""jwt":"completion-token""#));
        assert!(deploy_body.contains(r#""main_module":"main.js""#));
        assert!(deploy_body.contains("name=\"metadata\""));
    }

    #[tokio::test]
    async fn workers_static_assets_skips_upload_when_everything_is_deduped() {
        // When CF returns no pending buckets, the session JWT is already the
        // completion token: step 2 is skipped and the deploy redeems it directly.
        let (store, requests) = cf_store_scripted(vec![
            (200, cf_ok(r#"{"jwt":"already-complete","buckets":[]}"#)),
            (200, cf_ok(r#"{"id":"my-worker"}"#)),
        ]);
        let store_dyn: &dyn AssetObjectStore = &store;
        store_dyn
            .put_object("/index.html", b"<html>hi</html>", "text/html")
            .await
            .unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "no byte upload when nothing is pending");
        assert!(requests[1].url.ends_with("/workers/scripts/my-worker"));
        let deploy_body = String::from_utf8(requests[1].body.clone().unwrap()).unwrap();
        assert!(deploy_body.contains(r#""jwt":"already-complete""#));
    }

    #[tokio::test]
    async fn workers_static_assets_does_not_claim_publish_when_deploy_fails() {
        // Honesty guard: a failed step-3 deploy surfaces the error and never
        // reports a durable publish. The byte upload still happened (2 prior
        // requests), but the outcome is an error, not a false success.
        let body = b"<html>hi</html>";
        let hash = cf_asset_hash("/index.html", body);
        let (store, requests) = cf_store_scripted(vec![
            (200, session_result("session-jwt", &hash)),
            (201, cf_ok(r#"{"jwt":"completion-token"}"#)),
            // 400 is a non-retryable client error, so the deploy fails on the
            // first attempt (a 5xx would trip the client's retry loop).
            (
                400,
                r#"{"success":false,"errors":[{"code":10021,"message":"boom"}],"messages":[],"result":null}"#
                    .to_string(),
            ),
        ]);
        let store_dyn: &dyn AssetObjectStore = &store;
        let error = store_dyn
            .put_object("/index.html", body, "text/html")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("script deploy failed"),
            "unexpected error: {error}"
        );
        assert_eq!(requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn workers_static_assets_errors_when_session_has_pending_but_no_jwt() {
        // A session that returns pending buckets but no upload JWT cannot
        // authorize the byte upload; the publish fails rather than proceeding.
        let body = b"<html>hi</html>";
        let hash = cf_asset_hash("/index.html", body);
        let (store, requests) = cf_store_scripted(vec![(
            200,
            cf_ok(&format!(r#"{{"buckets":[["{hash}"]]}}"#)),
        )]);
        let store_dyn: &dyn AssetObjectStore = &store;
        let error = store_dyn
            .put_object("/index.html", body, "text/html")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no jwt to authorize the byte upload"),
            "unexpected error: {error}"
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "only the session request was made"
        );
    }

    #[tokio::test]
    async fn workers_static_assets_rejects_a_bucket_hash_not_in_the_manifest() {
        // If CF names a hash the publish never declared, that is a protocol
        // violation — reject rather than upload the wrong bytes under it.
        let (store, _requests) = cf_store_scripted(vec![(
            200,
            session_result("session-jwt", "ffffffffffffffffffffffffffffffff"),
        )]);
        let store_dyn: &dyn AssetObjectStore = &store;
        let error = store_dyn
            .put_object("/index.html", b"<html>hi</html>", "text/html")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not in the published manifest"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn workers_static_assets_reports_s3_only_operations_unsupported() {
        // #411: presign + arbitrary keyed GET/HEAD/LIST/DELETE are structurally
        // unsupported on this CF-native publish target and return a clear error.
        let (store, _last) = cf_store(200, UPLOAD_SESSION_OK);
        let store_dyn: &dyn AssetObjectStore = &store;

        assert!(store_dyn
            .get_object("k", TEST_READ_BUDGET)
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

    // ---- #411 live Workers Static Assets publish proof (gate-owned) ---------

    /// The env vars the gate sets to run the live publish-and-serve proof. There
    /// is no live Cloudflare here, so every local run SKIPS cleanly; the gate,
    /// which has a real account + a route/custom domain on the script, sets
    /// these and runs the full 3-step publish against the real API:
    ///
    ///   * `FERROGATE_WSA_ACCOUNT_ID`  — the Cloudflare account id.
    ///   * `FERROGATE_WSA_API_TOKEN`   — an API token with Workers Scripts Edit
    ///     (an inline plaintext token, resolved exactly as the production
    ///     `WorkersStaticAssets` backend resolves `cf_api_token`).
    ///   * `FERROGATE_WSA_SCRIPT_NAME` — the Worker script to publish onto.
    ///   * `FERROGATE_WSA_SERVE_URL`   — OPTIONAL. When set, the test GETs it
    ///     after publishing and asserts the just-published bytes are served,
    ///     closing the loop end-to-end (requires the script to have a route /
    ///     custom domain, which the gate configures).
    struct LiveWsaEnv {
        account_id: String,
        api_token: String,
        script_name: String,
        serve_url: Option<String>,
    }

    fn live_wsa_env() -> Option<LiveWsaEnv> {
        let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        Some(LiveWsaEnv {
            account_id: var("FERROGATE_WSA_ACCOUNT_ID")?,
            api_token: var("FERROGATE_WSA_API_TOKEN")?,
            script_name: var("FERROGATE_WSA_SCRIPT_NAME")?,
            serve_url: var("FERROGATE_WSA_SERVE_URL"),
        })
    }

    #[tokio::test]
    async fn live_workers_static_assets_publishes_and_optionally_serves() {
        let Some(env) = live_wsa_env() else {
            eprintln!(
                "skipping live_workers_static_assets_publishes_and_optionally_serves: set \
                 FERROGATE_WSA_ACCOUNT_ID, FERROGATE_WSA_API_TOKEN and FERROGATE_WSA_SCRIPT_NAME \
                 (and optionally FERROGATE_WSA_SERVE_URL) to run the live publish proof (gate-owned; \
                 no live Cloudflare in the dev sandbox)"
            );
            return;
        };

        // A real CloudflareClient (reqwest transport) — the same wiring the
        // production `WorkersStaticAssets` backend builds in `state_assets.rs`.
        let cf_config = ferrogate_cloudflare::CloudflareConfig::new(env.account_id, env.api_token);
        let resolver = Arc::new(ferrogate_cloudflare::EnvTokenResolver::from_process_env());
        let client = CloudflareClient::new(cf_config, resolver)
            .expect("failed to build the live Cloudflare client");
        let store = WorkersStaticAssetsStore::new(Arc::new(client), env.script_name);

        // Publish a small, uniquely-marked index.html through the full 3-step
        // flow. A unique body guarantees at least one pending bucket (dodging
        // the server-side dedup edge case) and lets the serve check assert the
        // exact bytes this run published.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let body =
            format!("<!doctype html><html><body>ferrogate wsa live probe {stamp}</body></html>")
                .into_bytes();
        let store_dyn: &dyn AssetObjectStore = &store;
        store_dyn
            .put_object("/index.html", &body, "text/html")
            .await
            .expect("live Workers Static Assets publish failed");

        // If the gate wired a serving route/domain, close the loop: the edge
        // must serve exactly what we just published.
        if let Some(serve_url) = env.serve_url {
            let http = reqwest::Client::new();
            let response = http
                .get(&serve_url)
                .send()
                .await
                .expect("serve GET failed to send");
            assert!(
                response.status().is_success(),
                "serve GET returned HTTP {}",
                response.status()
            );
            let served = response.bytes().await.expect("serve GET body").to_vec();
            assert_eq!(
                served, body,
                "served bytes must match the just-published bundle"
            );
        }
    }
}
