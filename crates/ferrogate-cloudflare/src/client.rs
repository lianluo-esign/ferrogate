// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Thin reqwest-based Cloudflare API client with Bearer auth, retries, and preflight.

//! The shared Cloudflare API client (issue #405).
//!
//! [`CloudflareClient`] is a thin wrapper over an [`HttpTransport`] that adds
//! Bearer auth, `{account_id}` path templating, envelope decoding, typed error
//! mapping, and a retry/backoff loop that honors Cloudflare's global API rate
//! limit (~1,200 requests / 5 min / user). Both the HTTP transport and the
//! clock are **injectable seams** so the whole client — including the backoff
//! schedule — is unit-testable with no network and no real sleeps.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use serde::de::DeserializeOwned;

use crate::config::CloudflareConfig;
use crate::envelope::CloudflareEnvelope;
use crate::error::CloudflareError;
use crate::resolver::{ResolvedToken, TokenResolver};

/// HTTP verbs the client issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// A transport-level request. The `bearer_token` is the already-resolved
/// secret; `Debug` is hand-written to keep it out of logs.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub bearer_token: String,
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer_token", &"<redacted>")
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

/// A transport-level response. `status` is the HTTP status; a non-2xx status is
/// NOT an error at this layer — the client maps it to a typed
/// [`CloudflareError`] after inspecting the envelope.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub body: Vec<u8>,
}

/// The HTTP execution seam. The production impl is [`ReqwestTransport`]; tests
/// inject a scripted fake so envelope/error mapping and backoff are exercised
/// without a network.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Execute a request. Returns `Ok(response)` for *any* HTTP status;
    /// `Err(CloudflareError::Transport)` only for connect/TLS/timeout/body
    /// failures that produced no usable response.
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError>;
}

/// The clock seam used by the backoff loop. Injecting a fake clock lets tests
/// assert the exact backoff schedule without real sleeps.
#[async_trait]
pub trait Clock: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

/// Production clock backed by `tokio::time::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioClock;

#[async_trait]
impl Clock for TokioClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Retry/backoff policy honoring Cloudflare's global API rate limit.
///
/// The schedule is **deterministic** (no random jitter) so it is exactly
/// assertable in tests: on a retryable failure the client waits the server's
/// `Retry-After` when present, else `base_backoff * 2^attempt`, each capped at
/// `max_backoff`. Cloudflare's global limit is ~1,200 requests / 5 min / user
/// (≈4 req/s); a 1s base with exponential growth backs off well inside that
/// envelope after a 429.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 4,
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
        }
    }
}

impl RetryPolicy {
    /// The delay before the `attempt`-th retry (0-based). `retry_after` is the
    /// server's hint, which wins when present. Result is capped at
    /// `max_backoff`; arithmetic is saturating so a large attempt count cannot
    /// overflow.
    pub fn backoff_delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        if let Some(hint) = retry_after {
            return hint.min(self.max_backoff);
        }
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let millis = self
            .base_backoff
            .as_millis()
            .saturating_mul(u128::from(factor));
        let capped = millis.min(self.max_backoff.as_millis());
        Duration::from_millis(capped as u64)
    }
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Outcome of the retry loop: the final response plus how many transport calls
/// were made (1 = succeeded first try).
struct RetryOutcome {
    response: HttpResponse,
    attempts: u32,
}

/// The shared Cloudflare API client.
pub struct CloudflareClient {
    config: CloudflareConfig,
    resolver: Arc<dyn TokenResolver>,
    transport: Arc<dyn HttpTransport>,
    clock: Arc<dyn Clock>,
    retry: RetryPolicy,
}

impl CloudflareClient {
    /// Build a production client: a real reqwest transport + tokio clock +
    /// default retry policy. Fails only if the reqwest client cannot be built.
    pub fn new(
        config: CloudflareConfig,
        resolver: Arc<dyn TokenResolver>,
    ) -> Result<Self, CloudflareError> {
        Ok(Self {
            config,
            resolver,
            transport: Arc::new(ReqwestTransport::new()?),
            clock: Arc::new(TokioClock),
            retry: RetryPolicy::default(),
        })
    }

    /// Assemble a client from explicit parts — the seam tests use to inject a
    /// scripted transport and fake clock.
    pub fn from_parts(
        config: CloudflareConfig,
        resolver: Arc<dyn TokenResolver>,
        transport: Arc<dyn HttpTransport>,
        clock: Arc<dyn Clock>,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            config,
            resolver,
            transport,
            clock,
            retry,
        }
    }

    /// The Cloudflare account id this client is bound to.
    pub fn account_id(&self) -> &str {
        &self.config.account_id
    }

    /// The configuration model backing this client.
    pub fn config(&self) -> &CloudflareConfig {
        &self.config
    }

    /// Resolve the token for a (possibly tenant-scoped) request.
    fn resolve_token(&self, tenant: Option<&str>) -> Result<ResolvedToken, CloudflareError> {
        self.resolver.resolve(self.config.token_reference(tenant))
    }

    /// Build the absolute URL for a `client/v4`-relative path, templating
    /// `{account_id}`.
    fn build_url(&self, path: &str) -> String {
        let templated = path.replace("{account_id}", &self.config.account_id);
        format!(
            "{}/{}",
            self.config.api_base_url.trim_end_matches('/'),
            templated.trim_start_matches('/')
        )
    }

    /// Issue a request and decode its `result` into `T`.
    ///
    /// `path` is relative to the configured `client/v4` base and may contain
    /// the `{account_id}` placeholder. `tenant` selects a per-tenant token
    /// override when configured.
    pub async fn request_json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Vec<u8>>,
        tenant: Option<&str>,
    ) -> Result<T, CloudflareError> {
        let (status, retry_after, bytes) = self.send_raw(method, path, body, tenant).await?;
        let envelope: CloudflareEnvelope<T> = serde_json::from_slice(&bytes).map_err(|e| {
            CloudflareError::Decode(format!("failed to decode Cloudflare envelope: {e}"))
        })?;
        envelope.into_result(status, retry_after)
    }

    /// Convenience GET returning a decoded `result`.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        tenant: Option<&str>,
    ) -> Result<T, CloudflareError> {
        self.request_json(HttpMethod::Get, path, None, tenant).await
    }

    /// Issue a request whose success carries no meaningful `result` (delete
    /// endpoints that return `result: null`). Returns `()` on a
    /// `success: true` envelope, a typed error otherwise.
    pub async fn request_ack(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Vec<u8>>,
        tenant: Option<&str>,
    ) -> Result<(), CloudflareError> {
        let (status, retry_after, bytes) = self.send_raw(method, path, body, tenant).await?;
        let envelope: CloudflareEnvelope<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|e| {
                CloudflareError::Decode(format!("failed to decode Cloudflare envelope: {e}"))
            })?;
        envelope.into_ack(status, retry_after)
    }

    /// Preflight/health check: a cheap `GET /accounts/{account_id}` that
    /// verifies the token is valid AND scoped for the account. A token that
    /// authenticates but lacks a required permission group surfaces as
    /// [`CloudflareError::MissingScope`], whose message names the required
    /// permission groups (see [`crate::scopes`]).
    pub async fn preflight(&self, tenant: Option<&str>) -> Result<(), CloudflareError> {
        let (status, retry_after, bytes) = self
            .send_raw(HttpMethod::Get, "accounts/{account_id}", None, tenant)
            .await?;
        let envelope: CloudflareEnvelope<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|e| {
                CloudflareError::Decode(format!(
                    "failed to decode Cloudflare preflight envelope: {e}"
                ))
            })?;
        envelope.into_ack(status, retry_after)
    }

    /// Resolve the token, run the retry loop, and return the raw response
    /// parts — short-circuiting an exhausted 429 into a typed
    /// [`CloudflareError::RateLimited`] carrying the attempt count.
    async fn send_raw(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Vec<u8>>,
        tenant: Option<&str>,
    ) -> Result<(u16, Option<Duration>, Vec<u8>), CloudflareError> {
        let token = self.resolve_token(tenant)?;
        let request = HttpRequest {
            method,
            url: self.build_url(path),
            bearer_token: token.expose().to_string(),
            body,
        };
        let RetryOutcome { response, attempts } = self.execute_with_retry(request).await?;
        if response.status == 429 {
            return Err(CloudflareError::RateLimited {
                retry_after: response.retry_after,
                attempts,
            });
        }
        Ok((response.status, response.retry_after, response.body))
    }

    /// The retry/backoff loop. Retries retryable HTTP statuses (429/5xx) and
    /// retryable transport failures up to `max_retries`, sleeping via the
    /// injected [`Clock`]. Returns the final response (any status) or an
    /// exhausted-transport error.
    async fn execute_with_retry(
        &self,
        request: HttpRequest,
    ) -> Result<RetryOutcome, CloudflareError> {
        let mut attempt: u32 = 0;
        loop {
            match self.transport.execute(request.clone()).await {
                Ok(response)
                    if is_retryable_status(response.status) && attempt < self.retry.max_retries =>
                {
                    let delay = self.retry.backoff_delay(attempt, response.retry_after);
                    self.clock.sleep(delay).await;
                    attempt += 1;
                }
                Ok(response) => {
                    return Ok(RetryOutcome {
                        response,
                        attempts: attempt + 1,
                    })
                }
                Err(err) if err.is_retryable() && attempt < self.retry.max_retries => {
                    let delay = self.retry.backoff_delay(attempt, None);
                    self.clock.sleep(delay).await;
                    attempt += 1;
                }
                Err(err) => {
                    if attempt == 0 {
                        return Err(err);
                    }
                    return Err(CloudflareError::ExhaustedRetries {
                        attempts: attempt + 1,
                        last: Box::new(err),
                    });
                }
            }
        }
    }
}

/// Production [`HttpTransport`] backed by reqwest with Bearer auth.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build the reqwest client with connect/overall timeouts. Installs the
    /// default rustls crypto provider best-effort (the workspace's reqwest is
    /// `rustls-no-provider`, so a standalone consumer must select one).
    pub fn new() -> Result<Self, CloudflareError> {
        ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                CloudflareError::Config(format!("failed to build Cloudflare HTTP client: {e}"))
            })?;
        Ok(Self { client })
    }

    /// Wrap an already-built reqwest client (share the gateway's pool).
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
            HttpMethod::Put => self.client.put(&request.url),
            HttpMethod::Patch => self.client.patch(&request.url),
            HttpMethod::Delete => self.client.delete(&request.url),
        };
        builder = builder
            .header(AUTHORIZATION, format!("Bearer {}", request.bearer_token))
            .header(ACCEPT, "application/json");
        if let Some(body) = request.body {
            builder = builder.header(CONTENT_TYPE, "application/json").body(body);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| CloudflareError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_retry_after_secs);
        let body = response
            .bytes()
            .await
            .map_err(|e| CloudflareError::Transport(format!("failed to read response body: {e}")))?
            .to_vec();
        Ok(HttpResponse {
            status,
            retry_after,
            body,
        })
    }
}

/// Parse a numeric-seconds `Retry-After` header. The HTTP-date form is
/// intentionally not honored (Cloudflare emits delta-seconds for its API rate
/// limit); an unparseable value yields `None` so the client falls back to its
/// exponential schedule.
fn parse_retry_after_secs(value: &reqwest::header::HeaderValue) -> Option<Duration> {
    value
        .to_str()
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Best-effort install of the aws-lc-rs rustls provider for standalone
/// consumers/tests. The gateway binary may already have installed `ring`, so
/// this is idempotent and ignores the "already installed" result.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
