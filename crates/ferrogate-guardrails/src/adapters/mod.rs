// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Native semantic-detector adapters (Presidio, LLM-Guard) behind a pluggable transport.

//! Native adapter integrations for self-hostable semantic security detectors
//! (#201): Microsoft Presidio (DLP/PII, `/analyze`) and ProtectAI LLM-Guard
//! (prompt injection, `/analyze/prompt`).
//!
//! Both adapters target CUSTOMER-VPC self-hosted deployments — no vendor SaaS,
//! no vendor credential required (an optional bearer token is supported for a
//! reverse-proxy in front of the service). Each adapter keeps its wire format
//! in a single `wire` serde module so a vendor contract drift is a one-file
//! fix, and speaks HTTP through the [`DetectorTransport`] trait so tests can
//! replay recorded fixtures deterministically with no network.

use crate::{
    classify_reqwest_error, ensure_rustls_crypto_provider, status_error, DetectorError,
    DetectorErrorKind, DetectorHealth, DetectorSecret, GuardrailDnsResolver,
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
    Client, StatusCode, Url,
};
use sha2::Sha256;
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

pub mod llm_guard;
pub mod presidio;
pub mod workers_ai_llama_guard;
pub use llm_guard::{LlmGuardPromptInjectionConfig, LlmGuardPromptInjectionDetector};
pub use presidio::{PresidioDetector, PresidioDetectorConfig};
pub use workers_ai_llama_guard::{
    WorkersAiLlamaGuardConfig, WorkersAiLlamaGuardDetector,
    DEFAULT_MODEL as WORKERS_AI_LLAMA_GUARD_DEFAULT_MODEL,
};

/// Recorded-fixture transport for deterministic, network-free adapter tests.
/// Never part of a production build.
#[cfg(any(test, feature = "conformance"))]
pub mod fixture;

/// A raw HTTP reply as seen by an adapter: status code plus bounded body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The single seam between an adapter and the network. Production uses
/// [`HttpJsonTransport`]; tests use [`fixture::FixtureTransport`] to replay
/// recorded request/response pairs deterministically.
#[async_trait]
pub trait DetectorTransport: fmt::Debug + Send + Sync {
    /// POST `body` as `application/json` to the transport's endpoint and
    /// return the reply. Errors are already classified detector errors
    /// (timeout / unavailable / payload bounds); HTTP status mapping is the
    /// caller's concern.
    async fn post_json(&self, body: &[u8]) -> Result<TransportReply, DetectorError>;
}

/// Production transport: a bounded reqwest client pinned to one endpoint, with
/// safe DNS (private ranges rejected unless explicitly allowed), no redirects,
/// an optional bearer token, and a hard response-size ceiling.
pub struct HttpJsonTransport {
    endpoint: Url,
    client: Client,
    bearer_token: Option<DetectorSecret>,
    max_response_bytes: usize,
}

impl fmt::Debug for HttpJsonTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpJsonTransport")
            .field("endpoint", &"<configured>")
            .field("bearer_token", &self.bearer_token)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl HttpJsonTransport {
    pub fn new(
        endpoint: Url,
        timeout: Duration,
        allow_private_network: bool,
        bearer_token: Option<DetectorSecret>,
        max_response_bytes: usize,
    ) -> Result<Self, DetectorError> {
        ensure_rustls_crypto_provider();
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(timeout)
            .dns_resolver(GuardrailDnsResolver {
                allow_private_network,
            })
            .build()
            .map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::InvalidConfiguration,
                    "failed to initialize guardrail adapter HTTP client",
                )
            })?;
        Ok(Self {
            endpoint,
            client,
            bearer_token,
            max_response_bytes,
        })
    }
}

#[async_trait]
impl DetectorTransport for HttpJsonTransport {
    async fn post_json(&self, body: &[u8]) -> Result<TransportReply, DetectorError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(body.to_vec());
        if let Some(token) = &self.bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {}", token.expose()));
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "guardrail adapter response exceeds configured limit",
            ));
        }
        let mut bytes = Vec::new();
        loop {
            let remaining = self.max_response_bytes.saturating_sub(bytes.len());
            let chunk = response.chunk().await.map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::Unavailable,
                    "guardrail adapter response could not be read",
                )
            })?;
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.len() > remaining {
                return Err(DetectorError::new(
                    DetectorErrorKind::PayloadTooLarge,
                    "guardrail adapter response exceeds configured limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(TransportReply {
            status,
            body: bytes,
        })
    }
}

/// Map a non-success HTTP status onto the shared detector error taxonomy.
pub(crate) fn adapter_status_error(status: u16) -> DetectorError {
    match StatusCode::from_u16(status) {
        Ok(status) => status_error(status),
        Err(_) => DetectorError::new(
            DetectorErrorKind::InvalidResponse,
            "guardrail adapter returned an invalid HTTP status",
        ),
    }
}

/// Keyed, non-reversible fingerprint for evidence: HMAC-SHA256 over the
/// flagged value, hex-encoded. Mirrors the deterministic detector's evidence
/// scheme so downstream tooling treats all fingerprints uniformly.
pub(crate) fn hmac_evidence_fingerprint(
    key: &DetectorSecret,
    value: &str,
) -> Result<String, DetectorError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| {
        DetectorError::new(
            DetectorErrorKind::Internal,
            "guardrail adapter fingerprint key is unusable",
        )
    })?;
    mac.update(value.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut output = String::with_capacity("hmac-sha256:".len() + bytes.len() * 2);
    output.push_str("hmac-sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

/// Convert a character index (as reported by Python-based services such as
/// Presidio, which index by Unicode code point) to a byte offset in `text`.
/// `None` when the index is out of range.
pub(crate) fn char_index_to_byte_offset(text: &str, char_index: usize) -> Option<usize> {
    let mut count = 0usize;
    for (byte_offset, _) in text.char_indices() {
        if count == char_index {
            return Some(byte_offset);
        }
        count += 1;
    }
    (char_index == count).then_some(text.len())
}

/// Short, stable digest of an adapter's semantic configuration, appended to the
/// reported detector version so evidence records which configuration produced a
/// verdict.
pub(crate) fn config_digest(parts: &[&str]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(8);
    for byte in &digest[..4] {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Simple success/failure counters shared by the native adapters. The adapters
/// deliberately have no circuit breaker of their own (`CustomHttpDetector`
/// owns that pattern); their declared failure modes therefore exclude
/// `CircuitOpen`.
#[derive(Debug, Default)]
pub(crate) struct AdapterCounters {
    request_total: AtomicU64,
    success_total: AtomicU64,
    failure_total: AtomicU64,
}

impl AdapterCounters {
    pub(crate) fn record_request(&self) {
        self.request_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_outcome<T>(
        &self,
        outcome: Result<T, DetectorError>,
    ) -> Result<T, DetectorError> {
        match &outcome {
            Ok(_) => self.success_total.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.failure_total.fetch_add(1, Ordering::Relaxed),
        };
        outcome
    }

    pub(crate) fn health(&self) -> DetectorHealth {
        DetectorHealth {
            circuit_open: false,
            consecutive_failures: 0,
            in_flight: 0,
            request_total: self.request_total.load(Ordering::Relaxed),
            success_total: self.success_total.load(Ordering::Relaxed),
            failure_total: self.failure_total.load(Ordering::Relaxed),
        }
    }
}

/// The failure modes both native adapters may surface. No `CircuitOpen` (no
/// adapter-local circuit breaker) and no patch-application kinds (patch
/// application is owned by the gateway).
pub(crate) fn native_adapter_failure_modes() -> Vec<DetectorErrorKind> {
    vec![
        DetectorErrorKind::Timeout,
        DetectorErrorKind::Unavailable,
        DetectorErrorKind::InvalidResponse,
        DetectorErrorKind::Overloaded,
        DetectorErrorKind::Unauthorized,
        DetectorErrorKind::PayloadTooLarge,
        DetectorErrorKind::InvalidConfiguration,
        DetectorErrorKind::Internal,
    ]
}
