// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Typed, bounded Guardrail detector contracts for FerroGate.

//! Narrow Guardrail detector contracts and the built-in `custom_http` runtime.
//!
//! Policy composition belongs to `ferrogate-policy`; gateway request wiring
//! belongs to `ferrogate-cli`. This crate owns only detector execution and its
//! safety boundary: async I/O, deadlines, bulkheads, circuit state, safe DNS,
//! typed results, and constrained text patches.

use async_trait::async_trait;
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
    Client, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

mod policy;
pub use policy::*;
mod envelope;
pub use envelope::*;
mod deterministic;
pub use deterministic::*;

const CONTRACT_VERSION: u32 = 1;
pub const MAX_DETECTOR_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectorStage {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DetectorTenant<'a> {
    pub organization_id: Option<&'a str>,
    pub team_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub api_key_id: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorInput<'a> {
    pub protocol: GuardrailProtocol,
    pub stage: DetectorStage,
    pub tenant: DetectorTenant<'a>,
    pub model: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub text: &'a str,
    pub segments: &'a [ContentSegment],
}

/// How a detector authenticates to its backend. Declared in the descriptor so
/// operators can audit which detectors carry credentials without inspecting
/// their (secret-bearing) configuration.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectorCredentialType {
    None,
    BearerToken,
}

/// Where a detector processes content. `InRepo` never leaves the gateway
/// process; `ProviderSaas` projects content to an external vendor; `CustomerVpc`
/// reaches a customer-operated endpoint.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataResidency {
    InRepo,
    ProviderSaas,
    CustomerVpc,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DetectorDescriptor {
    pub id: String,
    pub version: String,
    pub supports_request: bool,
    pub supports_response: bool,
    pub supports_transform: bool,
    pub supported_sources: Vec<ContentSource>,
    /// Credential class this detector presents to its backend.
    pub credential: DetectorCredentialType,
    /// Where this detector processes content.
    pub data_residency: DataResidency,
    /// Upper bound on the projected request payload this detector accepts.
    pub max_payload_bytes: usize,
    /// Failure modes this detector may surface. Every runtime error's kind is a
    /// member of this set (declared is a superset of what is emitted).
    pub declared_failure_modes: Vec<DetectorErrorKind>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectorVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for FindingSeverity {
    fn default() -> Self {
        Self::High
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Finding {
    pub category: String,
    #[serde(default)]
    pub severity: FindingSeverity,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub byte_start: Option<usize>,
    #[serde(default)]
    pub byte_end: Option<usize>,
    #[serde(default)]
    pub segment_id: Option<String>,
    /// Keyed, non-reversible identity of the matched value. The cleartext is
    /// never required for enforcement or durable evidence.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Kept only in the in-memory decision path for backward-compatible
    /// redaction. Callers must never persist this field as evidence.
    #[serde(default)]
    pub matched_text: Option<String>,
    #[serde(default)]
    pub attributes: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContentPatch {
    pub segment_id: String,
    pub expected_fingerprint: String,
    pub protocol_location: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub replacement: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DetectorResult {
    pub verdict: DetectorVerdict,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub patches: Vec<ContentPatch>,
    pub detector_version: String,
}

impl DetectorResult {
    pub fn first_matched_text(&self) -> Option<&str> {
        self.findings
            .iter()
            .find_map(|finding| finding.matched_text.as_deref())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectorErrorKind {
    Timeout,
    Unavailable,
    InvalidResponse,
    Overloaded,
    Unauthorized,
    PayloadTooLarge,
    CircuitOpen,
    InvalidConfiguration,
    InvalidPatch,
    StalePatch,
    ProtectedPath,
    Internal,
}

impl DetectorErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::Overloaded => "overloaded",
            Self::Unauthorized => "unauthorized",
            Self::PayloadTooLarge => "payload_too_large",
            Self::CircuitOpen => "circuit_open",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::InvalidPatch => "invalid_patch",
            Self::StalePatch => "stale_patch",
            Self::ProtectedPath => "protected_path",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorError {
    pub kind: DetectorErrorKind,
    message: String,
}

impl DetectorError {
    pub fn new(kind: DetectorErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn safe_message(&self) -> &str {
        &self.message
    }

    fn affects_circuit(&self) -> bool {
        matches!(
            self.kind,
            DetectorErrorKind::Timeout
                | DetectorErrorKind::Unavailable
                | DetectorErrorKind::InvalidResponse
                | DetectorErrorKind::Overloaded
        )
    }

    fn retriable(&self) -> bool {
        matches!(
            self.kind,
            DetectorErrorKind::Timeout
                | DetectorErrorKind::Unavailable
                | DetectorErrorKind::Overloaded
        )
    }
}

impl fmt::Display for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for DetectorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorHealth {
    pub circuit_open: bool,
    pub consecutive_failures: u32,
    pub in_flight: usize,
    pub request_total: u64,
    pub success_total: u64,
    pub failure_total: u64,
}

#[async_trait]
pub trait GuardrailDetector: fmt::Debug + Send + Sync {
    fn descriptor(&self) -> DetectorDescriptor;

    fn health(&self) -> DetectorHealth;

    async fn evaluate(
        &self,
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError>;
}

#[derive(Clone)]
pub struct DetectorSecret(String);

impl DetectorSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for DetectorSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone)]
pub struct CustomHttpDetectorConfig {
    pub id: String,
    pub endpoint: String,
    pub timeout: Duration,
    pub max_concurrency: usize,
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown: Duration,
    pub max_retries: u8,
    pub max_payload_bytes: usize,
    pub max_response_bytes: usize,
    pub allow_private_network: bool,
    pub supported_sources: Vec<ContentSource>,
    pub bearer_token: Option<DetectorSecret>,
}

impl fmt::Debug for CustomHttpDetectorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomHttpDetectorConfig")
            .field("id", &self.id)
            // URL paths are allowed for routing but may accidentally contain
            // credentials. The endpoint is operator-visible through config;
            // it does not belong in general-purpose Debug output.
            .field("endpoint", &"<configured>")
            .field("timeout", &self.timeout)
            .field("max_concurrency", &self.max_concurrency)
            .field("circuit_failure_threshold", &self.circuit_failure_threshold)
            .field("circuit_cooldown", &self.circuit_cooldown)
            .field("max_retries", &self.max_retries)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allow_private_network", &self.allow_private_network)
            .field("supported_sources", &self.supported_sources)
            .field("bearer_token", &self.bearer_token)
            .finish()
    }
}

pub struct CustomHttpDetector {
    config: CustomHttpDetectorConfig,
    endpoint: Url,
    client: Client,
    permits: Arc<Semaphore>,
    circuit: Mutex<CircuitState>,
    request_total: AtomicU64,
    success_total: AtomicU64,
    failure_total: AtomicU64,
}

impl fmt::Debug for CustomHttpDetector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomHttpDetector")
            .field("config", &self.config)
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

impl CustomHttpDetector {
    pub fn new(config: CustomHttpDetectorConfig) -> Result<Self, DetectorError> {
        validate_config(&config)?;
        let endpoint = Url::parse(&config.endpoint).map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::InvalidConfiguration,
                "guardrail detector endpoint is not a valid URL",
            )
        })?;
        validate_custom_http_endpoint(&endpoint, config.allow_private_network)?;

        ensure_rustls_crypto_provider();
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(config.timeout)
            .pool_max_idle_per_host(config.max_concurrency.min(8))
            .dns_resolver(GuardrailDnsResolver {
                allow_private_network: config.allow_private_network,
            })
            .build()
            .map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::InvalidConfiguration,
                    "failed to initialize guardrail detector HTTP client",
                )
            })?;

        Ok(Self {
            permits: Arc::new(Semaphore::new(config.max_concurrency)),
            config,
            endpoint,
            client,
            circuit: Mutex::new(CircuitState::default()),
            request_total: AtomicU64::new(0),
            success_total: AtomicU64::new(0),
            failure_total: AtomicU64::new(0),
        })
    }

    fn enter_circuit(&self, now: Instant) -> Result<(), DetectorError> {
        let mut state = self.circuit.lock().map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::Internal,
                "guardrail detector circuit state is unavailable",
            )
        })?;
        let Some(opened_at) = state.opened_at else {
            return Ok(());
        };
        if now.duration_since(opened_at) < self.config.circuit_cooldown || state.half_open_probe {
            return Err(DetectorError::new(
                DetectorErrorKind::CircuitOpen,
                "guardrail detector circuit is open",
            ));
        }
        state.half_open_probe = true;
        Ok(())
    }

    fn record_success(&self) {
        self.success_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut state) = self.circuit.lock() {
            state.consecutive_failures = 0;
            state.opened_at = None;
            state.half_open_probe = false;
        }
    }

    fn record_failure(&self, error: &DetectorError, now: Instant) {
        self.failure_total.fetch_add(1, Ordering::Relaxed);
        if !error.affects_circuit() {
            if let Ok(mut state) = self.circuit.lock() {
                state.half_open_probe = false;
            }
            return;
        }
        if let Ok(mut state) = self.circuit.lock() {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.half_open_probe = false;
            if state.consecutive_failures >= self.config.circuit_failure_threshold {
                state.opened_at = Some(now);
            }
        }
    }

    async fn send_once(&self, request_body: Vec<u8>) -> Result<DetectorResult, DetectorError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(request_body);
        if let Some(token) = &self.config.bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {}", token.expose()));
        }

        let response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.config.max_response_bytes as u64)
        {
            return Err(DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "guardrail detector response exceeds configured limit",
            ));
        }

        let mut response = response;
        let mut bytes = Vec::new();
        loop {
            let remaining = self.config.max_response_bytes.saturating_sub(bytes.len());
            if remaining == 0 {
                return Err(DetectorError::new(
                    DetectorErrorKind::PayloadTooLarge,
                    "guardrail detector response exceeds configured limit",
                ));
            }
            let chunk = response.chunk().await.map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::Unavailable,
                    "guardrail detector response could not be read",
                )
            })?;
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.len() > remaining {
                return Err(DetectorError::new(
                    DetectorErrorKind::PayloadTooLarge,
                    "guardrail detector response exceeds configured limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        parse_detector_response(&bytes)
    }
}

#[async_trait]
impl GuardrailDetector for CustomHttpDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: self.config.id.clone(),
            version: "custom-http/1".to_string(),
            supports_request: true,
            supports_response: true,
            supports_transform: true,
            supported_sources: self.config.supported_sources.clone(),
            credential: if self.config.bearer_token.is_some() {
                DetectorCredentialType::BearerToken
            } else {
                DetectorCredentialType::None
            },
            data_residency: DataResidency::ProviderSaas,
            max_payload_bytes: self.config.max_payload_bytes,
            // The external SaaS path can surface the full network/circuit/patch
            // error surface; only ProtectedPath is unreachable here (it is a
            // patch-application concern owned by the gateway, not the detector).
            declared_failure_modes: vec![
                DetectorErrorKind::Timeout,
                DetectorErrorKind::Unavailable,
                DetectorErrorKind::InvalidResponse,
                DetectorErrorKind::Overloaded,
                DetectorErrorKind::Unauthorized,
                DetectorErrorKind::PayloadTooLarge,
                DetectorErrorKind::CircuitOpen,
                DetectorErrorKind::InvalidConfiguration,
                DetectorErrorKind::InvalidPatch,
                DetectorErrorKind::StalePatch,
                DetectorErrorKind::Internal,
            ],
        }
    }

    fn health(&self) -> DetectorHealth {
        let (circuit_open, consecutive_failures) = self
            .circuit
            .lock()
            .map(|state| (state.opened_at.is_some(), state.consecutive_failures))
            .unwrap_or((true, 0));
        DetectorHealth {
            circuit_open,
            consecutive_failures,
            in_flight: self
                .config
                .max_concurrency
                .saturating_sub(self.permits.available_permits()),
            request_total: self.request_total.load(Ordering::Relaxed),
            success_total: self.success_total.load(Ordering::Relaxed),
            failure_total: self.failure_total.load(Ordering::Relaxed),
        }
    }

    async fn evaluate(
        &self,
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        self.request_total.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if now >= deadline {
            let error = DetectorError::new(
                DetectorErrorKind::Timeout,
                "guardrail detector deadline expired before execution",
            );
            self.record_failure(&error, now);
            return Err(error);
        }
        if let Err(error) = self.enter_circuit(now) {
            // A rejected request is still a detector failure, but must not
            // mutate the circuit state while a half-open probe is in flight.
            self.failure_total.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        let projected_segments = input
            .segments
            .iter()
            .filter(|segment| self.config.supported_sources.contains(&segment.source))
            .cloned()
            .collect::<Vec<_>>();
        let projected_text = if input.segments.is_empty()
            && self
                .config
                .supported_sources
                .contains(&ContentSource::Unknown)
        {
            input.text.to_string()
        } else {
            projected_segments
                .iter()
                .map(|segment| segment.text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };
        if projected_text.len() > self.config.max_payload_bytes {
            let error = DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "guardrail detector request exceeds configured limit",
            );
            self.record_failure(&error, Instant::now());
            return Err(error);
        }

        let request = DetectorRequest {
            contract_version: CONTRACT_VERSION,
            protocol: input.protocol,
            stage: input.stage,
            tenant: input.tenant.clone(),
            model: input.model,
            provider: input.provider,
            text: &projected_text,
            segments: &projected_segments,
        };
        let request_body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(_) => {
                let error = DetectorError::new(
                    DetectorErrorKind::Internal,
                    "failed to encode guardrail detector request",
                );
                self.record_failure(&error, Instant::now());
                return Err(error);
            }
        };
        if request_body.len() > self.config.max_payload_bytes {
            let error = DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "guardrail detector request exceeds configured limit",
            );
            self.record_failure(&error, Instant::now());
            return Err(error);
        }

        let permit_wait = deadline.saturating_duration_since(Instant::now());
        let permit = match tokio::time::timeout(
            permit_wait,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Err(_) => {
                let error = DetectorError::new(
                    DetectorErrorKind::Overloaded,
                    "guardrail detector concurrency wait exceeded deadline",
                );
                self.record_failure(&error, Instant::now());
                return Err(error);
            }
            Ok(Err(_)) => {
                let error = DetectorError::new(
                    DetectorErrorKind::Internal,
                    "guardrail detector concurrency gate is closed",
                );
                self.record_failure(&error, Instant::now());
                return Err(error);
            }
        };

        let mut attempt = 0_u8;
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(DetectorError::new(
                    DetectorErrorKind::Timeout,
                    "guardrail detector deadline expired",
                ));
            }
            let attempt_timeout = remaining.min(self.config.timeout);
            match tokio::time::timeout(attempt_timeout, self.send_once(request_body.clone())).await
            {
                Ok(Ok(result)) => {
                    if let Err(error) =
                        validate_detector_result(&projected_text, &projected_segments, &result)
                    {
                        break Err(error);
                    }
                    break Ok(result);
                }
                Ok(Err(error)) if error.retriable() && attempt < self.config.max_retries => {
                    attempt = attempt.saturating_add(1);
                }
                Ok(Err(error)) => break Err(error),
                Err(_) => {
                    break Err(DetectorError::new(
                        DetectorErrorKind::Timeout,
                        "guardrail detector request timed out",
                    ));
                }
            }
        };
        drop(permit);

        match &result {
            Ok(_) => self.record_success(),
            Err(error) => self.record_failure(error, Instant::now()),
        }
        result
    }
}

#[derive(Debug, Serialize)]
struct DetectorRequest<'a> {
    contract_version: u32,
    protocol: GuardrailProtocol,
    stage: DetectorStage,
    tenant: DetectorTenant<'a>,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    text: &'a str,
    segments: &'a [ContentSegment],
}

#[derive(Debug, Default)]
struct CircuitState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    half_open_probe: bool,
}

#[derive(Debug, Deserialize)]
struct DetectorWireResponse {
    #[serde(default)]
    verdict: Option<DetectorVerdict>,
    #[serde(default, rename = "match")]
    legacy_match: Option<bool>,
    #[serde(default)]
    matched_text: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    findings: Vec<Finding>,
    #[serde(default)]
    patches: Vec<ContentPatch>,
    #[serde(default)]
    detector_version: Option<String>,
}

fn parse_detector_response(bytes: &[u8]) -> Result<DetectorResult, DetectorError> {
    let mut wire: DetectorWireResponse = serde_json::from_slice(bytes).map_err(|_| {
        DetectorError::new(
            DetectorErrorKind::InvalidResponse,
            "guardrail detector returned invalid JSON",
        )
    })?;
    let verdict = match (wire.verdict, wire.legacy_match) {
        (Some(verdict), _) => verdict,
        (None, Some(true)) => DetectorVerdict::Fail,
        (None, Some(false)) => DetectorVerdict::Pass,
        (None, None) => {
            return Err(DetectorError::new(
                DetectorErrorKind::InvalidResponse,
                "guardrail detector response is missing verdict",
            ))
        }
    };
    if wire.legacy_match == Some(true) && wire.matched_text.is_none() {
        return Err(DetectorError::new(
            DetectorErrorKind::InvalidResponse,
            "legacy guardrail detector match is missing matched_text",
        ));
    }
    if let Some(matched_text) = wire.matched_text.take() {
        wire.findings.insert(
            0,
            Finding {
                category: wire.category.unwrap_or_else(|| "custom_http".to_string()),
                severity: FindingSeverity::High,
                confidence: None,
                byte_start: None,
                byte_end: None,
                segment_id: None,
                fingerprint: None,
                matched_text: Some(matched_text),
                attributes: Map::new(),
            },
        );
    }
    Ok(DetectorResult {
        verdict,
        findings: wire.findings,
        patches: wire.patches,
        detector_version: wire
            .detector_version
            .unwrap_or_else(|| "custom-http/1".to_string()),
    })
}

fn validate_detector_result(
    text: &str,
    segments: &[ContentSegment],
    result: &DetectorResult,
) -> Result<(), DetectorError> {
    validate_content_patches_for_segments(segments, &result.patches)?;
    for finding in &result.findings {
        let coordinate_text = match finding.segment_id.as_deref() {
            Some(segment_id) => segments
                .iter()
                .find(|segment| segment.segment_id == segment_id)
                .map(|segment| segment.text.as_str())
                .ok_or_else(|| {
                    DetectorError::new(
                        DetectorErrorKind::InvalidResponse,
                        "guardrail detector returned a finding for an unknown segment",
                    )
                })?,
            None => text,
        };
        match (finding.byte_start, finding.byte_end) {
            (None, None) => {}
            (Some(start), Some(end))
                if start <= end
                    && end <= coordinate_text.len()
                    && coordinate_text.is_char_boundary(start)
                    && coordinate_text.is_char_boundary(end) => {}
            _ => {
                return Err(DetectorError::new(
                    DetectorErrorKind::InvalidResponse,
                    "guardrail detector returned an invalid finding byte range",
                ));
            }
        }
    }
    Ok(())
}

fn validate_config(config: &CustomHttpDetectorConfig) -> Result<(), DetectorError> {
    if config.id.trim().is_empty()
        || config.max_concurrency == 0
        || config.max_concurrency > Semaphore::MAX_PERMITS
        || config.circuit_failure_threshold == 0
        || config.timeout.is_zero()
        || config.timeout > MAX_DETECTOR_TIMEOUT
        || config.circuit_cooldown.is_zero()
        || config.max_payload_bytes == 0
        || config.max_response_bytes == 0
        || config.max_retries > 1
        || config.supported_sources.is_empty()
        || config
            .supported_sources
            .iter()
            .enumerate()
            .any(|(index, source)| config.supported_sources[index + 1..].contains(source))
    {
        return Err(DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "guardrail detector limits or source declarations are invalid, timeout exceeds 30 seconds, or retries exceed one",
        ));
    }
    Ok(())
}

fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // The gateway binary may already have selected ring. Installing the
        // workspace-default aws-lc provider is therefore intentionally
        // best-effort and only matters for standalone crate consumers/tests.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn validate_custom_http_endpoint(
    endpoint: &Url,
    allow_private_network: bool,
) -> Result<(), DetectorError> {
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "guardrail detector endpoint must be an http(s) URL without credentials, query, or fragment",
        ));
    }
    if !allow_private_network {
        if let Some(host) = endpoint.host_str() {
            if host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().is_ok_and(is_disallowed_detector_ip)
            {
                return Err(DetectorError::new(
                    DetectorErrorKind::InvalidConfiguration,
                    "guardrail detector private-network endpoint requires explicit allow_private_network",
                ));
            }
        }
    }
    Ok(())
}

fn classify_reqwest_error(error: &reqwest::Error) -> DetectorError {
    if error.is_timeout() {
        DetectorError::new(
            DetectorErrorKind::Timeout,
            "guardrail detector request timed out",
        )
    } else if error.is_connect() {
        DetectorError::new(
            DetectorErrorKind::Unavailable,
            "guardrail detector is unavailable",
        )
    } else {
        DetectorError::new(
            DetectorErrorKind::Unavailable,
            "guardrail detector request failed",
        )
    }
}

fn status_error(status: StatusCode) -> DetectorError {
    let (kind, message) = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            DetectorErrorKind::Unauthorized,
            "guardrail detector rejected its configured credential",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            DetectorErrorKind::Overloaded,
            "guardrail detector is rate limited",
        ),
        status if status.is_server_error() => (
            DetectorErrorKind::Unavailable,
            "guardrail detector returned a server error",
        ),
        _ => (
            DetectorErrorKind::InvalidResponse,
            "guardrail detector returned an unexpected HTTP status",
        ),
    };
    DetectorError::new(kind, message)
}

#[derive(Debug, Clone, Copy)]
struct GuardrailDnsResolver {
    allow_private_network: bool,
}

impl Resolve for GuardrailDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow_private_network = self.allow_private_network;
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0)).await.map_err(
                |_| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(
                        "guardrail detector DNS resolution failed",
                    ))
                },
            )?;
            let filtered = filter_resolved_detector_addresses(addresses, allow_private_network);
            if filtered.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "guardrail detector DNS resolved only disallowed addresses",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(filtered.into_iter()) as Addrs)
        })
    }
}

fn filter_resolved_detector_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    allow_private_network: bool,
) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|address| allow_private_network || !is_disallowed_detector_ip(address.ip()))
        .collect()
}

pub fn is_disallowed_detector_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_disallowed_v4(ip),
        IpAddr::V6(ip) => is_disallowed_v6(ip),
    }
}

fn is_disallowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240
}

fn is_disallowed_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_disallowed_v4(mapped);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// Reusable detector conformance harness and its in-repo mock adapter. Gated so
/// the mock never enters a production build: available under `cfg(test)` and
/// behind the opt-in `conformance` feature for downstream adapter authors.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;

#[cfg(test)]
mod conformance_test;
#[cfg(test)]
mod deterministic_test;
#[cfg(test)]
mod lib_test;
