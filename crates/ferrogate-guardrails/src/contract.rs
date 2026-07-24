// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Typed detector contract: stages, inputs, descriptors, verdicts,
//! findings, patches, errors, health, the `GuardrailDetector` trait, and
//! the redacting `DetectorSecret` wrapper.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    fmt,
    time::{Duration, Instant},
};

use crate::{ContentSegment, ContentSource, GuardrailProtocol};

pub(crate) const CONTRACT_VERSION: u32 = 1;
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

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    #[default]
    High,
    Critical,
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

    pub(crate) fn affects_circuit(&self) -> bool {
        matches!(
            self.kind,
            DetectorErrorKind::Timeout
                | DetectorErrorKind::Unavailable
                | DetectorErrorKind::InvalidResponse
                | DetectorErrorKind::Overloaded
        )
    }

    pub(crate) fn retriable(&self) -> bool {
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

    pub(crate) fn expose(&self) -> &str {
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
