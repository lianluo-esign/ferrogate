// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: ProtectAI LLM-Guard prompt-injection adapter (self-hosted, detect-only, #201).

//! [`LlmGuardPromptInjectionDetector`] speaks the ProtectAI LLM-Guard API
//! prompt-scanner contract (`POST /analyze/prompt`) against a CUSTOMER-VPC
//! self-hosted deployment. The prompt-injection scanner classifies whole
//! prompts and returns no spans, so this adapter is DETECT-ONLY
//! (`supports_transform: false`): a hit can deny or shadow-record, never
//! surgically redact.
//!
//! The entire wire format lives in [`wire`]; an LLM-Guard contract drift is a
//! one-file fix there.

use super::{
    adapter_status_error, config_digest, hmac_evidence_fingerprint, AdapterCounters,
    DetectorTransport, HttpJsonTransport,
};
use crate::{
    native_adapter_failure_modes, validate_custom_http_endpoint, ContentSource, DataResidency,
    DetectorCredentialType, DetectorDescriptor, DetectorError, DetectorErrorKind, DetectorHealth,
    DetectorInput, DetectorResult, DetectorSecret, DetectorVerdict, Finding, FindingSeverity,
    GuardrailDetector, MAX_DETECTOR_TIMEOUT,
};
use async_trait::async_trait;
use reqwest::Url;
use serde_json::Map;
use std::collections::HashSet;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

/// The LLM-Guard API prompt-scanner JSON contract, isolated so a vendor
/// contract drift is a one-file (one-module) fix. Request: `POST
/// /analyze/prompt` with `prompt`. Response: `is_valid` (overall verdict
/// across the scanners configured server-side), a `scanners` map of scanner
/// name to risk score in `[0, 1]` (higher is riskier), and the
/// `sanitized_prompt`, which this adapter deliberately IGNORES: rewriting the
/// prompt to a vendor-normalized string is not span-safe, so the adapter stays
/// detect-only.
pub mod wire {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    /// The scanner name LLM-Guard uses for its prompt-injection classifier.
    pub const PROMPT_INJECTION_SCANNER: &str = "PromptInjection";

    #[derive(Debug, Serialize)]
    pub struct AnalyzePromptRequest<'a> {
        pub prompt: &'a str,
    }

    #[derive(Debug, Deserialize)]
    pub struct AnalyzePromptResponse {
        pub is_valid: bool,
        #[serde(default)]
        pub scanners: BTreeMap<String, f64>,
        #[serde(default)]
        pub sanitized_prompt: Option<String>,
    }
}

const LLM_GUARD_ADAPTER_VERSION: &str = "llm-guard-prompt-injection-adapter/1";

#[derive(Clone)]
pub struct LlmGuardPromptInjectionConfig {
    pub id: String,
    /// Full URL of the LLM-Guard API's `/analyze/prompt` route.
    pub endpoint: String,
    /// Risk score at or above which a hit is recorded even when the service
    /// reports `is_valid: true`, in percent (0-100). A server-side
    /// `is_valid: false` always fails regardless of this threshold.
    pub score_threshold_percent: u8,
    pub timeout: Duration,
    pub max_payload_bytes: usize,
    pub max_response_bytes: usize,
    pub allow_private_network: bool,
    pub supported_sources: Vec<ContentSource>,
    /// Optional bearer token (`LLM_GUARD_API` supports token auth; also covers
    /// a reverse proxy).
    pub bearer_token: Option<DetectorSecret>,
    /// Required: the evidence fingerprint is a keyed HMAC of the analyzed
    /// text (the scanner returns no spans, so the flagged identity is the
    /// whole projected prompt).
    pub fingerprint_key: DetectorSecret,
}

impl fmt::Debug for LlmGuardPromptInjectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmGuardPromptInjectionConfig")
            .field("id", &self.id)
            .field("endpoint", &"<configured>")
            .field("score_threshold_percent", &self.score_threshold_percent)
            .field("timeout", &self.timeout)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allow_private_network", &self.allow_private_network)
            .field("supported_sources", &self.supported_sources)
            .field("bearer_token", &self.bearer_token)
            .field("fingerprint_key", &self.fingerprint_key)
            .finish()
    }
}

/// Prompt-injection detector backed by a self-hosted ProtectAI LLM-Guard API.
pub struct LlmGuardPromptInjectionDetector {
    config: LlmGuardPromptInjectionConfig,
    transport: Arc<dyn DetectorTransport>,
    version: String,
    counters: AdapterCounters,
}

impl fmt::Debug for LlmGuardPromptInjectionDetector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmGuardPromptInjectionDetector")
            .field("config", &self.config)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn validate_config(config: &LlmGuardPromptInjectionConfig) -> Result<Url, DetectorError> {
    let endpoint = Url::parse(&config.endpoint).map_err(|_| {
        DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "llm-guard detector endpoint is not a valid URL",
        )
    })?;
    validate_custom_http_endpoint(&endpoint, config.allow_private_network)?;
    if config.id.trim().is_empty()
        || config.score_threshold_percent > 100
        || config.timeout.is_zero()
        || config.timeout > MAX_DETECTOR_TIMEOUT
        || config.max_payload_bytes == 0
        || config.max_response_bytes == 0
        || config.supported_sources.is_empty()
        || config
            .supported_sources
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != config.supported_sources.len()
    {
        return Err(DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "llm-guard detector id, threshold, limits, or sources are invalid",
        ));
    }
    Ok(endpoint)
}

impl LlmGuardPromptInjectionDetector {
    /// Production constructor: builds the bounded HTTP transport.
    pub fn new(config: LlmGuardPromptInjectionConfig) -> Result<Self, DetectorError> {
        let endpoint = validate_config(&config)?;
        let transport = HttpJsonTransport::new(
            endpoint,
            config.timeout,
            config.allow_private_network,
            config.bearer_token.clone(),
            config.max_response_bytes,
        )?;
        Self::with_transport(config, Arc::new(transport))
    }

    /// Construct over an explicit transport (fixture replay in tests, or a
    /// caller-supplied client).
    pub fn with_transport(
        config: LlmGuardPromptInjectionConfig,
        transport: Arc<dyn DetectorTransport>,
    ) -> Result<Self, DetectorError> {
        validate_config(&config)?;
        let digest = config_digest(&[&config.score_threshold_percent.to_string()]);
        Ok(Self {
            version: format!("{LLM_GUARD_ADAPTER_VERSION}+cfg.{digest}"),
            config,
            transport,
            counters: AdapterCounters::default(),
        })
    }

    async fn evaluate_inner(
        &self,
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        let selected = input
            .segments
            .iter()
            .filter(|segment| self.config.supported_sources.contains(&segment.source))
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>();
        let projected = selected.join("\n");
        if projected.len() > self.config.max_payload_bytes {
            return Err(DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "llm-guard detector request exceeds configured limit",
            ));
        }
        if projected.is_empty() {
            return Ok(self.pass_result());
        }
        let request = wire::AnalyzePromptRequest { prompt: &projected };
        let body = serde_json::to_vec(&request).map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::Internal,
                "failed to encode llm-guard analyze request",
            )
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "llm-guard detector deadline expired",
            ));
        }
        let attempt_timeout = remaining.min(self.config.timeout);
        let reply =
            match tokio::time::timeout(attempt_timeout, self.transport.post_json(&body)).await {
                Ok(reply) => reply?,
                Err(_) => {
                    return Err(DetectorError::new(
                        DetectorErrorKind::Timeout,
                        "llm-guard detector request timed out",
                    ))
                }
            };
        if reply.status != 200 {
            return Err(adapter_status_error(reply.status));
        }
        let response: wire::AnalyzePromptResponse =
            serde_json::from_slice(&reply.body).map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::InvalidResponse,
                    "llm-guard detector returned a malformed analyze response",
                )
            })?;

        let score = response
            .scanners
            .get(wire::PROMPT_INJECTION_SCANNER)
            .copied();
        let threshold = f64::from(self.config.score_threshold_percent) / 100.0;
        let hit = !response.is_valid || score.is_some_and(|score| score >= threshold);
        if !hit {
            return Ok(self.pass_result());
        }
        Ok(DetectorResult {
            verdict: DetectorVerdict::Fail,
            findings: vec![Finding {
                category: "prompt_injection.llm_guard".to_string(),
                severity: FindingSeverity::High,
                confidence: score.map(|score| score as f32),
                // The scanner classifies the whole prompt; there is no span.
                byte_start: None,
                byte_end: None,
                segment_id: None,
                fingerprint: Some(hmac_evidence_fingerprint(
                    &self.config.fingerprint_key,
                    &projected,
                )?),
                matched_text: None,
                attributes: Map::new(),
            }],
            // Detect-only: no patches, ever.
            patches: Vec::new(),
            detector_version: self.version.clone(),
        })
    }

    fn pass_result(&self) -> DetectorResult {
        DetectorResult {
            verdict: DetectorVerdict::Pass,
            findings: Vec::new(),
            patches: Vec::new(),
            detector_version: self.version.clone(),
        }
    }
}

#[async_trait]
impl GuardrailDetector for LlmGuardPromptInjectionDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: self.config.id.clone(),
            version: self.version.clone(),
            supports_request: true,
            supports_response: true,
            // The scanner returns no spans; a hit cannot be surgically
            // redacted. Honest contract: detect-only.
            supports_transform: false,
            supported_sources: self.config.supported_sources.clone(),
            credential: if self.config.bearer_token.is_some() {
                DetectorCredentialType::BearerToken
            } else {
                DetectorCredentialType::None
            },
            // Self-hosted LLM-Guard API inside the customer's network boundary.
            data_residency: DataResidency::CustomerVpc,
            max_payload_bytes: self.config.max_payload_bytes,
            declared_failure_modes: native_adapter_failure_modes(),
        }
    }

    fn health(&self) -> DetectorHealth {
        self.counters.health()
    }

    async fn evaluate(
        &self,
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        self.counters.record_request();
        if Instant::now() >= deadline {
            return self.counters.record_outcome(Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "llm-guard detector deadline expired before execution",
            )));
        }
        let outcome = self.evaluate_inner(input, deadline).await;
        self.counters.record_outcome(outcome)
    }
}
