// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Microsoft Presidio analyzer adapter (self-hosted DLP/PII path, #201).

//! [`PresidioDetector`] speaks the Microsoft Presidio analyzer HTTP contract
//! (`POST /analyze`) against a CUSTOMER-VPC self-hosted deployment. Presidio
//! returns recognized-entity spans, so this adapter is transform-capable: every
//! span on a mutable text segment yields a redaction patch.
//!
//! The entire wire format lives in [`wire`]; a Presidio contract drift is a
//! one-file fix there.

use super::{
    adapter_status_error, char_index_to_byte_offset, config_digest, hmac_evidence_fingerprint,
    AdapterCounters, DetectorTransport, HttpJsonTransport,
};
use crate::{
    is_mutable_text_segment, native_adapter_failure_modes, validate_custom_http_endpoint,
    ContentPatch, ContentSegment, ContentSource, DataResidency, DetectorCredentialType,
    DetectorDescriptor, DetectorError, DetectorErrorKind, DetectorHealth, DetectorInput,
    DetectorResult, DetectorSecret, DetectorVerdict, Finding, FindingSeverity, GuardrailDetector,
    MAX_DETECTOR_TIMEOUT,
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

/// The Presidio analyzer JSON contract, isolated so a vendor contract drift is
/// a one-file (one-module) fix. Request: `POST /analyze` with `text`,
/// `language`, `score_threshold`, and an optional `entities` allow-list.
/// Response: a JSON array of recognizer results carrying `entity_type`,
/// CHARACTER-indexed `start`/`end` (Presidio is Python; offsets are Unicode
/// code points, not bytes), and `score`. Unknown response fields (e.g.
/// `analysis_explanation`, `recognition_metadata`) are tolerated and ignored.
pub mod wire {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize)]
    pub struct AnalyzeRequest<'a> {
        pub text: &'a str,
        pub language: &'a str,
        pub score_threshold: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entities: Option<&'a [String]>,
    }

    #[derive(Debug, Deserialize)]
    pub struct RecognizerResult {
        pub entity_type: String,
        /// Character (code-point) index, inclusive start.
        pub start: usize,
        /// Character (code-point) index, exclusive end.
        pub end: usize,
        pub score: f64,
    }
}

const PRESIDIO_ADAPTER_VERSION: &str = "presidio-analyzer-adapter/1";
const REDACTION: &str = "[REDACTED]";

#[derive(Clone)]
pub struct PresidioDetectorConfig {
    pub id: String,
    /// Full URL of the analyzer's `/analyze` route on the self-hosted service.
    pub endpoint: String,
    /// Language hint sent with every request (Presidio requires it).
    pub language: String,
    /// Minimum recognizer score to act on, in percent (0-100). Sent to
    /// Presidio as `score_threshold` and re-checked locally.
    pub score_threshold_percent: u8,
    /// Optional entity allow-list (e.g. `["EMAIL_ADDRESS", "PHONE_NUMBER"]`).
    /// `None` asks Presidio for every recognizer it has loaded.
    pub entities: Option<Vec<String>>,
    pub timeout: Duration,
    pub max_payload_bytes: usize,
    pub max_response_bytes: usize,
    pub allow_private_network: bool,
    pub supported_sources: Vec<ContentSource>,
    /// Optional bearer token for a reverse proxy in front of the service.
    /// Presidio itself has no authentication.
    pub bearer_token: Option<DetectorSecret>,
    /// Required: evidence fingerprints are keyed HMACs of the matched span.
    pub fingerprint_key: DetectorSecret,
}

impl fmt::Debug for PresidioDetectorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresidioDetectorConfig")
            .field("id", &self.id)
            .field("endpoint", &"<configured>")
            .field("language", &self.language)
            .field("score_threshold_percent", &self.score_threshold_percent)
            .field("entities", &self.entities)
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

/// DLP/PII detector backed by a self-hosted Microsoft Presidio analyzer.
pub struct PresidioDetector {
    config: PresidioDetectorConfig,
    transport: Arc<dyn DetectorTransport>,
    version: String,
    counters: AdapterCounters,
}

impl fmt::Debug for PresidioDetector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresidioDetector")
            .field("config", &self.config)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn validate_config(config: &PresidioDetectorConfig) -> Result<Url, DetectorError> {
    let endpoint = Url::parse(&config.endpoint).map_err(|_| {
        DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "presidio detector endpoint is not a valid URL",
        )
    })?;
    validate_custom_http_endpoint(&endpoint, config.allow_private_network)?;
    if config.id.trim().is_empty()
        || config.language.trim().is_empty()
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
        || config.entities.as_ref().is_some_and(|entities| {
            entities.is_empty()
                || entities.iter().any(|entity| entity.trim().is_empty())
                || entities.iter().collect::<HashSet<_>>().len() != entities.len()
        })
    {
        return Err(DetectorError::new(
            DetectorErrorKind::InvalidConfiguration,
            "presidio detector id, language, threshold, limits, sources, or entities are invalid",
        ));
    }
    Ok(endpoint)
}

impl PresidioDetector {
    /// Production constructor: builds the bounded HTTP transport.
    pub fn new(config: PresidioDetectorConfig) -> Result<Self, DetectorError> {
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
        config: PresidioDetectorConfig,
        transport: Arc<dyn DetectorTransport>,
    ) -> Result<Self, DetectorError> {
        validate_config(&config)?;
        let digest = config_digest(&[
            &config.language,
            &config.score_threshold_percent.to_string(),
            &config
                .entities
                .as_deref()
                .map(|entities| entities.join(","))
                .unwrap_or_default(),
        ]);
        Ok(Self {
            version: format!("{PRESIDIO_ADAPTER_VERSION}+cfg.{digest}"),
            config,
            transport,
            counters: AdapterCounters::default(),
        })
    }

    fn score_threshold(&self) -> f64 {
        f64::from(self.config.score_threshold_percent) / 100.0
    }

    async fn analyze_segment(
        &self,
        segment: &ContentSegment,
        deadline: Instant,
        findings: &mut Vec<Finding>,
        patches: &mut Vec<ContentPatch>,
    ) -> Result<(), DetectorError> {
        let request = wire::AnalyzeRequest {
            text: &segment.text,
            language: &self.config.language,
            score_threshold: self.score_threshold(),
            entities: self.config.entities.as_deref(),
        };
        let body = serde_json::to_vec(&request).map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::Internal,
                "failed to encode presidio analyze request",
            )
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "presidio detector deadline expired",
            ));
        }
        let attempt_timeout = remaining.min(self.config.timeout);
        let reply =
            match tokio::time::timeout(attempt_timeout, self.transport.post_json(&body)).await {
                Ok(reply) => reply?,
                Err(_) => {
                    return Err(DetectorError::new(
                        DetectorErrorKind::Timeout,
                        "presidio detector request timed out",
                    ))
                }
            };
        if reply.status != 200 {
            return Err(adapter_status_error(reply.status));
        }
        let results: Vec<wire::RecognizerResult> =
            serde_json::from_slice(&reply.body).map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::InvalidResponse,
                    "presidio detector returned a malformed analyze response",
                )
            })?;

        let threshold = self.score_threshold();
        let mut spans: Vec<(usize, usize, wire::RecognizerResult)> = Vec::new();
        for result in results {
            if result.score < threshold {
                continue;
            }
            let (Some(byte_start), Some(byte_end)) = (
                char_index_to_byte_offset(&segment.text, result.start),
                char_index_to_byte_offset(&segment.text, result.end),
            ) else {
                return Err(DetectorError::new(
                    DetectorErrorKind::InvalidResponse,
                    "presidio detector returned an out-of-range entity span",
                ));
            };
            if byte_start >= byte_end {
                return Err(DetectorError::new(
                    DetectorErrorKind::InvalidResponse,
                    "presidio detector returned an empty or inverted entity span",
                ));
            }
            spans.push((byte_start, byte_end, result));
        }
        // Deterministic order + non-overlapping patches (overlapping patch sets
        // are rejected downstream and would collapse surgical redaction).
        spans.sort_by_key(|(start, end, _)| (*start, *end));
        let mut last_patched_end: Option<usize> = None;
        for (byte_start, byte_end, result) in spans {
            let matched = &segment.text[byte_start..byte_end];
            findings.push(Finding {
                category: format!("pii.presidio.{}", result.entity_type.to_ascii_lowercase()),
                severity: FindingSeverity::High,
                confidence: Some(result.score as f32),
                byte_start: Some(byte_start),
                byte_end: Some(byte_end),
                segment_id: Some(segment.segment_id.clone()),
                fingerprint: Some(hmac_evidence_fingerprint(
                    &self.config.fingerprint_key,
                    matched,
                )?),
                matched_text: None,
                attributes: Map::new(),
            });
            let overlaps = last_patched_end.is_some_and(|end| byte_start < end);
            if is_mutable_text_segment(segment) && !overlaps {
                last_patched_end = Some(byte_end);
                patches.push(ContentPatch {
                    segment_id: segment.segment_id.clone(),
                    expected_fingerprint: segment.fingerprint.clone(),
                    protocol_location: segment.protocol_location.clone(),
                    byte_start,
                    byte_end,
                    replacement: REDACTION.to_string(),
                });
            }
        }
        Ok(())
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
            .collect::<Vec<_>>();
        let total_bytes: usize = selected.iter().map(|segment| segment.text.len()).sum();
        if total_bytes > self.config.max_payload_bytes {
            return Err(DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "presidio detector request exceeds configured limit",
            ));
        }
        let mut findings = Vec::new();
        let mut patches = Vec::new();
        for segment in &selected {
            if segment.text.is_empty() {
                continue;
            }
            self.analyze_segment(segment, deadline, &mut findings, &mut patches)
                .await?;
        }
        Ok(DetectorResult {
            verdict: if findings.is_empty() {
                DetectorVerdict::Pass
            } else {
                DetectorVerdict::Fail
            },
            findings,
            patches,
            detector_version: self.version.clone(),
        })
    }
}

#[async_trait]
impl GuardrailDetector for PresidioDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: self.config.id.clone(),
            version: self.version.clone(),
            supports_request: true,
            supports_response: true,
            // Presidio returns entity spans, so span redaction is supported.
            supports_transform: true,
            supported_sources: self.config.supported_sources.clone(),
            credential: if self.config.bearer_token.is_some() {
                DetectorCredentialType::BearerToken
            } else {
                DetectorCredentialType::None
            },
            // Self-hosted analyzer inside the customer's network boundary.
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
                "presidio detector deadline expired before execution",
            )));
        }
        let outcome = self.evaluate_inner(input, deadline).await;
        self.counters.record_outcome(outcome)
    }
}
