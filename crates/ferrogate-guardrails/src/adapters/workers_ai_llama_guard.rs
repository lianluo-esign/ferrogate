// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Optional Cloudflare Workers AI Llama Guard content-moderation detection provider (#422).

//! [`WorkersAiLlamaGuardDetector`] is an **optional, opt-in** FerroGate
//! detection provider (issue #422) that projects content to Cloudflare's
//! Workers AI Llama Guard model (`@cf/meta/llama-guard-*`) and turns its
//! `safe`/`unsafe` + hazard-category verdict into a [`DetectorResult`] the
//! FerroGate guardrail engine composes with native/custom rules.
//!
//! # Where it sits in the architecture
//!
//! FerroGate's own guardrail engine stays the source of truth. This detector
//! is ONE optional [`GuardrailDetector`] (the #164 pluggable detection-provider
//! seam) among others: it returns a detection *verdict*, and FerroGate — not
//! Llama Guard — decides flag vs. block by composing that verdict with the
//! policy's native rules (see `aggregate_check_outcomes` and the policy
//! `on_pass`/`on_fail`/`on_error` actions). The detector never decides
//! enforcement on its own.
//!
//! # Caveat: content-moderation, not prompt-injection
//!
//! Llama Guard classifies content against a fixed hazard taxonomy (hate,
//! violence, sexual content, self-harm, crimes, weapons, ...). It is a
//! **content-moderation** model, NOT a prompt-injection detector. Operators who
//! need prompt-injection coverage should keep FerroGate's native rules and/or
//! the self-hosted LLM-Guard prompt-injection adapter; this detector is
//! complementary, not a replacement.
//!
//! # Opt-in and graceful disable
//!
//! The detector is constructed only from an explicit [`WorkersAiLlamaGuardConfig`]
//! plus a live shared [`CloudflareClient`] (issue #405). Because the client is
//! built from the operator's `[cloudflare]` account/token configuration, the
//! detector simply cannot exist unless the operator has opted in by configuring
//! Cloudflare — that is the "graceful disable when not configured" boundary.
//!
//! # Failure handling (fail-open vs. fail-closed)
//!
//! On a Cloudflare/Workers-AI error the detector returns a typed
//! [`DetectorError`] (it does NOT silently pass), exactly like the other remote
//! detectors (`custom_http`, `presidio`, `llm_guard_prompt_injection`). The
//! fail-open vs. fail-closed choice is therefore owned by the *policy* — its
//! `on_error` actions decide whether a provider outage allows or blocks the
//! request — keeping this detector consistent with every other remote provider
//! and keeping enforcement policy in FerroGate.
//!
//! The entire Workers AI wire format lives in [`wire`], so a vendor contract
//! drift is a one-module fix.

use super::{config_digest, hmac_evidence_fingerprint};
use crate::{
    native_adapter_failure_modes, ContentSource, DataResidency, DetectorCredentialType,
    DetectorDescriptor, DetectorError, DetectorErrorKind, DetectorHealth, DetectorInput,
    DetectorResult, DetectorSecret, DetectorVerdict, Finding, FindingSeverity, GuardrailDetector,
    MAX_DETECTOR_TIMEOUT,
};
use async_trait::async_trait;
use ferrogate_cloudflare::{CloudflareClient, CloudflareError, HttpMethod};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

/// The Workers AI `/ai/run` JSON contract for Llama Guard, isolated so a vendor
/// contract drift is a one-module fix.
///
/// Request: a chat-style `messages` array (Llama Guard classifies the
/// conversation). Response: the shared Cloudflare client already unwraps the
/// `{ success, errors, result }` envelope, so the adapter deserializes only the
/// `result` object — [`RunResult`] — whose `response` field is the model's
/// classification. Llama Guard is an LLM, so `response` is `"one of"` a plain
/// `"safe"`/`"unsafe\nS2,S9"` string or a structured per-category object; the
/// adapter's [`interpret_response`] handles both shapes.
pub mod wire {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize)]
    pub struct RunRequest<'a> {
        pub messages: Vec<RunMessage<'a>>,
    }

    #[derive(Debug, Serialize)]
    pub struct RunMessage<'a> {
        pub role: &'a str,
        pub content: &'a str,
    }

    /// The `result` object of a Workers AI `/ai/run` response (the outer
    /// Cloudflare envelope is already stripped by the shared client).
    #[derive(Debug, Deserialize)]
    pub struct RunResult {
        /// The model's classification output. `"one of"` per the Workers AI
        /// schema: a string (`"safe"` / `"unsafe\nS2"`) or a structured object.
        #[serde(default)]
        pub response: Option<serde_json::Value>,
    }
}

const WORKERS_AI_LLAMA_GUARD_VERSION: &str = "workers-ai-llama-guard-adapter/1";

/// A sensible default Workers AI Llama Guard model slug for operators who have
/// no specific version preference. Any `@cf/meta/llama-guard-*` model is
/// accepted by [`WorkersAiLlamaGuardConfig`].
pub const DEFAULT_MODEL: &str = "@cf/meta/llama-guard-3-8b";

/// Opt-in configuration for the Workers AI Llama Guard detection provider.
///
/// This is the operator-facing knob set. The Cloudflare account/token is NOT
/// here — it is carried by the shared [`CloudflareClient`] built from the
/// `[cloudflare]` block (issue #405), which is what gates the whole detector on
/// Cloudflare being configured.
#[derive(Clone)]
pub struct WorkersAiLlamaGuardConfig {
    /// Stable detector id (surfaced in descriptors/evidence).
    pub id: String,
    /// The Workers AI model slug, e.g. `@cf/meta/llama-guard-3-8b`. Must be a
    /// `@cf/meta/llama-guard-*` model.
    pub model: String,
    /// Optional hazard-category allow-list of MLCommons S-codes (`"S1"`..`"S14"`).
    /// When `Some`, only these categories cause a `Fail`; other unsafe verdicts
    /// pass. When `None`, any `unsafe` verdict fails.
    pub categories: Option<Vec<String>>,
    /// Per-evaluate deadline ceiling for the Workers AI call.
    pub timeout: Duration,
    /// Upper bound on the projected request payload.
    pub max_payload_bytes: usize,
    /// Content sources this detector inspects.
    pub supported_sources: Vec<ContentSource>,
    /// Keyed HMAC key for evidence fingerprints. Llama Guard returns no spans,
    /// so the flagged identity is the whole projected content.
    pub fingerprint_key: DetectorSecret,
}

impl fmt::Debug for WorkersAiLlamaGuardConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkersAiLlamaGuardConfig")
            .field("id", &self.id)
            .field("model", &self.model)
            .field("categories", &self.categories)
            .field("timeout", &self.timeout)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("supported_sources", &self.supported_sources)
            .field("fingerprint_key", &self.fingerprint_key)
            .finish()
    }
}

/// Content-moderation detector backed by Cloudflare Workers AI Llama Guard.
pub struct WorkersAiLlamaGuardDetector {
    config: WorkersAiLlamaGuardConfig,
    client: Arc<CloudflareClient>,
    /// The `/ai/run/{model}` path, relative to the client's `client/v4` base
    /// and carrying the `{account_id}` placeholder the client templates.
    path: String,
    version: String,
    counters: super::AdapterCounters,
}

impl fmt::Debug for WorkersAiLlamaGuardDetector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkersAiLlamaGuardDetector")
            .field("config", &self.config)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn validate_config(config: &WorkersAiLlamaGuardConfig) -> Result<(), DetectorError> {
    let model = config.model.trim();
    if config.id.trim().is_empty()
        || model.is_empty()
        || !model.starts_with("@cf/meta/llama-guard")
        || config.timeout.is_zero()
        || config.timeout > MAX_DETECTOR_TIMEOUT
        || config.max_payload_bytes == 0
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
            "workers-ai llama-guard detector id, model, timeout, limits, or sources are invalid",
        ));
    }
    if let Some(categories) = &config.categories {
        if categories.is_empty()
            || categories
                .iter()
                .any(|code| normalize_hazard_code(code).is_none())
            || categories
                .iter()
                .map(|code| normalize_hazard_code(code))
                .collect::<HashSet<_>>()
                .len()
                != categories.len()
        {
            return Err(DetectorError::new(
                DetectorErrorKind::InvalidConfiguration,
                "workers-ai llama-guard categories must be unique valid S-codes (S1..S14) when set",
            ));
        }
    }
    Ok(())
}

impl WorkersAiLlamaGuardDetector {
    /// Build the detector over a shared Cloudflare client (issue #405). The
    /// client carries the account id + Workers-AI-scoped token; the client's
    /// injectable [`ferrogate_cloudflare::HttpTransport`] is what tests mock,
    /// so no network is required to exercise this detector.
    pub fn new(
        config: WorkersAiLlamaGuardConfig,
        client: Arc<CloudflareClient>,
    ) -> Result<Self, DetectorError> {
        validate_config(&config)?;
        let digest = config_digest(&[
            &config.model,
            &config
                .categories
                .as_ref()
                .map(|codes| codes.join(","))
                .unwrap_or_default(),
        ]);
        let path = format!("accounts/{{account_id}}/ai/run/{}", config.model.trim());
        Ok(Self {
            version: format!("{WORKERS_AI_LLAMA_GUARD_VERSION}+cfg.{digest}"),
            path,
            config,
            client,
            counters: super::AdapterCounters::default(),
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

    async fn evaluate_inner(
        &self,
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        let projected = input
            .segments
            .iter()
            .filter(|segment| self.config.supported_sources.contains(&segment.source))
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if projected.len() > self.config.max_payload_bytes {
            return Err(DetectorError::new(
                DetectorErrorKind::PayloadTooLarge,
                "workers-ai llama-guard detector request exceeds configured limit",
            ));
        }
        if projected.is_empty() {
            return Ok(self.pass_result());
        }

        let request = wire::RunRequest {
            messages: vec![wire::RunMessage {
                role: "user",
                content: &projected,
            }],
        };
        let body = serde_json::to_vec(&request).map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::Internal,
                "failed to encode workers-ai llama-guard run request",
            )
        })?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "workers-ai llama-guard detector deadline expired",
            ));
        }
        let attempt_timeout = remaining.min(self.config.timeout);
        // A tenant-scoped Cloudflare token override (issue #405) is selected by
        // organization id when the operator configured per-tenant tokens.
        let tenant = input.tenant.organization_id;
        let call = self.client.request_json::<wire::RunResult>(
            HttpMethod::Post,
            &self.path,
            Some(body),
            tenant,
        );
        let result: wire::RunResult = match tokio::time::timeout(attempt_timeout, call).await {
            Ok(result) => result.map_err(|error| classify_cloudflare_error(&error))?,
            Err(_) => {
                return Err(DetectorError::new(
                    DetectorErrorKind::Timeout,
                    "workers-ai llama-guard detector request timed out",
                ))
            }
        };

        let response = result.response.ok_or_else(|| {
            DetectorError::new(
                DetectorErrorKind::InvalidResponse,
                "workers-ai llama-guard response is missing the model output",
            )
        })?;
        let verdict = interpret_response(&response).ok_or_else(|| {
            DetectorError::new(
                DetectorErrorKind::InvalidResponse,
                "workers-ai llama-guard response could not be interpreted",
            )
        })?;

        if !verdict.is_unsafe {
            return Ok(self.pass_result());
        }

        // FerroGate — not Llama Guard — decides block vs. flag. Apply the
        // operator's optional category allow-list here so only the configured
        // hazard classes surface as a Fail; the composed policy does the rest.
        let flagged: Vec<String> = match &self.config.categories {
            Some(allow) => {
                let allow: HashSet<Option<&'static str>> = allow
                    .iter()
                    .map(|code| normalize_hazard_code(code))
                    .collect();
                let retained: Vec<String> = verdict
                    .categories
                    .iter()
                    .filter(|code| allow.contains(&normalize_hazard_code(code)))
                    .cloned()
                    .collect();
                if retained.is_empty() && !verdict.categories.is_empty() {
                    // Unsafe, but only in categories the operator opted out of.
                    return Ok(self.pass_result());
                }
                retained
            }
            None => verdict.categories.clone(),
        };

        let fingerprint = hmac_evidence_fingerprint(&self.config.fingerprint_key, &projected)?;
        let findings = if flagged.is_empty() {
            // Unsafe with no parseable category (or allow-list matched the
            // "unknown" fallback): emit one generic content-moderation finding.
            vec![self.finding(None, &fingerprint)]
        } else {
            flagged
                .iter()
                .map(|code| self.finding(Some(code), &fingerprint))
                .collect()
        };

        Ok(DetectorResult {
            verdict: DetectorVerdict::Fail,
            findings,
            // Content-moderation classifier: no spans, so detect-only, no patch.
            patches: Vec::new(),
            detector_version: self.version.clone(),
        })
    }

    fn finding(&self, hazard_code: Option<&str>, fingerprint: &str) -> Finding {
        let mut attributes = Map::new();
        attributes.insert(
            "provider".to_string(),
            Value::String("workers_ai_llama_guard".to_string()),
        );
        attributes.insert(
            "model".to_string(),
            Value::String(self.config.model.clone()),
        );
        let category = match hazard_code.and_then(normalize_hazard_code) {
            Some(code) => {
                attributes.insert("hazard_code".to_string(), Value::String(code.to_string()));
                attributes.insert(
                    "hazard_name".to_string(),
                    Value::String(hazard_name(code).to_string()),
                );
                format!(
                    "content_moderation.llama_guard.{}",
                    code.to_ascii_lowercase()
                )
            }
            None => "content_moderation.llama_guard.unsafe".to_string(),
        };
        Finding {
            category,
            severity: FindingSeverity::High,
            confidence: None,
            byte_start: None,
            byte_end: None,
            segment_id: None,
            fingerprint: Some(fingerprint.to_string()),
            matched_text: None,
            attributes,
        }
    }
}

#[async_trait]
impl GuardrailDetector for WorkersAiLlamaGuardDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: self.config.id.clone(),
            version: self.version.clone(),
            supports_request: true,
            supports_response: true,
            // Content-moderation verdict has no spans; a hit cannot be
            // surgically redacted. Honest contract: detect-only.
            supports_transform: false,
            supported_sources: self.config.supported_sources.clone(),
            // Authenticates to Workers AI with the shared client's token.
            credential: DetectorCredentialType::BearerToken,
            // Content is projected to Cloudflare (an external vendor).
            data_residency: DataResidency::ProviderSaas,
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
                "workers-ai llama-guard detector deadline expired before execution",
            )));
        }
        let outcome = self.evaluate_inner(input, deadline).await;
        self.counters.record_outcome(outcome)
    }
}

/// The interpreted Llama Guard verdict: overall safety plus any flagged
/// hazard-category S-codes (upper-cased, e.g. `"S2"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LlamaGuardVerdict {
    pub is_unsafe: bool,
    pub categories: Vec<String>,
}

/// Interpret the model's `response` value into a verdict. Handles both the
/// plain-text form (`"safe"` / `"unsafe\nS2,S9"`) and the structured per-category
/// object form Workers AI can return. `None` means the shape was
/// uninterpretable (surfaced as `InvalidResponse`).
pub(crate) fn interpret_response(value: &Value) -> Option<LlamaGuardVerdict> {
    match value {
        Value::String(text) => Some(interpret_text(text)),
        Value::Bool(safe) => Some(LlamaGuardVerdict {
            is_unsafe: !safe,
            categories: Vec::new(),
        }),
        Value::Object(map) => interpret_object(map),
        _ => None,
    }
}

fn interpret_text(text: &str) -> LlamaGuardVerdict {
    let normalized = text.trim();
    let mut tokens = normalized
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|token| !token.is_empty());
    let first = tokens.next().unwrap_or("");
    let is_unsafe = first.eq_ignore_ascii_case("unsafe");
    let mut categories = Vec::new();
    if is_unsafe {
        for token in tokens {
            if let Some(code) = normalize_hazard_code(token) {
                if !categories.iter().any(|existing| existing == code) {
                    categories.push(code.to_string());
                }
            }
        }
    }
    LlamaGuardVerdict {
        is_unsafe,
        categories,
    }
}

fn interpret_object(map: &Map<String, Value>) -> Option<LlamaGuardVerdict> {
    // Shape A: a top-level `{ "safe": bool, "categories": [...] }`.
    if let Some(safe) = map.get("safe").and_then(Value::as_bool) {
        let categories = map
            .get("categories")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(normalize_hazard_code)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return Some(LlamaGuardVerdict {
            is_unsafe: !safe,
            categories: dedup(categories),
        });
    }

    // Shape B: a per-category map `{ "S2": {"safe": false}, "S9": true, ... }`.
    let mut categories = Vec::new();
    let mut recognized = false;
    for (key, value) in map {
        let Some(code) = normalize_hazard_code(key) else {
            continue;
        };
        recognized = true;
        let category_safe = match value {
            Value::Bool(safe) => *safe,
            Value::Object(inner) => inner.get("safe").and_then(Value::as_bool).unwrap_or(true),
            _ => true,
        };
        if !category_safe {
            categories.push(code.to_string());
        }
    }
    if !recognized {
        return None;
    }
    let categories = dedup(categories);
    Some(LlamaGuardVerdict {
        is_unsafe: !categories.is_empty(),
        categories,
    })
}

fn dedup(mut codes: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    codes.retain(|code| seen.insert(code.clone()));
    codes
}

/// Normalize a hazard-category token to a canonical `S<n>` code (`1..=14`),
/// or `None` if it is not a recognized Llama Guard 3 S-code.
fn normalize_hazard_code(token: &str) -> Option<&'static str> {
    let token = token.trim();
    let digits = token.strip_prefix(['s', 'S'])?;
    let number: u8 = digits.parse().ok()?;
    Some(match number {
        1 => "S1",
        2 => "S2",
        3 => "S3",
        4 => "S4",
        5 => "S5",
        6 => "S6",
        7 => "S7",
        8 => "S8",
        9 => "S9",
        10 => "S10",
        11 => "S11",
        12 => "S12",
        13 => "S13",
        14 => "S14",
        _ => return None,
    })
}

/// Human-readable name for an MLCommons/Llama-Guard-3 hazard S-code.
fn hazard_name(code: &str) -> &'static str {
    match code {
        "S1" => "Violent Crimes",
        "S2" => "Non-Violent Crimes",
        "S3" => "Sex-Related Crimes",
        "S4" => "Child Sexual Exploitation",
        "S5" => "Defamation",
        "S6" => "Specialized Advice",
        "S7" => "Privacy",
        "S8" => "Intellectual Property",
        "S9" => "Indiscriminate Weapons",
        "S10" => "Hate",
        "S11" => "Suicide & Self-Harm",
        "S12" => "Sexual Content",
        "S13" => "Elections",
        "S14" => "Code Interpreter Abuse",
        _ => "Unknown Hazard Category",
    }
}

/// Map a shared-client [`CloudflareError`] onto the guardrail detector error
/// taxonomy. The detector surfaces the error (never a silent pass); the policy
/// `on_error` action owns the fail-open/fail-closed decision.
fn classify_cloudflare_error(error: &CloudflareError) -> DetectorError {
    let (kind, message): (DetectorErrorKind, &str) = match error {
        CloudflareError::Config(_) | CloudflareError::TokenResolution(_) => (
            DetectorErrorKind::InvalidConfiguration,
            "workers-ai llama-guard client is misconfigured",
        ),
        CloudflareError::Transport(_) | CloudflareError::ExhaustedRetries { .. } => (
            DetectorErrorKind::Unavailable,
            "workers-ai llama-guard endpoint is unavailable",
        ),
        CloudflareError::Decode(_) => (
            DetectorErrorKind::InvalidResponse,
            "workers-ai llama-guard returned an undecodable response",
        ),
        CloudflareError::MissingScope { .. } | CloudflareError::Unauthorized { .. } => (
            DetectorErrorKind::Unauthorized,
            "workers-ai llama-guard token is invalid or missing the Workers AI scope",
        ),
        CloudflareError::RateLimited { .. } => (
            DetectorErrorKind::Overloaded,
            "workers-ai llama-guard is rate limited",
        ),
        CloudflareError::Api { .. } => (
            DetectorErrorKind::Unavailable,
            "workers-ai llama-guard returned an API error",
        ),
    };
    DetectorError::new(kind, message)
}

#[cfg(test)]
#[path = "workers_ai_llama_guard_test.rs"]
mod workers_ai_llama_guard_test;
