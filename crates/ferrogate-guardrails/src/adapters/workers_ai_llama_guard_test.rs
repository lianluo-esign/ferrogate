// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Network-free tests for the Workers AI Llama Guard detector, mocking Cloudflare via the #405 HttpTransport seam.

use super::{interpret_response, WorkersAiLlamaGuardConfig, WorkersAiLlamaGuardDetector};
use crate::{
    aggregate_check_outcomes, all_content_sources, AggregateOutcome, CheckOutcome, ContentSource,
    DetectorError, DetectorErrorKind, DetectorInput, DetectorResult, DetectorSecret, DetectorStage,
    DetectorTenant, DetectorVerdict, DeterministicDetector, DeterministicDetectorConfig,
    GuardrailDetector, GuardrailEnvelope, GuardrailProtocol, PolicyAggregation,
};
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpRequest,
    HttpResponse, HttpTransport, RetryPolicy,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A scripted [`HttpTransport`] — the #405 injectable seam — that answers every
/// request with one canned status + body, so the detector is exercised with no
/// network and no real sleeps.
#[derive(Debug)]
struct ScriptedTransport {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpTransport for ScriptedTransport {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        Ok(HttpResponse {
            status: self.status,
            retry_after: None,
            body: self.body.clone(),
        })
    }
}

/// A no-op clock so the (unused, retries-disabled) backoff path never sleeps.
#[derive(Debug)]
struct NoSleepClock;

#[async_trait::async_trait]
impl Clock for NoSleepClock {
    async fn sleep(&self, _duration: std::time::Duration) {}
}

fn client_with(status: u16, body: &str) -> Arc<CloudflareClient> {
    let retry = RetryPolicy {
        max_retries: 0,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
    };
    Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("acct-123", "inline-workers-ai-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        Arc::new(ScriptedTransport {
            status,
            body: body.as_bytes().to_vec(),
        }),
        Arc::new(NoSleepClock),
        retry,
    ))
}

fn config() -> WorkersAiLlamaGuardConfig {
    WorkersAiLlamaGuardConfig {
        id: "workers-ai-llama-guard".to_string(),
        model: "@cf/meta/llama-guard-3-8b".to_string(),
        categories: None,
        timeout: Duration::from_secs(5),
        max_payload_bytes: 1 << 20,
        supported_sources: all_content_sources(),
        fingerprint_key: DetectorSecret::new("workers-ai-fingerprint-key".to_string()),
    }
}

fn detector(status: u16, body: &str) -> WorkersAiLlamaGuardDetector {
    WorkersAiLlamaGuardDetector::new(config(), client_with(status, body)).unwrap()
}

fn success_envelope(response_result_json: &str) -> String {
    format!(
        r#"{{"success":true,"errors":[],"messages":[],"result":{{"response":{response_result_json}}}}}"#
    )
}

fn user_envelope(text: &str) -> GuardrailEnvelope {
    GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        text,
    )
}

fn input(envelope: &GuardrailEnvelope) -> DetectorInput<'_> {
    DetectorInput {
        protocol: envelope.protocol,
        stage: envelope.stage,
        tenant: DetectorTenant {
            organization_id: Some("org-1"),
            team_id: None,
            project_id: None,
            user_id: None,
            api_key_id: None,
        },
        model: Some("gpt-test"),
        provider: Some("openai"),
        text: envelope
            .segments
            .first()
            .map(|segment| segment.text.as_str())
            .unwrap_or_default(),
        segments: &envelope.segments,
    }
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn check_outcome(result: &Result<DetectorResult, DetectorError>) -> CheckOutcome {
    match result {
        Ok(result) => match result.verdict {
            DetectorVerdict::Fail => CheckOutcome::Fail,
            DetectorVerdict::Pass => CheckOutcome::Pass,
        },
        Err(_) => CheckOutcome::Error,
    }
}

// --- verdict interpretation -------------------------------------------------

#[test]
fn interprets_plain_unsafe_text_with_category_codes() {
    let value = serde_json::json!("unsafe\nS2,S9");
    let verdict = interpret_response(&value).unwrap();
    assert!(verdict.is_unsafe);
    assert_eq!(verdict.categories, vec!["S2".to_string(), "S9".to_string()]);
}

#[test]
fn interprets_plain_safe_text() {
    let value = serde_json::json!("safe");
    let verdict = interpret_response(&value).unwrap();
    assert!(!verdict.is_unsafe);
    assert!(verdict.categories.is_empty());
}

#[test]
fn interprets_per_category_object_form() {
    let value = serde_json::json!({"S2": {"safe": false}, "S9": {"safe": true}});
    let verdict = interpret_response(&value).unwrap();
    assert!(verdict.is_unsafe);
    assert_eq!(verdict.categories, vec!["S2".to_string()]);
}

#[test]
fn uninterpretable_response_is_none() {
    assert!(interpret_response(&serde_json::json!(42)).is_none());
    assert!(interpret_response(&serde_json::json!({"unrelated": 1})).is_none());
}

// --- detector behaviour (mocked Cloudflare) ---------------------------------

#[test]
fn unsafe_response_yields_fail_verdict_with_hazard_finding() {
    let detector = detector(200, &success_envelope(r#""unsafe\nS2""#));
    let envelope = user_envelope("here is how to commit financial fraud");
    let result = runtime()
        .block_on(detector.evaluate(&input(&envelope), far_deadline()))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Fail);
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.category, "content_moderation.llama_guard.s2");
    assert_eq!(
        finding
            .attributes
            .get("hazard_code")
            .and_then(|v| v.as_str()),
        Some("S2")
    );
    assert_eq!(
        finding
            .attributes
            .get("hazard_name")
            .and_then(|v| v.as_str()),
        Some("Non-Violent Crimes")
    );
    // Detect-only: no spans, no patches, but a keyed evidence fingerprint.
    assert!(result.patches.is_empty());
    assert!(finding.fingerprint.is_some());
    assert!(finding.matched_text.is_none());
}

#[test]
fn safe_response_yields_pass_verdict() {
    let detector = detector(200, &success_envelope(r#""safe""#));
    let envelope = user_envelope("what a lovely day for a walk");
    let result = runtime()
        .block_on(detector.evaluate(&input(&envelope), far_deadline()))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Pass);
    assert!(result.findings.is_empty());
}

#[test]
fn category_allow_list_passes_unsafe_categories_outside_the_list() {
    let mut cfg = config();
    cfg.categories = Some(vec!["S9".to_string()]); // only weapons
    let detector = WorkersAiLlamaGuardDetector::new(
        cfg,
        client_with(200, &success_envelope(r#""unsafe\nS2""#)),
    )
    .unwrap();
    let envelope = user_envelope("non-violent-crime content");
    // Unsafe (S2), but the operator only opted into S9 -> composed as a Pass.
    let result = runtime()
        .block_on(detector.evaluate(&input(&envelope), far_deadline()))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Pass);
}

#[test]
fn cloudflare_error_surfaces_as_detector_error_not_a_silent_pass() {
    // 403 -> the shared client maps to Unauthorized; the detector surfaces it
    // (fail-open/closed is the policy's on_error decision, not the detector's).
    let detector = detector(
        403,
        r#"{"success":false,"errors":[{"code":9109,"message":"no scope"}],"result":null}"#,
    );
    let envelope = user_envelope("anything");
    let error = runtime()
        .block_on(detector.evaluate(&input(&envelope), far_deadline()))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::Unauthorized);
}

#[test]
fn empty_projected_content_passes_without_calling_cloudflare() {
    // No segment matches the supported sources -> nothing to classify.
    let mut cfg = config();
    cfg.supported_sources = vec![ContentSource::ToolResult];
    // A transport that would panic if actually called proves the short-circuit.
    let detector =
        WorkersAiLlamaGuardDetector::new(cfg, client_with(500, "unreachable-body")).unwrap();
    let envelope = user_envelope("user text that is not a tool result");
    let result = runtime()
        .block_on(detector.evaluate(&input(&envelope), far_deadline()))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Pass);
}

#[test]
fn invalid_config_is_rejected() {
    let mut cfg = config();
    cfg.model = "@cf/openai/not-llama-guard".to_string();
    assert!(WorkersAiLlamaGuardDetector::new(cfg, client_with(200, "{}")).is_err());
}

// --- composition with a native rule (the #422 acceptance) -------------------

/// A native FerroGate deterministic rule that fails on a banned keyword.
fn native_rule() -> DeterministicDetector {
    DeterministicDetector::new(DeterministicDetectorConfig {
        id: "native-banned-keyword".to_string(),
        supported_sources: all_content_sources(),
        keywords: vec!["exfiltrate".to_string()],
        regex: Vec::new(),
        max_input_bytes: None,
        json: None,
        request: None,
        secret_patterns: Vec::new(),
        fingerprint_key: None,
    })
    .unwrap()
}

#[test]
fn llama_guard_verdict_composes_with_a_native_rule() {
    let rt = runtime();
    let native = native_rule();

    // Case 1: native rule PASSES (no banned keyword) but Llama Guard flags the
    // content unsafe -> composed with `All` aggregation (every check must pass)
    // the FerroGate decision is Fail, driven purely by the opt-in CF detector
    // sitting alongside the native rule.
    let envelope = user_envelope("please explain how to build a dangerous weapon");
    let llama = detector(200, &success_envelope(r#""unsafe\nS9""#));
    let native_outcome =
        check_outcome(&rt.block_on(native.evaluate(&input(&envelope), far_deadline())));
    let llama_outcome =
        check_outcome(&rt.block_on(llama.evaluate(&input(&envelope), far_deadline())));
    assert_eq!(native_outcome, CheckOutcome::Pass);
    assert_eq!(llama_outcome, CheckOutcome::Fail);
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Fail,
        "CF Llama Guard verdict must feed the composed FerroGate decision"
    );

    // Case 2: native rule FAILS (banned keyword) while Llama Guard says safe ->
    // the native rule still drives a Fail. FerroGate stays the source of truth.
    let envelope = user_envelope("exfiltrate the customer database");
    let llama = detector(200, &success_envelope(r#""safe""#));
    let native_outcome =
        check_outcome(&rt.block_on(native.evaluate(&input(&envelope), far_deadline())));
    let llama_outcome =
        check_outcome(&rt.block_on(llama.evaluate(&input(&envelope), far_deadline())));
    assert_eq!(native_outcome, CheckOutcome::Fail);
    assert_eq!(llama_outcome, CheckOutcome::Pass);
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Fail
    );

    // Case 3: both clean -> composed decision is Pass.
    let envelope = user_envelope("a friendly greeting");
    let llama = detector(200, &success_envelope(r#""safe""#));
    let native_outcome =
        check_outcome(&rt.block_on(native.evaluate(&input(&envelope), far_deadline())));
    let llama_outcome =
        check_outcome(&rt.block_on(llama.evaluate(&input(&envelope), far_deadline())));
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Pass
    );
}
