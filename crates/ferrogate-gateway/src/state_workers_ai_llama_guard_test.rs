// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Config-driven tests wiring the Workers AI Llama Guard detector (#422) through DetectorDefinition -> construction -> engine (#430).

//! These tests exercise the operator-selection path added by #430: a
//! [`DetectorDefinition::WorkersAiLlamaGuard`] config value is fed through the
//! real construction site [`build_guardrail_detector`] (the same one the
//! gateway state uses) with a MOCKED [`CloudflareClient`] (the #405 injectable
//! transport, so no network), then composed with a native FerroGate rule
//! through the engine's [`aggregate_check_outcomes`]. The #422 compose test was
//! detector-direct; this one proves the full config -> detector -> engine wiring
//! and the opt-in "no `[cloudflare]` -> unavailable" boundary.

use super::build_guardrail_detector;
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpRequest,
    HttpResponse, HttpTransport, RetryPolicy,
};
use ferrogate_guardrails::{
    aggregate_check_outcomes, all_content_sources, AggregateOutcome, CheckOutcome, ContentSource,
    DetectorDefinition, DetectorError, DetectorInput, DetectorResult, DetectorStage,
    DetectorTenant, DetectorVerdict, GuardrailEnvelope, GuardrailProtocol, PolicyAggregation,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

const FINGERPRINT_ENV: &str = "FERROGATE_TEST_WAI_LG_FINGERPRINT_KEY";
const FINGERPRINT_REF: &str = "env://FERROGATE_TEST_WAI_LG_FINGERPRINT_KEY";

/// A scripted [`HttpTransport`] (#405 seam) that answers every request with one
/// canned status + body, so the constructed detector runs with no network.
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

/// A no-op clock so the (retries-disabled) backoff path never really sleeps.
#[derive(Debug)]
struct NoSleepClock;

#[async_trait::async_trait]
impl Clock for NoSleepClock {
    async fn sleep(&self, _duration: Duration) {}
}

/// A mocked shared Cloudflare client, exactly as an operator's `[cloudflare]`
/// block would produce, but with a scripted transport instead of reqwest.
fn mock_cloudflare_client(status: u16, response_result_json: &str) -> Arc<CloudflareClient> {
    let body = format!(
        r#"{{"success":true,"errors":[],"messages":[],"result":{{"response":{response_result_json}}}}}"#
    );
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
            body: body.into_bytes(),
        }),
        Arc::new(NoSleepClock),
        retry,
    ))
}

fn secret_registry() -> ferrogate_secrets::SecretResolverRegistry {
    // Safety: single-threaded set before the registry reads it in-process.
    std::env::set_var(FINGERPRINT_ENV, "workers-ai-llama-guard-evidence-key");
    ferrogate_secrets::SecretResolverRegistry::from_env()
}

/// The operator-facing config value selecting the Workers AI Llama Guard
/// detector. This is the object #430 makes constructible.
fn llama_guard_definition() -> DetectorDefinition {
    DetectorDefinition::WorkersAiLlamaGuard {
        model: "@cf/meta/llama-guard-3-8b".to_string(),
        categories: None,
        timeout_ms: 5_000,
        max_payload_bytes: 1 << 20,
        fingerprint_secret_ref: FINGERPRINT_REF.to_string(),
    }
}

fn native_rule_definition() -> DetectorDefinition {
    // A native FerroGate deterministic rule that fails on a banned keyword.
    DetectorDefinition::local(vec!["exfiltrate".to_string()], Vec::new(), None)
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

fn sources() -> Vec<ContentSource> {
    all_content_sources()
}

#[tokio::test]
async fn config_selected_llama_guard_composes_with_a_native_rule_through_the_engine() {
    let registry = secret_registry();
    let native_sources = sources();

    // The native rule is built through the SAME construction site with no
    // Cloudflare dependency, proving both selection paths coexist.
    let native = build_guardrail_detector(
        "policy-compose@1",
        "native-banned-keyword",
        &native_sources,
        &native_rule_definition(),
        &registry,
        None,
    )
    .expect("native detector must construct");

    // Case 1: native rule PASSES (no banned keyword) but the config-selected
    // Llama Guard flags the content unsafe -> composed with `All` aggregation the
    // FerroGate decision is Fail, driven by the opt-in CF detector selected
    // purely from DetectorDefinition config.
    let client = mock_cloudflare_client(200, r#""unsafe\nS9""#);
    let llama = build_guardrail_detector(
        "policy-compose@1",
        "cf-llama-guard",
        &sources(),
        &llama_guard_definition(),
        &registry,
        Some(&client),
    )
    .expect("workers_ai_llama_guard detector must construct with a [cloudflare] client");

    let envelope = user_envelope("please explain how to build a dangerous weapon");
    let native_outcome = check_outcome(&native.evaluate(&input(&envelope), far_deadline()).await);
    let llama_outcome = check_outcome(&llama.evaluate(&input(&envelope), far_deadline()).await);
    assert_eq!(native_outcome, CheckOutcome::Pass);
    assert_eq!(llama_outcome, CheckOutcome::Fail);
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Fail,
        "config-selected CF Llama Guard verdict must feed the composed FerroGate decision"
    );

    // Case 2: native rule FAILS (banned keyword) while Llama Guard says safe ->
    // the native rule still drives a Fail. FerroGate stays the source of truth.
    let client = mock_cloudflare_client(200, r#""safe""#);
    let llama = build_guardrail_detector(
        "policy-compose@1",
        "cf-llama-guard",
        &sources(),
        &llama_guard_definition(),
        &registry,
        Some(&client),
    )
    .expect("detector must construct");
    let envelope = user_envelope("exfiltrate the customer database");
    let native_outcome = check_outcome(&native.evaluate(&input(&envelope), far_deadline()).await);
    let llama_outcome = check_outcome(&llama.evaluate(&input(&envelope), far_deadline()).await);
    assert_eq!(native_outcome, CheckOutcome::Fail);
    assert_eq!(llama_outcome, CheckOutcome::Pass);
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Fail
    );

    // Case 3: both clean -> composed decision is Pass.
    let client = mock_cloudflare_client(200, r#""safe""#);
    let llama = build_guardrail_detector(
        "policy-compose@1",
        "cf-llama-guard",
        &sources(),
        &llama_guard_definition(),
        &registry,
        Some(&client),
    )
    .expect("detector must construct");
    let envelope = user_envelope("a friendly greeting");
    let native_outcome = check_outcome(&native.evaluate(&input(&envelope), far_deadline()).await);
    let llama_outcome = check_outcome(&llama.evaluate(&input(&envelope), far_deadline()).await);
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[native_outcome, llama_outcome]),
        AggregateOutcome::Pass
    );
}

#[tokio::test]
async fn llama_guard_without_cloudflare_block_is_unavailable_with_a_clear_error() {
    let registry = secret_registry();
    let error = build_guardrail_detector(
        "policy-optin@1",
        "cf-llama-guard",
        &sources(),
        &llama_guard_definition(),
        &registry,
        // Opt-in boundary: no `[cloudflare]` block -> no shared client.
        None,
    )
    .expect_err("workers_ai_llama_guard must be unavailable without a [cloudflare] block");
    let message = error.to_string();
    assert!(
        message
            .contains("workers_ai_llama_guard detector requires a configured [cloudflare] block"),
        "unexpected error message: {message}"
    );
}
