// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Dedicated unit coverage for the image-generation request
// pipeline (issue #275): request validation, prompt-only guardrail
// normalization, per-image (non-token) usage estimation/settlement, and the
// retry/fallback attempt decision.

use super::*;
use crate::config::{ApiKey, Config, Model, Provider};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Synchronous shim over the now-`async` `crate::auth::authenticate`
/// (issue #373); shadows the glob-imported name for this test module so the
/// synchronous request-plan tests below stay unchanged.
fn authenticate(
    state: &crate::state::AppState,
    headers: &http::HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> Result<crate::auth::AuthContext, crate::auth::AuthError> {
    block_on(crate::auth::authenticate(
        state,
        headers,
        required_scope,
        request_id,
    ))
}

#[test]
fn estimates_one_image_by_default() {
    let body = serde_json::json!({"model": "art", "prompt": "a red fox"});
    let usage = estimate_images_usage(&body);
    // The billed unit rides the completion-token dimension; prompt side is 0.
    assert_eq!(usage.prompt_tokens, 0);
    assert_eq!(usage.completion_tokens, 1);
    assert_eq!(usage.total_tokens, 1);
}

#[test]
fn estimates_the_requested_image_count() {
    let body = serde_json::json!({"model": "art", "prompt": "a red fox", "n": 4});
    assert_eq!(estimate_images_usage(&body).total_tokens, 4);
}

#[test]
fn clamps_a_hostile_image_count_estimate() {
    let body = serde_json::json!({"model": "art", "prompt": "x", "n": 100000});
    assert_eq!(
        estimate_images_usage(&body).total_tokens,
        MAX_ESTIMATED_IMAGE_COUNT
    );
}

#[test]
fn settlement_counts_the_response_data_array() {
    let estimate = BillingTokenUsage::new(0, 3, 3);
    let body = br#"{"created":1,"data":[{"url":"a"},{"url":"b"}]}"#;
    let usage = image_settlement_usage(body, &estimate);
    // Two images actually returned, regardless of the request estimate of 3.
    assert_eq!(usage.completion_tokens, 2);
    assert_eq!(usage.total_tokens, 2);
}

#[test]
fn settlement_falls_back_to_the_estimate_when_response_has_no_data_array() {
    let estimate = BillingTokenUsage::new(0, 5, 5);
    let usage = image_settlement_usage(b"not json", &estimate);
    assert_eq!(usage.total_tokens, 5);
}

fn images_plan_config() -> Config {
    Config {
        providers: vec![Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:9999/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            cloudflare_ai_gateway: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "art".into(),
            provider: "openai".into(),
            provider_model: "gpt-image-1".into(),
            routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
            canary: None,
            shadow: None,
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: vec!["images".into()],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        api_keys: vec![ApiKey {
            region_allowlist: Vec::new(),
            id: "key_dev".into(),
            name: "Development key".into(),
            key_env: None,
            key: Some("secret".into()),
            key_hash: None,
            enabled: true,
            scopes: vec![IMAGES_SCOPE.into()],
            allowed_models: Vec::new(),
            denied_models: Vec::new(),
            allowed_providers: Vec::new(),
            denied_providers: Vec::new(),
            organization_id: None,
            platform_operator: None,
            team_id: None,
            project_id: None,
            workspace_id: None,
            user_id: None,
            monthly_token_budget: None,
            request_limit_per_minute: None,
            expires_at_unix: None,
            log_bodies: Some(true),
            cache_enabled: None,
        }],
        ..Config::default()
    }
}

fn images_plan_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer secret"),
    );
    headers
}

#[test]
fn request_plan_rejects_missing_prompt_field() {
    let state = AppState::new(images_plan_config());
    let auth = authenticate(&state, &images_plan_headers(), IMAGES_SCOPE, "fg-test").unwrap();
    let body = br#"{"model":"art"}"#;

    let rejection = build_images_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "invalid_request");
}

#[test]
fn request_plan_rejects_an_empty_prompt() {
    let state = AppState::new(images_plan_config());
    let auth = authenticate(&state, &images_plan_headers(), IMAGES_SCOPE, "fg-test").unwrap();
    let body = br#"{"model":"art","prompt":"   "}"#;

    let rejection = build_images_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "invalid_request");
}

#[test]
fn request_plan_rejects_unknown_model() {
    let state = AppState::new(images_plan_config());
    let auth = authenticate(&state, &images_plan_headers(), IMAGES_SCOPE, "fg-test").unwrap();
    let body = br#"{"model":"unknown","prompt":"a red fox"}"#;

    let rejection = build_images_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "model_not_found");
    assert_eq!(rejection.logical_model.as_deref(), Some("unknown"));
}

#[test]
fn request_plan_accepts_a_valid_prompt_and_normalizes_a_guardrail_envelope() {
    let state = AppState::new(images_plan_config());
    let auth = authenticate(&state, &images_plan_headers(), IMAGES_SCOPE, "fg-test").unwrap();
    let body = br#"{"model":"art","prompt":"a red fox in snow","n":2}"#;

    let plan = build_images_request_plan(&state, &auth, body).unwrap();

    assert_eq!(plan.request.model, "art");
    assert_eq!(plan.routes.len(), 1);
    assert_eq!(plan.estimated_usage.total_tokens, 2);
    assert_eq!(plan.guardrail_envelope.segments.len(), 1);
    assert_eq!(
        plan.guardrail_envelope.segments[0].text,
        "a red fox in snow"
    );
    assert_eq!(plan.guardrail_envelope.protocol, GuardrailProtocol::Images);
}

#[test]
fn images_attempt_retries_before_falling_back_for_retryable_status() {
    let decision = images_attempt_decision(true, 0, /* max_dispatch_retries */ 2, 0, 2);
    assert!(matches!(decision, ImagesAttemptDecision::RetryProvider));
}

#[test]
fn images_attempt_falls_back_after_retries_are_exhausted() {
    let decision = images_attempt_decision(true, 2, /* max_dispatch_retries */ 2, 0, 2);
    assert!(matches!(decision, ImagesAttemptDecision::TryFallbackRoute));
}

#[test]
fn images_attempt_returns_error_when_no_fallback_remains() {
    let decision = images_attempt_decision(true, 2, /* max_dispatch_retries */ 2, 1, 2);
    assert!(matches!(decision, ImagesAttemptDecision::ReturnError));
}
