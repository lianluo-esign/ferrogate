// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Dedicated unit coverage for the embeddings request pipeline (issue #207).

use super::*;
use crate::config::{ApiKey, Config, Model, Provider};

#[test]
fn estimates_prompt_tokens_for_a_single_string_input() {
    let body = serde_json::json!({
        "model": "fast-embed",
        "input": "hello world"
    });

    let usage = estimate_embeddings_usage(&body);

    assert!(usage.prompt_tokens >= 1);
    assert_eq!(usage.completion_tokens, 0);
    assert_eq!(usage.total_tokens, usage.prompt_tokens);
}

#[test]
fn estimates_prompt_tokens_across_a_batch_input() {
    let single = serde_json::json!({"model": "fast-embed", "input": "hello world"});
    let batch = serde_json::json!({
        "model": "fast-embed",
        "input": ["hello world", "hello world"]
    });

    let single_usage = estimate_embeddings_usage(&single);
    let batch_usage = estimate_embeddings_usage(&batch);

    assert_eq!(batch_usage.prompt_tokens, single_usage.prompt_tokens * 2);
}

#[test]
fn missing_or_non_text_input_estimates_zero_tokens() {
    assert_eq!(embeddings_input_character_count(None), 0);
    assert_eq!(
        embeddings_input_character_count(Some(&serde_json::json!(42))),
        0
    );
    assert_eq!(
        embeddings_input_character_count(Some(&serde_json::json!([1, 2, 3]))),
        0
    );
}

fn embeddings_plan_config() -> Config {
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
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-embed".into(),
            provider: "openai".into(),
            provider_model: "text-embedding-3-small".into(),
            routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: vec!["embeddings".into()],
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
            scopes: vec![EMBEDDINGS_SCOPE.into()],
            allowed_models: Vec::new(),
            denied_models: Vec::new(),
            allowed_providers: Vec::new(),
            denied_providers: Vec::new(),
            organization_id: None,
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

fn embeddings_plan_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer secret"),
    );
    headers
}

#[test]
fn request_plan_rejects_missing_input_field() {
    let state = AppState::new(embeddings_plan_config());
    let auth = authenticate(
        &state,
        &embeddings_plan_headers(),
        EMBEDDINGS_SCOPE,
        "fg-test",
    )
    .unwrap();
    let body = br#"{"model":"fast-embed"}"#;

    let rejection = build_embeddings_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "invalid_request");
}

#[test]
fn request_plan_rejects_non_string_non_array_input() {
    let state = AppState::new(embeddings_plan_config());
    let auth = authenticate(
        &state,
        &embeddings_plan_headers(),
        EMBEDDINGS_SCOPE,
        "fg-test",
    )
    .unwrap();
    let body = br#"{"model":"fast-embed","input":42}"#;

    let rejection = build_embeddings_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "invalid_request");
}

#[test]
fn request_plan_rejects_unknown_model() {
    let state = AppState::new(embeddings_plan_config());
    let auth = authenticate(
        &state,
        &embeddings_plan_headers(),
        EMBEDDINGS_SCOPE,
        "fg-test",
    )
    .unwrap();
    let body = br#"{"model":"unknown-model","input":"hello"}"#;

    let rejection = build_embeddings_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "model_not_found");
    assert_eq!(rejection.logical_model.as_deref(), Some("unknown-model"));
}

#[test]
fn request_plan_accepts_a_valid_string_input_and_normalizes_a_guardrail_envelope() {
    let state = AppState::new(embeddings_plan_config());
    let auth = authenticate(
        &state,
        &embeddings_plan_headers(),
        EMBEDDINGS_SCOPE,
        "fg-test",
    )
    .unwrap();
    let body = br#"{"model":"fast-embed","input":"embed this"}"#;

    let plan = build_embeddings_request_plan(&state, &auth, body).unwrap();

    assert_eq!(plan.request.model, "fast-embed");
    assert_eq!(plan.routes.len(), 1);
    assert_eq!(plan.guardrail_envelope.segments.len(), 1);
    assert_eq!(plan.guardrail_envelope.segments[0].text, "embed this");
    assert_eq!(
        plan.guardrail_envelope.protocol,
        GuardrailProtocol::Embeddings
    );
}

#[test]
fn embeddings_attempt_retries_before_falling_back_for_retryable_status() {
    let decision = embeddings_attempt_decision(true, 0, /* max_dispatch_retries */ 2, 0, 2);
    assert!(matches!(decision, EmbeddingsAttemptDecision::RetryProvider));
}

#[test]
fn embeddings_attempt_falls_back_after_retries_are_exhausted() {
    let decision = embeddings_attempt_decision(true, 2, /* max_dispatch_retries */ 2, 0, 2);
    assert!(matches!(
        decision,
        EmbeddingsAttemptDecision::TryFallbackRoute
    ));
}

#[test]
fn embeddings_attempt_returns_error_when_no_fallback_remains() {
    let decision = embeddings_attempt_decision(true, 2, /* max_dispatch_retries */ 2, 1, 2);
    assert!(matches!(decision, EmbeddingsAttemptDecision::ReturnError));
}

#[test]
fn embeddings_attempt_returns_error_immediately_when_not_retryable_and_no_fallback() {
    let decision = embeddings_attempt_decision(false, 0, /* max_dispatch_retries */ 2, 0, 1);
    assert!(matches!(decision, EmbeddingsAttemptDecision::ReturnError));
}
