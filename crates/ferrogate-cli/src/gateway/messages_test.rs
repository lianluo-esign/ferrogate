// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the Anthropic `POST /v1/messages` ingress
// request pipeline (issue #272) -- Anthropic->chat translation flowing through
// the shared governance planner, guardrail-envelope parity, and dispatch
// retry/fallback decisions.

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
/// synchronous `authed` helper and request-plan tests below stay unchanged.
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

fn messages_plan_config() -> Config {
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
            name: "claude-logical".into(),
            provider: "openai".into(),
            provider_model: "gpt-test".into(),
            routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
            canary: None,
            shadow: None,
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: vec!["chat".into(), "streaming".into()],
            context_window: Some(8192),
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
            scopes: vec![MESSAGES_SCOPE.into()],
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

fn messages_plan_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer secret"),
    );
    headers
}

fn authed(state: &AppState) -> AuthContext {
    authenticate(state, &messages_plan_headers(), MESSAGES_SCOPE, "fg-test").unwrap()
}

#[test]
fn request_plan_translates_anthropic_body_and_normalizes_chat_guardrail_envelope() {
    let state = AppState::new(messages_plan_config());
    let auth = authed(&state);
    let body = br#"{
        "model": "claude-logical",
        "max_tokens": 128,
        "stream": true,
        "system": "be concise",
        "messages": [{ "role": "user", "content": "hello guardrail" }]
    }"#;

    let plan = build_messages_request_plan(&state, &auth, body).unwrap();

    assert_eq!(plan.request.model, "claude-logical");
    assert!(plan.request.stream);
    assert_eq!(plan.routes.len(), 1);
    assert_eq!(plan.routes[0].provider, "openai");
    assert_eq!(plan.routes[0].provider_model, "gpt-test");

    // Anthropic system + user turn are translated into an OpenAI chat body.
    assert_eq!(plan.chat_body["messages"][0]["role"], "system");
    assert_eq!(plan.chat_body["messages"][0]["content"], "be concise");
    assert_eq!(plan.chat_body["messages"][1]["role"], "user");
    assert_eq!(plan.chat_body["messages"][1]["content"], "hello guardrail");
    assert_eq!(plan.chat_body["stream"], true);

    // Governance sees the same protocol + text as the OpenAI ingress.
    assert_eq!(
        plan.guardrail_envelope.protocol,
        GuardrailProtocol::ChatCompletions
    );
    assert!(plan
        .guardrail_envelope
        .segments
        .iter()
        .any(|segment| segment.text.contains("hello guardrail")));
    assert!(plan.estimated_usage.total_tokens > 0);
}

#[test]
fn request_plan_translates_tools_and_tool_use_for_dispatch() {
    let state = AppState::new(messages_plan_config());
    let auth = authed(&state);
    let body = br#"{
        "model": "claude-logical",
        "max_tokens": 256,
        "tools": [{ "name": "lookup", "input_schema": { "type": "object" } }],
        "messages": [
            { "role": "assistant", "content": [
                { "type": "tool_use", "id": "toolu_1", "name": "lookup", "input": { "q": "x" } }
            ]},
            { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "toolu_1", "content": "done" }
            ]}
        ]
    }"#;

    let plan = build_messages_request_plan(&state, &auth, body).unwrap();

    assert_eq!(plan.chat_body["tools"][0]["type"], "function");
    assert_eq!(plan.chat_body["tools"][0]["function"]["name"], "lookup");
    let assistant = &plan.chat_body["messages"][0];
    assert_eq!(assistant["role"], "assistant");
    assert_eq!(assistant["tool_calls"][0]["id"], "toolu_1");
    let tool_message = &plan.chat_body["messages"][1];
    assert_eq!(tool_message["role"], "tool");
    assert_eq!(tool_message["tool_call_id"], "toolu_1");
}

#[test]
fn request_plan_rejects_body_without_messages_array() {
    let state = AppState::new(messages_plan_config());
    let auth = authed(&state);
    let body = br#"{"model":"claude-logical","max_tokens":64}"#;

    let rejection = build_messages_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "invalid_request");
}

#[test]
fn request_plan_rejects_unknown_model() {
    let state = AppState::new(messages_plan_config());
    let auth = authed(&state);
    let body = br#"{"model":"nope","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#;

    let rejection = build_messages_request_plan(&state, &auth, body).unwrap_err();

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.code, "model_not_found");
    assert_eq!(rejection.logical_model.as_deref(), Some("nope"));
}

#[test]
fn estimate_messages_usage_is_non_zero_for_a_prompt() {
    let chat_body = serde_json::json!({
        "model": "claude-logical",
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": "hello world" }]
    });

    let usage = estimate_messages_usage(&chat_body, "claude-logical");

    assert!(usage.prompt_tokens > 0);
    assert_eq!(usage.completion_tokens, 32);
    assert_eq!(
        usage.total_tokens,
        usage.prompt_tokens + usage.completion_tokens
    );
}

// Issue #282: a Claude model resolves to the cl100k proxy tokenizer, so the
// prompt side is the real BPE count plus per-message overhead -- not chars/4.
#[test]
fn estimate_messages_usage_uses_the_local_tokenizer_for_claude() {
    let content = "The quick brown fox jumps over the lazy dog.";
    let chat_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": content }]
    });

    let bpe = estimate_messages_usage(&chat_body, "claude-3-5-sonnet-20241022");
    let heuristic = estimate_messages_usage(&chat_body, "opaque-alias");

    assert!(
        bpe.prompt_tokens < heuristic.prompt_tokens,
        "bpe prompt {} should be tighter than heuristic prompt {}",
        bpe.prompt_tokens,
        heuristic.prompt_tokens,
    );
    let expected = crate::tokenizer::count_tokens(
        "claude-3-5-sonnet-20241022",
        &collect_prompt_text(chat_body.get("messages")),
    )
    .expect("claude maps to the cl100k proxy")
        + 4;
    assert_eq!(bpe.prompt_tokens, expected);
}

// Issue #310 settlement-parity regression: the incremental streaming path
// extracts usage from the RAW provider SSE (native extractor over the last
// usage-bearing frame), while the buffered path extracts it from the
// reconstructed chat completion. For the same stream both must settle the
// same token counts -- otherwise switching a request between modes changes
// what gets billed (the #213 under-billing failure mode).
#[test]
fn streamed_usage_extraction_matches_buffered_settlement_for_the_same_stream() {
    let state = AppState::new(messages_plan_config());
    let sse: &[u8] = concat!(
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"parity\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":6,\"total_tokens\":17}}\n\n",
        "data: [DONE]\n\n",
    )
    .as_bytes();

    // Buffered mode: reconstruct the completion, then the native extractor.
    let completion = chat_sse_to_completion(sse);
    let completion_bytes = serde_json::to_vec(&completion).unwrap();
    let buffered = state
        .extract_provider_usage("openai", &completion_bytes)
        .unwrap()
        .expect("buffered completion should carry usage");

    // Streamed mode: the native extractor over the raw SSE usage frames.
    let streamed = extract_last_provider_stream_usage(sse, |payload| {
        state
            .extract_provider_usage("openai", payload)
            .ok()
            .flatten()
    })
    .expect("streamed capture should carry usage");

    assert_eq!(streamed.prompt_tokens, buffered.prompt_tokens);
    assert_eq!(streamed.completion_tokens, buffered.completion_tokens);
    assert_eq!(streamed.total_tokens, buffered.total_tokens);
    assert_eq!(streamed.total_tokens, Some(17));
}

#[test]
fn messages_attempt_retries_before_falling_back_for_retryable_status() {
    assert!(matches!(
        messages_attempt_decision(true, 0, 2, 0, 2),
        MessagesAttemptDecision::RetryProvider
    ));
}

#[test]
fn messages_attempt_falls_back_after_retries_are_exhausted() {
    assert!(matches!(
        messages_attempt_decision(true, 2, 2, 0, 2),
        MessagesAttemptDecision::TryFallbackRoute
    ));
}

#[test]
fn messages_attempt_returns_error_when_no_fallback_remains() {
    assert!(matches!(
        messages_attempt_decision(true, 2, 2, 1, 2),
        MessagesAttemptDecision::ReturnError
    ));
}
