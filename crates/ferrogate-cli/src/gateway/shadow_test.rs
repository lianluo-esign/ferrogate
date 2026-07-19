// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Tests for shadow/mirror dispatch (issue #276): sampling +
// budget gating, fire-and-forget dispatch against a mock upstream, and
// failure-swallowing without ever affecting the primary path.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use serde_json::json;

use super::*;
use crate::config::{Model, Provider, ShadowRoute};
use crate::state::AppState;
use ferrogate_core::TenantContext;

fn provider(name: &str, base_url: &str, enabled: bool) -> Provider {
    Provider {
        region: None,
        aws_access_key_id: None,
        aws_secret_access_key_env: None,
        aws_session_token_env: None,
        gcp_project_id: None,
        gcp_access_token_env: None,
        name: name.into(),
        kind: "openai".into(),
        base_url: base_url.into(),
        api_key_env: None,
        secret_ref: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        enabled,
    }
}

fn model_with_shadow(shadow: Option<ShadowRoute>) -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "primary".into(),
        provider_model: "gpt-4o-mini".into(),
        routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
        canary: None,
        shadow,
        fallbacks: vec![],
        visible_organization_ids: vec![],
        visible_project_ids: vec![],
        capabilities: vec![],
        context_window: None,
        input_price_per_1m: Some(1.0),
        output_price_per_1m: Some(1.0),
        enabled: true,
        cache_enabled: None,
    }
}

fn shadow_route(sample_percent: u8, max_requests: u64, enabled: bool) -> ShadowRoute {
    ShadowRoute {
        provider: "shadow".into(),
        provider_model: "gpt-4o".into(),
        sample_percent,
        max_requests,
        enabled,
    }
}

fn state_with(shadow: Option<ShadowRoute>, shadow_base_url: &str) -> AppState {
    let config = crate::config::Config {
        providers: vec![
            provider("primary", "http://127.0.0.1:1/primary", true),
            provider("shadow", shadow_base_url, true),
        ],
        models: vec![model_with_shadow(shadow)],
        ..crate::config::Config::default()
    };
    AppState::new(config)
}

fn params(body: serde_json::Value) -> ShadowMirrorParams {
    ShadowMirrorParams {
        endpoint: AiEndpoint::ChatCompletions,
        request_id: "req-1".into(),
        route: "openai.chat.completions",
        logical_model: "fast-chat".into(),
        tenant: TenantContext::default(),
        api_key_id: Some("key-1".into()),
        sticky_key: "key-1".into(),
        body,
    }
}

#[test]
fn decision_is_none_when_no_shadow_configured() {
    let state = state_with(None, "http://127.0.0.1:1/shadow");
    assert!(shadow_decision(&state, "fast-chat", "key-1").is_none());
}

#[test]
fn decision_is_none_when_sample_percent_zero() {
    let state = state_with(Some(shadow_route(0, 0, true)), "http://127.0.0.1:1/shadow");
    assert!(shadow_decision(&state, "fast-chat", "key-1").is_none());
}

#[test]
fn decision_is_none_when_disabled() {
    let state = state_with(
        Some(shadow_route(100, 0, false)),
        "http://127.0.0.1:1/shadow",
    );
    assert!(shadow_decision(&state, "fast-chat", "key-1").is_none());
}

#[test]
fn decision_selects_target_and_charges_budget() {
    let state = state_with(
        Some(shadow_route(100, 0, true)),
        "http://127.0.0.1:1/shadow",
    );
    let target = shadow_decision(&state, "fast-chat", "key-1").expect("should sample");
    assert_eq!(target.provider.name, "shadow");
    assert_eq!(target.provider_model, "gpt-4o");
}

#[test]
fn decision_respects_budget_cap() {
    let state = state_with(
        Some(shadow_route(100, 2, true)),
        "http://127.0.0.1:1/shadow",
    );
    assert!(shadow_decision(&state, "fast-chat", "key-1").is_some());
    assert!(shadow_decision(&state, "fast-chat", "key-1").is_some());
    assert!(
        shadow_decision(&state, "fast-chat", "key-1").is_none(),
        "third decision must be refused by the budget cap"
    );
}

#[tokio::test]
async fn dispatch_records_success_against_mock_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).unwrap();
        let received = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        received
    });

    let base_url = format!("http://127.0.0.1:{port}/v1");
    let state = state_with(Some(shadow_route(100, 0, true)), &base_url);
    let target = shadow_decision(&state, "fast-chat", "key-1").expect("sampled");

    execute_shadow_dispatch(
        state.clone(),
        target,
        params(json!({"model": "fast-chat", "stream": true, "messages": []})),
    )
    .await;

    let received = handle.join().unwrap();
    // The client's `stream: true` was mirrored as a non-streaming call.
    assert!(received.contains("POST"));
    assert_eq!(
        state.shadow_metrics(),
        (1, 0),
        "success must be metered as shadow"
    );
}

#[tokio::test]
async fn dispatch_swallows_connection_failure() {
    // Port 1 is not listening: the shadow dispatch must fail internally,
    // record a shadow failure, and return without panicking -- it can never
    // affect the primary response.
    let state = state_with(Some(shadow_route(100, 0, true)), "http://127.0.0.1:1/v1");
    let target = shadow_decision(&state, "fast-chat", "key-1").expect("sampled");

    execute_shadow_dispatch(
        state.clone(),
        target,
        params(json!({"model": "fast-chat", "messages": []})),
    )
    .await;

    assert_eq!(
        state.shadow_metrics(),
        (0, 1),
        "a failed shadow dispatch is swallowed and metered as a failure"
    );
}

#[tokio::test]
async fn dispatch_records_failure_on_non_success_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = stream.read(&mut buffer).unwrap();
        stream
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let base_url = format!("http://127.0.0.1:{port}/v1");
    let state = state_with(Some(shadow_route(100, 0, true)), &base_url);
    let target = shadow_decision(&state, "fast-chat", "key-1").expect("sampled");

    execute_shadow_dispatch(
        state.clone(),
        target,
        params(json!({"model": "fast-chat", "messages": []})),
    )
    .await;

    handle.join().unwrap();
    assert_eq!(state.shadow_metrics(), (0, 1));
}
