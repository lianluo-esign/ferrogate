// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Regression tests for ferrogate-test local harness readiness identity checks.

use super::*;

fn response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        body: body.to_string(),
        raw: format!("HTTP/1.1 {status}\r\n\r\n{body}"),
    }
}

#[test]
fn gateway_readiness_accepts_only_ferrogate_healthz_identity() {
    let healthz = response(200, r#"{"service":"ferrogate","status":"ok"}"#);

    assert!(healthz_identifies_ferrogate(&healthz));
}

#[test]
fn gateway_readiness_rejects_a_mock_models_response_even_when_http_200() {
    let provider_models = response(200, r#"{"object":"list","data":[{"id":"provider-chat"}]}"#);

    assert!(!healthz_identifies_ferrogate(&provider_models));
}

#[test]
fn gateway_readiness_rejects_wrong_service_non_json_and_non_200() {
    let wrong_service = response(200, r#"{"service":"ferrogate-auth","status":"ok"}"#);
    let plain_200 = response(200, "ok");
    let unavailable = response(503, r#"{"service":"ferrogate","status":"ok"}"#);

    assert!(!healthz_identifies_ferrogate(&wrong_service));
    assert!(!healthz_identifies_ferrogate(&plain_200));
    assert!(!healthz_identifies_ferrogate(&unavailable));
}
