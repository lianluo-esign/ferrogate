// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for request building, response classification, and pagination
//! (#360). Pure logic only — no live network.

use super::*;
use crate::auth::Credential;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::ExitClass;
use crate::output::OutputFormat;
use std::sync::Mutex;
use std::task::{Context as TaskContext, Poll, Waker};

fn context_with_endpoint(endpoint: &str, tenant: Option<&str>) -> EffectiveContext {
    EffectiveContext {
        context_name: Some("test".to_string()),
        endpoint: endpoint.to_string(),
        tenant: tenant.map(str::to_string),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: crate::auth::AuthSource::None,
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

/// Minimal single-poll executor: the fake transport's future is always ready,
/// so a spin-poll with a no-op waker completes it without pulling in a runtime.
fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    // Safety: the future is owned locally and never moved after pinning.
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => continue,
        }
    }
}

#[test]
fn prepare_request_builds_url_headers_and_body() {
    let context = context_with_endpoint("https://prod.example.com", Some("acme"));
    let credential = Credential::new("secret-token").unwrap();
    let spec = RequestSpec::new(Method::POST, "/admin/v1/tenants")
        .with_json_body(serde_json::json!({"name": "new-tenant"}))
        .with_query("dry_run", "true");
    let prepared = prepare_request(&spec, &context, Some(&credential)).unwrap();

    assert_eq!(prepared.method, Method::POST);
    assert_eq!(
        prepared.url,
        "https://prod.example.com/admin/v1/tenants?dry_run=true"
    );
    assert_eq!(
        prepared.header("authorization"),
        Some("Bearer secret-token")
    );
    assert_eq!(prepared.header("accept"), Some("application/json"));
    assert_eq!(prepared.header("content-type"), Some("application/json"));
    assert_eq!(prepared.header("x-ferrogate-tenant"), Some("acme"));
    assert!(prepared.header("user-agent").unwrap().contains("ferrogate"));
    assert_eq!(prepared.body, br#"{"name":"new-tenant"}"#.to_vec());
}

#[test]
fn prepare_request_without_credential_omits_authorization() {
    let context = context_with_endpoint("http://127.0.0.1:8080", None);
    let spec = RequestSpec::get("/admin/v1/status");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert_eq!(prepared.header("authorization"), None);
    assert_eq!(prepared.header("x-ferrogate-tenant"), None);
    assert!(prepared.body.is_empty());
    assert_eq!(prepared.url, "http://127.0.0.1:8080/admin/v1/status");
}

#[test]
fn prepare_request_preserves_endpoint_base_path() {
    let context = context_with_endpoint("https://host.example.com/gw/", None);
    let spec = RequestSpec::get("/admin/v1/status");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert_eq!(prepared.url, "https://host.example.com/gw/admin/v1/status");
}

#[test]
fn prepare_request_percent_encodes_query() {
    let context = context_with_endpoint("http://localhost:8080", None);
    let spec = RequestSpec::get("/admin/v1/search").with_query("q", "a b&c");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert!(prepared.url.contains("q=a+b%26c") || prepared.url.contains("q=a%20b%26c"));
}

#[test]
fn classify_success_extracts_body_and_correlation_ids() {
    let raw = RawResponse {
        status: 200,
        headers: vec![
            ("x-request-id".to_string(), "fgadm-01".to_string()),
            ("x-trace-id".to_string(), "trace-99".to_string()),
        ],
        body: br#"{"items":[{"id":"t1"}]}"#.to_vec(),
    };
    let response = classify(&raw).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.request_id.as_deref(), Some("fgadm-01"));
    assert_eq!(response.trace_id.as_deref(), Some("trace-99"));
    assert_eq!(response.body["items"][0]["id"], "t1");
}

#[test]
fn classify_empty_success_body_is_null() {
    let raw = RawResponse {
        status: 204,
        headers: vec![],
        body: vec![],
    };
    let response = classify(&raw).unwrap();
    assert_eq!(response.body, serde_json::Value::Null);
}

#[test]
fn classify_decodes_ferrogate_error_envelope() {
    let raw = RawResponse {
        status: 404,
        headers: vec![("x-trace-id".to_string(), "trace-77".to_string())],
        body: br#"{"error":{"message":"no such tenant","type":"ferrogate_error","code":"tenant_not_found","request_id":"fgadm-77","hint":"check the id"}}"#.to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.http_status, 404);
    assert_eq!(error.code, "tenant_not_found");
    assert_eq!(error.message, "no such tenant");
    assert_eq!(error.request_id.as_deref(), Some("fgadm-77"));
    assert_eq!(error.trace_id.as_deref(), Some("trace-77"));
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
    // Unknown extra fields are preserved as details, not dropped.
    assert_eq!(error.details.unwrap()["hint"], "check the id");
}

#[test]
fn classify_extracts_retry_after_hint() {
    let raw = RawResponse {
        status: 429,
        headers: vec![("retry-after".to_string(), "12".to_string())],
        body: br#"{"error":{"message":"slow down","type":"ferrogate_error","code":"rate_limited","request_id":null}}"#.to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Transport);
    assert_eq!(error.retry_after_secs, Some(12));
}

#[test]
fn classify_synthesizes_error_for_nonjson_body() {
    let raw = RawResponse {
        status: 502,
        headers: vec![],
        body: b"upstream unreachable".to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.http_status, 502);
    assert_eq!(error.code, "server_error");
    assert_eq!(error.message, "upstream unreachable");
    assert_eq!(error.exit_class(), ExitClass::Server);
}

#[test]
fn page_request_query_params() {
    let page = PageRequest::first(50);
    assert_eq!(
        page.query_params(),
        vec![
            ("offset".to_string(), "0".to_string()),
            ("limit".to_string(), "50".to_string())
        ]
    );
    let no_limit = PageRequest {
        offset: 100,
        limit: None,
    };
    assert_eq!(
        no_limit.query_params(),
        vec![("offset".to_string(), "100".to_string())]
    );
}

#[test]
fn next_page_stops_on_known_total() {
    let first = PageRequest::first(50);
    let next = next_page(&first, 50, Some(120)).unwrap();
    assert_eq!(next.offset, 50);
    let third = next_page(&next, 50, Some(120)).unwrap();
    assert_eq!(third.offset, 100);
    // 100 + 20 returned reaches the total of 120: done.
    assert_eq!(next_page(&third, 20, Some(120)), None);
}

#[test]
fn next_page_stops_on_short_page_when_total_unknown() {
    let first = PageRequest::first(50);
    // A full page implies more may follow.
    assert!(next_page(&first, 50, None).is_some());
    // A short page is the last page.
    assert_eq!(next_page(&first, 30, None), None);
    // An empty page always ends iteration.
    assert_eq!(next_page(&first, 0, None), None);
}

#[test]
fn plan_all_pages_covers_every_item_without_truncation() {
    assert_eq!(plan_all_pages(0, 50), vec![]);
    let pages = plan_all_pages(120, 50);
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[0].offset, 0);
    assert_eq!(pages[1].offset, 50);
    assert_eq!(pages[2].offset, 100);
    // A zero limit is clamped so the plan is finite.
    assert_eq!(plan_all_pages(3, 0).len(), 3);
}

/// Fake transport recording the last prepared request and returning a scripted
/// response, so the client orchestration is proven without a network.
struct FakeTransport {
    response: RawResponse,
    seen: Mutex<Option<PreparedRequest>>,
}

impl Transport for FakeTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        *self.seen.lock().unwrap() = Some(request);
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}

#[test]
fn client_sends_prepared_request_and_classifies_success() {
    let context = context_with_endpoint("https://prod.example.com", Some("acme"));
    let credential = Credential::new("secret").unwrap();
    let transport = FakeTransport {
        response: RawResponse {
            status: 200,
            headers: vec![("x-request-id".to_string(), "fgadm-abc".to_string())],
            body: br#"{"status":"ok"}"#.to_vec(),
        },
        seen: Mutex::new(None),
    };
    let client = ControlPlaneClient::new(context, Some(credential), transport);
    let spec = RequestSpec::get("/admin/v1/status");
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.request_id.as_deref(), Some("fgadm-abc"));
    assert_eq!(response.body["status"], "ok");
}

#[test]
fn client_maps_error_envelope_to_cli_error() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = FakeTransport {
        response: RawResponse {
            status: 403,
            headers: vec![],
            body: br#"{"error":{"message":"wrong scope","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-x"}}"#.to_vec(),
        },
        seen: Mutex::new(None),
    };
    let client = ControlPlaneClient::new(context, None, transport);
    let spec = RequestSpec::get("/admin/v1/tenants");
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}
