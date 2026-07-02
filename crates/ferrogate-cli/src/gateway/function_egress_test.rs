// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the gateway-side edge-function TLS executor (#120).

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

use super::*;

fn request_for(addr: &str, body: &str) -> EdgeFunctionHttpRequest {
    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_string(), "Bearer scoped-jwt".to_string());
    headers.insert("apikey".to_string(), "project-anon".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    EdgeFunctionHttpRequest {
        method: "POST".to_string(),
        url: format!("http://{addr}/functions/v1/charge-credits"),
        headers,
        body: body.to_string(),
    }
}

#[tokio::test]
async fn executes_post_and_returns_bounded_outcome() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 2048];
        let read = stream.read(&mut buffer).unwrap();
        let received = String::from_utf8_lossy(&buffer[..read]).to_string();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"charged\":true}",
            )
            .unwrap();
        received
    });

    let request = request_for(&addr, r#"{"amount":10}"#);
    let outcome = execute_edge_function_request(
        &request,
        "charge-credits",
        Duration::from_secs(2),
        64 * 1024,
    )
    .await
    .unwrap();

    assert_eq!(outcome.status_code, 200);
    assert_eq!(outcome.function_slug, "charge-credits");
    assert_eq!(outcome.body_excerpt, r#"{"charged":true}"#);

    // The gateway forwarded the request line, credential header, and body.
    let received = handle.join().unwrap();
    assert!(received.contains("POST /functions/v1/charge-credits"));
    assert!(received
        .to_lowercase()
        .contains("authorization: bearer scoped-jwt"));
    assert!(received.contains(r#"{"amount":10}"#));
}

#[tokio::test]
async fn rejects_oversized_response_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        // Content-Length declares a body larger than the caller's cap.
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap();
        let _ = stream.write_all(&[b'x'; 100]);
    });

    let request = request_for(&addr, "{}");
    let error =
        execute_edge_function_request(&request, "charge-credits", Duration::from_secs(2), 16)
            .await
            .unwrap_err();
    assert!(error.to_string().contains("too_large"));
    let _ = handle.join();
}

#[tokio::test]
async fn rejects_unsupported_scheme() {
    let mut request = request_for("127.0.0.1:1", "{}");
    request.url = "ftp://example.com/functions/v1/x".to_string();
    let error = execute_edge_function_request(&request, "x", Duration::from_secs(1), 1024)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported function url scheme"));
}

fn broker_config() -> FunctionEgressGatewayConfig {
    let allowlist = r#"[{"tenant":"org_a","base_url":"https://aaaa.supabase.co","function_slugs":["charge-credits"]}]"#.to_string();
    FunctionEgressGatewayConfig::from_values(
        Some("signing-secret".to_string()),
        Some("project-anon".to_string()),
        Some(allowlist),
    )
    .expect("broker enabled when secret present")
}

fn invocation_request(slug: &str) -> FunctionInvocationRequest {
    FunctionInvocationRequest {
        tenant: "ignored-by-server".to_string(),
        target: ferrogate_runtime::SupabaseEdgeFunctionTarget {
            base_url: "https://aaaa.supabase.co".to_string(),
            function_slug: slug.to_string(),
            auth_key_ref: "secret:svc".to_string(),
        },
        method: "POST".to_string(),
        body_json: r#"{"amount":5}"#.to_string(),
    }
}

#[test]
fn broker_disabled_without_signing_secret() {
    assert!(FunctionEgressGatewayConfig::from_values(None, None, None).is_none());
    assert!(FunctionEgressGatewayConfig::from_values(Some("   ".into()), None, None).is_none());
}

#[test]
fn prepare_builds_request_with_scoped_bearer_for_allowlisted_target() {
    let config = broker_config();
    let (request, slug) = prepare_brokered_invocation(
        &config,
        "org_a",
        &invocation_request("charge-credits"),
        1_000,
    )
    .unwrap();
    assert_eq!(slug, "charge-credits");
    assert_eq!(
        request.url,
        "https://aaaa.supabase.co/functions/v1/charge-credits"
    );
    let auth = request.headers.get("authorization").unwrap();
    assert!(auth.starts_with("Bearer "));
    // Bearer is a minted JWT (three dot-separated segments), not the raw key.
    assert_eq!(auth.trim_start_matches("Bearer ").split('.').count(), 3);
    assert_eq!(request.headers.get("apikey").unwrap(), "project-anon");
    assert_eq!(request.body, r#"{"amount":5}"#);
}

#[test]
fn prepare_denies_non_allowlisted_tenant_or_slug() {
    let config = broker_config();
    assert!(matches!(
        prepare_brokered_invocation(
            &config,
            "org_ghost",
            &invocation_request("charge-credits"),
            1
        ),
        Err(FunctionBrokerError::Denied(_))
    ));
    assert!(matches!(
        prepare_brokered_invocation(&config, "org_a", &invocation_request("delete-all"), 1),
        Err(FunctionBrokerError::Denied(_))
    ));
}
