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
