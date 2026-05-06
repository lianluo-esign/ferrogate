mod support;

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use support::{
    free_addr, http_request, spawn_provider_upstream_response, start_gateway, wait_for_gateway,
};

fn write_config(path: &std::path::Path, gateway_addr: &str, base_url: &str) {
    write_config_with_extra(path, gateway_addr, base_url, "");
}

fn write_config_with_extra(
    path: &std::path::Path,
    gateway_addr: &str,
    base_url: &str,
    extra_toml: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "{base_url}"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "chat"
name = "Chat"
key = "chat-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

{extra_toml}
"#
        ),
    )
    .unwrap();
}

fn chat(addr: &str) -> String {
    chat_body(addr, r#"{"model":"fast-chat","messages":[]}"#)
}

fn chat_body(addr: &str, body: &str) -> String {
    http_request(
        addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer chat-secret",
            "Content-Type: application/json",
        ],
        body,
    )
}

#[test]
fn chat_maps_https_provider_connect_failure_to_502() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "https://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr);
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn chat_maps_streaming_provider_connect_failure_to_502() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "http://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat_body(
        &gateway_addr,
        r#"{"model":"fast-chat","stream":true,"messages":[]}"#,
    );
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn chat_rejects_malformed_json_before_provider_dispatch() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "http://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat_body(&gateway_addr, r#"{"model":"fast-chat""#);
    assert!(response.contains("400 Bad Request"));
    assert!(response.contains("invalid_json"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn chat_rejects_oversized_body_as_payload_too_large() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "http://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = format!(
        r#"{{"model":"fast-chat","messages":[{{"role":"user","content":"{}"}}]}}"#,
        "x".repeat(1024 * 1024)
    );
    let response = chat_body(&gateway_addr, &body);
    assert!(response.contains("413 Payload Too Large"));
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    assert!(response.contains("payload_too_large"));
    assert!(!response.contains("invalid_json"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn chat_maps_provider_connect_failure_to_502() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "http://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr);
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn chat_maps_malformed_provider_response_to_502() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let provider_addr = listener.local_addr().unwrap().to_string();
    let provider = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 512];
        let _ = stream.read(&mut buffer).unwrap();
        stream.write_all(b"not-http").unwrap();
    });

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(
        &config,
        &gateway_addr,
        &format!("http://{provider_addr}/v1"),
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr);
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    provider.join().unwrap();
}

#[test]
fn chat_normalizes_provider_error_response() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream_response(
        1,
        "429 Too Many Requests",
        "application/json",
        r#"{"error":{"message":"provider rate limited","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(
        &config,
        &gateway_addr,
        &format!("http://{provider_addr}/v1"),
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr);
    assert!(response.contains("429 Too Many Requests"));
    assert!(response.contains("\"type\":\"provider_error\""));
    assert!(response.contains("\"provider_type\":\"rate_limit_error\""));
    assert!(response.contains("\"code\":\"rate_limit_exceeded\""));
    assert!(response.contains("\"provider_status\":429"));
    assert!(response.contains("\"request_id\":\"fg-"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
}

#[test]
fn chat_maps_oversized_provider_response_to_502() {
    let gateway_addr = free_addr();
    let response_body = format!(r#"{{"id":"chatcmpl_big","body":"{}"}}"#, "x".repeat(128));
    let (provider_addr, provider_handle) = spawn_provider_upstream_response(
        1,
        "200 OK",
        "application/json",
        Box::leak(response_body.into_boxed_str()),
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config_with_extra(
        &config,
        &gateway_addr,
        &format!("http://{provider_addr}/v1"),
        r#"
[reliability]
provider_response_body_max_bytes = 32
"#,
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr);
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    assert!(response.contains("provider_response_body_too_large"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
}
