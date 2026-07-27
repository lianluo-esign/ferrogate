// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod support;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use support::{
    free_addr, http_request, spawn_provider_upstream_response, start_gateway, start_ready_gateway,
    wait_for_gateway,
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
platform_operator = true

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
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let (mut gateway, gateway_addr) = start_ready_gateway(&config, |addr| {
        write_config(&config, addr, "http://127.0.0.1:9/v1");
    });

    let response = chat_body(
        &gateway_addr,
        r#"{"model":"fast-chat","stream":true,"messages":[]}"#,
    );
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_dispatch_error"));
    // #384: same transport-class contract on the streaming leg.
    assert!(
        response.contains("provider dispatch failed: provider streaming request failed (connect)"),
        "streaming connect failure did not name its transport class: {response}"
    );
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
    // #384: the class must reach the caller so an unreachable upstream is
    // distinguishable from one that simply did not answer in time. Both used
    // to render the identical "provider request failed".
    assert!(
        response.contains("provider dispatch failed: provider request failed (connect)"),
        "connect failure did not name its transport class: {response}"
    );
    assert!(!response.contains("chat-secret"));
    // The operator-configured upstream URL must never reach the caller.
    assert!(!response.contains("127.0.0.1:9"));

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
    let (provider_addr, provider_handle) = spawn_provider_upstream_response(
        1,
        "429 Too Many Requests",
        "application/json",
        r#"{"error":{"message":"provider rate limited","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let base_url = format!("http://{provider_addr}/v1");
    // Retry only relaunches the gateway on a lost bind race, before any request
    // is dispatched, so the single-accept provider mock is never disturbed.
    let (mut gateway, gateway_addr) = start_ready_gateway(&config, |addr| {
        write_config(&config, addr, &base_url);
    });

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

// Issue #311 structural guard: streaming provider bodies are forwarded
// natively on the async runtime. No per-stream blocking-thread shim
// (`spawn_blocking` pump or `block_on` reader) may reappear anywhere in the
// streaming pipeline, and the old sync `ProviderBodyReader` type stays gone.
//
// The paths are `ferrogate-gateway`'s, not this crate's: #553 stage 3b moved
// the whole gateway trunk out of `ferrogate-cli/src/gateway/`, and this guard
// -- like the three `asset_bucket.rs` allow-lists #561 repaired -- kept naming
// the old location. It did NOT go quiet, because `source` panics on a missing
// file rather than skipping it: it went red at `a772842`.
//
// This target is NOT one of #561's unselected 50. It is its own matrix slice in
// `.github/workflows/rust-ai-proxy-tests.yml` and it runs in
// `scripts/local-test-modules.sh`, which makes the fact worse rather than
// better: `ci.yml` fires on `release: published` only, the last release
// (`v2026.07.18`) predates `a772842`, so the RELEASE GATE has been red since
// that commit and no run has been asked to read it. Selection is not health --
// a job that never fires selects nothing in practice.
//
// The `.contains(...)` bans below have an existence floor (`source` panics on
// ENOENT, so a deletion is loud) but no content floor on their own: splitting
// `chat.rs` into `chat.rs` + `chat_stream.rs`, leaving a `pub use` behind and
// putting the pump in the new file, would leave every read succeeding, nothing
// matching, and the guard green. Each file therefore also has to still CONTAIN
// the streaming machinery it is being checked for -- so a move takes the
// sentinel with it and reds here instead of passing over a shell.
#[test]
fn streaming_pipeline_has_no_blocking_thread_shim() {
    let source = |relative: &str| {
        // The manifest dir is `crates/ferrogate-cli`; the streaming pipeline
        // now lives in the sibling `crates/ferrogate-gateway`.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ferrogate-gateway")
            .join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
    };
    // (file, the streaming item that file owns). The sentinel is the thing the
    // ban is ABOUT: if it is not here any more, the pipeline moved and the
    // absence of `spawn_blocking` in this file says nothing.
    for (file, sentinel) in [
        (
            "src/server/dispatch.rs",
            "impl StreamingBodySource for ProviderBodyStream",
        ),
        (
            "src/server/chat.rs",
            "async fn read_provider_streaming_body",
        ),
        ("src/server/messages.rs", "write_streaming_response("),
        ("src/messages_stream.rs", "struct MessagesStreamNormalizer"),
        (
            "src/responses_stream.rs",
            "struct ResponsesStreamNormalizer",
        ),
        ("src/responses.rs", "trait StreamingBodySource"),
    ] {
        let contents = source(file);
        assert!(
            contents.contains(sentinel),
            "{file} no longer contains `{sentinel}`: the streaming pipeline moved, so this \
             file's clean bill of health is about an empty shell. Re-point the guard at \
             wherever the pump now lives."
        );
        assert!(
            !contents.contains("spawn_blocking"),
            "{file} reintroduced a spawn_blocking streaming shim"
        );
        assert!(
            !contents.contains("block_on"),
            "{file} reintroduced a block_on streaming bridge"
        );
    }
    assert!(
        !source("src/server/dispatch.rs").contains("ProviderBodyReader"),
        "the sync ProviderBodyReader shim is back in dispatch.rs"
    );
}

// Issue #311: a client disconnect mid-stream must abort the upstream provider
// read promptly -- the async pump returns on the failed downstream write and
// drops the provider connection, instead of letting the upstream stream run
// to completion in the background.
#[test]
fn client_disconnect_aborts_upstream_streaming_read() {
    let gateway_addr = free_addr();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let provider_addr = listener.local_addr().unwrap().to_string();
    let provider = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = stream.read(&mut buffer).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream
            .write_all(b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
            .unwrap();
        stream.flush().unwrap();
        // Keep emitting ticks: once the client is gone, the gateway must drop
        // this connection, making a write here fail well before the ~15s the
        // stream would otherwise keep going.
        let started = Instant::now();
        for _ in 0..600 {
            if stream
                .write_all(b"data: {\"choices\":[{\"delta\":{\"content\":\"tick\"}}]}\n\n")
                .and_then(|_| stream.flush())
                .is_err()
            {
                return (true, started.elapsed());
            }
            thread::sleep(Duration::from_millis(25));
        }
        (false, started.elapsed())
    });

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(
        &config,
        &gateway_addr,
        &format!("http://{provider_addr}/v1"),
    );
    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    {
        let mut stream = TcpStream::connect(&gateway_addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let body =
            r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        write!(
            stream,
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer chat-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        let mut response = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "gateway closed before first SSE chunk");
            response.extend_from_slice(&buffer[..read]);
            if String::from_utf8_lossy(&response).contains("\"content\":\"first\"") {
                break;
            }
        }
        // Drop the client connection mid-stream.
    }

    let (aborted, elapsed) = provider.join().unwrap();
    assert!(
        aborted,
        "upstream stream ran to completion after client disconnect"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "upstream read was not aborted promptly after client disconnect: {elapsed:?}"
    );
    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
