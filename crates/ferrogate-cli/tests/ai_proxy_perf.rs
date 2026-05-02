mod support;

use std::time::{Duration, Instant};

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

const REQUESTS: usize = 120;

fn read_rss_kb(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[test]
fn openai_chat_non_streaming_dispatch_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) =
        spawn_provider_upstream(REQUESTS, r#"{"id":"chatcmpl_perf","choices":[]}"#);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "chat_perf"
name = "Chat perf"
key = "chat-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let pid = gateway.id();
    let start_rss = read_rss_kb(pid);

    let mut latencies = Vec::with_capacity(REQUESTS);
    let started = Instant::now();
    for _ in 0..REQUESTS {
        let request_started = Instant::now();
        let response = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer chat-secret",
                "Content-Type: application/json",
            ],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        );
        latencies.push(request_started.elapsed());
        assert!(response.contains("200 OK"));
        assert!(response.contains("chatcmpl_perf"));
        assert!(!response.contains("provider-secret"));
    }

    latencies.sort();
    let p95 = latencies[REQUESTS * 95 / 100];
    let end_rss = read_rss_kb(pid);

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), REQUESTS);

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "chat planning smoke exceeded 10s for {REQUESTS} requests"
    );
    assert!(
        p95 < Duration::from_millis(250),
        "chat planning p95 exceeded 250ms: {p95:?}"
    );
    assert!(
        end_rss <= start_rss + 32 * 1024,
        "gateway RSS grew too much: start={start_rss}KB end={end_rss}KB"
    );
}

#[test]
fn openai_chat_auth_error_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:9/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "chat_perf"
name = "Chat perf"
key = "chat-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let pid = gateway.id();
    let start_rss = read_rss_kb(pid);

    let mut latencies = Vec::with_capacity(REQUESTS);
    let started = Instant::now();
    for _ in 0..REQUESTS {
        let request_started = Instant::now();
        let response = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &["Content-Type: application/json"],
            r#"{"model":"fast-chat","messages":[]}"#,
        );
        latencies.push(request_started.elapsed());
        assert!(response.contains("401 Unauthorized"));
        assert!(response.contains("missing_api_key"));
        assert!(!response.contains("chat-secret"));
    }

    latencies.sort();
    let p95 = latencies[REQUESTS * 95 / 100];
    let end_rss = read_rss_kb(pid);

    gateway.kill().unwrap();
    gateway.wait().unwrap();

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "auth error smoke exceeded 10s for {REQUESTS} requests"
    );
    assert!(
        p95 < Duration::from_millis(250),
        "auth error p95 exceeded 250ms: {p95:?}"
    );
    assert!(
        end_rss <= start_rss + 32 * 1024,
        "gateway RSS grew too much: start={start_rss}KB end={end_rss}KB"
    );
}
