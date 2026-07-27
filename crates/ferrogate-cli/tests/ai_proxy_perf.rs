// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod support;

use std::{
    thread,
    time::{Duration, Instant},
};

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

const REQUESTS: usize = 120;
const CONCURRENT_REQUESTS: usize = 32;
/// Number of successive concurrent bursts the concurrent-dispatch smokes drive.
/// Two bursts let them compare steady-state RSS across bursts (see the tests) so
/// the memory guard is robust to one-time allocator retention (#240).
const STREAMING_BURSTS: usize = 2;
/// Time given to the gateway to quiesce before sampling RSS, so the reading
/// reflects steady state rather than the in-flight peak of a burst.
const RSS_SETTLE: Duration = Duration::from_millis(300);

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
platform_operator = true
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
platform_operator = true
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

#[test]
fn openai_chat_concurrent_dispatch_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        STREAMING_BURSTS * CONCURRENT_REQUESTS,
        r#"{"id":"chatcmpl_concurrent","choices":[]}"#,
    );
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
platform_operator = true
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let pid = gateway.id();

    // See the streaming smoke below for the rationale: a single 32-way
    // concurrent burst forces the system allocator to acquire and retain arenas,
    // so start-vs-post-burst RSS growth measures that one-time retention (which
    // swings tens of MB run to run) rather than a leak. Drive two bursts and
    // guard the *second* steady-state delta instead (#240).
    let run_burst = || {
        let mut workers = Vec::with_capacity(CONCURRENT_REQUESTS);
        for _ in 0..CONCURRENT_REQUESTS {
            let gateway_addr = gateway_addr.clone();
            workers.push(thread::spawn(move || {
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
                (request_started.elapsed(), response)
            }));
        }
        let mut latencies = Vec::with_capacity(CONCURRENT_REQUESTS);
        for worker in workers {
            let (latency, response) = worker.join().unwrap();
            latencies.push(latency);
            assert!(response.contains("200 OK"));
            assert!(response.contains("chatcmpl_concurrent"));
            assert!(!response.contains("chat-secret"));
        }
        latencies
    };

    let started = Instant::now();
    let mut latencies = run_burst();
    thread::sleep(RSS_SETTLE);
    let rss_after_first = read_rss_kb(pid);
    latencies.extend(run_burst());
    thread::sleep(RSS_SETTLE);
    let rss_after_second = read_rss_kb(pid);

    latencies.sort();
    let p95 = latencies[latencies.len() * 95 / 100];

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(
        provider_requests.len(),
        STREAMING_BURSTS * CONCURRENT_REQUESTS
    );

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "concurrent chat smoke exceeded 10s for {} requests",
        STREAMING_BURSTS * CONCURRENT_REQUESTS
    );
    assert!(
        p95 < Duration::from_millis(500),
        "concurrent chat p95 exceeded 500ms: {p95:?}"
    );
    // Steady-state leak guard: after the first burst pays the one-time
    // retention cost, a leak-free gateway barely grows across a second burst.
    // 12MB is generous headroom over the observed ~2-5MB steady-state delta and
    // still well under the ~32MB a per-request leak would add. See #240.
    let second_delta = rss_after_second.saturating_sub(rss_after_first);
    assert!(
        second_delta <= 12 * 1024,
        "gateway RSS kept growing across bursts (possible leak): \
         after_first={rss_after_first}KB after_second={rss_after_second}KB delta={second_delta}KB"
    );
}

#[test]
fn openai_chat_streaming_concurrent_dispatch_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        STREAMING_BURSTS * CONCURRENT_REQUESTS,
        "data: {\"id\":\"chatcmpl_stream_perf\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n",
    );
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
platform_operator = true
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let pid = gateway.id();

    // Drive a single burst of `CONCURRENT_REQUESTS` concurrent streaming
    // requests, returning their per-request latencies. Sampling RSS *after* the
    // gateway has been given a moment to settle lets the allocator quiesce so
    // the reading reflects steady state rather than the in-flight high-water
    // mark of the burst itself.
    let run_burst = || {
        let mut workers = Vec::with_capacity(CONCURRENT_REQUESTS);
        for _ in 0..CONCURRENT_REQUESTS {
            let gateway_addr = gateway_addr.clone();
            workers.push(thread::spawn(move || {
                let request_started = Instant::now();
                let response = http_request(
                    &gateway_addr,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        "Authorization: Bearer chat-secret",
                        "Content-Type: application/json",
                    ],
                    r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#,
                );
                (request_started.elapsed(), response)
            }));
        }
        let mut latencies = Vec::with_capacity(CONCURRENT_REQUESTS);
        for worker in workers {
            let (latency, response) = worker.join().unwrap();
            latencies.push(latency);
            assert!(response.contains("200 OK"));
            assert!(response.contains("chatcmpl_stream_perf"));
            assert!(response.contains("data: [DONE]"));
            assert!(!response.contains("chat-secret"));
        }
        latencies
    };

    let started = Instant::now();

    // First burst: warms the process and forces the system allocator to acquire
    // (and, on glibc, retain) the per-connection/streaming arenas. RSS does not
    // shrink back after the burst, so comparing start-vs-post-burst RSS measures
    // that one-time retention, not a leak -- which is exactly what made the old
    // `end <= start + 32MB` check flaky (#240).
    let mut latencies = run_burst();
    thread::sleep(RSS_SETTLE);
    let rss_after_first = read_rss_kb(pid);

    // Second burst: reuses the arenas the first burst already mapped. A gateway
    // with no per-request leak plateaus here (steady state), so the *second*
    // delta is small and stable; a genuine unbounded leak would keep growing by
    // roughly another burst's worth of memory. Guarding the second delta -- not
    // the absolute post-warmup growth -- is therefore robust to allocator
    // retention while still catching a real leak.
    latencies.extend(run_burst());
    thread::sleep(RSS_SETTLE);
    let rss_after_second = read_rss_kb(pid);

    latencies.sort();
    let p95 = latencies[latencies.len() * 95 / 100];

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(
        provider_requests.len(),
        STREAMING_BURSTS * CONCURRENT_REQUESTS
    );
    assert!(provider_requests
        .iter()
        .all(|request| request.contains("\"stream\":true")));

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "concurrent streaming chat smoke exceeded 10s for {} requests",
        STREAMING_BURSTS * CONCURRENT_REQUESTS
    );
    assert!(
        p95 < Duration::from_millis(500),
        "concurrent streaming chat p95 exceeded 500ms: {p95:?}"
    );
    // Steady-state leak guard. After the first burst has paid the one-time
    // allocator-retention cost (`after_first` varies wildly, ~69-104MB run to
    // run -- the noise that made the old absolute check flaky), a leak-free
    // gateway barely grows across a second identical burst. The observed
    // second-burst delta is small and stable (~2-5MB across dozens of runs); the
    // 12MB budget is ~2.5x headroom over that steady state while still well
    // below the ~32MB a per-request leak would add on the second burst.
    let second_delta = rss_after_second.saturating_sub(rss_after_first);
    assert!(
        second_delta <= 12 * 1024,
        "gateway RSS kept growing across bursts (possible leak): \
         after_first={rss_after_first}KB after_second={rss_after_second}KB delta={second_delta}KB"
    );
}
