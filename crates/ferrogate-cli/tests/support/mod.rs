// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

pub fn start_gateway(config: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args(["run", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

pub fn wait_for_gateway(addr: &str) {
    // Generous readiness window: a Supabase-backed gateway re-runs the full
    // idempotent schema batch and the ~150-probe validate_schema pass against
    // a REMOTE pooler before listening, which takes minutes at cross-region
    // round-trip latencies (~300ms/query). Fast (local/in-memory) environments
    // are unaffected -- this only bounds how long a genuinely broken startup
    // waits before failing.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(300) {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut buffer = [0_u8; 512];
            if stream.read(&mut buffer).unwrap_or(0) > 0 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway did not become ready at {addr}");
}

/// Like [`http_request`] but sends a binary request body and returns the raw
/// response bytes, for endpoints that push non-UTF-8 payloads (e.g. a zip site
/// bundle) or serve binary content.
#[allow(dead_code)]
pub fn http_request_bytes(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n").unwrap();
    stream.write_all(body).unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

/// Like [`http_request`] but with an explicit `Host` header, for exercising
/// host-based resolution (e.g. custom-domain static-site serving, #265) --
/// `http_request` always sends `Host: localhost`.
#[allow(dead_code)]
pub fn http_request_with_host(
    addr: &str,
    host: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

pub fn http_request(addr: &str, method: &str, path: &str, headers: &[&str], body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    // Generous read timeout: some endpoints (e.g. `/v1/tools/execute` gated on a
    // tool approval that is left to fail closed by its TTL) intentionally hold
    // the response until a server-side deadline elapses. The timeout only bounds
    // how long a genuinely hung request waits before failing; it never changes a
    // response, so keeping it well above any test's server-side wait avoids
    // coupling approval-TTL choices to the client read deadline.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[allow(dead_code)]
pub fn spawn_provider_upstream(
    count: usize,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    spawn_provider_upstream_response(count, "200 OK", "application/json", response_body)
}

#[allow(dead_code)]
pub fn spawn_provider_upstream_response(
    count: usize,
    status: &'static str,
    content_type: &'static str,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

/// Spawns a plain-HTTP mock webhook receiver on `127.0.0.1` that accepts
/// any number of sequential `Connection: close` JSON POSTs, recording each
/// body in arrival order. Used to prove outbound webhook dispatch (e.g. the
/// proactive budget-threshold alerting in issue #170) against a real
/// gateway process rather than by reading the dispatch code.
#[allow(dead_code)]
pub fn spawn_webhook_capture_server() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/webhook", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_captured = Arc::clone(&captured);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_http_request(&mut stream);
            let Some(header_end) = find_header_end(request.as_bytes()) else {
                continue;
            };
            let body = &request.as_bytes()[header_end + 4..];
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                server_captured.lock().unwrap().push(value);
            }
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
            let _ = stream.write_all(response.as_bytes());
        }
    });

    (endpoint, captured)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = find_header_end(&request) {
            let content_length = parse_content_length(&request[..header_end]);
            let body_read = request.len().saturating_sub(header_end + 4);
            if body_read >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
                    .flatten()
            })
        })
        .unwrap_or(0)
}
