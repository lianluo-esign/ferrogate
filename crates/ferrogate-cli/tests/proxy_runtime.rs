// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn ferrogate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn start_gateway(config: &std::path::Path) -> Child {
    ferrogate()
        .args(["run", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_gateway(addr: &str) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
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

fn wait_for_tcp_listener(addr: &str) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway did not open TCP listener at {addr}");
}

fn http_get(addr: &str, path: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn https_get_with_openssl(addr: &str, path: &str, host: &str) -> Option<String> {
    let mut child = Command::new("openssl")
        .args(["s_client", "-connect", addr, "-servername", host, "-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    {
        let mut stdin = child.stdin.take().unwrap();
        write!(
            stdin,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    }

    let output = child.wait_with_output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn spawn_echo_upstream() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.push_str(&String::from_utf8_lossy(&buffer[..read]));
            if request.contains("\r\n\r\n") {
                break;
            }
        }
        let body = format!("seen-request:\n{request}");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

fn spawn_streaming_upstream() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
            )
            .unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(500));
        stream.write_all(b"6\r\n world\r\n0\r\n\r\n").unwrap();
    });
    (addr, handle)
}

#[test]
fn healthz_and_reverse_proxy_vertical_slice_work() {
    let gateway_addr = free_addr();
    let (upstream_addr, upstream_handle) = spawn_echo_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[upstreams]]
name = "echo"
url = "http://{upstream_addr}/base"

[[routes]]
name = "echo"
upstream = "echo"
hosts = ["example.test"]
path_prefixes = ["/proxy"]
strip_prefix = "/proxy"

[[routes.request_headers]]
name = "x-ferrogate-route"
value = "echo"

[[routes.request_headers]]
name = "x-ferrogate-secret"
value = "{{env.FERROGATE_PROXY_TEST_SECRET}}"

[[routes.response_headers]]
name = "x-ferrogate-response"
value = "proxied"
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROXY_TEST_SECRET", "resolved-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let health = http_get(&gateway_addr, "/healthz", "localhost");
    assert!(health.contains("200 OK"));
    assert!(health.contains("\"status\":\"ok\""));
    assert!(health.contains("x-request-id"));
    assert!(health.contains("x-trace-id"));

    let admin = http_get(&gateway_addr, "/admin/status", "localhost");
    assert!(admin.contains("200 OK"));
    assert!(admin.contains("\"snapshot\":\""));
    assert!(admin.contains("\"runtime\":\"pingora\""));

    let metrics = http_get(&gateway_addr, "/metrics", "localhost");
    let normalized_metrics = metrics.to_ascii_lowercase();
    assert!(metrics.contains("200 OK"));
    assert!(normalized_metrics.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(normalized_metrics.contains("x-trace-id"));
    assert!(metrics.contains("# TYPE ferrogate_request_logs_total counter"));
    assert!(metrics.contains("ferrogate_billing_events_total 0"));

    let response = http_get(&gateway_addr, "/proxy/get?x=1", "example.test");
    let normalized_response = response.to_ascii_lowercase();
    assert!(response.contains("200 OK"));
    assert!(response.contains("GET /base/get?x=1 HTTP/1.1"));
    assert!(normalized_response.contains("host: 127.0.0.1:"));
    assert!(normalized_response.contains("x-ferrogate-route: echo"));
    assert!(normalized_response.contains("x-ferrogate-secret: resolved-secret"));
    assert!(!normalized_response.contains("{env.ferrogate_proxy_test_secret}"));
    assert!(normalized_response.contains("x-ferrogate-response: proxied"));
    assert!(normalized_response.contains("x-request-id"));
    assert!(normalized_response.contains("x-trace-id"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let upstream_request = upstream_handle.join().unwrap();
    assert!(upstream_request.contains("x-forwarded-host: example.test"));
    assert!(upstream_request
        .to_ascii_lowercase()
        .contains("x-ferrogate-trace-id: fg-"));
}

#[test]
fn proxied_response_body_is_not_fully_buffered_before_downstream_write() {
    let gateway_addr = free_addr();
    let (upstream_addr, upstream_handle) = spawn_streaming_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[upstreams]]
name = "stream"
url = "http://{upstream_addr}"

[[routes]]
name = "stream"
upstream = "stream"
path_prefixes = ["/stream"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let mut stream = TcpStream::connect(&gateway_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();

    let started = Instant::now();
    let mut response = Vec::new();
    while !String::from_utf8_lossy(&response).contains("hello") {
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).unwrap();
        assert_ne!(read, 0, "connection closed before first streamed chunk");
        response.extend_from_slice(&byte[..read]);
    }

    assert!(
        started.elapsed() < Duration::from_millis(400),
        "gateway buffered the first upstream body chunk until the delayed chunk was ready"
    );

    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    response.extend_from_slice(&rest);
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("hello"));
    assert!(response.contains(" world"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    upstream_handle.join().unwrap();
}

#[test]
fn tls_listener_serves_healthz_when_certificate_is_configured() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    if !write_self_signed_test_certificate(&cert, &key) {
        return;
    }

    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[tls]
enabled = true
cert_path = "{}"
key_path = "{}"
"#,
            cert.display(),
            key.display()
        ),
    )
    .unwrap();

    let mut child = start_gateway(&config);
    wait_for_tcp_listener(&gateway_addr);

    let response = https_get_with_openssl(&gateway_addr, "/healthz", "localhost")
        .expect("openssl should be available after certificate generation");
    assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("ok"), "{response}");

    child.kill().ok();
    child.wait().ok();
}

fn write_self_signed_test_certificate(cert: &std::path::Path, key: &std::path::Path) -> bool {
    let Ok(status) = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    else {
        return false;
    };
    status.success()
}
