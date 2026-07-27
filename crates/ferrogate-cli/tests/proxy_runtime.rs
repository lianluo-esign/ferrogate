// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

// Pingora's inherited-listener transfer is implemented only on Linux.
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::fd::AsRawFd,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

use pingora::server::Fds;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const OPENSSL_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

// This target predates `support` and keeps its own helpers; it is pulled in
// only for the #568 death-signal arming below.
#[allow(dead_code)]
mod support;

/// Pre-armed so a gateway started here dies with its test even when the test
/// panics past the `kill()` line or the harness is SIGKILLed (#568). The
/// `GatewayProcess` guard below still runs on the ordinary path; this covers the
/// paths that run no destructor at all.
fn ferrogate() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrogate"));
    support::reap_with_test(&mut command);
    command
}

struct ListenerReservation {
    listener: TcpListener,
    addr: String,
}

impl ListenerReservation {
    fn reserve() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        Self { listener, addr }
    }

    fn addr(&self) -> &str {
        &self.addr
    }
}

struct GatewayProcess {
    child: Child,
    output: tempfile::NamedTempFile,
}

impl GatewayProcess {
    fn output_snapshot(&self) -> String {
        std::fs::read_to_string(self.output.path()).unwrap_or_default()
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn start_gateway(config: &Path, reservation: ListenerReservation) -> GatewayProcess {
    let upgrade_sock = configure_listener_transfer(config);
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_writer = output.reopen().unwrap();
    let child = ferrogate()
        .args(["run", "--config", config.to_str().unwrap(), "--upgrade"])
        .stdout(Stdio::from(output_writer.try_clone().unwrap()))
        .stderr(Stdio::from(output_writer))
        .spawn()
        .unwrap();
    let mut gateway = GatewayProcess { child, output };
    wait_for_upgrade_socket(&mut gateway, &upgrade_sock);

    let mut inherited = Fds::new();
    inherited.add(
        reservation.addr().to_string(),
        reservation.listener.as_raw_fd(),
    );
    inherited
        .send_to_sock(upgrade_sock.to_str().unwrap())
        .unwrap_or_else(|error| {
            panic!(
                "failed to transfer reserved listener {} to gateway: {error}\n{}",
                reservation.addr(),
                gateway.output_snapshot()
            )
        });

    drop(reservation.listener);
    gateway
}

fn wait_for_upgrade_socket(gateway: &mut GatewayProcess, upgrade_sock: &Path) {
    let started = Instant::now();
    loop {
        if std::fs::metadata(upgrade_sock).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            return;
        }
        if let Some(status) = gateway.child.try_wait().unwrap() {
            panic!(
                "gateway exited before opening listener transfer socket {}: {status}\n{}",
                upgrade_sock.display(),
                gateway.output_snapshot()
            );
        }
        if started.elapsed() >= STARTUP_TIMEOUT {
            panic!(
                "gateway did not open listener transfer socket {}\n{}",
                upgrade_sock.display(),
                gateway.output_snapshot()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn configure_listener_transfer(config: &Path) -> PathBuf {
    let upgrade_sock = config.with_file_name("proxy-runtime-upgrade.sock");
    let source = std::fs::read_to_string(config).unwrap();
    let mut document = source.parse::<toml::Value>().unwrap();
    let root = document.as_table_mut().unwrap();
    let reliability = root
        .entry("reliability")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .unwrap();
    reliability.insert(
        "graceful_upgrade_sock".to_string(),
        toml::Value::String(upgrade_sock.to_string_lossy().into_owned()),
    );
    std::fs::write(config, toml::to_string(&document).unwrap()).unwrap();
    upgrade_sock
}

fn wait_for_gateway(gateway: &mut GatewayProcess, addr: &str) {
    let started = Instant::now();
    let mut last_response = None;
    while started.elapsed() < STARTUP_TIMEOUT {
        if let Some(status) = gateway.child.try_wait().unwrap() {
            panic!(
                "gateway exited before becoming ready at {addr}: {status}\n{}",
                gateway.output_snapshot()
            );
        }
        if let Ok(response) = gateway_health(addr) {
            if is_healthy_response(&response) {
                return;
            }
            last_response = Some(response);
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "gateway did not become ready at {addr}; last response: {:?}\n{}",
        last_response,
        gateway.output_snapshot()
    );
}

fn gateway_health(addr: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn is_healthy_response(response: &str) -> bool {
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    let mut status = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    if status.next() != Some("HTTP/1.1") || status.next() != Some("200") {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|document| {
            document.get("status").and_then(serde_json::Value::as_str) == Some("ok")
        })
}

fn wait_for_tls_gateway(gateway: &mut GatewayProcess, addr: &str, host: &str) -> String {
    let started = Instant::now();
    let mut last_response = None;
    while started.elapsed() < STARTUP_TIMEOUT {
        if let Some(status) = gateway.child.try_wait().unwrap() {
            panic!(
                "TLS gateway exited before becoming ready at {addr}: {status}\n{}",
                gateway.output_snapshot()
            );
        }
        if let Some(response) = https_get_with_openssl(addr, "/healthz", host) {
            if is_healthy_response(&response) {
                return response;
            }
            last_response = Some(response);
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "TLS gateway did not become ready at {addr}; last response: {:?}\n{}",
        last_response,
        gateway.output_snapshot()
    );
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

fn http_get_with_headers(addr: &str, path: &str, host: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
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

    if !write_https_probe(&mut child, path, host) {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().ok()?;
                return Some(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(None) if started.elapsed() < OPENSSL_REQUEST_TIMEOUT => {
                thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn write_https_probe(child: &mut Child, path: &str, host: &str) -> bool {
    let Some(mut stdin) = child.stdin.take() else {
        return false;
    };
    write_https_probe_request(&mut stdin, path, host)
}

fn write_https_probe_request(output: &mut impl Write, path: &str, host: &str) -> bool {
    write!(
        output,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .is_ok()
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
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
    let (upstream_addr, upstream_handle) = spawn_echo_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

# #542: a pure L7 reverse-proxy deployment has no credentials of any
# kind and is open by design. Since #542 that posture is named rather
# than inherited from an empty [[api_keys]] section, and a config with
# no credential source refuses to start without it.
[auth]
disabled = true

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

    let mut gateway = start_gateway(&config, gateway_listener);
    wait_for_gateway(&mut gateway, &gateway_addr);

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

    gateway.shutdown();
    let upstream_request = upstream_handle.join().unwrap();
    assert!(upstream_request.contains("x-forwarded-host: example.test"));
    assert!(upstream_request
        .to_ascii_lowercase()
        .contains("x-ferrogate-trace-id: fg-"));
}

#[test]
fn reverse_proxy_accepts_traceparent_and_preserves_trace_headers() {
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
    let (upstream_addr, upstream_handle) = spawn_echo_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

# #542: a pure L7 reverse-proxy deployment has no credentials of any
# kind and is open by design. Since #542 that posture is named rather
# than inherited from an empty [[api_keys]] section, and a config with
# no credential source refuses to start without it.
[auth]
disabled = true

[[upstreams]]
name = "echo"
url = "http://{upstream_addr}"

[[routes]]
name = "echo"
upstream = "echo"
hosts = ["example.test"]
path_prefixes = ["/proxy"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config, gateway_listener);
    wait_for_gateway(&mut gateway, &gateway_addr);

    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let response = http_get_with_headers(
        &gateway_addr,
        "/proxy/get",
        "example.test",
        &[
            ("traceparent", traceparent),
            ("tracestate", "token4ai=ingress"),
        ],
    );
    assert!(response.contains("200 OK"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-trace-id: 4bf92f3577b34da6a3ce929d0e0e4736"),
        "{response}"
    );

    gateway.shutdown();
    let upstream_request = upstream_handle.join().unwrap().to_ascii_lowercase();
    assert!(upstream_request.contains(&format!("traceparent: {traceparent}")));
    assert!(upstream_request.contains("tracestate: token4ai=ingress"));
    assert!(upstream_request.contains("x-ferrogate-trace-id: 4bf92f3577b34da6a3ce929d0e0e4736"));
}

#[test]
fn proxied_response_body_is_not_fully_buffered_before_downstream_write() {
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
    let (upstream_addr, upstream_handle) = spawn_streaming_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

# #542: a pure L7 reverse-proxy deployment has no credentials of any
# kind and is open by design. Since #542 that posture is named rather
# than inherited from an empty [[api_keys]] section, and a config with
# no credential source refuses to start without it.
[auth]
disabled = true

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

    let mut gateway = start_gateway(&config, gateway_listener);
    wait_for_gateway(&mut gateway, &gateway_addr);

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

    gateway.shutdown();
    upstream_handle.join().unwrap();
}

#[test]
fn tls_listener_serves_healthz_when_certificate_is_configured() {
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
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

# #542: a pure L7 reverse-proxy deployment has no credentials of any
# kind and is open by design. Since #542 that posture is named rather
# than inherited from an empty [[api_keys]] section, and a config with
# no credential source refuses to start without it.
[auth]
disabled = true

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

    let mut child = start_gateway(&config, gateway_listener);
    let response = wait_for_tls_gateway(&mut child, &gateway_addr, "localhost");
    assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("ok"), "{response}");

    child.shutdown();
}

#[test]
fn inherited_listener_has_no_rebind_window() {
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
    assert_eq!(
        TcpListener::bind(&gateway_addr).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    let contender_ready = Arc::new(Barrier::new(2));
    let contender_stop = Arc::new(AtomicBool::new(false));
    let contender_acquired = Arc::new(AtomicBool::new(false));
    let contender_attempts = Arc::new(AtomicUsize::new(0));
    let contender_addr = gateway_addr.clone();
    let contender = {
        let ready = Arc::clone(&contender_ready);
        let stop = Arc::clone(&contender_stop);
        let acquired = Arc::clone(&contender_acquired);
        let attempts = Arc::clone(&contender_attempts);
        thread::spawn(move || {
            ready.wait();
            while !stop.load(Ordering::Acquire) {
                attempts.fetch_add(1, Ordering::Release);
                match TcpListener::bind(&contender_addr) {
                    Ok(listener) => {
                        acquired.store(true, Ordering::Release);
                        while !stop.load(Ordering::Acquire) {
                            thread::yield_now();
                        }
                        drop(listener);
                        return;
                    }
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse),
                }
                thread::yield_now();
            }
        })
    };
    contender_ready.wait();
    while contender_attempts.load(Ordering::Acquire) == 0 {
        thread::yield_now();
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        // #542: no credential source, so the open posture is stated by name.
        format!("listen = \"{gateway_addr}\"\n\n[auth]\ndisabled = true\n"),
    )
    .unwrap();

    let mut gateway = start_gateway(&config, gateway_listener);
    contender_stop.store(true, Ordering::Release);
    contender.join().unwrap();
    assert!(
        !contender_acquired.load(Ordering::Acquire),
        "a competing bind acquired the listener during descriptor transfer"
    );
    assert_eq!(
        TcpListener::bind(&gateway_addr).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse,
        "the listener must remain owned after the parent transfers and closes its descriptor"
    );
    wait_for_gateway(&mut gateway, &gateway_addr);
    let response = gateway_health(&gateway_addr).unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("\"status\":\"ok\""), "{response}");
    gateway.shutdown();
}

/// #542, at the process boundary: the config every other test in this file
/// used to write -- a bare `listen` with no credential source of any kind --
/// no longer starts a gateway.
///
/// It is the deployment the issue is about. Until #542, `ferrogate run` on this
/// file bound a listener whose `authenticate()` admitted every request, with no
/// credential presented, carrying the wildcard scope and `platform_operator:
/// true`; a virtual key minted into the control plane changed nothing, because
/// the predicate that decided it counted `[[api_keys]]` only. The gateway now
/// refuses to start and the error names the switch, so an operator who wants
/// the open posture gets it by asking, and one who does not gets told.
///
/// Delete the startup gate in `gateway::serve` and this goes red: the process
/// binds and stays up instead of exiting with the message.
#[test]
fn a_gateway_with_no_credential_source_refuses_to_start_and_names_the_switch() {
    let gateway_listener = ListenerReservation::reserve();
    let gateway_addr = gateway_listener.addr().to_string();
    drop(gateway_listener);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, format!("listen = \"{gateway_addr}\"\n")).unwrap();

    let output = ferrogate()
        .args(["run", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "an implicitly-open gateway must not start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no credential source"),
        "unexpected startup error: {stderr}"
    );
    assert!(
        stderr.contains("[auth]") && stderr.contains("disabled = true"),
        "the error must name the switch so the operator can act on it: {stderr}"
    );
    assert!(
        TcpStream::connect(&gateway_addr).is_err(),
        "nothing may be listening after a refused startup"
    );
}

#[test]
fn readiness_requires_successful_health_json() {
    assert!(is_healthy_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"
    ));
    assert!(!is_healthy_response(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"
    ));
    assert!(!is_healthy_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"status\":\"error\"}"
    ));
    assert!(!is_healthy_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    ));
}

#[test]
fn https_probe_treats_broken_pipe_as_not_ready() {
    let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    assert!(!write_https_probe_request(
        &mut writer,
        "/healthz",
        "localhost"
    ));
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
