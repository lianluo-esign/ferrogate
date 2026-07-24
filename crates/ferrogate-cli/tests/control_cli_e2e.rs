// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: End-to-end coverage for the #360 Control Plane API client slice
// wired into the `ferrogate` binary: runs the REAL CLI process against local
// mock HTTP/HTTPS servers and asserts the load-bearing product contracts —
// stable exit-code classes, table/JSON output on stdout, diagnostics on stderr,
// request-id surfacing, timeout and TLS-failure handling, wrong-scope behavior,
// precedence, version compatibility, and secret-free context management.
//
// These are hermetic (loopback sockets + a tempdir config home); no gateway,
// database, or network egress is required. The "real ferrogate-test scenario"
// acceptance box (durable/API-visible mutation + audit evidence through a live
// standalone Control Plane API) is deliberately NOT covered here — it is the
// test gate's job.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const STATUS_BODY: &str = concat!(
    "{\"service\":\"ferrogate\",\"version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\",\"runtime\":\"pingora\",\"snapshot\":\"snap-1\",",
    "\"providers\":2,\"enabled_providers\":2,\"models\":3,\"enabled_models\":3,",
    "\"routes\":1,\"enabled_routes\":1,\"upstreams\":1,\"enabled_upstreams\":1,",
    "\"api_keys\":1,\"tools\":0,\"auth_required\":true}"
);

// ----- process helpers -------------------------------------------------------

fn base_cmd(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrogate"));
    // Isolate from any FERROGATE_* the runner's environment may carry so the
    // precedence tests below control every input explicitly.
    for var in [
        "FERROGATE_ENDPOINT",
        "FERROGATE_CONTEXT",
        "FERROGATE_TENANT",
        "FERROGATE_TIMEOUT_MILLIS",
    ] {
        command.env_remove(var);
    }
    command.env("FERROGATE_CLI_HOME", home);
    command
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited via signal")
}

// ----- plain HTTP mock -------------------------------------------------------

fn http_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("Connection: close\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    response
}

/// Spawn a loopback server that replies with `response` to every connection.
/// Returns the `http://127.0.0.1:PORT` base URL. The thread is detached and
/// dies when the test process exits.
fn spawn_http(response: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            drain_request(&mut stream);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// Spawn a server that accepts, sleeps past any reasonable client timeout, then
/// (best-effort) replies — used to prove the client's timeout → Transport
/// exit-code mapping.
fn spawn_slow_http(response: String, delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            drain_request(&mut stream);
            thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn drain_request(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut buffer = [0_u8; 4096];
    let _ = stream.read(&mut buffer);
}

// ----- TLS mock --------------------------------------------------------------

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    )
}

/// Spawn a self-signed TLS server on loopback. Returns the port; connect with
/// `https://localhost:PORT`. Handshake/read errors are ignored so a client that
/// rejects the untrusted cert simply drops the connection.
fn spawn_tls(response: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = tls_server_config();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(connection) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(connection, stream);
            let mut buffer = [0_u8; 2048];
            let _ = tls.read(&mut buffer);
            let _ = tls.write_all(response.as_bytes());
            let _ = tls.flush();
        }
    });
    port
}

// ----- ops status: success + output ------------------------------------------

#[test]
fn ops_status_json_ok_surfaces_request_id() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        200,
        "OK",
        &[
            ("x-request-id", "rid-abc"),
            ("content-type", "application/json"),
        ],
        STATUS_BODY,
    ));

    let output = base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint, "--output", "json"])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim())
        .unwrap_or_else(|error| panic!("stdout must be JSON ({error}): {}", stdout(&output)));
    assert_eq!(body["service"], "ferrogate");
    assert_eq!(body["runtime"], "pingora");
    // Correlation id is a diagnostic → stderr, never mixed into the JSON payload.
    assert!(
        stderr(&output).contains("request-id: rid-abc"),
        "request-id must be surfaced on stderr: {}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("request-id"),
        "stdout must carry data only"
    );
}

#[test]
fn ops_status_table_ok() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(200, "OK", &[], STATUS_BODY));

    let output = base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("FIELD") && out.contains("VALUE"),
        "table header: {out}"
    );
    assert!(
        out.contains("service") && out.contains("ferrogate"),
        "table body: {out}"
    );
    assert!(
        out.contains("runtime") && out.contains("pingora"),
        "table body: {out}"
    );
}

// ----- exit-code classes -----------------------------------------------------

fn run_status_against_error(status: u16, reason: &str, body: &str) -> Output {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        status,
        reason,
        &[("content-type", "application/json")],
        body,
    ));
    base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint, "--output", "json"])
        .output()
        .unwrap()
}

#[test]
fn wrong_scope_403_maps_to_auth_exit_class() {
    let output = run_status_against_error(
        403,
        "Forbidden",
        r#"{"error":{"message":"admin.read scope required","type":"ferrogate_error","code":"forbidden","request_id":"rid-403"}}"#,
    );
    assert_eq!(code(&output), 3, "403 → Auth (exit 3): {}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("admin.read scope required"), "message: {err}");
    assert!(
        err.contains("code: forbidden"),
        "error code surfaced: {err}"
    );
    assert!(
        err.contains("request-id: rid-403"),
        "request id surfaced: {err}"
    );
    assert!(
        stdout(&output).trim().is_empty(),
        "no data on stdout for a failure"
    );
}

#[test]
fn not_found_404_maps_to_not_found_exit_class() {
    let output = run_status_against_error(
        404,
        "Not Found",
        r#"{"error":{"message":"no such resource","type":"ferrogate_error","code":"not_found"}}"#,
    );
    assert_eq!(
        code(&output),
        4,
        "404 → NotFoundConflict (exit 4): {}",
        stderr(&output)
    );
}

#[test]
fn validation_400_maps_to_validation_exit_class() {
    let output = run_status_against_error(
        400,
        "Bad Request",
        r#"{"error":{"message":"bad input","type":"ferrogate_error","code":"invalid_request"}}"#,
    );
    assert_eq!(
        code(&output),
        5,
        "400 → Validation (exit 5): {}",
        stderr(&output)
    );
}

#[test]
fn server_500_maps_to_server_exit_class() {
    let output = run_status_against_error(
        500,
        "Internal Server Error",
        r#"{"error":{"message":"boom","type":"ferrogate_error","code":"server_error"}}"#,
    );
    assert_eq!(
        code(&output),
        7,
        "500 → Server (exit 7): {}",
        stderr(&output)
    );
}

#[test]
fn timeout_maps_to_transport_exit_class() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_slow_http(
        http_response(200, "OK", &[], STATUS_BODY),
        Duration::from_secs(5),
    );
    let output = base_cmd(home.path())
        .args([
            "ops",
            "status",
            "--endpoint",
            &endpoint,
            "--timeout-millis",
            "300",
        ])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        6,
        "timeout → Transport (exit 6): {}",
        stderr(&output)
    );
}

// ----- TLS -------------------------------------------------------------------

#[test]
fn tls_verification_failure_maps_to_transport_exit_class() {
    let port = spawn_tls(http_response(200, "OK", &[], STATUS_BODY));
    let home = tempfile::tempdir().unwrap();
    let endpoint = format!("https://localhost:{port}");
    let output = base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint])
        .output()
        .unwrap();
    // Untrusted self-signed cert, verification on → no authoritative answer.
    assert_eq!(
        code(&output),
        6,
        "TLS failure → Transport (exit 6): {}",
        stderr(&output)
    );
}

#[test]
fn tls_skip_verify_context_succeeds() {
    let port = spawn_tls(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        STATUS_BODY,
    ));
    let home = tempfile::tempdir().unwrap();
    let endpoint = format!("https://localhost:{port}");

    let create = base_cmd(home.path())
        .args([
            "context",
            "create",
            "tls",
            "--endpoint",
            &endpoint,
            "--insecure-skip-tls-verify",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&create), 0, "context create: {}", stderr(&create));

    let output = base_cmd(home.path())
        .args(["ops", "status", "--context", "tls", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        0,
        "skip-verify context should connect: {}",
        stderr(&output)
    );
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(body["service"], "ferrogate");
}

// ----- version compatibility -------------------------------------------------

#[test]
fn incompatible_server_version_fails_closed() {
    let home = tempfile::tempdir().unwrap();
    // Older than MIN_SUPPORTED_API_VERSION (2026.6.0).
    let old_body = r#"{"service":"ferrogate","version":"2026.5.0","runtime":"pingora"}"#;
    let endpoint = spawn_http(http_response(200, "OK", &[], old_body));
    let output = base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        2,
        "old server → Usage (exit 2): {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("older than the minimum supported"),
        "actionable compat message: {}",
        stderr(&output)
    );
}

// ----- precedence ------------------------------------------------------------

#[test]
fn endpoint_flag_beats_env() {
    let home = tempfile::tempdir().unwrap();
    let good = spawn_http(http_response(200, "OK", &[], STATUS_BODY));
    let output = base_cmd(home.path())
        // env points at a dead port; the flag must win and succeed.
        .env("FERROGATE_ENDPOINT", "http://127.0.0.1:1")
        .args(["ops", "status", "--endpoint", &good, "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        0,
        "explicit --endpoint flag must beat FERROGATE_ENDPOINT: {}",
        stderr(&output)
    );
}

#[test]
fn env_endpoint_beats_context() {
    let home = tempfile::tempdir().unwrap();
    let good = spawn_http(http_response(200, "OK", &[], STATUS_BODY));

    // Context endpoint points at a dead port.
    let create = base_cmd(home.path())
        .args([
            "context",
            "create",
            "p",
            "--endpoint",
            "http://127.0.0.1:1",
            "--use",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&create), 0, "context create: {}", stderr(&create));

    let output = base_cmd(home.path())
        .env("FERROGATE_ENDPOINT", &good)
        .args(["ops", "status", "--context", "p", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        0,
        "FERROGATE_ENDPOINT env must beat the context endpoint: {}",
        stderr(&output)
    );
}

// ----- context management: no secret ever printed ----------------------------

#[test]
fn context_crud_never_prints_secrets() {
    let home = tempfile::tempdir().unwrap();
    let secret = "super-secret-token-value";

    let create = base_cmd(home.path())
        .env("PROD_TOKEN", secret)
        .args([
            "context",
            "create",
            "prod",
            "--endpoint",
            "https://control.example.com",
            "--tenant",
            "acme",
            "--token-env",
            "PROD_TOKEN",
            "--use",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&create), 0, "create: {}", stderr(&create));
    assert_no_secret(&create, secret);
    assert!(
        stderr(&create).contains("env:PROD_TOKEN"),
        "create reports the credential source: {}",
        stderr(&create)
    );

    let list = base_cmd(home.path())
        .env("PROD_TOKEN", secret)
        .args(["context", "list"])
        .output()
        .unwrap();
    assert_eq!(code(&list), 0, "list: {}", stderr(&list));
    assert_no_secret(&list, secret);
    let list_out = stdout(&list);
    assert!(
        list_out.contains("prod"),
        "list shows the context: {list_out}"
    );
    assert!(
        list_out.contains("env:PROD_TOKEN"),
        "list shows the source: {list_out}"
    );
    assert!(
        list_out.contains('*'),
        "list marks the current context: {list_out}"
    );

    let show = base_cmd(home.path())
        .env("PROD_TOKEN", secret)
        .args(["context", "show", "prod"])
        .output()
        .unwrap();
    assert_eq!(code(&show), 0, "show: {}", stderr(&show));
    assert_no_secret(&show, secret);
    let show_out = stdout(&show);
    assert!(
        show_out.contains("https://control.example.com"),
        "show endpoint: {show_out}"
    );
    assert!(
        show_out.contains("env:PROD_TOKEN"),
        "show source: {show_out}"
    );

    // The on-disk store must not contain the secret value either.
    let store_text = std::fs::read_to_string(home.path().join("contexts.toml")).unwrap_or_default();
    assert!(
        !store_text.contains(secret),
        "store file leaked the secret: {store_text}"
    );
    assert!(
        store_text.contains("PROD_TOKEN"),
        "store keeps the source var name"
    );

    let delete = base_cmd(home.path())
        .args(["context", "delete", "prod"])
        .output()
        .unwrap();
    assert_eq!(code(&delete), 0, "delete: {}", stderr(&delete));

    let show_gone = base_cmd(home.path())
        .args(["context", "show", "prod"])
        .output()
        .unwrap();
    assert_eq!(
        code(&show_gone),
        2,
        "showing a deleted context is a usage error"
    );
}

fn assert_no_secret(output: &Output, secret: &str) {
    assert!(
        !stdout(output).contains(secret),
        "secret leaked to stdout: {}",
        stdout(output)
    );
    assert!(
        !stderr(output).contains(secret),
        "secret leaked to stderr: {}",
        stderr(output)
    );
}
