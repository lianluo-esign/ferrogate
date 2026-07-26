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

// ----- list pagination through the real binary -------------------------------

/// Spawn a loopback server that answers each request from `pages`, keyed by the
/// `offset` query parameter, so a multi-page walk is driven by the CLI's own
/// cursor arithmetic rather than by a fixed canned reply. An offset with no
/// scripted page yields an empty page, which would end the walk early and fail
/// the assertions below — the walk cannot pass by accident.
fn spawn_paged_http(pages: Vec<(u64, String)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let offset = request
                .split_whitespace()
                .nth(1)
                .and_then(|target| target.split('?').nth(1))
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("offset=")?.parse::<u64>().ok())
                })
                .unwrap_or(0);
            let body = pages
                .iter()
                .find(|(page_offset, _)| *page_offset == offset)
                .map(|(_, body)| body.clone())
                .unwrap_or_else(|| r#"{"object":"list","data":[],"total":0}"#.to_string());
            let response = http_response(200, "OK", &[("content-type", "application/json")], &body);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// `--all-pages` walks past the first server page and loses no rows. This is
/// the CLI-level proof that pagination is wired end to end — the pure
/// `next_page`/`plan_all_pages` unit tests exercise the arithmetic, this
/// exercises the binary that calls it.
#[test]
fn ctl_list_all_pages_walks_every_page_without_losing_rows() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_paged_http(vec![
        (
            0,
            r#"{"object":"list","data":[{"id":"vk-1"},{"id":"vk-2"}],"total":5}"#.to_string(),
        ),
        (
            2,
            r#"{"object":"list","data":[{"id":"vk-3"},{"id":"vk-4"}],"total":5}"#.to_string(),
        ),
        (
            4,
            r#"{"object":"list","data":[{"id":"vk-5"}],"total":5}"#.to_string(),
        ),
    ]);

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--all-pages",
            "--limit",
            "2",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim())
        .unwrap_or_else(|error| panic!("stdout must be JSON ({error}): {}", stdout(&output)));
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("merged items array")
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["vk-1", "vk-2", "vk-3", "vk-4", "vk-5"],
        "every page's rows must survive the merge"
    );
    assert_eq!(body["total"], 5);
    // A complete result never nags about --all-pages.
    assert!(
        !stderr(&output).contains("--all-pages"),
        "stderr: {}",
        stderr(&output)
    );
}

/// Without `--all-pages` a list still returns one server page — but it must say
/// so. A truncated page that looks complete is the failure mode the issue's
/// "without silently truncating results" bullet forbids.
#[test]
fn ctl_list_single_page_announces_the_remaining_rows() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_paged_http(vec![(
        0,
        r#"{"object":"list","data":[{"id":"vk-1"},{"id":"vk-2"}],"total":5}"#.to_string(),
    )]);

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--limit",
            "2",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    let diagnostics = stderr(&output);
    assert!(
        diagnostics.contains("showing 2 of 5") && diagnostics.contains("--all-pages"),
        "the operator must be told rows were left behind: {diagnostics}"
    );
    // The notice is a diagnostic, so a piped JSON payload stays clean.
    assert!(
        !stdout(&output).contains("note:"),
        "stdout must be data only"
    );
}

/// Table mode must show the envelope's `total`, otherwise a truncated page is
/// visually identical to a complete one in the default output format.
#[test]
fn ctl_list_table_shows_pagination_metadata() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_paged_http(vec![(
        0,
        r#"{"object":"list","data":[{"id":"vk-1"}],"total":500}"#.to_string(),
    )]);

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--limit",
            "1",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("ID") && out.contains("vk-1"), "{out}");
    assert!(
        out.contains("total") && out.contains("500"),
        "the row count must survive table rendering: {out}"
    );
}

/// `--sort` reaches the server verbatim, including the leading `-` descending
/// marker that clap would otherwise swallow as an unknown short flag.
#[test]
fn ctl_list_sort_flag_reaches_the_server() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let _ = sender.send(request);
            let response = http_response(
                200,
                "OK",
                &[("content-type", "application/json")],
                r#"{"object":"list","data":[],"total":0}"#,
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &format!("http://127.0.0.1:{port}"),
            "--sort",
            "tier",
            "--sort",
            "-created_at",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let request = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        request.contains("sort=tier"),
        "request line missing the primary sort key: {request}"
    );
    assert!(
        request.contains("sort=-created_at") || request.contains("sort=%2Dcreated_at"),
        "request line missing the descending sort key: {request}"
    );
}

/// A server error's structured `details` payload reaches the operator. The
/// transport decoded it from the start; nothing rendered it, so
/// `expected_version`-style payloads never reached a human.
#[test]
fn api_error_details_are_rendered_to_stderr() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        409,
        "Conflict",
        &[("content-type", "application/json")],
        r#"{"error":{"message":"version conflict","type":"ferrogate_error","code":"version_conflict","request_id":"rid-9","expected_version":3}}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 4, "409 is the not-found/conflict exit class");
    let diagnostics = stderr(&output);
    assert!(
        diagnostics.contains("details:") && diagnostics.contains("expected_version"),
        "structured error details must reach the operator: {diagnostics}"
    );
    assert!(
        diagnostics.contains("code: version_conflict") && diagnostics.contains("request-id: rid-9"),
        "{diagnostics}"
    );
}

/// A context CA bundle is honored by the client, not silently ignored: a
/// bundle that is not valid PEM fails the command with an actionable message
/// instead of quietly falling back to the system trust roots.
#[test]
fn context_ca_bundle_is_honored_not_ignored() {
    let home = tempfile::tempdir().unwrap();
    let bundle = home.path().join("not-a-bundle.pem");
    std::fs::write(&bundle, b"this is not a certificate").unwrap();
    let endpoint = spawn_http(http_response(200, "OK", &[], STATUS_BODY));

    let create = base_cmd(home.path())
        .args([
            "context",
            "create",
            "ca-ctx",
            "--endpoint",
            &endpoint,
            "--ca-bundle",
            bundle.to_str().unwrap(),
            "--use",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&create), 0, "stderr: {}", stderr(&create));

    // The bundle round-trips through the store and is shown back.
    let show = base_cmd(home.path())
        .args(["context", "show", "ca-ctx"])
        .output()
        .unwrap();
    assert!(
        stdout(&show).contains("ca_bundle") && stdout(&show).contains("not-a-bundle.pem"),
        "stdout: {}",
        stdout(&show)
    );

    let output = base_cmd(home.path())
        .args(["ops", "status", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        2,
        "an unusable CA bundle is a configuration error, not a silent fallback: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("CA bundle"),
        "the diagnostic must name the bundle: {}",
        stderr(&output)
    );
}

/// A private CA the operator configured is actually **trusted**, not merely
/// parsed.
///
/// The rejection test above proves an unusable bundle fails closed, but it
/// would stay green if `add_root_certificate` were replaced by a no-op after
/// the parse: nothing asserted the certificate reached the TLS trust store.
/// This closes that by serving a leaf signed by a freshly generated private CA
/// — a certificate the system roots cannot possibly validate — and requiring
/// the handshake to succeed with `--ca-bundle` and only with it.
#[test]
fn context_ca_bundle_is_actually_trusted_for_the_handshake() {
    let home = tempfile::tempdir().unwrap();
    let (ca_pem, port) = spawn_tls_signed_by_private_ca(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        STATUS_BODY,
    ));
    let bundle = home.path().join("private-ca.pem");
    std::fs::write(&bundle, ca_pem).unwrap();
    let endpoint = format!("https://localhost:{port}");

    // Control: without the bundle the leaf chains to an unknown root, so
    // verification fails. This is what makes the success below load-bearing.
    let untrusted = base_cmd(home.path())
        .args(["ops", "status", "--endpoint", &endpoint, "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&untrusted),
        6,
        "an unknown private CA must fail verification without the bundle: {}",
        stderr(&untrusted)
    );

    let create = base_cmd(home.path())
        .args([
            "context",
            "create",
            "private-ca",
            "--endpoint",
            &endpoint,
            "--ca-bundle",
            bundle.to_str().unwrap(),
            "--use",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&create), 0, "stderr: {}", stderr(&create));

    let trusted = base_cmd(home.path())
        .args(["ops", "status", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&trusted),
        0,
        "the configured CA must complete the handshake: {}",
        stderr(&trusted)
    );
    assert!(
        stdout(&trusted).contains("\"service\""),
        "stdout: {}",
        stdout(&trusted)
    );
}

/// Serve TLS with a leaf signed by a generated private CA. Returns the CA's PEM
/// (for `--ca-bundle`) and the port; connect with `https://localhost:PORT`.
fn spawn_tls_signed_by_private_ca(response: String) -> (String, u16) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrogate-cli-test-ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        leaf_key.serialize_der(),
    ));
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert.der().clone(), ca_cert.der().clone()], key)
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
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
    (ca_pem, port)
}

// ----- the ways --all-pages must refuse rather than mislead ------------------

/// **The blocker, through the real binary.** An empty page in the middle of a
/// collection the server says holds 5 rows must not produce 2 rows and exit 0.
///
/// The walk's stop conditions alone could not prevent this: `next_page` ends
/// iteration on any empty page, before consulting the known total, so a
/// concurrent delete (or a server filtering after paging) truncated the answer
/// silently — under the very flag whose purpose is to never truncate, and with
/// the truncation notice suppressed because `--all-pages` was passed.
#[test]
fn ctl_all_pages_fails_loudly_when_a_mid_collection_page_is_empty() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_paged_http(vec![
        (
            0,
            r#"{"object":"list","data":[{"id":"vk-1"},{"id":"vk-2"}],"total":5,"offset":0,"limit":2}"#
                .to_string(),
        ),
        (
            2,
            r#"{"object":"list","data":[],"total":5,"offset":2,"limit":2}"#.to_string(),
        ),
    ]);

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--all-pages",
            "--limit",
            "2",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_ne!(
        code(&output),
        0,
        "a truncated all-pages walk must not exit 0; stdout: {}",
        stdout(&output)
    );
    let diagnostics = stderr(&output);
    assert!(
        diagnostics.contains("fetched 2 of the 5 rows"),
        "the operator must be told the walk came up short: {diagnostics}"
    );
    // A partial payload must not be presented as the answer either.
    assert!(
        !stdout(&output).contains("vk-1"),
        "a short walk must not print rows as if complete: {}",
        stdout(&output)
    );
}

/// `--all-pages` on a destructive verb is refused **before** the request goes
/// out. The mock counts requests, so "nothing was sent" is measured, not
/// assumed: previously the DELETE was issued, the server deleted the project,
/// and only then did the CLI report "usage error" — the operator was told their
/// command was malformed after the damage was done.
#[test]
fn ctl_all_pages_on_a_mutating_verb_sends_nothing() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let _ = sender.send(String::from_utf8_lossy(&buffer[..read]).into_owned());
            let response = http_response(200, "OK", &[], r#"{"deleted":true}"#);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "projects",
            "delete",
            "proj-1",
            "--endpoint",
            &format!("http://127.0.0.1:{port}"),
            "--all-pages",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "--all-pages on a mutation is a usage error: {}",
        stderr(&output)
    );
    assert!(
        receiver.recv_timeout(Duration::from_millis(750)).is_err(),
        "the DELETE must never have reached the server"
    );
}

/// `--all-pages` on a cursor-paginated verb refuses after one page instead of
/// firing up to MAX_PAGES (10 000) identical requests. The mock counts the
/// requests it served, so the refusal is proven by the request count, not only
/// by the message.
#[test]
fn ctl_all_pages_on_a_cursor_endpoint_refuses_after_one_page() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel::<()>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = sender.send(());
            // A cursor page: no total, no usable offset — the server ignores
            // offset/limit entirely, so every request returns this same page.
            let response = http_response(
                200,
                "OK",
                &[("content-type", "application/json")],
                r#"{"object":"list","data":[{"id":"ev-1"}],"limit":1,"has_more":true,"next_after_event_id":"ev-1"}"#,
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "agent-jobs",
            "events",
            "job-1",
            "--endpoint",
            &format!("http://127.0.0.1:{port}"),
            "--all-pages",
            "--limit",
            "1",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "a cursor endpoint is a usage error under --all-pages: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("cursor-paginated"),
        "the rule must be stated, not implied: {}",
        stderr(&output)
    );
    let mut served = 0;
    while receiver.recv_timeout(Duration::from_millis(250)).is_ok() {
        served += 1;
    }
    assert_eq!(served, 1, "exactly one page may be fetched before refusing");
}

/// **The storm in its broad form, through the real binary.** An endpoint that
/// paginates by neither offset nor cursor carries no cursor marker, so the
/// cursor rule never sees it: it ignores `offset`/`limit` and hands back the
/// whole collection every time. A full page with no `total` made the walk
/// advance the offset forever — 10 000 requests at the operator's control plane
/// and every row buffered 10 000 times before the cap errored.
///
/// This is the majority shape of the contract, not an edge case: 43 of the 65
/// `list*` operations declare no `limit`/`offset` query parameter and echo no
/// `total`/`limit`/`offset` back, `listVirtualKeys` (used here) among them. It
/// stays invisible in a dev tenant whose collections fit in one page, which is
/// why it needed a fixture with exactly this shape — the suite had none, so the
/// page cap could be deleted outright with everything still green.
///
/// The mock serves the identical full page regardless of the `offset` asked
/// for, and counts what it served, so the refusal is proven by request count.
#[test]
fn ctl_all_pages_on_an_offset_blind_endpoint_refuses_after_one_page() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel::<()>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = sender.send(());
            // The offset in the request is ignored outright: no `total`, no
            // `offset`, no `limit` — just the same full page, every time.
            let response = http_response(
                200,
                "OK",
                &[("content-type", "application/json")],
                r#"{"object":"list","data":[{"id":"vk-1"},{"id":"vk-2"}]}"#,
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &format!("http://127.0.0.1:{port}"),
            "--all-pages",
            "--limit",
            "2",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "an endpoint with no page window is a usage error under --all-pages: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("echoes no offset, limit, or total"),
        "the rule must be stated, not implied: {}",
        stderr(&output)
    );
    // Refusing must not print a half-answer to stdout: a truncated list on
    // stdout with a diagnostic on stderr is what a piping operator misses.
    assert!(
        !stdout(&output).contains("vk-1"),
        "no rows may be printed for a refused walk: {}",
        stdout(&output)
    );
    let mut served = 0;
    while receiver.recv_timeout(Duration::from_millis(250)).is_ok() {
        served += 1;
    }
    assert_eq!(
        served, 1,
        "exactly one page may be fetched before refusing, not 10 000"
    );
}

/// `--sort` says out loud that the server does not honor it. Zero operations in
/// the OpenAPI contract declare a `sort` query parameter, so a flag advertised
/// on 200+ verb blocks that provably changes nothing is the ignored-field
/// anti-pattern wearing the server's clothes. The key is still forwarded
/// verbatim (a client must not fake a collection ordering from one page), but
/// the operator is told not to trust the order.
#[test]
fn ctl_list_sort_warns_that_the_api_does_not_honor_it() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"list","data":[],"total":0}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--sort",
            "-created_at",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("--sort") && stderr(&output).contains("sort"),
        "the operator must be warned the order is the server's default: {}",
        stderr(&output)
    );
    // The warning is a diagnostic; a piped JSON payload stays clean.
    assert!(!stdout(&output).contains("note:"), "{}", stdout(&output));

    // And a list WITHOUT --sort must not be nagged.
    let quiet = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        !stderr(&quiet).contains("--sort"),
        "stderr: {}",
        stderr(&quiet)
    );
}

/// A `--sort` value that swallowed the next flag is rejected instead of
/// silently sorting by "--output" and treating `json` as a resource id.
#[test]
fn ctl_list_sort_rejects_a_swallowed_flag() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            "http://127.0.0.1:1",
            "--sort",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 2, "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("--output"),
        "the diagnostic must name the swallowed flag: {}",
        stderr(&output)
    );
}

/// `--tenant` says out loud that the server does not act on it.
///
/// The flag is documented as "Override the tenant for this invocation" and
/// becomes an `x-ferrogate-tenant` header that **no** Control Plane API
/// operation declares — admin tenancy comes from the bearer token. So
/// `ctl virtual-keys list --tenant acme` exits 0 and returns whatever the
/// token's scope is: a wrong-tenant read presented as a scoped one. That is
/// worse than a dropped `ca_bundle_path`, because what is wrong is the
/// operator's belief about *whose data they are reading*.
///
/// Three existing tests pin only the sending side and would survive the
/// capability being entirely fictional. This one pins the diagnostic.
#[test]
fn ctl_tenant_flag_warns_that_the_api_does_not_honor_it() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"list","data":[],"total":0}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--tenant",
            "acme",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let diagnostics = stderr(&output);
    assert!(
        diagnostics.contains("x-ferrogate-tenant") && diagnostics.contains("bearer token"),
        "the operator must be told the tenant did not scope the read: {diagnostics}"
    );
    // And pointed at the selection that does work.
    assert!(diagnostics.contains("--filter tenant="), "{diagnostics}");
    // The note is a diagnostic; a piped JSON payload stays clean.
    assert!(!stdout(&output).contains("note:"), "{}", stdout(&output));

    // The same command WITHOUT a tenant must not be nagged — a note that fires
    // unconditionally is one operators learn to ignore.
    let quiet = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &endpoint,
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        !stderr(&quiet).contains("x-ferrogate-tenant"),
        "stderr: {}",
        stderr(&quiet)
    );
}

/// A context's `project`/`workspace` are recorded, shown by `context show`, and
/// never sent with any request — so an operator who set them is told, on the
/// invocation where it matters, rather than being left to assume the call was
/// scoped.
#[test]
fn ctl_context_project_and_workspace_are_announced_as_never_sent() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"list","data":[],"total":0}"#,
    ));

    let created = base_cmd(home.path())
        .args([
            "context",
            "create",
            "scoped",
            "--endpoint",
            &endpoint,
            "--project",
            "payments",
            "--workspace",
            "ws-1",
            "--use",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&created), 0, "stderr: {}", stderr(&created));

    let output = base_cmd(home.path())
        .args(["ctl", "virtual-keys", "list", "--output", "json"])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let diagnostics = stderr(&output);
    assert!(
        diagnostics.contains("project and workspace")
            && diagnostics.contains("not sent with any request"),
        "both fields must be reported as unsent: {diagnostics}"
    );
    assert!(!stdout(&output).contains("note:"), "{}", stdout(&output));
}

/// A server error that echoes key material is redacted on the way to stderr,
/// exactly as a success body is.
///
/// The transport forwards every unknown error-object key into `details`, and
/// `details` was printed verbatim — so a rejected virtual-key create echoing
/// the offending document put the live key on stderr in clear, while the same
/// field on the 200 path was blanked by `redact_response`. Redaction that
/// covers only the happy path is not redaction.
#[test]
fn ctl_error_details_do_not_leak_secret_fields() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = spawn_http(http_response(
        400,
        "Bad Request",
        &[("content-type", "application/json")],
        r#"{"error":{"message":"invalid virtual key document","type":"ferrogate_error","code":"invalid_request","request_id":"rid-leak","echo":{"key":"vk_live_LEAKED_SECRET","name":"broken"}}}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "create",
            "--endpoint",
            &endpoint,
            "--data",
            r#"{"name":"broken"}"#,
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 5, "400 is the validation exit class");
    let diagnostics = stderr(&output);
    assert!(
        !diagnostics.contains("vk_live_LEAKED_SECRET"),
        "key material must never reach stderr: {diagnostics}"
    );
    assert!(
        diagnostics.contains("<redacted>"),
        "the field must be shown as redacted, not dropped: {diagnostics}"
    );
    // The actionable half of the payload survives.
    assert!(
        diagnostics.contains("details:") && diagnostics.contains("broken"),
        "{diagnostics}"
    );
    assert!(!stdout(&output).contains("vk_live"), "{}", stdout(&output));
}
