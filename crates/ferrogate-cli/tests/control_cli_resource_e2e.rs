// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: End-to-end coverage for the #361–#365 Control Plane API resource
// command families wired into the `ferrogate` binary via the generic `ctl`
// dispatch. Runs the REAL CLI process against a local mock HTTP server and
// asserts the load-bearing product contracts: the metadata-driven tree reaches
// each family, dispatches the correct HTTP method + path, renders table/JSON on
// stdout with diagnostics on stderr, maps errors onto the stable exit-class,
// and redacts one-time key material on reads.
//
// Hermetic (loopback socket + a tempdir config home); no gateway, database, or
// network egress. The "real ferrogate-test scenario" acceptance (durable /
// API-visible mutation + audit evidence through a live standalone Control Plane
// API) is deliberately NOT covered here — it is the test gate's job.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ----- process helpers -------------------------------------------------------

fn base_cmd(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrogate"));
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

// ----- capturing HTTP mock ---------------------------------------------------

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

/// A loopback server that records the request line (`METHOD PATH`) of every
/// connection and replies with a fixed response. Returns the base URL plus a
/// handle to the captured request lines, so a test can assert the generic
/// dispatch built the right method + path.
struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn last_request(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn spawn_mock(response: String) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if let Some(line) = read_request_line(&mut stream) {
                sink.lock().unwrap().push(line);
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    MockServer {
        base_url: format!("http://127.0.0.1:{port}"),
        requests,
    }
}

/// Read the first request line, e.g. `GET /admin/v1/virtual-keys/vk-1 HTTP/1.1`,
/// and return the `METHOD PATH` portion.
fn read_request_line(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer).ok()?;
    let text = String::from_utf8_lossy(&buffer[..read]);
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some(format!("{method} {path}"))
}

// ----- #361 IAM: list JSON round trip + captured request ---------------------

#[test]
fn iam_virtual_keys_list_json_round_trip() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[
            ("x-request-id", "rid-vk-list"),
            ("content-type", "application/json"),
        ],
        r#"[{"id":"vk-1","label":"prod"},{"id":"vk-2","label":"dev"}]"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    // Generic dispatch built the right method + collection path.
    assert_eq!(mock.last_request(), "GET /admin/v1/virtual-keys");
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim())
        .unwrap_or_else(|error| panic!("stdout must be JSON ({error}): {}", stdout(&output)));
    assert_eq!(body[0]["id"], "vk-1");
    assert_eq!(body[1]["label"], "dev");
    // Correlation id → stderr only.
    assert!(
        stderr(&output).contains("request-id: rid-vk-list"),
        "request-id on stderr: {}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("request-id"),
        "stdout is data-only"
    );
}

// ----- #361 IAM: secret redaction on a read ----------------------------------

#[test]
fn iam_virtual_keys_list_redacts_secret_material() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"[{"id":"vk-1","key":"sk-LEAK-1","secret":"SHH-1"},{"id":"vk-2","key":"sk-LEAK-2"}]"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "list",
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        !out.contains("sk-LEAK-1") && !out.contains("sk-LEAK-2") && !out.contains("SHH-1"),
        "a read must not surface key material: {out}"
    );
    assert!(
        out.contains("<redacted>"),
        "secret fields are blanked: {out}"
    );
    assert!(out.contains("vk-1"), "non-secret fields survive: {out}");
}

#[test]
fn iam_virtual_keys_get_redacts_secret_material() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"id":"vk-1","label":"prod","key":"sk-LEAK","secret":"SHH-LEAK"}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "get",
            "vk-1",
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "GET /admin/v1/virtual-keys/vk-1");
    let out = stdout(&output);
    assert!(
        !out.contains("sk-LEAK") && !out.contains("SHH-LEAK"),
        "no leak: {out}"
    );
    assert!(out.contains("<redacted>"), "blanked: {out}");
    assert!(out.contains("prod"), "label survives: {out}");
}

// ----- #361 IAM: create surfaces the one-time secret (mutation, not redacted) -

#[test]
fn iam_virtual_keys_create_surfaces_one_time_secret() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        201,
        "Created",
        &[("content-type", "application/json")],
        r#"{"id":"vk-new","key":"sk-ONE-TIME-abc","label":"ci"}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "create",
            "--data",
            r#"{"label":"ci"}"#,
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "POST /admin/v1/virtual-keys");
    let out = stdout(&output);
    assert!(
        out.contains("sk-ONE-TIME-abc"),
        "a create response must surface the one-time secret once: {out}"
    );
    assert!(
        !out.contains("<redacted>"),
        "the mutation response is not redacted: {out}"
    );
    // Since #505 a mutating verb's stdout is a decision receipt, and the
    // server's document — including the one-time secret — is nested under
    // `response`. Pinned here so the secret cannot quietly move (or vanish)
    // behind the envelope.
    let receipt: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(receipt["object"], "mutation_receipt", "{out}");
    assert_eq!(receipt["response"]["key"], "sk-ONE-TIME-abc", "{out}");
}

// ----- #362 agent/mcp: create round trip + table list ------------------------

#[test]
fn agent_mcp_servers_create_round_trip() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        201,
        "Created",
        &[("content-type", "application/json")],
        r#"{"id":"mcp-1","name":"srv","status":"active"}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "mcp-servers",
            "create",
            "--data",
            r#"{"name":"srv"}"#,
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "POST /admin/v1/mcp-servers");
    // `create` is a mutating verb, so since #505 stdout is the decision receipt
    // and the created object lives under `response` — asserting `body["id"]`
    // directly (as this test did before the refactor) reads a null.
    let receipt: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(receipt["object"], "mutation_receipt", "{receipt}");
    assert_eq!(receipt["verb"], "create", "{receipt}");
    assert_eq!(receipt["target"]["method"], "POST", "{receipt}");
    assert_eq!(receipt["response"]["id"], "mcp-1", "{receipt}");
    assert_eq!(receipt["response"]["status"], "active", "{receipt}");
}

#[test]
fn agent_workflows_list_table_output() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"[{"id":"wf-1","name":"nightly"},{"id":"wf-2","name":"hourly"}]"#,
    ));

    // No --output flag → default table rendering.
    let output = base_cmd(home.path())
        .args([
            "ctl",
            "agent-workflows",
            "list",
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "GET /admin/v1/agent-workflows");
    let out = stdout(&output);
    assert!(
        out.contains("ID") && out.contains("NAME"),
        "table header: {out}"
    );
    assert!(
        out.contains("nightly") && out.contains("wf-2"),
        "table body: {out}"
    );
}

// ----- #363 asset/channel: table list + captured request ---------------------

#[test]
fn asset_registry_list_table_output() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"[{"asset_type":"cli_tool","name":"cli","version":"1.0.0"}]"#,
    ));

    let output = base_cmd(home.path())
        .args(["ctl", "assets", "list", "--endpoint", &mock.base_url])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "GET /v1/assets");
    let out = stdout(&output);
    assert!(
        out.contains("ASSET_TYPE") && out.contains("VERSION"),
        "table header: {out}"
    );
    assert!(
        out.contains("cli_tool") && out.contains("1.0.0"),
        "table body: {out}"
    );
}

#[test]
fn asset_channels_list_json_with_pagination_and_filter() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"list","data":[{"channel":"stable","version":"1.0.0"}]}"#,
    ));

    // asset-channels `list` is a nested read under the asset item; the id
    // segments select the asset, and --limit/--filter fold into the query.
    let output = base_cmd(home.path())
        .args([
            "ctl",
            "asset-channels",
            "list",
            "cli_tool",
            "mytool",
            "--endpoint",
            &mock.base_url,
            "--limit",
            "10",
            "--filter",
            "platform=linux",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    // Generic dispatch built the nested path and appended pagination + filter.
    let request = mock.last_request();
    assert!(
        request.starts_with("GET /v1/assets/cli_tool/mytool/channels?"),
        "nested list path with query: {request}"
    );
    assert!(request.contains("limit=10"), "limit param: {request}");
    assert!(
        request.contains("platform=linux"),
        "filter param: {request}"
    );
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(body["data"][0]["channel"], "stable");
}

// ----- #364 billing/usage + operator-action ----------------------------------

#[test]
fn billing_usage_reports_json_round_trip() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"list","data":[{"period":"2026-07","total_tokens":1000}]}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "usage",
            "reports",
            "--endpoint",
            &mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "GET /admin/v1/usage-reports");
    let body: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(body["data"][0]["total_tokens"], 1000);
}

#[test]
fn operator_gateway_configs_list_table_output() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"[{"id":"gw-default","active":true}]"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "gateway-configs",
            "list",
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.last_request(), "GET /admin/v1/gateway-configs");
    let out = stdout(&output);
    assert!(
        out.contains("ID") && out.contains("ACTIVE"),
        "table header: {out}"
    );
    assert!(out.contains("gw-default"), "table body: {out}");
}

// ----- error → exit-class ----------------------------------------------------

#[test]
fn not_found_maps_to_not_found_exit_class() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        404,
        "Not Found",
        &[("content-type", "application/json")],
        r#"{"error":{"message":"no such virtual key","type":"ferrogate_error","code":"not_found","request_id":"rid-404"}}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "virtual-keys",
            "get",
            "missing",
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        4,
        "404 → NotFoundConflict (exit 4): {}",
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("no such virtual key"),
        "message surfaced: {err}"
    );
    assert!(
        err.contains("code: not_found"),
        "error code surfaced: {err}"
    );
    assert!(
        err.contains("request-id: rid-404"),
        "request id surfaced: {err}"
    );
    assert!(
        stdout(&output).trim().is_empty(),
        "no data on stdout for a failure"
    );
}

#[test]
fn missing_body_on_a_write_is_a_usage_error() {
    let home = tempfile::tempdir().unwrap();
    // No server needed: the missing-document check fails before any request.
    let output = base_cmd(home.path())
        .args([
            "ctl",
            "mcp-servers",
            "create",
            "--endpoint",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "missing write body → Usage (exit 2): {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("requires a JSON request document"),
        "actionable message: {}",
        stderr(&output)
    );
}

// ----- discovery: the generic tree is reachable from --help ------------------

#[test]
fn ctl_help_lists_resource_families() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["ctl", "--help"])
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let out = stdout(&output);
    // A representative family from each epic is discoverable.
    for family in [
        "virtual-keys",
        "mcp-servers",
        "assets",
        "usage",
        "gateway-configs",
    ] {
        assert!(out.contains(family), "`ctl --help` lists '{family}': {out}");
    }
}
