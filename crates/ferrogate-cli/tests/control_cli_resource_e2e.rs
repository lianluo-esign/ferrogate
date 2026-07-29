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

#[allow(dead_code)]
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ----- process helpers -------------------------------------------------------

fn base_cmd(home: &Path) -> Command {
    let mut command = support::ferrogate_command();
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

#[derive(Clone)]
struct CapturedRequest {
    line: String,
    raw: String,
}

/// A loopback server that records every non-preflight request and replies with a
/// fixed response. The shared Control Plane client performs an action-time
/// `/healthz` preflight before ordinary API requests; the mock satisfies that
/// handshake but deliberately does not count it as a resource dispatch.
struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl MockServer {
    fn last_request(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .map(|request| request.line.clone())
            .unwrap_or_default()
    }

    fn last_raw_request(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .map(|request| request.raw.clone())
            .unwrap_or_default()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
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
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            if request.line == "GET /healthz" {
                let _ = stream.write_all(action_time_response(&request.raw).as_bytes());
                let _ = stream.flush();
                continue;
            }
            sink.lock().unwrap().push(request);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    MockServer {
        base_url: format!("http://127.0.0.1:{port}"),
        requests,
    }
}

fn action_time_response(request: &str) -> String {
    let action_id = header_value(request, "x-ferrogate-action-id").unwrap_or("fgact_missing");
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = format!("v1;issued_at={issued_at};ttl=300;action_id={action_id};sig=mock");
    http_response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("x-ferrogate-time-token", &token),
        ],
        "{}",
    )
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Read a complete HTTP request and return both its `METHOD PATH` line and raw
/// bytes. The raw capture is needed for headers such as `Accept`, while existing
/// tests keep asserting the stable line via `last_request()`.
fn read_http_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&buffer[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        if request.len() < body_start + content_length {
            continue;
        }
        let raw = String::from_utf8_lossy(&request).into_owned();
        let first_line = raw.lines().next()?;
        let mut parts = first_line.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        return Some(CapturedRequest {
            line: format!("{method} {path}"),
            raw,
        });
    }
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
fn request_logs_export_writes_single_record_bytes_without_implicit_newline() {
    let home = tempfile::tempdir().unwrap();
    let body = r#"{"id":"one"}"#;
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[
            ("content-type", "application/x-ndjson"),
            ("x-request-id", "rid-export-one"),
            ("x-trace-id", "trace-export-one"),
        ],
        body,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "request-logs",
            "export",
            "--endpoint",
            &mock.base_url,
            "--filter",
            "request_id=req_1",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(
        output.stdout.as_slice(),
        body.as_bytes(),
        "raw export stdout must be byte-for-byte and must not append a newline"
    );
    let err = stderr(&output);
    assert!(
        err.contains("request-id: rid-export-one"),
        "request id must stay diagnostic on stderr: {err}"
    );
    assert!(
        err.contains("trace-id: trace-export-one"),
        "trace id must stay diagnostic on stderr: {err}"
    );
    let out = stdout(&output);
    assert!(
        !out.contains("rid-export-one") && !out.contains("trace-export-one"),
        "correlation ids must not corrupt export stdout: {out}"
    );
    let request = mock.last_request();
    assert!(
        request.starts_with("GET /admin/v1/request-log-exports?"),
        "export path with query: {request}"
    );
    assert!(
        request.contains("request_id=req_1"),
        "filter query: {request}"
    );
    assert_eq!(
        header_value(&mock.last_raw_request(), "accept"),
        Some("application/x-ndjson"),
        "raw export must request NDJSON"
    );
}

#[test]
fn request_logs_export_writes_multi_record_ndjson_bytes_exactly() {
    let home = tempfile::tempdir().unwrap();
    let body = "{\"id\":\"one\"}\n{\"id\":\"two\"}";
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/x-ndjson")],
        body,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "request-logs",
            "export",
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(
        output.stdout.as_slice(),
        body.as_bytes(),
        "multi-record NDJSON must bypass structured JSON decoding and rendering"
    );
    assert_eq!(
        header_value(&mock.last_raw_request(), "accept"),
        Some("application/x-ndjson")
    );
}

#[test]
fn request_logs_export_refuses_structured_rendering_flags_before_transport() {
    let output_home = tempfile::tempdir().unwrap();
    let output_mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/x-ndjson")],
        r#"{"id":"unused"}"#,
    ));

    let output_flag = base_cmd(output_home.path())
        .args([
            "ctl",
            "request-logs",
            "export",
            "--endpoint",
            &output_mock.base_url,
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output_flag), 2, "stderr: {}", stderr(&output_flag));
    assert!(
        stderr(&output_flag).contains("--output does not apply"),
        "raw export must reject structured rendering: {}",
        stderr(&output_flag)
    );
    assert!(
        stdout(&output_flag).trim().is_empty(),
        "usage failure must not write stdout"
    );
    assert_eq!(
        output_mock.request_count(),
        0,
        "--output refusal must happen before transport"
    );

    let all_pages_home = tempfile::tempdir().unwrap();
    let all_pages_mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/x-ndjson")],
        r#"{"id":"unused"}"#,
    ));

    let all_pages_flag = base_cmd(all_pages_home.path())
        .args([
            "ctl",
            "request-logs",
            "export",
            "--endpoint",
            &all_pages_mock.base_url,
            "--all-pages",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&all_pages_flag),
        2,
        "stderr: {}",
        stderr(&all_pages_flag)
    );
    assert!(
        stderr(&all_pages_flag).contains("--all-pages does not apply"),
        "raw export must reject list walking: {}",
        stderr(&all_pages_flag)
    );
    assert!(
        stdout(&all_pages_flag).trim().is_empty(),
        "usage failure must not write stdout"
    );
    assert_eq!(
        all_pages_mock.request_count(),
        0,
        "--all-pages refusal must happen before transport"
    );
}

#[test]
fn request_logs_export_keeps_typed_error_envelope_on_raw_path() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        408,
        "Request Timeout",
        &[
            ("content-type", "application/json"),
            ("x-trace-id", "trace-export-timeout"),
        ],
        r#"{"error":{"message":"export timed out","type":"ferrogate_error","code":"request_timeout","request_id":"rid-export-timeout"}}"#,
    ));

    let output = base_cmd(home.path())
        .args([
            "ctl",
            "request-logs",
            "export",
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 6, "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).trim().is_empty(),
        "raw error responses must not be written as export data"
    );
    let err = stderr(&output);
    assert!(err.contains("export timed out"), "message surfaced: {err}");
    assert!(
        err.contains("code: request_timeout"),
        "code surfaced: {err}"
    );
    assert!(
        err.contains("request-id: rid-export-timeout"),
        "request id surfaced: {err}"
    );
    assert!(
        err.contains("trace-id: trace-export-timeout"),
        "trace id surfaced: {err}"
    );
    assert_eq!(
        header_value(&mock.last_raw_request(), "accept"),
        Some("application/x-ndjson"),
        "even failing raw exports use the raw Accept header"
    );
}

#[test]
fn billing_events_replay_confirmation_blocks_and_yes_sends_once() {
    let blocked_home = tempfile::tempdir().unwrap();
    let blocked_mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"billing_outbox_dead_letter_replay","report_id":"rpt_42","replayed":true}"#,
    ));

    let blocked = base_cmd(blocked_home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "billing-events",
            "replay",
            "rpt_42",
            "--endpoint",
            &blocked_mock.base_url,
            "--non-interactive",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&blocked), 2, "stderr: {}", stderr(&blocked));
    let blocked_err = stderr(&blocked);
    assert!(
        blocked_err.contains("requires confirmation") && blocked_err.contains("--yes"),
        "replay refusal must name the explicit acknowledgement: {blocked_err}"
    );
    assert!(
        stdout(&blocked).trim().is_empty(),
        "blocked replay must not emit a receipt"
    );
    assert_eq!(
        blocked_mock.request_count(),
        0,
        "unacknowledged replay must not reach transport"
    );

    let yes_home = tempfile::tempdir().unwrap();
    let yes_mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"billing_outbox_dead_letter_replay","report_id":"rpt_42","replayed":true}"#,
    ));

    let sent = base_cmd(yes_home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "billing-events",
            "replay",
            "rpt_42",
            "--endpoint",
            &yes_mock.base_url,
            "--non-interactive",
            "--yes",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&sent), 0, "stderr: {}", stderr(&sent));
    assert_eq!(yes_mock.request_count(), 1, "--yes must send one replay");
    assert_eq!(
        yes_mock.last_request(),
        "POST /admin/v1/billing-outbox-dead-letters/rpt_42/replay"
    );
    let receipt: serde_json::Value =
        serde_json::from_str(stdout(&sent).trim()).unwrap_or_else(|error| {
            panic!(
                "stdout must be a JSON replay receipt ({error}): {}",
                stdout(&sent)
            )
        });
    assert_eq!(receipt["object"], "mutation_receipt", "{receipt}");
    assert_eq!(receipt["verb"], "replay", "{receipt}");
    assert_eq!(receipt["response"]["replayed"], true, "{receipt}");
    assert_eq!(receipt["response"]["report_id"], "rpt_42", "{receipt}");
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

#[test]
fn guarded_wallet_adjust_without_ack_never_reaches_transport() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"wallet","tenant_id":"tenant-a"}"#,
    ));

    let output = base_cmd(home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "wallets",
            "adjust",
            "tenant-a",
            "--data",
            r#"{"delta_credits":-100}"#,
            "--endpoint",
            &mock.base_url,
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "unacknowledged guarded execution must fail as usage: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("requires confirmation"),
        "error names the confirmation requirement: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).trim().is_empty(),
        "a refused mutation must not emit a receipt: {}",
        stdout(&output)
    );
    assert_eq!(
        mock.request_count(),
        0,
        "guarded mutation reached transport without --yes"
    );
}

#[test]
fn guarded_wallet_adjust_non_interactive_requires_yes_before_transport() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"wallet","tenant_id":"tenant-a"}"#,
    ));

    let output = base_cmd(home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "wallets",
            "adjust",
            "tenant-a",
            "--data",
            r#"{"delta_credits":-100}"#,
            "--endpoint",
            &mock.base_url,
            "--non-interactive",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        2,
        "non-interactive guarded mutation must fail as usage: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("--yes"),
        "non-interactive refusal points at explicit acknowledgement: {}",
        stderr(&output)
    );
    assert_eq!(
        mock.request_count(),
        0,
        "--non-interactive guarded mutation reached transport without --yes"
    );
}

#[test]
fn guarded_wallet_adjust_yes_reaches_transport_exactly_once() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("x-request-id", "rid-wallet-adjust"),
        ],
        r#"{"object":"wallet","tenant_id":"tenant-a","balance_credits":900}"#,
    ));

    let output = base_cmd(home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "wallets",
            "adjust",
            "tenant-a",
            "--data",
            r#"{"delta_credits":-100}"#,
            "--endpoint",
            &mock.base_url,
            "--non-interactive",
            "--yes",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.request_count(), 1, "--yes must send one request");
    assert_eq!(
        mock.last_request(),
        "POST /admin/v1/wallets/tenant-a/adjust"
    );
    let receipt: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).unwrap_or_else(|error| {
            panic!(
                "stdout must be a JSON receipt ({error}): {}",
                stdout(&output)
            )
        });
    assert_eq!(receipt["object"], "mutation_receipt", "{receipt}");
    assert_eq!(receipt["dry_run"], false, "{receipt}");
    assert_eq!(receipt["response"]["balance_credits"], 900, "{receipt}");
    assert!(
        stderr(&output).contains("request-id: rid-wallet-adjust"),
        "request id stays diagnostic: {}",
        stderr(&output)
    );
}

#[test]
fn guarded_wallet_adjust_dry_run_sends_no_request() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        200,
        "OK",
        &[("content-type", "application/json")],
        r#"{"object":"wallet","tenant_id":"tenant-a"}"#,
    ));

    let output = base_cmd(home.path())
        .stdin(Stdio::null())
        .args([
            "ctl",
            "wallets",
            "adjust",
            "tenant-a",
            "--data",
            r#"{"delta_credits":-100}"#,
            "--endpoint",
            &mock.base_url,
            "--non-interactive",
            "--dry-run",
            "--output",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(mock.request_count(), 0, "dry-run must not send");
    let receipt: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).unwrap_or_else(|error| {
            panic!(
                "stdout must be a JSON receipt ({error}): {}",
                stdout(&output)
            )
        });
    assert_eq!(receipt["object"], "mutation_receipt", "{receipt}");
    assert_eq!(receipt["dry_run"], true, "{receipt}");
    assert_eq!(
        receipt["target"]["path"], "/admin/v1/wallets/tenant-a/adjust",
        "{receipt}"
    );
}

#[test]
fn unguarded_mutation_still_sends_without_yes() {
    let home = tempfile::tempdir().unwrap();
    let mock = spawn_mock(http_response(
        201,
        "Created",
        &[("content-type", "application/json")],
        r#"{"id":"vk-new","label":"ci"}"#,
    ));

    let output = base_cmd(home.path())
        .stdin(Stdio::null())
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
    assert_eq!(
        mock.request_count(),
        1,
        "ordinary unguarded mutations must not inherit the confirmation gate"
    );
    assert_eq!(mock.last_request(), "POST /admin/v1/virtual-keys");
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
