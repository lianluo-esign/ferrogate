// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::Cursor;
use std::net::TcpListener;

#[test]
fn deny_by_default_requires_execute_allowlist() {
    let config = McpServerConfig {
        name: "github".into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        tools_to_execute: Vec::new(),
        tools_to_auto_execute: Vec::new(),
        approval_policy: ApprovalPolicy::Never,
        tool_include: Vec::new(),
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    };

    let error = validate_mcp_server_config(&config).unwrap_err().to_string();

    assert!(error.contains("tools_to_execute"));
}

#[test]
fn namespaces_and_filters_tools() {
    let config = McpServerConfig {
        name: "github".into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        tools_to_execute: vec!["search".into()],
        tools_to_auto_execute: vec!["search".into()],
        approval_policy: ApprovalPolicy::Never,
        tool_include: vec!["sea*".into()],
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    };

    assert!(tool_selected(&config, "search"));
    assert!(!tool_selected(&config, "write"));
    assert!(tool_allowlisted(&config.tools_to_execute, "search"));
    assert!(!tool_allowlisted(&config.tools_to_execute, "write"));
}

#[test]
fn parses_tools_list_with_rmcp_model() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "search",
                "description": "Search repos",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
            }]
        }
    });

    let tools = parse_tools_list(&response).unwrap();

    assert_eq!(tools[0].name, "search");
    assert_eq!(tools[0].description.as_deref(), Some("Search repos"));
    assert_eq!(tools[0].input_schema["type"], "object");
}

#[test]
fn manager_status_and_tools_skip_busy_sessions() {
    let manager = McpManager::default();
    let busy = Arc::new(Mutex::new(McpSession::new(test_config("busy"))));
    let ready = Arc::new(Mutex::new(McpSession::new(test_config("ready"))));
    {
        let mut ready_session = ready.lock().unwrap();
        ready_session.connected = true;
        ready_session.tools = vec![McpTool {
            name: "ready-search".into(),
            server_name: "ready".into(),
            remote_name: "search".into(),
            description: Some("Search".into()),
            input_schema: json!({"type": "object"}),
            auto_execute: false,
            approval_policy: ApprovalPolicy::Never,
        }];
    }
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.sessions.insert("busy".into(), Arc::clone(&busy));
        inner.sessions.insert("ready".into(), Arc::clone(&ready));
    }
    let _busy_guard = busy.lock().unwrap();

    let tools = manager.tools();
    let statuses = manager.statuses();

    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "ready-search");
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name, "ready");
}

#[test]
fn timeout_cleanup_kills_stdio_child_and_marks_session_degraded() {
    let manager = McpManager::default();
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let child = Arc::new(Mutex::new(child));
    let session = Arc::new(Mutex::new(McpSession {
        config: test_config("local"),
        tools: vec![McpTool {
            name: "local-search".into(),
            server_name: "local".into(),
            remote_name: "search".into(),
            description: Some("Search".into()),
            input_schema: json!({"type": "object"}),
            auto_execute: false,
            approval_policy: ApprovalPolicy::Never,
        }],
        client: Some(McpClient::Stdio(StdioMcpClient {
            child: Arc::clone(&child),
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })),
        connected: true,
        last_error: None,
        reconnect_attempts: 0,
        last_connected_at_unix: Some(1),
        next_reconnect_backoff_secs: 1,
    }));
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.sessions.insert("local".into(), Arc::clone(&session));
    }

    let cleanup = manager.dispatch_cleanup_handle("local-search").unwrap();
    assert!(cleanup.cleanup_after_timeout(Duration::from_secs(1)));

    let mut child = child.lock().unwrap();
    let status =
        wait_for_child_exit(&mut child).expect("stdio child should be killed by timeout cleanup");
    assert!(!status.success());
    drop(child);

    let status = manager.statuses().pop().unwrap();
    assert_eq!(status.name, "local");
    assert!(!status.connected);
    assert_eq!(status.health, "degraded");
    assert_eq!(status.tools, 0);
    assert!(status
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("timed out after 1 seconds")));
}

fn test_config(name: &str) -> McpServerConfig {
    McpServerConfig {
        name: name.into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        tools_to_execute: vec!["search".into()],
        tools_to_auto_execute: Vec::new(),
        approval_policy: ApprovalPolicy::Never,
        tool_include: Vec::new(),
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    }
}

fn wait_for_child_exit(child: &mut Child) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn resolve_namespaced_session_prefers_longest_configured_server_name() {
    // Regression: tool names are built as `{server}-{remote}` and server names
    // may contain hyphens. Naive split_once('-') mis-routed `my-fs-read` to a
    // server `my`. Longest configured-prefix match resolves it correctly.
    let mut sessions = HashMap::new();
    sessions.insert(
        "my".to_string(),
        Arc::new(Mutex::new(McpSession::new(test_config("my")))),
    );
    sessions.insert(
        "my-fs".to_string(),
        Arc::new(Mutex::new(McpSession::new(test_config("my-fs")))),
    );

    let (server, remote, _) = resolve_namespaced_session(&sessions, "my-fs-read")
        .expect("hyphenated server must resolve");
    assert_eq!(server, "my-fs");
    assert_eq!(remote, "read");

    // A name that matches only the shorter server still resolves to it.
    let (server, remote, _) =
        resolve_namespaced_session(&sessions, "my-list").expect("short server must resolve");
    assert_eq!(server, "my");
    assert_eq!(remote, "list");

    // Unnamespaced or unknown-server names resolve to nothing.
    assert!(resolve_namespaced_session(&sessions, "plainname").is_none());
    assert!(resolve_namespaced_session(&sessions, "ghost-tool").is_none());
    assert!(resolve_namespaced_session(&sessions, "my-").is_none());
}

#[test]
fn execute_tool_fails_closed_for_unnamespaced_and_unknown_names() {
    let manager = McpManager::default();

    let unnamespaced = manager
        .execute_tool(McpToolExecutionRequest {
            name: "plainname".into(),
            arguments: json!({}),
        })
        .unwrap_err();
    assert_eq!(unnamespaced.code(), "tool_not_found");
    assert!(unnamespaced
        .message()
        .contains("serverName-toolName namespace"));

    let unknown = manager
        .execute_tool(McpToolExecutionRequest {
            name: "ghost-tool".into(),
            arguments: json!({}),
        })
        .unwrap_err();
    assert_eq!(unknown.code(), "tool_not_found");
    assert!(unknown.message().contains("did not match any configured"));
}

#[test]
fn mcp_execution_error_exposes_stable_codes_and_messages() {
    assert_eq!(McpExecutionError::Denied("d".into()).code(), "tool_denied");
    assert_eq!(
        McpExecutionError::NotFound("n".into()).code(),
        "tool_not_found"
    );
    assert_eq!(
        McpExecutionError::Unavailable("u".into()).code(),
        "mcp_server_unavailable"
    );
    assert_eq!(
        McpExecutionError::Failed("f".into()).code(),
        "tool_execution_failed"
    );
    assert_eq!(McpExecutionError::Failed("boom".into()).message(), "boom");
}

#[test]
fn mcp_tool_as_tool_def_preserves_namespaced_name_and_schema() {
    let tool = McpTool {
        name: "srv-search".into(),
        server_name: "srv".into(),
        remote_name: "search".into(),
        description: Some("Search".into()),
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        auto_execute: false,
        approval_policy: ApprovalPolicy::Never,
    };
    let def = tool.as_tool_def();
    assert_eq!(def.name, "srv-search");
    assert_eq!(def.description.as_deref(), Some("Search"));
    assert_eq!(def.input_schema["properties"]["q"]["type"], "string");
}

#[test]
fn validate_http_endpoint_accepts_http_https_and_rejects_others() {
    assert!(validate_http_endpoint("http://127.0.0.1:8080/mcp").is_ok());
    assert!(validate_http_endpoint("https://example.com/mcp").is_ok());
    assert!(validate_http_endpoint("ftp://example.com").is_err());
    assert!(validate_http_endpoint("stdio://local").is_err());
    assert!(validate_http_endpoint("not a uri at all").is_err());
}

#[test]
fn mcp_server_config_applies_serde_defaults() {
    let config: McpServerConfig = serde_json::from_value(json!({
        "name": "local",
        "transport": "stdio",
        "command": "mcp-server"
    }))
    .expect("minimal config must parse");
    assert_eq!(config.timeout_ms, 30_000);
    assert_eq!(
        config.health_ping_interval_secs,
        DEFAULT_HEALTH_PING_INTERVAL_SECS
    );
    assert_eq!(
        config.max_reconnect_attempts,
        DEFAULT_MAX_RECONNECT_ATTEMPTS
    );
    assert_eq!(config.auth_type, McpAuthType::None);
    assert!(config.tools_to_execute.is_empty());
    assert_eq!(config.transport, McpTransport::Stdio);
}

#[test]
fn manager_from_configs_records_unavailable_session_without_live_server() {
    // reconfigure connects; an unreachable endpoint must record an error and a
    // status rather than panic, and expose no executable tools.
    let manager = McpManager::from_configs(&[test_config("offline")]);
    let statuses = manager.statuses();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name, "offline");
    assert!(!statuses[0].connected);
    assert!(manager.tools().is_empty());
    assert!(manager.tool_by_name("offline-search").is_none());
}

// -- issue #167: MCP TLS/HTTPS/SSE support -----------------------------

#[test]
fn parse_http_target_defaults_https_to_port_443_and_http_to_port_80() {
    // Uses a numeric IP literal (rather than a hostname) so the test doesn't
    // depend on DNS resolution being available in the test environment.
    let https = parse_http_target("https://127.0.0.1/mcp").unwrap();
    assert_eq!(https.scheme, HttpScheme::Https);
    assert_eq!(https.authority, "127.0.0.1");
    assert_eq!(https.address.port(), 443);

    let http = parse_http_target("http://127.0.0.1/mcp").unwrap();
    assert_eq!(http.scheme, HttpScheme::Http);
    assert_eq!(http.authority, "127.0.0.1");
    assert_eq!(http.address.port(), 80);

    let https_custom_port = parse_http_target("https://127.0.0.1:8443/mcp").unwrap();
    assert_eq!(https_custom_port.authority, "127.0.0.1:8443");
    assert_eq!(https_custom_port.address.port(), 8443);
}

#[test]
fn validate_mcp_tls_config_accepts_missing_ca_cert_path() {
    validate_mcp_tls_config(&McpTlsConfig::default()).unwrap();
}

#[test]
fn validate_mcp_tls_config_rejects_missing_ca_cert_file() {
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some("/nonexistent/ferrogate-mcp-test-ca.pem".into()),
    };
    let error = validate_mcp_tls_config(&tls).unwrap_err().to_string();
    assert!(error.contains("ca_cert_path"));
}

#[test]
fn validate_mcp_tls_config_rejects_non_pem_ca_cert_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-cert.pem");
    std::fs::write(&path, b"this is not PEM data").unwrap();
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(path.to_string_lossy().into_owned()),
    };
    let error = validate_mcp_tls_config(&tls).unwrap_err().to_string();
    assert!(error.contains("ca_cert_path") || error.contains("no PEM certificates"));
}

#[test]
fn validate_mcp_tls_config_accepts_valid_pem_ca_cert() {
    let CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(path.to_string_lossy().into_owned()),
    };
    validate_mcp_tls_config(&tls).unwrap();
}

#[test]
fn mcp_tls_client_config_builds_with_insecure_skip_verify() {
    let tls = McpTlsConfig {
        insecure_skip_verify: true,
        ca_cert_path: None,
    };
    mcp_tls_client_config(&tls).unwrap();
}

#[test]
fn mcp_tls_client_config_builds_with_native_roots_only() {
    let tls = McpTlsConfig::default();
    mcp_tls_client_config(&tls).unwrap();
}

#[test]
fn read_sse_json_response_extracts_first_complete_json_data_event() {
    let stream = ": keep-alive comment\n\nevent: ignored\ndata: not json at all\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
    let mut reader = Cursor::new(stream.as_bytes());
    let value = read_sse_json_response(&mut reader).unwrap();
    assert_eq!(value["result"]["ok"], true);
}

#[test]
fn read_sse_json_response_joins_multi_line_data_fields() {
    let stream = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
    let mut reader = Cursor::new(stream.as_bytes());
    let value = read_sse_json_response(&mut reader).unwrap();
    assert_eq!(value["id"], 1);
}

#[test]
fn read_sse_json_response_errors_on_closed_stream_without_data() {
    let mut reader = Cursor::new(b"event: nothing-useful\n".as_slice());
    assert!(read_sse_json_response(&mut reader).is_err());
}

fn spawn_https_test_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
    response: String,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    // Must run before any rustls ClientConfig/ServerConfig builder in this
    // process — see `ensure_rustls_crypto_provider` in lib.rs.
    ensure_rustls_crypto_provider();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("valid self-signed test certificate");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let conn =
            ServerConnection::new(Arc::new(server_config)).expect("valid rustls server config");
        let mut tls_stream = StreamOwned::new(conn, tcp);
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = Read::read(&mut tls_stream, &mut chunk).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
            if received.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        tls_stream.write_all(response.as_bytes()).unwrap();
        tls_stream.flush().unwrap();
    });
    (addr, handle)
}

fn json_http_response(json_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    )
}

#[test]
fn post_http_json_establishes_real_tls_connection_over_https_with_insecure_skip_verify() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig {
        insecure_skip_verify: true,
        ca_cert_path: None,
    };
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    )
    .expect("https round trip must succeed");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}

#[test]
fn post_http_json_verifies_https_certificate_via_custom_ca_cert_path() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();

    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(ca_path.to_string_lossy().into_owned()),
    };
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    )
    .expect("https round trip trusting the custom CA must succeed");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}

#[test]
fn post_http_json_rejects_untrusted_https_certificate_by_default() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig::default();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    );

    assert!(result.is_err());
    // The server thread's write will fail/short-circuit once the client aborts
    // the handshake; only assert it doesn't hang.
    let _ = handle.join();
}

#[test]
fn post_http_json_parses_sse_formatted_response_over_plain_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = Read::read(&mut tcp, &mut chunk).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
            if received.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let sse_body =
            ": ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{sse_body}"
        );
        tcp.write_all(response.as_bytes()).unwrap();
        tcp.flush().unwrap();
    });

    let endpoint = format!("http://{addr}/mcp");
    let tls = McpTlsConfig::default();
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::Sse,
        &body,
    )
    .expect("SSE-formatted response must parse");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}
