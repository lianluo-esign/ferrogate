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
        oauth: None,
        signed_jwt_audience: None,
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
        oauth: None,
        signed_jwt_audience: None,
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
        oauth: None,
        signed_jwt_audience: None,
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
fn legacy_headers_auth_parses_but_serializes_as_explicit_shared_credentials() {
    let config: McpServerConfig = serde_json::from_value(json!({
        "name": "shared",
        "transport": "streamable_http",
        "url": "http://127.0.0.1/mcp",
        "auth_type": "headers",
        "headers": [{"name": "Authorization", "value_env": "SHARED_TOKEN"}],
        "tools_to_execute": ["search"]
    }))
    .unwrap();
    assert_eq!(config.auth_type, McpAuthType::SharedHeaders);
    assert_eq!(
        serde_json::to_value(&config).unwrap()["auth_type"],
        "shared_headers"
    );
    validate_mcp_server_config(&config).unwrap();
}

#[test]
fn unsupported_identity_modes_fail_config_validation_exactly() {
    let mut oauth = test_config("oauth");
    oauth.auth_type = McpAuthType::Oauth;
    assert_eq!(
        validate_mcp_server_config(&oauth).unwrap_err().to_string(),
        "MCP auth_type oauth is not implemented; use per_user_oauth for user-isolated OAuth or shared_headers for shared credentials"
    );

    let mut headers = test_config("peruser");
    headers.auth_type = McpAuthType::PerUserHeaders;
    assert_eq!(
        validate_mcp_server_config(&headers).unwrap_err().to_string(),
        "MCP auth_type per_user_headers is not implemented; use per_user_oauth, original_bearer, or ferrogate_signed_jwt"
    );
}

#[test]
fn per_user_oauth_requires_complete_https_authorization_code_config() {
    let mut config = test_config("identity");
    config.auth_type = McpAuthType::PerUserOauth;
    assert!(validate_mcp_server_config(&config)
        .unwrap_err()
        .to_string()
        .contains("requires oauth configuration"));

    config.oauth = Some(McpOauthConfig {
        issuer: "http://idp.invalid".into(),
        client_id: "client".into(),
        client_secret_ref: Some("env://OIDC_SECRET".into()),
        redirect_uri: Some("https://gateway.example/v1/mcp/identity/callback".into()),
        scopes: vec!["openid".into()],
        audience: None,
        allow_insecure_http: false,
    });
    assert!(validate_mcp_server_config(&config)
        .unwrap_err()
        .to_string()
        .contains("must use https"));
    config.oauth.as_mut().unwrap().allow_insecure_http = true;
    validate_mcp_server_config(&config).unwrap();
}

#[test]
fn dispatch_header_debug_output_redacts_bearer() {
    let headers = McpDispatchHeaders::bearer("never-print-this-token".into()).unwrap();
    let debug = format!("{headers:?}");
    assert!(!debug.contains("never-print-this-token"));
    assert!(debug.contains("redacted"));
}

#[test]
fn dispatch_headers_reject_bearer_header_injection() {
    assert!(McpDispatchHeaders::bearer("token\r\nx-forged: value".into()).is_err());
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

#[test]
fn read_json_body_rejects_oversized_content_length_without_allocating() {
    // An attacker-controlled (lying) Content-Length larger than the cap must
    // bail BEFORE any allocation -- the prior `vec![0u8; len]` aborted the whole
    // gateway process on a huge len.
    let mut reader = Cursor::new(br#"{"ok":true}"#.as_slice());
    let result = read_json_body(&mut reader, Some(MAX_MCP_RESPONSE_BYTES + 1));
    assert!(result.is_err(), "oversized Content-Length must be rejected");
}

#[test]
fn read_json_body_parses_a_content_length_bounded_body() {
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let mut reader = Cursor::new(body.as_slice());
    let value = read_json_body(&mut reader, Some(body.len())).unwrap();
    assert_eq!(value["id"], 1);
}

#[test]
fn read_json_body_parses_a_body_without_content_length() {
    let mut reader = Cursor::new(br#"{"ok":true}"#.as_slice());
    let value = read_json_body(&mut reader, None).unwrap();
    assert_eq!(value["ok"], true);
}

/// True for the I/O errors a one-shot test server legitimately sees when the
/// client already has what it needs (or gave up under CPU load) and dropped the
/// connection. These must never fail a test: the protocol behaviour under test
/// happened on the client side; a racing EPIPE/ECONNRESET on the server thread
/// is benign. See issue #327 (same family as #234/#235/#240/#324).
fn is_benign_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof, WouldBlock,
    };
    matches!(
        err.kind(),
        BrokenPipe | ConnectionReset | ConnectionAborted | WouldBlock | TimedOut | UnexpectedEof
    )
}

/// Reads from a test-server socket until the end of the HTTP request headers
/// (CRLFCRLF) or EOF. Tolerates a client that reset the connection under load
/// instead of panicking, returning whatever was captured so far. Only a
/// genuinely-unexpected I/O error panics (that would be a real bug, not a race).
fn read_until_headers_end(stream: &mut impl Read) -> Vec<u8> {
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match Read::read(stream, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&chunk[..n]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if is_benign_disconnect(&err) => break,
            Err(err) => panic!("unexpected read error in one-shot test server: {err}"),
        }
    }
    received
}

/// Writes the canned response to a test-server socket and flushes it, tolerating
/// a client that already hung up (the client got what it needed, or timed out
/// under load and dropped the connection). Only a genuinely-unexpected I/O error
/// panics.
fn write_response_tolerant(stream: &mut impl Write, response: &[u8]) {
    if let Err(err) = stream.write_all(response) {
        assert!(
            is_benign_disconnect(&err),
            "unexpected write error in one-shot test server: {err}"
        );
        return;
    }
    if let Err(err) = stream.flush() {
        assert!(
            is_benign_disconnect(&err),
            "unexpected flush error in one-shot test server: {err}"
        );
    }
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
        let _received = read_until_headers_end(&mut tls_stream);
        write_response_tolerant(&mut tls_stream, response.as_bytes());
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
fn post_http_json_preserves_upstream_401_as_identity_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let received = read_until_headers_end(&mut tcp);
        let request = String::from_utf8_lossy(&received);
        assert!(request.contains("Authorization: Bearer per-user-token\r\n"));
        write_response_tolerant(
            &mut tcp,
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"});
    let error = post_http_json(
        &format!("http://{addr}/mcp"),
        Duration::from_secs(2),
        &[("Authorization".into(), "Bearer per-user-token".into())],
        &McpTlsConfig::default(),
        &McpTransport::StreamableHttp,
        &body,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "mcp_upstream_unauthorized");
    handle.join().unwrap();
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

// -- issue #277: 2026-07-28 negotiation + Mcp-Method/Mcp-Name routing ---

#[test]
fn negotiate_protocol_version_matrix_prefers_new_and_honours_legacy() {
    // Server-side ingress negotiation (old->new and new->new both resolve to a
    // mutually supported version; anything unknown negotiates down to newest).
    assert_eq!(negotiate_protocol_version(Some("2026-07-28")), "2026-07-28");
    assert_eq!(negotiate_protocol_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(negotiate_protocol_version(None), "2026-07-28");
    assert_eq!(negotiate_protocol_version(Some("2099-01-01")), "2026-07-28");
}

#[test]
fn resolve_negotiated_version_matrix_adopts_server_choice_or_falls_back() {
    // Client-side: adopt the server's echoed version when supported, else fall
    // back to the previous stable revision.
    assert_eq!(resolve_negotiated_version(Some("2026-07-28")), "2026-07-28");
    assert_eq!(resolve_negotiated_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(resolve_negotiated_version(None), "2025-06-18");
    assert_eq!(resolve_negotiated_version(Some("2099-01-01")), "2025-06-18");
    assert!(is_supported_protocol_version("2026-07-28"));
    assert!(!is_supported_protocol_version("2099-01-01"));
}

#[test]
fn verify_routing_headers_accepts_matching_or_absent_and_rejects_mismatch() {
    // Absent headers (pre-2026-07-28 client) always pass.
    assert!(verify_routing_headers(None, None, "tools/call", Some("srv-search")).is_ok());
    // Matching headers pass.
    assert!(verify_routing_headers(
        Some("tools/call"),
        Some("srv-search"),
        "tools/call",
        Some("srv-search"),
    )
    .is_ok());
    // Method mismatch fails closed.
    let method_error = verify_routing_headers(Some("tools/list"), None, "tools/call", Some("x"))
        .expect_err("method mismatch must fail");
    assert_eq!(method_error.header, "Mcp-Method");
    // Name mismatch fails closed.
    let name_error = verify_routing_headers(
        Some("tools/call"),
        Some("srv-evil"),
        "tools/call",
        Some("srv-search"),
    )
    .expect_err("name mismatch must fail");
    assert_eq!(name_error.header, "Mcp-Name");
}

/// Runs a single request against a throwaway plain-HTTP server that captures
/// the raw request and replies with `reply_body`. Returns the captured request.
fn capture_one_http_request(addr_reply: &str, client_call: impl FnOnce(String)) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let reply = addr_reply.to_string();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let received = read_until_headers_end(&mut tcp);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            reply.len(),
            reply
        );
        // The request is fully captured before we reply, so return it even if
        // the client already gave up and the write races an EPIPE under load.
        write_response_tolerant(&mut tcp, response.as_bytes());
        String::from_utf8_lossy(&received).to_string()
    });
    client_call(format!("http://{addr}/mcp"));
    // Never hard-panic on a benign server-thread exit; the captured request is
    // what the callers assert on and it is produced before the reply write.
    handle.join().unwrap_or_default()
}

#[test]
fn streamable_http_emits_mcp_method_and_name_headers_on_tools_call() {
    let request = capture_one_http_request(
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}"#,
        |endpoint| {
            let mut config = test_config("github");
            config.url = Some(endpoint);
            // Generous test-only timeout so the client never abandons the
            // round trip under CPU load (issue #327); production default is 30s.
            config.timeout_ms = 30_000;
            let mut client = HttpMcpClient::new(&config).unwrap();
            client
                .call_tool("search", json!({"q": "x"}), &McpDispatchHeaders::empty())
                .unwrap();
        },
    );
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("mcp-method: tools/call"),
        "request: {request}"
    );
    assert!(lower.contains("mcp-name: search"), "request: {request}");
}

#[test]
fn http_client_adopts_2026_07_28_when_server_echoes_it() {
    let mut negotiated = String::new();
    let request = capture_one_http_request(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28"}}"#,
        |endpoint| {
            let mut config = test_config("srv");
            config.url = Some(endpoint);
            // Generous test-only timeout so the client never abandons the
            // round trip under CPU load (issue #327); production default is 30s.
            config.timeout_ms = 30_000;
            let mut client = HttpMcpClient::new(&config).unwrap();
            client.initialize().unwrap();
            negotiated = client.protocol_version().to_string();
        },
    );
    // Outbound initialize advertises the new revision...
    assert!(request.contains("2026-07-28"), "request: {request}");
    // ...and the client adopts the server's echoed version.
    assert_eq!(negotiated, "2026-07-28");
}

#[test]
fn http_client_falls_back_when_server_pins_or_omits_protocol_version() {
    let mut pinned = String::new();
    capture_one_http_request(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
        |endpoint| {
            let mut config = test_config("srv");
            config.url = Some(endpoint);
            // Generous test-only timeout so the client never abandons the
            // round trip under CPU load (issue #327); production default is 30s.
            config.timeout_ms = 30_000;
            let mut client = HttpMcpClient::new(&config).unwrap();
            client.initialize().unwrap();
            pinned = client.protocol_version().to_string();
        },
    );
    assert_eq!(pinned, "2025-06-18");

    let mut omitted = String::new();
    capture_one_http_request(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        let mut client = HttpMcpClient::new(&config).unwrap();
        client.initialize().unwrap();
        omitted = client.protocol_version().to_string();
    });
    assert_eq!(omitted, "2025-06-18");
}

// -- issue #408: Cloudflare-hosted managed MCP servers as upstreams --------

#[test]
fn cloudflare_managed_mcp_url_detection_flags_only_cf_hosts() {
    assert!(is_cloudflare_managed_mcp_url(CLOUDFLARE_MANAGED_MCP_URL));
    assert!(is_cloudflare_managed_mcp_url(
        "https://mcp.cloudflare.com/mcp"
    ));
    assert!(is_cloudflare_managed_mcp_url(
        "https://docs.mcp.cloudflare.com/mcp"
    ));
    assert!(is_cloudflare_managed_mcp_url(&cloudflare_product_mcp_url(
        "bindings"
    )));
    // Tenant Worker MCP endpoints are flagged only on the /mcp and /sse paths.
    assert!(is_cloudflare_managed_mcp_url(
        "https://acme.workers.dev/mcp"
    ));
    assert!(is_cloudflare_managed_mcp_url(
        "https://acme.workers.dev/sse"
    ));
    assert!(!is_cloudflare_managed_mcp_url(
        "https://acme.workers.dev/api"
    ));
    // Non-Cloudflare hosts and junk are never flagged.
    assert!(!is_cloudflare_managed_mcp_url("https://example.com/mcp"));
    assert!(!is_cloudflare_managed_mcp_url(
        "https://mcp.cloudflare.com.evil.example/mcp"
    ));
    assert!(!is_cloudflare_managed_mcp_url("not a url at all"));
    assert_eq!(
        cloudflare_product_mcp_url("docs"),
        "https://docs.mcp.cloudflare.com/mcp"
    );
    assert_eq!(CLOUDFLARE_MANAGED_MCP_URL, "https://mcp.cloudflare.com/mcp");
}

#[test]
fn cloudflare_bearer_header_and_managed_config_are_valid_deny_by_default() {
    let header = cloudflare_bearer_header("cf-api-token");
    assert_eq!(header.name, "Authorization");
    assert_eq!(header.value.as_deref(), Some("Bearer cf-api-token"));
    assert!(header.value_env.is_none());

    let config = cloudflare_managed_bearer_config(
        "cfmanaged",
        CLOUDFLARE_MANAGED_MCP_URL,
        "cf-api-token",
        vec!["search".into(), "execute".into()],
    );
    assert_eq!(config.transport, McpTransport::StreamableHttp);
    assert_eq!(config.auth_type, McpAuthType::SharedHeaders);
    assert_eq!(config.url.as_deref(), Some(CLOUDFLARE_MANAGED_MCP_URL));
    assert_eq!(config.tools_to_execute, vec!["search", "execute"]);
    // Passes the generic MCP validation (deny-by-default + shared-header auth).
    validate_mcp_server_config(&config).unwrap();
}

/// Canned responses for the in-process Cloudflare-managed MCP stub, dispatched
/// by the outbound `Mcp-Method` routing header (2026-07-28 Streamable HTTP).
/// The `tools/list` reply emulates a Code Mode server (`search`/`execute`) plus
/// a mutating `write` tool that must be filtered out by deny-by-default.
fn cloudflare_stub_response_for(request: &str) -> String {
    let lower = request.to_ascii_lowercase();
    if lower.contains("mcp-method: initialize") {
        json_http_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","capabilities":{}}}"#,
        )
    } else if lower.contains("mcp-method: tools/list") {
        json_http_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
                {"name":"search","description":"Code Mode search","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}},
                {"name":"execute","description":"Code Mode execute","inputSchema":{"type":"object","properties":{"code":{"type":"string"}}}},
                {"name":"write","description":"mutating tool","inputSchema":{"type":"object"}}
            ]}}"#,
        )
    } else {
        // tools/call (and any ping) — a successful, non-error tool result.
        json_http_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"cf-ok"}],"isError":false}}"#,
        )
    }
}

/// In-process stub emulating a Cloudflare managed MCP server over plain HTTP.
/// Serves `connections` one-shot (Connection: close) requests, captures each
/// raw request for auth-header assertions, and dispatches replies by method.
fn spawn_cloudflare_managed_stub(
    connections: usize,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_thread = Arc::clone(&captured);
    let handle = thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut tcp, _)) = listener.accept() else {
                break;
            };
            let received = read_until_headers_end(&mut tcp);
            let request = String::from_utf8_lossy(&received).to_string();
            let response = cloudflare_stub_response_for(&request);
            write_response_tolerant(&mut tcp, response.as_bytes());
            captured_thread.lock().unwrap().push(request);
        }
    });
    (addr, captured, handle)
}

#[test]
fn cloudflare_managed_bearer_upstream_connects_lists_allowlisted_and_executes() {
    // connect() performs initialize + tools/list (2 connections); the allowlisted
    // execute is a 3rd. Each uses Connection: close, so the stub serves 3.
    let (addr, captured, handle) = spawn_cloudflare_managed_stub(3);
    let mut config = cloudflare_managed_bearer_config(
        "cfmanaged",
        format!("http://{addr}/mcp"),
        "cf-secret-token",
        vec!["search".into(), "execute".into()],
    );
    // Generous timeout so the round trips never abandon under CPU load (#327).
    config.timeout_ms = 30_000;

    let manager = McpManager::from_configs(&[config]);

    let status = manager.statuses().pop().expect("one session");
    assert!(
        status.connected,
        "CF managed upstream must connect: {:?}",
        status.last_error
    );

    // Deny-by-default: only the two allowlisted Code Mode tools are exposed; the
    // remote `write` tool is filtered out of the listing entirely.
    let mut listed: Vec<String> = manager.tools().into_iter().map(|tool| tool.name).collect();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "cfmanaged-execute".to_string(),
            "cfmanaged-search".to_string()
        ]
    );
    assert!(manager.tool_by_name("cfmanaged-write").is_none());

    // Execute an allowlisted Code Mode tool end-to-end through tools/call.
    let result = manager
        .execute_tool(McpToolExecutionRequest {
            name: "cfmanaged-search".into(),
            arguments: json!({"query": "how do I bind KV"}),
        })
        .expect("allowlisted Code Mode tool executes");
    assert!(!result.is_error);
    assert_eq!(result.content["content"][0]["text"], "cf-ok");

    handle.join().unwrap();

    // The Cloudflare API bearer token is injected on every upstream request.
    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(
        requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer cf-secret-token")),
        "CF bearer must be injected on every request: {requests:?}"
    );
}

#[test]
fn cloudflare_managed_denied_tool_is_refused_before_dispatch() {
    // Only `search` is allowlisted; a `write` call is refused deny-by-default
    // without ever contacting the (here unreachable) upstream.
    let config = cloudflare_managed_bearer_config(
        "cfmanaged",
        "http://127.0.0.1:1/mcp",
        "cf-secret-token",
        vec!["search".into()],
    );
    let manager = McpManager::from_configs(&[config]);

    let error = manager
        .execute_tool(McpToolExecutionRequest {
            name: "cfmanaged-write".into(),
            arguments: json!({}),
        })
        .unwrap_err();
    assert_eq!(error.code(), "tool_denied");
    assert!(error.message().contains("not allowlisted"));
}

#[test]
fn post_http_json_parses_sse_formatted_response_over_plain_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let _received = read_until_headers_end(&mut tcp);
        let sse_body =
            ": ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{sse_body}"
        );
        write_response_tolerant(&mut tcp, response.as_bytes());
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
