// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;

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
