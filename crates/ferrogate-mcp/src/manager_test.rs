// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::test_support::test_config;
use serde_json::json;

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
    let mut config = test_config("local");
    config.transport = McpTransport::Stdio;
    config.url = None;
    config.command = Some("sleep".into());
    config.args = vec!["60".into()];
    let client = StdioMcpClient::new(&config).unwrap();
    let child = Arc::clone(&client.child);
    let session = Arc::new(Mutex::new(McpSession {
        config,
        tools: vec![McpTool {
            name: "local-search".into(),
            server_name: "local".into(),
            remote_name: "search".into(),
            description: Some("Search".into()),
            input_schema: json!({"type": "object"}),
            auto_execute: false,
            approval_policy: ApprovalPolicy::Never,
        }],
        client: Some(McpClient::Stdio(client)),
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

#[test]
fn manager_health_check_keeps_modern_stdio_healthy_without_ping() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("manager-health.requests");
    let script = r#"
capture=$1
shift
for response in "$@"; do
    IFS= read -r request || exit 1
    printf '%s\n' "$request" >> "$capture"
    printf '%s\n' "$response"
done
"#;
    let mut config = test_config("modern-health");
    config.transport = McpTransport::Stdio;
    config.url = None;
    config.command = Some("sh".into());
    config.args = vec![
        "-c".into(),
        script.into(),
        "ferrogate-manager-modern-health".into(),
        capture.to_string_lossy().into_owned(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#.into(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[],"ttlMs":5000,"cacheScope":"private"}}"#.into(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#.into(),
    ];

    let manager = McpManager::from_configs(&[config]);
    assert!(manager.statuses()[0].connected);
    manager.health_check_and_reconnect();
    assert!(manager.statuses()[0].connected);
    drop(manager);

    let methods: Vec<String> = std::fs::read_to_string(capture)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["method"]
                .as_str()
                .unwrap()
                .into()
        })
        .collect();
    assert_eq!(
        methods,
        ["server/discover", "tools/list", "server/discover"]
    );
    assert!(!methods.iter().any(|method| method == "ping"));
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
