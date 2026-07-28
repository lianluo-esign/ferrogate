// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Wire-level stdio client tests using a finite subprocess peer.

use super::*;
use crate::test_support::test_config;

const FINITE_PEER: &str = r#"
capture=$1
shift
for response in "$@"; do
    IFS= read -r request || exit 1
    printf '%s\n' "$request" >> "$capture"
    printf '%s\n' "$response"
done
"#;

fn peer_config(capture: &std::path::Path, responses: &[&str]) -> McpServerConfig {
    let mut config = test_config("stdio-peer");
    config.transport = crate::config::McpTransport::Stdio;
    config.url = None;
    config.command = Some("sh".into());
    config.args = vec![
        "-c".into(),
        FINITE_PEER.into(),
        "ferrogate-mcp-stdio-peer".into(),
        capture.to_string_lossy().into_owned(),
    ];
    config
        .args
        .extend(responses.iter().map(|response| response.to_string()));
    config
}

fn captured_requests(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

const RESTARTING_LEGACY_PEER: &str = r#"
capture=$1
marker=$2
mode=$3
if mkdir "$marker" 2>/dev/null; then
    IFS= read -r request || exit 1
    printf '%s\n' "$request" >> "$capture"
    if [ "$mode" = "silent" ]; then
        IFS= read -r ignored || exit 0
    fi
    exit 0
fi
IFS= read -r request || exit 1
printf '%s\n' "$request" >> "$capture"
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}'
"#;

fn restarting_peer_config(
    capture: &std::path::Path,
    marker: &std::path::Path,
    mode: &str,
) -> McpServerConfig {
    let mut config = test_config("restarting-stdio-peer");
    config.transport = crate::config::McpTransport::Stdio;
    config.url = None;
    config.command = Some("sh".into());
    config.args = vec![
        "-c".into(),
        RESTARTING_LEGACY_PEER.into(),
        "ferrogate-mcp-restarting-peer".into(),
        capture.to_string_lossy().into_owned(),
        marker.to_string_lossy().into_owned(),
        mode.into(),
    ];
    config.timeout_ms = 50;
    config
}

#[test]
fn modern_stdio_wire_probes_then_carries_per_request_meta() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("modern.requests");
    let responses = [
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[],"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
    ];
    let mut client = StdioMcpClient::new(&peer_config(&capture, &responses)).unwrap();

    client.negotiate().unwrap();
    client.list_tools().unwrap();
    client
        .call_tool("search", serde_json::json!({"q": "x"}))
        .unwrap();
    client.health_check().unwrap();
    let protocol = client.negotiated_protocol().unwrap();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "server/discover",
            "tools/list",
            "tools/call",
            "server/discover"
        ]
    );
    assert!(!requests
        .iter()
        .any(|request| request["method"] == "initialize"));
    for request in &requests {
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "ferrogate"
        );
        assert!(
            request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object()
        );
    }
    assert_eq!(requests[2]["params"]["name"], "search");
    assert_eq!(
        requests[2]["params"]["arguments"],
        serde_json::json!({"q": "x"})
    );
    assert_eq!(protocol.mode, crate::protocol::McpProtocolMode::Modern);
    assert_eq!(protocol.version, "2026-07-28");
    assert_eq!(protocol.downgrade_reason, None);
    assert!(!requests.iter().any(|request| request["method"] == "ping"));
}

#[test]
fn stdio_method_not_found_falls_back_to_legacy_initialize() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("legacy.requests");
    let responses = [
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#,
    ];
    let mut client = StdioMcpClient::new(&peer_config(&capture, &responses)).unwrap();

    client.negotiate().unwrap();
    client.list_tools().unwrap();
    let protocol = client.negotiated_protocol().unwrap();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["method"], "server/discover");
    assert_eq!(requests[1]["method"], "initialize");
    assert_eq!(requests[1]["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(requests[2]["method"], "tools/list");
    assert!(requests[1]["params"].get("_meta").is_none());
    assert!(requests[2]["params"].get("_meta").is_none());
    assert_eq!(protocol.mode, crate::protocol::McpProtocolMode::Legacy);
    assert_eq!(protocol.version, "2025-11-25");
    assert_eq!(
        protocol.downgrade_reason,
        Some(crate::protocol::McpProtocolDowngradeReason::StdioMethodNotFound)
    );
}

#[test]
fn stdio_recognized_modern_error_does_not_initialize() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("rejected.requests");
    let responses = [r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported"}}"#];
    let mut client = StdioMcpClient::new(&peer_config(&capture, &responses)).unwrap();

    let error = client.negotiate().unwrap_err().to_string();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], "server/discover");
    assert!(error.contains("JSON-RPC error code -32022"), "{error}");
}

#[test]
fn stdio_invalid_params_probe_error_falls_back_to_legacy_initialize() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("invalid-params.requests");
    let responses = [
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"initialize first"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}"#,
    ];
    let mut client = StdioMcpClient::new(&peer_config(&capture, &responses)).unwrap();

    client.negotiate().unwrap();
    let protocol = client.negotiated_protocol().unwrap();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests[0]["method"], "server/discover");
    assert_eq!(requests[1]["method"], "initialize");
    assert_eq!(
        protocol.downgrade_reason,
        Some(crate::protocol::McpProtocolDowngradeReason::StdioUnrecognizedError)
    );
}

#[test]
fn stdio_silent_probe_times_out_restarts_and_initializes_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("silent.requests");
    let marker = dir.path().join("silent-first-process");
    let mut client =
        StdioMcpClient::new(&restarting_peer_config(&capture, &marker, "silent")).unwrap();

    client.negotiate().unwrap();
    let protocol = client.negotiated_protocol().unwrap();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], "server/discover");
    assert_eq!(requests[1]["method"], "initialize");
    assert_eq!(
        protocol.downgrade_reason,
        Some(crate::protocol::McpProtocolDowngradeReason::StdioProbeTimeout)
    );
}

#[test]
fn stdio_probe_process_exit_restarts_and_initializes_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("exit.requests");
    let marker = dir.path().join("exit-first-process");
    let mut client =
        StdioMcpClient::new(&restarting_peer_config(&capture, &marker, "exit")).unwrap();

    client.negotiate().unwrap();
    let protocol = client.negotiated_protocol().unwrap();
    drop(client);

    let requests = captured_requests(&capture);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], "server/discover");
    assert_eq!(requests[1]["method"], "initialize");
    assert_eq!(
        protocol.downgrade_reason,
        Some(crate::protocol::McpProtocolDowngradeReason::StdioProbeProcessExit)
    );
}
