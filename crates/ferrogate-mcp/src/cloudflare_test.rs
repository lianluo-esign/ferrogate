// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::config::validate_mcp_server_config;
use crate::manager::{McpManager, McpToolExecutionRequest};
use crate::test_support::{json_http_response, read_until_headers_end, write_response_tolerant};
use serde_json::json;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

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
/// The stub is stateless: it answers `server/discover` and never `initialize`,
/// matching the released 2026-07-28 contract.
/// The `tools/list` reply emulates a Code Mode server (`search`/`execute`) plus
/// a mutating `write` tool that must be filtered out by deny-by-default.
fn cloudflare_stub_response_for(request: &str) -> String {
    let lower = request.to_ascii_lowercase();
    if lower.contains("mcp-method: server/discover") {
        json_http_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
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
        // tools/call — a successful, non-error tool result.
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
    // connect() performs server/discover + tools/list (2 connections); the
    // allowlisted execute is a 3rd. Each uses Connection: close, so the stub
    // serves 3.
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
