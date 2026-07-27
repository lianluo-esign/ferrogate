// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: HTTP-level regression proof that the native MCP JSON-RPC transport
//   (`POST /v1/mcp`, method `tools/call`) routes execution through the SAME
//   governed tool chokepoint (`execute_tool_request_with_governance`) as the REST
//   endpoint `POST /v1/mcp/tool/execute`. A follow-up adversarial audit found that
//   `tools/call` executed MCP tools directly via `execute_mcp_tool`, BYPASSING the
//   #200/#204 managed-action guardrails (input block/quarantine, output
//   redaction/withhold) and the approval gate. These tests drive a real gateway
//   process with a live stdio MCP server and prove: (1) an Mcp-class Block
//   guardrail that matches the tool arguments fails the JSON-RPC call closed — the
//   tool never runs — recording the chokepoint-only `tool.guardrail` rejection
//   evidence; and (2) a clean JSON-RPC call still executes end-to-end.

mod support;

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use ferrogate_guardrails::{
    all_content_sources, CheckBinding, DetectorDefinition, DetectorStage, ManagedActionClass,
    ManagedActionSelector, PolicyAction, PolicyAggregation, PolicyExecution, PolicyMode,
    PolicyRevision, PolicyScopeSelector, PolicyStreamingMode,
};
use serde_json::{json, Value};
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

/// Regression proof for the JSON-RPC `tools/call` guardrail bypass: an Mcp-class
/// managed-action guardrail whose Request-stage detector matches the tool's
/// arguments must fail the JSON-RPC call closed — exactly as it already does for
/// `POST /v1/mcp/tool/execute`. Before the fix, `tools/call` reached
/// `execute_mcp_tool` directly and the guardrail was never evaluated, so the
/// flagged tool ran. A clean call on the same tool still executes, proving the
/// block is the guardrail's doing rather than a broken transport.
#[test]
fn mcp_json_rpc_tools_call_is_blocked_by_managed_action_guardrail() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stdio_mcp.py");
    write_stdio_mcp_script(&script);
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, mcp_governance_config(&gateway_addr, &script)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    // The stdio MCP server must have connected and registered `local-echo` before
    // the chokepoint's `tool_by_name` lookup can find it (otherwise a missing tool
    // — not a guardrail block — would be the reason the call fails).
    wait_for_tool(&gateway_addr, "local-echo");

    // An Mcp-class guardrail: a Request-stage keyword match blocks the action.
    provision_guardrail_policy(
        &gateway_addr,
        "mcp-block-input",
        mcp_guardrail_block_policy("mcp-block-input", "BLOCKME"),
    );

    // Flagged JSON-RPC `tools/call`: the arguments carry the blocked keyword, so
    // the input guardrail at the chokepoint must fail the call closed before the
    // stdio server ever executes it.
    let blocked = tools_call(
        &gateway_addr,
        "local-echo",
        json!({ "message": "please BLOCKME now" }),
    );
    assert!(
        blocked.get("result").is_none(),
        "a guardrail-blocked call must not return a tool result: {blocked}"
    );
    let blocked_message = blocked["error"]["message"].as_str().unwrap_or_default();
    assert!(
        blocked_message.contains("blocked by guardrail policy"),
        "the JSON-RPC error must attribute the guardrail block: {blocked}"
    );
    assert!(
        !blocked.to_string().contains("please BLOCKME now"),
        "a blocked action must never echo the flagged tool output: {blocked}"
    );

    // Chokepoint-only evidence: the `tool.guardrail` rejection audit event is
    // recorded solely by `execute_tool_request_with_governance`. Its presence for
    // a `tools/call` request proves the JSON-RPC transport now routes through the
    // governed chokepoint rather than calling `execute_mcp_tool` directly.
    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.guardrail"
                && event["outcome"] == "rejected"
                && event["target"] == "mcp:local:echo"
        }),
        "missing chokepoint guardrail rejection evidence for the JSON-RPC path: {audit_events}"
    );

    // A clean JSON-RPC `tools/call` on the same tool still executes end-to-end and
    // returns the echoed result — proving governance did not break the happy path.
    let clean = tools_call(
        &gateway_addr,
        "local-echo",
        json!({ "message": "routine hello" }),
    );
    assert!(
        clean.get("error").is_none(),
        "a clean call must not surface an error: {clean}"
    );
    assert_eq!(
        clean["result"]["isError"], false,
        "a clean call is a non-error result: {clean}"
    );
    assert_eq!(
        clean["result"]["content"][0]["text"], "routine hello",
        "the clean tool must actually run and echo its argument: {clean}"
    );

    // The clean execution is likewise recorded on the governed seam.
    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.execute"
                && event["outcome"] == "success"
                && event["target"] == "mcp:local/tool:echo"
        }),
        "missing successful tool.execute evidence for the clean JSON-RPC call: {audit_events}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #277 fail-closed proof: a `tools/call` whose body method disagrees with
/// the inbound `Mcp-Method` routing header must be rejected before execution and
/// audited, so a caller cannot be scope-gated / rate-limited / metered as one
/// operation while the body runs another. A matching header is NOT rejected as a
/// mismatch (it proceeds to normal handling).
#[test]
fn mcp_json_rpc_rejects_routing_header_method_mismatch_and_audits_it() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, mismatch_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // Body says tools/call, header says tools/list: fail closed.
    let mismatched = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
            "Mcp-Method: tools/list",
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "local-echo", "arguments": {} }
        })
        .to_string(),
    ));
    assert!(
        mismatched.get("result").is_none(),
        "a routing-header mismatch must not return a result: {mismatched}"
    );
    let message = mismatched["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("routing header mismatch"),
        "the JSON-RPC error must attribute the routing-header mismatch: {mismatched}"
    );

    // The rejection is audited on the governed seam.
    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    assert!(
        events.iter().any(|event| {
            event["action"] == "mcp.routing_header_mismatch" && event["outcome"] == "rejected"
        }),
        "missing routing-header mismatch audit evidence: {audit_events}"
    );

    // A matching header is not treated as a mismatch (it proceeds to normal
    // handling; the tool is simply not registered here).
    let matched = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
            "Mcp-Method: tools/call",
            "Mcp-Name: local-echo",
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "local-echo", "arguments": {} }
        })
        .to_string(),
    ));
    let matched_message = matched["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !matched_message.contains("routing header mismatch"),
        "a matching routing header must not be rejected as a mismatch: {matched}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Minimal gateway config for the routing-header mismatch test: a client with
/// tools scopes and an admin for reading audit evidence. No MCP servers are
/// needed because the mismatch is rejected before any tool executes.
fn mismatch_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
platform_operator = true
"#
    )
}

/// Invoke a tool through the native MCP JSON-RPC transport (`POST /v1/mcp`,
/// method `tools/call`) and return the parsed JSON-RPC response envelope.
fn tools_call(gateway_addr: &str, name: &str, arguments: Value) -> Value {
    response_json(http_request(
        gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        })
        .to_string(),
    ))
}

/// Poll `GET /v1/tools` until the named MCP tool is registered (the stdio server
/// has connected and its `tools/list` has been ingested).
fn wait_for_tool(gateway_addr: &str, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let body = response_json(http_request(
            gateway_addr,
            "GET",
            "/v1/tools",
            &["Authorization: Bearer tool-secret"],
            "",
        ));
        if body["data"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == name))
        {
            return;
        }
        last = body;
        thread::sleep(Duration::from_millis(25));
    }
    panic!("MCP tool {name} did not register: {last}");
}

/// A durable, enforced managed-action guardrail policy scoped to
/// `ManagedActionClass::Mcp` that blocks when `keyword` appears in the scanned
/// input. Mirrors the `ManagedActionClass::Mcp` block policy used by the #200
/// socket-boundary e2e.
fn mcp_guardrail_block_policy(policy_id: &str, keyword: &str) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: format!("managed {policy_id} guardrail"),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector {
            managed_action: Some(ManagedActionSelector {
                classes: vec![ManagedActionClass::Mcp],
                targets: Vec::new(),
            }),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "mcp_guardrail_blocked",
            "managed MCP action blocked by guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "mcp_guardrail_unavailable",
            "managed MCP guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

/// Create + activate a guardrail policy revision through the admin API. The
/// create body is a serialized `PolicyRevision`; the activate body selects the
/// revision to make live. (Copied from the #200 managed-action e2e.)
fn provision_guardrail_policy(gateway_addr: &str, policy_id: &str, policy: PolicyRevision) {
    let created = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::to_string(&policy).unwrap(),
    ));
    assert_eq!(created["object"], "guardrail_policy_revision", "{created}");
    let revision = created["policy"]["revision"]
        .as_u64()
        .unwrap_or_else(|| panic!("guardrail create response missing revision: {created}"));
    let activated = response_json(http_request(
        gateway_addr,
        "POST",
        &format!("/admin/v1/guardrail-policies/{policy_id}/activate"),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &json!({ "revision": revision }).to_string(),
    ));
    assert_eq!(
        activated["object"], "guardrail_policy_binding",
        "{activated}"
    );
    assert_eq!(activated["active_revision"], revision, "{activated}");
}

fn response_json(response: String) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

/// A gateway with a live stdio MCP server exposing an `echo` tool (registered as
/// `local-echo`), a `tools.read`/`tools.execute` client, and an
/// `admin.read`/`admin.write` admin for provisioning guardrail policies and
/// reading audit evidence. The client carries no `organization_id`, so the MCP
/// plan/entitlement gate passes without a control-plane plan (mirrors the proven
/// `p3_mcp_gateway_connects_to_stdio_server` config).
fn mcp_governance_config(gateway_addr: &str, script: &Path) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
platform_operator = true

[[mcp_servers]]
name = "local"
transport = "stdio"
command = "python3"
args = ["{}"]
tools_to_execute = ["echo"]
timeout_ms = 3000
"#,
        script.display()
    )
}

/// A minimal line-delimited JSON-RPC stdio MCP server exposing a single `echo`
/// tool. (Copied from the agentic-lite `p3` stdio harness.)
fn write_stdio_mcp_script(path: &Path) {
    std::fs::write(
        path,
        r#"
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "stdio-mcp", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [{
                "name": "echo",
                "description": "Echo a message",
                "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
            }]
        }
    elif method == "tools/call":
        args = req.get("params", {}).get("arguments", {})
        result = {"content": [{"type": "text", "text": args.get("message", "")}]}
    elif method == "ping":
        result = {}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "unknown method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}), flush=True)
"#,
    )
    .unwrap();
}
