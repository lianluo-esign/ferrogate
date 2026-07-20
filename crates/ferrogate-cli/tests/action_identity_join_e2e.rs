// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: HTTP-level end-to-end proof for issue #306 (shared action
//   identity adoption): ONE governed MCP tool action produces guardrail
//   evidence, an approval record and audit rows that all carry the SAME
//   target-level canonical_target_sha256 action fingerprint — the exact value
//   `ferrogate_runtime::canonical_mcp_target` yields for the same
//   server/tool/arguments, i.e. the same source the #304 capability/timeline
//   rows persist — and the #199 investigation view joins them by fingerprint
//   (action_correlations) while reading STORED canonical decisions.

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

/// Issue #306 acceptance: a require-approval guardrail on a live stdio MCP
/// tool. The one flagged `tools/call`:
/// 1. records guardrail evaluation evidence carrying the action fingerprint
///    AND the stored canonical decision (write-time, not read-side heuristic),
/// 2. creates an approval record carrying the SAME action fingerprint (with
///    its stored canonical decision following the status transitions), while
///    the invocation-binding Blake2b fingerprint stays authoritative for the
///    approve call,
/// 3. records chokepoint audit rows carrying the SAME fingerprint,
/// 4. and the investigation view groups all of them into one
///    `action_correlations` entry keyed by that fingerprint.
///
/// The expected fingerprint is computed in this test via
/// `ferrogate_runtime::canonical_mcp_target(...).fingerprint()` — the same
/// builder `canonical_target_for_managed_action` uses for
/// `ManagedExternalAction::McpTool`, whose value the #304 storage test
/// (`timeline_row_action_fingerprint_equals_authorizer_evidence_fingerprint`)
/// already proves lands on capability/timeline rows — so equality here proves
/// the whole evidence chain shares ONE action identity.
#[test]
fn governed_mcp_action_evidence_joins_on_one_action_fingerprint() {
    let arguments = json!({ "message": "please GOVERNME now" });
    let expected_fingerprint =
        ferrogate_runtime::canonical_mcp_target("local", "echo", &arguments.to_string(), false)
            .expect("the MCP call has a canonical capability target")
            .fingerprint();

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stdio_mcp.py");
    write_stdio_mcp_script(&script);
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, mcp_governance_config(&gateway_addr, &script)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    wait_for_tool(&gateway_addr, "local-echo");

    // A require-approval Mcp-class guardrail: the Request-stage keyword match
    // escalates the action to the approval gate (rather than blocking it).
    provision_guardrail_policy(
        &gateway_addr,
        "mcp-approval-gate",
        mcp_guardrail_require_approval_policy("mcp-approval-gate", "GOVERNME"),
    );

    // The call blocks inside the approval gate — drive it on a background
    // thread while the main thread inspects and grants the approval.
    let gateway_for_call = gateway_addr.clone();
    let call_arguments = arguments.clone();
    let call = thread::spawn(move || tools_call(&gateway_for_call, "local-echo", call_arguments));

    // 2) The PENDING approval already carries the shared action fingerprint
    //    alongside — never instead of — its invocation-binding fingerprint,
    //    plus its stored canonical decision (ask/approval_pending).
    let pending = wait_for_pending_approval(&gateway_addr);
    assert_eq!(
        pending["action_fingerprint"], expected_fingerprint,
        "the approval must carry the canonical_target_sha256 identity: {pending}"
    );
    assert_eq!(pending["decision"], "ask", "{pending}");
    assert_eq!(pending["decision_reason"], "approval_pending", "{pending}");
    let invocation_fingerprint = pending["fingerprint"].as_str().unwrap().to_string();
    assert_ne!(
        invocation_fingerprint, expected_fingerprint,
        "the invocation-binding fingerprint is NOT the target-level identity"
    );
    let approval_id = pending["id"].as_str().unwrap().to_string();
    let request_id = pending["request_id"].as_str().unwrap().to_string();

    // Grant using the invocation-binding fingerprint (still authoritative).
    let approved = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/tool-approvals/{approval_id}/approve"),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"fingerprint":"{invocation_fingerprint}","reason":"operator approved"}}"#),
    ));
    assert_eq!(approved["status"], "approved", "{approved}");
    assert_eq!(approved["decision"], "allow", "{approved}");
    assert_eq!(
        approved["decision_reason"], "approval_approved",
        "{approved}"
    );
    assert_eq!(
        approved["action_fingerprint"], expected_fingerprint,
        "the action identity survives the status transition: {approved}"
    );

    // The governed tool then actually executes end-to-end.
    let clean = call.join().unwrap();
    assert!(clean.get("error").is_none(), "{clean}");
    assert_eq!(
        clean["result"]["content"][0]["text"], "please GOVERNME now",
        "the approved tool must run and echo its argument: {clean}"
    );

    // 1) Guardrail evidence: the evaluation row for this request carries the
    //    fingerprint AND the write-time stored canonical decision.
    let evaluations = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/guardrail-evaluations?request_id={request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let rows = evaluations["data"].as_array().unwrap();
    assert!(!rows.is_empty(), "{evaluations}");
    let governed_row = rows
        .iter()
        .find(|row| row["action_fingerprint"] == expected_fingerprint)
        .unwrap_or_else(|| {
            panic!("no guardrail evaluation carries the action fingerprint: {evaluations}")
        });
    assert!(
        governed_row["decision"].is_string(),
        "the canonical decision must be STORED on the row, not derived: {governed_row}"
    );
    assert!(
        governed_row["decision_reason"]
            .as_str()
            .unwrap_or_default()
            .starts_with("guardrail:"),
        "the stored reason code carries the lossless triple: {governed_row}"
    );

    // 3) Audit rows: the chokepoint's tool.execute success row carries the
    //    same fingerprint (the projection #304 deferred), alongside its #304
    //    decision/disposition columns; the approval-gate audit rows carry it
    //    too.
    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    let success = events
        .iter()
        .find(|event| {
            event["action"] == "tool.execute"
                && event["outcome"] == "success"
                && event["request_id"] == request_id.as_str()
        })
        .unwrap_or_else(|| panic!("missing tool.execute success audit row: {audit_events}"));
    assert_eq!(
        success["action_fingerprint"], expected_fingerprint,
        "{success}"
    );
    assert_eq!(success["output_disposition"], "returned", "{success}");
    for action in ["tool.approval_requested", "tool.approval_granted"] {
        let row = events
            .iter()
            .find(|event| event["action"] == action && event["request_id"] == request_id.as_str())
            .unwrap_or_else(|| panic!("missing {action} audit row: {audit_events}"));
        assert_eq!(
            row["action_fingerprint"], expected_fingerprint,
            "the {action} row must carry the shared identity: {row}"
        );
    }

    // 4) Investigation join (#199 + #306): the fingerprint groups guardrail
    //    evidence + approval + audit rows into one action correlation, and the
    //    approval evidence surfaces the identity + stored decision.
    let investigation = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let approvals = investigation["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1, "{investigation}");
    assert_eq!(
        approvals[0]["action_fingerprint"], expected_fingerprint,
        "{investigation}"
    );
    assert_eq!(approvals[0]["decision"], "allow", "{investigation}");
    let correlations = investigation["action_correlations"].as_array().unwrap();
    let correlation = correlations
        .iter()
        .find(|group| group["action_fingerprint"] == expected_fingerprint)
        .unwrap_or_else(|| {
            panic!("no action correlation groups the shared fingerprint: {investigation}")
        });
    assert!(
        !correlation["guardrail_evaluation_ids"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{correlation}"
    );
    assert_eq!(
        correlation["approval_ids"].as_array().unwrap(),
        &vec![Value::String(approval_id.clone())],
        "{correlation}"
    );
    assert!(
        !correlation["audit_event_ids"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{correlation}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn wait_for_pending_approval(gateway_addr: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let approvals = response_json(http_request(
            gateway_addr,
            "GET",
            "/admin/v1/tool-approvals",
            &["Authorization: Bearer admin-secret"],
            "",
        ));
        if let Some(pending) = approvals["data"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|approval| approval["status"] == "pending")
        {
            return pending.clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a pending tool approval: {approvals}"
        );
        thread::sleep(Duration::from_millis(50));
    }
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

/// Poll `GET /v1/tools` until the named MCP tool is registered.
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

/// A durable, enforced Mcp-class managed-action guardrail whose on_fail
/// escalates to the approval gate (RequireApproval) when `keyword` appears in
/// the scanned input.
fn mcp_guardrail_require_approval_policy(policy_id: &str, keyword: &str) -> PolicyRevision {
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
        on_fail: vec![PolicyAction::require_approval(
            "mcp_needs_approval",
            "managed MCP action requires approval",
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

/// Create + activate a guardrail policy revision through the admin API.
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

/// A gateway with a live stdio MCP server exposing an `echo` tool (registered
/// as `local-echo`), a tools client, and an admin key — plus a generous
/// approval window so the main thread can grant while the call blocks.
/// (Mirrors the proven mcp_jsonrpc_tool_governance_e2e config.)
fn mcp_governance_config(gateway_addr: &str, script: &Path) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
tool_approval_timeout_secs = 15

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]

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

/// A minimal line-delimited JSON-RPC stdio MCP server exposing a single
/// `echo` tool. (Copied from the agentic-lite `p3` stdio harness.)
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
