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
use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

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

/// Issue #307 acceptance: downstream handoff propagation. ONE governed MCP
/// action (same require-approval gate as the previous test) is the PARENT; a
/// subsequent A2A exchange declares that parent via
/// `x-ferrogate-parent-action-fingerprint`. Proves over a real gateway that:
/// 1. a malformed declared parent is a 400 and persists nothing,
/// 2. the child A2A request-log row carries the parent fingerprint and the
///    gateway re-stamps the header on its outbound (egress) forward,
/// 3. investigating the PARENT walks parent → child: its
///    `action_correlations` group lists the child's request id,
/// 4. investigating the CHILD surfaces its `parent_action_fingerprint` and
///    the parent-keyed correlation group to pivot on,
/// 5. an absent-parent A2A exchange records NULL explicitly — no parent field
///    on its evidence, and it never appears as anyone's child.
#[test]
fn downstream_a2a_exchange_carries_the_parent_action_identity() {
    let arguments = json!({ "message": "please GOVERNME downstream" });
    let parent_fingerprint =
        ferrogate_runtime::canonical_mcp_target("local", "echo", &arguments.to_string(), false)
            .expect("the MCP call has a canonical capability target")
            .fingerprint();

    // A stub A2A upstream: exactly two forwarded exchanges (declared-parent +
    // absent-parent; the malformed-header request must never reach it).
    let (upstream_addr, upstream) = spawn_provider_upstream(
        2,
        r#"{"parts":[{"kind":"text","text":"downstream reply"}]}"#,
    );

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stdio_mcp.py");
    write_stdio_mcp_script(&script);
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        handoff_config(&gateway_addr, &script, &upstream_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    wait_for_tool(&gateway_addr, "local-echo");
    provision_guardrail_policy(
        &gateway_addr,
        "mcp-approval-gate",
        mcp_guardrail_require_approval_policy("mcp-approval-gate", "GOVERNME"),
    );

    // --- The PARENT governed action: approval-gated MCP tools/call. ---
    let gateway_for_call = gateway_addr.clone();
    let call_arguments = arguments.clone();
    let call = thread::spawn(move || tools_call(&gateway_for_call, "local-echo", call_arguments));
    let pending = wait_for_pending_approval(&gateway_addr);
    assert_eq!(pending["action_fingerprint"], parent_fingerprint);
    let approval_id = pending["id"].as_str().unwrap().to_string();
    let invocation_fingerprint = pending["fingerprint"].as_str().unwrap().to_string();
    let parent_request_id = pending["request_id"].as_str().unwrap().to_string();
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
    let clean = call.join().unwrap();
    assert!(clean.get("error").is_none(), "{clean}");

    // --- 1) A malformed declared parent is rejected up front (400). ---
    let malformed = http_request(
        &gateway_addr,
        "POST",
        "/v1/agents/downstream-agent/message:send",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-parent-action-fingerprint: not-a-fingerprint",
        ],
        r#"{"params":{"message":{"parts":[{"kind":"text","text":"hello"}]}}}"#,
    );
    assert!(malformed.contains("HTTP/1.1 400"), "{malformed}");
    assert!(
        malformed.contains("invalid_parent_action_fingerprint_header"),
        "{malformed}"
    );

    // --- 2) The CHILD A2A exchange declaring the governed parent. ---
    let child = http_request(
        &gateway_addr,
        "POST",
        "/v1/agents/downstream-agent/message:send",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            &format!("x-ferrogate-parent-action-fingerprint: {parent_fingerprint}"),
        ],
        r#"{"params":{"message":{"parts":[{"kind":"text","text":"do the downstream work"}]}}}"#,
    );
    assert!(child.contains("HTTP/1.1 200"), "{child}");
    let child_request_id =
        response_header(&child, "x-request-id").expect("A2A response exposes its request id");

    // --- 5a) An absent-parent A2A exchange (NULL recorded explicitly). ---
    let orphan = http_request(
        &gateway_addr,
        "POST",
        "/v1/agents/downstream-agent/message:send",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
        ],
        r#"{"params":{"message":{"parts":[{"kind":"text","text":"no parent here"}]}}}"#,
    );
    assert!(orphan.contains("HTTP/1.1 200"), "{orphan}");
    let orphan_request_id =
        response_header(&orphan, "x-request-id").expect("A2A response exposes its request id");

    // --- 2b) Egress stamp: the gateway re-declared the parent on the
    //     outbound forward of the child call and did NOT invent one for the
    //     orphan call. ---
    let forwarded = upstream.join().unwrap();
    assert_eq!(forwarded.len(), 2, "exactly two exchanges reach upstream");
    assert!(
        forwarded[0].to_ascii_lowercase().contains(&format!(
            "x-ferrogate-parent-action-fingerprint: {parent_fingerprint}"
        )),
        "the egress leg must carry the declared parent (#307): {}",
        forwarded[0]
    );
    assert!(
        !forwarded[1]
            .to_ascii_lowercase()
            .contains("x-ferrogate-parent-action-fingerprint"),
        "no parent header may be fabricated on the absent-parent egress: {}",
        forwarded[1]
    );

    // --- 3) Investigating the PARENT walks parent → child. ---
    let parent_view = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={parent_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let correlations = parent_view["action_correlations"].as_array().unwrap();
    let group = correlations
        .iter()
        .find(|group| group["action_fingerprint"] == parent_fingerprint)
        .unwrap_or_else(|| panic!("no correlation group for the parent: {parent_view}"));
    let child_ids = group["child_request_ids"].as_array().unwrap();
    assert!(
        child_ids.contains(&Value::String(child_request_id.clone())),
        "the parent's correlation group must list the child A2A exchange (#307): {parent_view}"
    );
    assert!(
        !child_ids.contains(&Value::String(orphan_request_id.clone())),
        "the absent-parent exchange must not appear as a child: {parent_view}"
    );

    // --- 4) Investigating the CHILD surfaces its parent identity. ---
    let child_view = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={child_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let child_requests = child_view["requests"].as_array().unwrap();
    assert_eq!(child_requests.len(), 1, "{child_view}");
    assert_eq!(
        child_requests[0]["parent_action_fingerprint"], parent_fingerprint,
        "the child request evidence must carry its parent (#307): {child_view}"
    );
    assert!(
        child_view["action_correlations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["action_fingerprint"] == parent_fingerprint
                && group["child_request_ids"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String(child_request_id.clone()))),
        "the child's investigation must surface the parent-keyed group: {child_view}"
    );

    // --- 5b) The absent-parent exchange records NULL explicitly. ---
    let orphan_view = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={orphan_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let orphan_requests = orphan_view["requests"].as_array().unwrap();
    assert_eq!(orphan_requests.len(), 1, "{orphan_view}");
    assert!(
        orphan_requests[0]
            .get("parent_action_fingerprint")
            .is_none(),
        "an absent parent stays NULL (omitted), never fabricated: {orphan_view}"
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

fn response_header(response: &str, name: &str) -> Option<String> {
    let headers = response.split("\r\n\r\n").next()?;
    headers.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
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

/// The MCP-governance gateway config plus an A2A agent upstream pointing at a
/// local stub, and an `agents.invoke` key for the child A2A exchanges (#307).
fn handoff_config(gateway_addr: &str, script: &Path, upstream_addr: &str) -> String {
    format!(
        r#"{}
[[api_keys]]
id = "agent-client"
name = "Agent client"
key = "agent-secret"
scopes = ["agents.invoke"]
organization_id = "org_demo"

[[agent_upstreams]]
id = "downstream-agent"
name = "Downstream Agent"
enabled = true
protocol = "a2a"
endpoint = "http://{upstream_addr}/a2a"
capabilities = ["invoke", "read"]
"#,
        mcp_governance_config(gateway_addr, script)
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
