// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: HTTP-level end-to-end proof for #225 of the tool-governance
//   chokepoint's managed-action guardrail guardrails (#200): a Tool-scoped
//   RequireApproval policy gates `/v1/tools/execute` on the action-fingerprint
//   approval and only runs the tool once the approval is granted; a Tool-scoped
//   Quarantine policy rewrites (redacts) the tool's OUTPUT in place so the raw
//   flagged content never leaves the gateway; and a Tool-scoped Block policy
//   fails the action closed — all driven through the real gateway process over
//   `POST /v1/tools/execute` (`ToolExecuteBackend::Extension`).

mod support;

use std::{
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

/// Scenario 1 (issue #225): a Tool-scoped guardrail whose `on_fail` is
/// `require_approval` and whose Request-stage detector matches the tool's
/// arguments must gate `/v1/tools/execute` on the existing tool-approval flow —
/// the tool runs *only* once an approval bound to the action fingerprint is
/// granted. This proves the strong allowed-on-grant cycle: the execute request
/// blocks in `wait_for_tool_approval`, a pending approval bound to the
/// fingerprint appears, and granting it lets the tool run and return its result.
#[test]
fn require_approval_guardrail_gates_tool_execute_until_granted() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, tool_governance_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // Tool-scoped guardrail: a Request-stage keyword match escalates the action
    // to the approval gate rather than blocking it.
    provision_guardrail_policy(
        &gateway_addr,
        "tool-require-approval",
        tool_guardrail_policy(
            "tool-require-approval",
            DetectorStage::Request,
            "REQUIREGATE",
            PolicyAction::require_approval(
                "tool_guardrail_requires_approval",
                "managed tool action requires approval by guardrail policy",
            ),
        ),
    );

    // The execute request will BLOCK inside `wait_for_tool_approval` until the
    // approval is decided, so drive it on a background thread while the main
    // thread grants the pending approval.
    let gateway_for_call = gateway_addr.clone();
    let execution = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_call,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret",
                "Content-Type: application/json",
            ],
            r#"{"name":"tool.echo","arguments":{"message":"please REQUIREGATE now"},"session_id":"approval-session"}"#,
        ))
    });

    // A pending approval bound to the action fingerprint must be created by the
    // guardrail's RequireApproval escalation.
    let pending = wait_for_pending_approval(&gateway_addr, &[]);
    assert_eq!(pending["tool_name"], "tool.echo", "{pending}");
    assert_eq!(pending["status"], "pending", "{pending}");
    assert_eq!(pending["actor_api_key_id"], "tool-client", "{pending}");
    let fingerprint = pending["fingerprint"]
        .as_str()
        .filter(|fingerprint| fingerprint.len() >= 16)
        .unwrap_or_else(|| panic!("pending approval missing a bound fingerprint: {pending}"));

    // Granting the approval (bound to the fingerprint) unblocks the gated
    // execution: the tool runs and returns its real echoed result.
    let approved = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!(
            "/admin/v1/tool-approvals/{}/approve",
            pending["id"].as_str().unwrap()
        ),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"fingerprint":"{fingerprint}","reason":"operator approved"}}"#),
    ));
    assert_eq!(approved["status"], "approved", "{approved}");
    assert_eq!(approved["reviewer_api_key_id"], "admin", "{approved}");

    let executed = execution.join().unwrap();
    assert_eq!(executed["object"], "tool_execution", "{executed}");
    assert_eq!(executed["name"], "tool.echo", "{executed}");
    assert_eq!(executed["is_error"], false, "{executed}");
    assert_eq!(
        executed["content"]["echo"]["message"], "please REQUIREGATE now",
        "the tool must actually run and return its result once approved: {executed}"
    );
    assert_eq!(executed["session_id"], "approval-session", "{executed}");

    // Audit evidence: the guardrail escalation, the approval request, and the
    // grant-before-execution are all recorded on the tool-governance seam.
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
                && event["outcome"] == "approval_required"
                && event["target"] == "tool:tool.echo"
        }),
        "missing guardrail approval_required evidence: {audit_events}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "tool.approval_granted"
                && event["outcome"] == "approved"),
        "missing approval_granted evidence: {audit_events}"
    );
    assert!(
        events
            .iter()
            .any(|event| { event["action"] == "tool.execute" && event["outcome"] == "success" }),
        "missing successful tool.execute after grant: {audit_events}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Scenario 2 (issue #225): a Tool-scoped guardrail whose `on_fail` is
/// `quarantine` with a Response-stage detector matching the tool's OUTPUT must
/// rewrite the flagged result in place before it reaches the caller. The
/// deterministic (`local`) keyword detector emits a redaction content patch on
/// the mutable `ToolResult` segment, so the quarantine resolves to an
/// `effect==Redact` match: the gateway returns a non-error, redacted result and
/// the raw flagged output (`SECRETLEAK...`) never leaves the gateway.
#[test]
fn quarantine_guardrail_redacts_tool_execute_output() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, tool_governance_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // Tool-scoped guardrail: a Response-stage keyword match quarantines the
    // OUTPUT. Only a Response-stage check is present, so the input stage never
    // matches and the tool runs normally before its result is redacted.
    provision_guardrail_policy(
        &gateway_addr,
        "tool-quarantine-output",
        tool_guardrail_policy(
            "tool-quarantine-output",
            DetectorStage::Response,
            "SECRETLEAK",
            PolicyAction::quarantine(
                "tool_guardrail_quarantined",
                "managed tool output quarantined by guardrail policy",
            ),
        ),
    );

    let raw_marker = "SECRETLEAK-9f3c2a1b-exfiltrated-token";
    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        &json!({
            "name": "tool.echo",
            "arguments": { "message": format!("here is {raw_marker} do not leak") },
            "session_id": "quarantine-session"
        })
        .to_string(),
    ));

    // The tool executed (non-error) but its result was redacted in place: the
    // caller receives a `[REDACTED]` payload, never the raw flagged output.
    assert_eq!(executed["object"], "tool_execution", "{executed}");
    assert_eq!(executed["name"], "tool.echo", "{executed}");
    assert_eq!(
        executed["is_error"], false,
        "a quarantine redaction is a non-error result: {executed}"
    );
    assert_eq!(
        executed["content"], "[REDACTED]",
        "the flagged tool output must be redacted in place: {executed}"
    );
    assert!(
        !executed.to_string().contains("SECRETLEAK"),
        "raw flagged output must never leave the gateway: {executed}"
    );

    // Audit evidence: the output was redacted by the guardrail seam.
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
                && event["outcome"] == "redacted"
                && event["target"] == "tool:tool.echo"
        }),
        "missing guardrail redacted evidence: {audit_events}"
    );
    // #304: the redaction is recorded structurally, not just in prose — the
    // audit row carries output_disposition = "redacted" and the canonical
    // `degrade` decision derived from the redacted outcome.
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.guardrail"
                && event["outcome"] == "redacted"
                && event["output_disposition"] == "redacted"
                && event["decision"] == "degrade"
                && event["decision_reason"] == "audit_redacted"
        }),
        "missing structured output_disposition on the redacted audit row: {audit_events}"
    );
    // The tool.execute success row reflects what the caller actually received.
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.execute"
                && event["outcome"] == "success"
                && event["output_disposition"] == "redacted"
        }),
        "tool.execute row must carry the post-guardrail disposition: {audit_events}"
    );
    // #304/#309 ordering regression: the chokepoint emits the tool.execute
    // success row BEFORE the tool.guardrail redacted row, and that order must
    // survive persistence (the #309 background evidence writer is a single
    // FIFO consumer precisely so this sequence cannot invert).
    let success_position = events.iter().position(|event| {
        event["action"] == "tool.execute"
            && event["outcome"] == "success"
            && event["output_disposition"] == "redacted"
    });
    let redacted_position = events.iter().position(|event| {
        event["action"] == "tool.guardrail"
            && event["outcome"] == "redacted"
            && event["target"] == "tool:tool.echo"
    });
    assert!(
        success_position.unwrap() < redacted_position.unwrap(),
        "the tool.execute success row must persist before the tool.guardrail redacted row: {audit_events}"
    );
    assert!(
        !audit_events.to_string().contains("SECRETLEAK"),
        "durable audit evidence must not carry the raw flagged output: {audit_events}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Scenario 3 (issue #225 control): a Tool-scoped guardrail whose `on_fail` is a
/// plain `block` with a Request-stage detector matching the tool's arguments
/// must fail the action closed — `/v1/tools/execute` returns a `guardrail_blocked`
/// error and the tool never runs.
#[test]
fn block_guardrail_fails_tool_execute_closed() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, tool_governance_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    provision_guardrail_policy(
        &gateway_addr,
        "tool-block-input",
        tool_guardrail_policy(
            "tool-block-input",
            DetectorStage::Request,
            "BLOCKME",
            PolicyAction::block(
                "tool_guardrail_blocked",
                "managed tool action blocked by guardrail policy",
            ),
        ),
    );

    let blocked = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.echo","arguments":{"message":"please BLOCKME now"},"session_id":"block-session"}"#,
    ));
    assert_eq!(blocked["error"]["code"], "guardrail_blocked", "{blocked}");
    assert!(
        blocked.get("content").is_none(),
        "a blocked action must not return tool content: {blocked}"
    );

    // A clean action on the same tool stays allowed — proving the block is the
    // guardrail's doing, not a broken tool.
    let clean = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.echo","arguments":{"message":"routine hello"},"session_id":"block-session"}"#,
    ));
    assert_eq!(clean["object"], "tool_execution", "{clean}");
    assert_eq!(
        clean["content"]["echo"]["message"], "routine hello",
        "{clean}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// A durable, enforced managed-action guardrail policy scoped to
/// `ManagedActionClass::Tool` whose single `stage` check fails on `keyword` and
/// runs `on_fail_action`. Mirrors the production-tested policy shape used by the
/// #200 socket-boundary e2e, adapted to the Tool class and the #225 actions.
fn tool_guardrail_policy(
    policy_id: &str,
    stage: DetectorStage,
    keyword: &str,
    on_fail_action: PolicyAction,
) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: format!("managed {policy_id} guardrail"),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector {
            managed_action: Some(ManagedActionSelector {
                classes: vec![ManagedActionClass::Tool],
                targets: Vec::new(),
            }),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![on_fail_action],
        on_error: vec![PolicyAction::block(
            "tool_guardrail_unavailable",
            "managed tool guardrail policy unavailable",
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

/// Poll the admin tool-approvals list until a pending approval (not in
/// `exclude_ids`) appears. (Copied from the agentic-lite tool-approval e2e.)
fn wait_for_pending_approval(gateway_addr: &str, exclude_ids: &[&str]) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let body = response_json(http_request(
            gateway_addr,
            "GET",
            "/admin/v1/tool-approvals",
            &["Authorization: Bearer admin-secret"],
            "",
        ));
        if let Some(approval) = body["data"].as_array().unwrap().iter().find(|approval| {
            approval["status"] == "pending"
                && approval["id"]
                    .as_str()
                    .is_some_and(|id| !exclude_ids.contains(&id))
        }) {
            return approval.clone();
        }
        last = body;
        thread::sleep(Duration::from_millis(25));
    }
    panic!("tool approval did not become pending: {last}");
}

fn response_json(response: String) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

/// A gateway with the builtin `tool.echo` extension enabled for tenant
/// `org_demo`, a `tools.read`/`tools.execute` client, and an
/// `admin.read`/`admin.write` admin. `tool_approval_timeout_secs` is generous so
/// the RequireApproval scenario's pending approval survives until it is granted.
fn tool_governance_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
tool_approval_timeout_secs = 10

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
organization_id = "org_demo"
project_id = "project_gateway"

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]
network = []
filesystem = false
shell = false
tenant_scope = true

[extensions.config]
tenant_allowlist = ["org_demo"]
"#
    )
}
