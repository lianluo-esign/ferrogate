// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: HTTP-level end-to-end proof for issue #257 -- the asset closed
//   loop over the native MCP JSON-RPC ingress (`POST /v1/mcp`). Drives a real
//   gateway process (in-memory control plane, so no live Postgres is required):
//   publishes an asset through `/v1/assets/*`, then proves an MCP client can
//   (1) enumerate it via `resources/list`, (2) read it via `resources/read`
//   with a sha256 that matches the stored fingerprint, (3) fetch it via the
//   built-in `fetch_asset` tool routed through the SAME governed chokepoint as
//   every other tool (audit evidence on the `tool.execute` seam), and (4) that
//   a key without `assets.read` gets an error rather than an empty list. A
//   second test proves the `fetch_asset` tool call is gated by a Tool-scoped
//   RequireApproval managed-action guardrail and only runs once granted --
//   proving the built-in tool inherits the approval gate.

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

const FETCH_ASSET_TOOL: &str = "builtin.fetch_asset";

/// The publish -> discover -> read/fetch closed loop over `/v1/mcp`: an asset
/// published through `/v1/assets/*` is discoverable via `resources/list`,
/// readable via `resources/read` (sha256 matches the stored fingerprint), and
/// fetchable via the governed `fetch_asset` tool; a key without `assets.read`
/// is refused rather than shown an empty list.
#[test]
fn mcp_fetch_asset_and_resources_close_the_asset_loop() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, fetch_asset_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let content = "#!/bin/sh\necho closed-loop asset\n";
    let content_hash = publish_asset(&gateway_addr, content);

    // resources/list surfaces the published asset as an `asset://` resource with
    // the stored sha256 metadata, scoped to the calling key's tenant.
    let listed = mcp_call(&gateway_addr, "reader-secret", "resources/list", json!({}));
    let resources = listed["result"]["resources"].as_array().unwrap();
    let resource = resources
        .iter()
        .find(|resource| resource["uri"] == "asset://cli_tool/hello/1.0.0")
        .unwrap_or_else(|| panic!("published asset missing from resources/list: {listed}"));
    assert_eq!(resource["mimeType"], "text/plain", "{resource}");
    assert_eq!(resource["_meta"]["sha256"], content_hash, "{resource}");

    // resources/read returns the content inline; its sha256 matches the stored
    // fingerprint (acceptance criterion 2).
    let read = mcp_call(
        &gateway_addr,
        "reader-secret",
        "resources/read",
        json!({ "uri": "asset://cli_tool/hello/1.0.0" }),
    );
    let entry = &read["result"]["contents"][0];
    assert_eq!(entry["uri"], "asset://cli_tool/hello/1.0.0", "{read}");
    assert_eq!(entry["text"], content, "{read}");
    assert_eq!(entry["_meta"]["sha256"], content_hash, "{read}");

    // The `fetch_asset` built-in tool appears in tools/list (only for a key that
    // holds assets.read) and, when called, returns the same verified content
    // through the governed chokepoint.
    let tools = mcp_call(&gateway_addr, "reader-secret", "tools/list", json!({}));
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == FETCH_ASSET_TOOL),
        "fetch_asset must be advertised to an assets.read key: {tools}"
    );
    let fetched = mcp_call(
        &gateway_addr,
        "reader-secret",
        "tools/call",
        json!({
            "name": FETCH_ASSET_TOOL,
            "arguments": { "uri": "asset://cli_tool/hello/1.0.0" }
        }),
    );
    assert_eq!(fetched["result"]["isError"], false, "{fetched}");
    let block = &fetched["result"]["content"][0];
    assert_eq!(block["type"], "resource", "{fetched}");
    assert_eq!(block["resource"]["text"], content, "{fetched}");
    assert_eq!(
        block["resource"]["_meta"]["sha256"], content_hash,
        "{fetched}"
    );

    // Governed-chokepoint evidence: the `tool.execute` success audit event for
    // the built-in tool is recorded ONLY by `execute_tool_request_with_governance`
    // (acceptance criterion 3, audit half).
    assert!(
        audit_events(&gateway_addr).iter().any(|event| {
            event["action"] == "tool.execute"
                && event["outcome"] == "success"
                && event["target"] == FETCH_ASSET_TOOL
        }),
        "missing governed tool.execute evidence for fetch_asset"
    );

    // Acceptance criterion 1: a key WITHOUT assets.read is refused, not shown an
    // empty list masking a 403. The ingress maps resources/list to assets.read,
    // so the scope check fails closed with an error.
    let denied = http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer noassets-secret",
            "Content-Type: application/json",
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        })
        .to_string(),
    );
    assert!(
        denied.contains("HTTP/1.1 403"),
        "a key without assets.read must be refused, not shown an empty list: {denied}"
    );
    let denied_body = response_json(denied);
    assert_eq!(
        denied_body["error"]["code"], "scope_denied",
        "{denied_body}"
    );
    assert!(
        denied_body["result"].is_null() && denied_body["resources"].is_null(),
        "the refusal must not carry a (masking) resource list: {denied_body}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Acceptance criterion 3 (approval half): a Tool-scoped RequireApproval
/// managed-action guardrail must gate the `fetch_asset` tool call on the
/// action-fingerprint approval -- the built-in tool runs only once the approval
/// is granted, proving it flows through the same approval gate as every other
/// tool. The call blocks in `wait_for_tool_approval` on a background thread
/// while the main thread grants the pending approval.
#[test]
fn fetch_asset_tool_is_gated_by_require_approval_guardrail() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, fetch_asset_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let content = "#!/bin/sh\necho approval-gated asset\n";
    let content_hash = publish_asset(&gateway_addr, content);

    // A Tool-scoped Request-stage guardrail whose keyword matches the tool's
    // arguments escalates to the approval gate rather than blocking.
    provision_guardrail_policy(
        &gateway_addr,
        "fetch-asset-require-approval",
        tool_require_approval_policy("fetch-asset-require-approval", "cli_tool"),
    );

    // tools/call blocks until the approval is decided; drive it on a thread.
    let gateway_for_call = gateway_addr.clone();
    let execution = thread::spawn(move || {
        mcp_call(
            &gateway_for_call,
            "reader-secret",
            "tools/call",
            json!({
                "name": FETCH_ASSET_TOOL,
                "arguments": { "uri": "asset://cli_tool/hello/1.0.0" }
            }),
        )
    });

    let pending = wait_for_pending_approval(&gateway_addr);
    assert_eq!(pending["tool_name"], FETCH_ASSET_TOOL, "{pending}");
    assert_eq!(pending["actor_api_key_id"], "reader", "{pending}");
    let fingerprint = pending["fingerprint"]
        .as_str()
        .filter(|fingerprint| fingerprint.len() >= 16)
        .unwrap_or_else(|| panic!("pending approval missing a bound fingerprint: {pending}"));

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

    // Once granted, the gated tool actually runs and returns the verified asset.
    let fetched = execution.join().unwrap();
    assert_eq!(fetched["result"]["isError"], false, "{fetched}");
    assert_eq!(
        fetched["result"]["content"][0]["resource"]["_meta"]["sha256"], content_hash,
        "the approved tool must return the verified asset: {fetched}"
    );

    let events = audit_events(&gateway_addr);
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.guardrail"
                && event["outcome"] == "approval_required"
                && event["target"] == format!("tool:{FETCH_ASSET_TOOL}")
        }),
        "missing guardrail approval_required evidence for fetch_asset"
    );
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.approval_granted" && event["outcome"] == "approved"
        }),
        "missing approval_granted evidence"
    );
    assert!(
        events.iter().any(|event| {
            event["action"] == "tool.execute"
                && event["outcome"] == "success"
                && event["target"] == FETCH_ASSET_TOOL
        }),
        "missing successful tool.execute after grant"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Register tenant `org_demo` (free plan, asset hosting enabled) and publish a
/// `cli_tool/hello/1.0.0` asset, returning its stored content sha256.
fn publish_asset(gateway_addr: &str, content: &str) -> String {
    let register = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_demo","name":"Org Demo","slug":"org-demo"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );
    let push = response_json(http_request(
        gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/hello/1.0.0",
        &[
            "Authorization: Bearer publisher-secret",
            "Content-Type: text/plain",
        ],
        content,
    ));
    assert_eq!(push["asset"]["name"], "hello", "{push}");
    push["asset"]["content_hash"]
        .as_str()
        .expect("content_hash present")
        .to_string()
}

/// Invoke a JSON-RPC method through `POST /v1/mcp` and return the parsed
/// response envelope.
fn mcp_call(gateway_addr: &str, secret: &str, method: &str, params: Value) -> Value {
    response_json(http_request(
        gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        })
        .to_string(),
    ))
}

fn audit_events(gateway_addr: &str) -> Vec<Value> {
    response_json(http_request(
        gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ))["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// A Tool-scoped RequireApproval guardrail: a Request-stage keyword match
/// escalates any matching Tool-class managed action to the approval gate.
fn tool_require_approval_policy(policy_id: &str, keyword: &str) -> PolicyRevision {
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
            "tool_guardrail_requires_approval",
            "managed tool action requires approval by guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "tool_guardrail_unavailable",
            "managed tool guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

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
    assert_eq!(activated["active_revision"], revision, "{activated}");
}

fn wait_for_pending_approval(gateway_addr: &str) -> Value {
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
        if let Some(approval) = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|approval| approval["status"] == "pending")
        {
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

/// In-memory control plane (no DSN): an admin key, a publisher (assets.write) and
/// reader (assets.read + tools.*) both attributed to `org_demo`, and a
/// `noassets` key that holds tools.* but NOT assets.read. A generous approval
/// timeout keeps the RequireApproval pending approval alive until it is granted.
fn fetch_asset_config(gateway_addr: &str) -> String {
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
platform_operator = true

[[api_keys]]
id = "publisher"
name = "Publisher"
key = "publisher-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "reader"
name = "Reader"
key = "reader-secret"
scopes = ["assets.read", "tools.read", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "noassets"
name = "No assets"
key = "noassets-secret"
scopes = ["tools.read", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"
"#
    )
}
