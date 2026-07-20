// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: HTTP-level end-to-end proof for issue #305 (correlation holes):
//   every governance artifact a governed action produces — timeline events,
//   approval record, audit events, dispatch lease — joins on the same
//   {request_id, trace_id, agent_run_id} triple, and the #199 investigation
//   view finds approvals by agent_run_id directly (no related-id back-fill).

mod support;

use std::{
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

/// W3C traceparent whose trace-id half is `TRACE_ID`.
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const RUN_ID: &str = "run-corr-305";

/// Scenario 1 (issue #305 acceptance): one governed agent-run tool action that
/// requires approval. The approval record, every timeline (agent_run_events)
/// row, and every run-scoped audit row must carry the SAME
/// {request_id, trace_id, agent_run_id} triple — and the investigation view
/// selected by agent_run_id alone must join them all, including the approval
/// WITHOUT related-request-id back-fill.
#[test]
fn governed_agent_run_evidence_joins_on_one_correlation_triple() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, approval_agent_run_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // The run blocks inside the tool-approval gate, so drive it on a
    // background thread while the main thread grants the approval.
    let gateway_for_run = gateway_addr.clone();
    let run = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_run,
            "POST",
            "/v1/agent-runs",
            &[
                "Authorization: Bearer agent-secret",
                "Content-Type: application/json",
                &format!("x-ferrogate-agent-run-id: {RUN_ID}"),
                &format!("traceparent: {TRACEPARENT}"),
            ],
            r#"{"input":"run an approval-gated tool","max_turns":3,"timeout_millis":20000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"governed call"},"session_id":"corr-session"}]}"#,
        ))
    });

    // The pending approval must already carry the full correlation triple.
    let pending = wait_for_pending_approval(&gateway_addr);
    let request_id = pending["request_id"]
        .as_str()
        .expect("approval carries the run request id")
        .to_string();
    assert!(!request_id.is_empty());
    assert_eq!(pending["trace_id"], TRACE_ID, "{pending}");
    assert_eq!(
        pending["agent_run_id"], RUN_ID,
        "issue #305: the approval must be bound to its agent run: {pending}"
    );
    let approval_id = pending["id"].as_str().unwrap().to_string();
    let fingerprint = pending["fingerprint"].as_str().unwrap().to_string();

    // Grant the approval so the governed action actually executes.
    let approved = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/tool-approvals/{approval_id}/approve"),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"fingerprint":"{fingerprint}","reason":"operator approved"}}"#),
    ));
    assert_eq!(approved["status"], "approved", "{approved}");

    let outcome = run.join().unwrap();
    assert_eq!(outcome["object"], "agent_run", "{outcome}");
    assert_eq!(outcome["id"], RUN_ID, "{outcome}");
    assert_eq!(
        outcome["request_id"], request_id,
        "the approval's request id IS the run request's id: {outcome}"
    );
    assert_eq!(outcome["status"], "completed", "{outcome}");

    // Timeline join: the run record and EVERY agent event carry the triple.
    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/agent-runs/{RUN_ID}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["run"]["request_id"], request_id, "{timeline}");
    assert_eq!(timeline["run"]["trace_id"], TRACE_ID, "{timeline}");
    let agent_events = timeline["agent_events"].as_array().unwrap();
    assert!(!agent_events.is_empty());
    for event in agent_events {
        assert_eq!(event["run_id"], RUN_ID, "{event}");
        assert_eq!(event["request_id"], request_id, "{event}");
        assert_eq!(event["trace_id"], TRACE_ID, "{event}");
    }
    // The governed capability decision is part of the joined evidence.
    assert!(
        agent_events
            .iter()
            .any(|event| event["kind"] == "capability.requested"),
        "{timeline}"
    );
    // Audit join: every run-scoped audit row (approval requested/granted,
    // tool execution) carries the same triple.
    let audit_events = timeline["audit_events"].as_array().unwrap();
    assert!(!audit_events.is_empty());
    for event in audit_events {
        assert_eq!(event["agent_run_id"], RUN_ID, "{event}");
        assert_eq!(event["request_id"], request_id, "{event}");
        assert_eq!(event["trace_id"], TRACE_ID, "{event}");
    }
    assert!(
        audit_events
            .iter()
            .any(|event| event["action"] == "tool.approval_requested"),
        "{timeline}"
    );
    assert!(
        audit_events
            .iter()
            .any(|event| event["action"] == "tool.approval_granted"),
        "{timeline}"
    );

    // Investigation join (#199 + #305 acceptance): selecting by agent_run_id
    // ALONE joins run, timeline, audit AND the approval — the approval via its
    // own agent_run_id binding, not related-request-id back-fill.
    let investigation = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?agent_run_id={RUN_ID}"),
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(
        investigation["selector"],
        format!("agent_run_id={RUN_ID}"),
        "{investigation}"
    );
    let approvals = investigation["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1, "{investigation}");
    assert_eq!(approvals[0]["agent_run_id"], RUN_ID, "{investigation}");
    assert_eq!(approvals[0]["request_id"], request_id, "{investigation}");
    assert_eq!(approvals[0]["trace_id"], TRACE_ID, "{investigation}");
    assert_eq!(
        investigation["agent_runs"].as_array().unwrap().len(),
        1,
        "{investigation}"
    );
    assert!(
        !investigation["agent_events"].as_array().unwrap().is_empty(),
        "{investigation}"
    );
    assert!(
        !investigation["audit_events"].as_array().unwrap().is_empty(),
        "{investigation}"
    );
    for billing in investigation["billing_events"].as_array().unwrap() {
        assert_eq!(billing["agent_run_id"], RUN_ID, "{billing}");
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Scenario 2 (issue #305 acceptance, dispatch leg): a manual `run-now` fire of
/// a self-hosted-dispatch schedule stamps the admin request's
/// {request_id, trace_id} plus the started run's agent_run_id onto the durable
/// dispatch, and the worker's LEASE carries the same triple verbatim.
#[test]
fn run_now_dispatch_lease_carries_the_admin_requests_correlation_triple() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, scheduler_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // A schedule that would never tick on its own — only run-now fires it, so
    // the ONLY dispatch in the queue is the manually-triggered one.
    let create = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/agent-schedules",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "corr-sched",
            "tenant_id": "org_corr",
            "workspace_id": "ws-corr",
            "name": "corr-run-now",
            "spec_kind": "interval",
            "interval_secs": 86400,
            "enabled": false,
            "target_kind": "self_hosted_dispatch",
            "target": {"required_capabilities": ["shell"]}
        })
        .to_string(),
    );
    assert!(create.contains("HTTP/1.1 201"), "{create}");

    let register = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "tenant": {
                "organization_id": "org_corr",
                "team_id": null,
                "project_id": "corr-project",
                "workspace_id": "ws-corr",
                "user_id": null,
                "api_key_id": "admin"
            },
            "workspace_id": "ws-corr",
            "worker_name": "corr-worker",
            "identity_fingerprint": "sha256:corr-worker",
            "orchestration_enabled": false
        })
        .to_string(),
    ));
    let worker_id = register["worker"]["id"].as_str().unwrap().to_string();
    let transport_secret = register["transport_token_secret"]
        .as_str()
        .unwrap()
        .to_string();

    // Manual run-now trigger with a known traceparent; the response's
    // x-request-id header is the admin request id the dispatch must carry.
    let run_now = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/agent-schedules/corr-sched/run-now",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
            &format!("traceparent: {TRACEPARENT}"),
        ],
        "",
    );
    assert!(run_now.contains("HTTP/1.1 202"), "{run_now}");
    let run_now_request_id =
        response_header(&run_now, "x-request-id").expect("run-now response exposes its request id");
    let fire = response_json(run_now.clone());
    assert_eq!(fire["fire"]["outcome"], "dispatched", "{fire}");
    let dispatch_id = fire["fire"]["dispatch_id"].as_str().unwrap().to_string();

    // The worker leases the dispatch: the lease carries the triple verbatim.
    let lease = poll_for_lease(&gateway_addr, &transport_secret, &worker_id);
    assert_eq!(lease["dispatch_id"], dispatch_id, "{lease}");
    assert_eq!(
        lease["request_id"], run_now_request_id,
        "the lease must carry the run-now admin request id (#305): {lease}"
    );
    assert_eq!(
        lease["trace_id"], TRACE_ID,
        "the lease must carry the run-now trace id (#305): {lease}"
    );
    assert_eq!(
        lease["agent_run_id"], lease["run_id"],
        "the lease's agent-run correlation is the run it starts (#305): {lease}"
    );
    // #307 absent-parent acceptance: an admin run-now trigger is not a
    // governed ACTION, so the dispatch records an explicit NULL parent — the
    // lease carries no parent_action_fingerprint (omitted on the wire), and
    // nothing was fabricated to fill it.
    assert!(
        lease.get("parent_action_fingerprint").is_none(),
        "a run-now dispatch has no governed-action parent (#307): {lease}"
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

fn poll_for_lease(gateway_addr: &str, transport_secret: &str, worker_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body = serde_json::json!({
            "protocol_version": 1,
            "identity": {
                "tenant_id": "org_corr",
                "workspace_id": "ws-corr",
                "worker_id": worker_id,
                "token_id": "sha256:corr-worker",
                "token_secret": transport_secret,
            },
            "supported_capabilities": ["shell"],
            "now_unix": now_unix(),
            "lease_duration_secs": 30
        })
        .to_string();
        let response = http_request(
            gateway_addr,
            "POST",
            "/v1/self-hosted-workers/runs/poll",
            &[
                "Content-Type: application/json",
                "x-ferrogate-transport-security: mutual_tls",
            ],
            &body,
        );
        assert!(response.contains("HTTP/1.1 200"), "{response}");
        let lease = response_json(response);
        if lease.get("dispatch_id").and_then(Value::as_str).is_some() {
            return lease;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the worker to lease the run-now dispatch"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// Agent-run config with an always-approval `tool.echo` and a generous
/// approval window so the main thread can grant while the run blocks.
fn approval_agent_run_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
tool_approval_timeout_secs = 15

[agent_runtime]
enabled = true
provider = "external"
max_turns = 3
timeout_millis = 30000

[agent_runtime.external]
command = "sh"
args = [
  "-c",
  "payload=$(cat); if printf '%s' \"$payload\" | grep -q '\"tool_result_count\":0'; then printf 'tool\\tmock-tool-call\\ttool.echo\\t{{\"message\":\"governed call\"}}\\n'; else printf 'finish\\t%s\\n' \"$(printf '%s' \"$payload\" | sed -n 's/.*\"input\":\"\\([^\"]*\\)\".*/\\1/p')\"; fi"
]
timeout_millis = 1000

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "agent-client"
name = "Agent client"
key = "agent-secret"
scopes = ["agent.runs.create", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10
approval_policy = "always"

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

fn scheduler_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[scheduler]
enabled = true
tick_interval_secs = 3600
"#
    )
}
