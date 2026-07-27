// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod support;

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn agentic_lite_builtin_tools_are_visible_and_explicitly_executable() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, builtin_tools_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let admin_extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(admin_extensions["data"].as_array().unwrap().len(), 4);
    assert!(admin_extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|extension| extension["id"] == "tool.echo" && extension["active"] == true));
    assert!(admin_extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|extension| extension["id"] == "tool.health_check" && extension["active"] == false));

    let admin_tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(admin_tools["data"][0]["name"], "tool.echo");
    assert!(admin_tools["data"][0].get("config").is_none());

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "tool.echo");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.echo","arguments":{"message":"hello"},"session_id":"session-1"}"#,
    ));
    assert_eq!(executed["object"], "tool_execution");
    assert_eq!(executed["name"], "tool.echo");
    assert_eq!(executed["content"]["echo"]["message"], "hello");
    assert_eq!(executed["session_id"], "session-1");

    let denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.health_check","arguments":{}}"#,
    ));
    assert_eq!(denied["error"]["code"], "tool_not_found");

    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool_session:session-1"
            && event["outcome"] == "success"
            && event["message"].as_str().unwrap().contains("tool.echo")
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool.health_check"
            && event["outcome"] == "error"
    }));

    let session_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-sessions/session-1",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let session_events = session_events["data"].as_array().unwrap();
    assert_eq!(session_events.len(), 1);
    assert_eq!(session_events[0]["action"], "tool.execute");
    assert_eq!(session_events[0]["target"], "tool_session:session-1");
    assert_eq!(session_events[0]["outcome"], "success");
    assert!(session_events[0]["message"]
        .as_str()
        .unwrap()
        .contains("tool.echo"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agent_run_endpoint_is_fail_closed_until_enabled() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, builtin_tools_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let disabled = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
        ],
        r#"{"input":"summarize this"}"#,
    ));
    assert_eq!(disabled["error"]["code"], "agent_runtime_disabled");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agent_run_endpoint_creates_observable_opt_in_run() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, external_echo_agent_run_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let created = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-agent-run-id: agent-run-direct",
        ],
        r#"{"input":"produce a bounded agent result","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"from agent"},"session_id":"agent-tool-session"}]}"#,
    ));
    assert_eq!(created["object"], "agent_run");
    assert_eq!(created["id"], "agent-run-direct");
    assert_eq!(created["status"], "completed");
    assert_eq!(created["turns_executed"], 2);
    assert_eq!(created["output"], "produce a bounded agent result");
    assert_eq!(created["tool_results"].as_array().unwrap().len(), 1);
    assert_eq!(
        created["tool_results"][0]["content"]["echo"]["message"],
        "from agent"
    );

    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-runs/agent-run-direct",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["object"], "agent_run_timeline");
    assert_eq!(timeline["id"], "agent-run-direct");
    assert_eq!(timeline["summary"]["status"], "completed");
    assert_eq!(timeline["summary"]["request_count"], 0);
    assert_eq!(timeline["summary"]["audit_event_count"], 7);
    assert_eq!(timeline["summary"]["agent_event_count"], 7);
    assert_eq!(timeline["run"]["id"], "agent-run-direct");
    assert_eq!(timeline["run"]["status"], "completed");
    assert_eq!(timeline["run"]["provider"], "ferrogate.external");
    assert_eq!(timeline["run"]["turns_executed"], 2);
    assert_eq!(timeline["run"]["output_recorded"], true);
    assert_eq!(timeline["agent_events"].as_array().unwrap().len(), 7);
    assert!(timeline["agent_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| {
            event["kind"] == "tool_call_completed"
                && event["run_id"] == "agent-run-direct"
                && event["outcome"] == "success"
        }));
    assert!(timeline["agent_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| {
            event["kind"] == "capability.allowed"
                && event["run_id"] == "agent-run-direct"
                && event["target"] == "tool.echo"
                && event["outcome"] == "allowed"
                && event["tool_call_id"] == "mock-tool-call"
                && event["message"]
                    .as_str()
                    .unwrap()
                    .contains("gateway-mediated governance")
        }));
    let events = timeline["audit_events"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["action"] == "agent.run_started"
            && event["agent_run_id"] == "agent-run-direct"
            && event["tenant"]["api_key_id"] == "agent-client"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "agent.turn_started" && event["target"] == "agent_run:agent-run-direct"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "agent.run_completed"
            && event["outcome"] == "success"
            && event["message"] == "agent run completed"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool_session:agent-tool-session"
            && event["outcome"] == "success"
            && event["agent_run_id"] == "agent-run-direct"
    }));

    let no_scope = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"input":"blocked"}"#,
    ));
    assert_eq!(no_scope["error"]["code"], "scope_denied");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agent_run_endpoint_records_denied_tool_capability_in_timeline() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        external_echo_agent_run_config_without_tool_scope(&gateway_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let failed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-agent-run-id: agent-run-denied-tool",
        ],
        r#"{"input":"attempt a denied tool","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"blocked"},"session_id":"agent-denied-tool-session"}]}"#,
    ));
    assert_eq!(failed["object"], "agent_run");
    assert_eq!(failed["id"], "agent-run-denied-tool");
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["tool_results"].as_array().unwrap().len(), 0);

    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-runs/agent-run-denied-tool",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["object"], "agent_run_timeline");
    assert_eq!(timeline["run"]["id"], "agent-run-denied-tool");
    assert_eq!(timeline["run"]["status"], "failed");
    assert_eq!(timeline["run"]["provider"], "ferrogate.external");
    assert!(timeline["agent_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| {
            event["kind"] == "capability.denied"
                && event["run_id"] == "agent-run-denied-tool"
                && event["target"] == "tool.echo"
                && event["outcome"] == "denied"
                && event["tool_call_id"] == "mock-tool-call"
                && event["message"]
                    .as_str()
                    .unwrap()
                    .contains("denied before dispatch")
                && event["message"]
                    .as_str()
                    .unwrap()
                    .contains("missing tools.execute scope")
        }));
    assert!(timeline["audit_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| {
            event["action"] == "agent.run_stopped"
                && event["agent_run_id"] == "agent-run-denied-tool"
                && event["outcome"] == "stopped"
                && event["message"].as_str().unwrap().contains("scope_denied")
        }));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agent_run_endpoint_records_approval_required_tool_capability_in_timeline() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        external_echo_agent_run_approval_config(&gateway_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let failed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-agent-run-id: agent-run-approval-required",
        ],
        r#"{"input":"attempt an approval-gated tool","max_turns":3,"timeout_millis":3000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"needs approval"},"session_id":"agent-approval-tool-session"}]}"#,
    ));
    assert_eq!(failed["object"], "agent_run");
    assert_eq!(failed["id"], "agent-run-approval-required");
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["tool_results"].as_array().unwrap().len(), 0);

    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-runs/agent-run-approval-required",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["object"], "agent_run_timeline");
    assert_eq!(timeline["run"]["id"], "agent-run-approval-required");
    assert_eq!(timeline["run"]["status"], "failed");
    let agent_events = timeline["agent_events"].as_array().unwrap();
    assert!(agent_events.iter().any(|event| {
        event["kind"] == "capability.requested"
            && event["run_id"] == "agent-run-approval-required"
            && event["target"] == "tool.echo"
            && event["outcome"] == "requested"
            && event["tool_call_id"] == "mock-tool-call"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("requires approval before gateway-mediated dispatch")
    }));
    assert!(agent_events.iter().any(|event| {
        event["kind"] == "capability.denied"
            && event["run_id"] == "agent-run-approval-required"
            && event["target"] == "tool.echo"
            && event["outcome"] == "denied"
            && event["tool_call_id"] == "mock-tool-call"
            && event["message"].as_str().unwrap().contains("tool_denied")
    }));
    assert!(timeline["audit_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| {
            event["action"] == "tool.approval_requested"
                && event["agent_run_id"] == "agent-run-approval-required"
                && event["outcome"] == "pending"
        }));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn default_agent_runtime_requires_agent_worker_transport() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, agent_run_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let failed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-agent-run-id: agent-run-managed-default",
        ],
        r#"{"input":"start managed worker","max_turns":1,"timeout_millis":1000}"#,
    ));
    assert_eq!(
        failed["error"]["code"],
        "agent_worker_transport_unavailable"
    );
    assert!(failed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Firecracker microVM"));

    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-runs/agent-run-managed-default",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["run"]["status"], "failed");
    assert_eq!(timeline["run"]["provider"], "ferrogate.agent-worker");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agent_run_endpoint_can_use_external_provider_adapter() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, external_agent_run_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let created = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-runs",
        &[
            "Authorization: Bearer agent-secret",
            "Content-Type: application/json",
            "x-ferrogate-agent-run-id: agent-run-external",
        ],
        r#"{"input":"external-agent-input","max_turns":2,"timeout_millis":1000}"#,
    ));
    assert_eq!(created["object"], "agent_run");
    assert_eq!(created["id"], "agent-run-external");
    assert_eq!(created["status"], "completed");
    assert_eq!(created["output"], "external-provider-ok");
    assert_eq!(created["tool_results"].as_array().unwrap().len(), 0);

    let timeline = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-runs/agent-run-external",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(timeline["object"], "agent_run_timeline");
    assert_eq!(timeline["run"]["id"], "agent-run-external");
    assert_eq!(timeline["run"]["provider"], "ferrogate.external");
    assert_eq!(timeline["summary"]["status"], "completed");
    assert!(timeline["audit_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["action"] == "agent.run_completed"
            && event["agent_run_id"] == "agent-run-external"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agentic_lite_mcp_http_provider_imports_and_executes_allowed_tools() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server(2);
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, mcp_config(&gateway_addr, &mcp_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "github.search");
    assert!(tools["data"][0].get("config").is_none());

    let extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let mcp = extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["id"] == "mcp.http")
        .unwrap();
    assert_eq!(mcp["active"], true);
    assert_eq!(mcp["health"], "ok");
    assert!(mcp.get("config").is_none());
    assert!(!extensions.to_string().contains("/mcp"));

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github.search","arguments":{"query":"ferrogate"}}"#,
    ));
    assert_eq!(executed["name"], "github.search");
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let requests = mcp_handle.join().unwrap();
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/list\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/call\"")));
}

#[test]
fn tool_approvals_bind_fingerprint_and_fail_closed() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server(4);
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, approval_mcp_config(&gateway_addr, &mcp_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let unauthorized = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tool-approvals/approval-missing/approve",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"fingerprint":"wrong"}"#,
    ));
    assert_eq!(unauthorized["error"]["code"], "scope_denied");

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
            r#"{"name":"github.search","arguments":{"query":"ferrogate"}}"#,
        ))
    });

    let pending = wait_for_pending_approval(&gateway_addr, &[]);
    assert_eq!(pending["tool_name"], "github.search");
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["actor_api_key_id"], "tool-client");
    assert_eq!(pending["reviewer_api_key_id"], serde_json::Value::Null);
    assert!(pending["fingerprint"].as_str().unwrap().len() >= 16);
    assert!(!pending.to_string().contains("ferrogate"));
    assert!(pending.to_string().contains("[REDACTED]"));

    let mismatch = response_json(http_request(
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
        r#"{"fingerprint":"changed-arguments"}"#,
    ));
    assert_eq!(
        mismatch["error"]["code"],
        "tool_approval_fingerprint_mismatch"
    );
    let denied_execution = execution.join().unwrap();
    assert_eq!(denied_execution["error"]["code"], "tool_denied");

    let gateway_for_call = gateway_addr.clone();
    let approved_execution = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_call,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret",
                "Content-Type: application/json",
            ],
            r#"{"name":"github.search","arguments":{"query":"ferrogate"}}"#,
        ))
    });
    let pending = wait_for_pending_approval(&gateway_addr, &[pending["id"].as_str().unwrap()]);
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
        &format!(
            r#"{{"fingerprint":"{}","reason":"operator approved"}}"#,
            pending["fingerprint"].as_str().unwrap()
        ),
    ));
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["reviewer_api_key_id"], "admin");
    let executed = approved_execution.join().unwrap();
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    let gateway_for_call = gateway_addr.clone();
    let denied_call = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_call,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret",
                "Content-Type: application/json",
            ],
            r#"{"name":"github.search","arguments":{"query":"deny-me"}}"#,
        ))
    });
    let pending = wait_for_pending_approval(&gateway_addr, &[approved["id"].as_str().unwrap()]);
    let denied = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!(
            "/admin/v1/tool-approvals/{}/deny",
            pending["id"].as_str().unwrap()
        ),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"reason":"operator denied"}"#,
    ));
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied_call.join().unwrap()["error"]["code"], "tool_denied");
    let denied_reuse = response_json(http_request(
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
        &format!(
            r#"{{"fingerprint":"{}"}}"#,
            pending["fingerprint"].as_str().unwrap()
        ),
    ));
    assert_eq!(denied_reuse["error"]["code"], "tool_approval_terminal");

    let seen_ids = approval_ids(&gateway_addr);
    let gateway_for_call = gateway_addr.clone();
    let expired_by_admin_call = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_call,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret",
                "Content-Type: application/json",
            ],
            r#"{"name":"github.search","arguments":{"query":"admin-expire"}}"#,
        ))
    });
    let exclude = seen_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let pending = wait_for_pending_approval(&gateway_addr, &exclude);
    let admin_expired = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!(
            "/admin/v1/tool-approvals/{}/expire",
            pending["id"].as_str().unwrap()
        ),
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"reason":"operator expired"}"#,
    ));
    assert_eq!(admin_expired["status"], "expired");
    assert_eq!(
        expired_by_admin_call.join().unwrap()["error"]["code"],
        "tool_denied"
    );

    let expired = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github.search","arguments":{"query":"expire"}}"#,
    ));
    assert_eq!(expired["error"]["code"], "tool_denied");
    let approvals = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-approvals",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert!(approvals["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|approval| approval["status"] == "expired"));

    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    for action in [
        "tool.approval_requested",
        "tool.approval_granted",
        "tool.approval_denied",
        "tool.approval_expired",
        "tool.execute",
    ] {
        assert!(
            events.iter().any(|event| event["action"] == action),
            "missing audit action {action}: {audit_events}"
        );
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let requests = mcp_handle.join().unwrap();
    let tool_calls = requests
        .iter()
        .filter(|request| request.contains("\"tools/call\""))
        .count();
    assert_eq!(tool_calls, 1);
}

/// Issue #186: `/admin/v1/tool-approvals*` resolved a pending approval by
/// bare id with no tenant check, letting a tenant-scoped `admin` key read
/// or approve/deny/expire *another* tenant's pending tool-execution gate --
/// the same cross-tenant IDOR class #185 fixed elsewhere, for a
/// write-capable security-gate resource this time.
#[test]
fn tool_approvals_deny_cross_tenant_read_and_decision() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server(2);
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        approval_mcp_config_two_tenants(&gateway_addr, &mcp_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let gateway_for_call = gateway_addr.clone();
    let execution = thread::spawn(move || {
        response_json(http_request(
            &gateway_for_call,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret-a",
                "Content-Type: application/json",
            ],
            r#"{"name":"github.search","arguments":{"query":"ferrogate"}}"#,
        ))
    });

    let pending = wait_for_pending_approval(&gateway_addr, &[]);
    assert_eq!(pending["actor_api_key_id"], "tool-client-a");
    let approval_id = pending["id"].as_str().unwrap().to_string();

    // Tenant B cannot read tenant A's pending approval.
    let stolen_read = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/tool-approvals/{approval_id}"),
        &["Authorization: Bearer admin-b-secret"],
        "",
    ));
    assert_eq!(
        stolen_read["error"]["code"], "tenant_scope_denied",
        "tenant B must not be able to read tenant A's pending approval: {stolen_read}"
    );

    // Tenant B's own bulk list does not include tenant A's approval.
    let tenant_b_list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-approvals",
        &["Authorization: Bearer admin-b-secret"],
        "",
    ));
    let listed_ids: Vec<&str> = tenant_b_list["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|approval| approval["id"].as_str())
        .collect();
    assert!(
        !listed_ids.contains(&approval_id.as_str()),
        "tenant A's approval must not appear in tenant B's list: {tenant_b_list}"
    );

    // Tenant B cannot approve tenant A's pending tool execution.
    let stolen_approve = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/tool-approvals/{approval_id}/approve"),
        &[
            "Authorization: Bearer admin-b-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"fingerprint":"{}"}}"#,
            pending["fingerprint"].as_str().unwrap()
        ),
    ));
    assert_eq!(
        stolen_approve["error"]["code"], "tenant_scope_denied",
        "tenant B must not be able to approve tenant A's pending tool execution: {stolen_approve}"
    );

    // Tenant A can still approve its own pending tool execution.
    let approved = response_json(http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/tool-approvals/{approval_id}/approve"),
        &[
            "Authorization: Bearer admin-a-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"fingerprint":"{}"}}"#,
            pending["fingerprint"].as_str().unwrap()
        ),
    ));
    assert_eq!(approved["status"], "approved");
    let executed = execution.join().unwrap();
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    mcp_handle.join().unwrap();
}

#[test]
fn p3_mcp_gateway_lists_injects_and_executes_http_tools_with_governance() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server_with_tool(7, "search");
    let (provider_addr, provider_handle) = spawn_provider_upstream();
    let (otlp_addr, otlp_handle) = spawn_otlp_collector();
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        p3_mcp_config(&gateway_addr, &mcp_addr, &provider_addr, &otlp_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let mcp_status = wait_for_mcp_server_connected(&gateway_addr, "github");
    assert_eq!(mcp_status["name"], "github");
    assert_eq!(mcp_status["connected"], true);
    assert_eq!(mcp_status["tools"], 1);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "github-search");

    let initialized = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ferrogate-test","version":"1.0.0"}}}"#,
    ));
    assert_eq!(initialized["jsonrpc"], "2.0");
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["serverInfo"]["name"], "ferrogate");

    let mcp_tools = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    ));
    assert_eq!(mcp_tools["jsonrpc"], "2.0");
    assert_eq!(mcp_tools["id"], 2);
    assert_eq!(mcp_tools["result"]["tools"][0]["name"], "github-search");

    let mcp_called = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"github-search","arguments":{"query":"ferrogate"}}}"#,
    ));
    assert_eq!(mcp_called["jsonrpc"], "2.0");
    assert_eq!(mcp_called["id"], 3);
    assert_eq!(
        mcp_called["result"]["content"][0]["text"],
        "ferrogate-result"
    );

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"find ferrogate"}]}"#,
    );
    assert!(chat.contains("200 OK"), "{chat}");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-search","arguments":{"query":"ferrogate"},"session_id":"mcp-session-1"}"#,
    ));
    assert_eq!(executed["object"], "tool_execution");
    assert_eq!(executed["name"], "github-search");
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    let denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-write","arguments":{}}"#,
    ));
    assert_eq!(denied["error"]["code"], "tool_denied");

    let policy_denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer blocked-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-search","arguments":{"query":"ferrogate"}}"#,
    ));
    assert_eq!(policy_denied["error"]["code"], "tool_denied");
    assert_eq!(policy_denied["error"]["message"], "MCP search is blocked");

    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let audit_events = audit_events["data"].as_array().unwrap();
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.list"
            && event["request_id"]
                .as_str()
                .is_some_and(|request_id| request_id.starts_with("fg-"))
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["target"] == "tools"
            && event["outcome"] == "success"
    }));
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.list"
            && event["target"] == "mcp"
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("native MCP endpoint")
    }));
    // The native MCP JSON-RPC `tools/call` now executes through the shared
    // governed tool chokepoint (`execute_tool_request_with_governance`), the same
    // seam the REST `/v1/mcp/tool/execute` path uses, so it emits the chokepoint's
    // unified `tool.execute` audit message ("MCP upstream mcp:github tool search
    // executed") rather than the old JSON-RPC-only "executed through native MCP
    // endpoint" wording. The routing change is what closes the guardrail/approval
    // bypass proved in `mcp_jsonrpc_tool_governance_e2e`.
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "mcp:github/tool:search"
            && event["outcome"] == "success"
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("MCP upstream mcp:github tool search executed")
    }));
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool_session:mcp-session-1/mcp:github/tool:search"
            && event["outcome"] == "success"
            && event["tenant"]["organization_id"] == "org_demo"
            && event["tenant"]["project_id"] == "project_gateway"
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("MCP upstream mcp:github tool search executed")
    }));
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "mcp:github/tool:search"
            && event["outcome"] == "error"
            && event["tenant"]["api_key_id"] == "blocked-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("MCP upstream mcp:github tool search failed")
    }));

    let session_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-sessions/mcp-session-1",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let session_events = session_events["data"].as_array().unwrap();
    assert_eq!(session_events.len(), 1);
    assert_eq!(
        session_events[0]["target"],
        "tool_session:mcp-session-1/mcp:github/tool:search"
    );

    let billing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert!(billing["data"].as_array().unwrap().iter().any(|event| {
        event["provider"] == "mcp"
            && event["logical_model"] == "mcp_tool:github-search"
            && event["tenant"]["api_key_id"] == "tool-client"
    }));
    assert!(billing["data"].as_array().unwrap().iter().any(|event| {
        event["provider"] == "mcp"
            && event["logical_model"] == "mcp_tool:github-search"
            && event["tenant"]["api_key_id"] == "blocked-client"
            && event["status_code"] == 403
    }));

    let metrics = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        metrics.contains("ferrogate_mcp_tool_calls_total 3"),
        "{metrics}"
    );

    thread::sleep(Duration::from_secs(6));
    let observability = wait_for_observability_ok(&gateway_addr);
    assert_eq!(observability["data"][0]["provider"], "vector");
    assert_eq!(observability["data"][0]["health"], "ok");
    assert!(observability["data"][0]["last_success_at_unix"].is_number());
    assert_eq!(
        observability["data"][0]["last_export_error"],
        serde_json::Value::Null
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("\"tools\""), "{provider_request}");
    assert!(
        provider_request.contains("\"github-search\""),
        "{provider_request}"
    );

    let requests = mcp_handle.join().unwrap();
    assert!(requests
        .iter()
        .any(|request| request.contains("\"initialize\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/list\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/call\"")));
    assert!(requests.iter().any(|request| request.contains("\"ping\"")));
    assert!(!requests.join("\n").contains("tool-secret"));

    let otlp_requests = otlp_handle.join().unwrap();
    let otlp_raw = otlp_requests.join("\n---otlp-request---\n");
    assert!(otlp_raw.contains("POST /v1/metrics "), "{otlp_raw}");
    assert!(otlp_raw.contains("POST /v1/logs "), "{otlp_raw}");
    assert!(otlp_raw.contains("POST /v1/traces "), "{otlp_raw}");
    assert!(otlp_raw.contains("\"event_family\""), "{otlp_raw}");
    assert!(otlp_raw.contains("\"request\""), "{otlp_raw}");
    assert!(otlp_raw.contains("\"audit\""), "{otlp_raw}");
    assert!(
        otlp_raw.contains("\"billing_event_observed\""),
        "{otlp_raw}"
    );
    assert!(otlp_raw.contains("tool.execute"), "{otlp_raw}");
    assert!(otlp_raw.contains("mcp:github/tool:search"), "{otlp_raw}");
    assert!(otlp_raw.contains("mcp_tool:github-search"), "{otlp_raw}");
    assert!(otlp_raw.contains("MCP search is blocked"), "{otlp_raw}");
    assert!(otlp_raw.contains("tool-client"), "{otlp_raw}");
    assert!(!otlp_raw.contains("tool-secret"), "{otlp_raw}");
    assert!(!otlp_raw.contains("upstream-mcp-secret"), "{otlp_raw}");
}

#[test]
fn p3_mcp_gateway_connects_to_stdio_server() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stdio_mcp.py");
    write_stdio_mcp_script(&script);
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        p3_stdio_mcp_config(&gateway_addr, script.as_path()),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "local-echo");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"local-echo","arguments":{"message":"stdio ok"}}"#,
    ));
    assert_eq!(executed["name"], "local-echo");
    assert_eq!(executed["content"]["content"][0]["text"], "stdio ok");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn p3_mcp_gateway_times_out_slow_tool_dispatch_and_records_billing() {
    let (mcp_addr, mcp_handle) = spawn_slow_mcp_server();
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, p3_slow_mcp_config(&gateway_addr, &mcp_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let failed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-search","arguments":{"query":"ferrogate"}}"#,
    ));
    assert_eq!(failed["error"]["code"], "tool_execution_failed");
    assert!(
        failed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("timed out after 1 seconds"),
        "{failed}"
    );

    let billing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert!(billing["data"].as_array().unwrap().iter().any(|event| {
        event["provider"] == "mcp"
            && event["logical_model"] == "mcp_tool:github-search"
            && event["status_code"] == 502
    }));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let requests = mcp_handle.join().unwrap();
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/call\"")));
}

#[test]
fn agentic_lite_non_blocking_hook_failures_are_admin_visible() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, non_blocking_hook_failure_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "tool.echo");

    let extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let hook = extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["id"] == "hook.noop")
        .unwrap();
    assert_eq!(hook["active"], true);
    assert_eq!(hook["health"], "degraded");
    assert!(hook["last_error"].as_str().unwrap().contains("pre_request"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn builtin_tools_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "agent-client"
name = "Agent client"
key = "agent-secret"
scopes = ["agent.runs.create"]
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

[[extensions]]
id = "hook.noop"
kind = "request_hook"
source = "builtin"
enabled = true
order = 20

[[extensions]]
id = "event.audit_log"
kind = "event_sink"
source = "builtin"
enabled = true
order = 30

[[extensions]]
id = "tool.health_check"
kind = "tool_provider"
source = "builtin"
enabled = false
order = 40

[extensions.permissions]
tools = ["tool.health_check"]
"#
    )
}

fn agent_run_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[agent_runtime]
enabled = true
max_turns = 3
timeout_millis = 5000

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

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

fn external_echo_agent_run_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[agent_runtime]
enabled = true
provider = "external"
max_turns = 3
timeout_millis = 5000

[agent_runtime.external]
command = "sh"
args = [
  "-c",
  "payload=$(cat); if printf '%s' \"$payload\" | grep -q '\"tool_result_count\":0'; then printf 'tool\\tmock-tool-call\\ttool.echo\\t{{\"message\":\"from agent\"}}\\n'; else printf 'finish\\t%s\\n' \"$(printf '%s' \"$payload\" | sed -n 's/.*\"input\":\"\\([^\"]*\\)\".*/\\1/p')\"; fi"
]
timeout_millis = 1000

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

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

fn external_echo_agent_run_config_without_tool_scope(gateway_addr: &str) -> String {
    external_echo_agent_run_config(gateway_addr).replace(
        r#"scopes = ["agent.runs.create", "tools.execute"]"#,
        r#"scopes = ["agent.runs.create"]"#,
    )
}

fn external_echo_agent_run_approval_config(gateway_addr: &str) -> String {
    let config = external_echo_agent_run_config(gateway_addr).replace(
        r#"[agent_runtime.external]"#,
        r#"[reliability]
tool_approval_timeout_secs = 1

[agent_runtime.external]"#,
    );
    config.replace(
        r#"order = 10

[extensions.permissions]"#,
        r#"order = 10
approval_policy = "always"

[extensions.permissions]"#,
    )
}

fn external_agent_run_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[agent_runtime]
enabled = true
provider = "external"
max_turns = 3
timeout_millis = 5000

[agent_runtime.external]
command = "sh"
args = [
  "-c",
  "payload=$(cat); case \"$payload\" in *external-agent-input*) printf 'finish\\texternal-provider-ok\\n' ;; *) printf 'unexpected input\\n' >&2; exit 7 ;; esac"
]
timeout_millis = 1000

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "agent-client"
name = "Agent client"
key = "agent-secret"
scopes = ["agent.runs.create", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"
"#
    )
}

fn mcp_config(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
platform_operator = true

[[extensions]]
id = "mcp.http"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["github.search"]
network = ["127.0.0.1"]
filesystem = false
shell = false

[extensions.config]
endpoint = "http://{mcp_addr}/mcp"
timeout_ms = 3000
"#
    )
}

fn approval_mcp_config(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
# `tool_approvals_bind_fingerprint_and_fail_closed` has two competing timing
# needs. Its mismatch/approve/deny cases require the pending approval to stay
# alive until the admin decision request lands -- under full-workspace scheduler
# contention a 1s TTL let the approval auto-expire first, so `decision()`
# returned `tool_approval_terminal` (Expired) instead of the fingerprint/decision
# outcome (the intermittent failure this file used to flake on). Its final case
# deliberately leaves an execute request to *fail closed by TTL auto-expiry*, so
# the TTL must still elapse within the client read timeout. Both hold once the
# TTL comfortably exceeds worst-case decision latency and stays under the (now
# 30s) client read deadline in `support::http_request`.
tool_approval_timeout_secs = 8

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

[[extensions]]
id = "mcp.http"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10
approval_policy = "always"

[extensions.permissions]
tools = ["github.search"]
network = ["127.0.0.1"]
filesystem = false
shell = false

[extensions.config]
endpoint = "http://{mcp_addr}/mcp"
timeout_ms = 3000
"#
    )
}

fn approval_mcp_config_two_tenants(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
tool_approval_timeout_secs = 5

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "admin-a"
name = "Tenant A admin-console session key"
key = "admin-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-iso-a"

[[api_keys]]
id = "admin-b"
name = "Tenant B admin-console session key"
key = "admin-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-iso-b"

[[api_keys]]
id = "tool-client-a"
name = "Tenant A tool client"
key = "tool-secret-a"
scopes = ["tools.read", "tools.execute"]
organization_id = "tenant-iso-a"

[[extensions]]
id = "mcp.http"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10
approval_policy = "always"

[extensions.permissions]
tools = ["github.search"]
network = ["127.0.0.1"]
filesystem = false
shell = false

[extensions.config]
endpoint = "http://{mcp_addr}/mcp"
timeout_ms = 3000
"#
    )
}

fn non_blocking_hook_failure_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read"]
platform_operator = true

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]

[[extensions]]
id = "hook.noop"
kind = "request_hook"
source = "builtin"
enabled = true
order = 20

[extensions.config]
fail_pre_request = true
"#
    )
}

fn p3_mcp_config(
    gateway_addr: &str,
    mcp_addr: &str,
    provider_addr: &str,
    otlp_addr: &str,
) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[observability]
enabled = true
provider = "vector"
otlp_endpoint = "http://{otlp_addr}"
prometheus_metrics_path = "/metrics"
export_timeout_secs = 3

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "blocked-client"
name = "Blocked tool client"
key = "blocked-secret"
scopes = ["tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[policies]]
name = "deny blocked client MCP search"
effect = "deny"
api_key_ids = ["blocked-client"]
models = ["mcp_tool:github-search"]
providers = ["mcp:github"]
code = "mcp_policy_denied"
message = "MCP search is blocked"

[[mcp_servers]]
name = "github"
transport = "streamable_http"
url = "http://{mcp_addr}/mcp"
auth_type = "headers"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
tool_include = ["search"]
timeout_ms = 3000
health_ping_interval_secs = 10
max_reconnect_attempts = 5
min_reconnect_backoff_secs = 1
max_reconnect_backoff_secs = 30

[[mcp_servers.headers]]
name = "Authorization"
value = "Bearer upstream-mcp-secret"
"#
    )
}

fn p3_stdio_mcp_config(gateway_addr: &str, script: &Path) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

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

fn p3_slow_mcp_config(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
mcp_dispatch_timeout_secs = 1
mcp_dispatch_max_concurrency = 2

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[mcp_servers]]
name = "github"
transport = "streamable_http"
url = "http://{mcp_addr}/mcp"
tools_to_execute = ["search"]
tool_include = ["search"]
timeout_ms = 5000
"#
    )
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn wait_for_observability_ok(gateway_addr: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut last = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
        let body = response_json(http_request(
            gateway_addr,
            "GET",
            "/admin/v1/observability",
            &["Authorization: Bearer admin-secret"],
            "",
        ));
        if body["data"][0]["health"] == "ok" {
            return body;
        }
        last = body;
        thread::sleep(Duration::from_millis(250));
    }
    panic!("observability exporter did not become ok: {last}");
}

fn wait_for_mcp_server_connected(gateway_addr: &str, name: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    let mut last = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
        let body = response_json(http_request(
            gateway_addr,
            "GET",
            "/admin/v1/mcp-servers",
            &["Authorization: Bearer admin-secret"],
            "",
        ));
        if let Some(status) = body["data"]
            .as_array()
            .and_then(|statuses| statuses.iter().find(|status| status["name"] == name))
        {
            if status["connected"] == true {
                return status.clone();
            }
        }
        last = body;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("MCP server {name} did not become connected: {last}");
}

fn wait_for_pending_approval(gateway_addr: &str, exclude_ids: &[&str]) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut last = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
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

fn approval_ids(gateway_addr: &str) -> Vec<String> {
    response_json(http_request(
        gateway_addr,
        "GET",
        "/admin/v1/tool-approvals",
        &["Authorization: Bearer admin-secret"],
        "",
    ))["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|approval| approval["id"].as_str().map(ToOwned::to_owned))
        .collect()
}

fn spawn_otlp_collector() -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream);
                    requests.push(request);
                    let body = r#"{"ok":true}"#;
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("OTLP mock accept failed: {error}"),
            }
        }
        requests
    });
    (addr, handle)
}

fn spawn_mcp_server(count: usize) -> (String, JoinHandle<Vec<String>>) {
    spawn_mcp_server_with_tool(count, "github.search")
}

fn spawn_mcp_server_with_tool(
    count: usize,
    tool_name: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => loop {
                    if std::time::Instant::now() >= deadline {
                        return requests;
                    }
                    thread::sleep(Duration::from_millis(10));
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                        Err(error) => panic!("MCP mock accept failed: {error}"),
                    }
                },
                Err(error) => panic!("MCP mock accept failed: {error}"),
            };
            let request = read_http_request(&mut stream);
            let body = if request.contains("\"initialize\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"mock-mcp","version":"1.0.0"}}}"#
            } else if request.contains("\"ping\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
            } else if request.contains("\"tools/list\"") {
                if tool_name == "search" {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"github.search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
                }
            } else if request.contains("\"github.write\"") || request.contains("\"write\"") {
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"tool not allowed"}}"#
            } else {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ferrogate-result"}]}}"#
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

fn spawn_slow_mcp_server() -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        while std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("slow MCP mock accept failed: {error}"),
            };
            let request = read_http_request(&mut stream);
            let body = if request.contains("\"initialize\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"mock-mcp","version":"1.0.0"}}}"#
            } else if request.contains("\"tools/list\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
            } else {
                thread::sleep(Duration::from_secs(2));
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"late-result"}]}}"#
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .ok();
        }
        requests
    });
    (addr, handle)
}

fn spawn_provider_upstream() -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        let body = r#"{"id":"chatcmpl_tools","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

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

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_read = request.len().saturating_sub(header_end + 4);
            if body_read >= content_length(&request[..header_end]) {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
                    .flatten()
            })
        })
        .unwrap_or(0)
}
