// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Per-family report-only self-hosted execution vs cloud enforcement (issue
//! #245, extending the #242 CLI slice).
//!
//! For each decoupled governed external-action family (tool, MCP tool, skill,
//! browser, memory, secret) this proves the exact #242 distinction: under a
//! policy that would DENY the capability, a self-hosted worker still runs the
//! workload and records the decision as report-only, while a cloud (managed)
//! worker blocks the workload before it runs. Both anchor on the same
//! managed-probe gateway decision, so the report faithfully states what cloud
//! would have decided.

// The governed action types, `CapabilityPolicy`, `CapabilityAuthorizationDecision`,
// `FrameworkAdapterMode`, and `SimpleCapabilityAuthorizer` come in via `super::*`
// (the parent module's imports). Only the names the parent does not import are
// pulled in explicitly here.
use ferrogate_runtime::{ClassOnlyPolicyMode, SelfHostedTelemetryTrustLevel};

use super::*;
use crate::self_hosted_execution::{
    GovernedCapabilityDisposition, CLOUD_ENFORCEMENT_BOUNDARY, SELF_HOSTED_ENFORCEMENT_BOUNDARY,
    SELF_HOSTED_EXECUTION_OWNER, SELF_HOSTED_IDENTITY_TTL_MILLIS,
};

/// A gateway authorizer whose policy DENIES every capability: cloud would block
/// it, self-hosted must record it as report-only.
fn denying_authorizer() -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: std::collections::BTreeSet::new(),
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn tool_action() -> ManagedExternalAction {
    ManagedExternalAction::Tool(ManagedToolAction {
        tool_name: "native.echo".to_string(),
        arguments_policy: "smoke_literal:ferrogate self-hosted tool report-only".to_string(),
    })
}

fn mcp_action() -> ManagedExternalAction {
    ManagedExternalAction::McpTool(ManagedMcpToolAction {
        server_name: "local-smoke".to_string(),
        tool_name: "echo".to_string(),
        arguments_policy: "exact_arguments".to_string(),
        arguments: serde_json::json!({"message": "ferrogate self-hosted mcp report-only"}),
    })
}

fn skill_action() -> ManagedExternalAction {
    ManagedExternalAction::Skill(ManagedSkillAction {
        skill_id: "builtin.skill.echo".to_string(),
        declared_capabilities: vec!["tools".to_string(), "memory.read".to_string()],
    })
}

fn browser_action() -> ManagedExternalAction {
    ManagedExternalAction::Browser(ManagedBrowserAction {
        operation: ManagedBrowserOperation::Navigate,
        url: "about:blank".to_string(),
        timeout_millis: 2_000,
    })
}

fn memory_action() -> ManagedExternalAction {
    ManagedExternalAction::Memory(ManagedMemoryAction {
        access: ManagedMemoryAccess::Write,
        namespace: "session".to_string(),
        key: "summary".to_string(),
    })
}

fn secret_action() -> ManagedExternalAction {
    ManagedExternalAction::Secret(ManagedSecretAction {
        secret_id: "vault/openai-api-key".to_string(),
        purpose: "provider_call".to_string(),
    })
}

/// Assert the self-hosted run of `action` executed report-only: the workload
/// ran, and the denied gateway decision was recorded (never enforced).
fn assert_self_hosted_report_only(action: ManagedExternalAction, expected_backend: &str) {
    let execution = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &denying_authorizer(),
        action,
        false,
        1_000,
    )
    .expect("self-hosted report-only execution must never block");
    assert_report_only_contract(&execution, expected_backend);
}

/// Assert one already-executed self-hosted run carries the full report-only
/// customer-owned-host contract. Split from `assert_self_hosted_report_only` so
/// the network/REST tests (which stand up a live loopback listener and run the
/// workload themselves to observe the real I/O) reuse the same assertions.
fn assert_report_only_contract(execution: &GovernedWorkloadExecution, expected_backend: &str) {
    // The capability cloud would BLOCK ran anyway and was only recorded.
    assert!(execution.report_only());
    assert!(execution.cloud_would_block());
    assert_ne!(
        execution.recorded_decision(),
        CapabilityAuthorizationDecision::Allowed
    );
    assert!(matches!(
        execution.disposition,
        GovernedCapabilityDisposition::ReportOnly {
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
            ..
        }
    ));

    // Report-only boundary + server-clock identity expiry (customer host is not
    // trusted to set its own identity lifetime).
    assert_eq!(
        execution.enforcement_boundary,
        SELF_HOSTED_ENFORCEMENT_BOUNDARY
    );
    assert_eq!(execution.execution_owner, SELF_HOSTED_EXECUTION_OWNER);
    assert_eq!(
        execution.identity_expiry_unix_millis,
        1_000 + SELF_HOSTED_IDENTITY_TTL_MILLIS
    );

    // The workload really ran through the in-process governed handler.
    assert!(execution.workload_ran);
    assert_eq!(execution.workload_exit_code, Some(0));
    assert_eq!(execution.backend_name, expected_backend);

    // Evidence JSON carries the report-only capability contract.
    let evidence = execution.evidence_json();
    assert_eq!(evidence["worker_type"], "self-hosted");
    assert_eq!(evidence["capability_enforcement"], "reported");
    assert_eq!(evidence["enforcement_boundary"], "customer_owned_host");
    assert_eq!(evidence["execution_owner"], "customer");
    assert_eq!(evidence["trust_level"], "reported_by_self_hosted_worker");
    assert_eq!(evidence["report_only"], true);
    assert_eq!(evidence["cloud_would_block"], true);
    assert_eq!(evidence["identity_expiry_clock"], "server");
}

/// Assert the cloud (managed) run of `action` enforced the denied decision: it
/// blocked before any workload ran.
fn assert_cloud_enforces_and_blocks(action: ManagedExternalAction) {
    let error = run_governed_family_report_only(
        FrameworkAdapterMode::Managed,
        &smoke_session(FrameworkAdapterMode::Managed),
        &denying_authorizer(),
        action,
        false,
        1_000,
    )
    .expect_err("cloud must enforce and block a denied capability");

    let message = error.to_string();
    assert!(
        message.contains("blocks capability"),
        "cloud block message missing: {message}"
    );
    assert!(
        message.contains(CLOUD_ENFORCEMENT_BOUNDARY),
        "cloud block message missing boundary: {message}"
    );
}

#[test]
fn self_hosted_tool_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(tool_action(), "governed-tool-handler");
    assert_cloud_enforces_and_blocks(tool_action());
}

#[test]
fn self_hosted_mcp_tool_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(mcp_action(), "governed-mcp-tool-handler");
    assert_cloud_enforces_and_blocks(mcp_action());
}

#[test]
fn self_hosted_skill_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(skill_action(), "governed-skill-handler");
    assert_cloud_enforces_and_blocks(skill_action());
}

#[test]
fn self_hosted_browser_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(browser_action(), "governed-browser-handler");
    assert_cloud_enforces_and_blocks(browser_action());
}

#[test]
fn self_hosted_memory_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(memory_action(), "governed-memory-handler");
    assert_cloud_enforces_and_blocks(memory_action());
}

#[test]
fn self_hosted_secret_runs_report_only_while_cloud_blocks() {
    assert_self_hosted_report_only(secret_action(), "governed-secret-handler");
    assert_cloud_enforces_and_blocks(secret_action());
}

#[test]
fn cli_and_filesystem_are_not_routed_through_the_in_process_family_workload() {
    // CLI/filesystem authorized execution is bound to the ALLOW decision's
    // canonical-target fingerprint, so a denied capability cannot run through
    // the in-process family workload. The self-hosted run must refuse honestly
    // rather than pretend to have executed. (CLI report-only-on-deny is covered
    // by the #242 self-hosted-governed-execution-smoke local-process path.)
    let cli = ManagedExternalAction::Cli(ferrogate_runtime::ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "true".to_string()],
        working_dir: "/".to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    });
    let error = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &denying_authorizer(),
        cli,
        false,
        1_000,
    )
    .expect_err("cli must not route through the in-process family workload");
    assert!(error.to_string().contains("canonical-target fingerprint"));
}

// ---------------------------------------------------------------------------
// #247: network-egress + REST report-only vs cloud enforcement.
//
// These families perform real loopback outbound I/O. The self-hosted assertion
// stands up a controlled loopback listener (deterministic, like the existing
// adversarial/perf harnesses), runs the report-only workload against it, and
// proves BOTH that the I/O happened AND the denied decision was recorded with
// the full customer-owned-host contract. The cloud assertion uses a
// nonblocking listener and proves the enforce path blocks the same denied
// capability BEFORE any connection is made (no I/O).
// ---------------------------------------------------------------------------

fn network_egress_action(port: u16) -> ManagedExternalAction {
    ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
        host: "127.0.0.1".to_string(),
        port,
        protocol: "tcp".to_string(),
        resolved_ips: vec!["127.0.0.1".to_string()],
    })
}

fn rest_action(endpoint: std::net::SocketAddr) -> ManagedExternalAction {
    ManagedExternalAction::Rest(ManagedRestAction {
        method: "GET".to_string(),
        url: format!("http://{endpoint}/governed-rest-smoke"),
        headers_policy: "deny_credentials".to_string(),
        body_policy: "empty_body".to_string(),
        timeout_millis: 2_000,
        retry_limit: 0,
        resolved_ips: vec!["127.0.0.1".to_string()],
        redirect_chain: Vec::new(),
    })
}

/// Assert the cloud (managed) run of `action` blocked the denied capability
/// before making any connection to `blocked_listener` (no I/O).
fn assert_cloud_blocks_without_io(action: ManagedExternalAction, blocked_listener: &TcpListener) {
    let error = run_governed_family_report_only(
        FrameworkAdapterMode::Managed,
        &smoke_session(FrameworkAdapterMode::Managed),
        &denying_authorizer(),
        action,
        false,
        1_000,
    )
    .expect_err("cloud must enforce and block a denied network/REST capability");
    let message = error.to_string();
    assert!(
        message.contains("blocks capability"),
        "cloud block message missing: {message}"
    );
    assert!(
        message.contains(CLOUD_ENFORCEMENT_BOUNDARY),
        "cloud block message missing boundary: {message}"
    );
    // No connection ever reached the listener: cloud blocked before any I/O.
    assert!(
        matches!(
            blocked_listener.accept(),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "cloud enforce path performed loopback I/O on a denied capability"
    );
}

#[test]
fn self_hosted_network_egress_runs_report_only_while_cloud_blocks() {
    // (i) self-hosted: the egress really happens against a live listener and the
    // denied decision is recorded report-only.
    let server = spawn_one_shot_network_egress_smoke_server();
    let execution = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &denying_authorizer(),
        network_egress_action(server.endpoint.port()),
        false,
        1_000,
    )
    .expect("self-hosted network egress report-only must never block");
    let received_payload = server.join().expect("network egress server thread");

    assert_eq!(
        received_payload, "ferrogate governed network smoke\n",
        "self-hosted report-only egress did not perform the real loopback I/O"
    );
    assert_report_only_contract(&execution, "governed-network-egress-handler");

    // (ii) cloud: the same denied capability blocks with NO I/O.
    let blocked_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    blocked_listener
        .set_nonblocking(true)
        .expect("set cloud-block listener nonblocking");
    let blocked_port = blocked_listener.local_addr().unwrap().port();
    assert_cloud_blocks_without_io(network_egress_action(blocked_port), &blocked_listener);
}

#[test]
fn self_hosted_rest_runs_report_only_while_cloud_blocks() {
    // (i) self-hosted: the REST request is really served by a live loopback HTTP
    // listener and the denied decision is recorded report-only.
    let server = spawn_one_shot_rest_smoke_server();
    let execution = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &denying_authorizer(),
        rest_action(server.endpoint),
        false,
        1_000,
    )
    .expect("self-hosted REST report-only must never block");
    let served_request = server.join().expect("rest server thread");

    assert!(
        served_request.contains("GET /governed-rest-smoke"),
        "self-hosted report-only REST did not perform the real loopback request: {served_request}"
    );
    assert_report_only_contract(&execution, "governed-rest-handler");

    // (ii) cloud: the same denied capability blocks with NO I/O.
    let blocked_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    blocked_listener
        .set_nonblocking(true)
        .expect("set cloud-block listener nonblocking");
    let blocked_endpoint = blocked_listener.local_addr().unwrap();
    assert_cloud_blocks_without_io(rest_action(blocked_endpoint), &blocked_listener);
}
