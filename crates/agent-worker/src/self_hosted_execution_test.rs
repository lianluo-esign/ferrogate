// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Report-only self-hosted execution vs cloud enforcement (issue #242).

use std::collections::BTreeSet;

use ferrogate_runtime::{
    CapabilityAuthorizationDecision, CapabilityPolicy, ClassOnlyPolicyMode, FrameworkAdapterMode,
    ManagedCliAction, SimpleCapabilityAuthorizer,
};

use super::*;
use crate::external_actions::RuntimeGatewayExternalActionAuthorizer;
use crate::local_process_backend::local_process_backend_readiness;
use crate::test_support::lock_firecracker_env;

/// A gateway authorizer whose policy DENIES the CLI capability: cloud would
/// block it, self-hosted must record it as report-only.
fn denying_authorizer() -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::new(),
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn workload_action() -> ManagedCliAction {
    ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf 'ferrogate self-hosted report-only workload\\n'".to_string(),
        ],
        working_dir: crate::local_process_backend::WORKSPACE_MOUNTPOINT.to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    }
}

#[test]
fn self_hosted_identity_expiry_is_stamped_by_the_server_clock() {
    assert_eq!(
        self_hosted_identity_expiry(1_000),
        1_000 + SELF_HOSTED_IDENTITY_TTL_MILLIS
    );
    // Saturating: a server clock near u64::MAX never panics.
    assert_eq!(self_hosted_identity_expiry(u64::MAX), u64::MAX);
}

#[test]
fn self_hosted_report_only_runs_a_denied_workload_through_the_local_process_backend() {
    let _env_lock = lock_firecracker_env();
    if let Err(reason) = local_process_backend_readiness() {
        eprintln!(
            "self-hosted report-only: unprivileged namespace stack unavailable ({reason}); \
             skipping the workload-run assertion"
        );
        return;
    }

    let execution = run_governed_cli_workload(
        FrameworkAdapterMode::SelfHosted,
        &self_hosted_smoke_session(),
        &denying_authorizer(),
        workload_action(),
        false,
        1_000,
    )
    .expect("self-hosted report-only execution must never block");

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

    // Report-only boundary + server-clock identity expiry.
    assert_eq!(
        execution.enforcement_boundary,
        SELF_HOSTED_ENFORCEMENT_BOUNDARY
    );
    assert_eq!(execution.execution_owner, SELF_HOSTED_EXECUTION_OWNER);
    assert_eq!(
        execution.identity_expiry_unix_millis,
        1_000 + SELF_HOSTED_IDENTITY_TTL_MILLIS
    );

    // The workload really ran through the local-process backend.
    assert!(execution.workload_ran);
    assert_eq!(execution.workload_exit_code, Some(0));
    assert_eq!(execution.backend_name, "local-process");
    assert!(
        execution
            .workload_output
            .contains("ferrogate self-hosted report-only workload"),
        "workload output missing: {}",
        execution.workload_output
    );

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

#[test]
fn cloud_enforces_and_blocks_the_same_denied_capability() {
    let _env_lock = lock_firecracker_env();
    // No readiness guard needed: cloud must block BEFORE any host work runs, so
    // the local-process backend is never touched on a denied capability.
    let error = run_governed_cli_workload(
        FrameworkAdapterMode::Managed,
        &self_hosted_smoke_session(),
        &denying_authorizer(),
        workload_action(),
        false,
        1_000,
    )
    .expect_err("cloud must enforce and block a denied capability");

    let message = error.to_string();
    assert!(
        message.contains("blocks capability"),
        "cloud block message missing: {message}"
    );
    assert!(message.contains("ferrogate_managed_runtime"), "{message}");
}

#[test]
fn cloud_allows_and_runs_an_allowed_capability() {
    let _env_lock = lock_firecracker_env();
    if let Err(reason) = local_process_backend_readiness() {
        eprintln!("cloud allow path: namespace stack unavailable ({reason}); skipping");
        return;
    }
    let authorizer = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([ferrogate_runtime::CapabilityAction::Cli]),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));

    let execution = run_governed_cli_workload(
        FrameworkAdapterMode::Managed,
        &self_hosted_smoke_session(),
        &authorizer,
        workload_action(),
        false,
        1_000,
    )
    .expect("cloud must run an allowed capability");

    assert!(!execution.report_only());
    assert!(!execution.cloud_would_block());
    assert_eq!(
        execution.recorded_decision(),
        CapabilityAuthorizationDecision::Allowed
    );
    assert_eq!(execution.enforcement_boundary, CLOUD_ENFORCEMENT_BOUNDARY);
    assert!(execution.workload_ran);
    assert_eq!(execution.workload_exit_code, Some(0));
}

#[test]
fn cloud_enforces_and_blocks_a_denied_firecracker_workload_before_any_boot() {
    let _env_lock = lock_firecracker_env();
    // Cloud enforcement blocks on the denied capability BEFORE the microVM is
    // provisioned, so no KVM/firecracker host work happens. This asserts the
    // enforce side of the #247 Firecracker report-only path WITHOUT needing KVM:
    // the block occurs before `firecracker_microvm_provision` is ever called.
    let error = run_governed_firecracker_workload(
        FrameworkAdapterMode::Managed,
        &self_hosted_smoke_session(),
        &denying_authorizer(),
        workload_action(),
        false,
        1_000,
        FirecrackerBootParameters {
            timeout_millis: 15_000,
            vcpu_count: 1,
            mem_size_mib: 256,
        },
    )
    .expect_err("cloud must enforce and block a denied firecracker capability");

    let message = error.to_string();
    assert!(
        message.contains("blocks capability"),
        "cloud block message missing: {message}"
    );
    assert!(message.contains("ferrogate_managed_runtime"), "{message}");
    // The block happened before any boot: no firecracker/KVM fail-closed text.
    assert!(
        !message.contains("firecracker microVM boot failed"),
        "cloud enforce path attempted a microVM boot: {message}"
    );
}

#[test]
fn report_only_exec_marker_carries_the_customer_owned_host_contract() {
    let marker = self_hosted_report_only_exec_marker("cli", "agent://managed/readiness", 2_000);
    assert!(
        marker.contains("enforcement_boundary=customer_owned_host"),
        "{marker}"
    );
    assert!(marker.contains("execution_owner=customer"), "{marker}");
    assert!(
        marker.contains("trust_level=reported_by_self_hosted_worker"),
        "{marker}"
    );
    assert!(marker.contains("identity_expiry_clock=server"), "{marker}");
    assert!(
        marker.contains(&format!(
            "identity_expiry_unix_millis={}",
            2_000 + SELF_HOSTED_IDENTITY_TTL_MILLIS
        )),
        "{marker}"
    );
}
