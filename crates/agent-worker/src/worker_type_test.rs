// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-05
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the `--worker-type` -> `FrameworkAdapterMode` mapping (#148):
//! this is the value threaded into every governed execution smoke command so
//! `--worker-type self-hosted` actually changes enforcement semantics instead
//! of only being read by the diagnostic `print_worker_type` command.

use super::*;

#[test]
fn cloud_worker_type_maps_to_managed_framework_adapter_mode() {
    assert_eq!(
        WorkerType::Cloud.framework_adapter_mode(),
        ferrogate_runtime::FrameworkAdapterMode::Managed
    );
}

#[test]
fn self_hosted_worker_type_maps_to_self_hosted_framework_adapter_mode() {
    assert_eq!(
        WorkerType::SelfHosted.framework_adapter_mode(),
        ferrogate_runtime::FrameworkAdapterMode::SelfHosted
    );
}

#[test]
fn cloud_worker_type_is_allowed_on_every_subcommand() {
    reject_unsupported_self_hosted_execution(
        WorkerType::Cloud,
        &Command::GovernedToolExecutionSmoke,
    )
    .expect("cloud must be allowed on a real execution subcommand");
    reject_unsupported_self_hosted_execution(WorkerType::Cloud, &Command::WorkerType)
        .expect("cloud must be allowed on the diagnostic command");
}

#[test]
fn self_hosted_worker_type_is_allowed_on_the_diagnostic_command() {
    reject_unsupported_self_hosted_execution(WorkerType::SelfHosted, &Command::WorkerType)
        .expect("the worker-type diagnostic must never be rejected");
    assert_eq!(
        self_hosted_command_support(&Command::WorkerType),
        SelfHostedCommandSupport::Diagnostic
    );
}

#[test]
fn self_hosted_worker_type_runs_report_only_on_the_covered_commands() {
    // The management-serving path and the dedicated governed execution
    // entrypoint are the first slice covered under self-hosted (#242); #245
    // extends real report-only execution to the decoupled governed families.
    // All of these run real report-only execution and must NOT fail closed.
    let covered = [
        Command::SelfHostedGovernedExecutionSmoke {
            now_unix_millis: Some(1_000),
        },
        Command::AcceptManagementJson {
            key_id: "k".to_string(),
            shared_secret: "s".to_string(),
            now_unix_millis: None,
        },
        // #245 decoupled governed families.
        Command::GovernedToolExecutionSmoke,
        Command::GovernedMcpToolExecutionSmoke,
        Command::GovernedSkillExecutionSmoke,
        Command::GovernedMemoryExecutionSmoke,
        Command::GovernedSecretExecutionSmoke,
        Command::GovernedBrowserExecutionSmoke,
    ];
    for command in covered {
        assert_eq!(
            self_hosted_command_support(&command),
            SelfHostedCommandSupport::ReportOnly,
            "{command:?} must be a covered report-only command"
        );
        reject_unsupported_self_hosted_execution(WorkerType::SelfHosted, &command)
            .expect("covered self-hosted commands must not fail closed");
    }
}

#[test]
fn self_hosted_worker_type_is_rejected_on_uncovered_execution_subcommands() {
    // Families not yet wired for report-only self-hosted execution stay
    // fail-closed rather than silently running as cloud. CLI/filesystem are
    // canonical-target-fingerprint bound; network-egress/REST do live loopback
    // I/O; the external-action authorization smokes are authorization-only. The
    // message must be accurate and reference the tracking issue (#245).
    for command in [
        Command::GovernedCliExecutionSmoke,
        Command::GovernedFilesystemExecutionSmoke,
        Command::GovernedNetworkEgressExecutionSmoke,
        Command::GovernedRestExecutionSmoke,
        Command::ExternalActionSmoke,
    ] {
        assert_eq!(
            self_hosted_command_support(&command),
            SelfHostedCommandSupport::FailClosed
        );
        let error = reject_unsupported_self_hosted_execution(WorkerType::SelfHosted, &command)
            .expect_err("self-hosted must be rejected for uncovered execution subcommands");
        assert!(error.to_string().contains("--worker-type self-hosted"));
        assert!(error.to_string().contains("TODO(#245)"));
    }
}
