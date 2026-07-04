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
    reject_unsupported_self_hosted_execution(WorkerType::Cloud, &Command::GovernedToolExecutionSmoke)
        .expect("cloud must be allowed on a real execution subcommand");
    reject_unsupported_self_hosted_execution(WorkerType::Cloud, &Command::WorkerType)
        .expect("cloud must be allowed on the diagnostic command");
}

#[test]
fn self_hosted_worker_type_is_allowed_on_the_diagnostic_command_only() {
    reject_unsupported_self_hosted_execution(WorkerType::SelfHosted, &Command::WorkerType)
        .expect("the worker-type diagnostic must never be rejected");
}

#[test]
fn self_hosted_worker_type_is_rejected_on_real_execution_subcommands() {
    // Sample across a few command families named in issue #148 (the smoke
    // family and the two real serving commands) rather than just one, since
    // the point of the guard is that it applies uniformly.
    for command in [
        Command::GovernedToolExecutionSmoke,
        Command::GovernedCliExecutionSmoke,
        Command::ExternalActionSmoke,
    ] {
        let error = reject_unsupported_self_hosted_execution(WorkerType::SelfHosted, &command)
            .expect_err("self-hosted must be rejected for real execution subcommands");
        assert!(error.to_string().contains("--worker-type self-hosted"));
        assert!(error.to_string().contains("issue #148"));
    }
}
