// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-05
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for #148: every governed execution smoke command builds its
//! `FrameworkAdapterSession` via `smoke_session(mode)`, so the mode argument
//! threaded in from `main.rs`'s `cli.worker_type` (rather than a hardcoded
//! `FrameworkAdapterMode::Managed`) is what ends up on the session. The gate
//! (`validate_managed_worker_session`) has always fail-closed rejected
//! non-managed sessions; before this fix that rejection was unreachable
//! because `smoke_session()` ignored its caller's worker type entirely.

use super::*;

#[test]
fn smoke_session_uses_the_managed_mode_it_is_given() {
    let session = smoke_session(FrameworkAdapterMode::Managed);
    assert_eq!(session.mode, FrameworkAdapterMode::Managed);
}

#[test]
fn smoke_session_uses_the_self_hosted_mode_it_is_given() {
    let session = smoke_session(FrameworkAdapterMode::SelfHosted);
    assert_eq!(session.mode, FrameworkAdapterMode::SelfHosted);
}

#[test]
fn governed_tool_execution_smoke_command_runs_report_only_for_self_hosted_mode() {
    // Proves the mode argument reaches the command end-to-end (main.rs ->
    // governed_tool_execution_smoke_command). #242 first wired report-only
    // self-hosted execution; #245 extends it to the decoupled governed families
    // including tool execution: self-hosted now runs the workload report-only
    // (recording, not enforcing, the gateway decision) instead of failing
    // closed. The per-family report-only/enforce contract is asserted in
    // external_actions_self_hosted_family_test.rs.
    governed_tool_execution_smoke_command(FrameworkAdapterMode::SelfHosted)
        .expect("self-hosted governed tool smoke command must run report-only");
}
