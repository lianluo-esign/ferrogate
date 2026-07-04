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
fn governed_tool_execution_smoke_command_fails_closed_for_self_hosted_mode() {
    // Proves the mode argument actually reaches the command end-to-end
    // (main.rs -> governed_tool_execution_smoke_command -> smoke_session ->
    // the gate), not just the standalone smoke_session() unit above. Nothing
    // in this build implements report-only, non-enforced execution yet, so
    // self-hosted must be rejected here rather than silently running as
    // managed (issue #148) or panicking on an unreachable code path.
    let error = governed_tool_execution_smoke_command(FrameworkAdapterMode::SelfHosted)
        .expect_err("self-hosted governed tool smoke command must fail closed");
    assert!(error
        .to_string()
        .contains("only enforces managed worker sessions"));
}
