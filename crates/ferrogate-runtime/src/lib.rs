// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Pingora runtime boundary.

mod agent;
mod reload;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use agent::{
    AgentCancellation, AgentContext, AgentHarness, AgentHarnessConfig, AgentProvider,
    AgentRunEvent, AgentRunEventKind, AgentRunEventSink, AgentRunInput, AgentRunOutcome,
    AgentRunStatus, AgentRuntimeError, AgentRuntimeResult, AgentStep, AgentToolDispatchRequest,
    ExternalAgentProvider, ExternalAgentProviderConfig, GovernedAgentToolDispatcher,
};
pub use reload::{ReloadCandidate, ReloadCoordinator, ReloadOutcome, RuntimeSnapshot};

/// Runtime lifecycle commands exposed by the CLI and future control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    Run,
    Validate,
    Reload,
}
