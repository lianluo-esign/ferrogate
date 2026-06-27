// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Pingora runtime boundary.

mod agent;
mod framework_adapter;
mod isolation;
mod managed_worker;
mod reload;
mod self_hosted_worker;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use agent::{
    AgentCancellation, AgentContext, AgentHarness, AgentHarnessConfig, AgentProvider,
    AgentRunEvent, AgentRunEventKind, AgentRunEventSink, AgentRunInput, AgentRunOutcome,
    AgentRunStatus, AgentRuntimeError, AgentRuntimeResult, AgentStep, AgentToolDispatchRequest,
    ExternalAgentProvider, ExternalAgentProviderConfig, GovernedAgentToolDispatcher,
};
pub use framework_adapter::{
    FrameworkAdapter, FrameworkAdapterCapabilities, FrameworkAdapterDescriptor,
    FrameworkAdapterError, FrameworkAdapterEventKind, FrameworkAdapterMode,
    FrameworkAdapterRunRequest, FrameworkAdapterSession, FrameworkAdapterSessionRequest,
    NativeHarnessAdapter, NormalizedFrameworkEvent, SupportedFramework,
};
pub use isolation::{
    select_isolation_backend, CollectedIsolationArtifacts, CollectedIsolationLogs,
    IsolationArtifact, IsolationBackendCapabilities, IsolationBackendDescriptor,
    IsolationBackendKind, IsolationBackendLifecycle, IsolationCleanupOutcome, IsolationError,
    IsolationExecOutcome, IsolationExecRequest, IsolationFilesystemPolicy,
    IsolationLifecycleEvidence, IsolationNetworkPolicy, IsolationPolicy, IsolationPrepareRequest,
    IsolationPrepared, IsolationResourceLimits, IsolationResult, IsolationSnapshotOutcome,
    IsolationStarted, IsolationStopOutcome,
};
pub use managed_worker::{
    AgentWorkerControlClient, ManagedWorkerError, ManagedWorkerExecution, ManagedWorkerRunRequest,
    ManagedWorkerScheduler, ManagedWorkerSchedulerConfig, ManagedWorkerSession,
    ManagedWorkerSessionRequest, ManagedWorkerSessionStatus, WorkerTemplate,
};
pub use reload::{ReloadCandidate, ReloadCoordinator, ReloadOutcome, RuntimeSnapshot};
pub use self_hosted_worker::{
    RegisteredSelfHostedWorker, SelfHostedTelemetryEvent, SelfHostedTelemetryIngestor,
    SelfHostedTelemetryKind, SelfHostedTelemetryRequest, SelfHostedTelemetryTrustLevel,
    SelfHostedWorkerError, SelfHostedWorkerHeartbeat, SelfHostedWorkerIdentity,
    SelfHostedWorkerRegistration, SelfHostedWorkerRegistry,
};
#[cfg(feature = "wasm")]
pub use wasm::{
    WasmHostAbi, WasmHostRunOutcome, WasmRunOutcome, WasmSandboxConfig, WasmSandboxError,
    WasmSandboxExecutor,
};

/// Runtime lifecycle commands exposed by the CLI and future control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    Run,
    Validate,
    Reload,
}
