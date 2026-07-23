// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Pingora runtime boundary.

mod action_identity;
mod agent;
mod capability_boundary;
mod cloudflare_gateway_control;
mod cloudflare_gateway_deploy;
mod cloudflare_worker;
mod framework_adapter;
mod function_egress;
mod function_token;
mod isolation;
mod managed_external_action;
mod managed_worker;
mod reload;
mod self_hosted_mtls;
mod self_hosted_worker;
mod supabase_edge_function;
mod target_capability;

pub use action_identity::{
    audit_outcome_from_action_decision, capability_decision_from_action_decision, decision_codes,
    guardrail_outcome_from_action_decision, is_canonical_action_fingerprint, ActingPrincipal,
    ActionContext, ActionDecision, ActionIdentity, ActionReceipt, AuditOutcome, DecisionReason,
    GuardrailEnforcement, GuardrailOutcome, GuardrailOutcomeParseError, GuardrailTriggeredAction,
    GuardrailVerdict, OutputDisposition, UnknownAuditOutcome, ACTION_FINGERPRINT_CONTRACT,
};
pub use agent::{
    AgentCancellation, AgentContext, AgentHarness, AgentHarnessConfig, AgentProvider,
    AgentRunEvent, AgentRunEventKind, AgentRunEventSink, AgentRunInput, AgentRunOutcome,
    AgentRunStatus, AgentRuntimeError, AgentRuntimeResult, AgentStep, AgentToolDispatchRequest,
    ExternalAgentProvider, ExternalAgentProviderConfig, GovernedAgentToolDispatcher,
};
pub use capability_boundary::{
    self_hosted_trust_level_for_capability_report, CapabilityAction,
    CapabilityAuthorizationDecision, CapabilityAuthorizationEvidence,
    CapabilityAuthorizationOutcome, CapabilityAuthorizer, CapabilityBoundaryError,
    CapabilityPolicy, CapabilityTargetGrant, ManagedCapabilityRequest, SimpleCapabilityAuthorizer,
};
pub use cloudflare_gateway_control::{
    BlockingHttpControlTransport, GatewayControlTransport, WorkerGatewayControlSurface,
};
pub use cloudflare_gateway_deploy::{
    GatewayDeployOutcome, GatewayWorkerDeployer, GatewayWorkerSpec, DEFAULT_AGENT_DO_BINDING,
    DEFAULT_AGENT_DO_CLASS, DEFAULT_GATEWAY_SCRIPT_NAME, GATEWAY_MULTIPART_BOUNDARY,
};
pub use cloudflare_worker::{
    cloudflare_backend_descriptor, cloudflare_backend_descriptor_default,
    managed_worker_session_status_wire, CloudflareAgentControlClient, CloudflareControlSurface,
    CloudflareControlSurfaceError, CloudflareRunExecOutcome, CloudflareRunExecRequest,
    CloudflareRunHandle, CloudflareRunProps, CloudflareRunPropsResolver, CloudflareRunStartRequest,
    CloudflareRunStatus, MockCloudflareCall, MockCloudflareControlSurface, CLOUDFLARE_BACKEND_NAME,
    CLOUDFLARE_BACKEND_VERSION, CLOUDFLARE_HOST_LIFECYCLE_OWNER,
};
pub use framework_adapter::{
    authorize_framework_capability, self_hosted_framework_capability_report, FrameworkAdapter,
    FrameworkAdapterArtifact, FrameworkAdapterArtifactRequest, FrameworkAdapterArtifacts,
    FrameworkAdapterCapabilities, FrameworkAdapterDescriptor, FrameworkAdapterError,
    FrameworkAdapterEventKind, FrameworkAdapterMode, FrameworkAdapterResumeRequest,
    FrameworkAdapterRunRequest, FrameworkAdapterSession, FrameworkAdapterSessionRequest,
    FrameworkAdapterStreamRequest, FrameworkCapabilityRequest, FrameworkEventTimelineRecord,
    NativeHarnessAdapter, NormalizedFrameworkEvent, ProcessFrameworkAdapter,
    ProcessFrameworkLaunch, SupportedFramework,
};
pub use function_egress::{
    FunctionEgressAllowlist, FunctionEgressDenied, FunctionEgressRule, FunctionInvocationOutcome,
    FunctionInvocationRequest, ANY_FUNCTION_SLUG,
};
pub use function_token::{
    FunctionTokenClaims, FunctionTokenError, FunctionTokenMinter, DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    MAX_FUNCTION_TOKEN_TTL_SECS,
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
pub use managed_external_action::{
    authorize_managed_external_action, canonical_target_for_managed_action,
    managed_external_action_transport_failure_event, normalized_event_from_canonical_json,
    self_hosted_external_action_report, ExternalActionAuthorizationError,
    ExternalActionAuthorizationRequest, ExternalActionAuthorizationResponse,
    ExternalActionBrowserOperation, ExternalActionDecision, ExternalActionFilesystemAccess,
    ExternalActionFramework, ExternalActionMemoryAccess, ExternalActionMode, ExternalActionSession,
    ExternalActionSpec, GatewayExternalActionTransportRequest,
    GatewayExternalActionTransportResponse, ManagedBrowserAction, ManagedBrowserOperation,
    ManagedCliAction, ManagedExternalAction, ManagedExternalActionDecision,
    ManagedExternalActionRequest, ManagedFilesystemAccess, ManagedFilesystemAction,
    ManagedMcpToolAction, ManagedMemoryAccess, ManagedMemoryAction, ManagedNetworkEgressAction,
    ManagedRestAction, ManagedSecretAction, ManagedSkillAction, ManagedToolAction,
};
#[cfg(unix)]
pub use managed_worker::AgentWorkerUnixManagementClient;
pub use managed_worker::{
    AgentWorkerControlClient, AgentWorkerEncryptedPayload, AgentWorkerFrameworkArtifactResult,
    AgentWorkerFrameworkEventResult, AgentWorkerFrameworkHandler, AgentWorkerHttpManagementClient,
    AgentWorkerIsolationBackendReport, AgentWorkerLifecycleResult, AgentWorkerManagementAction,
    AgentWorkerManagementEnvelope, AgentWorkerManagementError, AgentWorkerManagementErrorCode,
    AgentWorkerManagementFrame, AgentWorkerManagementFrameEncoding, AgentWorkerManagementKey,
    AgentWorkerManagementResponse, AgentWorkerManagementResult, AgentWorkerManagementSecurity,
    AgentWorkerManagementTransport, AgentWorkerManagementVerification,
    AgentWorkerManagementVerifier, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    InMemoryAgentWorkerManagementTransport, ManagedWorkerCancellation, ManagedWorkerError,
    ManagedWorkerExecution, ManagedWorkerFailedExecution, ManagedWorkerFailure,
    ManagedWorkerLifecycleAction, ManagedWorkerLifecycleRecord, ManagedWorkerRunRequest,
    ManagedWorkerScheduler, ManagedWorkerSchedulerConfig, ManagedWorkerSession,
    ManagedWorkerSessionRequest, ManagedWorkerSessionStatus, WorkerTemplate,
    AGENT_WORKER_CLOCK_SKEW_MILLIS, AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES,
    AGENT_WORKER_PROTOCOL_VERSION, AGENT_WORKER_SYMMETRIC_AEAD_ALGORITHM,
};
pub use reload::{ReloadCandidate, ReloadCoordinator, ReloadOutcome, RuntimeSnapshot};
pub use self_hosted_mtls::{
    build_self_hosted_worker_client_config, connect_self_hosted_worker_client,
    IssuedSelfHostedWorkerCert, SelfHostedCertRevocationList, SelfHostedMtlsAdmissionError,
    SelfHostedMtlsCertIssuer, SelfHostedMtlsConnection, SelfHostedMtlsError,
    SelfHostedMtlsIngressAdmission, SelfHostedMtlsServer, SelfHostedMtlsTrustAnchor,
    SelfHostedTransportToken, SelfHostedTransportTokenIssuer, SelfHostedTransportTokenStore,
    SelfHostedWorkerCertBinding, VerifiedMutualTls, DEFAULT_SELF_HOSTED_CLIENT_CERT_TTL_SECS,
    DEFAULT_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS, MAX_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS,
    SELF_HOSTED_WORKER_SPIFFE_PREFIX,
};
pub use self_hosted_worker::{
    generate_transport_token_secret, production_mtls_transport_implemented,
    InMemorySelfHostedRunQueue, InMemorySelfHostedWorkerTransport, RegisteredSelfHostedWorker,
    SelfHostedArtifactUpload, SelfHostedArtifactUploadRequest, SelfHostedCheckpointFetchRequest,
    SelfHostedCheckpointReference, SelfHostedRunAck, SelfHostedRunAckRequest,
    SelfHostedRunAckStatus, SelfHostedRunAction, SelfHostedRunDispatch,
    SelfHostedRunEvidenceCorrelation, SelfHostedRunLease, SelfHostedRunPollRequest,
    SelfHostedRunQueueRecord, SelfHostedTelemetryEvent, SelfHostedTelemetryIngestor,
    SelfHostedTelemetryKind, SelfHostedTelemetryRequest, SelfHostedTelemetryTrustLevel,
    SelfHostedTransportAdmissionError, SelfHostedTransportChannel, SelfHostedTransportPolicy,
    SelfHostedTransportPosture, SelfHostedWorkerEncryptedPayload, SelfHostedWorkerError,
    SelfHostedWorkerHeartbeat, SelfHostedWorkerHttpTransportClient,
    SelfHostedWorkerHttpTransportSecurity, SelfHostedWorkerIdentity, SelfHostedWorkerRegistration,
    SelfHostedWorkerRegistry, SelfHostedWorkerTransport, SelfHostedWorkerTransportFrame,
    SelfHostedWorkerTransportFrameEncoding, SelfHostedWorkerTransportIdentity,
    SELF_HOSTED_WORKER_PROTOCOL_VERSION,
};
pub use supabase_edge_function::{
    EdgeFunctionHttpRequest, FunctionCredential, SupabaseEdgeFunctionError,
    SupabaseEdgeFunctionInvocation, SupabaseEdgeFunctionTarget,
    DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS,
};
pub use target_capability::{
    bind_filesystem_target, canonical_cli_target, canonical_filesystem_target,
    canonical_mcp_target, canonical_network_host, canonical_network_url, canonical_secret_target,
    opaque_reference_fingerprint, BoundCapabilityTarget, CanonicalCapabilityTarget,
    CapabilityTargetSelector, ClassOnlyPolicyMode, JsonShape, McpRisk, TargetOperation,
};
/// Runtime lifecycle commands exposed by the CLI and future control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    Run,
    Validate,
    Reload,
}
