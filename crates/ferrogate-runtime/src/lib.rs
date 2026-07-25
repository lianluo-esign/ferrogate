// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Pingora runtime boundary.

mod action_identity;
mod agent;
mod capability_boundary;
mod cloudflare_agent_cost;
mod cloudflare_agent_memory;
mod cloudflare_agent_schedule;
mod cloudflare_container;
mod cloudflare_gateway_control;
mod cloudflare_gateway_deploy;
mod cloudflare_worker;
mod cloudflare_worker_target;
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
pub use cloudflare_agent_cost::{
    evaluate as evaluate_agent_budget, should_dispatch, AgentBudgetPolicy, AgentBurnLedger,
    AgentBurnLedgerError, AgentCostAttribution, AgentCostGovernor, AgentCostReceipt,
    AgentRuntimeUsageSample, AgentRuntimeUsageSource, BudgetDecision, CfRuntimeCostModel,
    CfRuntimePricing, CostBreakdown, CostGovernorError, CostWindow, InMemoryAgentBurnLedger,
    KillMode, ScriptedUsageSource, StorageAgentBurnLedger, BYTES_PER_GIGABYTE,
    DEFAULT_DO_REQUEST_USD_PER_MILLION, DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS,
    DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION, DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION,
    DEFAULT_STORAGE_USD_PER_GB_MONTH, DEFAULT_WARN_FRACTION, SECONDS_PER_BILLING_MONTH,
    UNITS_PER_MILLION, WEBSOCKET_MESSAGES_PER_BILLED_REQUEST,
};
pub use cloudflare_agent_memory::{
    AgentChatHistory, AgentChatMessage, AgentChatPruneOutcome, AgentInstanceIdentity,
    AgentMemoryClient, AgentMemoryError, AgentSemanticMatch, AgentSemanticMatches, AgentSqlOutcome,
    AgentStateSnapshot, AGENT_INSTANCE_COMPONENT_MAX_LEN, AGENT_INSTANCE_NAME_PREFIX,
    AGENT_INSTANCE_NAME_SEPARATOR,
};
pub use cloudflare_agent_schedule::{
    AgentScheduleCancelOutcome, AgentScheduleCancelSelector, AgentScheduleClient,
    AgentScheduleCreated, AgentScheduleError, AgentScheduleKind, AgentScheduleList,
    AgentScheduleListCriteria, AgentScheduleRecord, AgentScheduleTaskSpec, AgentScheduleWhen,
    SCHEDULE_TASK_ID_MAX_LEN,
};
pub use cloudflare_container::{
    cloudflare_container_capabilities, cloudflare_container_descriptor, ContainerArtifactEntry,
    ContainerArtifacts, ContainerCleaned, ContainerControlClient, ContainerControlError,
    ContainerExecKind, ContainerExecOutput, ContainerExecSpec, ContainerInstanceTier,
    ContainerLogs, ContainerPrepareSpec, ContainerPrepared, ContainerSignal, ContainerStartSpec,
    ContainerStarted, ContainerStopped, CLOUDFLARE_CONTAINER_BACKEND_NAME,
    CLOUDFLARE_CONTAINER_HOST_LIFECYCLE_OWNER,
};
pub use cloudflare_gateway_control::{
    BlockingHttpControlTransport, GatewayControlTransport, WorkerGatewayControlSurface,
};
// Re-export the Cloudflare HTTP transport types so the `GatewayControlTransport`
// seam (and the container/memory/schedule clients built on it) is implementable
// from other crates — notably the agent-worker Cloudflare container backend
// (#415) — without a direct `ferrogate-cloudflare` dependency.
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
pub use cloudflare_worker_target::{
    prepare_governed_worker_invocation, CloudflareWorkerInvocation, CloudflareWorkerTarget,
    CloudflareWorkerTargetError, PreparedWorkerInvocation, WorkerBrokerError,
    WorkerInvocationRequest, DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS, WORKER_FUNCTION_CAPABILITY,
};
pub use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse, HttpTransport};
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
