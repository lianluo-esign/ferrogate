// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Handler-facing external action gate.
//!
//! Framework handlers in the standalone `agent-worker` process call this gate
//! before touching tools, MCP, CLI, REST, filesystem, browser automation,
//! secrets, memory, or network egress. The worker may prepare typed action
//! requests, but the authorization decision must come from the gateway-mediated
//! capability boundary.

use std::{
    collections::BTreeSet,
    io::{self, Read},
};

use anyhow::Result;
use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityAction, CapabilityAuthorizationDecision,
    CapabilityAuthorizer, CapabilityPolicy, FrameworkAdapterError, FrameworkAdapterMode,
    FrameworkAdapterSession, ManagedBrowserAction, ManagedBrowserOperation, ManagedCliAction,
    ManagedExternalAction, ManagedExternalActionRequest, ManagedFilesystemAccess,
    ManagedFilesystemAction, ManagedMcpToolAction, ManagedMemoryAccess, ManagedMemoryAction,
    ManagedNetworkEgressAction, ManagedRestAction, ManagedSecretAction, ManagedSkillAction,
    ManagedToolAction, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer, SupportedFramework,
};
use serde::{Deserialize, Serialize};

const EXTERNAL_ACTION_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionGateRequest {
    pub(crate) session: FrameworkAdapterSession,
    pub(crate) action: ManagedExternalAction,
    pub(crate) high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionGateDecision {
    pub(crate) decision: CapabilityAuthorizationDecision,
    pub(crate) event: NormalizedFrameworkEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExternalActionAuthorizationRequest {
    pub(crate) session: ExternalActionSession,
    pub(crate) action: ExternalActionSpec,
    #[serde(default)]
    pub(crate) high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExternalActionSession {
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) tenant_id: String,
    pub(crate) workspace_id: String,
    pub(crate) worker_id: String,
    pub(crate) isolation_backend: String,
    pub(crate) adapter_name: String,
    pub(crate) adapter_version: String,
    pub(crate) framework: ExternalActionFramework,
    #[serde(default = "default_external_action_mode")]
    pub(crate) mode: ExternalActionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionFramework {
    ClaudeCode,
    Codex,
    Hermes,
    NativeHarness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionMode {
    Managed,
    SelfHosted,
}

fn default_external_action_mode() -> ExternalActionMode {
    ExternalActionMode::Managed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ExternalActionSpec {
    Tool {
        tool_name: String,
        arguments_policy: String,
    },
    McpTool {
        server_name: String,
        tool_name: String,
        arguments_policy: String,
    },
    Cli {
        command: String,
        args: Vec<String>,
        working_dir: String,
        env_policy: String,
        timeout_millis: u64,
        stdout_limit_bytes: u64,
        stderr_limit_bytes: u64,
        artifact_capture: bool,
    },
    Skill {
        skill_id: String,
        declared_capabilities: Vec<String>,
    },
    Filesystem {
        path: String,
        access: ExternalActionFilesystemAccess,
        workspace_relative: bool,
    },
    Browser {
        operation: ExternalActionBrowserOperation,
        url: String,
        timeout_millis: u64,
    },
    Rest {
        method: String,
        url: String,
        headers_policy: String,
        body_policy: String,
        timeout_millis: u64,
        retry_limit: u32,
    },
    Secret {
        secret_id: String,
        purpose: String,
    },
    Memory {
        access: ExternalActionMemoryAccess,
        namespace: String,
        key: String,
    },
    NetworkEgress {
        host: String,
        port: u16,
        protocol: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionFilesystemAccess {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionBrowserOperation {
    Navigate,
    Screenshot,
    Click,
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionMemoryAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExternalActionAuthorizationResponse {
    pub(crate) accepted: bool,
    pub(crate) decision: Option<ExternalActionDecision>,
    pub(crate) event: Option<serde_json::Value>,
    pub(crate) error: Option<ExternalActionAuthorizationError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalActionDecision {
    Allowed,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExternalActionAuthorizationError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl ExternalActionGateDecision {
    pub(crate) fn allowed(&self) -> bool {
        self.decision == CapabilityAuthorizationDecision::Allowed
    }
}

pub(crate) trait GatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError>;
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeGatewayExternalActionAuthorizer<A> {
    authorizer: A,
}

impl<A> RuntimeGatewayExternalActionAuthorizer<A> {
    pub(crate) fn new(authorizer: A) -> Self {
        Self { authorizer }
    }
}

impl<A> GatewayExternalActionAuthorizer for RuntimeGatewayExternalActionAuthorizer<A>
where
    A: CapabilityAuthorizer,
{
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let (evidence, event) = authorize_managed_external_action(&self.authorizer, request)?;
        Ok(ExternalActionGateDecision {
            decision: evidence.decision,
            event,
        })
    }
}

pub(crate) fn authorize_handler_external_action<A>(
    authorizer: Option<&A>,
    request: ExternalActionGateRequest,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer,
{
    validate_managed_worker_session(&request.session)?;
    let Some(authorizer) = authorizer else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed external action denied: gateway authorization client is unavailable"
                .to_string(),
        ));
    };
    let decision = authorizer.authorize_external_action(ManagedExternalActionRequest {
        session: request.session,
        action: request.action,
        high_risk: request.high_risk,
    })?;
    if decision.allowed() {
        Ok(decision)
    } else {
        Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed external action denied before handler execution: {}",
            decision
                .event
                .message
                .as_deref()
                .unwrap_or("gateway authorization was not allowed")
        )))
    }
}

pub(crate) fn external_action_smoke_command() -> Result<()> {
    let decision = external_action_smoke()?;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn accept_external_action_json_command() -> Result<()> {
    let mut input = String::new();
    read_external_action_stream(&mut io::stdin(), &mut input)?;
    let response = accept_external_action_json(
        &input,
        &RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        )),
    )?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn accept_external_action_json<A>(
    input: &str,
    authorizer: &A,
) -> Result<ExternalActionAuthorizationResponse>
where
    A: GatewayExternalActionAuthorizer,
{
    if input.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker external action request exceeds maximum message size");
    }
    let request: ExternalActionAuthorizationRequest = serde_json::from_str(input)?;
    let gate_request = match request.try_into_gate_request() {
        Ok(request) => request,
        Err(error) => return Ok(ExternalActionAuthorizationResponse::rejected(error)),
    };
    Ok(
        match authorize_handler_external_action(Some(authorizer), gate_request) {
            Ok(decision) => ExternalActionAuthorizationResponse::from_decision(decision),
            Err(error) => ExternalActionAuthorizationResponse::rejected(error),
        },
    )
}

fn external_action_smoke() -> Result<ExternalActionGateDecision> {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        },
    ));
    authorize_handler_external_action(
        Some(&gate),
        ExternalActionGateRequest {
            session: smoke_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )
    .map_err(Into::into)
}

fn smoke_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "agent-worker-external-action-smoke-session".to_string(),
        run_id: "agent-worker-external-action-smoke-run".to_string(),
        tenant_id: "smoke-tenant".to_string(),
        workspace_id: "smoke-workspace".to_string(),
        worker_id: "agent-worker-smoke".to_string(),
        isolation_backend: "firecracker".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::Managed,
    }
}

fn read_external_action_stream<R: Read>(reader: &mut R, output: &mut String) -> Result<()> {
    let mut limited = reader.take((EXTERNAL_ACTION_MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_string(output)?;
    if output.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker external action request exceeds maximum message size");
    }
    Ok(())
}

impl ExternalActionAuthorizationRequest {
    fn try_into_gate_request(self) -> Result<ExternalActionGateRequest, FrameworkAdapterError> {
        Ok(ExternalActionGateRequest {
            session: self.session.try_into_framework_session()?,
            action: self.action.into_managed_action(),
            high_risk: self.high_risk,
        })
    }
}

impl ExternalActionSession {
    fn try_into_framework_session(self) -> Result<FrameworkAdapterSession, FrameworkAdapterError> {
        Ok(FrameworkAdapterSession {
            session_id: self.session_id,
            run_id: self.run_id,
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
            worker_id: self.worker_id,
            isolation_backend: self.isolation_backend,
            adapter_name: self.adapter_name,
            adapter_version: self.adapter_version,
            framework: self.framework.into_supported_framework(),
            mode: self.mode.into_framework_mode(),
        })
    }
}

impl ExternalActionFramework {
    fn into_supported_framework(self) -> SupportedFramework {
        match self {
            Self::ClaudeCode => SupportedFramework::ClaudeCode,
            Self::Codex => SupportedFramework::Codex,
            Self::Hermes => SupportedFramework::Hermes,
            Self::NativeHarness => SupportedFramework::NativeHarness,
        }
    }
}

impl ExternalActionMode {
    fn into_framework_mode(self) -> FrameworkAdapterMode {
        match self {
            Self::Managed => FrameworkAdapterMode::Managed,
            Self::SelfHosted => FrameworkAdapterMode::SelfHosted,
        }
    }
}

impl ExternalActionSpec {
    fn into_managed_action(self) -> ManagedExternalAction {
        match self {
            Self::Tool {
                tool_name,
                arguments_policy,
            } => ManagedExternalAction::Tool(ManagedToolAction {
                tool_name,
                arguments_policy,
            }),
            Self::McpTool {
                server_name,
                tool_name,
                arguments_policy,
            } => ManagedExternalAction::McpTool(ManagedMcpToolAction {
                server_name,
                tool_name,
                arguments_policy,
            }),
            Self::Cli {
                command,
                args,
                working_dir,
                env_policy,
                timeout_millis,
                stdout_limit_bytes,
                stderr_limit_bytes,
                artifact_capture,
            } => ManagedExternalAction::Cli(ManagedCliAction {
                command,
                args,
                working_dir,
                env_policy,
                timeout_millis,
                stdout_limit_bytes,
                stderr_limit_bytes,
                artifact_capture,
            }),
            Self::Skill {
                skill_id,
                declared_capabilities,
            } => ManagedExternalAction::Skill(ManagedSkillAction {
                skill_id,
                declared_capabilities,
            }),
            Self::Filesystem {
                path,
                access,
                workspace_relative,
            } => ManagedExternalAction::Filesystem(ManagedFilesystemAction {
                path,
                access: access.into_managed_access(),
                workspace_relative,
            }),
            Self::Browser {
                operation,
                url,
                timeout_millis,
            } => ManagedExternalAction::Browser(ManagedBrowserAction {
                operation: operation.into_managed_operation(),
                url,
                timeout_millis,
            }),
            Self::Rest {
                method,
                url,
                headers_policy,
                body_policy,
                timeout_millis,
                retry_limit,
            } => ManagedExternalAction::Rest(ManagedRestAction {
                method,
                url,
                headers_policy,
                body_policy,
                timeout_millis,
                retry_limit,
            }),
            Self::Secret { secret_id, purpose } => {
                ManagedExternalAction::Secret(ManagedSecretAction { secret_id, purpose })
            }
            Self::Memory {
                access,
                namespace,
                key,
            } => ManagedExternalAction::Memory(ManagedMemoryAction {
                access: access.into_managed_access(),
                namespace,
                key,
            }),
            Self::NetworkEgress {
                host,
                port,
                protocol,
            } => ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                host,
                port,
                protocol,
            }),
        }
    }
}

impl ExternalActionFilesystemAccess {
    fn into_managed_access(self) -> ManagedFilesystemAccess {
        match self {
            Self::Read => ManagedFilesystemAccess::Read,
            Self::Write => ManagedFilesystemAccess::Write,
            Self::Delete => ManagedFilesystemAccess::Delete,
        }
    }
}

impl ExternalActionBrowserOperation {
    fn into_managed_operation(self) -> ManagedBrowserOperation {
        match self {
            Self::Navigate => ManagedBrowserOperation::Navigate,
            Self::Screenshot => ManagedBrowserOperation::Screenshot,
            Self::Click => ManagedBrowserOperation::Click,
            Self::Script => ManagedBrowserOperation::Script,
        }
    }
}

impl ExternalActionMemoryAccess {
    fn into_managed_access(self) -> ManagedMemoryAccess {
        match self {
            Self::Read => ManagedMemoryAccess::Read,
            Self::Write => ManagedMemoryAccess::Write,
        }
    }
}

impl ExternalActionAuthorizationResponse {
    fn from_decision(decision: ExternalActionGateDecision) -> Self {
        let decision_label = match decision.decision {
            CapabilityAuthorizationDecision::Allowed => ExternalActionDecision::Allowed,
            CapabilityAuthorizationDecision::Denied => ExternalActionDecision::Denied,
            CapabilityAuthorizationDecision::ApprovalRequired => {
                ExternalActionDecision::ApprovalRequired
            }
        };
        Self {
            accepted: decision.allowed(),
            decision: Some(decision_label),
            event: Some(decision.event.canonical_json()),
            error: None,
        }
    }

    fn rejected(error: FrameworkAdapterError) -> Self {
        Self {
            accepted: false,
            decision: None,
            event: None,
            error: Some(ExternalActionAuthorizationError {
                code: external_action_error_code(&error).to_string(),
                message: error.to_string(),
            }),
        }
    }
}

fn external_action_error_code(error: &FrameworkAdapterError) -> &'static str {
    match error {
        FrameworkAdapterError::InvalidDescriptor(_) => "invalid_descriptor",
        FrameworkAdapterError::InvalidRequest(_) => "invalid_request",
        FrameworkAdapterError::CapabilityDenied(_) => "capability_denied",
    }
}

fn validate_managed_worker_session(
    session: &FrameworkAdapterSession,
) -> Result<(), FrameworkAdapterError> {
    require_non_empty("session_id", &session.session_id)?;
    require_non_empty("run_id", &session.run_id)?;
    require_non_empty("tenant_id", &session.tenant_id)?;
    require_non_empty("workspace_id", &session.workspace_id)?;
    require_non_empty("worker_id", &session.worker_id)?;
    require_non_empty("isolation_backend", &session.isolation_backend)?;
    require_non_empty("adapter_name", &session.adapter_name)?;
    if session.mode != FrameworkAdapterMode::Managed {
        return Err(FrameworkAdapterError::InvalidRequest(
            "handler external action gate only enforces managed worker sessions".to_string(),
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), FrameworkAdapterError> {
    if value.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{ManagedCliAction, ManagedMcpToolAction, ManagedRestAction};

    #[test]
    fn managed_tool_action_must_pass_gateway_authorization_before_execution() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));

        let decision = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
        assert_eq!(
            decision.event.metadata.get("tenant_id").map(String::as_str),
            Some("tenant-1")
        );
        assert_eq!(
            decision.event.metadata.get("worker_id").map(String::as_str),
            Some("worker-1")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("isolation_backend")
                .map(String::as_str),
            Some("firecracker")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("external_target")
                .map(String::as_str),
            Some("tool:native.echo")
        );
    }

    #[test]
    fn managed_cli_action_is_blocked_when_gateway_requires_approval() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Cli(ManagedCliAction {
                    command: "bash".to_string(),
                    args: vec!["-lc".to_string(), "curl https://example.test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "deny_all_except_path".to_string(),
                    timeout_millis: 1_000,
                    stdout_limit_bytes: 4096,
                    stderr_limit_bytes: 4096,
                    artifact_capture: false,
                }),
                high_risk: true,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires approval"));
    }

    #[test]
    fn managed_rest_action_fails_closed_without_gateway_authorizer() {
        let error = authorize_handler_external_action::<
            RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer>,
        >(
            None,
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "strip_credentials".to_string(),
                    body_policy: "redact_and_scan".to_string(),
                    timeout_millis: 2_000,
                    retry_limit: 0,
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("gateway authorization client"));
    }

    #[test]
    fn managed_mcp_action_denial_happens_before_handler_execution() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::McpTool(ManagedMcpToolAction {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn self_hosted_sessions_do_not_use_managed_enforcement_gate() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut self_hosted = session();
        self_hosted.mode = FrameworkAdapterMode::SelfHosted;

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: self_hosted,
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("managed worker sessions"));
    }

    #[test]
    fn external_action_smoke_emits_allowed_gateway_capability_event() {
        let decision = external_action_smoke().unwrap();
        let json = decision.event.canonical_json();

        assert_eq!(json["kind"], "capability.allowed");
        assert_eq!(json["metadata"]["external_action"], "tool");
        assert_eq!(json["metadata"]["external_target"], "tool:native.echo");
        assert_eq!(json["metadata"]["tenant_id"], "smoke-tenant");
        assert_eq!(json["metadata"]["worker_id"], "agent-worker-smoke");
    }

    #[test]
    fn external_action_json_contract_allows_tool_without_executing_it() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let input = serde_json::to_string(&tool_json_request()).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(response.accepted);
        assert_eq!(response.decision, Some(ExternalActionDecision::Allowed));
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.allowed");
        assert_eq!(event["metadata"]["external_target"], "tool:native.echo");
    }

    #[test]
    fn external_action_json_contract_rejects_cli_approval_before_execution() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.high_risk = true;
        request.action = ExternalActionSpec::Cli {
            command: "bash".to_string(),
            args: vec!["-lc".to_string(), "curl https://example.test".to_string()],
            working_dir: "/workspace".to_string(),
            env_policy: "deny_all_except_path".to_string(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 4096,
            stderr_limit_bytes: 4096,
            artifact_capture: false,
        };
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            Some("capability_denied")
        );
        assert!(response
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains("requires approval")));
    }

    #[test]
    fn external_action_json_contract_rejects_self_hosted_enforcement() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.session.mode = ExternalActionMode::SelfHosted;
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            Some("invalid_request")
        );
    }

    #[test]
    fn external_action_json_contract_covers_every_managed_action_surface() {
        let allowed_actions = BTreeSet::from([
            CapabilityAction::Tool,
            CapabilityAction::McpTool,
            CapabilityAction::Cli,
            CapabilityAction::Skill,
            CapabilityAction::Filesystem,
            CapabilityAction::Browser,
            CapabilityAction::Rest,
            CapabilityAction::Secret,
            CapabilityAction::MemoryRead,
            CapabilityAction::MemoryWrite,
            CapabilityAction::NetworkEgress,
        ]);
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions,
                allow_direct_network_egress: true,
                ..CapabilityPolicy::default()
            },
        ));

        for (action, expected_action, expected_target) in external_action_contract_cases() {
            let mut request = tool_json_request();
            request.action = action;
            let input = serde_json::to_string(&request).unwrap();

            let response = accept_external_action_json(&input, &gate).unwrap();

            assert!(response.accepted, "{expected_action}:{expected_target}");
            assert_eq!(response.decision, Some(ExternalActionDecision::Allowed));
            let event = response.event.unwrap();
            assert_eq!(event["kind"], "capability.allowed");
            assert_eq!(event["metadata"]["external_action"], expected_action);
            assert_eq!(event["metadata"]["external_target"], expected_target);
            assert_eq!(event["metadata"]["tenant_id"], "tenant-1");
            assert_eq!(event["metadata"]["worker_id"], "worker-1");
            assert_eq!(event["metadata"]["isolation_backend"], "firecracker");
        }
    }

    #[test]
    fn external_action_json_contract_keeps_network_egress_fail_closed_by_default() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: false,
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.action = ExternalActionSpec::NetworkEgress {
            host: "api.example.test".to_string(),
            port: 443,
            protocol: "https".to_string(),
        };
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            Some("capability_denied")
        );
        assert!(response
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains("direct network egress")));
    }

    fn session() -> FrameworkAdapterSession {
        FrameworkAdapterSession {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            isolation_backend: "firecracker".to_string(),
            adapter_name: "native-harness".to_string(),
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            framework: SupportedFramework::NativeHarness,
            mode: FrameworkAdapterMode::Managed,
        }
    }

    fn tool_json_request() -> ExternalActionAuthorizationRequest {
        ExternalActionAuthorizationRequest {
            session: ExternalActionSession {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-1".to_string(),
                isolation_backend: "firecracker".to_string(),
                adapter_name: "native-harness".to_string(),
                adapter_version: env!("CARGO_PKG_VERSION").to_string(),
                framework: ExternalActionFramework::NativeHarness,
                mode: ExternalActionMode::Managed,
            },
            action: ExternalActionSpec::Tool {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            },
            high_risk: false,
        }
    }

    fn external_action_contract_cases() -> Vec<(ExternalActionSpec, &'static str, &'static str)> {
        vec![
            (
                ExternalActionSpec::Tool {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                },
                "tool",
                "tool:native.echo",
            ),
            (
                ExternalActionSpec::McpTool {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                },
                "mcp.tool",
                "mcp:filesystem:read_file",
            ),
            (
                ExternalActionSpec::Cli {
                    command: "cargo".to_string(),
                    args: vec!["test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "allowlist".to_string(),
                    timeout_millis: 30_000,
                    stdout_limit_bytes: 65_536,
                    stderr_limit_bytes: 65_536,
                    artifact_capture: true,
                },
                "cli",
                "cargo",
            ),
            (
                ExternalActionSpec::Skill {
                    skill_id: "repo-test".to_string(),
                    declared_capabilities: vec!["cli".to_string(), "filesystem".to_string()],
                },
                "skill",
                "skill:repo-test",
            ),
            (
                ExternalActionSpec::Filesystem {
                    path: "src/lib.rs".to_string(),
                    access: ExternalActionFilesystemAccess::Read,
                    workspace_relative: true,
                },
                "filesystem",
                "read:src/lib.rs",
            ),
            (
                ExternalActionSpec::Browser {
                    operation: ExternalActionBrowserOperation::Navigate,
                    url: "https://docs.example.test".to_string(),
                    timeout_millis: 5_000,
                },
                "browser",
                "browser:navigate:https://docs.example.test",
            ),
            (
                ExternalActionSpec::Rest {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "redact_authorization".to_string(),
                    body_policy: "guardrail_scan".to_string(),
                    timeout_millis: 10_000,
                    retry_limit: 2,
                },
                "rest",
                "POST https://api.example.test/v1/jobs",
            ),
            (
                ExternalActionSpec::Secret {
                    secret_id: "openai-api-key".to_string(),
                    purpose: "provider_call".to_string(),
                },
                "secret",
                "secret:openai-api-key",
            ),
            (
                ExternalActionSpec::Memory {
                    access: ExternalActionMemoryAccess::Read,
                    namespace: "session".to_string(),
                    key: "plan".to_string(),
                },
                "memory.read",
                "memory:read:session:plan",
            ),
            (
                ExternalActionSpec::Memory {
                    access: ExternalActionMemoryAccess::Write,
                    namespace: "session".to_string(),
                    key: "summary".to_string(),
                },
                "memory.write",
                "memory:write:session:summary",
            ),
            (
                ExternalActionSpec::NetworkEgress {
                    host: "api.example.test".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                },
                "network.egress",
                "api.example.test:443",
            ),
        ]
    }
}
