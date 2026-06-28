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
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityAction, CapabilityAuthorizationDecision,
    CapabilityAuthorizer, CapabilityPolicy, FrameworkAdapterError, FrameworkAdapterEventKind,
    FrameworkAdapterMode, FrameworkAdapterSession, ManagedBrowserAction, ManagedBrowserOperation,
    ManagedCliAction, ManagedExternalAction, ManagedExternalActionRequest, ManagedFilesystemAccess,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayExternalActionTransportRequest {
    pub(crate) request_id: String,
    pub(crate) authorization: ExternalActionAuthorizationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayExternalActionTransportResponse {
    pub(crate) request_id: String,
    pub(crate) response: ExternalActionAuthorizationResponse,
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

pub(crate) fn external_action_unix_transport_smoke_command() -> Result<()> {
    let socket_path = std::env::temp_dir().join(format!(
        "ferrogate-agent-worker-external-action-{}-{}.sock",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    let server_socket_path = socket_path.clone();
    let server = thread::spawn(move || {
        serve_gateway_authorizer_unix(
            &server_socket_path,
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
                CapabilityPolicy {
                    allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                    ..CapabilityPolicy::default()
                },
            )),
            1,
        )
    });
    wait_for_authorizer_socket(&socket_path)?;
    let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);
    let decision = authorize_handler_external_action(
        Some(&client),
        ExternalActionGateRequest {
            session: smoke_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )?;
    let _ = server
        .join()
        .map_err(|_| anyhow::anyhow!("gateway authorizer Unix smoke thread panicked"))??;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn serve_gateway_authorizer_unix(
    socket_path: &Path,
    authorizer: impl GatewayExternalActionAuthorizer + Send + Sync + 'static,
    max_requests: usize,
) -> Result<Vec<GatewayExternalActionTransportResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let authorizer = Arc::new(authorizer);
    let mut handles = Vec::with_capacity(max_requests);
    while handles.len() < max_requests {
        let (stream, _) = listener.accept()?;
        let authorizer = Arc::clone(&authorizer);
        handles.push(thread::spawn(move || {
            handle_gateway_authorizer_stream(stream, authorizer)
        }));
    }
    let _ = std::fs::remove_file(socket_path);
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("gateway authorizer Unix thread panicked"))??,
        );
    }
    Ok(responses)
}

fn wait_for_authorizer_socket(socket_path: &Path) -> Result<()> {
    for _ in 0..100 {
        if socket_path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    anyhow::bail!(
        "timed out waiting for gateway authorizer socket {}",
        socket_path.display()
    );
}

fn handle_gateway_authorizer_stream<A>(
    mut stream: UnixStream,
    authorizer: Arc<A>,
) -> Result<GatewayExternalActionTransportResponse>
where
    A: GatewayExternalActionAuthorizer,
{
    let mut input = String::new();
    read_external_action_stream(&mut stream, &mut input)?;
    let request: GatewayExternalActionTransportRequest = serde_json::from_str(&input)?;
    let response = accept_external_action_authorization_request(request, authorizer.as_ref());
    stream.write_all(serde_json::to_string(&response)?.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(response)
}

pub(crate) struct UnixGatewayExternalActionAuthorizer {
    socket_path: std::path::PathBuf,
}

impl UnixGatewayExternalActionAuthorizer {
    pub(crate) fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl GatewayExternalActionAuthorizer for UnixGatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(request);
        let transport_request = GatewayExternalActionTransportRequest {
            request_id: gateway_authorization_request_id(&authorization),
            authorization,
        };
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "gateway external action authorizer transport unavailable: {error}"
            ))
        })?;
        let payload = serde_json::to_string(&transport_request).map_err(|error| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action authorization request serialization failed: {error}"
            ))
        })?;
        if payload.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action authorization request exceeds maximum message size"
                    .to_string(),
            ));
        }
        stream.write_all(payload.as_bytes()).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "gateway external action authorizer write failed: {error}"
            ))
        })?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| {
                FrameworkAdapterError::CapabilityDenied(format!(
                    "gateway external action authorizer request shutdown failed: {error}"
                ))
            })?;
        let mut response_json = String::new();
        read_external_action_stream(&mut stream, &mut response_json).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "gateway external action authorizer response read failed: {error}"
            ))
        })?;
        let response: GatewayExternalActionTransportResponse = serde_json::from_str(&response_json)
            .map_err(|error| {
                FrameworkAdapterError::InvalidRequest(format!(
                    "gateway external action authorization response decode failed: {error}"
                ))
            })?;
        if response.request_id != transport_request.request_id {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action authorization response request_id mismatch".to_string(),
            ));
        }
        response.response.into_gate_decision()
    }
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
    Ok(accept_external_action_authorization(request, authorizer))
}

fn accept_external_action_authorization_request<A>(
    request: GatewayExternalActionTransportRequest,
    authorizer: &A,
) -> GatewayExternalActionTransportResponse
where
    A: GatewayExternalActionAuthorizer,
{
    GatewayExternalActionTransportResponse {
        request_id: request.request_id,
        response: accept_external_action_authorization(request.authorization, authorizer),
    }
}

fn accept_external_action_authorization<A>(
    request: ExternalActionAuthorizationRequest,
    authorizer: &A,
) -> ExternalActionAuthorizationResponse
where
    A: GatewayExternalActionAuthorizer,
{
    let gate_request = match request.try_into_gate_request() {
        Ok(request) => request,
        Err(error) => return ExternalActionAuthorizationResponse::rejected(error),
    };
    match authorize_handler_external_action(Some(authorizer), gate_request) {
        Ok(decision) => ExternalActionAuthorizationResponse::from_decision(decision),
        Err(error) => ExternalActionAuthorizationResponse::rejected(error),
    }
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
    fn from_managed_request(request: ManagedExternalActionRequest) -> Self {
        Self {
            session: ExternalActionSession::from_framework_session(request.session),
            action: ExternalActionSpec::from_managed_action(request.action),
            high_risk: request.high_risk,
        }
    }

    fn try_into_gate_request(self) -> Result<ExternalActionGateRequest, FrameworkAdapterError> {
        Ok(ExternalActionGateRequest {
            session: self.session.try_into_framework_session()?,
            action: self.action.into_managed_action(),
            high_risk: self.high_risk,
        })
    }
}

impl ExternalActionSession {
    fn from_framework_session(session: FrameworkAdapterSession) -> Self {
        Self {
            session_id: session.session_id,
            run_id: session.run_id,
            tenant_id: session.tenant_id,
            workspace_id: session.workspace_id,
            worker_id: session.worker_id,
            isolation_backend: session.isolation_backend,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: ExternalActionFramework::from_supported_framework(session.framework),
            mode: ExternalActionMode::from_framework_mode(session.mode),
        }
    }

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
    fn from_supported_framework(framework: SupportedFramework) -> Self {
        match framework {
            SupportedFramework::ClaudeCode => Self::ClaudeCode,
            SupportedFramework::Codex => Self::Codex,
            SupportedFramework::Hermes => Self::Hermes,
            SupportedFramework::NativeHarness => Self::NativeHarness,
        }
    }

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
    fn from_framework_mode(mode: FrameworkAdapterMode) -> Self {
        match mode {
            FrameworkAdapterMode::Managed => Self::Managed,
            FrameworkAdapterMode::SelfHosted => Self::SelfHosted,
        }
    }

    fn into_framework_mode(self) -> FrameworkAdapterMode {
        match self {
            Self::Managed => FrameworkAdapterMode::Managed,
            Self::SelfHosted => FrameworkAdapterMode::SelfHosted,
        }
    }
}

impl ExternalActionSpec {
    fn kind_label(&self) -> &'static str {
        match self {
            Self::Tool { .. } => "tool",
            Self::McpTool { .. } => "mcp_tool",
            Self::Cli { .. } => "cli",
            Self::Skill { .. } => "skill",
            Self::Filesystem { .. } => "filesystem",
            Self::Browser { .. } => "browser",
            Self::Rest { .. } => "rest",
            Self::Secret { .. } => "secret",
            Self::Memory { .. } => "memory",
            Self::NetworkEgress { .. } => "network_egress",
        }
    }

    fn from_managed_action(action: ManagedExternalAction) -> Self {
        match action {
            ManagedExternalAction::Tool(action) => Self::Tool {
                tool_name: action.tool_name,
                arguments_policy: action.arguments_policy,
            },
            ManagedExternalAction::McpTool(action) => Self::McpTool {
                server_name: action.server_name,
                tool_name: action.tool_name,
                arguments_policy: action.arguments_policy,
            },
            ManagedExternalAction::Cli(action) => Self::Cli {
                command: action.command,
                args: action.args,
                working_dir: action.working_dir,
                env_policy: action.env_policy,
                timeout_millis: action.timeout_millis,
                stdout_limit_bytes: action.stdout_limit_bytes,
                stderr_limit_bytes: action.stderr_limit_bytes,
                artifact_capture: action.artifact_capture,
            },
            ManagedExternalAction::Skill(action) => Self::Skill {
                skill_id: action.skill_id,
                declared_capabilities: action.declared_capabilities,
            },
            ManagedExternalAction::Filesystem(action) => Self::Filesystem {
                path: action.path,
                access: ExternalActionFilesystemAccess::from_managed_access(action.access),
                workspace_relative: action.workspace_relative,
            },
            ManagedExternalAction::Browser(action) => Self::Browser {
                operation: ExternalActionBrowserOperation::from_managed_operation(action.operation),
                url: action.url,
                timeout_millis: action.timeout_millis,
            },
            ManagedExternalAction::Rest(action) => Self::Rest {
                method: action.method,
                url: action.url,
                headers_policy: action.headers_policy,
                body_policy: action.body_policy,
                timeout_millis: action.timeout_millis,
                retry_limit: action.retry_limit,
            },
            ManagedExternalAction::Secret(action) => Self::Secret {
                secret_id: action.secret_id,
                purpose: action.purpose,
            },
            ManagedExternalAction::Memory(action) => Self::Memory {
                access: ExternalActionMemoryAccess::from_managed_access(action.access),
                namespace: action.namespace,
                key: action.key,
            },
            ManagedExternalAction::NetworkEgress(action) => Self::NetworkEgress {
                host: action.host,
                port: action.port,
                protocol: action.protocol,
            },
        }
    }

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
    fn from_managed_access(access: ManagedFilesystemAccess) -> Self {
        match access {
            ManagedFilesystemAccess::Read => Self::Read,
            ManagedFilesystemAccess::Write => Self::Write,
            ManagedFilesystemAccess::Delete => Self::Delete,
        }
    }

    fn into_managed_access(self) -> ManagedFilesystemAccess {
        match self {
            Self::Read => ManagedFilesystemAccess::Read,
            Self::Write => ManagedFilesystemAccess::Write,
            Self::Delete => ManagedFilesystemAccess::Delete,
        }
    }
}

impl ExternalActionBrowserOperation {
    fn from_managed_operation(operation: ManagedBrowserOperation) -> Self {
        match operation {
            ManagedBrowserOperation::Navigate => Self::Navigate,
            ManagedBrowserOperation::Screenshot => Self::Screenshot,
            ManagedBrowserOperation::Click => Self::Click,
            ManagedBrowserOperation::Script => Self::Script,
        }
    }

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
    fn from_managed_access(access: ManagedMemoryAccess) -> Self {
        match access {
            ManagedMemoryAccess::Read => Self::Read,
            ManagedMemoryAccess::Write => Self::Write,
        }
    }

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

    fn into_gate_decision(self) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        if !self.accepted {
            let message = self
                .error
                .map(|error| error.message)
                .unwrap_or_else(|| "gateway external action authorization rejected".to_string());
            return Err(FrameworkAdapterError::CapabilityDenied(message));
        }
        let Some(event_json) = self.event else {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action authorization accepted without event".to_string(),
            ));
        };
        let event = normalized_event_from_canonical_json(event_json)?;
        let decision = match self.decision {
            Some(ExternalActionDecision::Allowed) => CapabilityAuthorizationDecision::Allowed,
            Some(ExternalActionDecision::Denied) => CapabilityAuthorizationDecision::Denied,
            Some(ExternalActionDecision::ApprovalRequired) => {
                CapabilityAuthorizationDecision::ApprovalRequired
            }
            None => {
                return Err(FrameworkAdapterError::InvalidRequest(
                    "gateway external action authorization accepted without decision".to_string(),
                ));
            }
        };
        Ok(ExternalActionGateDecision { decision, event })
    }
}

fn external_action_error_code(error: &FrameworkAdapterError) -> &'static str {
    match error {
        FrameworkAdapterError::InvalidDescriptor(_) => "invalid_descriptor",
        FrameworkAdapterError::InvalidRequest(_) => "invalid_request",
        FrameworkAdapterError::CapabilityDenied(_) => "capability_denied",
    }
}

fn normalized_event_from_canonical_json(
    value: serde_json::Value,
) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
    let metadata = value
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(
                "gateway external action event missing metadata".to_string(),
            )
        })?
        .iter()
        .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect::<Option<std::collections::BTreeMap<_, _>>>()
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(
                "gateway external action event metadata values must be strings".to_string(),
            )
        })?;
    Ok(NormalizedFrameworkEvent {
        session_id: json_string_field(&value, "session_id")?,
        run_id: json_string_field(&value, "run_id")?,
        adapter_name: json_string_field(&value, "adapter_name")?,
        adapter_version: json_string_field(&value, "adapter_version")?,
        framework: parse_supported_framework(&json_string_field(&value, "framework")?)?,
        mode: parse_framework_mode(&json_string_field(&value, "mode")?)?,
        kind: parse_capability_event_kind(&json_string_field(&value, "kind")?)?,
        message: value
            .get("message")
            .and_then(|message| {
                if message.is_null() {
                    Some(None)
                } else {
                    message.as_str().map(|message| Some(message.to_string()))
                }
            })
            .ok_or_else(|| {
                FrameworkAdapterError::InvalidRequest(
                    "gateway external action event message must be string or null".to_string(),
                )
            })?,
        metadata,
    })
}

fn json_string_field(
    value: &serde_json::Value,
    field: &str,
) -> Result<String, FrameworkAdapterError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action event {field} must be a non-empty string"
            ))
        })
}

fn parse_supported_framework(value: &str) -> Result<SupportedFramework, FrameworkAdapterError> {
    match value {
        "claude_code" => Ok(SupportedFramework::ClaudeCode),
        "codex" => Ok(SupportedFramework::Codex),
        "hermes" => Ok(SupportedFramework::Hermes),
        "native_harness" => Ok(SupportedFramework::NativeHarness),
        _ => Err(FrameworkAdapterError::InvalidRequest(format!(
            "unsupported gateway external action framework {value}"
        ))),
    }
}

fn parse_framework_mode(value: &str) -> Result<FrameworkAdapterMode, FrameworkAdapterError> {
    match value {
        "managed" => Ok(FrameworkAdapterMode::Managed),
        "self_hosted" => Ok(FrameworkAdapterMode::SelfHosted),
        _ => Err(FrameworkAdapterError::InvalidRequest(format!(
            "unsupported gateway external action mode {value}"
        ))),
    }
}

fn parse_capability_event_kind(
    value: &str,
) -> Result<FrameworkAdapterEventKind, FrameworkAdapterError> {
    match value {
        "capability.allowed" => Ok(FrameworkAdapterEventKind::CapabilityAllowed),
        "capability.denied" => Ok(FrameworkAdapterEventKind::CapabilityDenied),
        "capability.requested" => Ok(FrameworkAdapterEventKind::CapabilityRequested),
        _ => Err(FrameworkAdapterError::InvalidRequest(format!(
            "unsupported gateway external action event kind {value}"
        ))),
    }
}

fn gateway_authorization_request_id(authorization: &ExternalActionAuthorizationRequest) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        authorization.session.run_id,
        authorization.session.session_id,
        authorization.session.worker_id,
        authorization.session.adapter_name,
        authorization.action.kind_label()
    )
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

    #[test]
    fn unix_gateway_authorizer_transport_allows_managed_handler_action() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            serve_gateway_authorizer_unix(
                &server_socket_path,
                RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
                    CapabilityPolicy {
                        allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                        ..CapabilityPolicy::default()
                    },
                )),
                1,
            )
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let decision = authorize_handler_external_action(
            Some(&client),
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
        let served = server.join().unwrap().unwrap();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
        assert_eq!(
            decision
                .event
                .metadata
                .get("external_target")
                .map(String::as_str),
            Some("tool:native.echo")
        );
        assert_eq!(served.len(), 1);
        assert!(served[0].response.accepted);
        assert_eq!(
            served[0].request_id,
            "run-1:session-1:worker-1:native-harness:tool"
        );
    }

    #[test]
    fn unix_gateway_authorizer_transport_rejects_denied_gateway_decision() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer-deny.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            serve_gateway_authorizer_unix(
                &server_socket_path,
                RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default()),
                1,
            )
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        let served = server.join().unwrap().unwrap();

        assert!(error.to_string().contains("not allowed"));
        assert_eq!(served.len(), 1);
        assert!(!served[0].response.accepted);
        assert_eq!(
            served[0]
                .response
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("capability_denied")
        );
    }

    #[test]
    fn unix_gateway_authorizer_transport_rejects_response_identity_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer-bad-id.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            if server_socket_path.exists() {
                std::fs::remove_file(&server_socket_path).unwrap();
            }
            let listener = UnixListener::bind(&server_socket_path).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = String::new();
            read_external_action_stream(&mut stream, &mut input).unwrap();
            let request: GatewayExternalActionTransportRequest =
                serde_json::from_str(&input).unwrap();
            let response = GatewayExternalActionTransportResponse {
                request_id: format!("{}-tampered", request.request_id),
                response: ExternalActionAuthorizationResponse {
                    accepted: true,
                    decision: Some(ExternalActionDecision::Allowed),
                    event: Some(allowed_tool_event_json()),
                    error: None,
                },
            };
            stream
                .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                .unwrap();
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        server.join().unwrap();

        assert!(error.to_string().contains("request_id mismatch"));
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

    fn allowed_tool_event_json() -> serde_json::Value {
        RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ))
        .authorize_external_action(ManagedExternalActionRequest {
            session: session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        })
        .unwrap()
        .event
        .canonical_json()
    }
}
