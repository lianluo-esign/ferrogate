// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-mediated external action contract for managed agent workers.
//!
//! Managed framework handlers use these typed specs before touching any tool,
//! MCP server, shell, filesystem, browser, REST endpoint, secret, memory record,
//! or network destination. The gateway capability boundary remains the
//! enforcement point; self-hosted workers only report telemetry with lower
//! trust.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    authorize_framework_capability, self_hosted_framework_capability_report, CapabilityAction,
    CapabilityAuthorizationDecision, CapabilityAuthorizationEvidence, CapabilityAuthorizer,
    FrameworkAdapterError, FrameworkAdapterEventKind, FrameworkAdapterMode,
    FrameworkAdapterSession, FrameworkCapabilityRequest, NormalizedFrameworkEvent,
    SupportedFramework,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExternalActionRequest {
    pub session: FrameworkAdapterSession,
    pub action: ManagedExternalAction,
    pub high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExternalActionDecision {
    pub decision: CapabilityAuthorizationDecision,
    pub event: NormalizedFrameworkEvent,
}

impl ManagedExternalActionDecision {
    pub fn allowed(&self) -> bool {
        self.decision == CapabilityAuthorizationDecision::Allowed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionAuthorizationRequest {
    pub session: ExternalActionSession,
    pub action: ExternalActionSpec,
    #[serde(default)]
    pub high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionSession {
    pub session_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub isolation_backend: String,
    pub adapter_name: String,
    pub adapter_version: String,
    pub framework: ExternalActionFramework,
    #[serde(default = "default_external_action_mode")]
    pub mode: ExternalActionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionFramework {
    ClaudeCode,
    Codex,
    Hermes,
    NativeHarness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionMode {
    Managed,
    SelfHosted,
}

fn default_external_action_mode() -> ExternalActionMode {
    ExternalActionMode::Managed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExternalActionSpec {
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
pub enum ExternalActionFilesystemAccess {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionBrowserOperation {
    Navigate,
    Screenshot,
    Click,
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionMemoryAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionAuthorizationResponse {
    pub accepted: bool,
    pub decision: Option<ExternalActionDecision>,
    pub event: Option<serde_json::Value>,
    pub error: Option<ExternalActionAuthorizationError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayExternalActionTransportRequest {
    pub request_id: String,
    pub authorization: ExternalActionAuthorizationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayExternalActionTransportResponse {
    pub request_id: String,
    pub response: ExternalActionAuthorizationResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionDecision {
    Allowed,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionAuthorizationError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedExternalAction {
    Tool(ManagedToolAction),
    McpTool(ManagedMcpToolAction),
    Cli(ManagedCliAction),
    Skill(ManagedSkillAction),
    Filesystem(ManagedFilesystemAction),
    Browser(ManagedBrowserAction),
    Rest(ManagedRestAction),
    Secret(ManagedSecretAction),
    Memory(ManagedMemoryAction),
    NetworkEgress(ManagedNetworkEgressAction),
}

impl ManagedExternalAction {
    pub fn capability_action(&self) -> CapabilityAction {
        match self {
            Self::Tool(_) => CapabilityAction::Tool,
            Self::McpTool(_) => CapabilityAction::McpTool,
            Self::Cli(_) => CapabilityAction::Cli,
            Self::Skill(_) => CapabilityAction::Skill,
            Self::Filesystem(_) => CapabilityAction::Filesystem,
            Self::Browser(_) => CapabilityAction::Browser,
            Self::Rest(_) => CapabilityAction::Rest,
            Self::Secret(_) => CapabilityAction::Secret,
            Self::Memory(action) => match action.access {
                ManagedMemoryAccess::Read => CapabilityAction::MemoryRead,
                ManagedMemoryAccess::Write => CapabilityAction::MemoryWrite,
            },
            Self::NetworkEgress(_) => CapabilityAction::NetworkEgress,
        }
    }

    pub fn target(&self) -> String {
        match self {
            Self::Tool(action) => format!("tool:{}", action.tool_name),
            Self::McpTool(action) => format!("mcp:{}:{}", action.server_name, action.tool_name),
            Self::Cli(action) => action.command.clone(),
            Self::Skill(action) => format!("skill:{}", action.skill_id),
            Self::Filesystem(action) => format!("{}:{}", action.access.as_str(), action.path),
            Self::Browser(action) => {
                format!("browser:{}:{}", action.operation.as_str(), action.url)
            }
            Self::Rest(action) => format!("{} {}", action.method, action.url),
            Self::Secret(action) => format!("secret:{}", action.secret_id),
            Self::Memory(action) => format!(
                "memory:{}:{}:{}",
                action.access.as_str(),
                action.namespace,
                action.key
            ),
            Self::NetworkEgress(action) => format!("{}:{}", action.host, action.port),
        }
    }

    fn metadata(&self) -> BTreeMap<String, String> {
        match self {
            Self::Tool(action) => BTreeMap::from([
                ("tool_name".to_string(), action.tool_name.clone()),
                (
                    "arguments_policy".to_string(),
                    action.arguments_policy.clone(),
                ),
            ]),
            Self::McpTool(action) => BTreeMap::from([
                ("mcp_server".to_string(), action.server_name.clone()),
                ("mcp_tool".to_string(), action.tool_name.clone()),
                (
                    "arguments_policy".to_string(),
                    action.arguments_policy.clone(),
                ),
            ]),
            Self::Cli(action) => BTreeMap::from([
                ("command".to_string(), action.command.clone()),
                ("args".to_string(), action.args.join("\n")),
                ("working_dir".to_string(), action.working_dir.clone()),
                ("env_policy".to_string(), action.env_policy.clone()),
                (
                    "timeout_millis".to_string(),
                    action.timeout_millis.to_string(),
                ),
                (
                    "stdout_limit_bytes".to_string(),
                    action.stdout_limit_bytes.to_string(),
                ),
                (
                    "stderr_limit_bytes".to_string(),
                    action.stderr_limit_bytes.to_string(),
                ),
                (
                    "artifact_capture".to_string(),
                    action.artifact_capture.to_string(),
                ),
            ]),
            Self::Skill(action) => BTreeMap::from([
                ("skill_id".to_string(), action.skill_id.clone()),
                (
                    "declared_capabilities".to_string(),
                    action.declared_capabilities.join(","),
                ),
            ]),
            Self::Filesystem(action) => BTreeMap::from([
                ("path".to_string(), action.path.clone()),
                (
                    "filesystem_access".to_string(),
                    action.access.as_str().to_string(),
                ),
                (
                    "workspace_relative".to_string(),
                    action.workspace_relative.to_string(),
                ),
            ]),
            Self::Browser(action) => BTreeMap::from([
                (
                    "browser_operation".to_string(),
                    action.operation.as_str().to_string(),
                ),
                ("url".to_string(), action.url.clone()),
                (
                    "timeout_millis".to_string(),
                    action.timeout_millis.to_string(),
                ),
            ]),
            Self::Rest(action) => BTreeMap::from([
                ("method".to_string(), action.method.clone()),
                ("url".to_string(), action.url.clone()),
                ("headers_policy".to_string(), action.headers_policy.clone()),
                ("body_policy".to_string(), action.body_policy.clone()),
                (
                    "timeout_millis".to_string(),
                    action.timeout_millis.to_string(),
                ),
                ("retry_limit".to_string(), action.retry_limit.to_string()),
            ]),
            Self::Secret(action) => BTreeMap::from([
                ("secret_id".to_string(), action.secret_id.clone()),
                ("purpose".to_string(), action.purpose.clone()),
            ]),
            Self::Memory(action) => BTreeMap::from([
                (
                    "memory_access".to_string(),
                    action.access.as_str().to_string(),
                ),
                ("namespace".to_string(), action.namespace.clone()),
                ("key".to_string(), action.key.clone()),
            ]),
            Self::NetworkEgress(action) => BTreeMap::from([
                ("host".to_string(), action.host.clone()),
                ("port".to_string(), action.port.to_string()),
                ("protocol".to_string(), action.protocol.clone()),
            ]),
        }
    }
}

impl ExternalActionAuthorizationRequest {
    pub fn from_managed_request(request: ManagedExternalActionRequest) -> Self {
        Self {
            session: ExternalActionSession::from_framework_session(request.session),
            action: ExternalActionSpec::from_managed_action(request.action),
            high_risk: request.high_risk,
        }
    }

    pub fn into_managed_request(
        self,
    ) -> Result<ManagedExternalActionRequest, FrameworkAdapterError> {
        Ok(ManagedExternalActionRequest {
            session: self.session.into_framework_session()?,
            action: self.action.into_managed_action(),
            high_risk: self.high_risk,
        })
    }

    pub fn stable_request_id(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.session.run_id,
            self.session.session_id,
            self.session.worker_id,
            self.session.adapter_name,
            self.action.kind_label()
        )
    }
}

impl ExternalActionSession {
    pub fn from_framework_session(session: FrameworkAdapterSession) -> Self {
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

    pub fn into_framework_session(self) -> Result<FrameworkAdapterSession, FrameworkAdapterError> {
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
    pub fn from_supported_framework(framework: SupportedFramework) -> Self {
        match framework {
            SupportedFramework::ClaudeCode => Self::ClaudeCode,
            SupportedFramework::Codex => Self::Codex,
            SupportedFramework::Hermes => Self::Hermes,
            SupportedFramework::NativeHarness => Self::NativeHarness,
        }
    }

    pub fn into_supported_framework(self) -> SupportedFramework {
        match self {
            Self::ClaudeCode => SupportedFramework::ClaudeCode,
            Self::Codex => SupportedFramework::Codex,
            Self::Hermes => SupportedFramework::Hermes,
            Self::NativeHarness => SupportedFramework::NativeHarness,
        }
    }
}

impl ExternalActionMode {
    pub fn from_framework_mode(mode: FrameworkAdapterMode) -> Self {
        match mode {
            FrameworkAdapterMode::Managed => Self::Managed,
            FrameworkAdapterMode::SelfHosted => Self::SelfHosted,
        }
    }

    pub fn into_framework_mode(self) -> FrameworkAdapterMode {
        match self {
            Self::Managed => FrameworkAdapterMode::Managed,
            Self::SelfHosted => FrameworkAdapterMode::SelfHosted,
        }
    }
}

impl ExternalActionSpec {
    pub fn kind_label(&self) -> &'static str {
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

    pub fn from_managed_action(action: ManagedExternalAction) -> Self {
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

    pub fn into_managed_action(self) -> ManagedExternalAction {
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
    pub fn from_managed_access(access: ManagedFilesystemAccess) -> Self {
        match access {
            ManagedFilesystemAccess::Read => Self::Read,
            ManagedFilesystemAccess::Write => Self::Write,
            ManagedFilesystemAccess::Delete => Self::Delete,
        }
    }

    pub fn into_managed_access(self) -> ManagedFilesystemAccess {
        match self {
            Self::Read => ManagedFilesystemAccess::Read,
            Self::Write => ManagedFilesystemAccess::Write,
            Self::Delete => ManagedFilesystemAccess::Delete,
        }
    }
}

impl ExternalActionBrowserOperation {
    pub fn from_managed_operation(operation: ManagedBrowserOperation) -> Self {
        match operation {
            ManagedBrowserOperation::Navigate => Self::Navigate,
            ManagedBrowserOperation::Screenshot => Self::Screenshot,
            ManagedBrowserOperation::Click => Self::Click,
            ManagedBrowserOperation::Script => Self::Script,
        }
    }

    pub fn into_managed_operation(self) -> ManagedBrowserOperation {
        match self {
            Self::Navigate => ManagedBrowserOperation::Navigate,
            Self::Screenshot => ManagedBrowserOperation::Screenshot,
            Self::Click => ManagedBrowserOperation::Click,
            Self::Script => ManagedBrowserOperation::Script,
        }
    }
}

impl ExternalActionMemoryAccess {
    pub fn from_managed_access(access: ManagedMemoryAccess) -> Self {
        match access {
            ManagedMemoryAccess::Read => Self::Read,
            ManagedMemoryAccess::Write => Self::Write,
        }
    }

    pub fn into_managed_access(self) -> ManagedMemoryAccess {
        match self {
            Self::Read => ManagedMemoryAccess::Read,
            Self::Write => ManagedMemoryAccess::Write,
        }
    }
}

impl ExternalActionAuthorizationResponse {
    pub fn from_decision(decision: ManagedExternalActionDecision) -> Self {
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

    pub fn rejected(error: FrameworkAdapterError) -> Self {
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

    pub fn into_decision(self) -> Result<ManagedExternalActionDecision, FrameworkAdapterError> {
        let Some(event_json) = self.event else {
            if !self.accepted {
                let message = self.error.map(|error| error.message).unwrap_or_else(|| {
                    "gateway external action authorization rejected".to_string()
                });
                return Err(FrameworkAdapterError::CapabilityDenied(message));
            }
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
        Ok(ManagedExternalActionDecision { decision, event })
    }
}

pub fn normalized_event_from_canonical_json(
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
        .collect::<Option<BTreeMap<_, _>>>()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedToolAction {
    pub tool_name: String,
    pub arguments_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMcpToolAction {
    pub server_name: String,
    pub tool_name: String,
    pub arguments_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCliAction {
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: String,
    pub env_policy: String,
    pub timeout_millis: u64,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub artifact_capture: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSkillAction {
    pub skill_id: String,
    pub declared_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFilesystemAction {
    pub path: String,
    pub access: ManagedFilesystemAccess,
    pub workspace_relative: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedFilesystemAccess {
    Read,
    Write,
    Delete,
}

impl ManagedFilesystemAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBrowserAction {
    pub operation: ManagedBrowserOperation,
    pub url: String,
    pub timeout_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedBrowserOperation {
    Navigate,
    Screenshot,
    Click,
    Script,
}

impl ManagedBrowserOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Screenshot => "screenshot",
            Self::Click => "click",
            Self::Script => "script",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRestAction {
    pub method: String,
    pub url: String,
    pub headers_policy: String,
    pub body_policy: String,
    pub timeout_millis: u64,
    pub retry_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSecretAction {
    pub secret_id: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMemoryAction {
    pub access: ManagedMemoryAccess,
    pub namespace: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedMemoryAccess {
    Read,
    Write,
}

impl ManagedMemoryAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNetworkEgressAction {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

pub fn authorize_managed_external_action<A>(
    authorizer: &A,
    request: ManagedExternalActionRequest,
) -> Result<(CapabilityAuthorizationEvidence, NormalizedFrameworkEvent), FrameworkAdapterError>
where
    A: CapabilityAuthorizer,
{
    validate_managed_external_action(&request.action)?;
    let mut metadata = request.action.metadata();
    let capability_request = FrameworkCapabilityRequest {
        session: request.session,
        action: request.action.capability_action(),
        target: request.action.target(),
        high_risk: request.high_risk,
    };
    let (evidence, mut event) = authorize_framework_capability(authorizer, capability_request)?;
    metadata.insert(
        "external_action".to_string(),
        evidence.action.as_str().to_string(),
    );
    metadata.insert("external_target".to_string(), evidence.target.clone());
    event.metadata.extend(metadata);
    Ok((evidence, event))
}

pub fn self_hosted_external_action_report(
    request: ManagedExternalActionRequest,
) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
    validate_managed_external_action(&request.action)?;
    let mut event = self_hosted_framework_capability_report(FrameworkCapabilityRequest {
        session: request.session,
        action: request.action.capability_action(),
        target: request.action.target(),
        high_risk: request.high_risk,
    })?;
    let mut metadata = request.action.metadata();
    metadata.insert(
        "external_action".to_string(),
        event.metadata["action"].clone(),
    );
    metadata.insert(
        "external_target".to_string(),
        event.metadata["target"].clone(),
    );
    event.metadata.extend(metadata);
    Ok(event)
}

pub fn managed_external_action_transport_failure_event(
    request: &ManagedExternalActionRequest,
    reason: impl Into<String>,
) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
    validate_managed_external_action(&request.action)?;
    let reason = reason.into();
    let mut metadata = request.action.metadata();
    metadata.extend(BTreeMap::from([
        ("tenant_id".to_string(), request.session.tenant_id.clone()),
        (
            "workspace_id".to_string(),
            request.session.workspace_id.clone(),
        ),
        ("worker_id".to_string(), request.session.worker_id.clone()),
        (
            "action".to_string(),
            request.action.capability_action().as_str().to_string(),
        ),
        ("target".to_string(), request.action.target()),
        ("decision".to_string(), "denied".to_string()),
        (
            "isolation_backend".to_string(),
            request.session.isolation_backend.clone(),
        ),
        (
            "external_action".to_string(),
            request.action.capability_action().as_str().to_string(),
        ),
        ("external_target".to_string(), request.action.target()),
        (
            "failure_source".to_string(),
            "gateway_authorizer_transport".to_string(),
        ),
    ]));
    Ok(NormalizedFrameworkEvent {
        session_id: request.session.session_id.clone(),
        run_id: request.session.run_id.clone(),
        adapter_name: request.session.adapter_name.clone(),
        adapter_version: request.session.adapter_version.clone(),
        framework: request.session.framework,
        mode: request.session.mode,
        kind: FrameworkAdapterEventKind::CapabilityDenied,
        message: Some(reason),
        metadata,
    })
}

fn validate_managed_external_action(
    action: &ManagedExternalAction,
) -> Result<(), FrameworkAdapterError> {
    match action {
        ManagedExternalAction::Tool(action) => {
            require_request_field("tool_name", &action.tool_name)?;
            require_request_field("arguments_policy", &action.arguments_policy)?;
        }
        ManagedExternalAction::McpTool(action) => {
            require_request_field("server_name", &action.server_name)?;
            require_request_field("tool_name", &action.tool_name)?;
            require_request_field("arguments_policy", &action.arguments_policy)?;
        }
        ManagedExternalAction::Cli(action) => {
            require_request_field("command", &action.command)?;
            require_request_field("working_dir", &action.working_dir)?;
            require_request_field("env_policy", &action.env_policy)?;
            require_positive_u64("timeout_millis", action.timeout_millis)?;
            require_positive_u64("stdout_limit_bytes", action.stdout_limit_bytes)?;
            require_positive_u64("stderr_limit_bytes", action.stderr_limit_bytes)?;
            if action.args.iter().any(|arg| arg.trim().is_empty()) {
                return Err(FrameworkAdapterError::InvalidRequest(
                    "cli args must not contain empty values".to_string(),
                ));
            }
        }
        ManagedExternalAction::Skill(action) => {
            require_request_field("skill_id", &action.skill_id)?;
            if action
                .declared_capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
            {
                return Err(FrameworkAdapterError::InvalidRequest(
                    "declared_capabilities must not contain empty values".to_string(),
                ));
            }
        }
        ManagedExternalAction::Filesystem(action) => {
            require_request_field("path", &action.path)?;
        }
        ManagedExternalAction::Browser(action) => {
            require_request_field("url", &action.url)?;
            require_positive_u64("timeout_millis", action.timeout_millis)?;
        }
        ManagedExternalAction::Rest(action) => {
            require_request_field("method", &action.method)?;
            require_request_field("url", &action.url)?;
            require_request_field("headers_policy", &action.headers_policy)?;
            require_request_field("body_policy", &action.body_policy)?;
            require_positive_u64("timeout_millis", action.timeout_millis)?;
        }
        ManagedExternalAction::Secret(action) => {
            require_request_field("secret_id", &action.secret_id)?;
            require_request_field("purpose", &action.purpose)?;
        }
        ManagedExternalAction::Memory(action) => {
            require_request_field("namespace", &action.namespace)?;
            require_request_field("key", &action.key)?;
        }
        ManagedExternalAction::NetworkEgress(action) => {
            require_request_field("host", &action.host)?;
            require_request_field("protocol", &action.protocol)?;
            if action.port == 0 {
                return Err(FrameworkAdapterError::InvalidRequest(
                    "port must be greater than zero".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn require_request_field(field: &str, value: &str) -> Result<(), FrameworkAdapterError> {
    if value.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_positive_u64(field: &str, value: u64) -> Result<(), FrameworkAdapterError> {
    if value == 0 {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn external_action_error_code(error: &FrameworkAdapterError) -> &'static str {
    match error {
        FrameworkAdapterError::InvalidDescriptor(_) => "invalid_descriptor",
        FrameworkAdapterError::InvalidRequest(_) => "invalid_request",
        FrameworkAdapterError::CapabilityDenied(_) => "capability_denied",
    }
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
        "tool.requested" => Ok(FrameworkAdapterEventKind::ToolRequested),
        "mcp.tool.requested" => Ok(FrameworkAdapterEventKind::McpToolRequested),
        "skill.requested" => Ok(FrameworkAdapterEventKind::SkillRequested),
        "filesystem.requested" => Ok(FrameworkAdapterEventKind::FilesystemRequested),
        "secret.requested" => Ok(FrameworkAdapterEventKind::SecretRequested),
        "network.egress.requested" => Ok(FrameworkAdapterEventKind::NetworkEgressRequested),
        "browser.requested" => Ok(FrameworkAdapterEventKind::BrowserRequested),
        "memory.read" => Ok(FrameworkAdapterEventKind::MemoryRead),
        "memory.write" => Ok(FrameworkAdapterEventKind::MemoryWrite),
        _ => Err(FrameworkAdapterError::InvalidRequest(format!(
            "unsupported gateway external action event kind {value}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CapabilityAuthorizationDecision, CapabilityPolicy, FrameworkAdapter,
        FrameworkAdapterCapabilities, FrameworkAdapterEventKind, FrameworkAdapterMode,
        FrameworkAdapterSessionRequest, NativeHarnessAdapter, SimpleCapabilityAuthorizer,
    };

    #[test]
    fn managed_external_action_specs_map_every_surface_to_gateway_authorization() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let actions = vec![
            (
                ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                CapabilityAction::Tool,
                "tool:native.echo",
            ),
            (
                ManagedExternalAction::McpTool(ManagedMcpToolAction {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                }),
                CapabilityAction::McpTool,
                "mcp:filesystem:read_file",
            ),
            (
                ManagedExternalAction::Cli(ManagedCliAction {
                    command: "cargo".to_string(),
                    args: vec!["test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "allowlist".to_string(),
                    timeout_millis: 30_000,
                    stdout_limit_bytes: 65_536,
                    stderr_limit_bytes: 65_536,
                    artifact_capture: true,
                }),
                CapabilityAction::Cli,
                "cargo",
            ),
            (
                ManagedExternalAction::Skill(ManagedSkillAction {
                    skill_id: "repo-test".to_string(),
                    declared_capabilities: vec!["cli".to_string(), "filesystem".to_string()],
                }),
                CapabilityAction::Skill,
                "skill:repo-test",
            ),
            (
                ManagedExternalAction::Filesystem(ManagedFilesystemAction {
                    path: "src/lib.rs".to_string(),
                    access: ManagedFilesystemAccess::Read,
                    workspace_relative: true,
                }),
                CapabilityAction::Filesystem,
                "read:src/lib.rs",
            ),
            (
                ManagedExternalAction::Browser(ManagedBrowserAction {
                    operation: ManagedBrowserOperation::Navigate,
                    url: "https://docs.example.test".to_string(),
                    timeout_millis: 5_000,
                }),
                CapabilityAction::Browser,
                "browser:navigate:https://docs.example.test",
            ),
            (
                ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "redact_authorization".to_string(),
                    body_policy: "guardrail_scan".to_string(),
                    timeout_millis: 10_000,
                    retry_limit: 2,
                }),
                CapabilityAction::Rest,
                "POST https://api.example.test/v1/jobs",
            ),
            (
                ManagedExternalAction::Secret(ManagedSecretAction {
                    secret_id: "openai-api-key".to_string(),
                    purpose: "provider_call".to_string(),
                }),
                CapabilityAction::Secret,
                "secret:openai-api-key",
            ),
            (
                ManagedExternalAction::Memory(ManagedMemoryAction {
                    access: ManagedMemoryAccess::Read,
                    namespace: "session".to_string(),
                    key: "plan".to_string(),
                }),
                CapabilityAction::MemoryRead,
                "memory:read:session:plan",
            ),
            (
                ManagedExternalAction::Memory(ManagedMemoryAction {
                    access: ManagedMemoryAccess::Write,
                    namespace: "session".to_string(),
                    key: "summary".to_string(),
                }),
                CapabilityAction::MemoryWrite,
                "memory:write:session:summary",
            ),
            (
                ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                    host: "api.example.test".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                }),
                CapabilityAction::NetworkEgress,
                "api.example.test:443",
            ),
        ];
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: actions.iter().map(|(_, action, _)| *action).collect(),
            allow_direct_network_egress: true,
            ..CapabilityPolicy::default()
        });

        for (action, expected_capability, expected_target) in actions {
            assert_eq!(action.capability_action(), expected_capability);
            assert_eq!(action.target(), expected_target);

            let (evidence, event) = authorize_managed_external_action(
                &authorizer,
                ManagedExternalActionRequest {
                    session: session.clone(),
                    action,
                    high_risk: false,
                },
            )
            .unwrap();

            assert_eq!(evidence.decision, CapabilityAuthorizationDecision::Allowed);
            assert_eq!(evidence.action, expected_capability);
            assert_eq!(evidence.target, expected_target);
            assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityAllowed);
            assert_eq!(
                event.metadata.get("external_action").map(String::as_str),
                Some(expected_capability.as_str())
            );
            assert_eq!(
                event.metadata.get("external_target").map(String::as_str),
                Some(expected_target)
            );
        }
    }

    #[test]
    fn external_action_wire_contract_round_trips_managed_request_and_response() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let managed = ManagedExternalActionRequest {
            session,
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        };
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(managed);

        assert_eq!(
            authorization.stable_request_id(),
            "run-1:session-1:worker-1:native-harness:tool"
        );

        let round_trip = authorization.into_managed_request().unwrap();
        assert_eq!(round_trip.session.run_id, "run-1");
        assert_eq!(round_trip.action.target(), "tool:native.echo");

        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        });
        let (evidence, event) = authorize_managed_external_action(&authorizer, round_trip).unwrap();
        let response =
            ExternalActionAuthorizationResponse::from_decision(ManagedExternalActionDecision {
                decision: evidence.decision,
                event,
            });
        let decision = response.into_decision().unwrap();

        assert!(decision.allowed());
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
    fn managed_external_action_transport_requests_match_golden_fixture() {
        let actual = serde_json::to_value(managed_external_action_transport_requests()).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/managed_external_action_transport_requests.golden.json"
        ))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn managed_external_action_transport_responses_match_golden_fixture() {
        let actual = serde_json::to_value(managed_external_action_transport_responses()).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/managed_external_action_transport_responses.golden.json"
        ))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn external_action_response_rejects_malformed_accepted_evidence() {
        let response = ExternalActionAuthorizationResponse {
            accepted: true,
            decision: Some(ExternalActionDecision::Allowed),
            event: Some(serde_json::json!({
                "session_id": "session-1",
                "run_id": "run-1",
                "adapter_name": "native-harness",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "framework": "native_harness",
                "mode": "managed",
                "kind": "tool.completed",
                "message": null,
                "metadata": {}
            })),
            error: None,
        };

        let error = response.into_decision().unwrap_err();

        assert!(error
            .to_string()
            .contains("unsupported gateway external action event kind"));
    }

    #[test]
    fn managed_network_egress_external_action_fails_closed_without_egress_policy() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::NetworkEgress]),
            allow_direct_network_egress: false,
            ..CapabilityPolicy::default()
        });

        let (_, event) = authorize_managed_external_action(
            &authorizer,
            ManagedExternalActionRequest {
                session,
                action: ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                    host: "api.example.test".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();

        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityDenied);
        assert_eq!(
            event.metadata.get("decision").map(String::as_str),
            Some("denied")
        );
        assert_eq!(
            event.metadata.get("host").map(String::as_str),
            Some("api.example.test")
        );
        assert!(event
            .message
            .as_deref()
            .is_some_and(|message| message.contains("direct network egress")));
    }

    #[test]
    fn managed_cli_external_action_requires_approval_and_projects_policy_shape() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
            approval_required_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        });

        let (_, event) = authorize_managed_external_action(
            &authorizer,
            ManagedExternalActionRequest {
                session,
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
        .unwrap();

        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityRequested);
        assert_eq!(
            event.metadata.get("decision").map(String::as_str),
            Some("approval_required")
        );
        assert_eq!(
            event.metadata.get("command").map(String::as_str),
            Some("bash")
        );
        assert_eq!(
            event.metadata.get("env_policy").map(String::as_str),
            Some("deny_all_except_path")
        );
        assert_eq!(
            event.metadata.get("timeout_millis").map(String::as_str),
            Some("1000")
        );
        assert_eq!(
            event.metadata.get("artifact_capture").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            event.timeline_record().unwrap().outcome,
            "approval_required"
        );
    }

    #[test]
    fn managed_rest_external_action_denial_keeps_request_policy_evidence() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = SimpleCapabilityAuthorizer::default();

        let (_, event) = authorize_managed_external_action(
            &authorizer,
            ManagedExternalActionRequest {
                session,
                action: ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.third-party.test/v1/payments".to_string(),
                    headers_policy: "strip_credentials".to_string(),
                    body_policy: "redact_and_scan".to_string(),
                    timeout_millis: 2_000,
                    retry_limit: 0,
                }),
                high_risk: false,
            },
        )
        .unwrap();

        let record = event.timeline_record().unwrap();

        assert_eq!(record.kind, "capability.denied");
        assert_eq!(
            record.target,
            "POST https://api.third-party.test/v1/payments"
        );
        assert_eq!(record.outcome, "denied");
        assert_eq!(
            event.metadata.get("headers_policy").map(String::as_str),
            Some("strip_credentials")
        );
        assert_eq!(
            event.metadata.get("body_policy").map(String::as_str),
            Some("redact_and_scan")
        );
    }

    #[test]
    fn managed_external_action_transport_failure_projects_to_denied_timeline_event() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let event = managed_external_action_transport_failure_event(
            &ManagedExternalActionRequest {
                session,
                action: ManagedExternalAction::Cli(ManagedCliAction {
                    command: "codex".to_string(),
                    args: vec!["run".to_string(), "--json".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "gateway_injected_only".to_string(),
                    timeout_millis: 30_000,
                    stdout_limit_bytes: 1024,
                    stderr_limit_bytes: 1024,
                    artifact_capture: true,
                }),
                high_risk: false,
            },
            "gateway external action HTTP authorizer response read failed: timed out",
        )
        .unwrap();

        let record = event.timeline_record().unwrap();

        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityDenied);
        assert_eq!(record.kind, "capability.denied");
        assert_eq!(record.target, "codex");
        assert_eq!(record.outcome, "denied");
        assert_eq!(
            event.metadata.get("failure_source").map(String::as_str),
            Some("gateway_authorizer_transport")
        );
        assert_eq!(
            event.metadata.get("external_action").map(String::as_str),
            Some("cli")
        );
        assert!(event
            .message
            .as_deref()
            .is_some_and(|message| message.contains("response read failed")));
    }

    #[test]
    fn self_hosted_external_action_report_is_telemetry_not_enforcement() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter
            .start_session(FrameworkAdapterSessionRequest {
                mode: FrameworkAdapterMode::SelfHosted,
                ..session_request()
            })
            .unwrap();

        let event = self_hosted_external_action_report(ManagedExternalActionRequest {
            session,
            action: ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                host: "customer.local".to_string(),
                port: 8443,
                protocol: "https".to_string(),
            }),
            high_risk: true,
        })
        .unwrap();

        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityRequested);
        assert_eq!(
            event.metadata.get("trust_level").map(String::as_str),
            Some("reported_by_self_hosted_worker")
        );
        assert_eq!(
            event.metadata.get("external_action").map(String::as_str),
            Some("network.egress")
        );
        assert_eq!(
            event.metadata.get("external_target").map(String::as_str),
            Some("customer.local:8443")
        );
    }

    #[test]
    fn invalid_external_action_specs_fail_before_authorization() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        });

        let error = authorize_managed_external_action(
            &authorizer,
            ManagedExternalActionRequest {
                session,
                action: ManagedExternalAction::Cli(ManagedCliAction {
                    command: "bash".to_string(),
                    args: vec!["".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "allowlist".to_string(),
                    timeout_millis: 0,
                    stdout_limit_bytes: 4096,
                    stderr_limit_bytes: 4096,
                    artifact_capture: false,
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("timeout_millis"));
    }

    fn session_request() -> FrameworkAdapterSessionRequest {
        FrameworkAdapterSessionRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            isolation_backend: "firecracker".to_string(),
            mode: FrameworkAdapterMode::Managed,
            required_capabilities: FrameworkAdapterCapabilities {
                tools: true,
                mcp: true,
                streaming: true,
                ..FrameworkAdapterCapabilities::default()
            },
        }
    }

    fn managed_external_action_transport_requests() -> Vec<GatewayExternalActionTransportRequest> {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        [
            ManagedExternalActionRequest {
                session: session.clone(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
            ManagedExternalActionRequest {
                session: session.clone(),
                action: ManagedExternalAction::McpTool(ManagedMcpToolAction {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                }),
                high_risk: false,
            },
            ManagedExternalActionRequest {
                session: session.clone(),
                action: ManagedExternalAction::Cli(ManagedCliAction {
                    command: "cargo".to_string(),
                    args: vec!["test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "gateway_injected_only".to_string(),
                    timeout_millis: 30_000,
                    stdout_limit_bytes: 65_536,
                    stderr_limit_bytes: 65_536,
                    artifact_capture: true,
                }),
                high_risk: true,
            },
            ManagedExternalActionRequest {
                session: session.clone(),
                action: ManagedExternalAction::Skill(ManagedSkillAction {
                    skill_id: "repo-test".to_string(),
                    declared_capabilities: vec!["cli".to_string(), "filesystem".to_string()],
                }),
                high_risk: true,
            },
            ManagedExternalActionRequest {
                session,
                action: ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "redact_authorization".to_string(),
                    body_policy: "guardrail_scan".to_string(),
                    timeout_millis: 10_000,
                    retry_limit: 2,
                }),
                high_risk: true,
            },
        ]
        .into_iter()
        .map(|managed| {
            let authorization = ExternalActionAuthorizationRequest::from_managed_request(managed);
            GatewayExternalActionTransportRequest {
                request_id: authorization.stable_request_id(),
                authorization,
            }
        })
        .collect()
    }

    fn managed_external_action_transport_responses() -> Vec<GatewayExternalActionTransportResponse>
    {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        [
            managed_external_action_response_case(
                ManagedExternalActionRequest {
                    session: session.clone(),
                    action: ManagedExternalAction::Tool(ManagedToolAction {
                        tool_name: "native.echo".to_string(),
                        arguments_policy: "redacted_json".to_string(),
                    }),
                    high_risk: false,
                },
                CapabilityPolicy {
                    allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Tool]),
                    ..CapabilityPolicy::default()
                },
            ),
            managed_external_action_response_case(
                ManagedExternalActionRequest {
                    session: session.clone(),
                    action: ManagedExternalAction::Rest(ManagedRestAction {
                        method: "POST".to_string(),
                        url: "https://api.third-party.test/v1/payments".to_string(),
                        headers_policy: "strip_credentials".to_string(),
                        body_policy: "redact_and_scan".to_string(),
                        timeout_millis: 2_000,
                        retry_limit: 0,
                    }),
                    high_risk: false,
                },
                CapabilityPolicy::default(),
            ),
            managed_external_action_response_case(
                ManagedExternalActionRequest {
                    session: session.clone(),
                    action: ManagedExternalAction::Cli(ManagedCliAction {
                        command: "bash".to_string(),
                        args: vec!["-lc".to_string(), "cargo test".to_string()],
                        working_dir: "/workspace".to_string(),
                        env_policy: "gateway_injected_only".to_string(),
                        timeout_millis: 30_000,
                        stdout_limit_bytes: 65_536,
                        stderr_limit_bytes: 65_536,
                        artifact_capture: true,
                    }),
                    high_risk: true,
                },
                CapabilityPolicy {
                    allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
                    approval_required_actions: std::collections::BTreeSet::from([
                        CapabilityAction::Cli,
                    ]),
                    ..CapabilityPolicy::default()
                },
            ),
            {
                let authorization = ExternalActionAuthorizationRequest::from_managed_request(
                    ManagedExternalActionRequest {
                        session,
                        action: ManagedExternalAction::Browser(ManagedBrowserAction {
                            operation: ManagedBrowserOperation::Navigate,
                            url: "https://docs.example.test".to_string(),
                            timeout_millis: 0,
                        }),
                        high_risk: false,
                    },
                );
                let request_id = authorization.stable_request_id();
                GatewayExternalActionTransportResponse {
                    request_id,
                    response: ExternalActionAuthorizationResponse::rejected(
                        FrameworkAdapterError::InvalidRequest(
                            "timeout_millis must be greater than zero".to_string(),
                        ),
                    ),
                }
            },
        ]
        .into()
    }

    fn managed_external_action_response_case(
        managed: ManagedExternalActionRequest,
        policy: CapabilityPolicy,
    ) -> GatewayExternalActionTransportResponse {
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(managed);
        let request_id = authorization.stable_request_id();
        let managed = authorization.into_managed_request().unwrap();
        let authorizer = SimpleCapabilityAuthorizer::new(policy);
        let (evidence, event) = authorize_managed_external_action(&authorizer, managed).unwrap();
        GatewayExternalActionTransportResponse {
            request_id,
            response: ExternalActionAuthorizationResponse::from_decision(
                ManagedExternalActionDecision {
                    decision: evidence.decision,
                    event,
                },
            ),
        }
    }
}
