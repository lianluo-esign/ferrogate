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

use crate::{
    authorize_framework_capability, self_hosted_framework_capability_report, CapabilityAction,
    CapabilityAuthorizationEvidence, CapabilityAuthorizer, FrameworkAdapterError,
    FrameworkAdapterSession, FrameworkCapabilityRequest, NormalizedFrameworkEvent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExternalActionRequest {
    pub session: FrameworkAdapterSession,
    pub action: ManagedExternalAction,
    pub high_risk: bool,
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
}
