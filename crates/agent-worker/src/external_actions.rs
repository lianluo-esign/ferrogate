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

use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityAction, CapabilityAuthorizationDecision,
    CapabilityAuthorizer, CapabilityPolicy, FrameworkAdapterError, FrameworkAdapterMode,
    FrameworkAdapterSession, ManagedExternalAction, ManagedExternalActionRequest,
    ManagedToolAction, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer, SupportedFramework,
};
use std::collections::BTreeSet;

use anyhow::Result;

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
}
