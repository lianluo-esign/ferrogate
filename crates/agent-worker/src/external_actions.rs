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
    collections::BTreeMap,
    collections::BTreeSet,
    io::{self, Read, Write},
    net::TcpListener,
    net::{Shutdown, SocketAddr, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    authorize_managed_external_action, managed_external_action_transport_failure_event,
    CapabilityAction, CapabilityAuthorizationDecision, CapabilityAuthorizer, CapabilityPolicy,
    ExternalActionAuthorizationRequest, ExternalActionAuthorizationResponse, FrameworkAdapterError,
    FrameworkAdapterEventKind, FrameworkAdapterMode, FrameworkAdapterSession,
    GatewayExternalActionTransportRequest, GatewayExternalActionTransportResponse,
    ManagedBrowserAction, ManagedBrowserOperation, ManagedCliAction, ManagedExternalAction,
    ManagedExternalActionDecision, ManagedExternalActionRequest, ManagedFilesystemAccess,
    ManagedFilesystemAction, ManagedMcpToolAction, ManagedMemoryAccess, ManagedMemoryAction,
    ManagedNetworkEgressAction, ManagedRestAction, ManagedSecretAction, ManagedSkillAction,
    ManagedToolAction, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer, SupportedFramework,
};

const EXTERNAL_ACTION_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const DEFAULT_EXTERNAL_ACTION_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Trust level marker for managed external-action audit/billing evidence.
///
/// Managed actions are enforced at the gateway capability boundary, so their
/// evidence is `enforced`. Self-hosted worker telemetry is only reported and
/// must never be treated as enforced evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalActionEvidenceTrust {
    Enforced,
    Reported,
}

impl ExternalActionEvidenceTrust {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Reported => "reported",
        }
    }

    fn for_mode(mode: FrameworkAdapterMode) -> Self {
        match mode {
            FrameworkAdapterMode::Managed => Self::Enforced,
            FrameworkAdapterMode::SelfHosted => Self::Reported,
        }
    }
}

/// Coarse billing class derived from the capability action, so downstream
/// billing can attribute spend to tool, runtime, network, or third-party API
/// usage without inspecting the action payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalActionBillingClass {
    Tool,
    Runtime,
    Network,
    ThirdPartyApi,
}

impl ExternalActionBillingClass {
    fn for_action(action: CapabilityAction) -> Self {
        match action {
            CapabilityAction::Tool | CapabilityAction::McpTool => Self::Tool,
            CapabilityAction::Cli
            | CapabilityAction::Skill
            | CapabilityAction::Browser
            | CapabilityAction::Filesystem
            | CapabilityAction::Secret
            | CapabilityAction::MemoryRead
            | CapabilityAction::MemoryWrite => Self::Runtime,
            CapabilityAction::NetworkEgress => Self::Network,
            CapabilityAction::Rest => Self::ThirdPartyApi,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Runtime => "runtime",
            Self::Network => "network",
            Self::ThirdPartyApi => "third_party_api",
        }
    }
}

/// Usage units placeholder for one authorized external action.
///
/// Authorization can only attribute the invocation itself; token, runtime, and
/// egress units stay zero until the action runs and the billing pipeline settles
/// real usage. This is a typed placeholder, not a pricing engine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ExternalActionUsageUnits {
    pub(crate) invocations: u64,
    pub(crate) token_units: u64,
    pub(crate) runtime_millis: u64,
    pub(crate) egress_bytes: u64,
}

/// Billing attribution for one managed external-action authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionBillingAttribution {
    pub(crate) action_class: ExternalActionBillingClass,
    pub(crate) usage: ExternalActionUsageUnits,
}

impl ExternalActionBillingAttribution {
    fn for_action(action: CapabilityAction) -> Self {
        Self {
            action_class: ExternalActionBillingClass::for_action(action),
            usage: ExternalActionUsageUnits {
                invocations: 1,
                ..ExternalActionUsageUnits::default()
            },
        }
    }
}

/// Typed audit + billing evidence for one managed external-action authorization.
///
/// Every managed authorization decision (allow, deny, or approval-required)
/// yields exactly one record linking the decision to the full worker identity
/// tuple — tenant, workspace, session, run, worker, adapter, and isolation
/// backend — plus the capability action, the trust level, and billing
/// attribution. Self-hosted telemetry produces a record marked `reported` with
/// no gateway enforcement decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionEvidenceRecord {
    pub(crate) tenant_id: String,
    pub(crate) workspace_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) worker_id: String,
    pub(crate) adapter_name: String,
    pub(crate) adapter_version: String,
    pub(crate) isolation_backend: String,
    pub(crate) action: CapabilityAction,
    pub(crate) target: String,
    pub(crate) decision: Option<CapabilityAuthorizationDecision>,
    pub(crate) trust: ExternalActionEvidenceTrust,
    pub(crate) billing: ExternalActionBillingAttribution,
}

impl ExternalActionEvidenceRecord {
    /// Build the audit/billing record from a worker session, the managed action,
    /// and the gateway decision. `decision` is `None` for self-hosted reported
    /// telemetry, where there is no gateway enforcement decision to attribute.
    pub(crate) fn for_action(
        session: &FrameworkAdapterSession,
        action: &ManagedExternalAction,
        decision: Option<CapabilityAuthorizationDecision>,
    ) -> Self {
        let capability = action.capability_action();
        Self {
            tenant_id: session.tenant_id.clone(),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            run_id: session.run_id.clone(),
            worker_id: session.worker_id.clone(),
            adapter_name: session.adapter_name.clone(),
            adapter_version: session.adapter_version.clone(),
            isolation_backend: session.isolation_backend.clone(),
            action: capability,
            target: action.target(),
            decision,
            trust: ExternalActionEvidenceTrust::for_mode(session.mode),
            billing: ExternalActionBillingAttribution::for_action(capability),
        }
    }

    pub(crate) fn decision_label(&self) -> &'static str {
        match self.decision {
            Some(CapabilityAuthorizationDecision::Allowed) => "allowed",
            Some(CapabilityAuthorizationDecision::Denied) => "denied",
            Some(CapabilityAuthorizationDecision::ApprovalRequired) => "approval_required",
            None => "reported",
        }
    }

    /// Single-line audit tag linking the decision to the full identity tuple.
    ///
    /// Emitted alongside denial errors so denied managed actions stay visible in
    /// run timelines instead of disappearing as opaque worker-local failures.
    pub(crate) fn audit_tag(&self) -> String {
        format!(
            "audit[tenant={} workspace={} session={} run={} worker={} adapter={}@{} \
             isolation={} action={} target={} decision={} trust={} \
             billing={}/invocations:{}/tokens:{}/runtime_ms:{}/egress_bytes:{}]",
            self.tenant_id,
            self.workspace_id,
            self.session_id,
            self.run_id,
            self.worker_id,
            self.adapter_name,
            self.adapter_version,
            self.isolation_backend,
            self.action.as_str(),
            self.target,
            self.decision_label(),
            self.trust.as_str(),
            self.billing.action_class.as_str(),
            self.billing.usage.invocations,
            self.billing.usage.token_units,
            self.billing.usage.runtime_millis,
            self.billing.usage.egress_bytes,
        )
    }
}

/// A managed external-action gate decision paired with its audit/billing record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerExternalActionEvidence {
    pub(crate) decision: ExternalActionGateDecision,
    pub(crate) evidence: ExternalActionEvidenceRecord,
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
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let HandlerExternalActionEvidence { decision, evidence } =
        request_handler_external_action_evidence(authorizer, request)?;
    if decision.allowed() {
        Ok(decision)
    } else {
        Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed external action denied before handler execution: {} {}",
            decision
                .event
                .message
                .as_deref()
                .unwrap_or("gateway authorization was not allowed"),
            evidence.audit_tag(),
        )))
    }
}

/// Authorize a managed external action and return the gate decision paired with
/// its typed audit/billing evidence record.
///
/// This is the managed authorization entrypoint that always produces evidence:
/// allow, deny, and approval-required decisions each yield exactly one record.
/// Denied decisions are returned here (not converted to an error) so the
/// evidence stays visible to the caller instead of being swallowed as a
/// worker-local failure.
pub(crate) fn request_handler_external_action_evidence<A>(
    authorizer: Option<&A>,
    request: ExternalActionGateRequest,
) -> Result<HandlerExternalActionEvidence, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let session = request.session.clone();
    let action = request.action.clone();
    let decision = request_handler_external_action_decision(authorizer, request)?;
    let evidence =
        ExternalActionEvidenceRecord::for_action(&session, &action, Some(decision.decision));
    Ok(HandlerExternalActionEvidence { decision, evidence })
}

pub(crate) fn request_handler_external_action_decision<A>(
    authorizer: Option<&A>,
    request: ExternalActionGateRequest,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    validate_managed_worker_session(&request.session)?;
    let Some(authorizer) = authorizer else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed external action denied: gateway authorization client is unavailable"
                .to_string(),
        ));
    };
    authorizer.authorize_external_action(ManagedExternalActionRequest {
        session: request.session,
        action: request.action,
        high_risk: request.high_risk,
    })
}

pub(crate) fn external_action_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let decision = external_action_smoke(mode)?;
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

pub(crate) fn external_action_unix_transport_smoke_command(
    mode: FrameworkAdapterMode,
) -> Result<()> {
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
            session: smoke_session(mode),
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

pub(crate) fn external_action_http_transport_smoke_command(
    endpoint: SocketAddr,
    mode: FrameworkAdapterMode,
) -> Result<()> {
    let client = HttpGatewayExternalActionAuthorizer::new(endpoint);
    let decision = authorize_handler_external_action(
        Some(&client),
        ExternalActionGateRequest {
            session: smoke_session(mode),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )?;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn governed_cli_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf 'ferrogate governed cli smoke\\n'".to_string(),
        ],
        working_dir: std::env::current_dir()?.display().to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_cli_action(&gate, smoke_session(mode), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_cli_timeout_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "sleep 1".to_string()],
        working_dir: std::env::current_dir()?.display().to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 25,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_cli_action_with_failure_evidence(
        &gate,
        smoke_session(mode),
        action,
        false,
    )?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_cli_cancel_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "sleep 5".to_string()],
        working_dir: std::env::current_dir()?.display().to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 5_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_cli_action_with_cancel_evidence(
        &gate,
        smoke_session(mode),
        action,
        false,
    )?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_tool_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedToolAction {
        tool_name: "native.echo".to_string(),
        arguments_policy: "smoke_literal:ferrogate governed tool smoke".to_string(),
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_tool_action(&gate, smoke_session(mode), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_mcp_tool_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedMcpToolAction {
        server_name: "local-smoke".to_string(),
        tool_name: "echo".to_string(),
        arguments_policy: "smoke_literal:ferrogate governed mcp smoke".to_string(),
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::McpTool]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_mcp_tool_action(&gate, smoke_session(mode), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_skill_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedSkillAction {
        skill_id: "builtin.skill.echo".to_string(),
        declared_capabilities: vec!["tools".to_string(), "memory.read".to_string()],
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Skill]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_skill_action(&gate, smoke_session(mode), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_memory_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let mut store = BTreeMap::new();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([
                CapabilityAction::MemoryRead,
                CapabilityAction::MemoryWrite,
            ]),
            ..CapabilityPolicy::default()
        },
    ));
    let mut events = Vec::new();
    events.extend(execute_governed_memory_action(
        &gate,
        smoke_session(mode),
        ManagedMemoryAction {
            access: ManagedMemoryAccess::Write,
            namespace: "session".to_string(),
            key: "summary".to_string(),
        },
        &mut store,
        false,
    )?);
    events.extend(execute_governed_memory_action(
        &gate,
        smoke_session(mode),
        ManagedMemoryAction {
            access: ManagedMemoryAccess::Read,
            namespace: "session".to_string(),
            key: "summary".to_string(),
        },
        &mut store,
        false,
    )?);
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_secret_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let secrets = BTreeMap::from([(
        "openai-api-key".to_string(),
        "ferrogate governed secret smoke".to_string(),
    )]);
    let action = ManagedSecretAction {
        secret_id: "openai-api-key".to_string(),
        purpose: "provider_call".to_string(),
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Secret]),
            ..CapabilityPolicy::default()
        },
    ));
    let events =
        execute_governed_secret_action(&gate, smoke_session(mode), action, &secrets, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_network_egress_execution_smoke_command(
    mode: FrameworkAdapterMode,
) -> Result<()> {
    let server = spawn_one_shot_network_egress_smoke_server();
    let action = ManagedNetworkEgressAction {
        host: "127.0.0.1".to_string(),
        port: server.endpoint.port(),
        protocol: "tcp".to_string(),
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
            allow_direct_network_egress: true,
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_network_egress_action(&gate, smoke_session(mode), action, false)?;
    let received_payload = server.join()?;
    let output = serde_json::json!({
        "events": events
            .into_iter()
            .map(|event| event.canonical_json())
            .collect::<Vec<_>>(),
        "received_payload": received_payload,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

pub(crate) fn governed_browser_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let action = ManagedBrowserAction {
        operation: ManagedBrowserOperation::Navigate,
        url: "about:blank".to_string(),
        timeout_millis: 2_000,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Browser]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_browser_action(&gate, smoke_session(mode), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_rest_execution_smoke_command(mode: FrameworkAdapterMode) -> Result<()> {
    let server = spawn_one_shot_rest_smoke_server();
    let action = ManagedRestAction {
        method: "GET".to_string(),
        url: format!("http://{}/governed-rest-smoke", server.endpoint),
        headers_policy: "deny_credentials".to_string(),
        body_policy: "empty_body".to_string(),
        timeout_millis: 2_000,
        retry_limit: 0,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_rest_action(&gate, smoke_session(mode), action, false)?;
    let served_request = server.join()?;
    let output = serde_json::json!({
        "events": events
            .into_iter()
            .map(|event| event.canonical_json())
            .collect::<Vec<_>>(),
        "served_request": served_request,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

pub(crate) fn governed_filesystem_execution_smoke_command(
    mode: FrameworkAdapterMode,
) -> Result<()> {
    let workspace = std::env::temp_dir().join(format!(
        "ferrogate-agent-worker-filesystem-smoke-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&workspace)?;
    let result = (|| -> Result<()> {
        let file_path = workspace.join("governed-filesystem-smoke.txt");
        std::fs::write(&file_path, "ferrogate governed filesystem smoke\n")?;
        let action = ManagedFilesystemAction {
            path: "governed-filesystem-smoke.txt".to_string(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        };
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));
        let events = execute_governed_filesystem_action(
            &gate,
            smoke_session(mode),
            action,
            &workspace,
            false,
        )?;
        println!(
            "{}",
            serde_json::to_string(
                &events
                    .into_iter()
                    .map(|event| event.canonical_json())
                    .collect::<Vec<_>>()
            )?
        );
        Ok(())
    })();
    let cleanup = std::fs::remove_dir_all(&workspace);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(error), _) => Err(error),
    }
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
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(request.clone());
        let transport_request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let mut stream = match UnixStream::connect(&self.socket_path) {
            Ok(stream) => stream,
            Err(error) => {
                return transport_failure_decision(
                    &request,
                    format!("gateway external action authorizer transport unavailable: {error}"),
                );
            }
        };
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
        if let Err(error) = stream.write_all(payload.as_bytes()) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer write failed: {error}"),
            );
        }
        if let Err(error) = stream.shutdown(std::net::Shutdown::Write) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer request shutdown failed: {error}"),
            );
        }
        let mut response_json = String::new();
        if let Err(error) = read_external_action_stream(&mut stream, &mut response_json) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer response read failed: {error}"),
            );
        }
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
        response
            .response
            .into_decision()
            .map(|decision| ExternalActionGateDecision {
                decision: decision.decision,
                event: decision.event,
            })
    }
}

pub(crate) struct HttpGatewayExternalActionAuthorizer {
    endpoint: SocketAddr,
    timeout: Duration,
}

impl HttpGatewayExternalActionAuthorizer {
    pub(crate) fn new(endpoint: SocketAddr) -> Self {
        Self::new_with_timeout(endpoint, DEFAULT_EXTERNAL_ACTION_HTTP_TIMEOUT)
    }

    pub(crate) fn new_with_timeout(endpoint: SocketAddr, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }
}

impl GatewayExternalActionAuthorizer for HttpGatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(request.clone());
        let transport_request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let payload = serde_json::to_string(&transport_request).map_err(|error| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action HTTP authorization request serialization failed: {error}"
            ))
        })?;
        if payload.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization request exceeds maximum message size"
                    .to_string(),
            ));
        }
        let mut stream = match TcpStream::connect_timeout(&self.endpoint, self.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return transport_failure_decision(
                    &request,
                    format!(
                        "gateway external action HTTP authorizer transport unavailable: {error}"
                    ),
                );
            }
        };
        if let Err(error) = stream.set_read_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!(
                    "gateway external action HTTP authorizer read timeout setup failed: {error}"
                ),
            );
        }
        if let Err(error) = stream.set_write_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!(
                    "gateway external action HTTP authorizer write timeout setup failed: {error}"
                ),
            );
        }
        let http_request = format!(
            "POST /v1/agent-worker/external-actions/authorize HTTP/1.1\r\n\
             host: {}\r\n\
             content-type: application/json\r\n\
             content-length: {}\r\n\
             connection: close\r\n\
             \r\n\
             {}",
            self.endpoint,
            payload.len(),
            payload
        );
        if let Err(error) = stream.write_all(http_request.as_bytes()) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer write failed: {error}"),
            );
        }
        if let Err(error) = stream.shutdown(Shutdown::Write) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer request shutdown failed: {error}"),
            );
        }
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer response read failed: {error}"),
            );
        }
        if response.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization response exceeds maximum message size"
                    .to_string(),
            ));
        }
        let response = match decode_http_authorizer_response(&response) {
            Ok(response) => response,
            Err(error) if matches!(error, FrameworkAdapterError::CapabilityDenied(_)) => {
                return transport_failure_decision(&request, error.to_string());
            }
            Err(error) => return Err(error),
        };
        if response.request_id != transport_request.request_id {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization response request_id mismatch"
                    .to_string(),
            ));
        }
        response
            .response
            .into_decision()
            .map(|decision| ExternalActionGateDecision {
                decision: decision.decision,
                event: decision.event,
            })
    }
}

fn transport_failure_decision(
    request: &ManagedExternalActionRequest,
    reason: impl Into<String>,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
    Ok(ExternalActionGateDecision {
        decision: CapabilityAuthorizationDecision::Denied,
        event: managed_external_action_transport_failure_event(request, reason)?,
    })
}

fn decode_http_authorizer_response(
    response: &[u8],
) -> Result<GatewayExternalActionTransportResponse, FrameworkAdapterError> {
    let response = std::str::from_utf8(response).map_err(|_| {
        FrameworkAdapterError::InvalidRequest(
            "gateway external action HTTP authorizer response is not valid UTF-8".to_string(),
        )
    })?;
    let Some(header_end) = response.find("\r\n\r\n") else {
        return Err(FrameworkAdapterError::InvalidRequest(
            "gateway external action HTTP authorizer response missing header terminator"
                .to_string(),
        ));
    };
    let (headers, body) = response.split_at(header_end);
    let status_line = headers.lines().next().unwrap_or_default();
    let status_code = parse_http_status_code(status_line)?;
    if status_code != 200 {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "gateway external action HTTP authorizer returned status {status_code}"
        )));
    }
    serde_json::from_str(body[4..].trim()).map_err(|error| {
        FrameworkAdapterError::InvalidRequest(format!(
            "gateway external action HTTP authorization response decode failed: {error}"
        ))
    })
}

fn parse_http_status_code(status_line: &str) -> Result<u16, FrameworkAdapterError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "gateway external action HTTP authorizer response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action HTTP authorizer response has invalid status code: {status_line}"
            ))
        })
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

pub(crate) fn accept_external_action_authorization_request<A>(
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
    let managed_request = match request.into_managed_request() {
        Ok(request) => request,
        Err(error) => return ExternalActionAuthorizationResponse::rejected(error),
    };
    match request_handler_external_action_decision(
        Some(authorizer),
        ExternalActionGateRequest {
            session: managed_request.session,
            action: managed_request.action,
            high_risk: managed_request.high_risk,
        },
    ) {
        Ok(decision) => {
            ExternalActionAuthorizationResponse::from_decision(ManagedExternalActionDecision {
                decision: decision.decision,
                event: decision.event,
            })
        }
        Err(error) => ExternalActionAuthorizationResponse::rejected(error),
    }
}

fn external_action_smoke(mode: FrameworkAdapterMode) -> Result<ExternalActionGateDecision> {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        },
    ));
    authorize_handler_external_action(
        Some(&gate),
        ExternalActionGateRequest {
            session: smoke_session(mode),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )
    .map_err(Into::into)
}

fn execute_governed_tool_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedToolAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Tool(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_tool_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::ToolRequested,
            message: Some("managed tool action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_mcp_tool_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedMcpToolAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::McpTool(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_mcp_tool_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::McpToolRequested,
            message: Some(
                "managed MCP tool action executed after gateway authorization".to_string(),
            ),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_skill_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedSkillAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Skill(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_skill_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::SkillRequested,
            message: Some("managed skill action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_memory_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedMemoryAction,
    store: &mut BTreeMap<String, String>,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Memory(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_memory_action(&action, store)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: match action.access {
                ManagedMemoryAccess::Read => FrameworkAdapterEventKind::MemoryRead,
                ManagedMemoryAccess::Write => FrameworkAdapterEventKind::MemoryWrite,
            },
            message: Some("managed memory action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_secret_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedSecretAction,
    secrets: &BTreeMap<String, String>,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Secret(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_secret_action(&action, secrets)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::SecretRequested,
            message: Some("managed secret action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_network_egress_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedNetworkEgressAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::NetworkEgress(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_network_egress_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::NetworkEgressRequested,
            message: Some(
                "managed network egress action executed after gateway authorization".to_string(),
            ),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_browser_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedBrowserAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Browser(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_browser_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::BrowserRequested,
            message: Some(
                "managed browser action executed after gateway authorization".to_string(),
            ),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_cli_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedCliAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Cli(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_cli_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::CliRequested,
            message: Some("managed CLI action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_cli_action_with_failure_evidence<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedCliAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Cli(action.clone()),
            high_risk,
        },
    )?;
    match run_authorized_cli_action(&action) {
        Ok(execution) => Ok(vec![
            decision.event,
            NormalizedFrameworkEvent {
                session_id: session.session_id,
                run_id: session.run_id,
                adapter_name: session.adapter_name,
                adapter_version: session.adapter_version,
                framework: session.framework,
                mode: session.mode,
                kind: FrameworkAdapterEventKind::CliRequested,
                message: Some(
                    "managed CLI action executed after gateway authorization".to_string(),
                ),
                metadata: execution.metadata(&action),
            },
        ]),
        Err(error) => Ok(vec![
            decision.event,
            NormalizedFrameworkEvent {
                session_id: session.session_id,
                run_id: session.run_id,
                adapter_name: session.adapter_name,
                adapter_version: session.adapter_version,
                framework: session.framework,
                mode: session.mode,
                kind: FrameworkAdapterEventKind::RunFailed,
                message: Some(format!(
                    "managed CLI action failed after gateway authorization: {error}"
                )),
                metadata: governed_cli_failure_metadata(&action, &error),
            },
        ]),
    }
}

fn execute_governed_cli_action_with_cancel_evidence<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedCliAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Cli(action.clone()),
            high_risk,
        },
    )?;
    let cancellation = run_authorized_cli_action_until_cancelled(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::RunCancelled,
            message: Some("managed CLI action cancelled after gateway authorization".to_string()),
            metadata: cancellation.metadata(&action),
        },
    ])
}

fn governed_cli_failure_metadata(
    action: &ManagedCliAction,
    error: &FrameworkAdapterError,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("external_action".to_string(), "cli".to_string()),
        ("external_target".to_string(), action.command.clone()),
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
        ("failed_after_authorization".to_string(), "true".to_string()),
        ("failure_reason".to_string(), error.to_string()),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernedCliCancellation {
    cancellation_reason: String,
    elapsed_millis: u128,
}

impl GovernedCliCancellation {
    fn metadata(self, action: &ManagedCliAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "cli".to_string()),
            ("external_target".to_string(), action.command.clone()),
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
            (
                "cancelled_after_authorization".to_string(),
                "true".to_string(),
            ),
            ("cancellation_reason".to_string(), self.cancellation_reason),
            (
                "elapsed_millis".to_string(),
                self.elapsed_millis.to_string(),
            ),
        ])
    }
}

fn run_authorized_cli_action_until_cancelled(
    action: &ManagedCliAction,
) -> Result<GovernedCliCancellation, FrameworkAdapterError> {
    let mut command = Command::new(&action.command);
    command
        .args(&action.args)
        .current_dir(&action.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if action.env_policy == "deny_all" {
        command.env_clear();
    }
    let mut child = spawn_cli_with_executable_busy_retry(&mut command).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action spawn failed after gateway authorization: {error}"
        ))
    })?;
    let started_at = Instant::now();
    thread::sleep(Duration::from_millis(25));
    if child
        .try_wait()
        .map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action status check failed: {error}"
            ))
        })?
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(GovernedCliCancellation {
            cancellation_reason: "operator_cancelled".to_string(),
            elapsed_millis: started_at.elapsed().as_millis(),
        });
    }
    Err(FrameworkAdapterError::CapabilityDenied(
        "managed CLI action completed before cancellation could be observed".to_string(),
    ))
}

fn execute_governed_rest_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedRestAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Rest(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_rest_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::RestRequested,
            message: Some("managed REST action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_filesystem_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedFilesystemAction,
    workspace_root: &Path,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Filesystem(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_filesystem_action(&action, workspace_root)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::FilesystemRequested,
            message: Some(
                "managed filesystem action executed after gateway authorization".to_string(),
            ),
            metadata: execution.metadata(&action),
        },
    ])
}

struct GovernedToolExecution {
    output_excerpt: String,
}

impl GovernedToolExecution {
    fn metadata(self, action: &ManagedToolAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "tool".to_string()),
            (
                "external_target".to_string(),
                format!("tool:{}", action.tool_name),
            ),
            ("tool_name".to_string(), action.tool_name.clone()),
            (
                "arguments_policy".to_string(),
                action.arguments_policy.clone(),
            ),
            ("output_excerpt".to_string(), self.output_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_tool_action(
    action: &ManagedToolAction,
) -> Result<GovernedToolExecution, FrameworkAdapterError> {
    if action.tool_name != "native.echo" {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "managed tool smoke does not support tool {}",
            action.tool_name
        )));
    }
    let message = smoke_literal_argument(&action.arguments_policy)?;
    Ok(GovernedToolExecution {
        output_excerpt: bounded_utf8_excerpt(message.as_bytes(), 512),
    })
}

struct GovernedMcpToolExecution {
    output_excerpt: String,
}

impl GovernedMcpToolExecution {
    fn metadata(self, action: &ManagedMcpToolAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "mcp.tool".to_string()),
            (
                "external_target".to_string(),
                format!("mcp:{}:{}", action.server_name, action.tool_name),
            ),
            ("mcp_server".to_string(), action.server_name.clone()),
            ("mcp_tool".to_string(), action.tool_name.clone()),
            (
                "arguments_policy".to_string(),
                action.arguments_policy.clone(),
            ),
            ("output_excerpt".to_string(), self.output_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_mcp_tool_action(
    action: &ManagedMcpToolAction,
) -> Result<GovernedMcpToolExecution, FrameworkAdapterError> {
    if action.server_name != "local-smoke" || action.tool_name != "echo" {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "managed MCP smoke does not support {}/{}",
            action.server_name, action.tool_name
        )));
    }
    let message = smoke_literal_argument(&action.arguments_policy)?;
    Ok(GovernedMcpToolExecution {
        output_excerpt: bounded_utf8_excerpt(message.as_bytes(), 512),
    })
}

fn smoke_literal_argument(policy: &str) -> Result<&str, FrameworkAdapterError> {
    policy
        .strip_prefix("smoke_literal:")
        .filter(|message| !message.trim().is_empty())
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(
                "managed smoke requires arguments_policy=smoke_literal:<message>".to_string(),
            )
        })
}

struct GovernedSkillExecution {
    output_excerpt: String,
}

impl GovernedSkillExecution {
    fn metadata(self, action: &ManagedSkillAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "skill".to_string()),
            (
                "external_target".to_string(),
                format!("skill:{}", action.skill_id),
            ),
            ("skill_id".to_string(), action.skill_id.clone()),
            (
                "declared_capabilities".to_string(),
                action.declared_capabilities.join(","),
            ),
            ("output_excerpt".to_string(), self.output_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_skill_action(
    action: &ManagedSkillAction,
) -> Result<GovernedSkillExecution, FrameworkAdapterError> {
    if action.skill_id != "builtin.skill.echo" {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "managed skill smoke does not support skill {}",
            action.skill_id
        )));
    }
    Ok(GovernedSkillExecution {
        output_excerpt: bounded_utf8_excerpt(
            action.declared_capabilities.join(",").as_bytes(),
            512,
        ),
    })
}

struct GovernedMemoryExecution {
    value_excerpt: String,
}

impl GovernedMemoryExecution {
    fn metadata(self, action: &ManagedMemoryAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "external_action".to_string(),
                format!("memory.{}", action.access.as_str()),
            ),
            (
                "external_target".to_string(),
                format!(
                    "memory:{}:{}:{}",
                    action.access.as_str(),
                    action.namespace,
                    action.key
                ),
            ),
            (
                "memory_access".to_string(),
                action.access.as_str().to_string(),
            ),
            ("namespace".to_string(), action.namespace.clone()),
            ("key".to_string(), action.key.clone()),
            ("value_excerpt".to_string(), self.value_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_memory_action(
    action: &ManagedMemoryAction,
    store: &mut BTreeMap<String, String>,
) -> Result<GovernedMemoryExecution, FrameworkAdapterError> {
    if action.namespace != "session" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed memory smoke only supports session namespace".to_string(),
        ));
    }
    let store_key = format!("{}:{}", action.namespace, action.key);
    match action.access {
        ManagedMemoryAccess::Write => {
            let value = "ferrogate governed memory smoke".to_string();
            store.insert(store_key, value.clone());
            Ok(GovernedMemoryExecution {
                value_excerpt: bounded_utf8_excerpt(value.as_bytes(), 512),
            })
        }
        ManagedMemoryAccess::Read => {
            let value = store.get(&store_key).ok_or_else(|| {
                FrameworkAdapterError::CapabilityDenied(
                    "managed memory action read failed after gateway authorization".to_string(),
                )
            })?;
            Ok(GovernedMemoryExecution {
                value_excerpt: bounded_utf8_excerpt(value.as_bytes(), 512),
            })
        }
    }
}

struct GovernedSecretExecution {
    secret_len: usize,
}

impl GovernedSecretExecution {
    fn metadata(self, action: &ManagedSecretAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "secret".to_string()),
            (
                "external_target".to_string(),
                format!("secret:{}", action.secret_id),
            ),
            ("secret_id".to_string(), action.secret_id.clone()),
            ("purpose".to_string(), action.purpose.clone()),
            ("redacted_value".to_string(), "***".to_string()),
            ("secret_len".to_string(), self.secret_len.to_string()),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_secret_action(
    action: &ManagedSecretAction,
    secrets: &BTreeMap<String, String>,
) -> Result<GovernedSecretExecution, FrameworkAdapterError> {
    let secret = secrets.get(&action.secret_id).ok_or_else(|| {
        FrameworkAdapterError::CapabilityDenied(
            "managed secret action lookup failed after gateway authorization".to_string(),
        )
    })?;
    Ok(GovernedSecretExecution {
        secret_len: secret.len(),
    })
}

struct GovernedNetworkEgressExecution {
    bytes_written: usize,
}

impl GovernedNetworkEgressExecution {
    fn metadata(self, action: &ManagedNetworkEgressAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "network.egress".to_string()),
            (
                "external_target".to_string(),
                format!("{}:{}", action.host, action.port),
            ),
            ("host".to_string(), action.host.clone()),
            ("port".to_string(), action.port.to_string()),
            ("protocol".to_string(), action.protocol.clone()),
            ("bytes_written".to_string(), self.bytes_written.to_string()),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_network_egress_action(
    action: &ManagedNetworkEgressAction,
) -> Result<GovernedNetworkEgressExecution, FrameworkAdapterError> {
    if action.protocol != "tcp" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed network egress smoke only supports tcp".to_string(),
        ));
    }
    if action.host != "127.0.0.1" && action.host != "localhost" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed network egress smoke only supports loopback hosts".to_string(),
        ));
    }
    let endpoint = SocketAddr::new(
        "127.0.0.1".parse().map_err(|error| {
            FrameworkAdapterError::InvalidRequest(format!(
                "managed network egress smoke loopback parse failed: {error}"
            ))
        })?,
        action.port,
    );
    let payload = b"ferrogate governed network smoke\n";
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed network egress connection failed after gateway authorization: {error}"
        ))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed network egress write timeout setup failed: {error}"
        ))
    })?;
    stream.write_all(payload).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed network egress write failed: {error}"
        ))
    })?;
    stream.shutdown(Shutdown::Write).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed network egress shutdown failed: {error}"
        ))
    })?;
    Ok(GovernedNetworkEgressExecution {
        bytes_written: payload.len(),
    })
}

struct GovernedBrowserExecution {
    page_state: String,
}

impl GovernedBrowserExecution {
    fn metadata(self, action: &ManagedBrowserAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "browser".to_string()),
            (
                "external_target".to_string(),
                format!("browser:{}:{}", action.operation.as_str(), action.url),
            ),
            (
                "browser_operation".to_string(),
                action.operation.as_str().to_string(),
            ),
            ("url".to_string(), action.url.clone()),
            (
                "timeout_millis".to_string(),
                action.timeout_millis.to_string(),
            ),
            ("page_state".to_string(), self.page_state),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_browser_action(
    action: &ManagedBrowserAction,
) -> Result<GovernedBrowserExecution, FrameworkAdapterError> {
    if action.operation != ManagedBrowserOperation::Navigate {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed browser smoke currently supports navigate only".to_string(),
        ));
    }
    if action.url != "about:blank" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed browser smoke only supports about:blank".to_string(),
        ));
    }
    Ok(GovernedBrowserExecution {
        page_state: "navigated".to_string(),
    })
}

struct GovernedFilesystemExecution {
    resolved_path: PathBuf,
    byte_len: usize,
    content_excerpt: String,
}

impl GovernedFilesystemExecution {
    fn metadata(self, action: &ManagedFilesystemAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "filesystem".to_string()),
            (
                "external_target".to_string(),
                format!("{}:{}", action.access.as_str(), action.path),
            ),
            ("path".to_string(), action.path.clone()),
            (
                "filesystem_access".to_string(),
                action.access.as_str().to_string(),
            ),
            (
                "workspace_relative".to_string(),
                action.workspace_relative.to_string(),
            ),
            (
                "resolved_path".to_string(),
                self.resolved_path.display().to_string(),
            ),
            ("byte_len".to_string(), self.byte_len.to_string()),
            ("content_excerpt".to_string(), self.content_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_filesystem_action(
    action: &ManagedFilesystemAction,
    workspace_root: &Path,
) -> Result<GovernedFilesystemExecution, FrameworkAdapterError> {
    if action.access != ManagedFilesystemAccess::Read {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke currently supports read access only".to_string(),
        ));
    }
    if !action.workspace_relative {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke requires workspace_relative=true".to_string(),
        ));
    }
    let relative = Path::new(&action.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke path must stay inside the workspace".to_string(),
        ));
    }
    let resolved_path = workspace_root.join(relative);
    let bytes = std::fs::read(&resolved_path).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem action read failed after gateway authorization: {error}"
        ))
    })?;
    Ok(GovernedFilesystemExecution {
        resolved_path,
        byte_len: bytes.len(),
        content_excerpt: bounded_utf8_excerpt(&bytes, 512),
    })
}

struct GovernedCliExecution {
    status_code: Option<i32>,
    stdout_excerpt: String,
    stderr_excerpt: String,
}

impl GovernedCliExecution {
    fn metadata(self, action: &ManagedCliAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "cli".to_string()),
            ("external_target".to_string(), action.command.clone()),
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
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
            (
                "status_code".to_string(),
                self.status_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
            ),
            ("stdout_excerpt".to_string(), self.stdout_excerpt),
            ("stderr_excerpt".to_string(), self.stderr_excerpt),
        ])
    }
}

fn run_authorized_cli_action(
    action: &ManagedCliAction,
) -> Result<GovernedCliExecution, FrameworkAdapterError> {
    let mut command = Command::new(&action.command);
    command
        .args(&action.args)
        .current_dir(&action.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if action.env_policy == "deny_all" {
        command.env_clear();
    }
    let mut child = spawn_cli_with_executable_busy_retry(&mut command).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action spawn failed after gateway authorization: {error}"
        ))
    })?;
    let started_at = Instant::now();
    let timeout = Duration::from_millis(action.timeout_millis.max(1));
    loop {
        if child
            .try_wait()
            .map_err(|error| {
                FrameworkAdapterError::CapabilityDenied(format!(
                    "managed CLI action status check failed: {error}"
                ))
            })?
            .is_some()
        {
            break;
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action timed out after {}ms",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action output collection failed: {error}"
        ))
    })?;
    if !output.status.success() {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action exited with status {:?}",
            output.status.code()
        )));
    }
    Ok(GovernedCliExecution {
        status_code: output.status.code(),
        stdout_excerpt: bounded_utf8_excerpt(&output.stdout, action.stdout_limit_bytes),
        stderr_excerpt: bounded_utf8_excerpt(&output.stderr, action.stderr_limit_bytes),
    })
}

fn spawn_cli_with_executable_busy_retry(command: &mut Command) -> io::Result<std::process::Child> {
    let mut last_error = None;
    for attempt in 0..5 {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(5 * (attempt + 1)));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("ExecutableFileBusy retry loop records the last error"))
}

fn bounded_utf8_excerpt(bytes: &[u8], limit: u64) -> String {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).to_string()
}

struct GovernedRestExecution {
    status_code: u16,
    response_excerpt: String,
}

impl GovernedRestExecution {
    fn metadata(self, action: &ManagedRestAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "rest".to_string()),
            (
                "external_target".to_string(),
                format!("{} {}", action.method, action.url),
            ),
            ("method".to_string(), action.method.clone()),
            ("url".to_string(), action.url.clone()),
            ("headers_policy".to_string(), action.headers_policy.clone()),
            ("body_policy".to_string(), action.body_policy.clone()),
            (
                "timeout_millis".to_string(),
                action.timeout_millis.to_string(),
            ),
            ("retry_limit".to_string(), action.retry_limit.to_string()),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
            ("status_code".to_string(), self.status_code.to_string()),
            ("response_excerpt".to_string(), self.response_excerpt),
        ])
    }
}

fn run_authorized_rest_action(
    action: &ManagedRestAction,
) -> Result<GovernedRestExecution, FrameworkAdapterError> {
    if action.method != "GET" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke currently supports GET only".to_string(),
        ));
    }
    let target = parse_local_http_url(&action.url)?;
    let timeout = Duration::from_millis(action.timeout_millis.max(1));
    let mut stream = TcpStream::connect_timeout(&target.endpoint, timeout).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action transport failed after gateway authorization: {error}"
        ))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action read timeout setup failed: {error}"
        ))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action write timeout setup failed: {error}"
        ))
    })?;
    let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
        target.path, target.endpoint
    );
    stream.write_all(request.as_bytes()).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action request write failed: {error}"
        ))
    })?;
    stream.shutdown(Shutdown::Write).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action request shutdown failed: {error}"
        ))
    })?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action response read failed: {error}"
        ))
    })?;
    let response = String::from_utf8_lossy(&response);
    let status_code = parse_smoke_http_status(response.lines().next().unwrap_or_default())?;
    if !(200..300).contains(&status_code) {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action returned status {status_code}"
        )));
    }
    Ok(GovernedRestExecution {
        status_code,
        response_excerpt: response.chars().take(512).collect(),
    })
}

struct LocalHttpTarget {
    endpoint: SocketAddr,
    path: String,
}

fn parse_local_http_url(raw: &str) -> Result<LocalHttpTarget, FrameworkAdapterError> {
    let Some(rest) = raw.strip_prefix("http://") else {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke only supports http:// local URLs".to_string(),
        ));
    };
    let (authority, path) = rest
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((rest, "/".to_string()));
    let endpoint = authority.parse::<SocketAddr>().map_err(|error| {
        FrameworkAdapterError::InvalidRequest(format!(
            "managed REST smoke URL endpoint is invalid: {error}"
        ))
    })?;
    if !endpoint.ip().is_loopback() {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke only supports loopback endpoints".to_string(),
        ));
    }
    Ok(LocalHttpTarget { endpoint, path })
}

fn parse_smoke_http_status(status_line: &str) -> Result<u16, FrameworkAdapterError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "managed REST action response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            FrameworkAdapterError::InvalidRequest(format!(
                "managed REST action response has invalid status code: {status_line}"
            ))
        })
}

struct RestSmokeServer {
    endpoint: SocketAddr,
    handle: thread::JoinHandle<Result<String>>,
}

impl RestSmokeServer {
    fn join(self) -> Result<String> {
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("REST smoke server thread panicked"))?
    }
}

fn spawn_one_shot_rest_smoke_server() -> RestSmokeServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = "ferrogate governed rest smoke\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )?;
        Ok(request.lines().next().unwrap_or_default().to_string())
    });
    RestSmokeServer { endpoint, handle }
}

struct NetworkEgressSmokeServer {
    endpoint: SocketAddr,
    handle: thread::JoinHandle<Result<String>>,
}

impl NetworkEgressSmokeServer {
    fn join(self) -> Result<String> {
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("network egress smoke server thread panicked"))?
    }
}

fn spawn_one_shot_network_egress_smoke_server() -> NetworkEgressSmokeServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload)?;
        Ok(String::from_utf8_lossy(&payload).to_string())
    });
    NetworkEgressSmokeServer { endpoint, handle }
}

fn smoke_session(mode: FrameworkAdapterMode) -> FrameworkAdapterSession {
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
        mode,
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
    use ferrogate_runtime::{
        ExternalActionBrowserOperation, ExternalActionDecision, ExternalActionFilesystemAccess,
        ExternalActionFramework, ExternalActionMemoryAccess, ExternalActionMode,
        ExternalActionSession, ExternalActionSpec, ManagedCliAction, ManagedMcpToolAction,
        ManagedRestAction,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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
    fn governed_tool_execution_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_tool_action(
            &gate,
            session(),
            ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "smoke_literal:tool smoke ok".to_string(),
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "tool.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("tool_name").map(String::as_str),
            Some("native.echo")
        );
        assert_eq!(
            events[1].metadata.get("output_excerpt").map(String::as_str),
            Some("tool smoke ok")
        );
    }

    #[test]
    fn governed_tool_execution_denial_happens_before_tool_dispatch() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_tool_action(
            &gate,
            session(),
            ManagedToolAction {
                tool_name: "unsupported.tool".to_string(),
                arguments_policy: "smoke_literal:must not run".to_string(),
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("does not support tool"));
    }

    #[test]
    fn governed_mcp_tool_execution_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::McpTool]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_mcp_tool_action(
            &gate,
            session(),
            ManagedMcpToolAction {
                server_name: "local-smoke".to_string(),
                tool_name: "echo".to_string(),
                arguments_policy: "smoke_literal:mcp smoke ok".to_string(),
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "mcp.tool.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("mcp_server").map(String::as_str),
            Some("local-smoke")
        );
        assert_eq!(
            events[1].metadata.get("mcp_tool").map(String::as_str),
            Some("echo")
        );
        assert_eq!(
            events[1].metadata.get("output_excerpt").map(String::as_str),
            Some("mcp smoke ok")
        );
    }

    #[test]
    fn governed_mcp_tool_execution_denial_happens_before_mcp_dispatch() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_mcp_tool_action(
            &gate,
            session(),
            ManagedMcpToolAction {
                server_name: "remote".to_string(),
                tool_name: "read_file".to_string(),
                arguments_policy: "smoke_literal:must not run".to_string(),
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("does not support"));
    }

    #[test]
    fn governed_skill_execution_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Skill]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_skill_action(
            &gate,
            session(),
            ManagedSkillAction {
                skill_id: "builtin.skill.echo".to_string(),
                declared_capabilities: vec!["tools".to_string(), "memory.read".to_string()],
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "skill.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("skill_id").map(String::as_str),
            Some("builtin.skill.echo")
        );
        assert_eq!(
            events[1]
                .metadata
                .get("declared_capabilities")
                .map(String::as_str),
            Some("tools,memory.read")
        );
        assert_eq!(
            events[1].metadata.get("output_excerpt").map(String::as_str),
            Some("tools,memory.read")
        );
    }

    #[test]
    fn governed_skill_execution_denial_happens_before_skill_invoke() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_skill_action(
            &gate,
            session(),
            ManagedSkillAction {
                skill_id: "external.skill.must-not-run".to_string(),
                declared_capabilities: vec!["filesystem".to_string()],
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("does not support skill"));
    }

    #[test]
    fn governed_memory_write_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::MemoryWrite]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut store = BTreeMap::new();

        let events = execute_governed_memory_action(
            &gate,
            session(),
            ManagedMemoryAction {
                access: ManagedMemoryAccess::Write,
                namespace: "session".to_string(),
                key: "summary".to_string(),
            },
            &mut store,
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "memory.write");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("memory_access").map(String::as_str),
            Some("write")
        );
        assert_eq!(
            store.get("session:summary").map(String::as_str),
            Some("ferrogate governed memory smoke")
        );
    }

    #[test]
    fn governed_memory_read_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::MemoryRead]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut store = BTreeMap::from([(
            "session:summary".to_string(),
            "ferrogate governed memory smoke".to_string(),
        )]);

        let events = execute_governed_memory_action(
            &gate,
            session(),
            ManagedMemoryAction {
                access: ManagedMemoryAccess::Read,
                namespace: "session".to_string(),
                key: "summary".to_string(),
            },
            &mut store,
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "memory.read");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("memory_access").map(String::as_str),
            Some("read")
        );
        assert_eq!(
            events[1].metadata.get("value_excerpt").map(String::as_str),
            Some("ferrogate governed memory smoke")
        );
    }

    #[test]
    fn governed_memory_write_denial_happens_before_store_mutation() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());
        let mut store = BTreeMap::new();

        let error = execute_governed_memory_action(
            &gate,
            session(),
            ManagedMemoryAction {
                access: ManagedMemoryAccess::Write,
                namespace: "session".to_string(),
                key: "summary".to_string(),
            },
            &mut store,
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!store.contains_key("session:summary"));
    }

    #[test]
    fn governed_memory_read_denial_happens_before_store_lookup() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());
        let mut store = BTreeMap::new();

        let error = execute_governed_memory_action(
            &gate,
            session(),
            ManagedMemoryAction {
                access: ManagedMemoryAccess::Read,
                namespace: "session".to_string(),
                key: "missing".to_string(),
            },
            &mut store,
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("read failed"));
    }

    #[test]
    fn governed_secret_execution_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Secret]),
                ..CapabilityPolicy::default()
            },
        ));
        let secrets = BTreeMap::from([(
            "openai-api-key".to_string(),
            "ferrogate governed secret smoke".to_string(),
        )]);

        let events = execute_governed_secret_action(
            &gate,
            session(),
            ManagedSecretAction {
                secret_id: "openai-api-key".to_string(),
                purpose: "provider_call".to_string(),
            },
            &secrets,
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "secret.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("secret_id").map(String::as_str),
            Some("openai-api-key")
        );
        assert_eq!(
            events[1].metadata.get("redacted_value").map(String::as_str),
            Some("***")
        );
        assert_eq!(
            events[1].metadata.get("secret_len").map(String::as_str),
            Some("31")
        );
    }

    #[test]
    fn governed_secret_execution_denial_happens_before_secret_lookup() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());
        let secrets = BTreeMap::new();

        let error = execute_governed_secret_action(
            &gate,
            session(),
            ManagedSecretAction {
                secret_id: "missing-secret".to_string(),
                purpose: "provider_call".to_string(),
            },
            &secrets,
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("lookup failed"));
    }

    #[test]
    fn governed_network_egress_runs_only_after_gateway_authorization() {
        let server = spawn_one_shot_network_egress_smoke_server();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: true,
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_network_egress_action(
            &gate,
            session(),
            ManagedNetworkEgressAction {
                host: "127.0.0.1".to_string(),
                port: server.endpoint.port(),
                protocol: "tcp".to_string(),
            },
            false,
        )
        .unwrap();
        let received_payload = server.join().unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "network.egress.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("protocol").map(String::as_str),
            Some("tcp")
        );
        assert_eq!(
            events[1].metadata.get("bytes_written").map(String::as_str),
            Some("33")
        );
        assert_eq!(received_payload, "ferrogate governed network smoke\n");
    }

    #[test]
    fn governed_network_egress_denial_happens_before_tcp_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let endpoint = listener.local_addr().unwrap();
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_network_egress_action(
            &gate,
            session(),
            ManagedNetworkEgressAction {
                host: "127.0.0.1".to_string(),
                port: endpoint.port(),
                protocol: "tcp".to_string(),
            },
            false,
        )
        .unwrap_err();
        let accepted = listener.accept();

        assert!(error.to_string().contains("direct network egress"));
        assert!(matches!(
            accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn governed_network_egress_respects_direct_egress_policy() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: false,
                ..CapabilityPolicy::default()
            },
        ));
        let mut session = session();
        session.worker_id = "network-policy-worker".to_string();

        let error = execute_governed_network_egress_action(
            &gate,
            session,
            ManagedNetworkEgressAction {
                host: "127.0.0.1".to_string(),
                port: 9,
                protocol: "tcp".to_string(),
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("direct network egress"));
    }

    #[test]
    fn governed_browser_execution_runs_only_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Browser]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_browser_action(
            &gate,
            session(),
            ManagedBrowserAction {
                operation: ManagedBrowserOperation::Navigate,
                url: "about:blank".to_string(),
                timeout_millis: 2_000,
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "browser.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1]
                .metadata
                .get("browser_operation")
                .map(String::as_str),
            Some("navigate")
        );
        assert_eq!(
            events[1].metadata.get("page_state").map(String::as_str),
            Some("navigated")
        );
    }

    #[test]
    fn governed_browser_execution_denial_happens_before_browser_action() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_browser_action(
            &gate,
            session(),
            ManagedBrowserAction {
                operation: ManagedBrowserOperation::Navigate,
                url: "https://example.invalid".to_string(),
                timeout_millis: 2_000,
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("only supports about:blank"));
    }

    #[test]
    fn governed_cli_execution_runs_only_after_gateway_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("governed-cli-smoke");
        let marker_path = temp.path().join("executed-marker");
        write_executable_script(
            &binary_path,
            &format!(
                "#!/bin/sh\nprintf 'executed %s\\n' \"$1\"\nprintf done > {}\n",
                marker_path.display()
            ),
        );
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_cli_action(
            &gate,
            session(),
            ManagedCliAction {
                command: binary_path.display().to_string(),
                args: vec!["ok".to_string()],
                working_dir: temp.path().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 1_000,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "cli.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert!(events[1]
            .metadata
            .get("stdout_excerpt")
            .is_some_and(|stdout| stdout.contains("executed ok")));
        assert!(marker_path.exists());
    }

    #[test]
    fn governed_cli_execution_denial_happens_before_process_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("must-not-run");
        let marker_path = temp.path().join("executed-marker");
        write_executable_script(
            &binary_path,
            &format!("#!/bin/sh\nprintf done > {}\n", marker_path.display()),
        );
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_cli_action(
            &gate,
            session(),
            ManagedCliAction {
                command: binary_path.display().to_string(),
                args: vec!["blocked".to_string()],
                working_dir: temp.path().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 1_000,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!marker_path.exists());
    }

    #[test]
    fn governed_cli_timeout_is_recorded_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_cli_action_with_failure_evidence(
            &gate,
            session(),
            ManagedCliAction {
                command: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "sleep 1".to_string()],
                working_dir: std::env::current_dir().unwrap().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 25,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "run.failed");
        assert!(events[1]
            .metadata
            .get("failed_after_authorization")
            .is_some_and(|value| value == "true"));
        assert!(events[1]
            .metadata
            .get("failure_reason")
            .is_some_and(|reason| reason.contains("timed out after")));
        assert_eq!(
            events[1].metadata.get("timeout_millis").map(String::as_str),
            Some("25")
        );
    }

    #[test]
    fn governed_cli_cancellation_is_recorded_after_gateway_authorization() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_cli_action_with_cancel_evidence(
            &gate,
            session(),
            ManagedCliAction {
                command: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "sleep 5".to_string()],
                working_dir: std::env::current_dir().unwrap().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 5_000,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "run.cancelled");
        assert!(events[1]
            .metadata
            .get("cancelled_after_authorization")
            .is_some_and(|value| value == "true"));
        assert_eq!(
            events[1]
                .metadata
                .get("cancellation_reason")
                .map(String::as_str),
            Some("operator_cancelled")
        );
        assert_eq!(
            events[1].metadata.get("timeout_millis").map(String::as_str),
            Some("5000")
        );
    }

    #[test]
    fn governed_rest_execution_runs_only_after_gateway_authorization() {
        let server = spawn_one_shot_rest_smoke_server();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_rest_action(
            &gate,
            session(),
            ManagedRestAction {
                method: "GET".to_string(),
                url: format!("http://{}/authorized", server.endpoint),
                headers_policy: "deny_credentials".to_string(),
                body_policy: "empty_body".to_string(),
                timeout_millis: 1_000,
                retry_limit: 0,
            },
            false,
        )
        .unwrap();
        let served_request = server.join().unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "rest.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("status_code").map(String::as_str),
            Some("200")
        );
        assert!(events[1]
            .metadata
            .get("response_excerpt")
            .is_some_and(|body| body.contains("ferrogate governed rest smoke")));
        assert_eq!(served_request, "GET /authorized HTTP/1.1");
    }

    #[test]
    fn governed_rest_execution_denial_happens_before_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let endpoint = listener.local_addr().unwrap();
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_rest_action(
            &gate,
            session(),
            ManagedRestAction {
                method: "GET".to_string(),
                url: format!("http://{endpoint}/blocked"),
                headers_policy: "deny_credentials".to_string(),
                body_policy: "empty_body".to_string(),
                timeout_millis: 1_000,
                retry_limit: 0,
            },
            false,
        )
        .unwrap_err();
        let accepted = listener.accept();

        assert!(error.to_string().contains("not allowed"));
        assert!(matches!(
            accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn governed_filesystem_execution_reads_only_after_gateway_authorization() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("allowed.txt"),
            "ferrogate governed filesystem smoke\n",
        )
        .unwrap();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "allowed.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "filesystem.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1]
                .metadata
                .get("filesystem_access")
                .map(String::as_str),
            Some("read")
        );
        assert_eq!(
            events[1].metadata.get("byte_len").map(String::as_str),
            Some("36")
        );
        assert!(events[1]
            .metadata
            .get("content_excerpt")
            .is_some_and(|content| content.contains("governed filesystem smoke")));
    }

    #[test]
    fn governed_filesystem_execution_denial_happens_before_read() {
        let temp = tempfile::tempdir().unwrap();
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "missing-after-denial.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("read failed"));
    }

    #[test]
    fn governed_filesystem_execution_rejects_workspace_escape_after_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));

        let error = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "../secret.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("must stay inside the workspace"));
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
        let decision = external_action_smoke(FrameworkAdapterMode::Managed).unwrap();
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
            response.decision,
            Some(ExternalActionDecision::ApprovalRequired)
        );
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.requested");
        assert_eq!(event["metadata"]["decision"], "approval_required");
        assert_eq!(event["metadata"]["external_action"], "cli");
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            None
        );
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
        assert_eq!(response.decision, Some(ExternalActionDecision::Denied));
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.denied");
        assert_eq!(event["metadata"]["decision"], "denied");
        assert_eq!(event["metadata"]["external_action"], "network.egress");
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            None
        );
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
            served[0].response.decision,
            Some(ExternalActionDecision::Denied)
        );
        assert_eq!(
            served[0].response.event.as_ref().unwrap()["kind"],
            "capability.denied"
        );
        assert_eq!(
            served[0]
                .response
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            None
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

    #[test]
    fn http_gateway_authorizer_transport_allows_managed_handler_action() {
        let expected_response = GatewayExternalActionTransportResponse {
            request_id: "run-1:session-1:worker-1:native-harness:tool".to_string(),
            response: ExternalActionAuthorizationResponse {
                accepted: true,
                decision: Some(ExternalActionDecision::Allowed),
                event: Some(allowed_tool_event_json()),
                error: None,
            },
        };
        let server = spawn_http_authorizer_contract_server(
            |request| {
                assert!(request
                    .starts_with("POST /v1/agent-worker/external-actions/authorize HTTP/1.1\r\n"));
                assert!(request.contains("\r\ncontent-type: application/json\r\n"));
                let body = http_request_body(&request);
                let request: GatewayExternalActionTransportRequest =
                    serde_json::from_str(body).unwrap();
                assert_eq!(
                    request.request_id,
                    "run-1:session-1:worker-1:native-harness:tool"
                );
            },
            expected_response,
            200,
        );
        let client = HttpGatewayExternalActionAuthorizer::new(server.endpoint);

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
        server.join();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
    }

    #[test]
    fn http_gateway_authorizer_transport_rejects_response_identity_mismatch() {
        let response = GatewayExternalActionTransportResponse {
            request_id: "tampered-request-id".to_string(),
            response: ExternalActionAuthorizationResponse {
                accepted: true,
                decision: Some(ExternalActionDecision::Allowed),
                event: Some(allowed_tool_event_json()),
                error: None,
            },
        };
        let server = spawn_http_authorizer_contract_server(|_| {}, response, 200);
        let client = HttpGatewayExternalActionAuthorizer::new(server.endpoint);

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
        server.join();

        assert!(error.to_string().contains("request_id mismatch"));
    }

    #[test]
    fn http_gateway_authorizer_transport_times_out_fail_closed() {
        let server = spawn_stalled_http_authorizer_server();
        let client = HttpGatewayExternalActionAuthorizer::new_with_timeout(
            server.endpoint,
            Duration::from_millis(50),
        );

        let decision = request_handler_external_action_decision(
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
        server.join();

        assert_eq!(decision.decision, CapabilityAuthorizationDecision::Denied);
        assert_eq!(decision.event.kind.as_str(), "capability.denied");
        assert_eq!(
            decision.event.metadata.get("decision").map(String::as_str),
            Some("denied")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("failure_source")
                .map(String::as_str),
            Some("gateway_authorizer_transport")
        );
        assert!(decision
            .event
            .message
            .as_deref()
            .is_some_and(|message| message.contains("response read failed")));
    }

    #[test]
    fn http_gateway_authorizer_transport_timeout_blocks_handler_execution() {
        let server = spawn_stalled_http_authorizer_server();
        let client = HttpGatewayExternalActionAuthorizer::new_with_timeout(
            server.endpoint,
            Duration::from_millis(50),
        );

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
        server.join();

        assert!(error.to_string().contains("response read failed"));
    }

    #[test]
    fn managed_allowed_action_emits_enforced_audit_billing_evidence() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));

        let result = request_handler_external_action_evidence(
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

        assert!(result.decision.allowed());
        let evidence = &result.evidence;
        // Full identity tuple links the action to tenant/workspace/session/run/
        // worker/adapter/isolation-backend.
        assert_eq!(evidence.tenant_id, "tenant-1");
        assert_eq!(evidence.workspace_id, "workspace-1");
        assert_eq!(evidence.session_id, "session-1");
        assert_eq!(evidence.run_id, "run-1");
        assert_eq!(evidence.worker_id, "worker-1");
        assert_eq!(evidence.adapter_name, "native-harness");
        assert_eq!(evidence.adapter_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(evidence.isolation_backend, "firecracker");
        assert_eq!(evidence.action, CapabilityAction::Tool);
        assert_eq!(evidence.target, "tool:native.echo");
        assert_eq!(
            evidence.decision,
            Some(CapabilityAuthorizationDecision::Allowed)
        );
        assert_eq!(evidence.decision_label(), "allowed");
        assert_eq!(evidence.trust, ExternalActionEvidenceTrust::Enforced);
        assert_eq!(
            evidence.billing.action_class,
            ExternalActionBillingClass::Tool
        );
        assert_eq!(evidence.billing.usage.invocations, 1);
        let tag = evidence.audit_tag();
        assert!(tag.contains("worker=worker-1"));
        assert!(tag.contains("decision=allowed"));
        assert!(tag.contains("trust=enforced"));
    }

    #[test]
    fn managed_denied_action_still_emits_visible_evidence() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());
        let request = || ExternalActionGateRequest {
            session: session(),
            action: ManagedExternalAction::McpTool(ManagedMcpToolAction {
                server_name: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                arguments_policy: "workspace_only".to_string(),
            }),
            high_risk: false,
        };

        // The denied decision is returned with evidence, not swallowed.
        let result = request_handler_external_action_evidence(Some(&gate), request()).unwrap();
        assert!(!result.decision.allowed());
        assert_eq!(
            result.decision.decision,
            CapabilityAuthorizationDecision::Denied
        );
        let evidence = &result.evidence;
        assert_eq!(
            evidence.decision,
            Some(CapabilityAuthorizationDecision::Denied)
        );
        assert_eq!(evidence.decision_label(), "denied");
        assert_eq!(evidence.trust, ExternalActionEvidenceTrust::Enforced);
        assert_eq!(evidence.action, CapabilityAction::McpTool);
        assert_eq!(evidence.tenant_id, "tenant-1");
        assert_eq!(evidence.worker_id, "worker-1");
        assert_eq!(evidence.isolation_backend, "firecracker");

        // The deny error carries the audit tag so the denial stays visible in
        // run timelines rather than becoming an opaque worker-local failure.
        let error = authorize_handler_external_action(Some(&gate), request()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("not allowed"));
        assert!(message.contains("audit["));
        assert!(message.contains("decision=denied"));
        assert!(message.contains("trust=enforced"));
        assert!(message.contains("worker=worker-1"));
    }

    #[test]
    fn managed_approval_required_action_emits_approval_evidence() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let result = request_handler_external_action_evidence(
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
        .unwrap();

        assert!(!result.decision.allowed());
        assert_eq!(
            result.decision.decision,
            CapabilityAuthorizationDecision::ApprovalRequired
        );
        let evidence = &result.evidence;
        assert_eq!(
            evidence.decision,
            Some(CapabilityAuthorizationDecision::ApprovalRequired)
        );
        assert_eq!(evidence.decision_label(), "approval_required");
        assert_eq!(evidence.trust, ExternalActionEvidenceTrust::Enforced);
        assert_eq!(evidence.action, CapabilityAction::Cli);
        assert_eq!(
            evidence.billing.action_class,
            ExternalActionBillingClass::Runtime
        );
    }

    #[test]
    fn self_hosted_action_evidence_is_reported_not_enforced() {
        let mut self_hosted = session();
        self_hosted.mode = FrameworkAdapterMode::SelfHosted;

        let evidence = ExternalActionEvidenceRecord::for_action(
            &self_hosted,
            &ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            None,
        );

        assert_eq!(evidence.trust, ExternalActionEvidenceTrust::Reported);
        assert_ne!(evidence.trust, ExternalActionEvidenceTrust::Enforced);
        assert_eq!(evidence.trust.as_str(), "reported");
        assert_eq!(evidence.decision, None);
        assert_eq!(evidence.decision_label(), "reported");
        assert_eq!(evidence.tenant_id, "tenant-1");
        assert_eq!(evidence.worker_id, "worker-1");
        assert!(evidence.audit_tag().contains("trust=reported"));
    }

    #[test]
    fn billing_attribution_is_populated_for_action_classes() {
        let rest = ExternalActionEvidenceRecord::for_action(
            &session(),
            &ManagedExternalAction::Rest(ManagedRestAction {
                method: "POST".to_string(),
                url: "https://api.example.test/v1/jobs".to_string(),
                headers_policy: "strip_credentials".to_string(),
                body_policy: "redact_and_scan".to_string(),
                timeout_millis: 2_000,
                retry_limit: 0,
            }),
            Some(CapabilityAuthorizationDecision::Allowed),
        );
        assert_eq!(
            rest.billing.action_class,
            ExternalActionBillingClass::ThirdPartyApi
        );
        assert_eq!(rest.billing.action_class.as_str(), "third_party_api");
        // Usage units are populated placeholders: one invocation is attributed at
        // authorization time; token/runtime/egress settle after execution.
        assert_eq!(rest.billing.usage.invocations, 1);
        assert_eq!(rest.billing.usage.token_units, 0);
        assert_eq!(rest.billing.usage.runtime_millis, 0);
        assert_eq!(rest.billing.usage.egress_bytes, 0);

        let network = ExternalActionEvidenceRecord::for_action(
            &session(),
            &ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                host: "api.example.test".to_string(),
                port: 443,
                protocol: "https".to_string(),
            }),
            Some(CapabilityAuthorizationDecision::Allowed),
        );
        assert_eq!(
            network.billing.action_class,
            ExternalActionBillingClass::Network
        );

        let tool = ExternalActionEvidenceRecord::for_action(
            &session(),
            &ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            Some(CapabilityAuthorizationDecision::Allowed),
        );
        assert_eq!(tool.billing.action_class, ExternalActionBillingClass::Tool);

        let cli = ExternalActionEvidenceRecord::for_action(
            &session(),
            &ManagedExternalAction::Cli(ManagedCliAction {
                command: "cargo".to_string(),
                args: vec!["test".to_string()],
                working_dir: "/workspace".to_string(),
                env_policy: "allowlist".to_string(),
                timeout_millis: 30_000,
                stdout_limit_bytes: 65_536,
                stderr_limit_bytes: 65_536,
                artifact_capture: true,
            }),
            Some(CapabilityAuthorizationDecision::Allowed),
        );
        assert_eq!(
            cli.billing.action_class,
            ExternalActionBillingClass::Runtime
        );
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

    struct HttpAuthorizerContractServer {
        endpoint: SocketAddr,
        handle: thread::JoinHandle<()>,
    }

    impl HttpAuthorizerContractServer {
        fn join(self) {
            self.handle.join().unwrap();
        }
    }

    fn spawn_http_authorizer_contract_server<F>(
        inspect_request: F,
        response: GatewayExternalActionTransportResponse,
        status_code: u16,
    ) -> HttpAuthorizerContractServer
    where
        F: FnOnce(String) + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            inspect_request(request);
            let body = serde_json::to_string(&response).unwrap();
            let reason = match status_code {
                200 => "OK",
                400 => "Bad Request",
                _ => "Error",
            };
            let response = format!(
                "HTTP/1.1 {status_code} {reason}\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        HttpAuthorizerContractServer { endpoint, handle }
    }

    fn spawn_stalled_http_authorizer_server() -> HttpAuthorizerContractServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        HttpAuthorizerContractServer { endpoint, handle }
    }

    fn write_executable_script(path: &Path, contents: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn http_request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default()
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

#[cfg(test)]
#[path = "external_actions_worker_type_test.rs"]
mod external_actions_worker_type_test;
