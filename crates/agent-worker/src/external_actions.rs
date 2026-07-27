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
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    authorize_managed_external_action, canonical_target_for_managed_action,
    managed_external_action_transport_failure_event, opaque_reference_fingerprint,
    CanonicalCapabilityTarget, CapabilityAction, CapabilityAuthorizationDecision,
    CapabilityAuthorizer, CapabilityPolicy, ExternalActionAuthorizationRequest,
    ExternalActionAuthorizationResponse, FrameworkAdapterError, FrameworkAdapterEventKind,
    FrameworkAdapterMode, FrameworkAdapterSession, GatewayExternalActionTransportRequest,
    GatewayExternalActionTransportResponse, ManagedBrowserAction, ManagedBrowserOperation,
    ManagedCliAction, ManagedExternalAction, ManagedExternalActionDecision,
    ManagedExternalActionRequest, ManagedFilesystemAccess, ManagedFilesystemAction,
    ManagedMcpToolAction, ManagedMemoryAccess, ManagedMemoryAction, ManagedNetworkEgressAction,
    ManagedRestAction, ManagedSecretAction, ManagedSkillAction, ManagedToolAction,
    NormalizedFrameworkEvent, SimpleCapabilityAuthorizer, SupportedFramework,
};

use ferrogate_payments::HEADER_PAYMENT_REQUIRED;

use crate::recorded_evidence::{
    recorded_excerpt, recorded_http_excerpt, recorded_metadata, redact_recorded_values,
};
use crate::self_hosted_execution::{
    run_governed_workload, GovernedWorkloadExecution, GovernedWorkloadOutcome,
};
use crate::x402_client::{
    detect_payment_required, AuthorizedRequest, HoldDisposition, RequestWireStage,
};

const EXTERNAL_ACTION_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const EXTERNAL_ACTION_UNIX_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
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
    let high_risk = request.high_risk;
    let decision = request_handler_external_action_decision(authorizer, request)?;
    if decision.allowed() {
        verify_authorized_action_fingerprint(&decision, &session, &action, high_risk)?;
    }
    let evidence =
        ExternalActionEvidenceRecord::for_action(&session, &action, Some(decision.decision));
    Ok(HandlerExternalActionEvidence { decision, evidence })
}

fn verify_authorized_action_fingerprint(
    decision: &ExternalActionGateDecision,
    session: &FrameworkAdapterSession,
    action: &ManagedExternalAction,
    high_risk: bool,
) -> Result<(), FrameworkAdapterError> {
    let expected_target =
        canonical_target_for_managed_action(action, &session.adapter_name, high_risk);
    let Some(expected_target) = expected_target else {
        return if matches!(
            action,
            ManagedExternalAction::McpTool(_)
                | ManagedExternalAction::Cli(_)
                | ManagedExternalAction::Filesystem(_)
                | ManagedExternalAction::Rest(_)
                | ManagedExternalAction::Secret(_)
                | ManagedExternalAction::NetworkEgress(_)
        ) {
            Err(FrameworkAdapterError::CapabilityDenied(
                "worker cannot derive a canonical execution target for the allowed target-level action"
                    .to_string(),
            ))
        } else {
            Ok(())
        };
    };
    let canonical_evidence = decision
        .event
        .metadata
        .get("canonical_target")
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(
                "gateway allowed a target-level action without canonical target evidence"
                    .to_string(),
            )
        })?;
    let provided_fingerprint = decision
        .event
        .metadata
        .get("action_fingerprint")
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(
                "gateway allowed a target-level action without an action fingerprint".to_string(),
            )
        })?;
    let evidence_fingerprint = opaque_reference_fingerprint(canonical_evidence);
    if provided_fingerprint != &evidence_fingerprint {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "gateway action fingerprint does not authenticate its canonical target evidence"
                .to_string(),
        ));
    }
    if !matches!(action, ManagedExternalAction::Filesystem(_))
        && canonical_evidence != &expected_target.canonical_json()
    {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "gateway action fingerprint mismatch: authorized target differs from execution target"
                .to_string(),
        ));
    }
    Ok(())
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                    class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                    ..CapabilityPolicy::default()
                },
            )),
            1,
        )
    });
    wait_for_authorizer_socket(&socket_path)?;
    let client =
        UnixGatewayExternalActionAuthorizer::new_authenticated(&socket_path, std::process::id());
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

pub(crate) fn governed_target_execution_unix_smoke_command(
    socket_path: &Path,
    expected_gateway_pid: u32,
    workspace_root: &Path,
    network_target: SocketAddr,
    mode: FrameworkAdapterMode,
) -> Result<()> {
    let client =
        UnixGatewayExternalActionAuthorizer::new_authenticated(socket_path, expected_gateway_pid);
    let mcp = execute_governed_mcp_tool_action(
        &client,
        smoke_session(mode),
        ManagedMcpToolAction {
            server_name: "local-smoke".to_string(),
            tool_name: "echo".to_string(),
            arguments_policy: "exact_arguments".to_string(),
            arguments: serde_json::json!({"message": "ferrogate governed mcp smoke"}),
        },
        false,
    )?;
    let filesystem = execute_governed_filesystem_action(
        &client,
        smoke_session(mode),
        ManagedFilesystemAction {
            path: "allowed.txt".to_string(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        },
        workspace_root,
        false,
    )?;
    let filesystem_write = execute_governed_filesystem_action(
        &client,
        smoke_session(mode),
        ManagedFilesystemAction {
            path: "allowed-created.txt".to_string(),
            access: ManagedFilesystemAccess::Write,
            workspace_relative: true,
        },
        workspace_root,
        false,
    )?;
    let network = execute_governed_network_egress_action(
        &client,
        smoke_session(mode),
        ManagedNetworkEgressAction {
            host: network_target.ip().to_string(),
            port: network_target.port(),
            protocol: "tcp".to_string(),
            resolved_ips: vec![network_target.ip().to_string()],
        },
        false,
    )?;
    let secrets = BTreeMap::from([(
        "vault/provider-key".to_string(),
        "resolved-secret-value".to_string(),
    )]);
    let secret = execute_governed_secret_action(
        &client,
        smoke_session(mode),
        ManagedSecretAction {
            secret_id: "vault/provider-key".to_string(),
            purpose: "provider.call".to_string(),
        },
        &secrets,
        false,
    )?;
    let cli = execute_governed_cli_action(
        &client,
        smoke_session(mode),
        ManagedCliAction {
            command: "/usr/bin/env".to_string(),
            args: Vec::new(),
            working_dir: workspace_root.display().to_string(),
            env_policy: "empty".to_string(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            artifact_capture: false,
        },
        false,
    )?;
    let output = serde_json::json!({
        "mcp": target_execution_projection(&mcp, &["output_excerpt"] )?,
        "filesystem": target_execution_projection(&filesystem, &["content_excerpt"] )?,
        "filesystem_write": target_execution_projection(&filesystem_write, &["byte_len"] )?,
        "network": target_execution_projection(&network, &["bytes_written"] )?,
        "secret": target_execution_projection(&secret, &["redacted_value", "secret_len"] )?,
        "cli": target_execution_projection(&cli, &["stdout_excerpt", "stderr_excerpt", "status_code"] )?,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn target_execution_projection(
    events: &[NormalizedFrameworkEvent],
    evidence_fields: &[&str],
) -> Result<serde_json::Value> {
    let event = events
        .last()
        .ok_or_else(|| anyhow::anyhow!("governed action produced no execution evidence"))?;
    if event
        .metadata
        .get("executed_after_authorization")
        .map(String::as_str)
        != Some("true")
    {
        anyhow::bail!("governed action did not prove post-authorization execution");
    }
    let mut projection = serde_json::Map::from_iter([(
        "executed_after_authorization".to_string(),
        serde_json::Value::Bool(true),
    )]);
    for field in evidence_fields {
        let value = event
            .metadata
            .get(*field)
            .ok_or_else(|| anyhow::anyhow!("governed action evidence omitted {field}"))?;
        projection.insert(
            (*field).to_string(),
            serde_json::Value::String(value.clone()),
        );
    }
    Ok(serde_json::Value::Object(projection))
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
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::Tool(action));
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
        arguments: serde_json::json!({"message": "ferrogate governed mcp smoke"}),
    };
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::McpTool(action));
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::McpTool]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::Skill(action));
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Skill]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::Memory(
            ManagedMemoryAction {
                access: ManagedMemoryAccess::Write,
                namespace: "session".to_string(),
                key: "summary".to_string(),
            },
        ));
    }
    let mut store = BTreeMap::new();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([
                CapabilityAction::MemoryRead,
                CapabilityAction::MemoryWrite,
            ]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
        "vault/openai-api-key".to_string(),
        "ferrogate governed secret smoke".to_string(),
    )]);
    let action = ManagedSecretAction {
        secret_id: "vault/openai-api-key".to_string(),
        purpose: "provider_call".to_string(),
    };
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::Secret(action));
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Secret]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
        resolved_ips: vec!["127.0.0.1".to_string()],
    };
    // #247: self-hosted runs report-only against the SAME live loopback listener.
    // The egress I/O still happens (the listener receives the payload) and the
    // denied gateway decision is recorded, never enforced. The workload runs
    // FIRST (it performs the connect), then the server thread is joined.
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_network_or_rest_report_only_smoke(
            ManagedExternalAction::NetworkEgress(action),
            "received_payload",
            move || server.join(),
        );
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
            allow_direct_network_egress: true,
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_family_report_only_smoke(ManagedExternalAction::Browser(action));
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Browser]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
        resolved_ips: vec!["127.0.0.1".to_string()],
        redirect_chain: Vec::new(),
    };
    // #247: self-hosted runs report-only against the SAME live loopback HTTP
    // listener. The request is really sent (the server serves it) and the denied
    // gateway decision is recorded, never enforced. Workload runs FIRST.
    if mode == FrameworkAdapterMode::SelfHosted {
        return self_hosted_network_or_rest_report_only_smoke(
            ManagedExternalAction::Rest(action),
            "served_request",
            move || server.join(),
        );
    }
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));
    let events = match execute_governed_rest_action(&gate, smoke_session(mode), action, false) {
        Ok(events) => events,
        Err(rejection) => {
            // The typed dispatch verdict IS the evidence on this path, so it is
            // emitted before the command fails. An operator (and any harness)
            // reads the discriminant off `metadata`, never off the message.
            eprintln!("{}", rejection.event.canonical_json());
            return Err(rejection.error.into());
        }
    };
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    expected_gateway_pid: u32,
    expected_gateway_uid: u32,
    timeout: Duration,
}

impl UnixGatewayExternalActionAuthorizer {
    pub(crate) fn new_authenticated(
        socket_path: impl Into<std::path::PathBuf>,
        expected_gateway_pid: u32,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_gateway_pid,
            expected_gateway_uid: rustix::process::geteuid().as_raw(),
            timeout: EXTERNAL_ACTION_UNIX_TIMEOUT,
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
        if let Err(error) = authenticate_unix_authorizer_peer(
            &stream,
            self.expected_gateway_pid,
            self.expected_gateway_uid,
        ) {
            return transport_failure_decision(&request, error);
        }
        if let Err(error) = stream.set_read_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer read timeout setup failed: {error}"),
            );
        }
        if let Err(error) = stream.set_write_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer write timeout setup failed: {error}"),
            );
        }
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

#[cfg(target_os = "linux")]
fn authenticate_unix_authorizer_peer(
    stream: &UnixStream,
    expected_gateway_pid: u32,
    expected_gateway_uid: u32,
) -> Result<(), String> {
    if expected_gateway_pid == 0 {
        return Err("gateway external action authorizer expected peer PID must be non-zero".into());
    }
    let peer = rustix::net::sockopt::socket_peercred(stream).map_err(|error| {
        format!("gateway external action authorizer peer credentials failed: {error}")
    })?;
    let peer_pid = u32::try_from(peer.pid.as_raw_pid()).map_err(|_| {
        "gateway external action authorizer peer PID cannot be represented".to_string()
    })?;
    if peer_pid != expected_gateway_pid {
        return Err(format!(
            "gateway external action authorizer peer PID mismatch: expected {expected_gateway_pid}, got {peer_pid}"
        ));
    }
    let peer_uid = peer.uid.as_raw();
    if peer_uid != expected_gateway_uid {
        return Err(format!(
            "gateway external action authorizer peer UID mismatch: expected {expected_gateway_uid}, got {peer_uid}"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn authenticate_unix_authorizer_peer(
    _stream: &UnixStream,
    _expected_gateway_pid: u32,
    _expected_gateway_uid: u32,
) -> Result<(), String> {
    Err("authenticated gateway Unix peer verification requires Linux SO_PEERCRED".to_string())
}

#[cfg(test)]
struct HttpGatewayExternalActionAuthorizer {
    endpoint: SocketAddr,
    timeout: Duration,
}

#[cfg(test)]
impl HttpGatewayExternalActionAuthorizer {
    pub(crate) fn new(endpoint: SocketAddr) -> Self {
        Self::new_with_timeout(endpoint, DEFAULT_EXTERNAL_ACTION_HTTP_TIMEOUT)
    }

    pub(crate) fn new_with_timeout(endpoint: SocketAddr, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
    let execution = run_authorized_cli_action(&action, &decision)?;
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
    match run_authorized_cli_action(&action, &decision) {
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
    let cancellation = run_authorized_cli_action_until_cancelled(&action, &decision)?;
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
    recorded_metadata([
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
        recorded_metadata([
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
    decision: &ExternalActionGateDecision,
) -> Result<GovernedCliCancellation, FrameworkAdapterError> {
    let authorized = open_authorized_cli_objects(decision)?;
    let mut command = authorized.command(action);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.env_clear();
    configure_managed_process_group(&mut command);
    let mut child = spawn_cli_with_executable_busy_retry(&mut command).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action spawn failed after gateway authorization: {error}"
        ))
    })?;
    let started_at = Instant::now();
    // Observe the leader over a bounded window instead of a single fixed sleep.
    // A fast leader that exits on its own (e.g. immediately after forking a
    // descendant) must be seen as "completed before cancellation"; under CPU
    // load its exit can land well after a fixed 25ms probe, which would
    // otherwise misclassify it as still-running and report a spurious cancel.
    // Break early the moment it exits, and only treat it as cancellable once it
    // is still alive after the full window -- either way the whole process group
    // is killed and reaped below, so the enforcement guarantee is unchanged.
    let observation_window = Duration::from_millis(500);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => {
                kill_and_reap_process_group(&mut child);
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "managed CLI action status check failed: {error}"
                )));
            }
        }
        if started_at.elapsed() >= observation_window {
            break None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    match status {
        None => {
            kill_and_reap_process_group(&mut child);
            return Ok(GovernedCliCancellation {
                cancellation_reason: "operator_cancelled".to_string(),
                elapsed_millis: started_at.elapsed().as_millis(),
            });
        }
        Some(_) => kill_process_group(child.id()),
    }
    Err(FrameworkAdapterError::CapabilityDenied(
        "managed CLI action completed before cancellation could be observed".to_string(),
    ))
}

/// Run one governed REST action end to end.
///
/// The error type is [`GovernedRestRejection`] rather than a bare
/// [`FrameworkAdapterError`] because a failure here is evidence, not just a
/// message: it carries the typed wire stage and the worker event that ships it
/// across the process boundary. The prose is preserved verbatim through
/// `Display`, so existing operator-facing behaviour is unchanged.
fn execute_governed_rest_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedRestAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, GovernedRestRejection>
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
    )
    .map_err(|error| GovernedRestRejection::gate_refused(&session, &action, error))?;
    let execution = run_authorized_rest_action(&action)
        .map_err(|failure| GovernedRestRejection::dispatch_failed(&session, &action, failure))?;
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
    let execution = run_authorized_filesystem_action(&action, workspace_root, &decision)?;
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
        recorded_metadata([
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
        output_excerpt: recorded_excerpt(message.as_bytes(), 512),
    })
}

struct GovernedMcpToolExecution {
    output_excerpt: String,
}

impl GovernedMcpToolExecution {
    fn metadata(self, action: &ManagedMcpToolAction) -> BTreeMap<String, String> {
        recorded_metadata([
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
    let message = action
        .arguments
        .get("message")
        .and_then(serde_json::Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(
                "managed MCP smoke requires exact arguments.message".to_string(),
            )
        })?;
    Ok(GovernedMcpToolExecution {
        output_excerpt: recorded_excerpt(message.as_bytes(), 512),
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
        recorded_metadata([
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
        output_excerpt: recorded_excerpt(action.declared_capabilities.join(",").as_bytes(), 512),
    })
}

struct GovernedMemoryExecution {
    value_excerpt: String,
}

impl GovernedMemoryExecution {
    fn metadata(self, action: &ManagedMemoryAction) -> BTreeMap<String, String> {
        recorded_metadata([
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
                value_excerpt: recorded_excerpt(value.as_bytes(), 512),
            })
        }
        ManagedMemoryAccess::Read => {
            let value = store.get(&store_key).ok_or_else(|| {
                FrameworkAdapterError::CapabilityDenied(
                    "managed memory action read failed after gateway authorization".to_string(),
                )
            })?;
            Ok(GovernedMemoryExecution {
                value_excerpt: recorded_excerpt(value.as_bytes(), 512),
            })
        }
    }
}

struct GovernedSecretExecution {
    secret_len: usize,
}

impl GovernedSecretExecution {
    fn metadata(self, action: &ManagedSecretAction) -> BTreeMap<String, String> {
        recorded_metadata([
            ("external_action".to_string(), "secret".to_string()),
            (
                "external_target".to_string(),
                format!("secret:{}", opaque_reference_fingerprint(&action.secret_id)),
            ),
            (
                "secret_ref_fingerprint".to_string(),
                opaque_reference_fingerprint(&action.secret_id),
            ),
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
        recorded_metadata([
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
    let pinned_ip = required_pinned_ip(&action.resolved_ips)?;
    if !pinned_ip.is_loopback() {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed network egress pinned IP is outside the loopback execution boundary"
                .to_string(),
        ));
    }
    let endpoint = SocketAddr::new(pinned_ip, action.port);
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
        recorded_metadata([
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
        recorded_metadata([
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
    decision: &ExternalActionGateDecision,
) -> Result<GovernedFilesystemExecution, FrameworkAdapterError> {
    if !matches!(
        action.access,
        ManagedFilesystemAccess::Read
            | ManagedFilesystemAccess::Write
            | ManagedFilesystemAccess::Execute
    ) {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem execution supports read, create-only write, and execute access"
                .to_string(),
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
    let resolved_root = std::fs::canonicalize(workspace_root).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root cannot be resolved: {error}"
        ))
    })?;
    let authorized_identity =
        authorized_filesystem_identity(decision, &resolved_root, relative, action.access)?;
    let (resolved_path, bytes) = match action.access {
        ManagedFilesystemAccess::Read => {
            read_beneath_authorized_root(&resolved_root, relative, authorized_identity.as_ref())?
        }
        ManagedFilesystemAccess::Write => {
            create_beneath_authorized_root(&resolved_root, relative, authorized_identity.as_ref())?
        }
        ManagedFilesystemAccess::Execute => {
            execute_beneath_authorized_root(&resolved_root, relative, authorized_identity.as_ref())?
        }
        ManagedFilesystemAccess::Delete => unreachable!(),
    };
    Ok(GovernedFilesystemExecution {
        resolved_path,
        byte_len: bytes.len(),
        content_excerpt: recorded_excerpt(&bytes, 512),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorizedFilesystemIdentity {
    Read {
        root_device: u64,
        root_inode: u64,
        target_device: u64,
        target_inode: u64,
        target_content_fingerprint: Option<String>,
    },
    Create {
        root_device: u64,
        root_inode: u64,
        parent_device: u64,
        parent_inode: u64,
    },
}

fn authorized_filesystem_identity(
    decision: &ExternalActionGateDecision,
    execution_root: &Path,
    relative: &Path,
    access: ManagedFilesystemAccess,
) -> Result<Option<AuthorizedFilesystemIdentity>, FrameworkAdapterError> {
    let selector = decision
        .event
        .metadata
        .get("selector")
        .map(String::as_str)
        .unwrap_or_default();
    if selector == "legacy_class_wide" {
        return Ok(None);
    }
    let canonical = decision
        .event
        .metadata
        .get("canonical_target")
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(
                "typed filesystem authorization omitted canonical target evidence".to_string(),
            )
        })?;
    let value: serde_json::Value = serde_json::from_str(canonical).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "typed filesystem authorization returned invalid canonical target evidence: {error}"
        ))
    })?;
    if value.get("kind").and_then(serde_json::Value::as_str) != Some("filesystem")
        || value.get("operation").and_then(serde_json::Value::as_str) != Some(access.as_str())
    {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "typed filesystem authorization returned the wrong target kind or operation"
                .to_string(),
        ));
    }
    let authorized_root = required_canonical_path_field(&value, "workspace_root")?;
    if authorized_root != execution_root {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem execution root differs from the authorized root".to_string(),
        ));
    }
    if access == ManagedFilesystemAccess::Write {
        let authorized_parent = required_canonical_path_field(&value, "resolved_parent")?;
        let expected_parent =
            execution_root.join(relative.parent().unwrap_or_else(|| Path::new("")));
        if authorized_parent != expected_parent {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "managed filesystem execution parent differs from the authorized parent"
                    .to_string(),
            ));
        }
        let leaf = relative
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or_else(|| {
                FrameworkAdapterError::CapabilityDenied(
                    "managed filesystem execution target has no UTF-8 leaf".to_string(),
                )
            })?;
        if value.get("leaf_name").and_then(serde_json::Value::as_str) != Some(leaf)
            || value
                .get("target_must_not_exist")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "typed filesystem create authorization omitted create-only target evidence"
                    .to_string(),
            ));
        }
        return Ok(Some(AuthorizedFilesystemIdentity::Create {
            root_device: required_u64_field(&value, "root_device")?,
            root_inode: required_u64_field(&value, "root_inode")?,
            parent_device: required_u64_field(&value, "parent_device")?,
            parent_inode: required_u64_field(&value, "parent_inode")?,
        }));
    }
    let authorized_target = required_canonical_path_field(&value, "resolved_path")?;
    if authorized_target != execution_root.join(relative) {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem execution target differs from the authorized target".to_string(),
        ));
    }
    Ok(Some(AuthorizedFilesystemIdentity::Read {
        root_device: required_u64_field(&value, "root_device")?,
        root_inode: required_u64_field(&value, "root_inode")?,
        target_device: required_u64_field(&value, "target_device")?,
        target_inode: required_u64_field(&value, "target_inode")?,
        target_content_fingerprint: value
            .get("target_content_fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }))
}

fn required_canonical_path_field(
    value: &serde_json::Value,
    field: &str,
) -> Result<PathBuf, FrameworkAdapterError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "typed filesystem authorization omitted {field}"
            ))
        })
}

fn required_u64_field(
    value: &serde_json::Value,
    field: &str,
) -> Result<u64, FrameworkAdapterError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "typed filesystem authorization omitted {field}"
            ))
        })
}

#[cfg(target_os = "linux")]
fn read_beneath_authorized_root(
    root: &Path,
    relative: &Path,
    authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};

    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root open failed: {error}"
        ))
    })?;
    let root_file: std::fs::File = root_fd.into();
    if let Some(authorized) = authorized {
        let AuthorizedFilesystemIdentity::Read {
            root_device,
            root_inode,
            ..
        } = authorized
        else {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "filesystem read received create authorization evidence".to_string(),
            ));
        };
        let metadata = root_file.metadata().map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed filesystem execution root identity failed: {error}"
            ))
        })?;
        if metadata.dev() != *root_device || metadata.ino() != *root_inode {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "managed filesystem execution root identity changed after authorization"
                    .to_string(),
            ));
        }
    }
    let target_fd = openat2(
        &root_file,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem target open beneath authorized root failed: {error}"
        ))
    })?;
    let mut target_file: std::fs::File = target_fd.into();
    if let Some(authorized) = authorized {
        let AuthorizedFilesystemIdentity::Read {
            target_device,
            target_inode,
            ..
        } = authorized
        else {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "filesystem read received create authorization evidence".to_string(),
            ));
        };
        let metadata = target_file.metadata().map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed filesystem target identity failed: {error}"
            ))
        })?;
        if metadata.dev() != *target_device || metadata.ino() != *target_inode {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "managed filesystem target identity changed after authorization".to_string(),
            ));
        }
        // Defense in depth: the authorization layer already refuses hard-linked
        // read targets, but a hard link is not a symlink, so openat2's
        // NO_SYMLINKS/RESOLVE_BENEATH would happily open one whose inode also has
        // a name outside the root. Refuse any multiply-linked read target here
        // too, at the point of the actual read.
        if metadata.nlink() > 1 {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "managed filesystem read target is hard-linked (st_nlink > 1); its inode may alias content outside the authorized root"
                    .to_string(),
            ));
        }
    }
    let mut bytes = Vec::new();
    target_file.read_to_end(&mut bytes).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem action read failed after gateway authorization: {error}"
        ))
    })?;
    Ok((root.join(relative), bytes))
}

#[cfg(target_os = "linux")]
fn create_beneath_authorized_root(
    root: &Path,
    relative: &Path,
    authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};

    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root open failed: {error}"
        ))
    })?;
    let root_file: std::fs::File = root_fd.into();
    let AuthorizedFilesystemIdentity::Create {
        root_device,
        root_inode,
        parent_device,
        parent_inode,
    } = authorized.ok_or_else(|| {
        FrameworkAdapterError::CapabilityDenied(
            "create-only filesystem writes require typed authorization evidence".to_string(),
        )
    })?
    else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "filesystem create received read authorization evidence".to_string(),
        ));
    };
    let root_metadata = root_file.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root identity failed: {error}"
        ))
    })?;
    if root_metadata.dev() != *root_device || root_metadata.ino() != *root_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem execution root identity changed after authorization".to_string(),
        ));
    }
    let parent_relative = relative
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_fd = openat2(
        &root_file,
        parent_relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem write parent open beneath authorized root failed: {error}"
        ))
    })?;
    let parent_file: std::fs::File = parent_fd.into();
    let parent_metadata = parent_file.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem write parent identity failed: {error}"
        ))
    })?;
    if parent_metadata.dev() != *parent_device || parent_metadata.ino() != *parent_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem write parent identity changed after authorization".to_string(),
        ));
    }
    let leaf = relative.file_name().ok_or_else(|| {
        FrameworkAdapterError::CapabilityDenied(
            "managed filesystem write target has no filename".to_string(),
        )
    })?;
    let target_fd = openat2(
        &parent_file,
        Path::new(leaf),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_bits_retain(0o600),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem create-only target open failed: {error}"
        ))
    })?;
    let _target_file: std::fs::File = target_fd.into();
    Ok((root.join(relative), Vec::new()))
}

#[cfg(target_os = "linux")]
fn execute_beneath_authorized_root(
    root: &Path,
    relative: &Path,
    authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    use std::{os::fd::AsRawFd, os::unix::fs::MetadataExt, os::unix::process::CommandExt};

    use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};

    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root open failed: {error}"
        ))
    })?;
    let root_file: std::fs::File = root_fd.into();
    let AuthorizedFilesystemIdentity::Read {
        root_device,
        root_inode,
        target_device,
        target_inode,
        target_content_fingerprint,
    } = authorized.ok_or_else(|| {
        FrameworkAdapterError::CapabilityDenied(
            "filesystem execute requires typed authorization evidence".to_string(),
        )
    })?
    else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "filesystem execute received create authorization evidence".to_string(),
        ));
    };
    let root_metadata = root_file.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem execution root identity failed: {error}"
        ))
    })?;
    if root_metadata.dev() != *root_device || root_metadata.ino() != *root_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem execution root identity changed after authorization".to_string(),
        ));
    }
    let expected_content_fingerprint = target_content_fingerprint.as_deref().ok_or_else(|| {
        FrameworkAdapterError::CapabilityDenied(
            "filesystem execute authorization omitted target content fingerprint".to_string(),
        )
    })?;
    let target_fd = openat2(
        &root_file,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem executable open beneath authorized root failed: {error}"
        ))
    })?;
    let target_file: std::fs::File = target_fd.into();
    let metadata = target_file.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem executable identity failed: {error}"
        ))
    })?;
    if metadata.dev() != *target_device || metadata.ino() != *target_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed filesystem executable identity changed after authorization".to_string(),
        ));
    }
    let target_file = immutable_executable_snapshot(target_file, expected_content_fingerprint)?;
    let mut command = Command::new(format!("/proc/self/fd/{}", target_file.as_raw_fd()));
    // Preserve the authorized target path as argv[0]: multi-call binaries
    // (busybox, uutils coreutils) dispatch on the program name and would
    // otherwise observe the opaque fd number. The executed bytes remain the
    // sealed snapshot behind the fd.
    command
        .arg0(root.join(relative))
        .current_dir(format!("/proc/self/fd/{}", root_file.as_raw_fd()))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_managed_process_group(&mut command);
    let mut child = command.spawn().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem executable spawn failed: {error}"
        ))
    })?;
    let started_at = Instant::now();
    let timeout = Duration::from_secs(2);
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                kill_and_reap_process_group(&mut child);
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "managed filesystem executable status failed: {error}"
                )));
            }
        };
        if let Some(status) = status {
            kill_process_group(child.id());
            if !status.success() {
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "managed filesystem executable exited with status {:?}",
                    status.code()
                )));
            }
            break;
        }
        if started_at.elapsed() >= timeout {
            kill_and_reap_process_group(&mut child);
            return Err(FrameworkAdapterError::CapabilityDenied(
                "managed filesystem executable timed out after 2000ms".to_string(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok((root.join(relative), Vec::new()))
}

#[cfg(not(target_os = "linux"))]
fn execute_beneath_authorized_root(
    _root: &Path,
    _relative: &Path,
    _authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    Err(FrameworkAdapterError::CapabilityDenied(
        "race-resistant managed filesystem execution requires Linux descriptor binding".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn create_beneath_authorized_root(
    _root: &Path,
    _relative: &Path,
    _authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    Err(FrameworkAdapterError::CapabilityDenied(
        "race-resistant managed filesystem creation requires Linux openat2".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn read_beneath_authorized_root(
    _root: &Path,
    _relative: &Path,
    _authorized: Option<&AuthorizedFilesystemIdentity>,
) -> Result<(PathBuf, Vec<u8>), FrameworkAdapterError> {
    Err(FrameworkAdapterError::CapabilityDenied(
        "race-resistant managed filesystem execution requires Linux openat2".to_string(),
    ))
}

struct GovernedCliExecution {
    status_code: Option<i32>,
    stdout_excerpt: String,
    stderr_excerpt: String,
}

impl GovernedCliExecution {
    fn metadata(self, action: &ManagedCliAction) -> BTreeMap<String, String> {
        recorded_metadata([
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
    decision: &ExternalActionGateDecision,
) -> Result<GovernedCliExecution, FrameworkAdapterError> {
    let authorized = open_authorized_cli_objects(decision)?;
    let mut command = authorized.command(action);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.env_clear();
    configure_managed_process_group(&mut command);
    let mut child = spawn_cli_with_executable_busy_retry(&mut command).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action spawn failed after gateway authorization: {error}"
        ))
    })?;
    let output = collect_bounded_child_output(
        &mut child,
        Duration::from_millis(action.timeout_millis.max(1)),
        action.stdout_limit_bytes,
        action.stderr_limit_bytes,
    )?;
    if !output.status.success() {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action exited with status {:?}",
            output.status.code()
        )));
    }
    Ok(GovernedCliExecution {
        status_code: output.status.code(),
        stdout_excerpt: recorded_excerpt(&output.stdout, action.stdout_limit_bytes),
        stderr_excerpt: recorded_excerpt(&output.stderr, action.stderr_limit_bytes),
    })
}

struct BoundedChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum BoundedPipeRead {
    Complete(Vec<u8>),
    Exceeded,
}

fn collect_bounded_child_output(
    child: &mut Child,
    timeout: Duration,
    stdout_limit: u64,
    stderr_limit: u64,
) -> Result<BoundedChildOutput, FrameworkAdapterError> {
    let Some(stdout) = child.stdout.take() else {
        kill_and_reap_process_group(child);
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed CLI action stdout pipe was not configured".to_string(),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        kill_and_reap_process_group(child);
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed CLI action stderr pipe was not configured".to_string(),
        ));
    };
    configure_nonblocking_pipe(&stdout).map_err(|error| {
        kill_and_reap_process_group(child);
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action stdout setup failed: {error}"
        ))
    })?;
    configure_nonblocking_pipe(&stderr).map_err(|error| {
        kill_and_reap_process_group(child);
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action stderr setup failed: {error}"
        ))
    })?;
    let stop_readers = Arc::new(AtomicBool::new(false));
    let mut stdout_reader = Some(spawn_bounded_pipe_reader(
        stdout,
        stdout_limit,
        Arc::clone(&stop_readers),
    ));
    let mut stderr_reader = Some(spawn_bounded_pipe_reader(
        stderr,
        stderr_limit,
        Arc::clone(&stop_readers),
    ));
    let mut stdout_result = None;
    let mut stderr_result = None;
    let started_at = Instant::now();

    let status = loop {
        if let Err(error) = poll_bounded_reader(&mut stdout_reader, &mut stdout_result) {
            kill_and_reap_process_group(child);
            stop_readers.store(true, Ordering::Release);
            join_remaining_reader(&mut stderr_reader);
            return Err(error);
        }
        if let Err(error) = poll_bounded_reader(&mut stderr_reader, &mut stderr_result) {
            kill_and_reap_process_group(child);
            stop_readers.store(true, Ordering::Release);
            join_remaining_reader(&mut stdout_reader);
            return Err(error);
        }
        if matches!(stdout_result, Some(BoundedPipeRead::Exceeded)) {
            kill_and_reap_process_group(child);
            stop_readers.store(true, Ordering::Release);
            join_remaining_reader(&mut stderr_reader);
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action stdout exceeded {stdout_limit} bytes"
            )));
        }
        if matches!(stderr_result, Some(BoundedPipeRead::Exceeded)) {
            kill_and_reap_process_group(child);
            stop_readers.store(true, Ordering::Release);
            join_remaining_reader(&mut stdout_reader);
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action stderr exceeded {stderr_limit} bytes"
            )));
        }
        let child_status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                kill_and_reap_process_group(child);
                stop_readers.store(true, Ordering::Release);
                join_remaining_reader(&mut stdout_reader);
                join_remaining_reader(&mut stderr_reader);
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "managed CLI action status check failed: {error}"
                )));
            }
        };
        if let Some(status) = child_status {
            // A successful leader may leave descendants holding the pipes. The
            // action owns the whole group, so no descendant may outlive it.
            kill_process_group(child.id());
            stop_readers.store(true, Ordering::Release);
            break status;
        }
        if started_at.elapsed() >= timeout {
            kill_and_reap_process_group(child);
            stop_readers.store(true, Ordering::Release);
            join_remaining_reader(&mut stdout_reader);
            join_remaining_reader(&mut stderr_reader);
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action timed out after {}ms",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(5));
    };

    let stdout = finish_bounded_reader(stdout_reader, stdout_result, "stdout");
    let stderr = finish_bounded_reader(stderr_reader, stderr_result, "stderr");
    Ok(BoundedChildOutput {
        status,
        stdout: stdout?,
        stderr: stderr?,
    })
}

fn spawn_bounded_pipe_reader<R>(
    mut pipe: R,
    limit: u64,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<BoundedPipeRead>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let stopping = stop.load(Ordering::Acquire);
            let read = match pipe.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stopping {
                        return Ok(BoundedPipeRead::Complete(captured));
                    }
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if read == 0 {
                return Ok(BoundedPipeRead::Complete(captured));
            }
            let next_len = u64::try_from(captured.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            if next_len > limit {
                return Ok(BoundedPipeRead::Exceeded);
            }
            captured.extend_from_slice(&buffer[..read]);
        }
    })
}

#[cfg(target_os = "linux")]
fn configure_nonblocking_pipe<Fd: std::os::fd::AsFd>(fd: &Fd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

#[cfg(not(target_os = "linux"))]
fn configure_nonblocking_pipe<Fd>(_fd: &Fd) -> io::Result<()> {
    Ok(())
}

fn poll_bounded_reader(
    reader: &mut Option<thread::JoinHandle<io::Result<BoundedPipeRead>>>,
    result: &mut Option<BoundedPipeRead>,
) -> Result<(), FrameworkAdapterError> {
    if reader.as_ref().is_some_and(thread::JoinHandle::is_finished) {
        *result = Some(join_bounded_reader(reader.take().expect("reader exists"))?);
    }
    Ok(())
}

fn finish_bounded_reader(
    reader: Option<thread::JoinHandle<io::Result<BoundedPipeRead>>>,
    result: Option<BoundedPipeRead>,
    stream: &str,
) -> Result<Vec<u8>, FrameworkAdapterError> {
    let result = match result {
        Some(result) => result,
        None => join_bounded_reader(reader.ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action {stream} reader disappeared"
            ))
        })?)?,
    };
    match result {
        BoundedPipeRead::Complete(bytes) => Ok(bytes),
        BoundedPipeRead::Exceeded => Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action {stream} exceeded its configured byte limit"
        ))),
    }
}

fn join_bounded_reader(
    reader: thread::JoinHandle<io::Result<BoundedPipeRead>>,
) -> Result<BoundedPipeRead, FrameworkAdapterError> {
    reader
        .join()
        .map_err(|_| {
            FrameworkAdapterError::CapabilityDenied(
                "managed CLI action output reader panicked".to_string(),
            )
        })?
        .map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action output collection failed: {error}"
            ))
        })
}

fn join_remaining_reader(reader: &mut Option<thread::JoinHandle<io::Result<BoundedPipeRead>>>) {
    if let Some(reader) = reader.take() {
        let _ = reader.join();
    }
}

struct AuthorizedCliObjects {
    executable: std::fs::File,
    /// Authorized executable path, preserved as `argv[0]` so multi-call
    /// binaries that dispatch on the program name (busybox, uutils
    /// coreutils) behave identically to a direct invocation. The executed
    /// bytes remain the sealed `/proc/self/fd/N` snapshot.
    executable_path: PathBuf,
    cwd: std::fs::File,
}

impl AuthorizedCliObjects {
    #[cfg(target_os = "linux")]
    fn command(&self, action: &ManagedCliAction) -> Command {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let mut command = Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        command
            .arg0(&self.executable_path)
            .args(&action.args)
            .current_dir(format!("/proc/self/fd/{}", self.cwd.as_raw_fd()));
        command
    }

    #[cfg(not(target_os = "linux"))]
    fn command(&self, _action: &ManagedCliAction) -> Command {
        unreachable!("authorized CLI objects are only available on Linux")
    }
}

#[cfg(target_os = "linux")]
fn open_authorized_cli_objects(
    decision: &ExternalActionGateDecision,
) -> Result<AuthorizedCliObjects, FrameworkAdapterError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{open, Mode, OFlags};

    let canonical = decision
        .event
        .metadata
        .get("canonical_target")
        .ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(
                "CLI authorization omitted canonical target evidence".to_string(),
            )
        })?;
    let target: CanonicalCapabilityTarget = serde_json::from_str(canonical).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "CLI authorization returned invalid canonical target evidence: {error}"
        ))
    })?;
    let CanonicalCapabilityTarget::Cli {
        executable,
        executable_device,
        executable_inode,
        executable_content_fingerprint,
        cwd,
        cwd_device,
        cwd_inode,
        ..
    } = target
    else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "CLI authorization returned the wrong canonical target kind".to_string(),
        ));
    };
    let executable_path = PathBuf::from(&executable);
    let executable = open(
        &executable,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "authorized CLI executable open failed: {error}"
        ))
    })?;
    let executable: std::fs::File = executable.into();
    let metadata = executable.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "authorized CLI executable identity failed: {error}"
        ))
    })?;
    if metadata.dev() != executable_device || metadata.ino() != executable_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "authorized CLI executable identity changed before execution".to_string(),
        ));
    }
    let executable = immutable_executable_snapshot(executable, &executable_content_fingerprint)?;
    let cwd = open(
        &cwd,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!("authorized CLI cwd open failed: {error}"))
    })?;
    let cwd: std::fs::File = cwd.into();
    let metadata = cwd.metadata().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "authorized CLI cwd identity failed: {error}"
        ))
    })?;
    if metadata.dev() != cwd_device || metadata.ino() != cwd_inode {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "authorized CLI cwd identity changed before execution".to_string(),
        ));
    }
    Ok(AuthorizedCliObjects {
        executable,
        executable_path,
        cwd,
    })
}

#[cfg(target_os = "linux")]
fn immutable_executable_snapshot(
    mut source: std::fs::File,
    expected_fingerprint: &str,
) -> Result<std::fs::File, FrameworkAdapterError> {
    use sha2::{Digest, Sha256};
    use std::os::fd::AsRawFd;

    use rustix::fs::{
        fchmod, fcntl_add_seals, memfd_create, open, MemfdFlags, Mode, OFlags, SealFlags,
    };

    const MAX_CLI_EXECUTABLE_BYTES: usize = 128 * 1024 * 1024;

    let snapshot_fd = memfd_create(
        "ferrogate-cli-executable",
        MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed immutable executable snapshot creation failed: {error}"
        ))
    })?;
    let mut snapshot: std::fs::File = snapshot_fd.into();
    let mut digest = Sha256::new();
    let mut copied = 0_usize;
    let mut magic = [0_u8; 4];
    let mut magic_len = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed executable snapshot read failed: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read).ok_or_else(|| {
            FrameworkAdapterError::CapabilityDenied(
                "managed executable snapshot length overflow".to_string(),
            )
        })?;
        if copied > MAX_CLI_EXECUTABLE_BYTES {
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed executable exceeds the {MAX_CLI_EXECUTABLE_BYTES}-byte immutable snapshot limit"
            )));
        }
        snapshot.write_all(&buffer[..read]).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed executable snapshot write failed: {error}"
            ))
        })?;
        let magic_remaining = magic.len().saturating_sub(magic_len);
        let magic_read = magic_remaining.min(read);
        magic[magic_len..magic_len + magic_read].copy_from_slice(&buffer[..magic_read]);
        magic_len += magic_read;
        digest.update(&buffer[..read]);
    }
    let actual_fingerprint = format!("sha256:{:x}", digest.finalize());
    if actual_fingerprint != expected_fingerprint {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed executable content fingerprint changed after authorization".to_string(),
        ));
    }
    if magic_len >= 2 && &magic[..2] == b"#!" {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed executable shebang scripts are denied until interpreter identity and content are bound"
                .to_string(),
        ));
    }
    if magic_len < 4 || &magic != b"\x7fELF" {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed executable is not a Linux ELF binary".to_string(),
        ));
    }
    fchmod(&snapshot, Mode::RUSR | Mode::XUSR).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed executable snapshot mode setup failed: {error}"
        ))
    })?;
    fcntl_add_seals(
        &snapshot,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed executable snapshot sealing failed: {error}"
        ))
    })?;
    let snapshot_path = format!("/proc/self/fd/{}", snapshot.as_raw_fd());
    let executable =
        open(snapshot_path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).map_err(|error| {
            FrameworkAdapterError::CapabilityDenied(format!(
                "managed sealed executable snapshot reopen failed: {error}"
            ))
        })?;
    Ok(executable.into())
}

#[cfg(target_os = "linux")]
fn configure_managed_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(target_os = "linux"))]
fn configure_managed_process_group(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn kill_process_group(raw_pid: u32) {
    let Ok(raw_pid) = i32::try_from(raw_pid) else {
        return;
    };
    let Some(pid) = rustix::process::Pid::from_raw(raw_pid) else {
        return;
    };
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
}

#[cfg(not(target_os = "linux"))]
fn kill_process_group(_raw_pid: u32) {}

fn kill_and_reap_process_group(child: &mut Child) {
    kill_process_group(child.id());
    let _ = child.wait();
}

#[cfg(not(target_os = "linux"))]
fn open_authorized_cli_objects(
    _decision: &ExternalActionGateDecision,
) -> Result<AuthorizedCliObjects, FrameworkAdapterError> {
    Err(FrameworkAdapterError::CapabilityDenied(
        "race-resistant managed CLI execution requires Linux descriptor binding".to_string(),
    ))
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

#[derive(Debug)]
struct GovernedRestExecution {
    status_code: u16,
    response_excerpt: String,
}

/// The action-describing half of a governed REST event's metadata, shared by the
/// success and the dispatch-failure events so a consumer sees the same shape
/// either way.
fn rest_action_metadata(action: &ManagedRestAction) -> BTreeMap<String, String> {
    recorded_metadata([
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
    ])
}

impl GovernedRestExecution {
    fn metadata(self, action: &ManagedRestAction) -> BTreeMap<String, String> {
        let mut metadata = rest_action_metadata(action);
        metadata.extend([
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
            ("dispatch_outcome".to_string(), "completed".to_string()),
            ("status_code".to_string(), self.status_code.to_string()),
            ("response_excerpt".to_string(), self.response_excerpt),
        ]);
        // A completed dispatch reached the upstream by definition, so the key is
        // present on the success path too. A consumer therefore never has to
        // distinguish "absent because it succeeded" from "absent because the
        // producer predates the key" — and if it ever did, the absent case reads
        // as retain anyway.
        RequestWireStage::SentOrUnknown.write_event_metadata(&mut metadata);
        // This map is assembled by `extend` rather than from one literal list,
        // so it does not go through `recorded_metadata`; sweep it here instead
        // of trusting that every future key was excerpted correctly.
        redact_recorded_values(metadata.values_mut());
        metadata
    }
}

/// HTTP status an x402 merchant returns to demand payment.
const STATUS_PAYMENT_REQUIRED: u16 = 402;

/// A failed REST dispatch, carrying the one fact only the worker can observe:
/// how far the outgoing request got on the wire (#353).
///
/// Before this type existed, every failure below collapsed into one opaque
/// `FrameworkAdapterError`. That is harmless while the worker sends no payment
/// proof, and becomes a money-safety defect the moment the #381 transport
/// binding attaches a `PAYMENT-SIGNATURE` to this very function: "the connection
/// was refused" (nothing was sent — the hold is safe to release) and "the read
/// timed out after the request was fully written" (the proof may have settled —
/// the hold must be retained) would be indistinguishable, and the gateway would
/// take the RELEASE edge on a payment that may already have moved on-chain.
#[derive(Debug)]
struct RestDispatchFailure {
    stage: RequestWireStage,
    error: FrameworkAdapterError,
}

impl RestDispatchFailure {
    /// Classify a failure that is PROVEN to have happened before any request
    /// byte could reach the peer. Only connection/validation/socket-setup
    /// failures qualify; a write that may have partially landed does not.
    fn proven_not_sent(error: FrameworkAdapterError) -> Self {
        Self {
            stage: RequestWireStage::ProvenNotSent,
            error,
        }
    }

    /// Collapse back to the shared adapter error, carrying the wire stage into
    /// the operator-facing message.
    ///
    /// This is DIAGNOSTICS, and only diagnostics. It matters for any REST
    /// failure, not just a paid one — "did my request actually reach the
    /// upstream?" is the first question after a failed side effect — but nothing
    /// may branch on the sentence. The machine-readable carrier is
    /// [`GovernedRestRejection`], which puts the same classification on the
    /// event's metadata as a frozen token
    /// ([`ferrogate_runtime::EGRESS_REQUEST_WIRE_STAGE_KEY`]). That separation is
    /// the point: the gateway's durable attempt API may only take its RELEASE
    /// edge (`X402SettlementLoop::cancel`) on a proven-unsent dispatch, and that
    /// decision must survive a reword of this string.
    fn into_error(self) -> FrameworkAdapterError {
        let reached = match self.stage.hold_disposition() {
            HoldDisposition::ReleasableBeforeSubmission => "no request byte reached the upstream",
            HoldDisposition::RetainOutcomeUnknown => "the request may have reached the upstream",
        };
        let annotate = |message: String| format!("{message} ({reached})");
        match self.error {
            FrameworkAdapterError::InvalidDescriptor(message) => {
                FrameworkAdapterError::InvalidDescriptor(annotate(message))
            }
            FrameworkAdapterError::InvalidRequest(message) => {
                FrameworkAdapterError::InvalidRequest(annotate(message))
            }
            FrameworkAdapterError::CapabilityDenied(message) => {
                FrameworkAdapterError::CapabilityDenied(annotate(message))
            }
        }
    }
}

/// A governed REST action that did not produce a response, delivered as TYPED
/// evidence rather than as prose (#353).
///
/// [`RestDispatchFailure::into_error`] annotates the operator-facing message
/// with how far the request got, which is the right thing for a human reading a
/// log. It is the wrong thing for the gateway: taking the durable attempt API's
/// RELEASE edge off a substring match would mean a reword of that sentence
/// silently flips every hold to the wrong edge, on a money decision.
///
/// So the rejection carries the classification three ways, and only one of them
/// is meant to be consumed:
///
/// * [`Self::wire_stage`] — the typed discriminant, in the shared
///   `ferrogate-runtime` vocabulary both processes can name.
/// * [`Self::event`] — the same discriminant written into worker event metadata
///   under [`ferrogate_runtime::EGRESS_REQUEST_WIRE_STAGE_KEY`], which is the
///   map that actually crosses the process boundary. **This is what a #381
///   consumer reads**, via [`RequestWireStage::from_event_metadata`].
/// * [`Self::error`] — human diagnostics, explicitly NOT load-bearing.
pub(crate) struct GovernedRestRejection {
    /// How far the request got. `SentOrUnknown` unless proven otherwise.
    pub(crate) wire_stage: RequestWireStage,
    /// The worker event carrying the typed classification as metadata. Boxed so
    /// the `Err` variant of every governed REST result stays small.
    pub(crate) event: Box<NormalizedFrameworkEvent>,
    /// The operator-facing failure, prose annotation included.
    pub(crate) error: FrameworkAdapterError,
}

impl GovernedRestRejection {
    /// The gateway-vocabulary verdict for the wallet hold. Derived from the
    /// typed stage; never from the message.
    pub(crate) fn hold_disposition(&self) -> HoldDisposition {
        self.wire_stage.hold_disposition()
    }

    /// Refusal by the gateway capability gate: no socket was ever opened, so the
    /// request is provably unsent. No prose annotation is added — the gate's own
    /// denial message already says exactly what happened, and annotating it with
    /// wire-stage language would be noise.
    fn gate_refused(
        session: &FrameworkAdapterSession,
        action: &ManagedRestAction,
        error: FrameworkAdapterError,
    ) -> Self {
        Self::build(
            session,
            action,
            RequestWireStage::ProvenNotSent,
            false,
            error,
        )
    }

    /// A dispatch that was authorized and then failed. The stage is whatever the
    /// dispatch proved, defaulting to retain.
    fn dispatch_failed(
        session: &FrameworkAdapterSession,
        action: &ManagedRestAction,
        failure: RestDispatchFailure,
    ) -> Self {
        let wire_stage = failure.stage;
        Self::build(session, action, wire_stage, true, failure.into_error())
    }

    fn build(
        session: &FrameworkAdapterSession,
        action: &ManagedRestAction,
        wire_stage: RequestWireStage,
        executed_after_authorization: bool,
        error: FrameworkAdapterError,
    ) -> Self {
        let mut metadata = rest_action_metadata(action);
        metadata.extend([
            (
                "executed_after_authorization".to_string(),
                executed_after_authorization.to_string(),
            ),
            ("dispatch_outcome".to_string(), "failed".to_string()),
            // Prose, recorded for humans. Deliberately alongside the typed keys
            // rather than instead of them.
            ("failure_reason".to_string(), error.to_string()),
        ]);
        // The typed discriminant + its derived hold disposition. Written last so
        // it cannot be shadowed by an action-derived key.
        wire_stage.write_event_metadata(&mut metadata);
        // `failure_reason` is an error string built over data the upstream
        // controlled; sweep it like every other recorded value.
        redact_recorded_values(metadata.values_mut());
        Self {
            wire_stage,
            event: Box::new(NormalizedFrameworkEvent {
                session_id: session.session_id.clone(),
                run_id: session.run_id.clone(),
                adapter_name: session.adapter_name.clone(),
                adapter_version: session.adapter_version.clone(),
                framework: session.framework,
                mode: session.mode,
                kind: FrameworkAdapterEventKind::RestRequested,
                message: Some(
                    "managed REST action did not complete after gateway authorization".to_string(),
                ),
                metadata,
            }),
            error,
        }
    }
}

impl std::fmt::Debug for GovernedRestRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernedRestRejection")
            .field("wire_stage", &self.wire_stage)
            .field("hold_disposition", &self.hold_disposition())
            .field("error", &self.error)
            .finish()
    }
}

impl std::fmt::Display for GovernedRestRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for GovernedRestRejection {}

/// Fail-safe classification: anything converted implicitly — every `?` on a
/// bare [`FrameworkAdapterError`] in the dispatch below — lands on
/// [`RequestWireStage`]'s default, which is `SentOrUnknown` ⇒ retain the hold.
/// Forgetting to classify a new failure path is therefore safe by construction;
/// only an explicit [`RestDispatchFailure::proven_not_sent`] can ever authorize
/// a release.
impl From<FrameworkAdapterError> for RestDispatchFailure {
    fn from(error: FrameworkAdapterError) -> Self {
        Self {
            stage: RequestWireStage::default(),
            error,
        }
    }
}

/// Dispatch one already-authorized managed REST action.
///
/// Scope, stated plainly so it is not overclaimed again (#353): this is a
/// LOOPBACK SMOKE executor. The three guards below — `GET` only,
/// `parse_local_http_url`'s `http://`-only rule, and its loopback-only rule —
/// mean it can never talk to a public HTTPS host, and its only non-test caller
/// (`governed_rest_execution_smoke_command`) points a hardcoded action at a
/// listener it spawns itself. The `402` branch is therefore correct behaviour
/// that is unreachable in the shipped binary; live x402 detection needs an
/// egress executor that does not yet exist in this crate.
///
/// The redaction and the wire-stage classification are NOT scoped that way: they
/// are properties of "a dispatch failed" and "a response was recorded", and
/// transfer to whatever real executor eventually lands.
fn run_authorized_rest_action(
    action: &ManagedRestAction,
) -> Result<GovernedRestExecution, RestDispatchFailure> {
    if action.method != "GET" {
        return Err(RestDispatchFailure::proven_not_sent(
            FrameworkAdapterError::InvalidRequest(
                "managed REST smoke currently supports GET only".to_string(),
            ),
        ));
    }
    let target = parse_local_http_url(&action.url).map_err(RestDispatchFailure::proven_not_sent)?;
    let pinned_ip =
        required_pinned_ip(&action.resolved_ips).map_err(RestDispatchFailure::proven_not_sent)?;
    if pinned_ip != target.endpoint.ip() {
        return Err(RestDispatchFailure::proven_not_sent(
            FrameworkAdapterError::CapabilityDenied(
                "managed REST execution endpoint differs from the authorized pinned IP".to_string(),
            ),
        ));
    }
    let timeout = Duration::from_millis(action.timeout_millis.max(1));
    // Connection and socket setup: proven pre-send, so a failure here is the
    // one case where the gateway may safely release a hold.
    let mut stream = TcpStream::connect_timeout(&target.endpoint, timeout).map_err(|error| {
        RestDispatchFailure::proven_not_sent(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action transport failed after gateway authorization: {error}"
        )))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        RestDispatchFailure::proven_not_sent(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action read timeout setup failed: {error}"
        )))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        RestDispatchFailure::proven_not_sent(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action write timeout setup failed: {error}"
        )))
    })?;
    let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
        target.path, target.endpoint
    );
    // From here on nothing is provably unsent. `write_all` can fail having
    // already delivered part of the request, and everything after it happens
    // with the full request on the wire, so all of these take the fail-safe
    // `SentOrUnknown` classification via `From`.
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
    if status_code == STATUS_PAYMENT_REQUIRED {
        return Err(payment_required_failure(action, &response).into());
    }
    if !(200..300).contains(&status_code) {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action returned status {status_code}"
        ))
        .into());
    }
    Ok(GovernedRestExecution {
        status_code,
        // Redact BEFORE truncating: a 512-char prefix of an unredacted response
        // would otherwise carry a usable prefix of a bearer credential.
        response_excerpt: recorded_http_excerpt(&response, 512),
    })
}

/// Turn a merchant `402` into a typed, fail-closed refusal that names the
/// challenge — the worker's non-custodial `402` detection (#353).
///
/// The worker does not pay, does not select what it is willing to pay, and does
/// not ask anyone to sign. It validates the challenge against the frozen wire
/// contract, proves the challenge is not redirecting payment away from the
/// egress URL FerroGate authorized, and reports the public evidence (challenge
/// hash, network, atomic amount, recipient) so the gateway can decide. Every
/// failure mode — a missing header, an unparseable challenge, a redirected
/// resource — is a refusal, never a payment.
fn payment_required_failure(action: &ManagedRestAction, response: &str) -> FrameworkAdapterError {
    let Some(header) = response_header_value(response, HEADER_PAYMENT_REQUIRED) else {
        return FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action returned status {STATUS_PAYMENT_REQUIRED} without a \
             {HEADER_PAYMENT_REQUIRED} challenge header; nothing was paid"
        ));
    };
    let request = AuthorizedRequest::new(action.method.clone(), action.url.clone());
    match detect_payment_required(header, request) {
        Ok(challenge) => FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action requires an x402 payment the worker will not self-authorize \
             (challenge {} on {} for {} atomic units to {}); the spend decision belongs to the \
             gateway",
            challenge.challenge_hash_hex,
            challenge.network_caip2,
            challenge.atomic_amount,
            challenge.recipient
        )),
        Err(error) => FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action returned an x402 challenge that failed closed: {error}"
        )),
    }
}

/// Read a single header value out of a raw HTTP response, case-insensitively.
/// Stops at the header/body separator so a body line can never be mistaken for
/// a header.
fn response_header_value<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    for line in response.lines().skip(1) {
        if line.trim_end_matches('\r').is_empty() {
            return None;
        }
        let Some((header, value)) = line.split_once(':') else {
            continue;
        };
        if header.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn required_pinned_ip(values: &[String]) -> Result<std::net::IpAddr, FrameworkAdapterError> {
    let [value] = values else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed network execution requires exactly one authorization-pinned IP".to_string(),
        ));
    };
    value.parse().map_err(|_| {
        FrameworkAdapterError::CapabilityDenied(
            "managed network execution received an invalid authorization-pinned IP".to_string(),
        )
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

/// Report-only self-hosted execution for the governed external-action families
/// (#245, extending the #242 CLI first slice).
///
/// Under self-hosted the workload ALWAYS runs and the gateway decision cloud
/// would have made is recorded as report-only telemetry; under cloud a
/// non-`Allowed` decision blocks the workload before it runs. Both anchor on the
/// same managed-probe capability decision via `run_governed_workload`.
///
/// Routed here: tool, MCP tool, skill, browser, memory, and secret (decoupled
/// from the ALLOW decision's canonical-target fingerprint), plus network-egress
/// and REST (#247 — real loopback outbound I/O against the pinned loopback
/// endpoint the action carries; the report-only path performs the I/O and
/// records the decision, cloud blocks before any I/O). CLI/filesystem stay on
/// their dedicated paths (CLI report-only is the #242 local-process slice;
/// filesystem remains fail-closed).
pub(crate) fn run_governed_family_report_only<A>(
    mode: FrameworkAdapterMode,
    session: &FrameworkAdapterSession,
    authorizer: &A,
    action: ManagedExternalAction,
    high_risk: bool,
    server_clock_unix_millis: u64,
) -> Result<GovernedWorkloadExecution, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let workload_action = action.clone();
    run_governed_workload(
        mode,
        session,
        authorizer,
        action,
        high_risk,
        server_clock_unix_millis,
        move || run_authorized_family_workload(&workload_action),
    )
}

/// Run the in-process governed workload for a decoupled external-action family.
/// This is the side effect `run_governed_workload` runs once the enforce-vs-report
/// decision has been made; it reuses the same `run_authorized_*_action` handlers
/// the enforced cloud path uses.
fn run_authorized_family_workload(
    action: &ManagedExternalAction,
) -> Result<GovernedWorkloadOutcome, FrameworkAdapterError> {
    let (output, backend_name) = match action {
        ManagedExternalAction::Tool(action) => (
            run_authorized_tool_action(action)?.output_excerpt,
            "governed-tool-handler",
        ),
        ManagedExternalAction::McpTool(action) => (
            run_authorized_mcp_tool_action(action)?.output_excerpt,
            "governed-mcp-tool-handler",
        ),
        ManagedExternalAction::Skill(action) => (
            run_authorized_skill_action(action)?.output_excerpt,
            "governed-skill-handler",
        ),
        ManagedExternalAction::Browser(action) => (
            run_authorized_browser_action(action)?.page_state,
            "governed-browser-handler",
        ),
        ManagedExternalAction::Memory(action) => {
            let mut store = BTreeMap::new();
            let execution = run_authorized_memory_action(action, &mut store)?;
            (execution.value_excerpt, "governed-memory-handler")
        }
        ManagedExternalAction::Secret(action) => {
            let secrets = BTreeMap::from([(
                action.secret_id.clone(),
                "ferrogate governed secret report-only smoke".to_string(),
            )]);
            let execution = run_authorized_secret_action(action, &secrets)?;
            (
                format!("secret_len={}", execution.secret_len),
                "governed-secret-handler",
            )
        }
        // #247: network-egress + REST perform real loopback outbound I/O. Under
        // self-hosted report-only the I/O still happens (against the pinned
        // loopback endpoint the action carries); under cloud the enforce path
        // blocks before this side effect ever runs, so no I/O occurs.
        ManagedExternalAction::NetworkEgress(action) => {
            let execution = run_authorized_network_egress_action(action)?;
            (
                format!("bytes_written={}", execution.bytes_written),
                "governed-network-egress-handler",
            )
        }
        ManagedExternalAction::Rest(action) => {
            let execution =
                run_authorized_rest_action(action).map_err(RestDispatchFailure::into_error)?;
            (
                format!(
                    "status_code={} response_excerpt={}",
                    execution.status_code, execution.response_excerpt
                ),
                "governed-rest-handler",
            )
        }
        ManagedExternalAction::Cli(_) | ManagedExternalAction::Filesystem(_) => {
            return Err(FrameworkAdapterError::InvalidRequest(
                "cli/filesystem report-only self-hosted execution is not routed through the \
                 in-process governed family workload: their authorized execution is bound to the \
                 ALLOW decision's canonical-target fingerprint. CLI report-only is delivered by \
                 the #242 self-hosted-governed-execution-smoke (local-process backend); filesystem \
                 remains fail-closed (TODO(#245))."
                    .to_string(),
            ));
        }
    };
    Ok(GovernedWorkloadOutcome {
        exit_code: Some(0),
        output,
        backend_name: backend_name.to_string(),
        containment_summary:
            "gateway-governed in-process handler workload (report-only under self-hosted)"
                .to_string(),
    })
}

/// Print report-only self-hosted evidence for a governed family smoke, mirroring
/// the #242 `self-hosted-governed-execution-smoke`: a DENY policy (cloud would
/// block) that still runs the workload and records it as report-only.
fn self_hosted_family_report_only_smoke(action: ManagedExternalAction) -> Result<()> {
    let authorizer = deny_all_report_only_authorizer();
    let execution = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &authorizer,
        action,
        false,
        crate::management::current_unix_millis(),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&execution.evidence_json())?
    );
    Ok(())
}

/// A DENY-everything authorizer: cloud would block, self-hosted records
/// report-only. Shared by the family report-only smokes (#245/#247).
fn deny_all_report_only_authorizer(
) -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::new(),
        class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

/// Report-only self-hosted smoke for the network-egress/REST families (#247).
///
/// These families perform real loopback outbound I/O, so the workload MUST run
/// before the one-shot loopback server thread is joined (the server blocks on
/// `accept()` until the workload connects). Unlike the in-process families, the
/// server is stood up by the caller and joined here after the report-only run.
fn self_hosted_network_or_rest_report_only_smoke(
    action: ManagedExternalAction,
    served_label: &str,
    join_server: impl FnOnce() -> Result<String>,
) -> Result<()> {
    let authorizer = deny_all_report_only_authorizer();
    let execution = run_governed_family_report_only(
        FrameworkAdapterMode::SelfHosted,
        &smoke_session(FrameworkAdapterMode::SelfHosted),
        &authorizer,
        action,
        false,
        crate::management::current_unix_millis(),
    )?;
    // The workload has now performed the loopback I/O; the server has a payload.
    let served = join_server()?;
    let output = serde_json::json!({
        "evidence": execution.evidence_json(),
        served_label: served,
    });
    println!("{}", serde_json::to_string(&output)?);
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                    resolved_ips: Vec::new(),
                    redirect_chain: Vec::new(),
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
                    arguments: serde_json::json!({}),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                arguments: serde_json::json!({"message": "mcp smoke ok"}),
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
                arguments: serde_json::json!({}),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        ));
        let secrets = BTreeMap::from([(
            "vault/openai-api-key".to_string(),
            "ferrogate governed secret smoke".to_string(),
        )]);

        let events = execute_governed_secret_action(
            &gate,
            session(),
            ManagedSecretAction {
                secret_id: "vault/openai-api-key".to_string(),
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
        let expected_secret_fingerprint = opaque_reference_fingerprint("vault/openai-api-key");
        assert_eq!(
            events[1]
                .metadata
                .get("secret_ref_fingerprint")
                .map(String::as_str),
            Some(expected_secret_fingerprint.as_str())
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                resolved_ips: vec!["127.0.0.1".to_string()],
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
                resolved_ips: Vec::new(),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                resolved_ips: Vec::new(),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                resolved_ips: vec!["127.0.0.1".to_string()],
                redirect_chain: Vec::new(),
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
                resolved_ips: Vec::new(),
                redirect_chain: Vec::new(),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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

        assert!(error
            .to_string()
            .contains("cannot derive a canonical execution target"));
    }

    #[test]
    fn self_hosted_sessions_do_not_use_managed_enforcement_gate() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
            let expected_target = if expected_action == "secret" {
                format!(
                    "secret:{}",
                    opaque_reference_fingerprint("vault/openai-api-key")
                )
            } else {
                expected_target.to_string()
            };
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.action = ExternalActionSpec::NetworkEgress {
            host: "api.example.test".to_string(),
            port: 443,
            protocol: "https".to_string(),
            resolved_ips: Vec::new(),
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
                        class_only_policy_mode:
                            ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                        ..CapabilityPolicy::default()
                    },
                )),
                1,
            )
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new_authenticated(
            &socket_path,
            std::process::id(),
        );

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
        let client = UnixGatewayExternalActionAuthorizer::new_authenticated(
            &socket_path,
            std::process::id(),
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
        let client = UnixGatewayExternalActionAuthorizer::new_authenticated(
            &socket_path,
            std::process::id(),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                arguments: serde_json::json!({}),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
                resolved_ips: Vec::new(),
                redirect_chain: Vec::new(),
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
                resolved_ips: Vec::new(),
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
                    arguments: serde_json::json!({}),
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
                    resolved_ips: Vec::new(),
                    redirect_chain: Vec::new(),
                },
                "rest",
                "POST https://api.example.test/v1/jobs",
            ),
            (
                ExternalActionSpec::Secret {
                    secret_id: "vault/openai-api-key".to_string(),
                    purpose: "provider_call".to_string(),
                },
                "secret",
                "secret:vault/openai-api-key",
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
                    resolved_ips: Vec::new(),
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
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
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
#[path = "external_actions_self_hosted_family_test.rs"]
mod self_hosted_family_test;

#[cfg(test)]
#[path = "external_actions_worker_type_test.rs"]
mod external_actions_worker_type_test;

#[cfg(test)]
#[path = "external_actions_target_test.rs"]
mod external_actions_target_test;

#[cfg(test)]
#[path = "external_actions_x402_test.rs"]
mod external_actions_x402_test;

#[cfg(test)]
#[path = "external_actions_recorded_evidence_test.rs"]
mod external_actions_recorded_evidence_test;
