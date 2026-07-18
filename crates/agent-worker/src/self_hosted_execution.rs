// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Report-only self-hosted worker execution (issue #242).
//!
//! Cloud (FerroGate-managed) and self-hosted (customer-operated) workers share
//! one `agent-worker` binary and one capability boundary. The only difference is
//! the ENFORCEMENT POLICY on a capability decision:
//!
//! - **cloud / managed** — `execution_owner: ferrogate`,
//!   `enforcement_boundary: ferrogate_managed_runtime`. The gateway capability
//!   decision is ENFORCED: a non-`Allowed` decision BLOCKS the workload
//!   (`FrameworkAdapterError::CapabilityDenied`) and nothing runs.
//! - **self-hosted** — `execution_owner: customer`,
//!   `enforcement_boundary: customer_owned_host`. FerroGate does not own the
//!   host, so it cannot hard-enforce there. The same gateway decision is
//!   OBSERVED and RECORDED as report-only telemetry
//!   (`trust_level: reported_by_self_hosted_worker`) and the workload runs
//!   REGARDLESS through the local-process isolation backend. A capability that
//!   cloud would BLOCK is therefore `allowed-but-recorded`, never blocked.
//!
//! Both modes anchor on the SAME gateway capability decision (computed against a
//! managed probe session), so the report-only record faithfully states what
//! cloud WOULD have decided. Self-hosted worker identity expiry is stamped by
//! the server clock (the customer host is not trusted to set it), matching the
//! `identity_expiry_clock: server` contract surfaced by the `worker-type`
//! diagnostic.

use ferrogate_runtime::{
    CapabilityAuthorizationDecision, FrameworkAdapterError, FrameworkAdapterMode,
    FrameworkAdapterSession, IsolationBackendLifecycle, IsolationExecRequest, IsolationPolicy,
    IsolationPrepareRequest, ManagedCliAction, ManagedExternalAction,
    SelfHostedTelemetryTrustLevel, SupportedFramework,
};

use crate::{
    external_actions::{
        request_handler_external_action_decision, ExternalActionGateRequest,
        GatewayExternalActionAuthorizer,
    },
    local_process_backend::{local_process_backend_readiness, LocalProcessIsolationBackend},
};

/// The customer owns the self-hosted host, so this is where enforcement lives.
pub(crate) const SELF_HOSTED_ENFORCEMENT_BOUNDARY: &str = "customer_owned_host";
/// FerroGate owns the managed runtime, so it enforces at the runtime boundary.
pub(crate) const CLOUD_ENFORCEMENT_BOUNDARY: &str = "ferrogate_managed_runtime";
pub(crate) const SELF_HOSTED_EXECUTION_OWNER: &str = "customer";
pub(crate) const CLOUD_EXECUTION_OWNER: &str = "ferrogate";
/// The self-hosted trust level string as it appears in report-only evidence.
pub(crate) const REPORTED_BY_SELF_HOSTED_WORKER: &str = "reported_by_self_hosted_worker";
/// Server-clock-stamped identity lifetime for a self-hosted report-only run.
pub(crate) const SELF_HOSTED_IDENTITY_TTL_MILLIS: u64 = 15 * 60 * 1000;

/// How a governed capability decision was handled for a workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GovernedCapabilityDisposition {
    /// Cloud/managed: the gateway decision is enforced. A non-`Allowed`
    /// decision blocks the workload and this disposition is never produced for
    /// a run that executed on a denial.
    Enforced {
        decision: CapabilityAuthorizationDecision,
    },
    /// Self-hosted: the gateway decision is recorded but NOT enforced. The
    /// workload runs regardless; the decision is only telemetry.
    ReportOnly {
        recorded_decision: CapabilityAuthorizationDecision,
        trust_level: SelfHostedTelemetryTrustLevel,
    },
}

pub(crate) fn decision_label(decision: CapabilityAuthorizationDecision) -> &'static str {
    match decision {
        CapabilityAuthorizationDecision::Allowed => "allowed",
        CapabilityAuthorizationDecision::Denied => "denied",
        CapabilityAuthorizationDecision::ApprovalRequired => "approval_required",
    }
}

/// One governed workload execution and the capability evidence it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GovernedWorkloadExecution {
    pub(crate) mode: FrameworkAdapterMode,
    pub(crate) capability_action: &'static str,
    pub(crate) target: String,
    pub(crate) disposition: GovernedCapabilityDisposition,
    pub(crate) enforcement_boundary: &'static str,
    pub(crate) execution_owner: &'static str,
    pub(crate) identity_expiry_unix_millis: u64,
    pub(crate) workload_ran: bool,
    pub(crate) workload_exit_code: Option<i32>,
    pub(crate) workload_output: String,
    pub(crate) backend_name: String,
    pub(crate) containment_summary: String,
}

impl GovernedWorkloadExecution {
    /// `true` when the recorded gateway decision would have BLOCKED this
    /// workload under cloud enforcement. For a self-hosted run this is exactly
    /// the "allowed-but-recorded" case: the capability was exercised anyway and
    /// only reported.
    pub(crate) fn cloud_would_block(&self) -> bool {
        match &self.disposition {
            GovernedCapabilityDisposition::Enforced { decision }
            | GovernedCapabilityDisposition::ReportOnly {
                recorded_decision: decision,
                ..
            } => *decision != CapabilityAuthorizationDecision::Allowed,
        }
    }

    pub(crate) fn recorded_decision(&self) -> CapabilityAuthorizationDecision {
        match &self.disposition {
            GovernedCapabilityDisposition::Enforced { decision }
            | GovernedCapabilityDisposition::ReportOnly {
                recorded_decision: decision,
                ..
            } => *decision,
        }
    }

    pub(crate) fn report_only(&self) -> bool {
        matches!(
            self.disposition,
            GovernedCapabilityDisposition::ReportOnly { .. }
        )
    }

    pub(crate) fn evidence_json(&self) -> serde_json::Value {
        let trust_level = match &self.disposition {
            GovernedCapabilityDisposition::ReportOnly { .. } => REPORTED_BY_SELF_HOSTED_WORKER,
            GovernedCapabilityDisposition::Enforced { .. } => "enforced_by_gateway",
        };
        serde_json::json!({
            "process": "agent-worker",
            "worker_type": worker_type_label(self.mode),
            "capability_enforcement": match self.mode {
                FrameworkAdapterMode::Managed => "enforced",
                FrameworkAdapterMode::SelfHosted => "reported",
            },
            "enforcement_boundary": self.enforcement_boundary,
            "execution_owner": self.execution_owner,
            "capability_action": self.capability_action,
            "capability_target": self.target,
            "recorded_decision": decision_label(self.recorded_decision()),
            "cloud_would_block": self.cloud_would_block(),
            "report_only": self.report_only(),
            "trust_level": trust_level,
            "identity_expiry_clock": "server",
            "identity_expiry_unix_millis": self.identity_expiry_unix_millis,
            "workload_ran": self.workload_ran,
            "workload_exit_code": self.workload_exit_code,
            "workload_output": self.workload_output,
            "isolation_backend": self.backend_name,
            "containment": self.containment_summary,
        })
    }
}

fn worker_type_label(mode: FrameworkAdapterMode) -> &'static str {
    match mode {
        FrameworkAdapterMode::Managed => "cloud",
        FrameworkAdapterMode::SelfHosted => "self-hosted",
    }
}

/// Server-clock-stamped self-hosted identity expiry. The customer host is not
/// trusted to set its own identity lifetime, so FerroGate stamps it.
pub(crate) fn self_hosted_identity_expiry(server_clock_unix_millis: u64) -> u64 {
    server_clock_unix_millis.saturating_add(SELF_HOSTED_IDENTITY_TTL_MILLIS)
}

/// Compute the gateway capability decision cloud WOULD make for this action.
///
/// The decision is always computed against a MANAGED probe session (the gate
/// only speaks managed sessions), so the self-hosted report-only record can
/// faithfully state what cloud enforcement would have decided. A non-`Allowed`
/// decision is returned as data here, never as an error — the caller's mode
/// decides whether to enforce it.
fn authorize_governed_capability<A>(
    authorizer: &A,
    session: &FrameworkAdapterSession,
    action: &ManagedCliAction,
    high_risk: bool,
) -> Result<CapabilityAuthorizationDecision, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let mut managed_probe = session.clone();
    managed_probe.mode = FrameworkAdapterMode::Managed;
    let decision = request_handler_external_action_decision(
        Some(authorizer),
        ExternalActionGateRequest {
            session: managed_probe,
            action: ManagedExternalAction::Cli(action.clone()),
            high_risk,
        },
    )?;
    Ok(decision.decision)
}

/// Run one workload fully confined through the worker-owned local-process
/// isolation backend (landed for #205). Re-probes host readiness and fails
/// closed if the unprivileged namespace stack is unavailable.
fn run_workload_through_local_process(
    session: &FrameworkAdapterSession,
    command: &ManagedCliAction,
) -> Result<LocalProcessWorkloadOutcome, FrameworkAdapterError> {
    let readiness = local_process_backend_readiness().map_err(|reason| {
        FrameworkAdapterError::InvalidRequest(format!(
            "self-hosted report-only execution refused (fail closed): local-process backend \
             unavailable: {reason}"
        ))
    })?;
    let mut backend = LocalProcessIsolationBackend::new(&session.worker_id, &readiness);
    let prepared = backend
        .prepare(IsolationPrepareRequest {
            session_id: session.session_id.clone(),
            run_id: session.run_id.clone(),
            worker_template_id: session.worker_id.clone(),
            framework_adapter: session.adapter_name.clone(),
            capability_envelope_id: format!(
                "cap:self-hosted:{}:{}",
                session.session_id, session.run_id
            ),
            policy: IsolationPolicy::default(),
        })
        .map_err(local_process_error)?;
    let backend_name = backend.backend_descriptor().backend_name.clone();
    let started = backend.start(prepared).map_err(local_process_error)?;
    let containment_summary = backend.containment_summary();
    let mut workload_args = vec![command.command.clone()];
    workload_args.extend(command.args.clone());
    let exec = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: started.instance_id.clone(),
            workload_ref: "agent://self-hosted/report-only".to_string(),
            args: workload_args,
        })
        .map_err(local_process_error)?;
    // Always clean up the workspace, even if exec produced a non-zero code.
    backend
        .cleanup(&started.instance_id)
        .map_err(local_process_error)?;
    Ok(LocalProcessWorkloadOutcome {
        exit_code: exec.exit_code,
        output: exec.message,
        backend_name,
        containment_summary,
    })
}

fn local_process_error(error: ferrogate_runtime::IsolationError) -> FrameworkAdapterError {
    FrameworkAdapterError::InvalidRequest(format!(
        "self-hosted local-process workload failed: {error}"
    ))
}

struct LocalProcessWorkloadOutcome {
    exit_code: Option<i32>,
    output: String,
    backend_name: String,
    containment_summary: String,
}

/// Run a governed CLI workload under the given worker mode.
///
/// - `Managed` (cloud): ENFORCE. A non-`Allowed` gateway decision returns
///   `CapabilityDenied` and the workload never runs.
/// - `SelfHosted`: REPORT-ONLY. The gateway decision is recorded but never
///   enforced; the workload runs through the local-process backend regardless,
///   and a capability cloud would block becomes allowed-but-recorded.
pub(crate) fn run_governed_cli_workload<A>(
    mode: FrameworkAdapterMode,
    session: &FrameworkAdapterSession,
    authorizer: &A,
    action: ManagedCliAction,
    high_risk: bool,
    server_clock_unix_millis: u64,
) -> Result<GovernedWorkloadExecution, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_governed_capability(authorizer, session, &action, high_risk)?;
    let target = format!("cli:{}", action.command);
    match mode {
        FrameworkAdapterMode::Managed => {
            // Cloud enforces: a non-allow decision blocks before any host work.
            if decision != CapabilityAuthorizationDecision::Allowed {
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "cloud (managed) worker blocks capability action=cli target={target} \
                     decision={}: enforcement_boundary={CLOUD_ENFORCEMENT_BOUNDARY}",
                    decision_label(decision)
                )));
            }
            let workload = run_workload_through_local_process(session, &action)?;
            Ok(GovernedWorkloadExecution {
                mode,
                capability_action: "cli",
                target,
                disposition: GovernedCapabilityDisposition::Enforced { decision },
                enforcement_boundary: CLOUD_ENFORCEMENT_BOUNDARY,
                execution_owner: CLOUD_EXECUTION_OWNER,
                // Managed identity expiry is owned by the managed runtime, not
                // the self-hosted server-clock stamp.
                identity_expiry_unix_millis: 0,
                workload_ran: true,
                workload_exit_code: workload.exit_code,
                workload_output: workload.output,
                backend_name: workload.backend_name,
                containment_summary: workload.containment_summary,
            })
        }
        FrameworkAdapterMode::SelfHosted => {
            // Self-hosted observes and reports: the workload runs regardless of
            // the decision; the decision is telemetry only.
            let workload = run_workload_through_local_process(session, &action)?;
            Ok(GovernedWorkloadExecution {
                mode,
                capability_action: "cli",
                target,
                disposition: GovernedCapabilityDisposition::ReportOnly {
                    recorded_decision: decision,
                    trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
                },
                enforcement_boundary: SELF_HOSTED_ENFORCEMENT_BOUNDARY,
                execution_owner: SELF_HOSTED_EXECUTION_OWNER,
                identity_expiry_unix_millis: self_hosted_identity_expiry(server_clock_unix_millis),
                workload_ran: true,
                workload_exit_code: workload.exit_code,
                workload_output: workload.output,
                backend_name: workload.backend_name,
                containment_summary: workload.containment_summary,
            })
        }
    }
}

/// Deterministic session identity for the self-hosted report-only smoke.
fn self_hosted_smoke_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "agent-worker-self-hosted-report-only-session".to_string(),
        run_id: "agent-worker-self-hosted-report-only-run".to_string(),
        tenant_id: "self-hosted-tenant".to_string(),
        workspace_id: "self-hosted-workspace".to_string(),
        worker_id: "agent-worker-self-hosted".to_string(),
        isolation_backend: "local-process".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::SelfHosted,
    }
}

/// A compact, single-line report-only capability marker for embedding in
/// management lifecycle evidence. Used by the self-hosted management-serving
/// path so a self-hosted `exec_or_attach` emits report-only capability evidence
/// alongside the workload it ran through the local-process backend.
pub(crate) fn self_hosted_report_only_exec_marker(
    capability_action: &str,
    target: &str,
    server_clock_unix_millis: u64,
) -> String {
    format!(
        "report_only_capability[enforcement_boundary={SELF_HOSTED_ENFORCEMENT_BOUNDARY} \
         execution_owner={SELF_HOSTED_EXECUTION_OWNER} trust_level={REPORTED_BY_SELF_HOSTED_WORKER} \
         action={capability_action} target={target} \
         decision=reported_without_gateway_enforcement identity_expiry_clock=server \
         identity_expiry_unix_millis={}]",
        self_hosted_identity_expiry(server_clock_unix_millis)
    )
}

/// `agent-worker self-hosted-governed-execution-smoke --worker-type self-hosted`.
///
/// Runs a governed CLI workload through the local-process backend under a
/// capability policy that DENIES the action. Under self-hosted report-only
/// policy the workload still runs and the denied capability is recorded, not
/// blocked — the exact "cloud would block, self-hosted records" behavior.
pub(crate) fn self_hosted_governed_execution_smoke_command(
    server_clock_unix_millis: u64,
) -> anyhow::Result<()> {
    use std::collections::BTreeSet;

    use ferrogate_runtime::{CapabilityPolicy, ClassOnlyPolicyMode, SimpleCapabilityAuthorizer};

    use crate::external_actions::RuntimeGatewayExternalActionAuthorizer;

    // A policy that allows NOTHING: cloud would DENY this CLI action.
    let authorizer = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::new(),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));
    let action = ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf 'ferrogate self-hosted report-only workload\\n'".to_string(),
        ],
        working_dir: crate::local_process_backend::WORKSPACE_MOUNTPOINT.to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let execution = run_governed_cli_workload(
        FrameworkAdapterMode::SelfHosted,
        &self_hosted_smoke_session(),
        &authorizer,
        action,
        false,
        server_clock_unix_millis,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&execution.evidence_json())?
    );
    Ok(())
}

#[cfg(test)]
#[path = "self_hosted_execution_test.rs"]
mod tests;
