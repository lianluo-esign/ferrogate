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
    SelfHostedRunEvidenceCorrelation, SelfHostedTelemetryTrustLevel, SupportedFramework,
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
    /// #329: the correlation identity carried on the run's dispatch lease
    /// (`request_id`/`trace_id`/`agent_run_id` from #305 + the #307
    /// `parent_action_fingerprint`). The worker stamps it onto the evidence it
    /// reports so the self-hosted leg emits the SAME action identity the control
    /// plane persisted, instead of forcing a gateway-side back-fill. Empty for a
    /// keyless run (no dispatching context) — never fabricated.
    pub(crate) lease_correlation: SelfHostedRunEvidenceCorrelation,
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
            // #329: the dispatch lease's correlation identity, stamped verbatim
            // onto the worker's emitted evidence. Absent keys serialize as null
            // (a keyless run) — never a fabricated id — so the control plane can
            // join this evidence on the SAME {request_id, trace_id,
            // agent_run_id} triple + parent fingerprint it stored on the
            // dispatch, or record NULL.
            "correlation": {
                "request_id": self.lease_correlation.request_id,
                "trace_id": self.lease_correlation.trace_id,
                "agent_run_id": self.lease_correlation.agent_run_id,
                "parent_action_fingerprint": self.lease_correlation.parent_action_fingerprint,
            },
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
    action: &ManagedExternalAction,
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
            action: action.clone(),
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

/// The result of running one governed workload's side effect, independent of the
/// capability family. `run_governed_workload` pairs this with the recorded
/// gateway decision to build the family-agnostic `GovernedWorkloadExecution`
/// evidence.
pub(crate) struct GovernedWorkloadOutcome {
    pub(crate) exit_code: Option<i32>,
    pub(crate) output: String,
    pub(crate) backend_name: String,
    pub(crate) containment_summary: String,
}

/// Run ONE governed workload of ANY capability family under the given worker
/// mode. This is the family-agnostic core of the report-only-vs-enforce
/// distinction established for CLI in #242 and extended to the remaining
/// governed families in #245.
///
/// - `Managed` (cloud): ENFORCE. A non-`Allowed` gateway decision returns
///   `CapabilityDenied` and `execute_workload` is NEVER invoked (the side effect
///   never runs).
/// - `SelfHosted`: REPORT-ONLY. The gateway decision is recorded but never
///   enforced; `execute_workload` runs regardless, and a capability cloud would
///   block becomes allowed-but-recorded.
///
/// The gateway decision is always computed against a MANAGED probe session (see
/// `authorize_governed_capability`), so the self-hosted report faithfully states
/// what cloud WOULD have decided. The workload side effect is provided by the
/// caller (`execute_workload`) so each family runs through its own execution
/// path (local-process backend for CLI, the in-process governed handler for the
/// other families) while sharing this one enforcement boundary.
pub(crate) fn run_governed_workload<A, F>(
    mode: FrameworkAdapterMode,
    session: &FrameworkAdapterSession,
    authorizer: &A,
    action: ManagedExternalAction,
    high_risk: bool,
    server_clock_unix_millis: u64,
    execute_workload: F,
) -> Result<GovernedWorkloadExecution, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
    F: FnOnce() -> Result<GovernedWorkloadOutcome, FrameworkAdapterError>,
{
    let decision = authorize_governed_capability(authorizer, session, &action, high_risk)?;
    let capability_action = action.capability_action().as_str();
    let target = action.target();
    match mode {
        FrameworkAdapterMode::Managed => {
            // Cloud enforces: a non-allow decision blocks before any host work.
            if decision != CapabilityAuthorizationDecision::Allowed {
                return Err(FrameworkAdapterError::CapabilityDenied(format!(
                    "cloud (managed) worker blocks capability action={capability_action} \
                     target={target} decision={}: enforcement_boundary={CLOUD_ENFORCEMENT_BOUNDARY}",
                    decision_label(decision)
                )));
            }
            let workload = execute_workload()?;
            Ok(GovernedWorkloadExecution {
                mode,
                capability_action,
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
                lease_correlation: SelfHostedRunEvidenceCorrelation::default(),
            })
        }
        FrameworkAdapterMode::SelfHosted => {
            // Self-hosted observes and reports: the workload runs regardless of
            // the decision; the decision is telemetry only.
            let workload = execute_workload()?;
            Ok(GovernedWorkloadExecution {
                mode,
                capability_action,
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
                lease_correlation: SelfHostedRunEvidenceCorrelation::default(),
            })
        }
    }
}

/// Run a governed CLI workload through the worker-owned local-process isolation
/// backend under the given worker mode (the #242 first slice). Thin wrapper over
/// the family-agnostic `run_governed_workload` core.
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
    let workload_session = session.clone();
    let workload_action = action.clone();
    run_governed_workload(
        mode,
        session,
        authorizer,
        ManagedExternalAction::Cli(action),
        high_risk,
        server_clock_unix_millis,
        move || {
            let outcome = run_workload_through_local_process(&workload_session, &workload_action)?;
            Ok(GovernedWorkloadOutcome {
                exit_code: outcome.exit_code,
                output: outcome.output,
                backend_name: outcome.backend_name,
                containment_summary: outcome.containment_summary,
            })
        },
    )
}

/// Boot parameters for a Firecracker report-only workload (#247).
#[derive(Debug, Clone, Copy)]
pub(crate) struct FirecrackerBootParameters {
    pub(crate) timeout_millis: u64,
    pub(crate) vcpu_count: u8,
    pub(crate) mem_size_mib: u32,
}

/// Run one governed workload by BOOTING a Firecracker microVM through the
/// worker-owned governed backend (KVM-validated, #227), mirroring the #242
/// local-process wiring but for the Firecracker isolation backend (#247).
///
/// - `Managed` (cloud): ENFORCE. A non-`Allowed` gateway decision blocks BEFORE
///   any microVM is provisioned — no KVM/firecracker host work happens.
/// - `SelfHosted`: REPORT-ONLY. The gateway decision is recorded but never
///   enforced; the microVM boots through the governed path regardless and the
///   boot evidence becomes the workload output. Fails closed (does NOT pretend
///   to boot) if the KVM/firecracker prerequisites are unavailable.
pub(crate) fn run_governed_firecracker_workload<A>(
    mode: FrameworkAdapterMode,
    session: &FrameworkAdapterSession,
    authorizer: &A,
    action: ManagedCliAction,
    high_risk: bool,
    server_clock_unix_millis: u64,
    boot: FirecrackerBootParameters,
) -> Result<GovernedWorkloadExecution, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    run_governed_workload(
        mode,
        session,
        authorizer,
        ManagedExternalAction::Cli(action),
        high_risk,
        server_clock_unix_millis,
        move || run_workload_through_firecracker(boot),
    )
}

/// Boot a real Firecracker microVM through the governed provision path and turn
/// its boot evidence into a family-agnostic workload outcome. Fails closed with
/// an honest message when the host/KVM/firecracker prerequisites are missing.
fn run_workload_through_firecracker(
    boot: FirecrackerBootParameters,
) -> Result<GovernedWorkloadOutcome, FrameworkAdapterError> {
    let mut microvm = crate::backends::firecracker_microvm_provision(
        boot.timeout_millis,
        boot.vcpu_count,
        boot.mem_size_mib,
    )
    .map_err(|error| {
        FrameworkAdapterError::InvalidRequest(format!(
            "self-hosted report-only execution refused (fail closed): firecracker microVM boot \
             failed: {}",
            error.summary()
        ))
    })?;
    let instance_id = microvm.instance_id.clone();
    let boot_markers = microvm.evidence.marker_summary();
    let stop = microvm.stop();
    Ok(GovernedWorkloadOutcome {
        exit_code: Some(0),
        output: format!(
            "firecracker microvm booted instance_id={instance_id} \
             serial_boot_markers=[{boot_markers}]"
        ),
        backend_name: "firecracker".to_string(),
        containment_summary: format!(
            "firecracker microVM (per-VM read-only rootfs + writable workspace; report-only under \
             self-hosted); {}",
            stop.summary()
        ),
    })
}

/// `agent-worker self-hosted-firecracker-execution-smoke --worker-type self-hosted`.
///
/// Boots a microVM through the governed Firecracker backend under a capability
/// policy that DENIES the action. Under self-hosted report-only policy the
/// microVM still boots and the denied capability is recorded, not blocked — the
/// Firecracker analog of the #242 local-process `self-hosted-governed-execution-smoke`.
pub(crate) fn self_hosted_firecracker_execution_smoke_command(
    timeout_millis: u64,
    vcpu_count: u8,
    mem_size_mib: u32,
    server_clock_unix_millis: u64,
) -> anyhow::Result<()> {
    use std::collections::BTreeSet;

    use ferrogate_runtime::{CapabilityPolicy, ClassOnlyPolicyMode, SimpleCapabilityAuthorizer};

    use crate::external_actions::RuntimeGatewayExternalActionAuthorizer;

    // A policy that allows NOTHING: cloud would DENY this action.
    let authorizer = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::new(),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));
    let action = ManagedCliAction {
        command: "/bin/true".to_string(),
        args: Vec::new(),
        working_dir: "/".to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let mut session = self_hosted_smoke_session();
    session.isolation_backend = "firecracker".to_string();
    let execution = run_governed_firecracker_workload(
        FrameworkAdapterMode::SelfHosted,
        &session,
        &authorizer,
        action,
        false,
        server_clock_unix_millis,
        FirecrackerBootParameters {
            timeout_millis,
            vcpu_count,
            mem_size_mib,
        },
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&execution.evidence_json())?
    );
    Ok(())
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
