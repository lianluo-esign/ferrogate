// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Managed worker scheduling boundary.
//!
//! The scheduler validates control-plane policy and then delegates host-level
//! lifecycle work to an `agent-worker` control client. It must not own
//! Firecracker or other isolation backend implementation details.

use std::{error::Error, fmt};

use blake2::{
    digest::{KeyInit, Mac},
    Blake2bMac512,
};

use crate::{
    select_isolation_backend, IsolationBackendDescriptor, IsolationCleanupOutcome, IsolationError,
    IsolationExecOutcome, IsolationExecRequest, IsolationPolicy, IsolationPrepareRequest,
    IsolationStarted, IsolationStopOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTemplate {
    pub id: String,
    pub framework_adapter: String,
    pub isolation_policy: IsolationPolicy,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSchedulerConfig {
    pub max_tenant_sessions: u32,
    pub max_workspace_sessions: u32,
}

impl Default for ManagedWorkerSchedulerConfig {
    fn default() -> Self {
        Self {
            max_tenant_sessions: 1,
            max_workspace_sessions: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSessionRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub requested_framework_adapter: String,
    pub capability_envelope_id: String,
    pub active_tenant_sessions: u32,
    pub active_workspace_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerRunRequest {
    pub workload_ref: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSession {
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub worker_template_id: String,
    pub framework_adapter: String,
    pub capability_envelope_id: String,
    pub selected_backend: IsolationBackendDescriptor,
    pub instance_id: String,
    pub status: ManagedWorkerSessionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedWorkerSessionStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
    CleanedUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerExecution {
    pub session: ManagedWorkerSession,
    pub exec: IsolationExecOutcome,
    pub stop: IsolationStopOutcome,
    pub cleanup: IsolationCleanupOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerFailedExecution {
    pub session: ManagedWorkerSession,
    pub error: ManagedWorkerError,
    pub stop: Option<IsolationStopOutcome>,
    pub cleanup: IsolationCleanupOutcome,
}

pub type ManagedWorkerFailure = Box<ManagedWorkerFailedExecution>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerCancellation {
    pub session: ManagedWorkerSession,
    pub stop: IsolationStopOutcome,
    pub cleanup: IsolationCleanupOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerLifecycleRecord {
    pub session_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_template_id: String,
    pub agent_worker_id: String,
    pub isolation_backend_kind: crate::IsolationBackendKind,
    pub isolation_instance_id: Option<String>,
    pub capability_envelope_id: String,
    pub status: ManagedWorkerSessionStatus,
    pub action: ManagedWorkerLifecycleAction,
    pub outcome: String,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedWorkerLifecycleAction {
    ExecOrAttach,
    Stop,
    Cleanup,
    Failure,
}

pub const AGENT_WORKER_PROTOCOL_VERSION: u32 = 1;
pub const AGENT_WORKER_CLOCK_SKEW_MILLIS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWorkerManagementAction {
    ProbeHandlers,
    ListBackends,
    Provision,
    ExecOrAttach,
    Stop,
    Cleanup,
    StreamStatus,
    CollectArtifacts,
}

impl AgentWorkerManagementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProbeHandlers => "probe_handlers",
            Self::ListBackends => "list_backends",
            Self::Provision => "provision",
            Self::ExecOrAttach => "exec_or_attach",
            Self::Stop => "stop",
            Self::Cleanup => "cleanup",
            Self::StreamStatus => "stream_status",
            Self::CollectArtifacts => "collect_artifacts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkerManagementSecurity {
    pub key_id: String,
    pub nonce: String,
    pub signature: String,
    pub algorithm: AgentWorkerSecurityAlgorithm,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWorkerSecurityAlgorithm {
    SharedSecretBlake2b,
    MtlsBoundBlake2b,
}

impl AgentWorkerSecurityAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedSecretBlake2b => "shared_secret_blake2b",
            Self::MtlsBoundBlake2b => "mtls_bound_blake2b",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkerManagementEnvelope {
    pub protocol_version: u32,
    pub action: AgentWorkerManagementAction,
    pub request_id: String,
    pub idempotency_key: String,
    pub issued_at_unix_millis: u64,
    pub deadline_unix_millis: u64,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub security: AgentWorkerManagementSecurity,
}

impl AgentWorkerManagementEnvelope {
    pub fn validate(&self, now_unix_millis: u64) -> Result<(), ManagedWorkerError> {
        if self.protocol_version != AGENT_WORKER_PROTOCOL_VERSION {
            return Err(ManagedWorkerError::InvalidRequest(format!(
                "unsupported agent-worker protocol version {}",
                self.protocol_version
            )));
        }
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("idempotency_key", &self.idempotency_key)?;
        require_non_empty("tenant_id", &self.tenant_id)?;
        require_non_empty("workspace_id", &self.workspace_id)?;
        require_non_empty("worker_id", &self.worker_id)?;
        require_non_empty("security.key_id", &self.security.key_id)?;
        require_non_empty("security.nonce", &self.security.nonce)?;
        require_non_empty("security.signature", &self.security.signature)?;
        if !self.security.encrypted
            && self.security.algorithm != AgentWorkerSecurityAlgorithm::MtlsBoundBlake2b
        {
            return Err(ManagedWorkerError::InvalidRequest(
                "agent-worker management requests must be encrypted or mTLS-bound".to_string(),
            ));
        }
        if self.deadline_unix_millis <= self.issued_at_unix_millis {
            return Err(ManagedWorkerError::InvalidRequest(
                "deadline_unix_millis must be after issued_at_unix_millis".to_string(),
            ));
        }
        if now_unix_millis > self.deadline_unix_millis {
            return Err(ManagedWorkerError::InvalidRequest(
                "agent-worker management request deadline expired".to_string(),
            ));
        }
        if self.issued_at_unix_millis
            > now_unix_millis.saturating_add(AGENT_WORKER_CLOCK_SKEW_MILLIS)
        {
            return Err(ManagedWorkerError::InvalidRequest(
                "agent-worker management request issued_at is too far in the future".to_string(),
            ));
        }
        Ok(())
    }

    pub fn canonical_signature_input(&self) -> String {
        [
            self.protocol_version.to_string(),
            self.action.as_str().to_string(),
            self.request_id.clone(),
            self.idempotency_key.clone(),
            self.issued_at_unix_millis.to_string(),
            self.deadline_unix_millis.to_string(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
            self.worker_id.clone(),
            self.session_id.clone().unwrap_or_default(),
            self.run_id.clone().unwrap_or_default(),
            self.security.key_id.clone(),
            self.security.nonce.clone(),
            self.security.algorithm.as_str().to_string(),
            self.security.encrypted.to_string(),
        ]
        .join("\n")
    }

    pub fn shared_secret_signature(
        &self,
        shared_secret: &str,
    ) -> Result<String, ManagedWorkerError> {
        require_non_empty("shared_secret", shared_secret)?;
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| {
                ManagedWorkerError::InvalidRequest(
                    "shared_secret is not a valid MAC key".to_string(),
                )
            })?;
        mac.update(self.canonical_signature_input().as_bytes());
        Ok(format!(
            "blake2b-mac:{}",
            encode_hex(&mac.finalize().into_bytes())
        ))
    }

    pub fn verify_shared_secret_signature(
        &self,
        shared_secret: &str,
    ) -> Result<(), ManagedWorkerError> {
        if !matches!(
            self.security.algorithm,
            AgentWorkerSecurityAlgorithm::SharedSecretBlake2b
                | AgentWorkerSecurityAlgorithm::MtlsBoundBlake2b
        ) {
            return Err(ManagedWorkerError::InvalidRequest(
                "unsupported agent-worker signature algorithm".to_string(),
            ));
        }
        let expected = self.shared_secret_signature(shared_secret)?;
        if !constant_time_eq(expected.as_bytes(), self.security.signature.as_bytes()) {
            return Err(ManagedWorkerError::InvalidRequest(
                "agent-worker management request signature verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkerFrameworkHandler {
    pub adapter_name: String,
    pub framework: String,
    pub version: String,
    pub ready: bool,
    pub readiness_reason: Option<String>,
}

pub trait AgentWorkerControlClient {
    fn framework_handlers(&mut self) -> &[AgentWorkerFrameworkHandler];
    fn backends(&mut self) -> &[IsolationBackendDescriptor];
    fn provision_managed_worker(
        &mut self,
        request: IsolationPrepareRequest,
    ) -> Result<IsolationStarted, ManagedWorkerError>;
    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> Result<IsolationExecOutcome, ManagedWorkerError>;
    fn stop_managed_worker(
        &mut self,
        instance_id: &str,
        reason: &str,
    ) -> Result<IsolationStopOutcome, ManagedWorkerError>;
    fn cleanup_managed_worker(
        &mut self,
        instance_id: &str,
    ) -> Result<IsolationCleanupOutcome, ManagedWorkerError>;
}

#[derive(Debug, Clone)]
pub struct ManagedWorkerScheduler {
    config: ManagedWorkerSchedulerConfig,
    templates: Vec<WorkerTemplate>,
}

impl ManagedWorkerScheduler {
    pub fn new(
        config: ManagedWorkerSchedulerConfig,
        templates: Vec<WorkerTemplate>,
    ) -> Result<Self, ManagedWorkerError> {
        if config.max_tenant_sessions == 0 {
            return Err(ManagedWorkerError::InvalidConfig(
                "max_tenant_sessions must be greater than zero".to_string(),
            ));
        }
        if config.max_workspace_sessions == 0 {
            return Err(ManagedWorkerError::InvalidConfig(
                "max_workspace_sessions must be greater than zero".to_string(),
            ));
        }
        if templates.is_empty() {
            return Err(ManagedWorkerError::InvalidConfig(
                "at least one worker template is required".to_string(),
            ));
        }
        Ok(Self { config, templates })
    }

    pub fn start_session<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerSession, ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        self.validate_request(&request)?;
        self.check_concurrency(&request)?;
        let template = self.select_template(&request)?;
        self.check_framework_handler(template, agent_worker)?;
        let selected_backend =
            select_isolation_backend(&template.isolation_policy, agent_worker.backends())
                .map_err(ManagedWorkerError::Isolation)?
                .clone();

        let started = agent_worker.provision_managed_worker(IsolationPrepareRequest {
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            worker_template_id: template.id.clone(),
            framework_adapter: template.framework_adapter.clone(),
            capability_envelope_id: request.capability_envelope_id.clone(),
            policy: template.isolation_policy.clone(),
        })?;

        Ok(ManagedWorkerSession {
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            session_id: request.session_id,
            run_id: request.run_id,
            worker_template_id: template.id.clone(),
            framework_adapter: template.framework_adapter.clone(),
            capability_envelope_id: request.capability_envelope_id,
            selected_backend,
            instance_id: started.instance_id,
            status: ManagedWorkerSessionStatus::Running,
        })
    }

    pub fn run_to_completion<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        run: ManagedWorkerRunRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerExecution, ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        let mut session = self.start_session(request, agent_worker)?;
        let exec = agent_worker.exec_or_attach(IsolationExecRequest {
            instance_id: session.instance_id.clone(),
            workload_ref: run.workload_ref,
            args: run.args,
        })?;
        let stop = agent_worker.stop_managed_worker(&session.instance_id, "completed")?;
        let cleanup = agent_worker.cleanup_managed_worker(&session.instance_id)?;
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerExecution {
            session,
            exec,
            stop,
            cleanup,
        })
    }

    pub fn run_with_cleanup<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        run: ManagedWorkerRunRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerExecution, ManagedWorkerFailure>
    where
        C: AgentWorkerControlClient,
    {
        let mut session = self.start_session(request, agent_worker).map_err(|error| {
            Box::new(ManagedWorkerFailedExecution {
                session: ManagedWorkerSession::failed_before_start(),
                error,
                stop: None,
                cleanup: IsolationCleanupOutcome::not_started(),
            })
        })?;
        let exec = match agent_worker.exec_or_attach(IsolationExecRequest {
            instance_id: session.instance_id.clone(),
            workload_ref: run.workload_ref,
            args: run.args,
        }) {
            Ok(exec) => exec,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let stop = match agent_worker.stop_managed_worker(&session.instance_id, "completed") {
            Ok(stop) => stop,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => cleanup,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(Box::new(ManagedWorkerFailedExecution {
                    session,
                    error,
                    stop: Some(stop),
                    cleanup: IsolationCleanupOutcome::not_started(),
                }));
            }
        };
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerExecution {
            session,
            exec,
            stop,
            cleanup,
        })
    }

    pub fn cancel_session<C>(
        &self,
        mut session: ManagedWorkerSession,
        reason: &str,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerCancellation, ManagedWorkerFailure>
    where
        C: AgentWorkerControlClient,
    {
        if reason.trim().is_empty() {
            return Err(Box::new(ManagedWorkerFailedExecution {
                session,
                error: ManagedWorkerError::InvalidRequest(
                    "cancel reason must not be empty".to_string(),
                ),
                stop: None,
                cleanup: IsolationCleanupOutcome::not_started(),
            }));
        }
        let stop = match agent_worker.stop_managed_worker(&session.instance_id, reason) {
            Ok(stop) => stop,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => cleanup,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(Box::new(ManagedWorkerFailedExecution {
                    session,
                    error,
                    stop: Some(stop),
                    cleanup: IsolationCleanupOutcome::not_started(),
                }));
            }
        };
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerCancellation {
            session,
            stop,
            cleanup,
        })
    }

    fn cleanup_failed_session<C>(
        &self,
        mut session: ManagedWorkerSession,
        error: ManagedWorkerError,
        agent_worker: &mut C,
    ) -> ManagedWorkerFailure
    where
        C: AgentWorkerControlClient,
    {
        let stop = agent_worker
            .stop_managed_worker(&session.instance_id, "failed")
            .ok();
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => {
                session.status = ManagedWorkerSessionStatus::CleanedUp;
                cleanup
            }
            Err(_) => IsolationCleanupOutcome::not_started(),
        };
        Box::new(ManagedWorkerFailedExecution {
            session,
            error,
            stop,
            cleanup,
        })
    }

    fn validate_request(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<(), ManagedWorkerError> {
        if request.tenant_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "tenant_id must not be empty".to_string(),
            ));
        }
        if request.workspace_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "workspace_id must not be empty".to_string(),
            ));
        }
        if request.session_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "session_id must not be empty".to_string(),
            ));
        }
        if request.run_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "run_id must not be empty".to_string(),
            ));
        }
        if request.requested_framework_adapter.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "requested_framework_adapter must not be empty".to_string(),
            ));
        }
        if request.capability_envelope_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "capability_envelope_id must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn check_concurrency(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<(), ManagedWorkerError> {
        if request.active_tenant_sessions >= self.config.max_tenant_sessions {
            return Err(ManagedWorkerError::QuotaExceeded(
                "tenant managed worker concurrency exceeded".to_string(),
            ));
        }
        if request.active_workspace_sessions >= self.config.max_workspace_sessions {
            return Err(ManagedWorkerError::QuotaExceeded(
                "workspace managed worker concurrency exceeded".to_string(),
            ));
        }
        Ok(())
    }

    fn select_template(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<&WorkerTemplate, ManagedWorkerError> {
        self.templates
            .iter()
            .find(|template| {
                template.enabled
                    && template.framework_adapter == request.requested_framework_adapter
            })
            .ok_or_else(|| {
                ManagedWorkerError::NoCompatibleTemplate(format!(
                    "no enabled worker template supports framework adapter {}",
                    request.requested_framework_adapter
                ))
            })
    }

    fn check_framework_handler<C>(
        &self,
        template: &WorkerTemplate,
        agent_worker: &mut C,
    ) -> Result<(), ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        let handlers = agent_worker.framework_handlers();
        let Some(handler) = handlers
            .iter()
            .find(|handler| handler.adapter_name == template.framework_adapter)
        else {
            return Err(ManagedWorkerError::NoCompatibleTemplate(format!(
                "agent-worker reported no handler for framework adapter {}",
                template.framework_adapter
            )));
        };
        if !handler.ready {
            return Err(ManagedWorkerError::NoCompatibleTemplate(format!(
                "agent-worker handler {} is not ready: {}",
                handler.adapter_name,
                handler
                    .readiness_reason
                    .as_deref()
                    .unwrap_or("readiness reason was not reported")
            )));
        }
        Ok(())
    }
}

impl ManagedWorkerSession {
    fn failed_before_start() -> Self {
        Self {
            tenant_id: String::new(),
            workspace_id: String::new(),
            session_id: String::new(),
            run_id: String::new(),
            worker_template_id: String::new(),
            framework_adapter: String::new(),
            capability_envelope_id: String::new(),
            selected_backend: IsolationBackendDescriptor {
                backend_name: String::new(),
                backend_version: String::new(),
                kind: crate::IsolationBackendKind::FirecrackerMicroVm,
                capabilities: crate::IsolationBackendCapabilities::default(),
            },
            instance_id: String::new(),
            status: ManagedWorkerSessionStatus::Failed,
        }
    }
}

impl ManagedWorkerExecution {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        [
            (
                ManagedWorkerLifecycleAction::ExecOrAttach,
                &self.exec.evidence,
            ),
            (ManagedWorkerLifecycleAction::Stop, &self.stop.evidence),
            (
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ),
        ]
        .into_iter()
        .map(|(action, evidence)| self.session.lifecycle_record(action, evidence))
        .collect()
    }
}

impl ManagedWorkerCancellation {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        [
            (ManagedWorkerLifecycleAction::Stop, &self.stop.evidence),
            (
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ),
        ]
        .into_iter()
        .map(|(action, evidence)| self.session.lifecycle_record(action, evidence))
        .collect()
    }
}

impl ManagedWorkerFailedExecution {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        let mut records = Vec::new();
        if let Some(stop) = &self.stop {
            records.push(
                self.session
                    .lifecycle_record(ManagedWorkerLifecycleAction::Stop, &stop.evidence),
            );
        }
        if self.cleanup.evidence.outcome == "not_started" {
            let mut record = self.session.lifecycle_record(
                ManagedWorkerLifecycleAction::Failure,
                &self.cleanup.evidence,
            );
            record.outcome = "failed".to_string();
            record.failure_reason = Some(self.error.to_string());
            records.push(record);
        } else {
            records.push(self.session.lifecycle_record(
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ));
        }
        records
    }
}

impl ManagedWorkerSession {
    fn lifecycle_record(
        &self,
        action: ManagedWorkerLifecycleAction,
        evidence: &crate::IsolationLifecycleEvidence,
    ) -> ManagedWorkerLifecycleRecord {
        ManagedWorkerLifecycleRecord {
            session_id: self.session_id.clone(),
            run_id: self.run_id.clone(),
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            worker_template_id: self.worker_template_id.clone(),
            agent_worker_id: evidence.agent_worker_id.clone(),
            isolation_backend_kind: self.selected_backend.kind.clone(),
            isolation_instance_id: evidence
                .isolation_instance_id
                .clone()
                .or_else(|| Some(self.instance_id.clone()).filter(|value| !value.is_empty())),
            capability_envelope_id: evidence.capability_envelope_id.clone(),
            status: self.status,
            action,
            outcome: evidence.outcome.clone(),
            failure_reason: evidence.failure_reason.clone(),
        }
    }
}

impl IsolationCleanupOutcome {
    fn not_started() -> Self {
        Self {
            instance_id: String::new(),
            evidence: crate::IsolationLifecycleEvidence {
                backend_name: String::new(),
                backend_version: String::new(),
                agent_worker_id: String::new(),
                isolation_instance_id: None,
                resource_limits: crate::IsolationResourceLimits::default(),
                network_policy: crate::IsolationNetworkPolicy::default(),
                filesystem_policy: crate::IsolationFilesystemPolicy::default(),
                capability_envelope_id: String::new(),
                outcome: "not_started".to_string(),
                failure_reason: Some("session was not provisioned".to_string()),
            },
        }
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ManagedWorkerError> {
    if value.trim().is_empty() {
        return Err(ManagedWorkerError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedWorkerError {
    InvalidConfig(String),
    InvalidRequest(String),
    QuotaExceeded(String),
    NoCompatibleTemplate(String),
    Isolation(IsolationError),
    AgentWorker(String),
}

impl fmt::Display for ManagedWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid managed worker config: {message}")
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid managed worker request: {message}")
            }
            Self::QuotaExceeded(message) => {
                write!(formatter, "managed worker quota exceeded: {message}")
            }
            Self::NoCompatibleTemplate(message) => {
                write!(
                    formatter,
                    "no compatible managed worker template: {message}"
                )
            }
            Self::Isolation(error) => write!(formatter, "managed worker isolation failed: {error}"),
            Self::AgentWorker(message) => {
                write!(formatter, "agent-worker control failed: {message}")
            }
        }
    }
}

impl Error for ManagedWorkerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Isolation(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IsolationBackendCapabilities, IsolationBackendKind, IsolationFilesystemPolicy,
        IsolationLifecycleEvidence, IsolationNetworkPolicy, IsolationResourceLimits,
    };

    #[test]
    fn schedules_managed_session_through_agent_worker_control_client() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);

        let execution = scheduler
            .run_to_completion(session_request(), run_request(), &mut agent_worker)
            .unwrap();

        assert_eq!(
            agent_worker.calls,
            vec![
                "framework_handlers",
                "backends",
                "provision_managed_worker",
                "exec_or_attach",
                "stop_managed_worker",
                "cleanup_managed_worker",
            ]
        );
        assert_eq!(
            execution.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert_eq!(
            execution.session.selected_backend.kind,
            IsolationBackendKind::FirecrackerMicroVm
        );
        assert_eq!(execution.session.worker_template_id, "template-codex");
        assert_eq!(execution.session.capability_envelope_id, "capability-1");
        assert_eq!(execution.exec.exit_code, Some(0));
        assert_eq!(
            execution.cleanup.evidence.agent_worker_id,
            "agent-worker-fake-1"
        );
        assert_eq!(
            execution.cleanup.evidence.isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        let records = execution.lifecycle_records();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[0].action,
            ManagedWorkerLifecycleAction::ExecOrAttach
        );
        assert_eq!(records[0].session_id, "session-1");
        assert_eq!(records[0].run_id, "run-1");
        assert_eq!(records[0].tenant_id, "tenant-1");
        assert_eq!(records[0].workspace_id, "workspace-1");
        assert_eq!(records[0].worker_template_id, "template-codex");
        assert_eq!(records[0].agent_worker_id, "agent-worker-fake-1");
        assert_eq!(
            records[0].isolation_backend_kind,
            IsolationBackendKind::FirecrackerMicroVm
        );
        assert_eq!(
            records[0].isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        assert_eq!(records[0].capability_envelope_id, "capability-1");
        assert_eq!(records[2].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[2].outcome, "cleaned_up");
    }

    #[test]
    fn rejects_request_before_agent_worker_when_tenant_concurrency_is_exceeded() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            active_tenant_sessions: 1,
            ..session_request()
        };

        let error = scheduler
            .start_session(request, &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::QuotaExceeded(_)));
        assert!(agent_worker.calls.is_empty());
    }

    #[test]
    fn rejects_session_when_agent_worker_handler_is_not_ready() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        agent_worker.handlers[0].ready = false;
        agent_worker.handlers[0].readiness_reason = Some("codex binary missing".to_string());

        let error = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::NoCompatibleTemplate(_)));
        assert_eq!(agent_worker.calls, vec!["framework_handlers"]);
        assert!(error.to_string().contains("codex binary missing"));
    }

    #[test]
    fn failed_before_start_projects_auditable_failure_lifecycle_record() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            active_tenant_sessions: 1,
            ..session_request()
        };

        let failure = scheduler
            .run_with_cleanup(request, run_request(), &mut agent_worker)
            .unwrap_err();

        assert!(agent_worker.calls.is_empty());
        let records = failure.lifecycle_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Failure);
        assert_eq!(records[0].outcome, "failed");
        assert!(records[0]
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("tenant managed worker concurrency exceeded")));
    }

    #[test]
    fn fails_closed_when_no_template_supports_framework_adapter() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            requested_framework_adapter: "unknown".to_string(),
            ..session_request()
        };

        let error = scheduler
            .start_session(request, &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::NoCompatibleTemplate(_)));
        assert!(agent_worker.calls.is_empty());
    }

    #[test]
    fn fails_closed_when_agent_worker_has_no_compatible_backend() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "rootless-docker",
            IsolationBackendKind::RootlessDocker,
        )]);

        let error = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap_err();

        assert!(matches!(
            error,
            ManagedWorkerError::Isolation(IsolationError::NoCompatibleBackend(_))
        ));
        assert_eq!(agent_worker.calls, vec!["framework_handlers", "backends"]);
    }

    #[test]
    fn run_with_cleanup_stops_and_cleans_up_after_exec_failure() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        agent_worker.fail_exec = true;

        let failure = scheduler
            .run_with_cleanup(session_request(), run_request(), &mut agent_worker)
            .unwrap_err();

        assert_eq!(
            agent_worker.calls,
            vec![
                "framework_handlers",
                "backends",
                "provision_managed_worker",
                "exec_or_attach",
                "stop_managed_worker",
                "cleanup_managed_worker",
            ]
        );
        assert!(matches!(failure.error, ManagedWorkerError::AgentWorker(_)));
        assert_eq!(
            failure.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert!(failure.stop.is_some());
        assert_eq!(failure.cleanup.evidence.outcome, "cleaned_up");
        let records = failure.lifecycle_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Stop);
        assert_eq!(records[1].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[1].outcome, "cleaned_up");
    }

    #[test]
    fn cancel_session_stops_and_cleans_up_through_agent_worker() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let session = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap();
        agent_worker.calls.clear();

        let cancellation = scheduler
            .cancel_session(session, "operator_cancelled", &mut agent_worker)
            .unwrap();

        assert_eq!(
            agent_worker.calls,
            vec!["stop_managed_worker", "cleanup_managed_worker"]
        );
        assert_eq!(
            cancellation.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert_eq!(
            cancellation.stop.evidence.outcome,
            "stopped:operator_cancelled"
        );
        assert_eq!(cancellation.cleanup.evidence.outcome, "cleaned_up");
        let records = cancellation.lifecycle_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Stop);
        assert_eq!(records[0].outcome, "stopped:operator_cancelled");
        assert_eq!(records[1].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[1].outcome, "cleaned_up");
    }

    #[test]
    fn rejects_invalid_scheduler_config() {
        let error = ManagedWorkerScheduler::new(
            ManagedWorkerSchedulerConfig {
                max_tenant_sessions: 0,
                max_workspace_sessions: 1,
            },
            vec![template()],
        )
        .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::InvalidConfig(_)));
    }

    #[test]
    fn agent_worker_management_envelope_requires_stable_secure_fields() {
        let envelope = management_envelope(AgentWorkerManagementAction::Provision);

        envelope.validate(1_000).unwrap();
        envelope
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        assert_eq!(envelope.action.as_str(), "provision");
        assert_eq!(
            envelope.security.algorithm.as_str(),
            "shared_secret_blake2b"
        );
        assert!(envelope
            .canonical_signature_input()
            .contains("provision\nrequest-1\nidempotency-1"));
        assert!(envelope.security.signature.starts_with("blake2b-mac:"));

        let mut missing_signature = envelope.clone();
        missing_signature.security.signature.clear();
        assert!(missing_signature
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("security.signature"));

        let mut unencrypted = envelope.clone();
        unencrypted.security.encrypted = false;
        assert!(unencrypted
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("encrypted or mTLS-bound"));

        let mut wrong_signature = envelope.clone();
        wrong_signature.security.signature = "blake2b-mac:bad".to_string();
        assert!(wrong_signature
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));

        assert!(envelope
            .verify_shared_secret_signature("wrong-secret")
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));

        let mut expired = envelope.clone();
        expired.deadline_unix_millis = 999;
        assert!(expired
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("deadline expired"));
    }

    fn scheduler() -> ManagedWorkerScheduler {
        ManagedWorkerScheduler::new(ManagedWorkerSchedulerConfig::default(), vec![template()])
            .unwrap()
    }

    fn template() -> WorkerTemplate {
        WorkerTemplate {
            id: "template-codex".to_string(),
            framework_adapter: "codex".to_string(),
            isolation_policy: IsolationPolicy {
                allowed_kinds: vec![IsolationBackendKind::FirecrackerMicroVm],
                ..IsolationPolicy::default()
            },
            enabled: true,
        }
    }

    fn session_request() -> ManagedWorkerSessionRequest {
        ManagedWorkerSessionRequest {
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            requested_framework_adapter: "codex".to_string(),
            capability_envelope_id: "capability-1".to_string(),
            active_tenant_sessions: 0,
            active_workspace_sessions: 0,
        }
    }

    fn run_request() -> ManagedWorkerRunRequest {
        ManagedWorkerRunRequest {
            workload_ref: "agent://codex/run".to_string(),
            args: vec!["--task".to_string(), "smoke".to_string()],
        }
    }

    fn management_envelope(action: AgentWorkerManagementAction) -> AgentWorkerManagementEnvelope {
        let mut envelope = AgentWorkerManagementEnvelope {
            protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
            action,
            request_id: "request-1".to_string(),
            idempotency_key: "idempotency-1".to_string(),
            issued_at_unix_millis: 900,
            deadline_unix_millis: 2_000,
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "agent-worker-fake-1".to_string(),
            session_id: Some("session-1".to_string()),
            run_id: Some("run-1".to_string()),
            security: AgentWorkerManagementSecurity {
                key_id: "agent-worker-key-1".to_string(),
                nonce: "nonce-1".to_string(),
                signature: String::new(),
                algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
                encrypted: true,
            },
        };
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        envelope
    }

    fn backend(name: &str, kind: IsolationBackendKind) -> IsolationBackendDescriptor {
        IsolationBackendDescriptor {
            backend_name: name.to_string(),
            backend_version: "test-1".to_string(),
            kind,
            capabilities: IsolationBackendCapabilities::full(),
        }
    }

    struct FakeAgentWorker {
        handlers: Vec<AgentWorkerFrameworkHandler>,
        backends: Vec<IsolationBackendDescriptor>,
        calls: Vec<&'static str>,
        fail_exec: bool,
        fail_stop: bool,
        fail_cleanup: bool,
    }

    impl FakeAgentWorker {
        fn new(backends: Vec<IsolationBackendDescriptor>) -> Self {
            Self {
                handlers: vec![AgentWorkerFrameworkHandler {
                    adapter_name: "codex".to_string(),
                    framework: "codex".to_string(),
                    version: "test-1".to_string(),
                    ready: true,
                    readiness_reason: None,
                }],
                backends,
                calls: Vec::new(),
                fail_exec: false,
                fail_stop: false,
                fail_cleanup: false,
            }
        }

        fn evidence(&self, instance_id: &str, outcome: &str) -> IsolationLifecycleEvidence {
            IsolationLifecycleEvidence {
                backend_name: "firecracker".to_string(),
                backend_version: "test-1".to_string(),
                agent_worker_id: "agent-worker-fake-1".to_string(),
                isolation_instance_id: Some(instance_id.to_string()),
                resource_limits: IsolationResourceLimits::default(),
                network_policy: IsolationNetworkPolicy::default(),
                filesystem_policy: IsolationFilesystemPolicy::default(),
                capability_envelope_id: "capability-1".to_string(),
                outcome: outcome.to_string(),
                failure_reason: None,
            }
        }
    }

    impl AgentWorkerControlClient for FakeAgentWorker {
        fn framework_handlers(&mut self) -> &[AgentWorkerFrameworkHandler] {
            self.calls.push("framework_handlers");
            &self.handlers
        }

        fn backends(&mut self) -> &[IsolationBackendDescriptor] {
            self.calls.push("backends");
            &self.backends
        }

        fn provision_managed_worker(
            &mut self,
            request: IsolationPrepareRequest,
        ) -> Result<IsolationStarted, ManagedWorkerError> {
            self.calls.push("provision_managed_worker");
            Ok(IsolationStarted {
                instance_id: format!("instance-{}", request.run_id),
                evidence: self.evidence(&format!("instance-{}", request.run_id), "started"),
            })
        }

        fn exec_or_attach(
            &mut self,
            request: IsolationExecRequest,
        ) -> Result<IsolationExecOutcome, ManagedWorkerError> {
            self.calls.push("exec_or_attach");
            if self.fail_exec {
                return Err(ManagedWorkerError::AgentWorker(
                    "exec failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationExecOutcome {
                instance_id: request.instance_id.clone(),
                exit_code: Some(0),
                message: format!("executed {}", request.workload_ref),
                evidence: self.evidence(&request.instance_id, "executed"),
            })
        }

        fn stop_managed_worker(
            &mut self,
            instance_id: &str,
            reason: &str,
        ) -> Result<IsolationStopOutcome, ManagedWorkerError> {
            self.calls.push("stop_managed_worker");
            if self.fail_stop {
                return Err(ManagedWorkerError::AgentWorker(
                    "stop failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationStopOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(instance_id, &format!("stopped:{reason}")),
            })
        }

        fn cleanup_managed_worker(
            &mut self,
            instance_id: &str,
        ) -> Result<IsolationCleanupOutcome, ManagedWorkerError> {
            self.calls.push("cleanup_managed_worker");
            if self.fail_cleanup {
                return Err(ManagedWorkerError::AgentWorker(
                    "cleanup failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationCleanupOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(instance_id, "cleaned_up"),
            })
        }
    }
}
