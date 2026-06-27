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

pub trait AgentWorkerControlClient {
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
                kind: crate::IsolationBackendKind::WasmSandbox,
                capabilities: crate::IsolationBackendCapabilities::default(),
            },
            instance_id: String::new(),
            status: ManagedWorkerSessionStatus::Failed,
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
        assert_eq!(agent_worker.calls, vec!["backends"]);
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

    fn backend(name: &str, kind: IsolationBackendKind) -> IsolationBackendDescriptor {
        IsolationBackendDescriptor {
            backend_name: name.to_string(),
            backend_version: "test-1".to_string(),
            kind,
            capabilities: IsolationBackendCapabilities::full(),
        }
    }

    struct FakeAgentWorker {
        backends: Vec<IsolationBackendDescriptor>,
        calls: Vec<&'static str>,
        fail_exec: bool,
        fail_stop: bool,
        fail_cleanup: bool,
    }

    impl FakeAgentWorker {
        fn new(backends: Vec<IsolationBackendDescriptor>) -> Self {
            Self {
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
