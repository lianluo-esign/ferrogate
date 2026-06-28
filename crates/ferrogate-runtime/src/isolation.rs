// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Managed worker isolation contract.
//!
//! This module describes the boundary that the host-side `agent-worker`
//! process must implement. The gateway/control plane can select policy and
//! record evidence, but Firecracker jailer setup and other host lifecycle
//! details belong behind this contract.

use std::{error::Error, fmt};

pub type IsolationResult<T> = Result<T, IsolationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationBackendKind {
    FirecrackerMicroVm,
    KataContainers,
    Gvisor,
    RootlessDocker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationBackendCapabilities {
    pub prepare: bool,
    pub start: bool,
    pub exec_or_attach: bool,
    pub stop: bool,
    pub snapshot_or_checkpoint: bool,
    pub collect_logs: bool,
    pub collect_artifacts: bool,
    pub cleanup: bool,
    pub governed_egress: bool,
    pub secret_injection: bool,
}

impl IsolationBackendCapabilities {
    pub fn full() -> Self {
        Self {
            prepare: true,
            start: true,
            exec_or_attach: true,
            stop: true,
            snapshot_or_checkpoint: true,
            collect_logs: true,
            collect_artifacts: true,
            cleanup: true,
            governed_egress: true,
            secret_injection: true,
        }
    }

    pub fn supports(&self, required: &Self) -> bool {
        (!required.prepare || self.prepare)
            && (!required.start || self.start)
            && (!required.exec_or_attach || self.exec_or_attach)
            && (!required.stop || self.stop)
            && (!required.snapshot_or_checkpoint || self.snapshot_or_checkpoint)
            && (!required.collect_logs || self.collect_logs)
            && (!required.collect_artifacts || self.collect_artifacts)
            && (!required.cleanup || self.cleanup)
            && (!required.governed_egress || self.governed_egress)
            && (!required.secret_injection || self.secret_injection)
    }
}

impl Default for IsolationBackendCapabilities {
    fn default() -> Self {
        Self {
            prepare: true,
            start: true,
            exec_or_attach: true,
            stop: true,
            snapshot_or_checkpoint: false,
            collect_logs: true,
            collect_artifacts: true,
            cleanup: true,
            governed_egress: true,
            secret_injection: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationBackendDescriptor {
    pub backend_name: String,
    pub backend_version: String,
    pub kind: IsolationBackendKind,
    pub host_lifecycle_owner: String,
    pub gateway_controls_backend: bool,
    pub capabilities: IsolationBackendCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationResourceLimits {
    pub cpu_count: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub max_runtime_millis: Option<u64>,
}

impl Default for IsolationResourceLimits {
    fn default() -> Self {
        Self {
            cpu_count: 1,
            memory_mib: 512,
            disk_mib: 1024,
            max_runtime_millis: Some(30_000),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationNetworkPolicy {
    pub direct_public_egress: bool,
    pub gateway_control_channel: bool,
    pub governed_egress: bool,
}

impl Default for IsolationNetworkPolicy {
    fn default() -> Self {
        Self {
            direct_public_egress: false,
            gateway_control_channel: true,
            governed_egress: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationFilesystemPolicy {
    pub read_only_rootfs: bool,
    pub writable_workspace: bool,
    pub host_path_mounts: bool,
}

impl Default for IsolationFilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only_rootfs: true,
            writable_workspace: true,
            host_path_mounts: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsolationPolicy {
    pub allowed_kinds: Vec<IsolationBackendKind>,
    pub required_capabilities: IsolationBackendCapabilities,
    pub resource_limits: IsolationResourceLimits,
    pub network_policy: IsolationNetworkPolicy,
    pub filesystem_policy: IsolationFilesystemPolicy,
}

impl IsolationPolicy {
    pub fn validate(&self) -> IsolationResult<()> {
        if self.resource_limits.cpu_count == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.cpu_count must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.memory_mib == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.memory_mib must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.disk_mib == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.disk_mib must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.max_runtime_millis == Some(0) {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.max_runtime_millis must be greater than zero".to_string(),
            ));
        }
        if self.network_policy.direct_public_egress {
            return Err(IsolationError::InvalidPolicy(
                "managed workers must not allow direct public egress".to_string(),
            ));
        }
        if !self.network_policy.gateway_control_channel {
            return Err(IsolationError::InvalidPolicy(
                "managed workers require the gateway control channel".to_string(),
            ));
        }
        if self.filesystem_policy.host_path_mounts {
            return Err(IsolationError::InvalidPolicy(
                "managed workers must not mount arbitrary host paths".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn select_isolation_backend<'a>(
    policy: &IsolationPolicy,
    candidates: &'a [IsolationBackendDescriptor],
) -> IsolationResult<&'a IsolationBackendDescriptor> {
    policy.validate()?;

    candidates
        .iter()
        .filter(|candidate| {
            (policy.allowed_kinds.is_empty() || policy.allowed_kinds.contains(&candidate.kind))
                && candidate
                    .capabilities
                    .supports(&policy.required_capabilities)
        })
        .min_by_key(|candidate| isolation_preference_rank(&candidate.kind))
        .ok_or_else(|| {
            IsolationError::NoCompatibleBackend(
                "no isolation backend matches policy and capability requirements".to_string(),
            )
        })
}

fn isolation_preference_rank(kind: &IsolationBackendKind) -> u8 {
    match kind {
        IsolationBackendKind::FirecrackerMicroVm => 0,
        IsolationBackendKind::KataContainers => 1,
        IsolationBackendKind::Gvisor => 2,
        IsolationBackendKind::RootlessDocker => 3,
    }
}

pub trait IsolationBackendLifecycle {
    fn descriptor(&self) -> &IsolationBackendDescriptor;
    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared>;
    fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted>;
    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> IsolationResult<IsolationExecOutcome>;
    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome>;
    fn snapshot_or_checkpoint(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<IsolationSnapshotOutcome>;
    fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs>;
    fn collect_artifacts(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<CollectedIsolationArtifacts>;
    fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPrepareRequest {
    pub session_id: String,
    pub run_id: String,
    pub worker_template_id: String,
    pub framework_adapter: String,
    pub capability_envelope_id: String,
    pub policy: IsolationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPrepared {
    pub prepared_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationStarted {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationExecRequest {
    pub instance_id: String,
    pub workload_ref: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationExecOutcome {
    pub instance_id: String,
    pub exit_code: Option<i32>,
    pub message: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationStopOutcome {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationSnapshotOutcome {
    pub instance_id: String,
    pub checkpoint_id: Option<String>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIsolationLogs {
    pub instance_id: String,
    pub lines: Vec<String>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationArtifact {
    pub id: String,
    pub path: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIsolationArtifacts {
    pub instance_id: String,
    pub artifacts: Vec<IsolationArtifact>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationCleanupOutcome {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationLifecycleEvidence {
    pub backend_name: String,
    pub backend_version: String,
    pub agent_worker_id: String,
    pub isolation_instance_id: Option<String>,
    pub resource_limits: IsolationResourceLimits,
    pub network_policy: IsolationNetworkPolicy,
    pub filesystem_policy: IsolationFilesystemPolicy,
    pub capability_envelope_id: String,
    pub outcome: String,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationError {
    InvalidPolicy(String),
    NoCompatibleBackend(String),
    Backend(String),
}

impl fmt::Display for IsolationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(message) => {
                write!(formatter, "invalid isolation policy: {message}")
            }
            Self::NoCompatibleBackend(message) => {
                write!(formatter, "no compatible isolation backend: {message}")
            }
            Self::Backend(message) => write!(formatter, "isolation backend failed: {message}"),
        }
    }
}

impl Error for IsolationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_microvm_backend_by_default_preference() {
        let docker = descriptor("rootless-docker", IsolationBackendKind::RootlessDocker);
        let gvisor = descriptor("gvisor", IsolationBackendKind::Gvisor);
        let firecracker = descriptor("firecracker", IsolationBackendKind::FirecrackerMicroVm);
        let candidates = vec![docker, gvisor, firecracker];

        let selected = select_isolation_backend(&IsolationPolicy::default(), &candidates).unwrap();

        assert_eq!(selected.kind, IsolationBackendKind::FirecrackerMicroVm);
        assert_eq!(selected.backend_name, "firecracker");
    }

    #[test]
    fn fails_closed_when_no_backend_matches_policy() {
        let candidates = vec![descriptor(
            "rootless-docker",
            IsolationBackendKind::RootlessDocker,
        )];
        let policy = IsolationPolicy {
            allowed_kinds: vec![IsolationBackendKind::FirecrackerMicroVm],
            ..IsolationPolicy::default()
        };

        let error = select_isolation_backend(&policy, &candidates).unwrap_err();

        assert!(matches!(error, IsolationError::NoCompatibleBackend(_)));
    }

    #[test]
    fn rejects_managed_worker_direct_public_egress() {
        let candidates = vec![descriptor(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )];
        let policy = IsolationPolicy {
            network_policy: IsolationNetworkPolicy {
                direct_public_egress: true,
                ..IsolationNetworkPolicy::default()
            },
            ..IsolationPolicy::default()
        };

        let error = select_isolation_backend(&policy, &candidates).unwrap_err();

        assert!(matches!(error, IsolationError::InvalidPolicy(_)));
        assert!(error.to_string().contains("direct public egress"));
    }

    #[test]
    fn local_fake_backend_exercises_lifecycle_contract() {
        let policy = IsolationPolicy::default();
        let mut backend = FakeIsolationBackend::new("agent-worker-test-1");
        let prepared = backend
            .prepare(IsolationPrepareRequest {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                worker_template_id: "template-1".to_string(),
                framework_adapter: "codex".to_string(),
                capability_envelope_id: "cap-1".to_string(),
                policy,
            })
            .unwrap();
        let started = backend.start(prepared).unwrap();
        let exec = backend
            .exec_or_attach(IsolationExecRequest {
                instance_id: started.instance_id.clone(),
                workload_ref: "agent://codex/run".to_string(),
                args: vec!["--task".to_string(), "smoke".to_string()],
            })
            .unwrap();
        let checkpoint = backend
            .snapshot_or_checkpoint(&started.instance_id)
            .unwrap();
        let logs = backend.collect_logs(&started.instance_id).unwrap();
        let artifacts = backend.collect_artifacts(&started.instance_id).unwrap();
        let stopped = backend.stop(&started.instance_id, "completed").unwrap();
        let cleanup = backend.cleanup(&started.instance_id).unwrap();

        assert_eq!(
            backend.calls,
            vec![
                "prepare",
                "start",
                "exec_or_attach",
                "snapshot_or_checkpoint",
                "collect_logs",
                "collect_artifacts",
                "stop",
                "cleanup",
            ]
        );
        assert_eq!(exec.exit_code, Some(0));
        assert_eq!(
            checkpoint.checkpoint_id.as_deref(),
            Some("checkpoint-instance-run-1")
        );
        assert_eq!(logs.lines, vec!["instance-run-1 started"]);
        assert_eq!(artifacts.artifacts[0].id, "artifact-instance-run-1");
        assert_eq!(stopped.evidence.outcome, "stopped:completed");
        assert_eq!(cleanup.evidence.outcome, "cleaned_up");
        assert_eq!(cleanup.evidence.agent_worker_id, "agent-worker-test-1");
        assert_eq!(
            cleanup.evidence.isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        assert!(!cleanup.evidence.network_policy.direct_public_egress);
    }

    #[test]
    fn fake_backend_reports_explicit_provision_and_cleanup_failures() {
        let mut prepare_failure = FakeIsolationBackend::new("agent-worker-test-1");
        prepare_failure.fail_prepare = true;

        let error = prepare_failure
            .prepare(prepare_request(IsolationPolicy::default()))
            .unwrap_err();

        assert!(matches!(error, IsolationError::Backend(_)));
        assert!(error.to_string().contains("prepare failed"));
        assert_eq!(prepare_failure.calls, vec!["prepare"]);

        let mut cleanup_failure = FakeIsolationBackend::new("agent-worker-test-1");
        let prepared = cleanup_failure
            .prepare(prepare_request(IsolationPolicy::default()))
            .unwrap();
        let started = cleanup_failure.start(prepared).unwrap();
        cleanup_failure.fail_cleanup = true;

        let error = cleanup_failure.cleanup(&started.instance_id).unwrap_err();

        assert!(matches!(error, IsolationError::Backend(_)));
        assert!(error.to_string().contains("cleanup failed"));
        assert_eq!(cleanup_failure.calls, vec!["prepare", "start", "cleanup"]);
    }

    #[test]
    fn fake_backend_failure_evidence_marks_failure_reason() {
        let mut backend = FakeIsolationBackend::new("agent-worker-test-1");
        let prepared = backend
            .prepare(prepare_request(IsolationPolicy::default()))
            .unwrap();
        let started = backend.start(prepared).unwrap();

        let evidence = backend.failure_evidence(Some(&started.instance_id), "timeout");

        assert_eq!(evidence.outcome, "failed");
        assert_eq!(evidence.failure_reason.as_deref(), Some("timeout"));
        assert_eq!(
            evidence.isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        assert_eq!(evidence.agent_worker_id, "agent-worker-test-1");
    }

    fn prepare_request(policy: IsolationPolicy) -> IsolationPrepareRequest {
        IsolationPrepareRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            worker_template_id: "template-1".to_string(),
            framework_adapter: "codex".to_string(),
            capability_envelope_id: "cap-1".to_string(),
            policy,
        }
    }

    fn descriptor(backend_name: &str, kind: IsolationBackendKind) -> IsolationBackendDescriptor {
        IsolationBackendDescriptor {
            backend_name: backend_name.to_string(),
            backend_version: "test-1".to_string(),
            kind,
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            capabilities: IsolationBackendCapabilities::full(),
        }
    }

    struct FakeIsolationBackend {
        descriptor: IsolationBackendDescriptor,
        agent_worker_id: String,
        policy: Option<IsolationPolicy>,
        capability_envelope_id: Option<String>,
        calls: Vec<&'static str>,
        fail_prepare: bool,
        fail_start: bool,
        fail_cleanup: bool,
    }

    impl FakeIsolationBackend {
        fn new(agent_worker_id: &str) -> Self {
            Self {
                descriptor: descriptor("fake-microvm", IsolationBackendKind::FirecrackerMicroVm),
                agent_worker_id: agent_worker_id.to_string(),
                policy: None,
                capability_envelope_id: None,
                calls: Vec::new(),
                fail_prepare: false,
                fail_start: false,
                fail_cleanup: false,
            }
        }

        fn evidence(&self, instance_id: Option<&str>, outcome: &str) -> IsolationLifecycleEvidence {
            let policy = self.policy.clone().expect("test backend prepared policy");
            IsolationLifecycleEvidence {
                backend_name: self.descriptor.backend_name.clone(),
                backend_version: self.descriptor.backend_version.clone(),
                agent_worker_id: self.agent_worker_id.clone(),
                isolation_instance_id: instance_id.map(ToOwned::to_owned),
                resource_limits: policy.resource_limits,
                network_policy: policy.network_policy,
                filesystem_policy: policy.filesystem_policy,
                capability_envelope_id: self
                    .capability_envelope_id
                    .clone()
                    .expect("test backend prepared capability envelope"),
                outcome: outcome.to_string(),
                failure_reason: None,
            }
        }

        fn failure_evidence(
            &self,
            instance_id: Option<&str>,
            reason: &str,
        ) -> IsolationLifecycleEvidence {
            let mut evidence = self.evidence(instance_id, "failed");
            evidence.failure_reason = Some(reason.to_string());
            evidence
        }
    }

    impl IsolationBackendLifecycle for FakeIsolationBackend {
        fn descriptor(&self) -> &IsolationBackendDescriptor {
            &self.descriptor
        }

        fn prepare(
            &mut self,
            request: IsolationPrepareRequest,
        ) -> IsolationResult<IsolationPrepared> {
            request.policy.validate()?;
            self.calls.push("prepare");
            self.policy = Some(request.policy);
            self.capability_envelope_id = Some(request.capability_envelope_id);
            if self.fail_prepare {
                return Err(IsolationError::Backend(
                    "prepare failed in fake backend".to_string(),
                ));
            }
            Ok(IsolationPrepared {
                prepared_id: format!("prepared-{}", request.run_id),
                evidence: self.evidence(None, "prepared"),
            })
        }

        fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted> {
            self.calls.push("start");
            if self.fail_start {
                return Err(IsolationError::Backend(
                    "start failed in fake backend".to_string(),
                ));
            }
            let instance_id = prepared.prepared_id.replacen("prepared", "instance", 1);
            Ok(IsolationStarted {
                instance_id: instance_id.clone(),
                evidence: self.evidence(Some(&instance_id), "started"),
            })
        }

        fn exec_or_attach(
            &mut self,
            request: IsolationExecRequest,
        ) -> IsolationResult<IsolationExecOutcome> {
            self.calls.push("exec_or_attach");
            Ok(IsolationExecOutcome {
                instance_id: request.instance_id.clone(),
                exit_code: Some(0),
                message: format!("executed {}", request.workload_ref),
                evidence: self.evidence(Some(&request.instance_id), "executed"),
            })
        }

        fn stop(
            &mut self,
            instance_id: &str,
            reason: &str,
        ) -> IsolationResult<IsolationStopOutcome> {
            self.calls.push("stop");
            Ok(IsolationStopOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(Some(instance_id), &format!("stopped:{reason}")),
            })
        }

        fn snapshot_or_checkpoint(
            &mut self,
            instance_id: &str,
        ) -> IsolationResult<IsolationSnapshotOutcome> {
            self.calls.push("snapshot_or_checkpoint");
            Ok(IsolationSnapshotOutcome {
                instance_id: instance_id.to_string(),
                checkpoint_id: Some(format!("checkpoint-{instance_id}")),
                evidence: self.evidence(Some(instance_id), "checkpointed"),
            })
        }

        fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs> {
            self.calls.push("collect_logs");
            Ok(CollectedIsolationLogs {
                instance_id: instance_id.to_string(),
                lines: vec![format!("{instance_id} started")],
                evidence: self.evidence(Some(instance_id), "logs_collected"),
            })
        }

        fn collect_artifacts(
            &mut self,
            instance_id: &str,
        ) -> IsolationResult<CollectedIsolationArtifacts> {
            self.calls.push("collect_artifacts");
            Ok(CollectedIsolationArtifacts {
                instance_id: instance_id.to_string(),
                artifacts: vec![IsolationArtifact {
                    id: format!("artifact-{instance_id}"),
                    path: "/workspace/result.txt".to_string(),
                    content_type: Some("text/plain".to_string()),
                }],
                evidence: self.evidence(Some(instance_id), "artifacts_collected"),
            })
        }

        fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome> {
            self.calls.push("cleanup");
            if self.fail_cleanup {
                return Err(IsolationError::Backend(
                    "cleanup failed in fake backend".to_string(),
                ));
            }
            Ok(IsolationCleanupOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(Some(instance_id), "cleaned_up"),
            })
        }
    }
}
