// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

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
fn capability_free_backend_is_never_selectable() {
    let mut inert = descriptor("kata", IsolationBackendKind::KataContainers);
    inert.capabilities = IsolationBackendCapabilities::none();
    let candidates = vec![inert];

    let error = select_isolation_backend(&IsolationPolicy::default(), &candidates).unwrap_err();

    assert!(matches!(error, IsolationError::NoCompatibleBackend(_)));
    assert!(
        !IsolationBackendCapabilities::none().supports(&IsolationBackendCapabilities::default())
    );
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

    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared> {
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

    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome> {
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
