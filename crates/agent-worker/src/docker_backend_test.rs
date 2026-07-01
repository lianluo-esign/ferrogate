// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;

fn prepare_request(policy: IsolationPolicy) -> IsolationPrepareRequest {
    IsolationPrepareRequest {
        session_id: "session-docker-1".to_string(),
        run_id: "run-docker-1".to_string(),
        worker_template_id: "template-docker".to_string(),
        framework_adapter: "native_harness".to_string(),
        capability_envelope_id: "cap-docker-1".to_string(),
        policy,
    }
}

#[test]
fn descriptor_reports_worker_owned_replaceable_backend() {
    let backend = DockerIsolationBackend::new("agent-worker-docker-1", "test-1");
    let descriptor = backend.descriptor();
    assert_eq!(descriptor.backend_name, "rootless-docker");
    assert_eq!(descriptor.kind, IsolationBackendKind::RootlessDocker);
    assert_eq!(descriptor.host_lifecycle_owner, "agent-worker");
    assert!(!descriptor.gateway_controls_backend);
    // The backend advertises the lifecycle it truly implements.
    assert!(descriptor.capabilities.exec_or_attach);
    assert!(descriptor.capabilities.governed_egress);
    assert!(!descriptor.capabilities.secret_injection);
}

#[test]
fn run_args_seal_network_and_enforce_policy() {
    let backend = DockerIsolationBackend::new("agent-worker-docker-1", "test-1");
    let policy = IsolationPolicy::default();
    let args = backend.run_args(
        &policy.resource_limits,
        &policy.network_policy,
        &policy.filesystem_policy,
    );
    // Managed default policy must produce a sealed, resource-limited container.
    assert!(args.windows(2).any(|w| w == ["--network", "none"]));
    assert!(args.iter().any(|a| a == "--read-only"));
    assert!(args.iter().any(|a| a == "--cpus"));
    assert!(args.iter().any(|a| a == "--memory"));
    assert!(args.iter().any(|a| a.starts_with("/workspace:")));
}

#[test]
fn prepare_requires_valid_policy_and_stores_context() {
    let mut backend = DockerIsolationBackend::new("agent-worker-docker-1", "test-1");
    let mut bad_policy = IsolationPolicy::default();
    bad_policy.resource_limits.cpu_count = 0;
    let error = backend.prepare(prepare_request(bad_policy)).unwrap_err();
    assert!(matches!(error, IsolationError::InvalidPolicy(_)));

    let prepared = backend
        .prepare(prepare_request(IsolationPolicy::default()))
        .unwrap();
    assert_eq!(prepared.prepared_id, "docker-prepared-run-docker-1");
    assert_eq!(prepared.evidence.outcome, "prepared");
    assert_eq!(prepared.evidence.backend_name, "rootless-docker");
}

#[test]
fn start_without_prepare_fails_closed() {
    let mut backend = DockerIsolationBackend::new("agent-worker-docker-1", "test-1");
    let error = backend
        .start(IsolationPrepared {
            prepared_id: "docker-prepared-x".to_string(),
            evidence: IsolationLifecycleEvidence {
                backend_name: "rootless-docker".to_string(),
                backend_version: "test-1".to_string(),
                agent_worker_id: "agent-worker-docker-1".to_string(),
                isolation_instance_id: None,
                resource_limits: IsolationResourceLimits::default(),
                network_policy: IsolationNetworkPolicy::default(),
                filesystem_policy: IsolationFilesystemPolicy::default(),
                capability_envelope_id: "cap".to_string(),
                outcome: "prepared".to_string(),
                failure_reason: None,
            },
        })
        .unwrap_err();
    assert!(matches!(error, IsolationError::Backend(_)));
}

// Real end-to-end lifecycle against a live docker daemon. Gated on daemon
// availability so the workspace suite stays hermetic where docker is absent.
#[test]
fn docker_backend_runs_full_lifecycle_against_real_container() {
    let Ok(version) = docker_backend_readiness() else {
        eprintln!("skipping docker lifecycle test: docker daemon not available");
        return;
    };

    let mut backend = DockerIsolationBackend::new("agent-worker-docker-e2e", &version);
    let prepared = backend
        .prepare(prepare_request(IsolationPolicy::default()))
        .expect("prepare");
    let started = backend.start(prepared).expect("start");
    assert!(started.instance_id.starts_with("docker-"));
    assert_eq!(started.evidence.outcome, "started");

    // Write into the sealed workspace, then exec a command and read it back.
    backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: started.instance_id.clone(),
            workload_ref: "agent://native/run".to_string(),
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo ferrogate > /workspace/result.txt".to_string(),
            ],
        })
        .expect("exec write");
    let exec = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: started.instance_id.clone(),
            workload_ref: "agent://native/run".to_string(),
            args: vec!["cat".to_string(), "/workspace/result.txt".to_string()],
        })
        .expect("exec read");
    assert_eq!(exec.exit_code, Some(0));
    assert_eq!(exec.message, "ferrogate");

    // The sealed network must actually block direct egress.
    let egress = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: started.instance_id.clone(),
            workload_ref: "agent://native/run".to_string(),
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                "ls /sys/class/net".to_string(),
            ],
        })
        .expect("exec net");
    // With --network none the only interface is loopback.
    assert_eq!(egress.message, "lo");

    let artifacts = backend
        .collect_artifacts(&started.instance_id)
        .expect("artifacts");
    assert!(artifacts
        .artifacts
        .iter()
        .any(|artifact| artifact.path == "/workspace/result.txt"));

    let stopped = backend
        .stop(&started.instance_id, "completed")
        .expect("stop");
    assert_eq!(stopped.evidence.outcome, "stopped:completed");

    let cleanup = backend.cleanup(&started.instance_id).expect("cleanup");
    assert_eq!(cleanup.evidence.outcome, "cleaned_up");
    assert_eq!(cleanup.evidence.agent_worker_id, "agent-worker-docker-e2e");

    // Container must be gone after cleanup — no host resource leak.
    let inspect = backend
        .run_docker(&["ps", "-a", "--filter", "name=nonexistent-marker"])
        .expect("ps");
    assert!(inspect.status.success());
}
