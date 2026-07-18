// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.
//! The full adversarial containment suite through the governed Agent action
//! path lives in `isolation_adversarial_test.rs`.

use super::*;
use crate::test_support::lock_firecracker_env;
use ferrogate_runtime::IsolationFilesystemPolicy;

#[test]
fn descriptor_declares_local_process_contract_and_never_outranks_real_backends() {
    let descriptor = local_process_backend_descriptor("unshare test-version");

    assert_eq!(descriptor.backend_name, "local-process");
    assert_eq!(descriptor.kind, IsolationBackendKind::LocalProcess);
    assert_eq!(descriptor.host_lifecycle_owner, "agent-worker");
    assert!(!descriptor.gateway_controls_backend);
    // Secret injection stays with the gateway-mediated path; the backend must
    // not claim it.
    assert!(!descriptor.capabilities.secret_injection);

    // The local-process tier is ranked strictly last: when any stronger real
    // backend (here Docker) is also selectable, selection never picks it.
    let docker = crate::docker_backend::docker_backend_descriptor("docker test-version");
    let candidates = vec![descriptor.clone(), docker.clone()];
    let selected =
        ferrogate_runtime::select_isolation_backend(&IsolationPolicy::default(), &candidates)
            .unwrap();
    assert_eq!(selected.kind, IsolationBackendKind::RootlessDocker);

    // Alone, it is selectable under the default managed policy.
    let only_local = vec![descriptor];
    let selected =
        ferrogate_runtime::select_isolation_backend(&IsolationPolicy::default(), &only_local)
            .unwrap();
    assert_eq!(selected.kind, IsolationBackendKind::LocalProcess);
}

#[test]
fn readiness_fails_closed_when_unshare_binary_is_missing() {
    let _env_lock = lock_firecracker_env();
    env::set_var(
        "AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN",
        "/nonexistent/ferrogate-unshare",
    );

    let error = local_process_backend_readiness().unwrap_err();

    env::remove_var("AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN");
    assert!(error.contains("fails closed"), "{error}");
    assert!(error.contains("/nonexistent/ferrogate-unshare"), "{error}");
}

#[test]
fn prepare_rejects_invalid_policy_before_touching_the_host() {
    let readiness = LocalProcessReadiness {
        unshare_bin: "/usr/bin/unshare".to_string(),
        sh_bin: "/bin/sh".to_string(),
        version: "unshare test-version".to_string(),
        namespaces: vec!["user", "mount", "pid", "net"],
    };
    let mut backend = LocalProcessIsolationBackend::new("worker-test", &readiness);
    let policy = IsolationPolicy {
        filesystem_policy: IsolationFilesystemPolicy {
            read_only_rootfs: true,
            writable_workspace: true,
            host_path_mounts: true,
        },
        ..IsolationPolicy::default()
    };

    let error = backend
        .prepare(IsolationPrepareRequest {
            session_id: "session".to_string(),
            run_id: "run".to_string(),
            worker_template_id: "template".to_string(),
            framework_adapter: "native_harness".to_string(),
            capability_envelope_id: "cap:session:run".to_string(),
            policy,
        })
        .unwrap_err();

    assert!(matches!(error, IsolationError::InvalidPolicy(_)), "{error}");
    // Nothing was prepared, so there is no workspace to leak.
    assert!(backend.workspace_dir().is_none());
}

#[test]
fn start_fails_closed_when_namespace_stack_becomes_unavailable_after_prepare() {
    let _env_lock = lock_firecracker_env();
    let readiness = LocalProcessReadiness {
        unshare_bin: "/usr/bin/unshare".to_string(),
        sh_bin: "/bin/sh".to_string(),
        version: "unshare test-version".to_string(),
        namespaces: vec!["user", "mount", "pid", "net"],
    };
    let mut backend = LocalProcessIsolationBackend::new("worker-test", &readiness);
    let prepared = backend
        .prepare(IsolationPrepareRequest {
            session_id: "session-lost-ns".to_string(),
            run_id: "run-lost-ns".to_string(),
            worker_template_id: "template".to_string(),
            framework_adapter: "native_harness".to_string(),
            capability_envelope_id: "cap:session:run".to_string(),
            policy: IsolationPolicy::default(),
        })
        .unwrap();

    // Simulate the host losing the namespace capability between prepare and
    // start: the start-time re-probe must refuse to run anything.
    env::set_var(
        "AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN",
        "/nonexistent/ferrogate-unshare",
    );
    let error = backend.start(prepared).unwrap_err();
    env::remove_var("AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN");

    assert!(matches!(error, IsolationError::Backend(_)), "{error}");
    assert!(error.to_string().contains("fails closed"), "{error}");
    assert!(!backend.is_running());
    assert!(backend.instance_id().is_none());

    // Cleanup removes the prepared workspace even after a refused start.
    let workspace = backend.workspace_dir().unwrap().to_path_buf();
    backend.cleanup("never-started").unwrap();
    assert!(!workspace.exists());
}
