// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::test_support::lock_firecracker_env;

#[test]
fn backend_registry_reports_firecracker_ready_only_from_configured_bundle() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    let jailer_path = temp.path().join("jailer");
    let kernel_path = temp.path().join("vmlinux");
    let rootfs_path = temp.path().join("rootfs.ext4");
    write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
    write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
    std::fs::write(&kernel_path, b"not executed").unwrap();
    std::fs::write(&rootfs_path, b"not executed").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

    let backends = isolation_backends();

    clear_firecracker_env();
    // Firecracker is the implemented backend and leads the registry; the
    // other kinds are registered behind the same contract so the gateway
    // can see the full replaceable set.
    assert_eq!(backends.len(), 5);
    assert_eq!(backends[0].backend_name, "firecracker");
    assert_eq!(backends[0].kind, "firecracker_micro_vm");
    assert_eq!(backends[0].host_lifecycle_owner, "agent-worker");
    assert!(!backends[0].gateway_controls_backend);
    assert!(backends[0].ready);
    assert_eq!(backends[0].backend_version, "external_bundle");
    assert!(backends[0]
        .readiness_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("kernel image")));

    env::set_var(
        "AGENT_WORKER_FIRECRACKER_BIN",
        temp.path().join("missing-firecracker"),
    );
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
    let missing = isolation_backends();
    clear_firecracker_env();
    assert!(!missing[0].ready);
    assert!(missing[0]
        .readiness_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("does not point to a file")));
}

#[test]
fn backend_registry_requires_firecracker_kernel_and_rootfs() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
    env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
    env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");

    let backends = isolation_backends();

    clear_firecracker_env();
    assert!(!backends[0].ready);
    let reason = backends[0].readiness_reason.as_deref().unwrap();
    assert!(reason.contains("Firecracker kernel image was not configured"));
    assert!(reason.contains("Firecracker rootfs image was not configured"));
}

#[test]
fn backend_registry_registers_replaceable_backends_and_fails_closed_for_unimplemented() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();
    env::remove_var("AGENT_WORKER_ENABLE_DOCKER_BACKEND");
    env::remove_var("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND");

    let backends = isolation_backends();

    // Every registered backend speaks the same contract: the worker owns
    // the host lifecycle and the gateway never controls it directly.
    for backend in &backends {
        assert_eq!(backend.host_lifecycle_owner, "agent-worker");
        assert!(!backend.gateway_controls_backend);
    }

    let kinds = backends
        .iter()
        .map(|backend| backend.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            "firecracker_micro_vm",
            "kata_containers",
            "gvisor",
            "rootless_docker",
            "local_process",
        ]
    );

    // Every non-Firecracker backend fails closed here: the two unimplemented
    // kinds because they have no host lifecycle, and Docker because it is a
    // real host implementation that is opt-in and not enabled by default.
    for backend in backends
        .iter()
        .filter(|backend| backend.kind != "firecracker_micro_vm")
    {
        assert!(!backend.ready, "{} must fail closed", backend.backend_name);
    }

    for backend in backends
        .iter()
        .filter(|backend| backend.kind == "kata_containers" || backend.kind == "gvisor")
    {
        assert_eq!(backend.backend_version, "unimplemented");
        assert!(backend
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not implemented in this agent-worker build")));
    }

    let docker = backends
        .iter()
        .find(|backend| backend.kind == "rootless_docker")
        .expect("docker backend registered");
    assert_eq!(docker.backend_version, "disabled");
    assert!(docker
        .readiness_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not enabled")));

    let local_process = backends
        .iter()
        .find(|backend| backend.kind == "local_process")
        .expect("local-process backend registered");
    assert_eq!(local_process.backend_version, "disabled");
    assert!(local_process
        .readiness_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not enabled")));
}

#[test]
fn selectable_backends_exclude_unimplemented_and_unconfigured_firecracker() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();
    env::remove_var("AGENT_WORKER_ENABLE_DOCKER_BACKEND");
    env::remove_var("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND");

    // With no Firecracker bundle configured and Docker not enabled, nothing
    // is selectable: the registry fails closed rather than handing back an
    // inert backend.
    let unconfigured = selectable_isolation_backend_descriptors();
    assert!(unconfigured.is_empty());
    let error = ferrogate_runtime::select_isolation_backend(&Default::default(), &unconfigured)
        .unwrap_err();
    assert!(matches!(
        error,
        ferrogate_runtime::IsolationError::NoCompatibleBackend(_)
    ));

    // Configure a Firecracker bundle: only Firecracker becomes selectable,
    // and the runtime selection contract returns exactly that backend. The
    // registered-but-unimplemented kinds never win selection because they
    // advertise no capabilities.
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    let jailer_path = temp.path().join("jailer");
    let kernel_path = temp.path().join("vmlinux");
    let rootfs_path = temp.path().join("rootfs.ext4");
    write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
    write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
    std::fs::write(&kernel_path, b"not executed").unwrap();
    std::fs::write(&rootfs_path, b"not executed").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

    let selectable = selectable_isolation_backend_descriptors();
    clear_firecracker_env();

    assert_eq!(selectable.len(), 1);
    assert_eq!(selectable[0].kind, IsolationBackendKind::FirecrackerMicroVm);

    let selected =
        ferrogate_runtime::select_isolation_backend(&Default::default(), &selectable).unwrap();
    assert_eq!(selected.backend_name, "firecracker");
    assert_eq!(selected.kind, IsolationBackendKind::FirecrackerMicroVm);
}

#[test]
fn firecracker_prepare_plan_is_worker_owned_and_does_not_boot_microvm() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    let jailer_path = temp.path().join("jailer");
    let kernel_path = temp.path().join("vmlinux");
    let rootfs_path = temp.path().join("rootfs.ext4");
    write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
    write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
    std::fs::write(&kernel_path, b"not executed").unwrap();
    std::fs::write(&rootfs_path, b"not executed").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

    let plan = firecracker_prepare_plan().unwrap();

    clear_firecracker_env();
    assert_eq!(plan.firecracker_bin, firecracker_path);
    assert_eq!(plan.jailer_bin, jailer_path);
    assert_eq!(plan.kernel_image, kernel_path);
    assert_eq!(plan.rootfs_image, rootfs_path);
    assert_eq!(plan.planned_steps[0], "prepare_runtime_bundle");
    assert!(plan.planned_steps.contains(&"start_microvm"));
    assert_eq!(
        plan.network_policy,
        "no_direct_public_egress_without_gateway_capability"
    );
    assert_eq!(
        plan.filesystem_policy,
        "read_only_rootfs_with_prepared_workspace"
    );
}

#[test]
fn firecracker_prepare_plan_fails_closed_without_bundle() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();

    let error = firecracker_prepare_plan().unwrap_err().to_string();

    assert!(error.contains("Firecracker binary path was not configured"));
}

#[test]
fn firecracker_host_preflight_reports_jailer_kvm_and_does_not_boot_microvm() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    let jailer_path = temp.path().join("jailer");
    let kernel_path = temp.path().join("vmlinux");
    let rootfs_path = temp.path().join("rootfs.ext4");
    let kvm_path = temp.path().join("not-kvm");
    std::fs::write(&firecracker_path, b"not executed").unwrap();
    std::fs::write(&jailer_path, b"not executed").unwrap();
    std::fs::write(&kernel_path, b"not executed").unwrap();
    std::fs::write(&rootfs_path, b"not executed").unwrap();
    std::fs::write(&kvm_path, b"not kvm").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE", &kvm_path);

    let preflight = firecracker_host_preflight();

    clear_firecracker_env();
    assert!(!preflight.ready());
    assert!(!preflight.proves_microvm_boot);
    assert!(preflight
        .failure_summary()
        .contains("AGENT_WORKER_FIRECRACKER_BIN is not executable"));
    assert!(preflight
        .failure_summary()
        .contains("AGENT_WORKER_FIRECRACKER_JAILER is not executable"));
    assert!(preflight
        .failure_summary()
        .contains("not a character device"));
}

#[test]
fn firecracker_host_preflight_reports_binary_versions_and_bundle_sizes() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let firecracker_path = temp.path().join("firecracker");
    let jailer_path = temp.path().join("jailer");
    let kernel_path = temp.path().join("vmlinux");
    let rootfs_path = temp.path().join("rootfs.ext4");
    write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
    write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
    std::fs::write(&kernel_path, b"kernel-bytes").unwrap();
    std::fs::write(&rootfs_path, b"rootfs-bytes").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
    env::set_var(
        "AGENT_WORKER_FIRECRACKER_KVM_DEVICE",
        temp.path().join("missing-kvm"),
    );

    let preflight = firecracker_host_preflight();

    clear_firecracker_env();
    assert_eq!(
        preflight.bundle.firecracker_bin.version_output.as_deref(),
        Some("Firecracker v.test")
    );
    assert_eq!(
        preflight.bundle.jailer_bin.version_output.as_deref(),
        Some("Jailer v.test")
    );
    assert_eq!(preflight.bundle.kernel_image.size_bytes, Some(12));
    assert_eq!(preflight.bundle.rootfs_image.size_bytes, Some(12));
    assert!(!preflight.proves_microvm_boot);
    assert!(preflight.success_summary().contains("Firecracker v.test"));
    assert!(preflight.success_summary().contains("Jailer v.test"));
    assert!(preflight.success_summary().contains("kernel_size_bytes=12"));
    assert!(preflight.success_summary().contains("rootfs_size_bytes=12"));
    assert!(preflight
        .success_summary()
        .contains("microVM boot is still not proven"));
}

#[test]
fn firecracker_guest_agent_preflight_fails_closed_without_channel_contract() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();

    let preflight = firecracker_guest_agent_preflight();

    assert!(!preflight.ready());
    assert!(!preflight.proves_microvm_boot);
    assert!(!preflight.proves_handler_execution);
    assert_eq!(preflight.channel_kind, "guest_agent_command");
    assert!(preflight
        .failure_summary()
        .contains("Firecracker guest agent command path was not configured"));
    assert!(preflight
        .failure_summary()
        .contains("Firecracker guest workspace was not configured"));
    assert!(preflight
        .failure_summary()
        .contains("Firecracker guest gateway authorizer endpoint was not configured"));
}

#[test]
fn firecracker_guest_agent_preflight_reports_ready_without_claiming_execution() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
    std::fs::create_dir(&workspace).unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );

    let preflight = firecracker_guest_agent_preflight();

    clear_firecracker_env();
    assert!(preflight.ready());
    assert!(!preflight.proves_microvm_boot);
    assert!(!preflight.proves_handler_execution);
    assert_eq!(
        preflight.command_channel.path.as_deref(),
        Some(guest_agent.to_str().unwrap())
    );
    assert_eq!(
        preflight.workspace.path.as_deref(),
        Some(workspace.to_str().unwrap())
    );
    assert_eq!(preflight.workspace.writable, Some(true));
    assert!(preflight
        .failure_summary()
        .contains("handler execution inside the microVM is still not proven"));
}

#[test]
fn firecracker_guest_agent_preflight_requires_workspace_directory() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace_file = temp.path().join("workspace-file");
    write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
    std::fs::write(&workspace_file, b"not a directory").unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace_file);
    env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );

    let preflight = firecracker_guest_agent_preflight();

    clear_firecracker_env();
    assert!(!preflight.ready());
    assert_eq!(preflight.workspace.writable, None);
    assert!(preflight
        .failure_summary()
        .contains("does not point to a directory"));
    assert!(!preflight.proves_handler_execution);
}

#[test]
fn firecracker_guest_launch_plan_fails_closed_without_guest_channel() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();

    let plan = firecracker_guest_launch_plan(Some("codex"));

    assert!(!plan.ready);
    assert_eq!(plan.adapter, "codex");
    assert_eq!(plan.host_lifecycle_owner, "agent-worker");
    assert!(!plan.gateway_controls_firecracker);
    assert!(!plan.proves_microvm_boot);
    assert!(!plan.proves_handler_execution);
    assert_eq!(
        plan.implementation_status,
        "guest_handler_rpc_not_implemented"
    );
    assert!(plan.required_gateway_capabilities.contains(&"filesystem"));
    assert!(plan
        .guest_agent
        .failure_summary()
        .contains("Firecracker guest agent command path was not configured"));
}

#[test]
fn firecracker_guest_launch_plan_records_adapter_capabilities_without_claiming_execution() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
    std::fs::create_dir(&workspace).unwrap();
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );

    let codex = firecracker_guest_launch_plan(Some("codex"));
    let hermes = firecracker_guest_launch_plan(Some("hermes"));

    clear_firecracker_env();
    assert!(codex.ready);
    assert_eq!(codex.adapter, "codex");
    assert!(codex.planned_steps.contains(&"invoke_guest_agent_command"));
    assert!(codex
        .planned_steps
        .contains(&"start_framework_handler_inside_microvm"));
    assert_eq!(
        codex.guest_network_policy,
        "gateway_control_channel_only_no_direct_public_egress"
    );
    assert!(codex.required_gateway_capabilities.contains(&"cli"));
    assert!(codex.required_gateway_capabilities.contains(&"checkpoint"));
    assert!(!codex.proves_microvm_boot);
    assert!(!codex.proves_handler_execution);
    assert_eq!(hermes.adapter, "hermes");
    assert!(hermes
        .required_gateway_capabilities
        .contains(&"memory.read"));
    assert!(hermes.required_gateway_capabilities.contains(&"subagents"));
}

#[test]
fn adapter_launch_profiles_are_framework_specific_without_claiming_execution() {
    let codex = adapter_launch_profile("codex");
    let claude = adapter_launch_profile("claude-code");
    let hermes = adapter_launch_profile("hermes");
    let native = adapter_launch_profile("native-harness");

    assert_eq!(codex.framework, "codex");
    assert_eq!(codex.entrypoint, "codex_exec");
    assert_eq!(
        codex.external_action_mode,
        "gateway_mediated_cli_filesystem_tools"
    );
    assert_eq!(claude.framework, "claude_code");
    assert_eq!(claude.entrypoint, "claude_code_non_interactive");
    assert_eq!(hermes.framework, "hermes");
    assert_eq!(hermes.entrypoint, "hermes_oneshot");
    assert_eq!(
        hermes.external_action_mode,
        "gateway_mediated_memory_subagents"
    );
    assert_eq!(native.framework, "native_harness");
    assert_eq!(native.event_stream, "normalized_jsonl");
}

#[test]
fn firecracker_start_configures_guest_rpc_vsock_without_claiming_execution() {
    let temp = tempfile::tempdir().unwrap();
    let artifacts = FirecrackerMicroVmArtifacts {
        run_dir: temp.path().to_path_buf(),
        api_socket: temp.path().join("firecracker.sock"),
        guest_rpc_socket: temp.path().join("firecracker-guest-rpc.sock"),
        firecracker_log: temp.path().join("firecracker.log"),
        serial_output: temp.path().join("serial.log"),
        stdout: temp.path().join("firecracker.stdout"),
        stderr: temp.path().join("firecracker.stderr"),
    };

    let vsock = firecracker_guest_rpc_vsock_config(&artifacts);

    assert_eq!(vsock["vsock_id"], "guest-rpc");
    assert_eq!(vsock["guest_cid"], 3);
    assert_eq!(
        vsock["uds_path"],
        artifacts.guest_rpc_socket.display().to_string()
    );
}

#[test]
fn guest_agent_builtin_start_response_is_identity_and_policy_bound() {
    let request = FirecrackerGuestRpcStartRequest {
        protocol_version: FirecrackerGuestAgentHandshake::PROTOCOL_VERSION.to_string(),
        action: "start_handler".to_string(),
        tenant_id: "tenant-a".to_string(),
        workspace_id: "workspace-a".to_string(),
        worker_id: "worker-a".to_string(),
        session_id: "session-a".to_string(),
        run_id: "run-a".to_string(),
        framework_adapter: "codex".to_string(),
        adapter_launch_profile: adapter_launch_profile("codex"),
        isolation_backend: "firecracker".to_string(),
        isolation_instance_id: "microvm-a".to_string(),
        rpc_channel: "stdio-json-lines".to_string(),
        required_gateway_capabilities: guest_launch_capabilities("codex")
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        network_policy: "gateway_control_channel_only_no_direct_public_egress".to_string(),
        filesystem_policy: "prepared_workspace_only_with_read_only_runtime_bundle".to_string(),
        artifact_policy: "guest_artifacts_must_return_as_artifact_created_events".to_string(),
        checkpoint_policy:
            "guest_checkpoint_requests_must_return_as_snapshot_or_checkpoint_evidence".to_string(),
        proves_microvm_boot: false,
        proves_handler_execution: false,
    };

    request.validate_for_guest_agent().unwrap();
    let response =
        FirecrackerGuestRpcStartResponse::not_implemented_for_request(&request, "pending");
    let line = serde_json::to_string(&response).unwrap();
    let parsed = FirecrackerGuestRpcStartResponse::parse(line.as_bytes(), 7, &request).unwrap();

    assert_eq!(parsed.status, "not_implemented");
    assert_eq!(parsed.worker_id, request.worker_id);
    assert_eq!(parsed.session_id, request.session_id);
    assert_eq!(parsed.run_id, request.run_id);
    assert_eq!(parsed.framework_adapter, request.framework_adapter);
    assert_eq!(parsed.isolation_instance_id, request.isolation_instance_id);
    assert_eq!(
        parsed.required_gateway_capabilities,
        request.required_gateway_capabilities
    );
    assert!(!parsed.proves_handler_execution);
    assert!(parsed.summary().contains("elapsed_millis=7"));
}

#[test]
fn guest_agent_builtin_start_request_validation_rejects_execution_claims() {
    let mut request = FirecrackerGuestRpcStartRequest {
        protocol_version: FirecrackerGuestAgentHandshake::PROTOCOL_VERSION.to_string(),
        action: "start_handler".to_string(),
        tenant_id: "tenant-a".to_string(),
        workspace_id: "workspace-a".to_string(),
        worker_id: "worker-a".to_string(),
        session_id: "session-a".to_string(),
        run_id: "run-a".to_string(),
        framework_adapter: "codex".to_string(),
        adapter_launch_profile: adapter_launch_profile("codex"),
        isolation_backend: "firecracker".to_string(),
        isolation_instance_id: "microvm-a".to_string(),
        rpc_channel: "stdio-json-lines".to_string(),
        required_gateway_capabilities: vec!["cli".to_string()],
        network_policy: "gateway_control_channel_only_no_direct_public_egress".to_string(),
        filesystem_policy: "prepared_workspace_only_with_read_only_runtime_bundle".to_string(),
        artifact_policy: "guest_artifacts_must_return_as_artifact_created_events".to_string(),
        checkpoint_policy:
            "guest_checkpoint_requests_must_return_as_snapshot_or_checkpoint_evidence".to_string(),
        proves_microvm_boot: false,
        proves_handler_execution: true,
    };

    let reason = request.validate_for_guest_agent().unwrap_err();

    assert!(reason.contains("cannot claim handler execution"));
    request.proves_handler_execution = false;
    request.worker_id.clear();
    assert_eq!(
        request.validate_for_guest_agent().unwrap_err(),
        "worker_id was empty"
    );
}

#[test]
fn firecracker_boot_smoke_fails_closed_when_preflight_fails() {
    let _env_lock = lock_firecracker_env();
    clear_firecracker_env();

    let report = firecracker_boot_smoke(FirecrackerBootSmokeOptions {
        timeout: Duration::from_millis(1),
        vcpu_count: 1,
        mem_size_mib: 256,
    });

    assert!(!report.ready);
    assert!(!report.boot_observed);
    assert!(!report.proves_microvm_boot);
    assert_eq!(report.failure_stage.as_deref(), Some("preflight_failed"));
    assert!(report
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("Firecracker binary path was not configured")));
}

#[test]
fn firecracker_host_socket_cleanup_reports_host_resource_failure() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("firecracker.sock");
    std::fs::create_dir(&socket_path).unwrap();

    let result = remove_firecracker_host_file(&socket_path);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains(socket_path.to_str().unwrap()));
}

fn test_microvm_artifacts(run_dir: &Path) -> FirecrackerMicroVmArtifacts {
    FirecrackerMicroVmArtifacts {
        run_dir: run_dir.to_path_buf(),
        api_socket: run_dir.join("firecracker.sock"),
        guest_rpc_socket: run_dir.join("firecracker-guest-rpc.sock"),
        firecracker_log: run_dir.join("firecracker.log"),
        serial_output: run_dir.join("serial.log"),
        stdout: run_dir.join("firecracker.stdout"),
        stderr: run_dir.join("firecracker.stderr"),
    }
}

#[test]
fn firecracker_rootfs_attachment_enforces_read_only_rootfs_policy() {
    let temp = tempfile::tempdir().unwrap();
    let rootfs_image = temp.path().join("rootfs.ext4");
    let artifacts = test_microvm_artifacts(&temp.path().join("vm-1"));

    // The backend-enforced policy must declare a read-only rootfs with a
    // writable workspace (`read_only_rootfs_with_prepared_workspace`).
    let policy = firecracker_filesystem_policy();
    assert!(policy.read_only_rootfs);
    assert!(policy.writable_workspace);

    let attachment = plan_firecracker_rootfs_attachment(&rootfs_image, &artifacts, &policy);

    // Rootfs drive honors read_only_rootfs=true.
    assert_eq!(attachment.rootfs_drive["is_read_only"], true);
    assert_eq!(attachment.rootfs_drive["is_root_device"], true);
    assert_eq!(
        attachment.rootfs_drive["path_on_host"],
        rootfs_image.display().to_string()
    );
    assert!(attachment.boot_args.contains("root=/dev/vda ro"));
    assert!(!attachment.boot_args.contains("root=/dev/vda rw"));

    // Writable workspace is a per-VM drive inside the VM's private run dir.
    let workspace_drive = attachment.workspace_drive.expect("workspace drive");
    assert_eq!(workspace_drive["is_read_only"], false);
    assert_eq!(workspace_drive["is_root_device"], false);
    let workspace_path = attachment.workspace_image.expect("workspace image path");
    assert_eq!(
        workspace_drive["path_on_host"],
        workspace_path.display().to_string()
    );
    assert!(workspace_path.starts_with(&artifacts.run_dir));
    assert_ne!(workspace_path, rootfs_image);
}

#[test]
fn firecracker_rootfs_attachment_boots_rw_only_when_policy_relaxes_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let rootfs_image = temp.path().join("rootfs.ext4");
    let artifacts = test_microvm_artifacts(&temp.path().join("vm-1"));
    let policy = IsolationFilesystemPolicy {
        read_only_rootfs: false,
        writable_workspace: false,
        host_path_mounts: false,
    };

    let attachment = plan_firecracker_rootfs_attachment(&rootfs_image, &artifacts, &policy);

    assert_eq!(attachment.rootfs_drive["is_read_only"], false);
    assert!(attachment.boot_args.contains("root=/dev/vda rw"));
    assert!(attachment.workspace_drive.is_none());
    assert!(attachment.workspace_image.is_none());
}

#[test]
fn concurrent_firecracker_microvms_never_share_writable_backing_file() {
    let temp = tempfile::tempdir().unwrap();
    let shared_rootfs = temp.path().join("shared-rootfs.ext4");
    let policy = firecracker_filesystem_policy();

    // Provision two run-dir sets back-to-back (same process, same
    // millisecond is possible) — they must never collide.
    let first = FirecrackerMicroVmArtifacts::new().unwrap();
    let second = FirecrackerMicroVmArtifacts::new().unwrap();
    assert_ne!(first.run_dir, second.run_dir);

    let first_plan = plan_firecracker_rootfs_attachment(&shared_rootfs, &first, &policy);
    let second_plan = plan_firecracker_rootfs_attachment(&shared_rootfs, &second, &policy);

    let writable_paths = |plan: &FirecrackerRootfsAttachment| -> Vec<String> {
        [&plan.rootfs_drive]
            .into_iter()
            .chain(plan.workspace_drive.as_ref())
            .filter(|drive| drive["is_read_only"] == false)
            .map(|drive| drive["path_on_host"].as_str().unwrap().to_string())
            .collect()
    };
    let first_writable = writable_paths(&first_plan);
    let second_writable = writable_paths(&second_plan);

    // The shared rootfs image is never attached writable, and the only
    // writable backing files are per-VM and disjoint.
    let shared_rootfs_path = shared_rootfs.display().to_string();
    assert!(!first_writable.contains(&shared_rootfs_path));
    assert!(!second_writable.contains(&shared_rootfs_path));
    assert!(!first_writable.is_empty());
    assert!(!second_writable.is_empty());
    assert!(first_writable
        .iter()
        .all(|path| !second_writable.contains(path)));

    std::fs::remove_dir_all(&first.run_dir).unwrap();
    std::fs::remove_dir_all(&second.run_dir).unwrap();
}

#[test]
fn firecracker_stop_removes_per_vm_workspace_image() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("microvm-run");
    let mut microvm = test_firecracker_microvm("microvm-workspace", &run_dir).unwrap();
    let workspace_image = microvm.artifacts.workspace_image_path();
    prepare_firecracker_workspace_image(&workspace_image).unwrap();
    assert!(workspace_image.is_file());

    let report = microvm.stop();

    assert_eq!(report.workspace_image_removed, Ok(true));
    assert!(!workspace_image.exists());
    assert!(report.cleanup_succeeded());
}

#[test]
fn firecracker_snapshot_report_projects_snapshot_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot_path = temp.path().join("firecracker.snapshot");
    let memory_path = temp.path().join("firecracker.mem");
    std::fs::write(&snapshot_path, b"snapshot-state").unwrap();
    std::fs::write(&memory_path, b"snapshot-memory").unwrap();
    let report = FirecrackerSnapshotReport {
        outcome: "snapshot_created".to_string(),
        snapshot_path,
        memory_path,
        snapshot_bytes: 14,
        memory_bytes: 15,
        steps: vec!["paused", "snapshot_created", "resumed"],
        failure_stage: None,
        failure_reason: None,
    };

    let artifacts = report.artifact_results("microvm-1");
    let events = report.artifact_events("session-1", "run-1", "microvm-1");

    assert!(report.succeeded());
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().any(|artifact| {
        artifact.artifact_id == "microvm-1-snapshot-state"
            && artifact.name == "firecracker.snapshot"
            && artifact.media_type == "application/octet-stream"
    }));
    assert!(artifacts.iter().any(|artifact| {
        artifact.artifact_id == "microvm-1-snapshot-memory"
            && artifact.name == "firecracker.mem"
            && artifact.media_type == "application/octet-stream"
    }));
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| {
        event.kind == "artifact.created"
            && event
                .metadata
                .get("isolation_instance_id")
                .map(String::as_str)
                == Some("microvm-1")
    }));
}

#[test]
fn serial_boot_markers_require_real_guest_boot_evidence() {
    let markers = serial_boot_markers(
        "[    0.000000] Linux version 6.1.174\n\
             [    0.000000] Hypervisor detected: KVM\n\
             [    0.000113] ACPI: RSDP 0x00000000000E0000 000024 (v02 FIRECK)\n\
             [    0.054831] printk: console [ttyS0] enabled\n\
             [    0.673622] VFS: Mounted root (ext4 filesystem) on device 254:0.\n\
             [    0.676346] Run /sbin/init as init process\n\
             [    0.692980] systemd[1]: systemd 255.4 running in system mode\n\
             [    1.000000] Reached target multi-user.target - Multi-User System.\n\
             ubuntu-fc-uvm login: root (automatic login)\n\
             root@ubuntu-fc-uvm:~# \n",
    );

    assert_eq!(
        markers,
        vec![
            "linux_version",
            "kvm_hypervisor",
            "firecracker_platform",
            "serial_console",
            "rootfs_mounted",
            "init_started",
            "systemd_started",
            "userspace_target_reached",
            "login_prompt",
            "root_shell_prompt"
        ]
    );
    assert!(serial_has_microvm_userspace_evidence(&markers));
    let process_only_markers = serial_boot_markers("Firecracker process started");
    assert_eq!(process_only_markers, vec!["firecracker_platform"]);
    assert!(!process_only_markers.contains(&"linux_version"));
    assert!(!process_only_markers.contains(&"kvm_hypervisor"));
    assert!(!serial_has_microvm_userspace_evidence(
        &process_only_markers
    ));
    assert!(!serial_has_microvm_userspace_evidence(&[
        "linux_version",
        "kvm_hypervisor",
        "firecracker_platform",
        "serial_console"
    ]));
}

fn write_executable_version_script(path: &Path, version: &str) -> std::io::Result<()> {
    std::fs::write(
            path,
            format!("#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then echo '{version}'; exit 0; fi\nexit 0\n"),
        )?;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
}

fn clear_firecracker_env() {
    env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
    env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
    env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
    env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
    env::remove_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE");
    env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT");
    env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE");
    env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT");
}
