// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::{
    backends::test_firecracker_microvm, state::AgentWorkerStateStore,
    test_support::lock_firecracker_env,
};
use ferrogate_runtime::{AgentWorkerManagementFrame, AgentWorkerUnixManagementClient};
use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::thread;
use std::{
    net::TcpStream,
    os::unix::net::{UnixListener, UnixStream},
};

#[test]
fn smoke_envelope_uses_signed_management_contract() {
    let envelope = smoke_envelope().unwrap();

    envelope.validate(1_000).unwrap();
    envelope
        .verify_shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    assert_eq!(envelope.action, AgentWorkerManagementAction::ProbeHandlers);
    assert_eq!(envelope.worker_id, "agent-worker-smoke");
    assert!(envelope.security.signature.starts_with("blake2b-mac:"));
}

#[test]
fn accepts_signed_management_json_from_gateway_contract() {
    let input = serde_json::to_string(&smoke_envelope().unwrap()).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["request_id"], "agent-worker-smoke-request");
    assert_eq!(response["action"], "probe_handlers");
    assert_eq!(response["result"]["kind"], "framework_handlers");
    assert_eq!(
        response["result"]["handlers"][0]["adapter_name"],
        "native-harness"
    );
    assert_eq!(
        response["result"]["handlers"][0]["framework"],
        "native_harness"
    );
    assert_eq!(response["error"], serde_json::Value::Null);
}

#[test]
fn rejects_management_json_with_wrong_secret_as_standard_response() {
    let input = serde_json::to_string(&smoke_envelope().unwrap()).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", "wrong-secret", 1_000).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], false);
    assert_eq!(response["request_id"], "agent-worker-smoke-request");
    assert_eq!(response["action"], "probe_handlers");
    assert_eq!(response["error"]["code"], "invalid_signature");
    assert_eq!(response["error"]["retryable"], false);
}

#[test]
fn rejects_management_json_with_unencrypted_channel_marker() {
    let mut envelope = smoke_envelope().unwrap();
    envelope.security.encrypted = false;
    envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], false);
    assert_eq!(response["error"]["code"], "transport_security_required");
    assert_eq!(response["error"]["retryable"], false);
}

#[test]
fn accepts_encrypted_management_frame_from_gateway_contract() {
    let mut envelope = smoke_envelope().unwrap();
    envelope.action = AgentWorkerManagementAction::ListBackends;
    envelope.request_id = "agent-worker-encrypted-frame-request".to_string();
    envelope.idempotency_key = "agent-worker-encrypted-frame-idempotency".to_string();
    envelope.security.nonce = "agent-worker-encrypted-frame-nonce".to_string();
    envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
    envelope.security.encrypted = true;
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let frame =
        AgentWorkerManagementFrame::encrypt_envelope(&envelope, SMOKE_SHARED_SECRET, [3; 24])
            .unwrap();
    let input = serde_json::to_string(&frame).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(
        response["request_id"],
        "agent-worker-encrypted-frame-request"
    );
    assert_eq!(response["action"], "list_backends");
    assert_eq!(response["tenant_id"], "smoke-tenant");
    assert_eq!(response["workspace_id"], "smoke-workspace");
    assert_eq!(response["worker_id"], "agent-worker-smoke");
    assert_eq!(response["result"]["kind"], "isolation_backends");
}

#[test]
fn accepts_encrypted_management_frame_over_http_contract() {
    let (addr, server) = spawn_http_management_server(1);

    let mut envelope = smoke_envelope().unwrap();
    envelope.action = AgentWorkerManagementAction::ListBackends;
    envelope.request_id = "agent-worker-http-frame-request".to_string();
    envelope.idempotency_key = "agent-worker-http-frame-idempotency".to_string();
    envelope.security.nonce = "agent-worker-http-frame-nonce".to_string();
    envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
    envelope.security.encrypted = true;
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let frame =
        AgentWorkerManagementFrame::encrypt_envelope(&envelope, SMOKE_SHARED_SECRET, [9; 24])
            .unwrap();
    let body = serde_json::to_string(&frame).unwrap();

    let response = send_http_management_request(addr, &body, "symmetric_aead");

    assert!(response.accepted);
    assert_eq!(response.request_id, "agent-worker-http-frame-request");
    assert_eq!(response.action, AgentWorkerManagementAction::ListBackends);
    assert!(matches!(
        response.result,
        Some(AgentWorkerManagementResult::IsolationBackends { .. })
    ));
    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 1);
    assert!(server_responses[0].accepted);
}

#[test]
fn routes_signed_provision_to_firecracker_lifecycle_branch_fail_closed() {
    let _env_lock = lock_firecracker_env();
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE");
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Provision,
        "agent-worker-provision",
    );
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], false);
    assert_eq!(response["request_id"], "agent-worker-provision-request");
    assert_eq!(response["action"], "provision");
    assert_eq!(response["error"]["code"], "incompatible_backend");
    assert_eq!(response["error"]["retryable"], false);
    assert!(response["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("Firecracker")));
}

#[test]
fn cleanup_lifecycle_action_returns_typed_noop_evidence_before_firecracker_start() {
    let envelope = lifecycle_envelope(AgentWorkerManagementAction::Cleanup, "agent-worker-cleanup");
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["action"], "cleanup");
    assert_eq!(response["result"]["kind"], "lifecycle");
    assert_eq!(
        response["result"]["lifecycle"]["session_id"],
        "agent-worker-cleanup-session"
    );
    assert_eq!(
        response["result"]["lifecycle"]["run_id"],
        "agent-worker-cleanup-run"
    );
    assert_eq!(response["result"]["lifecycle"]["status"], "cleaned_up");
    assert_eq!(
        response["result"]["lifecycle"]["backend_name"],
        "firecracker"
    );
    assert_eq!(response["result"]["lifecycle"]["outcome"], "not_started");
    assert_eq!(response["error"], serde_json::Value::Null);
}

#[test]
fn duplicate_lifecycle_request_replays_stored_result_without_new_event() {
    let first_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Cleanup,
        "agent-worker-dup-cleanup",
    );
    let mut duplicate_envelope = first_envelope.clone();
    duplicate_envelope.request_id = "agent-worker-dup-cleanup-retry-request".to_string();
    duplicate_envelope.security.nonce = "agent-worker-dup-cleanup-retry-nonce".to_string();
    duplicate_envelope.security.signature = duplicate_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();

    let first =
        accept_management_envelope(&mut transport, &mut state, &runtime, first_envelope, 1_000);
    let duplicate = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        duplicate_envelope,
        1_000,
    );

    assert!(first.accepted);
    assert!(duplicate.accepted);
    assert!(!first.duplicate_idempotency_key);
    assert!(duplicate.duplicate_idempotency_key);
    assert_eq!(
        duplicate.request_id,
        "agent-worker-dup-cleanup-retry-request"
    );
    assert_eq!(first.result, duplicate.result);
    assert_eq!(state.lifecycle_events().len(), 1);
}

#[test]
fn stream_status_lifecycle_action_reports_not_started_without_gateway_execution() {
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::StreamStatus,
        "agent-worker-status",
    );
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["action"], "stream_status");
    assert_eq!(response["result"]["kind"], "lifecycle");
    assert_eq!(response["result"]["lifecycle"]["status"], "failed");
    assert_eq!(response["result"]["lifecycle"]["outcome"], "not_started");
    assert_eq!(
        response["result"]["lifecycle"]["isolation_instance_id"],
        serde_json::Value::Null
    );
}

#[test]
fn exec_or_attach_without_microvm_provision_returns_lifecycle_evidence() {
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-native-run",
    );
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["action"], "exec_or_attach");
    assert_eq!(response["error"], serde_json::Value::Null);
    assert_eq!(response["result"]["kind"], "lifecycle");
    assert_eq!(response["result"]["lifecycle"]["status"], "failed");
    assert_eq!(response["result"]["lifecycle"]["outcome"], "not_started");
    assert!(response["result"]["lifecycle"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("before Firecracker microVM provision succeeds")));
}

#[test]
fn unix_management_exec_or_attach_reports_not_started_before_microvm_provision() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let socket_for_server = socket_path.clone();
    let server = thread::spawn(move || {
        serve_management_unix(
            &socket_for_server,
            "agent-worker-smoke-key",
            SMOKE_SHARED_SECRET,
            Some(1_000),
            1,
            None,
        )
        .unwrap()
    });

    wait_for_socket(&socket_path);
    let client = AgentWorkerUnixManagementClient::new(&socket_path);
    let exec = client
        .send_management_request(&shared_lifecycle_envelope(
            AgentWorkerManagementAction::ExecOrAttach,
            "agent-worker-native-socket",
            "exec",
        ))
        .unwrap();

    assert!(exec.accepted);
    assert_eq!(exec.error.as_ref().map(|error| error.code.as_str()), None);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(lifecycle.outcome, "not_started");

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 1);
    assert!(server_responses[0].accepted);
    assert!(!socket_path.exists());
}

#[test]
fn http_management_exec_or_attach_does_not_run_process_shim_before_microvm_provision() {
    let (addr, server) = spawn_http_management_server(2);

    let exec = send_http_management_request(
        addr,
        &serde_json::to_string(&shared_lifecycle_envelope_with_adapter(
            AgentWorkerManagementAction::ExecOrAttach,
            "agent-worker-native-http",
            "exec",
            "codex",
        ))
        .unwrap(),
        "mutual_tls",
    );
    let status = send_http_management_request(
        addr,
        &serde_json::to_string(&shared_lifecycle_envelope(
            AgentWorkerManagementAction::StreamStatus,
            "agent-worker-native-http",
            "status",
        ))
        .unwrap(),
        "mutual_tls",
    );

    assert!(exec.accepted);
    assert!(status.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(lifecycle.outcome, "not_started");
    assert_eq!(lifecycle.backend_name, "firecracker");
    assert!(lifecycle
        .message
        .contains("before Firecracker microVM provision succeeds"));
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "not_started");

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 2);
    assert!(server_responses.iter().all(|response| response.accepted));
}

#[test]
fn routes_signed_backend_listing_to_firecracker_registry_result() {
    let mut envelope = smoke_envelope().unwrap();
    envelope.action = AgentWorkerManagementAction::ListBackends;
    envelope.request_id = "agent-worker-list-backends-request".to_string();
    envelope.idempotency_key = "agent-worker-list-backends-idempotency".to_string();
    envelope.security.nonce = "agent-worker-list-backends-nonce".to_string();
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["request_id"], "agent-worker-list-backends-request");
    assert_eq!(response["action"], "list_backends");
    assert_eq!(response["result"]["kind"], "isolation_backends");
    assert_eq!(response["result"]["registry_implemented"], true);
    assert_eq!(
        response["result"]["backends"][0]["backend_name"],
        "firecracker"
    );
    assert_eq!(
        response["result"]["backends"][0]["kind"],
        "firecracker_micro_vm"
    );
    assert_eq!(response["error"], serde_json::Value::Null);
}

#[test]
fn accepts_signed_management_json_over_unix_socket_transport() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let socket_for_server = socket_path.clone();
    let server = thread::spawn(move || {
        serve_management_unix(
            &socket_for_server,
            "agent-worker-smoke-key",
            SMOKE_SHARED_SECRET,
            Some(1_000),
            1,
            None,
        )
        .unwrap()
    });

    wait_for_socket(&socket_path);
    let client = AgentWorkerUnixManagementClient::new(&socket_path);
    let response = client
        .send_management_request(&smoke_envelope().unwrap())
        .unwrap();

    assert!(response.accepted);
    assert_eq!(response.request_id, "agent-worker-smoke-request");
    assert_eq!(response.action, AgentWorkerManagementAction::ProbeHandlers);
    let Some(AgentWorkerManagementResult::FrameworkHandlers { handlers }) = response.result else {
        panic!("probe_handlers response did not include framework handler result");
    };
    assert!(handlers
        .iter()
        .any(|handler| handler.adapter_name == "native-harness" && handler.ready));
    assert!(response.error.is_none());

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 1);
    assert!(server_responses[0].accepted);
    assert_eq!(server_responses[0].request_id, "agent-worker-smoke-request");
    assert!(!socket_path.exists());
}

#[test]
fn unix_socket_server_keeps_verifier_state_across_connections() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let socket_for_server = socket_path.clone();
    let server = thread::spawn(move || {
        serve_management_unix(
            &socket_for_server,
            "agent-worker-smoke-key",
            SMOKE_SHARED_SECRET,
            Some(1_000),
            2,
            None,
        )
        .unwrap()
    });

    wait_for_socket(&socket_path);
    let client = AgentWorkerUnixManagementClient::new(&socket_path);
    let first = client
        .send_management_request(&smoke_envelope().unwrap())
        .unwrap();
    let replay = client
        .send_management_request(&smoke_envelope().unwrap())
        .unwrap();

    assert!(first.accepted);
    assert!(!replay.accepted);
    assert_eq!(
        replay.error.as_ref().map(|error| error.code.as_str()),
        Some("nonce_replay")
    );

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 2);
    assert!(server_responses[0].accepted);
    assert!(!server_responses[1].accepted);
    assert!(!socket_path.exists());
}

#[test]
fn unix_socket_server_replays_duplicate_idempotency_result_across_connections() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let socket_for_server = socket_path.clone();
    let server = thread::spawn(move || {
        serve_management_unix(
            &socket_for_server,
            "agent-worker-smoke-key",
            SMOKE_SHARED_SECRET,
            Some(1_000),
            2,
            None,
        )
        .unwrap()
    });

    wait_for_socket(&socket_path);
    let client = AgentWorkerUnixManagementClient::new(&socket_path);
    let first_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Cleanup,
        "agent-worker-socket-dup",
    );
    let mut duplicate_envelope = first_envelope.clone();
    duplicate_envelope.request_id = "agent-worker-socket-dup-retry-request".to_string();
    duplicate_envelope.security.nonce = "agent-worker-socket-dup-retry-nonce".to_string();
    duplicate_envelope.security.signature = duplicate_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();

    let first = client.send_management_request(&first_envelope).unwrap();
    let duplicate = client.send_management_request(&duplicate_envelope).unwrap();

    assert!(first.accepted);
    assert!(duplicate.accepted);
    assert!(!first.duplicate_idempotency_key);
    assert!(duplicate.duplicate_idempotency_key);
    assert_eq!(
        duplicate.request_id,
        "agent-worker-socket-dup-retry-request"
    );
    assert_eq!(first.result, duplicate.result);

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 2);
    assert!(server_responses[1].duplicate_idempotency_key);
    assert_eq!(server_responses[0].result, server_responses[1].result);
    assert!(!socket_path.exists());
}

#[test]
fn provision_records_failed_lifecycle_when_firecracker_bundle_is_configured() {
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
    std::env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE", &kvm_path);
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Provision,
        "agent-worker-configured-provision",
    );
    let input = serde_json::to_string(&envelope).unwrap();

    let response_json =
        accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
            .unwrap();
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["action"], "provision");
    assert_eq!(response["result"]["kind"], "lifecycle");
    assert_eq!(response["result"]["lifecycle"]["status"], "failed");
    assert_eq!(
        response["result"]["lifecycle"]["outcome"],
        "host_preflight_failed"
    );
    assert_eq!(
        response["result"]["lifecycle"]["backend_name"],
        "firecracker"
    );
    assert_eq!(
        response["result"]["lifecycle"]["backend_kind"],
        "firecracker_micro_vm"
    );
    // The recorded evidence carries the version of the backend that was
    // actually selected through the registry contract, not a constant.
    assert_eq!(
        response["result"]["lifecycle"]["backend_version"],
        "external_bundle"
    );
    assert!(response["result"]["lifecycle"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("host preflight failed")
            && message.contains("not a character device")));
    assert_eq!(response["error"], serde_json::Value::Null);
}

#[test]
fn docker_backend_provisions_and_execs_through_management_api_when_enabled() {
    let _env_lock = lock_firecracker_env();
    // No Firecracker bundle configured; enable the opt-in Docker tier so the
    // registry selects Docker through the same management contract.
    for var in [
        "AGENT_WORKER_FIRECRACKER_BIN",
        "AGENT_WORKER_FIRECRACKER_JAILER",
        "AGENT_WORKER_FIRECRACKER_KERNEL",
        "AGENT_WORKER_FIRECRACKER_ROOTFS",
        "AGENT_WORKER_FIRECRACKER_KVM_DEVICE",
    ] {
        std::env::remove_var(var);
    }
    std::env::set_var("AGENT_WORKER_ENABLE_DOCKER_BACKEND", "1");

    if crate::docker_backend::docker_backend_readiness().is_err() {
        std::env::remove_var("AGENT_WORKER_ENABLE_DOCKER_BACKEND");
        eprintln!("skipping docker management test: docker daemon not available");
        return;
    }

    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();

    let provision = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        shared_lifecycle_envelope(
            AgentWorkerManagementAction::Provision,
            "agent-worker-docker-api",
            "provision",
        ),
        1_000,
    );
    let exec = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        shared_lifecycle_envelope(
            AgentWorkerManagementAction::ExecOrAttach,
            "agent-worker-docker-api",
            "exec",
        ),
        1_000,
    );
    // Always clean up the real container before asserting so a failed assert
    // never leaks host resources.
    let cleanup = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        shared_lifecycle_envelope(
            AgentWorkerManagementAction::Cleanup,
            "agent-worker-docker-api",
            "cleanup",
        ),
        1_000,
    );
    std::env::remove_var("AGENT_WORKER_ENABLE_DOCKER_BACKEND");

    // Provision selected and ran the Docker backend, reported through the
    // exact same lifecycle wire result the Firecracker path uses.
    assert!(provision.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = &provision.result else {
        panic!(
            "expected provision lifecycle result, got {:?}",
            provision.result
        );
    };
    assert_eq!(lifecycle.backend_name, "rootless-docker");
    assert_eq!(lifecycle.backend_kind, "rootless_docker");
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Running
    );
    assert_eq!(lifecycle.outcome, "provisioned");
    assert!(lifecycle
        .isolation_instance_id
        .as_deref()
        .is_some_and(|id| id.starts_with("docker-")));

    // Exec ran a real command inside the container via the same contract.
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = &exec.result else {
        panic!("expected exec lifecycle result, got {:?}", exec.result);
    };
    assert_eq!(lifecycle.backend_name, "rootless-docker");
    assert_eq!(lifecycle.outcome, "executed");
    assert!(lifecycle.message.contains("agent-worker-docker-ready"));

    // Cleanup force-removed the container.
    assert!(cleanup.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = &cleanup.result else {
        panic!(
            "expected cleanup lifecycle result, got {:?}",
            cleanup.result
        );
    };
    assert_eq!(lifecycle.outcome, "cleaned_up");
}

#[test]
fn provision_failed_lifecycle_is_recorded_for_persistence_bridge() {
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
    std::env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE", &kvm_path);
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Provision,
        "agent-worker-recorded-provision",
    );
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();

    let response =
        accept_management_envelope(&mut transport, &mut state, &runtime, envelope, 1_000);
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE");

    assert!(response.accepted);
    assert_eq!(state.lifecycle_events().len(), 1);
    let event = &state.lifecycle_events()[0];
    assert_eq!(event.action, AgentWorkerManagementAction::Provision);
    assert_eq!(
        event.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(event.outcome, "host_preflight_failed");
    assert_eq!(event.isolation_instance_id, None);
}

#[test]
fn collect_artifacts_returns_retained_firecracker_artifact_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::CollectArtifacts,
        "agent-worker-firecracker-artifacts",
    );
    let session_id = envelope.session_id.clone().unwrap();
    let run_id = envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-test-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let response =
        accept_management_envelope(&mut transport, &mut state, &runtime, envelope, 1_000);

    assert!(response.accepted);
    assert_eq!(
        response.action,
        AgentWorkerManagementAction::CollectArtifacts
    );
    let Some(AgentWorkerManagementResult::HandlerArtifacts { artifacts, events }) = response.result
    else {
        panic!("collect_artifacts did not return Firecracker artifact manifest");
    };
    assert_eq!(artifacts.len(), 4);
    assert_eq!(events.len(), 4);
    assert!(artifacts.iter().any(|artifact| {
        artifact.artifact_id == "firecracker-test-instance-firecracker-log"
            && artifact.name == "firecracker.log"
            && artifact.byte_len > 0
    }));
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.name == "serial.log" && artifact.byte_len > 0));
    assert!(events.iter().all(|event| event.kind == "artifact.created"));
    assert!(events.iter().any(|event| {
        event
            .metadata
            .get("artifact_id")
            .is_some_and(|artifact_id| artifact_id == "firecracker-test-instance-firecracker-log")
            && event
                .metadata
                .get("isolation_instance_id")
                .is_some_and(|instance_id| instance_id == "firecracker-test-instance")
    }));
}

#[test]
fn stop_removes_retained_firecracker_microvm_from_worker_state() {
    let temp = tempfile::tempdir().unwrap();
    let stop_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Stop,
        "agent-worker-firecracker-stop",
    );
    let mut status_envelope = stop_envelope.clone();
    status_envelope.action = AgentWorkerManagementAction::StreamStatus;
    status_envelope.request_id = "agent-worker-firecracker-stop-status-request".to_string();
    status_envelope.idempotency_key =
        "agent-worker-firecracker-stop-status-idempotency".to_string();
    status_envelope.security.nonce = "agent-worker-firecracker-stop-status-nonce".to_string();
    status_envelope.security.signature = status_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let session_id = stop_envelope.session_id.clone().unwrap();
    let run_id = stop_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-stop-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let stop =
        accept_management_envelope(&mut transport, &mut state, &runtime, stop_envelope, 1_000);
    let status =
        accept_management_envelope(&mut transport, &mut state, &runtime, status_envelope, 1_000);

    assert!(stop.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = stop.result else {
        panic!("stop did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Cancelled
    );
    assert_eq!(lifecycle.outcome, "stopped");
    assert!(lifecycle.message.contains("process_outcome=killed"));
    assert!(lifecycle.message.contains("api_socket_removed=false"));
    assert!(lifecycle.message.contains("guest_rpc_socket_removed=false"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-stop-instance")
    );
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "not_started");
    assert_eq!(lifecycle.isolation_instance_id, None);
}

#[test]
fn cleanup_reports_failed_lifecycle_when_firecracker_host_resource_cleanup_fails() {
    let temp = tempfile::tempdir().unwrap();
    let cleanup_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::Cleanup,
        "agent-worker-firecracker-cleanup-failed",
    );
    let session_id = cleanup_envelope.session_id.clone().unwrap();
    let run_id = cleanup_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-cleanup-failed-instance", temp.path()).unwrap(),
    );
    std::fs::create_dir(temp.path().join("firecracker.sock")).unwrap();
    let runtime = AgentWorkerRuntime::default();

    let cleanup = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        cleanup_envelope,
        1_000,
    );

    assert!(cleanup.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = cleanup.result else {
        panic!("cleanup did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(lifecycle.outcome, "cleanup_failed");
    assert!(lifecycle.message.contains("process_outcome=killed"));
    assert!(lifecycle.message.contains("api_socket_remove_error="));
    assert!(lifecycle.message.contains("guest_rpc_socket_removed=false"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-cleanup-failed-instance")
    );
}

#[test]
fn exec_or_attach_reports_missing_guest_channel_without_stopping_microvm() {
    let _env_lock = lock_firecracker_env();
    clear_guest_agent_env();
    let temp = tempfile::tempdir().unwrap();
    let exec_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec",
    );
    let mut status_envelope = exec_envelope.clone();
    status_envelope.action = AgentWorkerManagementAction::StreamStatus;
    status_envelope.request_id = "agent-worker-firecracker-exec-status-request".to_string();
    status_envelope.idempotency_key =
        "agent-worker-firecracker-exec-status-idempotency".to_string();
    status_envelope.security.nonce = "agent-worker-firecracker-exec-status-nonce".to_string();
    status_envelope.security.signature = status_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);
    let status =
        accept_management_envelope(&mut transport, &mut state, &runtime, status_envelope, 1_000);

    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(lifecycle.outcome, "guest_agent_channel_unavailable");
    assert!(lifecycle
        .message
        .contains("Firecracker guest agent command path was not configured"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-instance")
    );
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "running");
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-instance")
    );
}

#[test]
fn snapshot_or_checkpoint_without_microvm_provision_returns_lifecycle_evidence() {
    let envelope = lifecycle_envelope(
        AgentWorkerManagementAction::SnapshotOrCheckpoint,
        "agent-worker-firecracker-snapshot-not-started",
    );
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();

    let response =
        accept_management_envelope(&mut transport, &mut state, &runtime, envelope, 1_000);

    assert!(response.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = response.result else {
        panic!("snapshot did not return lifecycle evidence");
    };
    assert_eq!(
        lifecycle.action,
        AgentWorkerManagementAction::SnapshotOrCheckpoint
    );
    assert_eq!(
        lifecycle.status,
        ferrogate_runtime::ManagedWorkerSessionStatus::Failed
    );
    assert_eq!(lifecycle.outcome, "not_started");
    assert_eq!(lifecycle.isolation_instance_id, None);
}

#[test]
fn snapshot_or_checkpoint_reports_firecracker_api_failure_without_stopping_microvm() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::SnapshotOrCheckpoint,
        "agent-worker-firecracker-snapshot",
    );
    let mut status_envelope = snapshot_envelope.clone();
    status_envelope.action = AgentWorkerManagementAction::StreamStatus;
    status_envelope.request_id = "agent-worker-firecracker-snapshot-status-request".to_string();
    status_envelope.idempotency_key =
        "agent-worker-firecracker-snapshot-status-idempotency".to_string();
    status_envelope.security.nonce = "agent-worker-firecracker-snapshot-status-nonce".to_string();
    status_envelope.security.signature = status_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let session_id = snapshot_envelope.session_id.clone().unwrap();
    let run_id = snapshot_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-snapshot-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let snapshot = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        snapshot_envelope,
        1_000,
    );
    let status =
        accept_management_envelope(&mut transport, &mut state, &runtime, status_envelope, 1_000);

    assert!(snapshot.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = snapshot.result else {
        panic!("snapshot did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "snapshot_failed");
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-snapshot-instance")
    );
    assert!(lifecycle.message.contains("failure_stage=pause_vm"));
    assert!(lifecycle.message.contains("firecracker_api_connect"));
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "running");
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-snapshot-instance")
    );
}

#[test]
fn exec_or_attach_reports_guest_rpc_gap_after_guest_agent_launch_probe() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_guest_agent_handshake_script(
        &guest_agent,
        &guest_start_not_implemented_response(
            "agent-worker-firecracker-exec-ready",
            "codex",
            "firecracker-exec-ready-instance",
        ),
    )
    .unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = shared_lifecycle_envelope_with_adapter(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-ready",
        "",
        "codex",
    );
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-ready-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_handler_rpc_not_implemented");
    assert!(lifecycle.message.contains("guest agent command launched"));
    assert!(lifecycle
        .message
        .contains("guest_rpc_channel=stdio-json-lines"));
    assert!(lifecycle
        .message
        .contains("guest_agent_version=ferrogate guest agent v.test"));
    assert!(lifecycle
        .message
        .contains("guest_rpc_start_request(protocol_version=ferrogate.agent-worker.guest.v1"));
    assert!(lifecycle.message.contains("worker_id=agent-worker-smoke"));
    assert!(lifecycle.message.contains("adapter=codex"));
    assert!(lifecycle.message.contains(
        "launch_profile=codex:codex_exec:normalized_jsonl:gateway_mediated_cli_filesystem_tools"
    ));
    assert!(lifecycle.message.contains("isolation_backend=firecracker"));
    assert!(lifecycle
        .message
        .contains("isolation_instance_id=firecracker-exec-ready-instance"));
    assert!(lifecycle
        .message
        .contains("required_gateway_capabilities=cli|filesystem|tools|artifacts|checkpoint"));
    assert!(lifecycle
        .message
        .contains("guest_rpc_start_response(status=not_implemented"));
    assert!(lifecycle.message.contains("action=start_handler"));
    assert!(lifecycle
        .message
        .contains("session_id=agent-worker-firecracker-exec-ready-session"));
    assert!(lifecycle
        .message
        .contains("run_id=agent-worker-firecracker-exec-ready-run"));
    assert!(lifecycle.message.contains(
        "launch_profile=codex:codex_exec:normalized_jsonl:gateway_mediated_cli_filesystem_tools"
    ));
    assert!(lifecycle
        .message
        .contains("required_gateway_capabilities=cli|filesystem|tools|artifacts|checkpoint"));
    assert!(lifecycle
        .message
        .contains("network_policy=gateway_control_channel_only_no_direct_public_egress"));
    assert!(lifecycle
        .message
        .contains("filesystem_policy=prepared_workspace_only_with_read_only_runtime_bundle"));
    assert!(lifecycle
        .message
        .contains("artifact_policy=guest_artifacts_must_return_as_artifact_created_events"));
    assert!(lifecycle.message.contains(
            "checkpoint_policy=guest_checkpoint_requests_must_return_as_snapshot_or_checkpoint_evidence"
        ));
    assert!(lifecycle.message.contains("proves_microvm_boot=false"));
    assert!(lifecycle.message.contains("proves_handler_execution=false"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-ready-instance")
    );
}

#[test]
fn exec_or_attach_can_send_guest_start_request_over_unix_json_lines_channel() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    let rpc_socket = temp.path().join("guest-rpc.sock");
    write_guest_agent_unix_rpc_handshake_script(&guest_agent, &rpc_socket).unwrap();
    std::fs::create_dir(&workspace).unwrap();
    let response = guest_start_not_implemented_response(
        "agent-worker-firecracker-exec-unix-rpc",
        "codex",
        "firecracker-exec-unix-rpc-instance",
    );
    let listener = UnixListener::bind(&rpc_socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        reader.read_line(&mut request).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        request
    });
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = shared_lifecycle_envelope_with_adapter(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-unix-rpc",
        "",
        "codex",
    );
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-unix-rpc-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);
    let request = server.join().unwrap();

    clear_guest_agent_env();
    assert!(exec.accepted);
    assert!(request.contains("\"action\":\"start_handler\""));
    assert!(request.contains("\"framework_adapter\":\"codex\""));
    assert!(request.contains("\"rpc_channel\":\"unix-json-lines\""));
    assert!(request.contains(
            "\"required_gateway_capabilities\":[\"cli\",\"filesystem\",\"tools\",\"artifacts\",\"checkpoint\"]"
        ));
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_handler_rpc_not_implemented");
    assert!(lifecycle
        .message
        .contains("guest_rpc_channel=unix-json-lines"));
    assert!(lifecycle
        .message
        .contains("guest_rpc_start_response(status=not_implemented"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-unix-rpc-instance")
    );
}

#[test]
fn exec_or_attach_rejects_successful_guest_agent_without_handshake() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-no-handshake",
    );
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-no-handshake-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_agent_handshake_unavailable");
    assert!(lifecycle
        .message
        .contains("did not return a valid guest RPC handshake"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-no-handshake-instance")
    );
}

#[test]
fn exec_or_attach_reports_guest_agent_launch_failure_without_stopping_microvm() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_executable_script(
            &guest_agent,
            "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then echo 'ferrogate guest agent v.test'; exit 0; fi\nexit 42\n",
        )
        .unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = lifecycle_envelope(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-launch-failed",
    );
    let mut status_envelope = exec_envelope.clone();
    status_envelope.action = AgentWorkerManagementAction::StreamStatus;
    status_envelope.request_id =
        "agent-worker-firecracker-exec-launch-failed-status-request".to_string();
    status_envelope.idempotency_key =
        "agent-worker-firecracker-exec-launch-failed-status-idempotency".to_string();
    status_envelope.security.nonce =
        "agent-worker-firecracker-exec-launch-failed-status-nonce".to_string();
    status_envelope.security.signature = status_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-launch-failed-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);
    let status =
        accept_management_envelope(&mut transport, &mut state, &runtime, status_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_agent_launch_failed");
    assert!(lifecycle
        .message
        .contains("exited before handler RPC channel was available"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-launch-failed-instance")
    );
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "running");
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-launch-failed-instance")
    );
}

#[test]
fn exec_or_attach_reports_guest_start_rpc_invalid_response_without_stopping_microvm() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_executable_script(
            &guest_agent,
            "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then echo 'ferrogate guest agent v.test'; exit 0; fi\nif [ \"${1:-}\" = \"--ferrogate-guest-agent-probe\" ]; then printf '%s\\n' '{\"protocol_version\":\"ferrogate.agent-worker.guest.v1\",\"ready\":true,\"rpc_channel\":\"stdio-json-lines\",\"guest_agent_version\":\"ferrogate guest agent v.test\"}'; exit 0; fi\nif [ \"${1:-}\" = \"--ferrogate-guest-agent-start\" ]; then cat >/dev/null; printf '%s\\n' '{\"protocol_version\":\"ferrogate.agent-worker.guest.v1\",\"status\":\"started\",\"message\":\"must not be accepted\",\"proves_handler_execution\":true}'; exit 0; fi\nexit 1\n",
        )
        .unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = shared_lifecycle_envelope_with_adapter(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-invalid-start",
        "",
        "codex",
    );
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-invalid-start-instance", temp.path()).unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_handler_rpc_unavailable");
    assert!(lifecycle.message.contains("invalid response"));
    assert!(lifecycle
        .message
        .contains("guest_rpc_start_request(protocol_version=ferrogate.agent-worker.guest.v1"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-invalid-start-instance")
    );
}

#[test]
fn exec_or_attach_rejects_guest_start_response_for_wrong_isolation_instance() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_guest_agent_handshake_script(
        &guest_agent,
        &guest_start_not_implemented_response(
            "agent-worker-firecracker-exec-response-mismatch",
            "codex",
            "wrong-firecracker-instance",
        ),
    )
    .unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = shared_lifecycle_envelope_with_adapter(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-response-mismatch",
        "",
        "codex",
    );
    let mut status_envelope = exec_envelope.clone();
    status_envelope.action = AgentWorkerManagementAction::StreamStatus;
    status_envelope.request_id =
        "agent-worker-firecracker-exec-response-mismatch-status-request".to_string();
    status_envelope.idempotency_key =
        "agent-worker-firecracker-exec-response-mismatch-status-idempotency".to_string();
    status_envelope.security.nonce =
        "agent-worker-firecracker-exec-response-mismatch-status-nonce".to_string();
    status_envelope.security.signature = status_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-response-mismatch-instance", temp.path())
            .unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);
    let status =
        accept_management_envelope(&mut transport, &mut state, &runtime, status_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_handler_rpc_unavailable");
    assert!(lifecycle.message.contains("invalid response"));
    assert!(lifecycle.message.contains("isolation_instance_id mismatch"));
    assert!(lifecycle.message.contains("wrong-firecracker-instance"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-response-mismatch-instance")
    );
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = status.result else {
        panic!("status did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "running");
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-response-mismatch-instance")
    );
}

#[test]
fn exec_or_attach_rejects_guest_start_response_for_wrong_capability_envelope() {
    let _env_lock = lock_firecracker_env();
    let temp = tempfile::tempdir().unwrap();
    let guest_agent = temp.path().join("ferrogate-guest-agent");
    let workspace = temp.path().join("workspace");
    write_guest_agent_handshake_script(
        &guest_agent,
        &guest_start_not_implemented_response_with_capabilities(
            "agent-worker-firecracker-exec-capability-mismatch",
            "codex",
            "firecracker-exec-capability-mismatch-instance",
            &["tools", "artifacts", "checkpoint"],
        ),
    )
    .unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
    std::env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
    std::env::set_var(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
    );
    let exec_envelope = shared_lifecycle_envelope_with_adapter(
        AgentWorkerManagementAction::ExecOrAttach,
        "agent-worker-firecracker-exec-capability-mismatch",
        "",
        "codex",
    );
    let session_id = exec_envelope.session_id.clone().unwrap();
    let run_id = exec_envelope.run_id.clone().unwrap();
    let mut transport = InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    );
    let mut state = InMemoryAgentWorkerStateStore::new();
    state.put_firecracker_microvm(
        session_id,
        run_id,
        test_firecracker_microvm("firecracker-exec-capability-mismatch-instance", temp.path())
            .unwrap(),
    );
    let runtime = AgentWorkerRuntime::default();

    let exec =
        accept_management_envelope(&mut transport, &mut state, &runtime, exec_envelope, 1_000);

    clear_guest_agent_env();
    assert!(exec.accepted);
    let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = exec.result else {
        panic!("exec did not return lifecycle evidence");
    };
    assert_eq!(lifecycle.outcome, "guest_handler_rpc_unavailable");
    assert!(lifecycle.message.contains("invalid response"));
    assert!(lifecycle
        .message
        .contains("required_gateway_capabilities mismatch"));
    assert!(lifecycle
        .message
        .contains("request=cli|filesystem|tools|artifacts|checkpoint"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("firecracker-exec-capability-mismatch-instance")
    );
}

#[test]
fn unix_socket_server_handles_later_connection_while_first_is_slow() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let socket_for_server = socket_path.clone();
    let server = thread::spawn(move || {
        serve_management_unix(
            &socket_for_server,
            "agent-worker-smoke-key",
            SMOKE_SHARED_SECRET,
            Some(1_000),
            2,
            None,
        )
        .unwrap()
    });

    wait_for_socket(&socket_path);
    let mut slow_stream = UnixStream::connect(&socket_path).unwrap();

    let mut fast_envelope = smoke_envelope().unwrap();
    fast_envelope.request_id = "agent-worker-fast-request".to_string();
    fast_envelope.idempotency_key = "agent-worker-fast-idempotency".to_string();
    fast_envelope.security.nonce = "agent-worker-fast-nonce".to_string();
    fast_envelope.security.signature = fast_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    let client = AgentWorkerUnixManagementClient::new(&socket_path);
    let fast = client.send_management_request(&fast_envelope).unwrap();

    assert!(fast.accepted);
    assert_eq!(fast.request_id, "agent-worker-fast-request");

    let mut slow_envelope = smoke_envelope().unwrap();
    slow_envelope.request_id = "agent-worker-slow-request".to_string();
    slow_envelope.idempotency_key = "agent-worker-slow-idempotency".to_string();
    slow_envelope.security.nonce = "agent-worker-slow-nonce".to_string();
    slow_envelope.security.signature = slow_envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    slow_stream
        .write_all(serde_json::to_string(&slow_envelope).unwrap().as_bytes())
        .unwrap();
    slow_stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut slow_response = String::new();
    slow_stream.read_to_string(&mut slow_response).unwrap();
    let slow_response: AgentWorkerManagementResponse =
        serde_json::from_str(slow_response.trim()).unwrap();

    assert!(slow_response.accepted);
    assert_eq!(slow_response.request_id, "agent-worker-slow-request");

    let server_responses = server.join().unwrap();
    assert_eq!(server_responses.len(), 2);
    assert!(server_responses.iter().any(|response| {
        response.accepted && response.request_id == "agent-worker-fast-request"
    }));
    assert!(server_responses.iter().any(|response| {
        response.accepted && response.request_id == "agent-worker-slow-request"
    }));
    assert!(!socket_path.exists());
}

#[test]
fn unix_socket_server_exits_and_cleans_up_after_idle_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("agent-worker-management.sock");
    let responses = serve_management_unix(
        &socket_path,
        "agent-worker-smoke-key",
        SMOKE_SHARED_SECRET,
        Some(1_000),
        2,
        Some(25),
    )
    .unwrap();

    assert!(responses.is_empty());
    assert!(!socket_path.exists());
}

fn wait_for_socket(socket_path: &Path) {
    for _ in 0..100 {
        if socket_path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("unix socket was not created at {}", socket_path.display());
}

fn spawn_http_management_server(
    max_requests: usize,
) -> (
    SocketAddr,
    thread::JoinHandle<Vec<ferrogate_runtime::AgentWorkerManagementResponse>>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        serve_management_http_bound_to_ephemeral_port(max_requests, addr_tx).unwrap()
    });
    let addr = addr_rx.recv().unwrap();
    (addr, server)
}

fn serve_management_http_bound_to_ephemeral_port(
    max_requests: usize,
    addr_tx: mpsc::Sender<SocketAddr>,
) -> Result<Vec<ferrogate_runtime::AgentWorkerManagementResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    addr_tx.send(listener.local_addr()?)?;
    serve_management_http_listener(
        listener,
        "agent-worker-smoke-key",
        SMOKE_SHARED_SECRET,
        Some(1_000),
        max_requests,
        None,
        None,
    )
}

fn write_executable_version_script(path: &Path, version: &str) -> std::io::Result<()> {
    write_executable_script(
            path,
            &format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then echo '{version}'; exit 0; fi\nexit 0\n"
            ),
        )
}

fn write_guest_agent_handshake_script(path: &Path, start_response: &str) -> std::io::Result<()> {
    write_executable_script(
            path,
            &format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then echo 'ferrogate guest agent v.test'; exit 0; fi\nif [ \"${{1:-}}\" = \"--ferrogate-guest-agent-probe\" ]; then printf '%s\\n' '{{\"protocol_version\":\"ferrogate.agent-worker.guest.v1\",\"ready\":true,\"rpc_channel\":\"stdio-json-lines\",\"guest_agent_version\":\"ferrogate guest agent v.test\"}}'; exit 0; fi\nif [ \"${{1:-}}\" = \"--ferrogate-guest-agent-start\" ]; then grep -q '\"action\":\"start_handler\"' || exit 2; printf '%s\\n' '{start_response}'; exit 0; fi\nexit 1\n"
            ),
        )
}

fn write_guest_agent_unix_rpc_handshake_script(
    path: &Path,
    rpc_socket: &Path,
) -> std::io::Result<()> {
    let handshake = serde_json::json!({
        "protocol_version": "ferrogate.agent-worker.guest.v1",
        "ready": true,
        "rpc_channel": "unix-json-lines",
        "rpc_socket_path": rpc_socket.display().to_string(),
        "guest_agent_version": "ferrogate guest agent v.test",
    })
    .to_string();
    write_executable_script(
            path,
            &format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then echo 'ferrogate guest agent v.test'; exit 0; fi\nif [ \"${{1:-}}\" = \"--ferrogate-guest-agent-probe\" ]; then printf '%s\\n' '{handshake}'; exit 0; fi\nif [ \"${{1:-}}\" = \"--ferrogate-guest-agent-start\" ]; then exit 44; fi\nexit 1\n"
            ),
        )
}

fn guest_start_not_implemented_response(
    envelope_prefix: &str,
    framework_adapter: &str,
    isolation_instance_id: &str,
) -> String {
    guest_start_not_implemented_response_with_capabilities(
        envelope_prefix,
        framework_adapter,
        isolation_instance_id,
        guest_start_capabilities(framework_adapter),
    )
}

fn guest_start_not_implemented_response_with_capabilities(
    envelope_prefix: &str,
    framework_adapter: &str,
    isolation_instance_id: &str,
    required_gateway_capabilities: &[&str],
) -> String {
    serde_json::json!({
            "protocol_version": "ferrogate.agent-worker.guest.v1",
            "action": "start_handler",
            "worker_id": "agent-worker-smoke",
            "session_id": format!("{envelope_prefix}-session"),
            "run_id": format!("{envelope_prefix}-run"),
            "framework_adapter": framework_adapter,
            "adapter_launch_profile": guest_start_launch_profile(framework_adapter),
            "isolation_backend": "firecracker",
            "isolation_instance_id": isolation_instance_id,
            "required_gateway_capabilities": required_gateway_capabilities,
            "network_policy": "gateway_control_channel_only_no_direct_public_egress",
            "filesystem_policy": "prepared_workspace_only_with_read_only_runtime_bundle",
            "artifact_policy": "guest_artifacts_must_return_as_artifact_created_events",
            "checkpoint_policy": "guest_checkpoint_requests_must_return_as_snapshot_or_checkpoint_evidence",
            "status": "not_implemented",
            "message": "guest handler RPC transport is not implemented",
            "proves_handler_execution": false,
        })
        .to_string()
}

fn guest_start_capabilities(framework_adapter: &str) -> &'static [&'static str] {
    match framework_adapter {
        "codex" | "claude-code" => &["cli", "filesystem", "tools", "artifacts", "checkpoint"],
        "hermes" => &[
            "memory.read",
            "memory.write",
            "subagents",
            "artifacts",
            "checkpoint",
        ],
        _ => &["tools", "artifacts", "checkpoint"],
    }
}

fn guest_start_launch_profile(framework_adapter: &str) -> serde_json::Value {
    match framework_adapter {
        "codex" => serde_json::json!({
            "framework": "codex",
            "entrypoint": "codex_exec",
            "event_stream": "normalized_jsonl",
            "external_action_mode": "gateway_mediated_cli_filesystem_tools",
        }),
        "claude-code" => serde_json::json!({
            "framework": "claude_code",
            "entrypoint": "claude_code_non_interactive",
            "event_stream": "normalized_jsonl",
            "external_action_mode": "gateway_mediated_cli_filesystem_tools",
        }),
        "hermes" => serde_json::json!({
            "framework": "hermes",
            "entrypoint": "hermes_oneshot",
            "event_stream": "normalized_jsonl",
            "external_action_mode": "gateway_mediated_memory_subagents",
        }),
        _ => serde_json::json!({
            "framework": "native_harness",
            "entrypoint": "native_harness_task",
            "event_stream": "normalized_jsonl",
            "external_action_mode": "gateway_mediated_tools",
        }),
    }
}

fn write_executable_script(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
}

fn clear_guest_agent_env() {
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE");
    std::env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT");
}

fn send_http_management_request(
    addr: SocketAddr,
    body: &str,
    transport_security: &str,
) -> AgentWorkerManagementResponse {
    let mut stream = None;
    for _ in 0..100 {
        match TcpStream::connect(addr) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    let mut stream = stream.unwrap_or_else(|| panic!("tcp listener was not created at {addr}"));
    write!(
            stream,
            "POST /v1/agent-worker/management HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\nx-ferrogate-transport-security: {transport_security}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body.trim()).unwrap()
}

fn lifecycle_envelope(
    action: AgentWorkerManagementAction,
    prefix: &str,
) -> AgentWorkerManagementEnvelope {
    shared_lifecycle_envelope(action, prefix, "")
}

fn shared_lifecycle_envelope(
    action: AgentWorkerManagementAction,
    prefix: &str,
    request_suffix: &str,
) -> AgentWorkerManagementEnvelope {
    shared_lifecycle_envelope_with_optional_adapter(action, prefix, request_suffix, None)
}

fn shared_lifecycle_envelope_with_adapter(
    action: AgentWorkerManagementAction,
    prefix: &str,
    request_suffix: &str,
    framework_adapter: &str,
) -> AgentWorkerManagementEnvelope {
    shared_lifecycle_envelope_with_optional_adapter(
        action,
        prefix,
        request_suffix,
        Some(framework_adapter),
    )
}

fn shared_lifecycle_envelope_with_optional_adapter(
    action: AgentWorkerManagementAction,
    prefix: &str,
    request_suffix: &str,
    framework_adapter: Option<&str>,
) -> AgentWorkerManagementEnvelope {
    let mut envelope = smoke_envelope().unwrap();
    envelope.action = action;
    let request_name = if request_suffix.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}-{request_suffix}")
    };
    envelope.request_id = format!("{request_name}-request");
    envelope.idempotency_key = format!("{request_name}-idempotency");
    envelope.session_id = Some(format!("{prefix}-session"));
    envelope.run_id = Some(format!("{prefix}-run"));
    envelope.framework_adapter = framework_adapter.map(ToOwned::to_owned);
    envelope.security.nonce = format!("{request_name}-nonce");
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    envelope
}
