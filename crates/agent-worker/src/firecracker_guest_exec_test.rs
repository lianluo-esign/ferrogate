// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.
//!
//! These tests prove the ENTIRE #280 guest execution protocol — capability
//! envelope enforcement at the VM boundary, workload execution, evidence
//! streaming, response binding, and the host-side Firecracker vsock mux
//! client — without KVM, by running the guest session core over socket pairs
//! and a fake Firecracker vsock mux (a Unix listener speaking the exact
//! `CONNECT <port>` / `OK <port>` preamble Firecracker uses). Only the
//! in-guest AF_VSOCK topology remains for the KVM-gated harness
//! (`tests/firecracker_agent_execution.rs`).

use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    thread,
    time::Duration,
};

use ferrogate_runtime::{
    AgentWorkerManagementAction, AgentWorkerManagementEnvelope, AgentWorkerManagementResult,
    AgentWorkerManagementSecurity, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    CapabilityAction, CapabilityPolicy, ClassOnlyPolicyMode, FrameworkAdapterMode,
    SimpleCapabilityAuthorizer, AGENT_WORKER_PROTOCOL_VERSION,
};

use super::*;
use crate::{
    backends::{
        firecracker_guest_vsock_start_request, test_firecracker_microvm,
        FirecrackerGuestRpcStartResponse,
    },
    external_actions::RuntimeGatewayExternalActionAuthorizer,
    state::{AgentWorkerStateStore, InMemoryAgentWorkerStateStore},
    test_support::lock_firecracker_env,
};

fn test_envelope(session: &str, run: &str) -> AgentWorkerManagementEnvelope {
    AgentWorkerManagementEnvelope {
        protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
        action: AgentWorkerManagementAction::ExecOrAttach,
        request_id: format!("{session}-request"),
        idempotency_key: format!("{session}-idempotency"),
        issued_at_unix_millis: 1_000,
        deadline_unix_millis: 60_000,
        tenant_id: "guest-exec-tenant".to_string(),
        workspace_id: "guest-exec-workspace".to_string(),
        worker_id: "guest-exec-worker".to_string(),
        session_id: Some(session.to_string()),
        run_id: Some(run.to_string()),
        framework_adapter: Some("native-harness".to_string()),
        security: AgentWorkerManagementSecurity {
            key_id: "guest-exec-key".to_string(),
            nonce: format!("{session}-nonce"),
            signature: String::new(),
            algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
            encrypted: false,
        },
    }
}

fn shell_workload(script: &str) -> FirecrackerGuestWorkloadSpec {
    FirecrackerGuestWorkloadSpec {
        capability_action: "cli".to_string(),
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), script.to_string()],
        timeout_millis: 5_000,
        output_limit_bytes: 4_096,
    }
}

fn serve_config(workspace: &Path) -> GuestServeConfig {
    GuestServeConfig {
        workspace: workspace.to_path_buf(),
        guest_agent_version: "test-guest-agent".to_string(),
    }
}

/// Drive one guest session over a socket pair and return the raw frames the
/// guest produced after the handshake.
fn drive_guest_session(
    request: &crate::backends::FirecrackerGuestRpcStartRequest,
    workspace: &Path,
) -> (serde_json::Value, Vec<serde_json::Value>) {
    let (mut guest_side, host_side) = UnixStream::pair().unwrap();
    let config = serve_config(workspace);
    let server = thread::spawn(move || serve_guest_session_with_config(&mut guest_side, &config));
    let mut reader = BufReader::new(host_side.try_clone().unwrap());
    let mut handshake_line = String::new();
    reader.read_line(&mut handshake_line).unwrap();
    let handshake: serde_json::Value = serde_json::from_str(handshake_line.trim()).unwrap();
    let mut writer = host_side;
    let request_json = serde_json::to_string(request).unwrap();
    writer.write_all(request_json.as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let mut frames = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let is_response = frame["frame"] == "response";
        frames.push(frame);
        if is_response {
            break;
        }
    }
    server.join().unwrap().unwrap();
    (handshake, frames)
}

#[test]
fn guest_agent_executes_granted_workload_and_streams_evidence() {
    let workspace = tempfile::tempdir().unwrap();
    let envelope = test_envelope("guest-exec-allowed-session", "guest-exec-allowed-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "guest-exec-instance",
        shell_workload("echo ferrogate-guest-exec-allowed"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:allowed".to_string(),
            vec!["cli".to_string()],
        ),
    );

    let (handshake, frames) = drive_guest_session(&request, workspace.path());

    assert_eq!(
        handshake["protocol_version"],
        "ferrogate.agent-worker.guest.v1"
    );
    assert_eq!(handshake["rpc_channel"], VSOCK_RPC_CHANNEL);
    assert_eq!(handshake["ready"], true);
    let kinds = frames
        .iter()
        .filter(|frame| frame["frame"] == "event")
        .map(|frame| frame["event"]["kind"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec!["capability.allowed", "run.started", "run.completed"]
    );
    let response = &frames.last().unwrap()["response"];
    assert_eq!(response["status"], "completed");
    assert_eq!(response["proves_handler_execution"], true);
    assert_eq!(response["workload_result"]["executed"], true);
    assert_eq!(response["workload_result"]["exit_code"], 0);
    assert_eq!(
        response["workload_result"]["capability_denial_enforced"],
        false
    );
    assert!(response["workload_result"]["output_excerpt"]
        .as_str()
        .unwrap()
        .contains("ferrogate-guest-exec-allowed"));
    // Identity binding is echoed for the host-side verifier.
    assert_eq!(response["session_id"], "guest-exec-allowed-session");
    assert_eq!(response["isolation_instance_id"], "guest-exec-instance");
    // Events are attributable to the isolation instance and the VM boundary.
    let event = &frames[0]["event"];
    assert_eq!(
        event["metadata"]["enforcement_boundary"],
        MICROVM_GUEST_ENFORCEMENT_BOUNDARY
    );
    assert_eq!(
        event["metadata"]["isolation_instance_id"],
        "guest-exec-instance"
    );
}

#[test]
fn guest_agent_enforces_capability_denial_and_never_spawns_the_workload() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("must-never-exist");
    let envelope = test_envelope("guest-exec-denied-session", "guest-exec-denied-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "guest-exec-instance",
        shell_workload(&format!("touch {}", marker.display())),
        // The gateway envelope grants NOTHING: the guest must enforce.
        FirecrackerGuestCapabilityEnvelope::enforced("cap:test:denied".to_string(), Vec::new()),
    );

    let (_, frames) = drive_guest_session(&request, workspace.path());

    let kinds = frames
        .iter()
        .filter(|frame| frame["frame"] == "event")
        .map(|frame| frame["event"]["kind"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec!["capability.denied"]);
    let denied_event = &frames[0]["event"];
    assert_eq!(
        denied_event["metadata"]["capability_denial_enforced"],
        "true"
    );
    let response = &frames.last().unwrap()["response"];
    assert_eq!(response["status"], "capability_denied");
    assert_eq!(response["proves_handler_execution"], false);
    assert_eq!(response["workload_result"]["executed"], false);
    assert_eq!(
        response["workload_result"]["capability_denial_enforced"],
        true
    );
    // ENFORCED, not report-only: the denied workload never ran.
    assert!(
        !marker.exists(),
        "denied workload executed anyway — capability envelope was not enforced"
    );
}

#[test]
fn guest_agent_fails_closed_on_unknown_enforcement_mode() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("must-never-exist-either");
    let envelope = test_envelope("guest-exec-mode-session", "guest-exec-mode-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "guest-exec-instance",
        shell_workload(&format!("touch {}", marker.display())),
        FirecrackerGuestCapabilityEnvelope {
            envelope_id: "cap:test:report-only".to_string(),
            granted_capabilities: vec!["cli".to_string()],
            // A report-only (or unknown) enforcement mode must not execute.
            enforcement: "report_only".to_string(),
        },
    );

    let (_, frames) = drive_guest_session(&request, workspace.path());

    let response = &frames.last().unwrap()["response"];
    assert_eq!(response["status"], "capability_denied");
    assert_eq!(
        response["workload_result"]["capability_denial_enforced"],
        true
    );
    assert!(!marker.exists());
}

#[test]
fn guest_agent_rejects_a_workload_without_a_capability_envelope() {
    let workspace = tempfile::tempdir().unwrap();
    let envelope = test_envelope("guest-exec-noenv-session", "guest-exec-noenv-run");
    let valid = firecracker_guest_vsock_start_request(
        &envelope,
        "guest-exec-instance",
        shell_workload("echo unreachable"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:strip".to_string(),
            vec!["cli".to_string()],
        ),
    );
    // Strip the envelope on the wire: the guest must fail closed.
    let mut raw = serde_json::to_value(&valid).unwrap();
    raw.as_object_mut().unwrap().remove("capability_envelope");
    let tampered: crate::backends::FirecrackerGuestRpcStartRequest =
        serde_json::from_value(raw).unwrap();

    let (_, frames) = drive_guest_session(&tampered, workspace.path());

    let response = &frames.last().unwrap()["response"];
    assert_eq!(response["status"], "workload_failed");
    assert_eq!(response["workload_result"]["executed"], false);
    assert!(response["message"]
        .as_str()
        .unwrap()
        .contains("without a gateway capability envelope"));
}

#[test]
fn guest_agent_serves_legacy_probe_requests_as_not_implemented() {
    let workspace = tempfile::tempdir().unwrap();
    let handshake = crate::backends::FirecrackerGuestAgentHandshake::parse(
        format!(
            "{}",
            serde_json::json!({
                "protocol_version": "ferrogate.agent-worker.guest.v1",
                "ready": true,
                "rpc_channel": VSOCK_RPC_CHANNEL,
            })
        )
        .as_bytes(),
    )
    .unwrap();
    let envelope = test_envelope("guest-exec-legacy-session", "guest-exec-legacy-run");
    let request = crate::backends::firecracker_guest_rpc_start_request(
        &envelope,
        &handshake,
        "guest-exec-instance",
    );

    let (_, frames) = drive_guest_session(&request, workspace.path());

    let response = &frames.last().unwrap()["response"];
    assert_eq!(response["status"], "not_implemented");
    assert_eq!(response["proves_handler_execution"], false);
    assert_eq!(response["workload_result"], serde_json::Value::Null);
}

// ---------------------------------------------------------------------------
// Host-side client through a fake Firecracker vsock mux
// ---------------------------------------------------------------------------

/// The host side of Firecracker's vsock device is a Unix socket with a
/// `CONNECT <port>` / `OK <port>` preamble. This fake speaks exactly that,
/// then hands the stream to the real guest session core.
fn spawn_fake_firecracker_vsock_mux(
    socket_path: &Path,
    expected_port: u32,
    workspace: &Path,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket_path).unwrap();
    let workspace = workspace.to_path_buf();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut connect_line = String::new();
        reader.read_line(&mut connect_line).unwrap();
        assert_eq!(connect_line.trim(), format!("CONNECT {expected_port}"));
        let mut stream = stream;
        stream
            .write_all(format!("OK {expected_port}\n").as_bytes())
            .unwrap();
        let config = serve_config(&workspace);
        // Serve over a duplex view: reads must go through the same BufReader
        // that consumed the preamble.
        let mut duplex = FakeMuxDuplex {
            reader,
            writer: stream,
        };
        serve_guest_session_with_config(&mut duplex, &config).unwrap();
    })
}

struct FakeMuxDuplex {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl std::io::Read for FakeMuxDuplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for FakeMuxDuplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[test]
fn host_vsock_exec_round_trip_executes_and_returns_guest_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("guest-rpc.sock");
    let mux = spawn_fake_firecracker_vsock_mux(&socket_path, 5252, temp.path());
    let envelope = test_envelope("vsock-exec-session", "vsock-exec-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "vsock-exec-instance",
        shell_workload("echo ferrogate-vsock-round-trip"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:vsock".to_string(),
            vec!["cli".to_string()],
        ),
    );

    let outcome =
        firecracker_guest_vsock_exec(&socket_path, 5252, &request, Duration::from_secs(10))
            .unwrap();
    mux.join().unwrap();

    assert_eq!(outcome.response.status(), "completed");
    assert!(outcome.response.proves_handler_execution());
    let result = outcome.response.workload_result().unwrap();
    assert!(result.executed);
    assert_eq!(result.exit_code, Some(0));
    assert!(result.output_excerpt.contains("ferrogate-vsock-round-trip"));
    assert_eq!(
        outcome.event_kinds(),
        vec!["capability.allowed", "run.started", "run.completed"]
    );
    assert_eq!(outcome.handshake.rpc_channel(), VSOCK_RPC_CHANNEL);
}

#[test]
fn host_vsock_exec_returns_enforced_denial_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("guest-rpc.sock");
    let marker = temp.path().join("denied-must-not-exist");
    let mux = spawn_fake_firecracker_vsock_mux(&socket_path, 5252, temp.path());
    let envelope = test_envelope("vsock-denied-session", "vsock-denied-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "vsock-denied-instance",
        shell_workload(&format!("touch {}", marker.display())),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:vsock-denied".to_string(),
            Vec::new(),
        ),
    );

    let outcome =
        firecracker_guest_vsock_exec(&socket_path, 5252, &request, Duration::from_secs(10))
            .unwrap();
    mux.join().unwrap();

    assert_eq!(outcome.response.status(), "capability_denied");
    assert!(!outcome.response.proves_handler_execution());
    let result = outcome.response.workload_result().unwrap();
    assert!(!result.executed);
    assert!(result.capability_denial_enforced);
    assert_eq!(outcome.event_kinds(), vec!["capability.denied"]);
    assert!(!marker.exists());
}

#[test]
fn host_vsock_exec_fails_closed_when_the_mux_rejects_connect() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("guest-rpc.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut stream = stream;
        stream.write_all(b"ERR no guest listener\n").unwrap();
    });
    let envelope = test_envelope("vsock-reject-session", "vsock-reject-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "vsock-reject-instance",
        shell_workload("echo unreachable"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:reject".to_string(),
            vec!["cli".to_string()],
        ),
    );

    let error = firecracker_guest_vsock_exec(&socket_path, 5252, &request, Duration::from_secs(5))
        .unwrap_err();
    server.join().unwrap();

    assert_eq!(error.outcome(), "guest_vsock_unavailable");
    assert!(error.reason().contains("rejected CONNECT"));
}

/// A fake mux that returns an attacker-controlled response instead of running
/// the real guest core.
fn spawn_tampering_mux(
    socket_path: &Path,
    tamper: impl Fn(&mut serde_json::Value) + Send + 'static,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket_path).unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut connect_line = String::new();
        reader.read_line(&mut connect_line).unwrap();
        let mut stream = stream;
        stream.write_all(b"OK 5252\n").unwrap();
        let handshake = serde_json::json!({
            "protocol_version": "ferrogate.agent-worker.guest.v1",
            "ready": true,
            "rpc_channel": VSOCK_RPC_CHANNEL,
        });
        stream
            .write_all(format!("{handshake}\n").as_bytes())
            .unwrap();
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let request: crate::backends::FirecrackerGuestRpcStartRequest =
            serde_json::from_str(request_line.trim()).unwrap();
        let response = FirecrackerGuestRpcStartResponse::for_guest_request(
            &request,
            "completed",
            "tampered",
            Some(FirecrackerGuestWorkloadResult {
                executed: true,
                exit_code: Some(0),
                output_excerpt: "tampered".to_string(),
                capability_denial_enforced: false,
                denial_reason: None,
            }),
            true,
        );
        let mut raw = serde_json::to_value(&response).unwrap();
        tamper(&mut raw);
        let frame = serde_json::json!({ "frame": "response", "response": raw });
        stream.write_all(format!("{frame}\n").as_bytes()).unwrap();
    })
}

#[test]
fn host_vsock_exec_fails_closed_on_response_identity_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("guest-rpc.sock");
    let mux = spawn_tampering_mux(&socket_path, |raw| {
        raw["worker_id"] = serde_json::Value::String("attacker-worker".to_string());
    });
    let envelope = test_envelope("vsock-tamper-session", "vsock-tamper-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "vsock-tamper-instance",
        shell_workload("echo unreachable"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:tamper".to_string(),
            vec!["cli".to_string()],
        ),
    );

    let error = firecracker_guest_vsock_exec(&socket_path, 5252, &request, Duration::from_secs(5))
        .unwrap_err();
    mux.join().unwrap();

    assert_eq!(error.outcome(), "guest_handler_rpc_unavailable");
    assert!(error.reason().contains("worker_id mismatch"));
}

#[test]
fn host_vsock_exec_fails_closed_when_completed_claims_no_execution() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("guest-rpc.sock");
    let mux = spawn_tampering_mux(&socket_path, |raw| {
        raw["workload_result"]["executed"] = serde_json::Value::Bool(false);
    });
    let envelope = test_envelope("vsock-fake-session", "vsock-fake-run");
    let request = firecracker_guest_vsock_start_request(
        &envelope,
        "vsock-fake-instance",
        shell_workload("echo unreachable"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            "cap:test:fake".to_string(),
            vec!["cli".to_string()],
        ),
    );

    let error = firecracker_guest_vsock_exec(&socket_path, 5252, &request, Duration::from_secs(5))
        .unwrap_err();
    mux.join().unwrap();

    assert_eq!(error.outcome(), "guest_handler_rpc_unavailable");
    assert!(error
        .reason()
        .contains("only a real zero-exit execution may report completed"));
}

// ---------------------------------------------------------------------------
// Lifecycle integration: exec_or_attach over the vsock channel
// ---------------------------------------------------------------------------

fn cli_authorizer(
    allow_cli: bool,
) -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    let allowed_actions = if allow_cli {
        BTreeSet::from([CapabilityAction::Cli])
    } else {
        BTreeSet::new()
    };
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions,
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn dispatch_exec_with_retained_microvm(
    session: &str,
    run: &str,
    allow_cli: bool,
    spawn_mux: bool,
) -> AgentWorkerManagementResult {
    let _env_lock = lock_firecracker_env();
    std::env::set_var(GUEST_VSOCK_PORT_ENV, "5252");
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("microvm-run");
    let mut state = InMemoryAgentWorkerStateStore::new();
    let microvm = test_firecracker_microvm(&format!("{session}-instance"), &run_dir).unwrap();
    let guest_rpc_socket = microvm.guest_rpc_socket_path();
    state.put_firecracker_microvm(session.to_string(), run.to_string(), microvm);
    let mux =
        spawn_mux.then(|| spawn_fake_firecracker_vsock_mux(&guest_rpc_socket, 5252, temp.path()));
    let envelope = test_envelope(session, run);
    let authorizer = cli_authorizer(allow_cli);
    let result = crate::lifecycle::dispatch_lifecycle_action(
        &mut state,
        &envelope,
        Some(&authorizer),
        FrameworkAdapterMode::Managed,
    );
    std::env::remove_var(GUEST_VSOCK_PORT_ENV);
    if let Some(mux) = mux {
        mux.join().unwrap();
    }
    result.unwrap().unwrap()
}

#[test]
fn lifecycle_exec_runs_the_workload_in_guest_when_gateway_allows() {
    let result = dispatch_exec_with_retained_microvm(
        "lifecycle-vsock-allowed-session",
        "lifecycle-vsock-allowed-run",
        true,
        true,
    );
    let AgentWorkerManagementResult::HandlerEvents { events } = result else {
        panic!("expected handler events, got {result:?}");
    };
    let kinds = events
        .iter()
        .map(|event| event.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec!["capability.allowed", "run.started", "run.completed"]
    );
    let completed = events.last().unwrap();
    assert!(completed
        .metadata
        .get("output_excerpt")
        .is_some_and(|output| output.contains("agent-worker-firecracker-guest-ready")));
    assert_eq!(
        completed
            .metadata
            .get("enforcement_boundary")
            .map(String::as_str),
        Some(MICROVM_GUEST_ENFORCEMENT_BOUNDARY)
    );
}

#[test]
fn lifecycle_exec_enforces_gateway_denial_inside_the_guest_boundary() {
    let result = dispatch_exec_with_retained_microvm(
        "lifecycle-vsock-denied-session",
        "lifecycle-vsock-denied-run",
        false,
        true,
    );
    let AgentWorkerManagementResult::HandlerEvents { events } = result else {
        panic!("expected handler events, got {result:?}");
    };
    let kinds = events
        .iter()
        .map(|event| event.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec!["capability.denied"]);
    assert_eq!(
        events[0]
            .metadata
            .get("capability_denial_enforced")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn lifecycle_exec_fails_closed_when_the_vsock_channel_is_unavailable() {
    let result = dispatch_exec_with_retained_microvm(
        "lifecycle-vsock-down-session",
        "lifecycle-vsock-down-run",
        true,
        false,
    );
    let AgentWorkerManagementResult::Lifecycle { lifecycle } = result else {
        panic!("expected lifecycle failure, got {result:?}");
    };
    assert_eq!(lifecycle.outcome, "guest_vsock_unavailable");
    assert!(lifecycle.message.contains("vsock guest execution failed"));
    assert_eq!(
        lifecycle.isolation_instance_id.as_deref(),
        Some("lifecycle-vsock-down-session-instance")
    );
}

#[test]
fn configured_guest_vsock_port_requires_a_positive_integer() {
    let _env_lock = lock_firecracker_env();
    std::env::remove_var(GUEST_VSOCK_PORT_ENV);
    assert_eq!(configured_guest_vsock_port(), None);
    std::env::set_var(GUEST_VSOCK_PORT_ENV, "0");
    assert_eq!(configured_guest_vsock_port(), None);
    std::env::set_var(GUEST_VSOCK_PORT_ENV, "not-a-port");
    assert_eq!(configured_guest_vsock_port(), None);
    std::env::set_var(GUEST_VSOCK_PORT_ENV, "5252");
    assert_eq!(configured_guest_vsock_port(), Some(5252));
    std::env::remove_var(GUEST_VSOCK_PORT_ENV);
}
