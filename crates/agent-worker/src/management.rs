// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixListener,
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    AgentWorkerManagementAction, AgentWorkerManagementEnvelope, AgentWorkerManagementErrorCode,
    AgentWorkerManagementFrame, AgentWorkerManagementKey, AgentWorkerManagementResponse,
    AgentWorkerManagementResult, AgentWorkerManagementSecurity, AgentWorkerManagementTransport,
    AgentWorkerManagementVerifier, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    InMemoryAgentWorkerManagementTransport, ManagedWorkerError,
    AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES, AGENT_WORKER_PROTOCOL_VERSION,
};

use crate::{backends::isolation_backends, handlers::framework_handlers};

const SMOKE_SHARED_SECRET: &str = "agent-worker-smoke-secret";

pub(crate) fn protocol_smoke() -> Result<()> {
    let mut transport =
        InMemoryAgentWorkerManagementTransport::new(AgentWorkerManagementVerifier::new(vec![
            AgentWorkerManagementKey {
                key_id: "agent-worker-smoke-key".to_string(),
                shared_secret: SMOKE_SHARED_SECRET.to_string(),
            },
        ])?);
    let response = transport.accept_management_request(smoke_envelope()?, 1_000);
    if !response.accepted {
        anyhow::bail!(
            "agent-worker management protocol smoke rejected request: {:?}",
            response.error
        );
    }
    println!(
        "agent-worker protocol smoke accepted request_id={} action={}",
        response.request_id,
        response.action.as_str()
    );
    Ok(())
}

pub(crate) fn accept_management_json_command(
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
) -> Result<()> {
    let mut input = String::new();
    read_management_stream(&mut io::stdin(), &mut input)?;
    let response = accept_management_json(
        &input,
        key_id,
        shared_secret,
        now_unix_millis.unwrap_or_else(current_unix_millis),
    )?;
    println!("{response}");
    Ok(())
}

pub(crate) fn serve_management_unix_command(
    socket_path: &Path,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
) -> Result<()> {
    let responses = serve_management_unix(
        socket_path,
        key_id,
        shared_secret,
        now_unix_millis,
        max_requests,
        idle_timeout_millis,
    )?;
    if let Some(response) = responses.last() {
        println!(
            "agent-worker unix management served requests={} last_request_id={} last_accepted={}",
            responses.len(),
            response.request_id,
            response.accepted
        );
    } else {
        println!("agent-worker unix management served requests=0 idle_timeout=true");
    }
    Ok(())
}

fn serve_management_unix(
    socket_path: &Path,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
) -> Result<Vec<ferrogate_runtime::AgentWorkerManagementResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let transport = Arc::new(Mutex::new(InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: key_id.to_string(),
            shared_secret: shared_secret.to_string(),
        }])?,
    )));
    let now_unix_millis = now_unix_millis.unwrap_or_else(current_unix_millis);
    let mut handles = Vec::with_capacity(max_requests);
    let idle_timeout = idle_timeout_millis.map(Duration::from_millis);
    if let Some(timeout) = idle_timeout {
        if timeout.is_zero() {
            anyhow::bail!("idle_timeout_millis must be greater than zero");
        }
        listener.set_nonblocking(true)?;
    }
    let mut idle_started = Instant::now();
    while handles.len() < max_requests {
        match listener.accept() {
            Ok((stream, _)) => {
                let transport = Arc::clone(&transport);
                let shared_secret = shared_secret.to_string();
                handles.push(thread::spawn(move || {
                    handle_management_unix_stream(
                        stream,
                        transport,
                        &shared_secret,
                        now_unix_millis,
                    )
                }));
                idle_started = Instant::now();
            }
            Err(error) if idle_timeout.is_some() && is_idle_accept_error(&error) => {
                let timeout = idle_timeout.expect("guarded by idle_timeout.is_some()");
                if idle_started.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(
                    timeout
                        .saturating_sub(idle_started.elapsed())
                        .min(Duration::from_millis(10)),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _ = std::fs::remove_file(socket_path);
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("agent-worker Unix management thread panicked"))??,
        );
    }
    Ok(responses)
}

fn is_idle_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn handle_management_unix_stream(
    mut stream: std::os::unix::net::UnixStream,
    transport: Arc<Mutex<InMemoryAgentWorkerManagementTransport>>,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    stream.set_nonblocking(false)?;
    let mut input = String::new();
    read_management_stream(&mut stream, &mut input)?;
    let envelope = decode_management_input(&input, shared_secret)?;
    let mut transport = transport
        .lock()
        .map_err(|_| anyhow::anyhow!("agent-worker management transport lock poisoned"))?;
    let response = accept_management_envelope(&mut transport, envelope, now_unix_millis);
    let response_json = serde_json::to_string(&response)?;
    stream.write_all(response_json.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(response)
}

fn accept_management_json(
    input: &str,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<String> {
    if input.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker management request exceeds maximum message size");
    }
    let envelope = decode_management_input(input, shared_secret)?;
    let mut transport =
        InMemoryAgentWorkerManagementTransport::new(AgentWorkerManagementVerifier::new(vec![
            AgentWorkerManagementKey {
                key_id: key_id.to_string(),
                shared_secret: shared_secret.to_string(),
            },
        ])?);
    let response = accept_management_envelope(&mut transport, envelope, now_unix_millis);
    Ok(serde_json::to_string(&response)?)
}

fn decode_management_input(
    input: &str,
    shared_secret: &str,
) -> Result<AgentWorkerManagementEnvelope> {
    if let Ok(envelope) = serde_json::from_str::<AgentWorkerManagementEnvelope>(input) {
        return Ok(envelope);
    }
    let frame: AgentWorkerManagementFrame = serde_json::from_str(input)?;
    frame.decode_envelope(shared_secret).map_err(Into::into)
}

fn read_management_stream<R: Read>(reader: &mut R, output: &mut String) -> Result<()> {
    let mut limited = reader.take((AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_string(output)?;
    if output.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker management request exceeds maximum message size");
    }
    Ok(())
}

fn accept_management_envelope(
    transport: &mut InMemoryAgentWorkerManagementTransport,
    envelope: AgentWorkerManagementEnvelope,
    now_unix_millis: u64,
) -> AgentWorkerManagementResponse {
    let response = transport.accept_management_request(envelope.clone(), now_unix_millis);
    if !response.accepted {
        return response;
    }
    match dispatch_management_action(envelope.clone()) {
        Ok(Some(result)) => response.with_result(result),
        Ok(None) => response,
        Err(error) => AgentWorkerManagementResponse::rejected(&envelope, &error),
    }
}

fn dispatch_management_action(
    envelope: AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    match envelope.action {
        AgentWorkerManagementAction::ProbeHandlers => {
            let handlers = framework_handlers();
            if handlers.iter().any(|handler| handler.ready) {
                Ok(Some(AgentWorkerManagementResult::FrameworkHandlers {
                    handlers,
                }))
            } else {
                Err(ManagedWorkerError::management_protocol_error(
                    AgentWorkerManagementErrorCode::HandlerUnavailable,
                    "agent-worker reported no ready framework handlers",
                ))
            }
        }
        AgentWorkerManagementAction::ListBackends => {
            Ok(Some(AgentWorkerManagementResult::IsolationBackends {
                registry_implemented: true,
                backends: isolation_backends(),
            }))
        }
        AgentWorkerManagementAction::Provision
        | AgentWorkerManagementAction::ExecOrAttach
        | AgentWorkerManagementAction::Stop
        | AgentWorkerManagementAction::Cleanup
        | AgentWorkerManagementAction::StreamStatus
        | AgentWorkerManagementAction::CollectArtifacts => {
            Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::UnsupportedAction,
                format!(
                    "agent-worker management action {} is not implemented by this worker process",
                    envelope.action.as_str()
                ),
            ))
        }
    }
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn smoke_envelope() -> Result<AgentWorkerManagementEnvelope> {
    let mut envelope = AgentWorkerManagementEnvelope {
        protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
        action: AgentWorkerManagementAction::ProbeHandlers,
        request_id: "agent-worker-smoke-request".to_string(),
        idempotency_key: "agent-worker-smoke-idempotency".to_string(),
        issued_at_unix_millis: 900,
        deadline_unix_millis: 2_000,
        tenant_id: "smoke-tenant".to_string(),
        workspace_id: "smoke-workspace".to_string(),
        worker_id: "agent-worker-smoke".to_string(),
        session_id: None,
        run_id: None,
        security: AgentWorkerManagementSecurity {
            key_id: "agent-worker-smoke-key".to_string(),
            nonce: "agent-worker-smoke-nonce".to_string(),
            signature: String::new(),
            algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
            encrypted: true,
        },
    };
    envelope.security.signature = envelope.shared_secret_signature(SMOKE_SHARED_SECRET)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{AgentWorkerManagementFrame, AgentWorkerUnixManagementClient};
    use std::os::unix::net::UnixStream;
    use std::thread;

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
            accept_management_json(&input, "agent-worker-smoke-key", "wrong-secret", 1_000)
                .unwrap();
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
    fn rejects_signed_lifecycle_action_until_worker_implements_handler() {
        let mut envelope = smoke_envelope().unwrap();
        envelope.action = AgentWorkerManagementAction::Provision;
        envelope.request_id = "agent-worker-provision-request".to_string();
        envelope.idempotency_key = "agent-worker-provision-idempotency".to_string();
        envelope.session_id = Some("agent-worker-provision-session".to_string());
        envelope.run_id = Some("agent-worker-provision-run".to_string());
        envelope.security.nonce = "agent-worker-provision-nonce".to_string();
        envelope.security.signature = envelope
            .shared_secret_signature(SMOKE_SHARED_SECRET)
            .unwrap();
        let input = serde_json::to_string(&envelope).unwrap();

        let response_json =
            accept_management_json(&input, "agent-worker-smoke-key", SMOKE_SHARED_SECRET, 1_000)
                .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

        assert_eq!(response["accepted"], false);
        assert_eq!(response["request_id"], "agent-worker-provision-request");
        assert_eq!(response["action"], "provision");
        assert_eq!(response["error"]["code"], "unsupported_action");
        assert_eq!(response["error"]["retryable"], false);
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
        let Some(AgentWorkerManagementResult::FrameworkHandlers { handlers }) = response.result
        else {
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
}
