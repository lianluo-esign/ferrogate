// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    io::{self, Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use ferrogate_runtime::{
    AgentWorkerFrameworkHandler, AgentWorkerManagementAction, AgentWorkerManagementEnvelope,
    AgentWorkerManagementErrorCode, AgentWorkerManagementKey, AgentWorkerManagementResponse,
    AgentWorkerManagementResult, AgentWorkerManagementSecurity, AgentWorkerManagementTransport,
    AgentWorkerManagementVerifier, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    InMemoryAgentWorkerManagementTransport, ManagedWorkerError, AGENT_WORKER_PROTOCOL_VERSION,
};
use serde_json::json;

const SMOKE_SHARED_SECRET: &str = "agent-worker-smoke-secret";

#[derive(Debug, Parser)]
#[command(name = "agent-worker")]
#[command(about = "Standalone FerroGate agent-worker process boundary")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a local management protocol smoke test without starting Firecracker.
    ProtocolSmoke,
    /// Probe framework handler readiness inside the agent-worker process.
    ProbeHandlers,
    /// Accept one signed management envelope as JSON on stdin and emit a JSON response.
    AcceptManagementJson {
        /// Management key id expected in the signed envelope.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_KEY_ID")]
        key_id: String,
        /// Shared secret used to verify the envelope MAC.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_SHARED_SECRET")]
        shared_secret: String,
        /// Verification time override for deterministic contract tests.
        #[arg(long)]
        now_unix_millis: Option<u64>,
    },
    /// Serve one signed management JSON request over a Unix domain socket.
    ServeManagementUnix {
        /// Unix socket path used for the management transport.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_SOCKET")]
        socket_path: PathBuf,
        /// Management key id expected in the signed envelope.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_KEY_ID")]
        key_id: String,
        /// Shared secret used to verify the envelope MAC.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_SHARED_SECRET")]
        shared_secret: String,
        /// Verification time override for deterministic contract tests.
        #[arg(long)]
        now_unix_millis: Option<u64>,
        /// Number of management requests to accept before exiting.
        #[arg(long, default_value_t = 1)]
        max_requests: usize,
        /// Exit after this many idle milliseconds without a new management connection.
        #[arg(long)]
        idle_timeout_millis: Option<u64>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ProtocolSmoke => protocol_smoke(),
        Command::ProbeHandlers => probe_handlers(),
        Command::AcceptManagementJson {
            key_id,
            shared_secret,
            now_unix_millis,
        } => accept_management_json_command(&key_id, &shared_secret, now_unix_millis),
        Command::ServeManagementUnix {
            socket_path,
            key_id,
            shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
        } => serve_management_unix_command(
            &socket_path,
            &key_id,
            &shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
        ),
    }
}

fn protocol_smoke() -> Result<()> {
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

fn probe_handlers() -> Result<()> {
    let handlers = framework_handlers();
    println!("{}", handlers_json(&handlers));
    Ok(())
}

fn accept_management_json_command(
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
) -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let response = accept_management_json(
        &input,
        key_id,
        shared_secret,
        now_unix_millis.unwrap_or_else(current_unix_millis),
    )?;
    println!("{response}");
    Ok(())
}

fn serve_management_unix_command(
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
                handles.push(thread::spawn(move || {
                    handle_management_unix_stream(stream, transport, now_unix_millis)
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
    now_unix_millis: u64,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    stream.set_nonblocking(false)?;
    let mut input = String::new();
    stream.read_to_string(&mut input)?;
    let envelope: AgentWorkerManagementEnvelope = serde_json::from_str(&input)?;
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
    let envelope: AgentWorkerManagementEnvelope = serde_json::from_str(input)?;
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
            Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::IncompatibleBackend,
                "agent-worker isolation backend registry is not implemented by this worker process",
            ))
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

fn framework_handlers() -> Vec<AgentWorkerFrameworkHandler> {
    vec![
        AgentWorkerFrameworkHandler {
            adapter_name: "native-harness".to_string(),
            framework: "native_harness".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ready: true,
            readiness_reason: Some(
                "native harness is built into the agent-worker process".to_string(),
            ),
        },
        probed_binary_handler(
            "codex",
            "codex",
            "AGENT_WORKER_CODEX_BIN",
            "Codex CLI binary path was not configured",
        ),
        probed_binary_handler(
            "claude-code",
            "claude_code",
            "AGENT_WORKER_CLAUDE_CODE_BIN",
            "Claude Code binary path was not configured",
        ),
        probed_binary_handler(
            "hermes",
            "hermes",
            "AGENT_WORKER_HERMES_BIN",
            "Hermes binary path was not configured",
        ),
    ]
}

fn probed_binary_handler(
    adapter_name: &str,
    framework: &str,
    env_var: &str,
    missing_message: &str,
) -> AgentWorkerFrameworkHandler {
    match env::var(env_var) {
        Ok(path) if !path.trim().is_empty() && Path::new(&path).is_file() => {
            AgentWorkerFrameworkHandler {
                adapter_name: adapter_name.to_string(),
                framework: framework.to_string(),
                version: "external".to_string(),
                ready: true,
                readiness_reason: Some(format!("{env_var} points to executable candidate {path}")),
            }
        }
        Ok(path) if !path.trim().is_empty() => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "unknown".to_string(),
            ready: false,
            readiness_reason: Some(format!("{env_var} does not point to a file: {path}")),
        },
        _ => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "unknown".to_string(),
            ready: false,
            readiness_reason: Some(missing_message.to_string()),
        },
    }
}

fn handlers_json(handlers: &[AgentWorkerFrameworkHandler]) -> String {
    let handlers = handlers
        .iter()
        .map(|handler| {
            json!({
                "adapter_name": handler.adapter_name,
                "framework": handler.framework,
                "version": handler.version,
                "ready": handler.ready,
                "readiness_reason": handler.readiness_reason,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "process": "agent-worker",
        "handler_owner": "agent-worker",
        "gateway_handler_probe": false,
        "handlers": handlers,
    })
    .to_string()
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
    use ferrogate_runtime::AgentWorkerUnixManagementClient;
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
    fn framework_handler_probe_reports_native_ready_without_path_scanning() {
        env::remove_var("AGENT_WORKER_CODEX_BIN");
        env::remove_var("AGENT_WORKER_CLAUDE_CODE_BIN");
        env::remove_var("AGENT_WORKER_HERMES_BIN");

        let handlers = framework_handlers();

        let native = handlers
            .iter()
            .find(|handler| handler.adapter_name == "native-harness")
            .unwrap();
        assert!(native.ready);
        assert_eq!(native.framework, "native_harness");

        let codex = handlers
            .iter()
            .find(|handler| handler.adapter_name == "codex")
            .unwrap();
        assert!(!codex.ready);
        assert!(codex
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("was not configured")));

        let json = handlers_json(&handlers);
        assert!(json.contains(r#""handler_owner":"agent-worker""#));
        assert!(json.contains(r#""gateway_handler_probe":false"#));
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
    fn rejects_signed_lifecycle_action_until_worker_implements_handler() {
        let mut envelope = smoke_envelope().unwrap();
        envelope.action = AgentWorkerManagementAction::Provision;
        envelope.request_id = "agent-worker-provision-request".to_string();
        envelope.idempotency_key = "agent-worker-provision-idempotency".to_string();
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
    fn routes_signed_backend_listing_to_backend_dispatch_stub() {
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

        assert_eq!(response["accepted"], false);
        assert_eq!(response["request_id"], "agent-worker-list-backends-request");
        assert_eq!(response["action"], "list_backends");
        assert_eq!(response["error"]["code"], "incompatible_backend");
        assert_eq!(response["error"]["retryable"], false);
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
