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
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use ferrogate_runtime::{
    AgentWorkerFrameworkHandler, AgentWorkerManagementAction, AgentWorkerManagementEnvelope,
    AgentWorkerManagementKey, AgentWorkerManagementSecurity, AgentWorkerManagementTransport,
    AgentWorkerManagementVerifier, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    InMemoryAgentWorkerManagementTransport, AGENT_WORKER_PROTOCOL_VERSION,
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
        } => serve_management_unix_command(&socket_path, &key_id, &shared_secret, now_unix_millis),
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
) -> Result<()> {
    let response = serve_one_management_unix(socket_path, key_id, shared_secret, now_unix_millis)?;
    println!(
        "agent-worker unix management accepted request_id={} accepted={}",
        response.request_id, response.accepted
    );
    Ok(())
}

fn serve_one_management_unix(
    socket_path: &Path,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let result = accept_one_management_unix_connection(
        &listener,
        key_id,
        shared_secret,
        now_unix_millis.unwrap_or_else(current_unix_millis),
    );
    let _ = std::fs::remove_file(socket_path);
    result
}

fn accept_one_management_unix_connection(
    listener: &UnixListener,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    let (mut stream, _) = listener.accept()?;
    let mut input = String::new();
    stream.read_to_string(&mut input)?;
    let response_json = accept_management_json(&input, key_id, shared_secret, now_unix_millis)?;
    stream.write_all(response_json.as_bytes())?;
    stream.write_all(b"\n")?;
    let response = serde_json::from_str(&response_json)?;
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
    let response = transport.accept_management_request(envelope, now_unix_millis);
    Ok(serde_json::to_string(&response)?)
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
    fn accepts_signed_management_json_over_unix_socket_transport() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("agent-worker-management.sock");
        let socket_for_server = socket_path.clone();
        let server = thread::spawn(move || {
            serve_one_management_unix(
                &socket_for_server,
                "agent-worker-smoke-key",
                SMOKE_SHARED_SECRET,
                Some(1_000),
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
        assert!(response.error.is_none());

        let server_response = server.join().unwrap();
        assert!(server_response.accepted);
        assert_eq!(server_response.request_id, "agent-worker-smoke-request");
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
