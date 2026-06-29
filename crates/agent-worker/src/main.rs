// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

mod backends;
mod external_actions;
mod handler_runtime;
mod handlers;
mod lifecycle;
mod management;
mod state;

#[cfg(test)]
mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static FIRECRACKER_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static HANDLER_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(crate) fn lock_firecracker_env() -> MutexGuard<'static, ()> {
        FIRECRACKER_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("firecracker env test lock poisoned")
    }

    pub(crate) fn lock_handler_env() -> MutexGuard<'static, ()> {
        HANDLER_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("handler env test lock poisoned")
    }
}

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
    /// Emit the worker-owned Firecracker prepare plan without starting a microVM.
    FirecrackerPreparePlan,
    /// Execute the configured framework handler binary smoke inside agent-worker ownership.
    SmokeHandlerBinary {
        /// Adapter to smoke: codex, claude-code, or hermes.
        #[arg(long)]
        adapter: String,
        /// Maximum time to wait for the binary probe command.
        #[arg(long, default_value_t = 2_000)]
        timeout_millis: u64,
    },
    /// Run a managed external-action authorization smoke without executing the action.
    ExternalActionSmoke,
    /// Accept one managed external-action authorization request as JSON on stdin.
    AcceptExternalActionJson,
    /// Run the Unix socket gateway-authorizer transport smoke without executing the action.
    ExternalActionUnixTransportSmoke,
    /// Call a gateway HTTP authorizer transport smoke without executing the action.
    ExternalActionHttpTransportSmoke {
        /// Gateway external action authorizer HTTP endpoint.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_HTTP_ENDPOINT")]
        gateway_authorizer_http_endpoint: SocketAddr,
    },
    /// Execute a local governed CLI smoke after gateway authorization.
    GovernedCliExecutionSmoke,
    /// Execute a local governed tool smoke after gateway authorization.
    GovernedToolExecutionSmoke,
    /// Execute a local governed MCP tool smoke after gateway authorization.
    GovernedMcpToolExecutionSmoke,
    /// Execute a local governed skill smoke after gateway authorization.
    GovernedSkillExecutionSmoke,
    /// Execute local governed memory read/write smokes after gateway authorization.
    GovernedMemoryExecutionSmoke,
    /// Execute a local governed secret access smoke after gateway authorization.
    GovernedSecretExecutionSmoke,
    /// Execute a local governed loopback network egress smoke after gateway authorization.
    GovernedNetworkEgressExecutionSmoke,
    /// Execute a local governed browser action smoke after gateway authorization.
    GovernedBrowserExecutionSmoke,
    /// Execute a local governed REST smoke after gateway authorization.
    GovernedRestExecutionSmoke,
    /// Execute a local governed filesystem read smoke after gateway authorization.
    GovernedFilesystemExecutionSmoke,
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
    /// Serve signed management JSON over the HTTP management API.
    ServeManagementHttp {
        /// HTTP listen address for the management API.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_HTTP_ADDR")]
        listen: SocketAddr,
        /// Gateway external action authorizer endpoint required before handler actions continue.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_HTTP_ENDPOINT")]
        external_action_authorizer_http_endpoint: Option<SocketAddr>,
        /// Management key id expected in the signed envelope.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_KEY_ID")]
        key_id: String,
        /// Shared secret used to verify the envelope MAC.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_SHARED_SECRET")]
        shared_secret: String,
        /// Verification time override for deterministic contract tests.
        #[arg(long)]
        now_unix_millis: Option<u64>,
        /// Number of HTTP management requests to accept before exiting.
        #[arg(long, default_value_t = 1)]
        max_requests: usize,
        /// Exit after this many idle milliseconds without a new HTTP connection.
        #[arg(long)]
        idle_timeout_millis: Option<u64>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ProtocolSmoke => management::protocol_smoke(),
        Command::ProbeHandlers => handlers::probe_handlers_command(),
        Command::FirecrackerPreparePlan => backends::firecracker_prepare_plan_command(),
        Command::SmokeHandlerBinary {
            adapter,
            timeout_millis,
        } => handlers::smoke_handler_binary_command(&adapter, timeout_millis),
        Command::ExternalActionSmoke => external_actions::external_action_smoke_command(),
        Command::AcceptExternalActionJson => {
            external_actions::accept_external_action_json_command()
        }
        Command::ExternalActionUnixTransportSmoke => {
            external_actions::external_action_unix_transport_smoke_command()
        }
        Command::ExternalActionHttpTransportSmoke {
            gateway_authorizer_http_endpoint,
        } => external_actions::external_action_http_transport_smoke_command(
            gateway_authorizer_http_endpoint,
        ),
        Command::GovernedCliExecutionSmoke => {
            external_actions::governed_cli_execution_smoke_command()
        }
        Command::GovernedToolExecutionSmoke => {
            external_actions::governed_tool_execution_smoke_command()
        }
        Command::GovernedMcpToolExecutionSmoke => {
            external_actions::governed_mcp_tool_execution_smoke_command()
        }
        Command::GovernedSkillExecutionSmoke => {
            external_actions::governed_skill_execution_smoke_command()
        }
        Command::GovernedMemoryExecutionSmoke => {
            external_actions::governed_memory_execution_smoke_command()
        }
        Command::GovernedSecretExecutionSmoke => {
            external_actions::governed_secret_execution_smoke_command()
        }
        Command::GovernedNetworkEgressExecutionSmoke => {
            external_actions::governed_network_egress_execution_smoke_command()
        }
        Command::GovernedBrowserExecutionSmoke => {
            external_actions::governed_browser_execution_smoke_command()
        }
        Command::GovernedRestExecutionSmoke => {
            external_actions::governed_rest_execution_smoke_command()
        }
        Command::GovernedFilesystemExecutionSmoke => {
            external_actions::governed_filesystem_execution_smoke_command()
        }
        Command::AcceptManagementJson {
            key_id,
            shared_secret,
            now_unix_millis,
        } => management::accept_management_json_command(&key_id, &shared_secret, now_unix_millis),
        Command::ServeManagementUnix {
            socket_path,
            key_id,
            shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
        } => management::serve_management_unix_command(
            &socket_path,
            &key_id,
            &shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
        ),
        Command::ServeManagementHttp {
            listen,
            external_action_authorizer_http_endpoint,
            key_id,
            shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
        } => management::serve_management_http_command(
            listen,
            &key_id,
            &shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
            external_action_authorizer_http_endpoint,
        ),
    }
}
