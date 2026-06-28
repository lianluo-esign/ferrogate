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

    pub(crate) fn lock_firecracker_env() -> MutexGuard<'static, ()> {
        FIRECRACKER_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("firecracker env test lock poisoned")
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
    /// Run a managed external-action authorization smoke without executing the action.
    ExternalActionSmoke,
    /// Accept one managed external-action authorization request as JSON on stdin.
    AcceptExternalActionJson,
    /// Run the Unix socket gateway-authorizer transport smoke without executing the action.
    ExternalActionUnixTransportSmoke,
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
        Command::ExternalActionSmoke => external_actions::external_action_smoke_command(),
        Command::AcceptExternalActionJson => {
            external_actions::accept_external_action_json_command()
        }
        Command::ExternalActionUnixTransportSmoke => {
            external_actions::external_action_unix_transport_smoke_command()
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
        ),
    }
}
