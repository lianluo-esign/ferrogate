// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

mod backends;
mod cloudflare_container_backend;
mod cloudflare_container_lifecycle;
mod docker_backend;
mod events;
mod external_actions;
mod firecracker_guest_exec;
mod handler_runtime;
mod handlers;
mod lifecycle;
mod local_process_backend;
mod management;
mod recorded_evidence;
mod self_hosted_execution;
mod state;
mod x402_client;

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

/// The worker deployment type this shared `agent-worker` binary runs as.
///
/// Cloud (FerroGate-managed) vs self-hosted (customer-operated) is a
/// trust/enforcement POLICY toggle, not a different program: both share the
/// same isolation backends, framework-handler adapters, and normalized event
/// schema. FerroGate therefore ships ONE `agent-worker` binary and selects the
/// type with `--worker-type` (which maps to `FrameworkAdapterMode`), rather
/// than building two separate binaries (issue #132).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum WorkerType {
    /// FerroGate-hosted managed runtime; capability actions are enforced.
    Cloud,
    /// Customer self-hosted worker; capability actions are report-only and
    /// identity expiry is stamped by the server clock (security boundary).
    #[value(name = "self-hosted")]
    SelfHosted,
}

impl WorkerType {
    fn framework_adapter_mode(self) -> ferrogate_runtime::FrameworkAdapterMode {
        match self {
            WorkerType::Cloud => ferrogate_runtime::FrameworkAdapterMode::Managed,
            WorkerType::SelfHosted => ferrogate_runtime::FrameworkAdapterMode::SelfHosted,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            WorkerType::Cloud => "cloud",
            WorkerType::SelfHosted => "self-hosted",
        }
    }
}

#[cfg(test)]
#[path = "worker_type_test.rs"]
mod worker_type_test;

#[derive(Debug, Parser)]
#[command(name = "agent-worker")]
#[command(about = "Standalone FerroGate agent-worker process boundary")]
#[command(version)]
struct Cli {
    /// Hidden compatibility entrypoint used by Firecracker guest-agent launch probes.
    #[arg(long = "ferrogate-guest-agent-probe", hide = true)]
    ferrogate_guest_agent_probe: bool,
    /// Hidden compatibility entrypoint used by Firecracker guest-agent start RPC.
    #[arg(long = "ferrogate-guest-agent-start", hide = true)]
    ferrogate_guest_agent_start: bool,
    /// Hidden guest-side entrypoint: serve real execution sessions on the
    /// microVM AF_VSOCK port (#280). Started by the guest init from the
    /// agent-worker binary staged in the rootfs.
    #[arg(long = "ferrogate-guest-agent-serve-vsock", hide = true)]
    ferrogate_guest_agent_serve_vsock: bool,
    /// Worker deployment type for this shared binary: `cloud` (FerroGate-managed
    /// runtime) or `self-hosted` (customer-operated). One binary, mode-selected
    /// (issue #132).
    #[arg(long, value_enum, default_value = "cloud", global = true)]
    worker_type: WorkerType,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the resolved worker type and its trust/enforcement semantics.
    WorkerType,
    /// Run a self-hosted report-only governed CLI workload through the
    /// local-process isolation backend. Only meaningful under
    /// `--worker-type self-hosted`: a capability cloud would BLOCK is recorded
    /// as report-only and the workload runs anyway (issue #242).
    SelfHostedGovernedExecutionSmoke {
        /// Server-clock override (unix millis) for deterministic identity
        /// expiry stamping in contract tests.
        #[arg(long)]
        now_unix_millis: Option<u64>,
    },
    /// Run a self-hosted report-only governed workload by BOOTING a Firecracker
    /// microVM through the governed backend (KVM-validated, #227). Only
    /// meaningful under `--worker-type self-hosted`: a capability cloud would
    /// BLOCK is recorded as report-only and the microVM boots anyway (issue
    /// #247). Fails closed if the KVM/firecracker prerequisites are unavailable.
    SelfHostedFirecrackerExecutionSmoke {
        /// Maximum time to wait for API readiness and guest serial boot evidence.
        #[arg(long, default_value_t = 15_000)]
        timeout_millis: u64,
        /// vCPU count for the report-only smoke microVM.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Guest memory in MiB for the report-only smoke microVM.
        #[arg(long, default_value_t = 256)]
        mem_size_mib: u32,
        /// Server-clock override (unix millis) for deterministic identity
        /// expiry stamping in contract tests.
        #[arg(long)]
        now_unix_millis: Option<u64>,
    },
    /// Run a local management protocol smoke test without starting Firecracker.
    ProtocolSmoke,
    /// Probe framework handler readiness inside the agent-worker process.
    ProbeHandlers,
    /// Emit the worker-owned Firecracker prepare plan without starting a microVM.
    FirecrackerPreparePlan,
    /// Emit worker-owned Firecracker host readiness preflight without starting a microVM.
    FirecrackerHostPreflight,
    /// Emit worker-owned Firecracker guest-agent channel preflight without starting a microVM.
    FirecrackerGuestAgentPreflight,
    /// Emit worker-owned Firecracker guest handler launch plan without starting a microVM.
    FirecrackerGuestLaunchPlan {
        /// Adapter the future guest handler launch should target.
        #[arg(long)]
        adapter: Option<String>,
    },
    /// Boot a configured Firecracker microVM and require serial-console boot evidence.
    FirecrackerBootSmoke {
        /// Maximum time to wait for API readiness and guest serial boot evidence.
        #[arg(long, default_value_t = 15_000)]
        timeout_millis: u64,
        /// vCPU count for the local smoke microVM.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Guest memory in MiB for the local smoke microVM.
        #[arg(long, default_value_t = 256)]
        mem_size_mib: u32,
    },
    /// Provision, status-check, and cleanup a real Firecracker microVM in one worker process.
    FirecrackerLifecycleSmoke,
    /// Boot a Firecracker microVM and execute real allowed + denied agent
    /// workloads inside the guest over the vsock channel, asserting the
    /// capability envelope is enforced at the VM boundary (#280). Requires a
    /// KVM host with the guest agent staged in the rootfs; fails closed with
    /// microvm_required_backend_unavailable evidence anywhere else.
    FirecrackerAgentExecSmoke {
        /// Maximum time to wait for boot plus the guest agent to accept.
        #[arg(long, default_value_t = 90_000)]
        timeout_millis: u64,
        /// vCPU count for the smoke microVM.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Guest memory in MiB for the smoke microVM.
        #[arg(long, default_value_t = 256)]
        mem_size_mib: u32,
        /// vsock port the staged guest agent listens on (defaults to
        /// AGENT_WORKER_FIRECRACKER_GUEST_VSOCK_PORT, then 5252).
        #[arg(long)]
        vsock_port: Option<u32>,
    },
    /// Execute the configured framework handler binary smoke inside agent-worker ownership.
    SmokeHandlerBinary {
        /// Adapter to smoke: codex, claude-code, or hermes.
        #[arg(long)]
        adapter: String,
        /// Maximum time to wait for the binary probe command.
        #[arg(long, default_value_t = 2_000)]
        timeout_millis: u64,
    },
    /// Execute a configured framework handler task smoke inside agent-worker ownership.
    SmokeHandlerTask {
        /// Adapter to smoke: codex, claude-code, or hermes.
        #[arg(long)]
        adapter: String,
        /// Maximum time to wait for the task smoke command.
        #[arg(long, default_value_t = 30_000)]
        timeout_millis: u64,
        /// Minimal prompt sent to the configured handler binary.
        #[arg(
            long,
            default_value = "Return exactly: ferrogate-agent-worker-task-smoke"
        )]
        prompt: String,
    },
    /// Run a managed external-action authorization smoke without executing the action.
    ExternalActionSmoke,
    /// Accept one managed external-action authorization request as JSON on stdin.
    AcceptExternalActionJson,
    /// Run the Unix socket gateway-authorizer transport smoke without executing the action.
    ExternalActionUnixTransportSmoke,
    /// Execute all target-governed action families through a live gateway Unix authorizer.
    GovernedTargetExecutionUnixSmoke {
        /// Gateway external action authorizer Unix socket.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_SOCKET")]
        gateway_authorizer_socket: PathBuf,
        /// Kernel-authenticated PID expected on the gateway Unix socket.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_PID")]
        gateway_authorizer_pid: u32,
        /// Workspace root containing the authorized filesystem smoke target.
        #[arg(long)]
        workspace_root: PathBuf,
        /// Pinned loopback endpoint authorized for the network smoke target.
        #[arg(long)]
        network_target: SocketAddr,
    },
    /// Execute a local governed CLI smoke after gateway authorization.
    GovernedCliExecutionSmoke,
    /// Execute a local governed CLI timeout smoke after gateway authorization.
    GovernedCliTimeoutSmoke,
    /// Execute a local governed CLI cancellation smoke after gateway authorization.
    GovernedCliCancelSmoke,
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
        /// Gateway Unix authorizer required before handler actions continue.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_SOCKET")]
        external_action_authorizer_socket: Option<PathBuf>,
        /// Kernel-authenticated PID expected on the gateway Unix socket.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_PID")]
        external_action_authorizer_pid: Option<u32>,
    },
    /// Serve signed management JSON over the HTTP management API.
    ServeManagementHttp {
        /// HTTP listen address for the management API.
        #[arg(long, env = "AGENT_WORKER_MANAGEMENT_HTTP_ADDR")]
        listen: SocketAddr,
        /// Gateway Unix authorizer required before handler actions continue.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_SOCKET")]
        external_action_authorizer_socket: Option<PathBuf>,
        /// Kernel-authenticated PID expected on the gateway Unix socket.
        #[arg(long, env = "AGENT_WORKER_EXTERNAL_ACTION_AUTHORIZER_PID")]
        external_action_authorizer_pid: Option<u32>,
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

fn print_worker_type(worker_type: WorkerType) -> Result<()> {
    let mode = worker_type.framework_adapter_mode();
    let evidence = serde_json::json!({
        "binary": "agent-worker",
        "shared_binary": true,
        "worker_type": worker_type.as_str(),
        "framework_adapter_mode": mode.as_str(),
        "capability_enforcement": match worker_type {
            WorkerType::Cloud => "enforced",
            WorkerType::SelfHosted => "reported",
        },
        "identity_expiry_clock": match worker_type {
            WorkerType::Cloud => "not_applicable",
            WorkerType::SelfHosted => "server",
        },
        "note": "cloud vs self-hosted is a policy toggle on one shared binary (issue #132)",
    });
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

/// Per-command self-hosted support classification.
///
/// Self-hosted execution is no longer a blanket fail-closed toggle (issue
/// #242). Covered commands run real report-only, non-enforced execution
/// through the local-process isolation backend; genuinely-uncovered commands
/// stay fail-closed with an accurate, actionable message rather than silently
/// running as `cloud`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfHostedCommandSupport {
    /// Diagnostic-only: never executes a workload (just prints resolved policy).
    Diagnostic,
    /// Runs real report-only self-hosted execution (issue #242, first slice).
    ReportOnly,
    /// Not yet covered under self-hosted; fails closed with an honest message.
    FailClosed,
}

/// Which self-hosted execution surface a command is on.
///
/// Covered (real report-only execution):
/// - #242 first slice: the `worker-type` diagnostic, the management-serving path
///   (`ServeManagementUnix`/`ServeManagementHttp`/`AcceptManagementJson`), and
///   the dedicated `SelfHostedGovernedExecutionSmoke` (local-process backend).
/// - #245: the decoupled governed external-action families — tool, MCP tool,
///   skill, memory, secret, and browser — run report-only through the shared
///   `run_governed_workload` engine (in-process governed handler).
/// - #247: `GovernedNetworkEgressExecutionSmoke`/`GovernedRestExecutionSmoke`
///   run report-only against a live loopback endpoint (real I/O, decision
///   recorded), and `SelfHostedFirecrackerExecutionSmoke` boots a microVM
///   report-only through the governed Firecracker backend.
///
/// Still fail-closed (accurate per-command message):
/// - CLI (`GovernedCli*`) and `GovernedFilesystemExecutionSmoke`: their
///   authorized execution is bound to the ALLOW decision's canonical-target
///   fingerprint, so a denied capability cannot route through them. CLI
///   report-only-on-deny is already delivered by the #242 dedicated smoke.
/// - The external-action authorization/transport smokes and the Unix
///   target-execution smoke: authorization/transport probes, not workload
///   execution.
fn self_hosted_command_support(command: &Command) -> SelfHostedCommandSupport {
    match command {
        Command::WorkerType => SelfHostedCommandSupport::Diagnostic,
        Command::SelfHostedGovernedExecutionSmoke { .. }
        | Command::ServeManagementUnix { .. }
        | Command::ServeManagementHttp { .. }
        | Command::AcceptManagementJson { .. }
        // #245: decoupled governed external-action families run report-only.
        | Command::GovernedToolExecutionSmoke
        | Command::GovernedMcpToolExecutionSmoke
        | Command::GovernedSkillExecutionSmoke
        | Command::GovernedMemoryExecutionSmoke
        | Command::GovernedSecretExecutionSmoke
        | Command::GovernedBrowserExecutionSmoke
        // #247: network-egress + REST run report-only against a live loopback
        // endpoint (real I/O, decision recorded); the Firecracker report-only
        // path boots a microVM through the governed backend.
        | Command::GovernedNetworkEgressExecutionSmoke
        | Command::GovernedRestExecutionSmoke
        | Command::SelfHostedFirecrackerExecutionSmoke { .. } => {
            SelfHostedCommandSupport::ReportOnly
        }
        // TODO(#247): CLI/filesystem (canonical-target fingerprint bound), the
        // external-action authorization/transport smokes, and the remaining
        // Firecracker guest-handler probe paths stay fail-closed rather than
        // silently running as cloud.
        _ => SelfHostedCommandSupport::FailClosed,
    }
}

/// Fail closed for commands not yet covered under self-hosted, with an accurate
/// per-command message. Covered and diagnostic commands are allowed through so
/// they can run real report-only execution.
fn reject_unsupported_self_hosted_execution(
    worker_type: WorkerType,
    command: &Command,
) -> Result<()> {
    if worker_type == WorkerType::SelfHosted
        && self_hosted_command_support(command) == SelfHostedCommandSupport::FailClosed
    {
        bail!(
            "--worker-type self-hosted is not yet implemented for `{command:?}`: this build \
             wires report-only self-hosted execution for the management-serving path \
             (serve-management-unix/http, accept-management-json) and the \
             self-hosted-governed-execution-smoke entrypoint (#242), the decoupled governed \
             families tool/mcp-tool/skill/memory/secret/browser (#245), and network-egress/REST \
             plus the self-hosted-firecracker-execution-smoke microVM boot (#247), but not this \
             subcommand yet. CLI/filesystem execution is bound to the allow-decision \
             canonical-target fingerprint (CLI report-only is covered by \
             self-hosted-governed-execution-smoke); the external-action authorization/transport \
             smokes are authorization probes, not workload execution. Use --worker-type cloud \
             (the default) for it, or run a covered command under --worker-type self-hosted."
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let guest_entrypoints = [
        cli.ferrogate_guest_agent_probe,
        cli.ferrogate_guest_agent_start,
        cli.ferrogate_guest_agent_serve_vsock,
    ]
    .iter()
    .filter(|selected| **selected)
    .count();
    if guest_entrypoints > 1 {
        bail!("only one Firecracker guest-agent entrypoint may be selected");
    }
    if cli.ferrogate_guest_agent_probe {
        return backends::firecracker_guest_agent_probe_entrypoint();
    }
    if cli.ferrogate_guest_agent_start {
        return backends::firecracker_guest_agent_start_entrypoint();
    }
    if cli.ferrogate_guest_agent_serve_vsock {
        return firecracker_guest_exec::firecracker_guest_agent_serve_vsock_entrypoint();
    }
    let Some(command) = cli.command else {
        bail!("no agent-worker command provided");
    };
    reject_unsupported_self_hosted_execution(cli.worker_type, &command)?;
    let worker_mode = cli.worker_type.framework_adapter_mode();
    match command {
        Command::WorkerType => print_worker_type(cli.worker_type),
        Command::SelfHostedGovernedExecutionSmoke { now_unix_millis } => {
            self_hosted_execution::self_hosted_governed_execution_smoke_command(
                now_unix_millis.unwrap_or_else(management::current_unix_millis),
            )
        }
        Command::SelfHostedFirecrackerExecutionSmoke {
            timeout_millis,
            vcpu_count,
            mem_size_mib,
            now_unix_millis,
        } => self_hosted_execution::self_hosted_firecracker_execution_smoke_command(
            timeout_millis,
            vcpu_count,
            mem_size_mib,
            now_unix_millis.unwrap_or_else(management::current_unix_millis),
        ),
        Command::ProtocolSmoke => management::protocol_smoke(),
        Command::ProbeHandlers => handlers::probe_handlers_command(),
        Command::FirecrackerPreparePlan => backends::firecracker_prepare_plan_command(),
        Command::FirecrackerHostPreflight => backends::firecracker_host_preflight_command(),
        Command::FirecrackerGuestAgentPreflight => {
            backends::firecracker_guest_agent_preflight_command()
        }
        Command::FirecrackerGuestLaunchPlan { adapter } => {
            backends::firecracker_guest_launch_plan_command(adapter.as_deref())
        }
        Command::FirecrackerBootSmoke {
            timeout_millis,
            vcpu_count,
            mem_size_mib,
        } => backends::firecracker_boot_smoke_command(timeout_millis, vcpu_count, mem_size_mib),
        Command::FirecrackerLifecycleSmoke => management::firecracker_lifecycle_smoke_command(),
        Command::FirecrackerAgentExecSmoke {
            timeout_millis,
            vcpu_count,
            mem_size_mib,
            vsock_port,
        } => backends::firecracker_agent_exec_smoke_command(
            timeout_millis,
            vcpu_count,
            mem_size_mib,
            vsock_port,
        ),
        Command::SmokeHandlerBinary {
            adapter,
            timeout_millis,
        } => handlers::smoke_handler_binary_command(&adapter, timeout_millis),
        Command::SmokeHandlerTask {
            adapter,
            timeout_millis,
            prompt,
        } => handlers::smoke_handler_task_command(&adapter, timeout_millis, &prompt),
        Command::ExternalActionSmoke => {
            external_actions::external_action_smoke_command(worker_mode)
        }
        Command::AcceptExternalActionJson => {
            external_actions::accept_external_action_json_command()
        }
        Command::ExternalActionUnixTransportSmoke => {
            external_actions::external_action_unix_transport_smoke_command(worker_mode)
        }
        Command::GovernedTargetExecutionUnixSmoke {
            gateway_authorizer_socket,
            gateway_authorizer_pid,
            workspace_root,
            network_target,
        } => external_actions::governed_target_execution_unix_smoke_command(
            &gateway_authorizer_socket,
            gateway_authorizer_pid,
            &workspace_root,
            network_target,
            worker_mode,
        ),
        Command::GovernedCliExecutionSmoke => {
            external_actions::governed_cli_execution_smoke_command(worker_mode)
        }
        Command::GovernedCliTimeoutSmoke => {
            external_actions::governed_cli_timeout_smoke_command(worker_mode)
        }
        Command::GovernedCliCancelSmoke => {
            external_actions::governed_cli_cancel_smoke_command(worker_mode)
        }
        Command::GovernedToolExecutionSmoke => {
            external_actions::governed_tool_execution_smoke_command(worker_mode)
        }
        Command::GovernedMcpToolExecutionSmoke => {
            external_actions::governed_mcp_tool_execution_smoke_command(worker_mode)
        }
        Command::GovernedSkillExecutionSmoke => {
            external_actions::governed_skill_execution_smoke_command(worker_mode)
        }
        Command::GovernedMemoryExecutionSmoke => {
            external_actions::governed_memory_execution_smoke_command(worker_mode)
        }
        Command::GovernedSecretExecutionSmoke => {
            external_actions::governed_secret_execution_smoke_command(worker_mode)
        }
        Command::GovernedNetworkEgressExecutionSmoke => {
            external_actions::governed_network_egress_execution_smoke_command(worker_mode)
        }
        Command::GovernedBrowserExecutionSmoke => {
            external_actions::governed_browser_execution_smoke_command(worker_mode)
        }
        Command::GovernedRestExecutionSmoke => {
            external_actions::governed_rest_execution_smoke_command(worker_mode)
        }
        Command::GovernedFilesystemExecutionSmoke => {
            external_actions::governed_filesystem_execution_smoke_command(worker_mode)
        }
        Command::AcceptManagementJson {
            key_id,
            shared_secret,
            now_unix_millis,
        } => management::accept_management_json_command(
            &key_id,
            &shared_secret,
            now_unix_millis,
            worker_mode,
        ),
        Command::ServeManagementUnix {
            socket_path,
            key_id,
            shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
            external_action_authorizer_socket,
            external_action_authorizer_pid,
        } => management::serve_management_unix_command(
            &socket_path,
            &key_id,
            &shared_secret,
            now_unix_millis,
            max_requests,
            idle_timeout_millis,
            management::external_authorizer_config(
                external_action_authorizer_socket,
                external_action_authorizer_pid,
            )?,
            worker_mode,
        ),
        Command::ServeManagementHttp {
            listen,
            external_action_authorizer_socket,
            external_action_authorizer_pid,
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
            management::external_authorizer_config(
                external_action_authorizer_socket,
                external_action_authorizer_pid,
            )?,
            worker_mode,
        ),
    }
}
