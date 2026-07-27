// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Real Firecracker guest-agent execution over the microVM vsock channel
//! (issue #280).
//!
//! Every retained microVM is provisioned with a `guest-rpc` vsock device whose
//! host side is a Unix socket in the VM's private run dir (see
//! `firecracker_guest_rpc_vsock_config` in `backends.rs`). This module turns
//! that transport anchor into a real execution path:
//!
//! - **Host side** (`firecracker_guest_vsock_exec`): connects to the retained
//!   microVM's vsock host socket, performs the Firecracker vsock mux
//!   handshake (`CONNECT <port>` / `OK <port>`), validates the guest agent's
//!   versioned JSON handshake, ships one `start_handler` request (command
//!   envelope + gateway capability envelope) into the guest, and streams the
//!   guest's normalized framework events back until the final bound response.
//! - **Guest side** (`firecracker_guest_agent_serve_vsock_entrypoint`): the
//!   same `agent-worker` binary staged inside the rootfs listens on the
//!   AF_VSOCK port, and for each session enforces the gateway capability
//!   envelope INSIDE the VM boundary before any workload is spawned. A
//!   workload whose capability action is not granted by the envelope is
//!   DENIED and never executes — enforced, not report-only. This is the #280
//!   capability-envelope enforcement at the microVM boundary.
//!
//! The session core (`serve_guest_session`) is transport-generic so the
//! protocol — envelope enforcement, workload execution, event streaming,
//! response binding — is fully unit-testable in the sandbox over socket
//! pairs; only the AF_VSOCK listener itself and the in-guest boot topology
//! require a KVM host (validated by the gated
//! `tests/firecracker_agent_execution.rs` harness).

use std::{
    env,
    io::{BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ferrogate_runtime::AgentWorkerFrameworkEventResult;
use serde::{Deserialize, Serialize};

use crate::backends::{
    FirecrackerGuestAgentHandshake, FirecrackerGuestAgentLaunchAttemptError,
    FirecrackerGuestRpcStartRequest, FirecrackerGuestRpcStartResponse,
};

/// Host-side opt-in: when set, `exec_or_attach` against a retained microVM
/// uses the real vsock guest execution path instead of the legacy
/// command-bridge probe. The value is the vsock port the guest agent listens
/// on.
pub(crate) const GUEST_VSOCK_PORT_ENV: &str = "AGENT_WORKER_FIRECRACKER_GUEST_VSOCK_PORT";
/// Guest-side listener port override (set by the guest init that starts the
/// staged agent-worker binary).
pub(crate) const GUEST_VSOCK_PORT_GUEST_ENV: &str = "FERROGATE_AGENT_WORKER_GUEST_VSOCK_PORT";
/// Guest-side workspace directory (same variable the command-bridge injects).
pub(crate) const GUEST_WORKSPACE_GUEST_ENV: &str = "FERROGATE_AGENT_WORKER_GUEST_WORKSPACE";
/// Optional guest-side bounded session count for deterministic smokes.
pub(crate) const GUEST_VSOCK_MAX_SESSIONS_ENV: &str =
    "FERROGATE_AGENT_WORKER_GUEST_VSOCK_MAX_SESSIONS";
/// Host-side per-exec timeout override.
pub(crate) const GUEST_VSOCK_EXEC_TIMEOUT_ENV: &str =
    "AGENT_WORKER_FIRECRACKER_GUEST_EXEC_TIMEOUT_MILLIS";

pub(crate) const DEFAULT_GUEST_VSOCK_PORT: u32 = 5252;
const DEFAULT_GUEST_VSOCK_EXEC_TIMEOUT_MILLIS: u64 = 30_000;

/// The vsock guest channel identifier carried in handshakes and requests.
pub(crate) const VSOCK_RPC_CHANNEL: &str = "vsock-json-lines";
/// The only enforcement mode the guest agent accepts for a capability
/// envelope. Anything else fails closed to a denial.
pub(crate) const MICROVM_BOUNDARY_ENFORCEMENT: &str = "enforced_at_microvm_boundary";
/// Enforcement boundary recorded in guest capability evidence.
pub(crate) const MICROVM_GUEST_ENFORCEMENT_BOUNDARY: &str = "microvm_guest";

/// Guard rails against a malicious or broken peer on either side.
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_STREAMED_EVENTS: usize = 256;
const OUTPUT_EXCERPT_CAP_BYTES: usize = 16 * 1024;

/// Whether the real vsock guest execution path is enabled on this host, and
/// on which port. Absent/invalid env means the legacy command-bridge path.
pub(crate) fn configured_guest_vsock_port() -> Option<u32> {
    let value = env::var(GUEST_VSOCK_PORT_ENV).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u32>().ok().filter(|port| *port > 0)
}

pub(crate) fn guest_vsock_exec_timeout() -> Duration {
    let millis = env::var(GUEST_VSOCK_EXEC_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GUEST_VSOCK_EXEC_TIMEOUT_MILLIS);
    Duration::from_millis(millis)
}

/// The bounded command the gateway envelope authorizes to run inside the
/// guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FirecrackerGuestWorkloadSpec {
    /// Capability action this workload exercises (e.g. `cli`). The guest
    /// agent enforces that the envelope grants it before spawning anything.
    pub(crate) capability_action: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) timeout_millis: u64,
    pub(crate) output_limit_bytes: u64,
}

impl FirecrackerGuestWorkloadSpec {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.capability_action.trim().is_empty() {
            return Err("workload.capability_action was empty".to_string());
        }
        if self.command.trim().is_empty() {
            return Err("workload.command was empty".to_string());
        }
        if self.timeout_millis == 0 {
            return Err("workload.timeout_millis must be greater than zero".to_string());
        }
        if self.output_limit_bytes == 0 {
            return Err("workload.output_limit_bytes must be greater than zero".to_string());
        }
        Ok(())
    }
}

/// The gateway capability envelope shipped into the guest with the workload.
/// The guest agent is the enforcement point: an action absent from
/// `granted_capabilities` is denied inside the VM boundary before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FirecrackerGuestCapabilityEnvelope {
    pub(crate) envelope_id: String,
    pub(crate) granted_capabilities: Vec<String>,
    /// Must be `enforced_at_microvm_boundary`; the guest fails closed on any
    /// other (unknown / report-only) enforcement mode.
    pub(crate) enforcement: String,
}

impl FirecrackerGuestCapabilityEnvelope {
    pub(crate) fn enforced(envelope_id: String, granted_capabilities: Vec<String>) -> Self {
        Self {
            envelope_id,
            granted_capabilities,
            enforcement: MICROVM_BOUNDARY_ENFORCEMENT.to_string(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.envelope_id.trim().is_empty() {
            return Err("capability_envelope.envelope_id was empty".to_string());
        }
        if self.enforcement.trim().is_empty() {
            return Err("capability_envelope.enforcement was empty".to_string());
        }
        Ok(())
    }
}

/// What actually happened to the workload inside the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FirecrackerGuestWorkloadResult {
    /// True only when the workload process was actually spawned in the guest.
    pub(crate) executed: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) output_excerpt: String,
    /// True when the capability envelope denial was enforced (workload never
    /// spawned) — never true together with `executed`.
    pub(crate) capability_denial_enforced: bool,
    pub(crate) denial_reason: Option<String>,
}

/// One framed line on the guest stream after the request: zero or more
/// events, then exactly one response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
enum GuestStreamFrame {
    Event {
        event: Box<AgentWorkerFrameworkEventResult>,
    },
    Response {
        response: Box<FirecrackerGuestRpcStartResponse>,
    },
}

// ---------------------------------------------------------------------------
// Guest side
// ---------------------------------------------------------------------------

pub(crate) struct GuestServeConfig {
    pub(crate) workspace: PathBuf,
    pub(crate) guest_agent_version: String,
}

impl GuestServeConfig {
    fn from_guest_env() -> Self {
        let workspace = env::var(GUEST_WORKSPACE_GUEST_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        Self {
            workspace,
            guest_agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Serve one guest execution session over an established stream.
///
/// Protocol (all JSON lines):
/// 1. guest -> host: versioned handshake (`rpc_channel=vsock-json-lines`).
/// 2. host -> guest: one `start_handler` request.
/// 3. guest -> host: `{"frame":"event",...}` normalized framework events.
/// 4. guest -> host: `{"frame":"response",...}` final identity-bound response.
///
/// The capability envelope is enforced HERE, inside the VM boundary: a
/// workload whose capability action is not granted never spawns.
pub(crate) fn serve_guest_session_with_config<S: Read + Write>(
    stream: &mut S,
    config: &GuestServeConfig,
) -> Result<(), String> {
    write_json_line(
        stream,
        &serde_json::json!({
            "protocol_version": FirecrackerGuestAgentHandshake::PROTOCOL_VERSION,
            "ready": true,
            "rpc_channel": VSOCK_RPC_CHANNEL,
            "guest_agent_version": config.guest_agent_version,
        }),
    )?;
    let request_line = read_bounded_line(stream).map_err(|error| error.reason().to_string())?;
    let request: FirecrackerGuestRpcStartRequest = serde_json::from_str(request_line.trim())
        .map_err(|error| format!("invalid guest start request JSON: {error}"))?;
    if let Err(reason) = request.validate_for_guest_agent() {
        // Fail closed with a bound response so the host records why.
        let response = FirecrackerGuestRpcStartResponse::for_guest_request(
            &request,
            "workload_failed",
            format!("guest agent rejected start request: {reason}"),
            Some(FirecrackerGuestWorkloadResult {
                executed: false,
                exit_code: None,
                output_excerpt: String::new(),
                capability_denial_enforced: false,
                denial_reason: Some(reason),
            }),
            false,
        );
        return write_json_line(
            stream,
            &GuestStreamFrame::Response {
                response: Box::new(response),
            },
        );
    }

    let Some(workload) = request.workload().cloned() else {
        // No command envelope: honest legacy behavior — the guest agent is
        // wired but was not asked to execute anything.
        let response = FirecrackerGuestRpcStartResponse::for_guest_request(
            &request,
            "not_implemented",
            "guest agent session served without a workload envelope; nothing was executed"
                .to_string(),
            None,
            false,
        );
        return write_json_line(
            stream,
            &GuestStreamFrame::Response {
                response: Box::new(response),
            },
        );
    };
    let envelope = request
        .capability_envelope()
        .cloned()
        .expect("validate_for_guest_agent guarantees an envelope when a workload is present");

    // Capability envelope enforcement at the VM boundary (#280): the denial is
    // decided and enforced HERE, before any process exists. Unknown
    // enforcement modes fail closed to a denial as well.
    let denial_reason = if envelope.enforcement != MICROVM_BOUNDARY_ENFORCEMENT {
        Some(format!(
            "capability envelope enforcement mode {} is not accepted by the guest agent; only {} \
             is enforced",
            envelope.enforcement, MICROVM_BOUNDARY_ENFORCEMENT
        ))
    } else if !envelope
        .granted_capabilities
        .iter()
        .any(|granted| granted == &workload.capability_action)
    {
        Some(format!(
            "capability action {} is not granted by gateway capability envelope {} \
             (granted=[{}])",
            workload.capability_action,
            envelope.envelope_id,
            envelope.granted_capabilities.join(",")
        ))
    } else {
        None
    };

    if let Some(reason) = denial_reason {
        let mut event = guest_event(&request, "capability.denied", &reason);
        event
            .metadata
            .insert("capability_action".to_string(), workload.capability_action);
        event
            .metadata
            .insert("envelope_id".to_string(), envelope.envelope_id.clone());
        event
            .metadata
            .insert("capability_denial_enforced".to_string(), "true".to_string());
        write_guest_event(stream, event)?;
        let response = FirecrackerGuestRpcStartResponse::for_guest_request(
            &request,
            "capability_denied",
            format!("guest agent enforced capability denial: {reason}"),
            Some(FirecrackerGuestWorkloadResult {
                executed: false,
                exit_code: None,
                output_excerpt: String::new(),
                capability_denial_enforced: true,
                denial_reason: Some(reason),
            }),
            false,
        );
        return write_json_line(
            stream,
            &GuestStreamFrame::Response {
                response: Box::new(response),
            },
        );
    }

    let mut allowed_event = guest_event(
        &request,
        "capability.allowed",
        "gateway capability envelope grants this workload inside the microVM boundary",
    );
    allowed_event.metadata.insert(
        "capability_action".to_string(),
        workload.capability_action.clone(),
    );
    allowed_event
        .metadata
        .insert("envelope_id".to_string(), envelope.envelope_id.clone());
    write_guest_event(stream, allowed_event)?;
    let started_event = guest_event(&request, "run.started", "guest workload started");
    write_guest_event(stream, started_event)?;

    let result = execute_guest_workload(&workload, &config.workspace);
    let (status, kind, message) = match (&result.executed, &result.exit_code) {
        (true, Some(0)) => (
            "completed",
            "run.completed",
            "guest workload completed inside the microVM".to_string(),
        ),
        (true, exit_code) => (
            "workload_failed",
            "run.failed",
            format!("guest workload failed inside the microVM; exit_code={exit_code:?}"),
        ),
        (false, _) => (
            "workload_failed",
            "run.failed",
            format!(
                "guest workload could not be spawned: {}",
                result.denial_reason.as_deref().unwrap_or("unknown")
            ),
        ),
    };
    let mut finished_event = guest_event(&request, kind, &message);
    finished_event.metadata.insert(
        "exit_code".to_string(),
        result
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_string()),
    );
    finished_event
        .metadata
        .insert("output_excerpt".to_string(), result.output_excerpt.clone());
    write_guest_event(stream, finished_event)?;

    let proves_handler_execution = result.executed;
    let response = FirecrackerGuestRpcStartResponse::for_guest_request(
        &request,
        status,
        message,
        Some(result),
        proves_handler_execution,
    );
    write_json_line(
        stream,
        &GuestStreamFrame::Response {
            response: Box::new(response),
        },
    )
}

pub(crate) fn execute_guest_workload(
    workload: &FirecrackerGuestWorkloadSpec,
    workspace: &Path,
) -> FirecrackerGuestWorkloadResult {
    let spawn = Command::new(&workload.command)
        .args(&workload.args)
        .current_dir(workspace)
        .env_clear()
        .env(GUEST_WORKSPACE_GUEST_ENV, workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(error) => {
            return FirecrackerGuestWorkloadResult {
                executed: false,
                exit_code: None,
                output_excerpt: String::new(),
                capability_denial_enforced: false,
                denial_reason: Some(format!(
                    "failed to spawn guest workload {}: {error}",
                    workload.command
                )),
            };
        }
    };
    let deadline = Instant::now() + Duration::from_millis(workload.timeout_millis);
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return FirecrackerGuestWorkloadResult {
                    executed: true,
                    exit_code: None,
                    output_excerpt: String::new(),
                    capability_denial_enforced: false,
                    denial_reason: Some(format!(
                        "guest workload timed out after timeout_millis={}",
                        workload.timeout_millis
                    )),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return FirecrackerGuestWorkloadResult {
                    executed: true,
                    exit_code: None,
                    output_excerpt: String::new(),
                    capability_denial_enforced: false,
                    denial_reason: Some(format!("guest workload wait failed: {error}")),
                };
            }
        }
    };
    let limit = usize::try_from(workload.output_limit_bytes)
        .unwrap_or(OUTPUT_EXCERPT_CAP_BYTES)
        .min(OUTPUT_EXCERPT_CAP_BYTES);
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.by_ref().take(limit as u64).read_to_end(&mut output);
    }
    if output.len() < limit {
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr
                .by_ref()
                .take((limit - output.len()) as u64)
                .read_to_end(&mut output);
        }
    }
    FirecrackerGuestWorkloadResult {
        executed: true,
        exit_code,
        // The guest workload's own stdout/stderr. It is arbitrary attacker-
        // reachable output — a workload that curls an upstream and prints the
        // exchange used to put every credential header it saw into the
        // `output_excerpt` of the `run.completed` frame the host records (#526).
        output_excerpt: crate::recorded_evidence::recorded_excerpt(
            crate::recorded_evidence::RecordedSurface::GuestWorkloadOutput,
            &output,
            limit as u64,
        )
        .trim()
        .to_string(),
        capability_denial_enforced: false,
        denial_reason: None,
    }
}

fn guest_event(
    request: &FirecrackerGuestRpcStartRequest,
    kind: &str,
    message: &str,
) -> AgentWorkerFrameworkEventResult {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("isolation_backend".to_string(), "firecracker".to_string());
    metadata.insert(
        "isolation_instance_id".to_string(),
        request.isolation_instance_id().to_string(),
    );
    metadata.insert(
        "handler_owner".to_string(),
        "agent-worker-guest".to_string(),
    );
    metadata.insert(
        "enforcement_boundary".to_string(),
        MICROVM_GUEST_ENFORCEMENT_BOUNDARY.to_string(),
    );
    AgentWorkerFrameworkEventResult {
        session_id: request.session_id().to_string(),
        run_id: request.run_id().to_string(),
        adapter_name: request.framework_adapter().to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: request.framework_adapter().to_string(),
        mode: "managed".to_string(),
        kind: kind.to_string(),
        message: Some(message.to_string()),
        metadata,
    }
}

/// Guest-side entrypoint: listen on the AF_VSOCK port inside the microVM and
/// serve execution sessions. Started by the guest init from the staged
/// `agent-worker` binary (`--ferrogate-guest-agent-serve-vsock`).
pub(crate) fn firecracker_guest_agent_serve_vsock_entrypoint() -> anyhow::Result<()> {
    let port = env::var(GUEST_VSOCK_PORT_GUEST_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GUEST_VSOCK_PORT);
    let max_sessions = env::var(GUEST_VSOCK_MAX_SESSIONS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0);
    let config = GuestServeConfig::from_guest_env();
    let listener = vsock::listen(port)
        .map_err(|error| anyhow::anyhow!("failed to listen on vsock port {port}: {error}"))?;
    eprintln!(
        "agent-worker guest agent listening on vsock port {port}; workspace={}",
        config.workspace.display()
    );
    let mut served = 0_u64;
    loop {
        let mut stream = match vsock::accept(&listener) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("agent-worker guest agent vsock accept failed: {error}");
                continue;
            }
        };
        if let Err(reason) = serve_guest_session_with_config(&mut stream, &config) {
            eprintln!("agent-worker guest agent session failed: {reason}");
        }
        served = served.saturating_add(1);
        if let Some(limit) = max_sessions {
            if served >= limit {
                return Ok(());
            }
        }
    }
}

/// Minimal AF_VSOCK support via rustix (no libc dependency). Only used inside
/// the guest; the host side of the Firecracker vsock device is a plain Unix
/// socket.
mod vsock {
    use std::{fs::File, os::fd::OwnedFd, time::Duration};

    use rustix::net::{
        addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque},
        AddressFamily, SocketType,
    };

    const VMADDR_CID_ANY: u32 = u32::MAX;

    /// `struct sockaddr_vm` (linux/vm_sockets.h).
    #[repr(C)]
    struct RawSockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    struct VsockAddr {
        cid: u32,
        port: u32,
    }

    // SAFETY: `with_sockaddr` passes a pointer to a stack-allocated
    // `sockaddr_vm`-layout struct valid for the duration of the call, with
    // its exact size.
    unsafe impl SocketAddrArg for VsockAddr {
        unsafe fn with_sockaddr<R>(
            &self,
            f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
        ) -> R {
            let raw = RawSockaddrVm {
                svm_family: AddressFamily::VSOCK.as_raw(),
                svm_reserved1: 0,
                svm_port: self.port,
                svm_cid: self.cid,
                svm_zero: [0; 4],
            };
            f(
                (&raw as *const RawSockaddrVm).cast(),
                core::mem::size_of::<RawSockaddrVm>() as SocketAddrLen,
            )
        }
    }

    pub(super) fn listen(port: u32) -> Result<OwnedFd, String> {
        let fd = rustix::net::socket(AddressFamily::VSOCK, SocketType::STREAM, None)
            .map_err(|error| format!("socket(AF_VSOCK): {error}"))?;
        rustix::net::bind(
            &fd,
            &VsockAddr {
                cid: VMADDR_CID_ANY,
                port,
            },
        )
        .map_err(|error| format!("bind(AF_VSOCK cid=any port={port}): {error}"))?;
        rustix::net::listen(&fd, 4).map_err(|error| format!("listen(AF_VSOCK): {error}"))?;
        Ok(fd)
    }

    pub(super) fn accept(listener: &OwnedFd) -> Result<File, String> {
        let conn =
            rustix::net::accept(listener).map_err(|error| format!("accept(AF_VSOCK): {error}"))?;
        // Bound guest-side reads so a dead host connection cannot wedge the
        // serve loop forever.
        let _ = rustix::net::sockopt::set_socket_timeout(
            &conn,
            rustix::net::sockopt::Timeout::Recv,
            Some(Duration::from_secs(60)),
        );
        Ok(File::from(conn))
    }
}

// ---------------------------------------------------------------------------
// Host side
// ---------------------------------------------------------------------------

/// The evidence one real guest execution produced.
#[derive(Debug, Clone)]
pub(crate) struct FirecrackerGuestVsockExecOutcome {
    pub(crate) handshake: FirecrackerGuestAgentHandshake,
    pub(crate) events: Vec<AgentWorkerFrameworkEventResult>,
    pub(crate) response: FirecrackerGuestRpcStartResponse,
    pub(crate) elapsed_millis: u128,
}

impl FirecrackerGuestVsockExecOutcome {
    pub(crate) fn event_kinds(&self) -> Vec<String> {
        self.events.iter().map(|event| event.kind.clone()).collect()
    }
}

/// Execute one workload inside the retained microVM through the Firecracker
/// vsock host socket. Fails closed on any transport, handshake, identity, or
/// status-policy violation; the retained VM is never torn down from here.
pub(crate) fn firecracker_guest_vsock_exec(
    guest_rpc_socket: &Path,
    port: u32,
    request: &FirecrackerGuestRpcStartRequest,
    timeout: Duration,
) -> Result<FirecrackerGuestVsockExecOutcome, FirecrackerGuestAgentLaunchAttemptError> {
    let started_at = Instant::now();
    let transport_error = |reason: String| {
        FirecrackerGuestAgentLaunchAttemptError::new("guest_vsock_unavailable", reason)
    };
    let mut stream = UnixStream::connect(guest_rpc_socket).map_err(|error| {
        transport_error(format!(
            "failed to connect Firecracker vsock host socket {}: {error}",
            guest_rpc_socket.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| {
            transport_error(format!(
                "failed to configure vsock host socket timeouts: {error}"
            ))
        })?;
    // Firecracker vsock mux handshake: `CONNECT <port>\n` -> `OK <hostport>\n`.
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .map_err(|error| {
            transport_error(format!("failed to send vsock CONNECT {port}: {error}"))
        })?;
    let mut reader = BufReader::new(stream);
    let ack = read_bounded_line(&mut reader)?;
    if !ack.trim().starts_with("OK ") {
        return Err(transport_error(format!(
            "Firecracker vsock mux rejected CONNECT {port}: {}",
            ack.trim()
        )));
    }
    let handshake_line = read_bounded_line(&mut reader).map_err(|error| {
        transport_error(format!(
            "failed to read guest agent vsock handshake: {}",
            error.reason()
        ))
    })?;
    let handshake =
        FirecrackerGuestAgentHandshake::parse(handshake_line.as_bytes()).map_err(|reason| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_agent_handshake_unavailable",
                format!("guest agent vsock handshake was invalid: {reason}"),
            )
        })?;
    if handshake.rpc_channel() != VSOCK_RPC_CHANNEL {
        return Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_agent_handshake_unavailable",
            format!(
                "guest agent vsock handshake declared rpc_channel {}; expected {VSOCK_RPC_CHANNEL}",
                handshake.rpc_channel()
            ),
        ));
    }
    {
        let stream = reader.get_mut();
        let request_json = serde_json::to_string(request).map_err(|error| {
            transport_error(format!("failed to serialize guest start request: {error}"))
        })?;
        stream
            .write_all(request_json.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .and_then(|()| stream.flush())
            .map_err(|error| {
                transport_error(format!("failed to write guest start request: {error}"))
            })?;
    }

    let mut events = Vec::new();
    let response = loop {
        if events.len() > MAX_STREAMED_EVENTS {
            return Err(transport_error(format!(
                "guest streamed more than {MAX_STREAMED_EVENTS} events before a response"
            )));
        }
        if started_at.elapsed() >= timeout {
            return Err(transport_error(format!(
                "guest execution did not complete before timeout_millis={}",
                timeout.as_millis()
            )));
        }
        let line = read_bounded_line(&mut reader).map_err(|error| {
            transport_error(format!(
                "failed to read guest stream frame: {}",
                error.reason()
            ))
        })?;
        let frame: GuestStreamFrame = serde_json::from_str(line.trim()).map_err(|error| {
            transport_error(format!("invalid guest stream frame JSON: {error}"))
        })?;
        match frame {
            GuestStreamFrame::Event { event } => events.push(*event),
            GuestStreamFrame::Response { response } => break *response,
        }
    };

    response.verify_binding(request).map_err(|reason| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!("guest vsock response did not bind to the request: {reason}"),
        )
    })?;
    validate_vsock_response_status(&response)?;
    Ok(FirecrackerGuestVsockExecOutcome {
        handshake,
        events,
        response: response.with_elapsed_millis(started_at.elapsed().as_millis()),
        elapsed_millis: started_at.elapsed().as_millis(),
    })
}

/// Status policy for real guest execution responses. Everything outside the
/// exact accepted evidence shapes fails closed.
fn validate_vsock_response_status(
    response: &FirecrackerGuestRpcStartResponse,
) -> Result<(), FirecrackerGuestAgentLaunchAttemptError> {
    let fail = |reason: String| {
        Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            reason,
        ))
    };
    match response.status() {
        "completed" => {
            let Some(result) = response.workload_result() else {
                return fail("completed response was missing workload_result".to_string());
            };
            if !result.executed || result.exit_code != Some(0) {
                return fail(format!(
                    "completed response claimed executed={} exit_code={:?}; only a real zero-exit \
                     execution may report completed",
                    result.executed, result.exit_code
                ));
            }
            if !response.proves_handler_execution() {
                return fail("completed response did not set proves_handler_execution".to_string());
            }
            Ok(())
        }
        "workload_failed" => {
            if response.workload_result().is_none() {
                return fail("workload_failed response was missing workload_result".to_string());
            }
            Ok(())
        }
        "capability_denied" => {
            let Some(result) = response.workload_result() else {
                return fail("capability_denied response was missing workload_result".to_string());
            };
            if result.executed || !result.capability_denial_enforced {
                return fail(format!(
                    "capability_denied response claimed executed={} \
                     capability_denial_enforced={}; a denial must be enforced with no execution",
                    result.executed, result.capability_denial_enforced
                ));
            }
            if response.proves_handler_execution() {
                return fail(
                    "capability_denied response cannot claim handler execution".to_string(),
                );
            }
            Ok(())
        }
        status => fail(format!(
            "guest vsock response returned unsupported status {status}"
        )),
    }
}

// ---------------------------------------------------------------------------
// Shared line framing
// ---------------------------------------------------------------------------

/// The ONE place a guest-side event frame leaves the microVM.
///
/// Every guest event the host records comes through here, so its metadata is
/// swept for bearer material once, centrally, instead of at each of the four
/// call sites that build one (#526). A new guest event added tomorrow inherits
/// the sweep by virtue of being written at all.
pub(crate) fn write_guest_event<S: Write>(
    stream: &mut S,
    mut event: AgentWorkerFrameworkEventResult,
) -> Result<(), String> {
    crate::recorded_evidence::redact_recorded_values(event.metadata.values_mut());
    write_json_line(
        stream,
        &GuestStreamFrame::Event {
            event: Box::new(event),
        },
    )
}

fn write_json_line<S: Write, T: Serialize>(stream: &mut S, value: &T) -> Result<(), String> {
    let json =
        serde_json::to_string(value).map_err(|error| format!("failed to serialize: {error}"))?;
    stream
        .write_all(json.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("failed to write JSON line: {error}"))
}

fn read_bounded_line<R: Read>(
    reader: &mut R,
) -> Result<String, FirecrackerGuestAgentLaunchAttemptError> {
    // Byte-at-a-time bounded read: correct for both raw streams and
    // BufReader-wrapped streams, and a peer cannot exhaust memory with an
    // unterminated line.
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if line.is_empty() {
                    return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                        "guest_vsock_unavailable",
                        "stream closed before a line was received".to_string(),
                    ));
                }
                break;
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > MAX_LINE_BYTES {
                    return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                        "guest_vsock_unavailable",
                        format!("line exceeded {MAX_LINE_BYTES} bytes"),
                    ));
                }
            }
            Err(error) => {
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_vsock_unavailable",
                    format!("failed to read line: {error}"),
                ));
            }
        }
    }
    String::from_utf8(line).map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_vsock_unavailable",
            format!("line was not UTF-8: {error}"),
        )
    })
}

#[cfg(test)]
#[path = "firecracker_guest_exec_test.rs"]
mod tests;
