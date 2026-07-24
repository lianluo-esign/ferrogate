// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Result};
use ferrogate_runtime::{
    AgentWorkerFrameworkArtifactResult, AgentWorkerFrameworkEventResult,
    AgentWorkerIsolationBackendReport, IsolationBackendCapabilities, IsolationBackendDescriptor,
    IsolationBackendKind, IsolationFilesystemPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub(crate) fn isolation_backends() -> Vec<AgentWorkerIsolationBackendReport> {
    registered_isolation_backends()
        .iter()
        .map(RegisteredIsolationBackend::to_report)
        .collect()
}

/// Descriptors for the isolation backends that can be selected for a managed
/// workload right now: every registered backend whose host lifecycle is
/// actually implemented and reports ready. Callers feed these to the runtime
/// `select_isolation_backend` contract, so an unimplemented or unconfigured
/// backend can never be chosen. The registry is fail-closed by construction:
/// unimplemented backends advertise no capabilities and are filtered out here
/// regardless.
pub(crate) fn selectable_isolation_backend_descriptors() -> Vec<IsolationBackendDescriptor> {
    registered_isolation_backends()
        .into_iter()
        .filter(RegisteredIsolationBackend::is_selectable)
        .map(|backend| backend.descriptor)
        .collect()
}

/// Whether this agent-worker build owns a real host lifecycle for a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsolationBackendImplementation {
    /// The worker owns the host lifecycle; readiness is probed from host
    /// configuration.
    HostImplemented,
    /// Registered for the replaceable isolation contract but not implemented in
    /// this build. Always fails closed.
    NotYetImplemented,
    /// Implemented, but the lifecycle is driven REMOTELY through the fronting
    /// agent-gateway Worker rather than owned by this host (issue #415: the
    /// Cloudflare Containers/Sandbox tier). It is advertised in the wire report
    /// so the gateway/control plane sees the replaceable contract, but the
    /// ON-HOST provisioning path never selects it — the worker cannot
    /// provision a Cloudflare container locally; it drives one remotely.
    GatewayDriven,
}

/// One backend in the worker's replaceable isolation registry. Every entry
/// speaks the runtime `IsolationBackendDescriptor` contract, so adding a
/// backend means adding a descriptor plus a host implementation — the gateway
/// side and the wire report never change shape.
struct RegisteredIsolationBackend {
    descriptor: IsolationBackendDescriptor,
    implementation: IsolationBackendImplementation,
    ready: bool,
    readiness_reason: Option<String>,
}

impl RegisteredIsolationBackend {
    /// A backend may be selected for a real ON-HOST workload only when the
    /// worker owns its host lifecycle and the host is configured and ready.
    /// Gateway-driven backends (issue #415) are deliberately excluded here:
    /// their lifecycle runs through the fronting Worker, not this host, so the
    /// on-host provisioning path must never pick them (fail-closed).
    fn is_selectable(&self) -> bool {
        matches!(
            self.implementation,
            IsolationBackendImplementation::HostImplemented
        ) && self.ready
    }

    fn to_report(&self) -> AgentWorkerIsolationBackendReport {
        AgentWorkerIsolationBackendReport {
            backend_name: self.descriptor.backend_name.clone(),
            backend_version: self.descriptor.backend_version.clone(),
            kind: isolation_backend_kind_wire(&self.descriptor.kind).to_string(),
            host_lifecycle_owner: self.descriptor.host_lifecycle_owner.clone(),
            gateway_controls_backend: self.descriptor.gateway_controls_backend,
            ready: self.ready,
            readiness_reason: self.readiness_reason.clone(),
        }
    }
}

pub(crate) fn isolation_backend_kind_wire(kind: &IsolationBackendKind) -> &'static str {
    match kind {
        IsolationBackendKind::FirecrackerMicroVm => "firecracker_micro_vm",
        IsolationBackendKind::KataContainers => "kata_containers",
        IsolationBackendKind::Gvisor => "gvisor",
        IsolationBackendKind::RootlessDocker => "rootless_docker",
        IsolationBackendKind::CloudflareContainer => "cloudflare_container",
        IsolationBackendKind::LocalProcess => "local_process",
    }
}

/// The full replaceable backend registry. Firecracker is the only backend with
/// a host lifecycle in this build; the rest are registered so the uniform
/// contract is visible to the gateway but fail closed until implemented.
fn registered_isolation_backends() -> Vec<RegisteredIsolationBackend> {
    vec![
        firecracker_registered_backend(),
        unimplemented_registered_backend("kata-containers", IsolationBackendKind::KataContainers),
        unimplemented_registered_backend("gvisor", IsolationBackendKind::Gvisor),
        docker_registered_backend(),
        local_process_registered_backend(),
        cloudflare_container_registered_backend(),
    ]
}

/// The Cloudflare Containers/Sandbox backend (issue #415) — the FIRST
/// gateway-driven tier. Its lifecycle runs through the fronting agent-gateway
/// Worker's `/container/*` routes (Cloudflare exposes no public container
/// lifecycle REST API), so it is registered `GatewayDriven`: advertised in the
/// wire report with real capabilities and readiness, but never picked by the
/// ON-HOST provisioning path. Readiness means "configured" (the fronting-Worker
/// URL and control token are present); no network call is made here, exactly
/// like the Docker/Firecracker preflights. Opt-in via the
/// `AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND=1` environment flag.
fn cloudflare_container_registered_backend() -> RegisteredIsolationBackend {
    use ferrogate_runtime::cloudflare_container_descriptor;
    if !crate::cloudflare_container_backend::cloudflare_container_backend_enabled() {
        return RegisteredIsolationBackend {
            descriptor: cloudflare_container_descriptor("disabled"),
            implementation: IsolationBackendImplementation::GatewayDriven,
            ready: false,
            readiness_reason: Some(
                "cloudflare container backend is not enabled; set \
                 AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND=1 to allow the Cloudflare \
                 Containers/Sandbox isolation tier"
                    .to_string(),
            ),
        };
    }
    match crate::cloudflare_container_backend::cloudflare_container_backend_readiness() {
        Ok((version, reason)) => RegisteredIsolationBackend {
            descriptor: cloudflare_container_descriptor(&version),
            implementation: IsolationBackendImplementation::GatewayDriven,
            ready: true,
            readiness_reason: Some(reason),
        },
        Err(reason) => RegisteredIsolationBackend {
            descriptor: cloudflare_container_descriptor("unknown"),
            implementation: IsolationBackendImplementation::GatewayDriven,
            ready: false,
            readiness_reason: Some(reason),
        },
    }
}

/// Environment variable an operator sets to pin managed provisioning to a
/// specific isolation backend by its wire kind (issue #442). This is the ONLY
/// way to reach a gateway-driven tier: the automatic on-host ranking
/// (`selectable_isolation_backend_descriptors` + `select_isolation_backend`)
/// deliberately never returns one, so a remote backend can only be provisioned
/// when the operator asks for it by name.
pub(crate) const PROVISION_ISOLATION_BACKEND_ENV: &str = "AGENT_WORKER_PROVISION_ISOLATION_BACKEND";

/// The wire kind an operator has pinned provisioning to, if any. Absent or blank
/// means "use the default on-host selection".
pub(crate) fn operator_pinned_isolation_backend() -> Option<String> {
    env::var(PROVISION_ISOLATION_BACKEND_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Resolve the ready Cloudflare container descriptor for an EXPLICIT operator
/// provision request, or an error explaining why the tier is unavailable (fail
/// closed). This is the only path that hands a gateway-driven descriptor to the
/// provision dispatch; the on-host selectable set never includes it. Readiness
/// means the backend is enabled and its fronting-Worker URL + control token are
/// configured — no network call is made here.
pub(crate) fn ready_cloudflare_container_descriptor() -> Result<IsolationBackendDescriptor, String>
{
    let backend = cloudflare_container_registered_backend();
    if backend.ready {
        Ok(backend.descriptor)
    } else {
        Err(backend.readiness_reason.unwrap_or_else(|| {
            "cloudflare container backend is not ready for provisioning".to_string()
        }))
    }
}

/// The local-process (Linux namespace) backend is a third real host
/// implementation for daemon-less, unprivileged hosts. Readiness is probed
/// with real `unshare` namespace invocations; if the host cannot provide the
/// full namespace stack it fails closed like any other backend. It is ranked
/// last by the runtime selection contract, so it never outranks a real
/// hypervisor or container backend.
fn local_process_registered_backend() -> RegisteredIsolationBackend {
    if !crate::local_process_backend::local_process_backend_enabled() {
        return RegisteredIsolationBackend {
            descriptor: crate::local_process_backend::local_process_backend_descriptor("disabled"),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: false,
            readiness_reason: Some(
                "local-process backend is not enabled; set \
                 AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND=1 to allow the namespaced \
                 local-process tier"
                    .to_string(),
            ),
        };
    }
    match crate::local_process_backend::local_process_backend_readiness() {
        Ok(readiness) => RegisteredIsolationBackend {
            descriptor: crate::local_process_backend::local_process_backend_descriptor(
                &readiness.version,
            ),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: true,
            readiness_reason: Some(format!(
                "unprivileged namespace stack available ({}); {}",
                readiness.namespaces.join(","),
                readiness.version
            )),
        },
        Err(reason) => RegisteredIsolationBackend {
            descriptor: crate::local_process_backend::local_process_backend_descriptor("unknown"),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: false,
            readiness_reason: Some(reason),
        },
    }
}

/// The Docker backend is a second real host implementation. Readiness is probed
/// from the docker daemon; when the daemon is unreachable it fails closed like
/// any other backend, but it is never a fake registry entry.
fn docker_registered_backend() -> RegisteredIsolationBackend {
    if !crate::docker_backend::docker_backend_enabled() {
        return RegisteredIsolationBackend {
            descriptor: crate::docker_backend::docker_backend_descriptor("disabled"),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: false,
            readiness_reason: Some(
                "docker backend is not enabled; set AGENT_WORKER_ENABLE_DOCKER_BACKEND=1 to allow \
                 the low-risk docker tier"
                    .to_string(),
            ),
        };
    }
    match crate::docker_backend::docker_backend_readiness() {
        Ok(version) => RegisteredIsolationBackend {
            descriptor: crate::docker_backend::docker_backend_descriptor(&version),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: true,
            readiness_reason: Some(format!("docker daemon reachable; server version {version}")),
        },
        Err(reason) => RegisteredIsolationBackend {
            descriptor: crate::docker_backend::docker_backend_descriptor("unknown"),
            implementation: IsolationBackendImplementation::HostImplemented,
            ready: false,
            readiness_reason: Some(reason),
        },
    }
}

fn unimplemented_registered_backend(
    backend_name: &str,
    kind: IsolationBackendKind,
) -> RegisteredIsolationBackend {
    RegisteredIsolationBackend {
        descriptor: IsolationBackendDescriptor {
            backend_name: backend_name.to_string(),
            backend_version: "unimplemented".to_string(),
            kind,
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            capabilities: IsolationBackendCapabilities::none(),
        },
        implementation: IsolationBackendImplementation::NotYetImplemented,
        ready: false,
        readiness_reason: Some(
            "backend is registered for the replaceable isolation contract but its host lifecycle \
             is not implemented in this agent-worker build"
                .to_string(),
        ),
    }
}

pub(crate) fn firecracker_prepare_plan_command() -> Result<()> {
    let plan = firecracker_prepare_plan()?;
    println!(
        "{}",
        json!({
            "process": "agent-worker",
            "backend_name": "firecracker",
            "backend_kind": "firecracker_micro_vm",
            "host_lifecycle_owner": "agent-worker",
            "gateway_controls_firecracker": false,
            "bundle": {
                "firecracker_bin": plan.firecracker_bin.display().to_string(),
                "jailer_bin": plan.jailer_bin.display().to_string(),
                "kernel_image": plan.kernel_image.display().to_string(),
                "rootfs_image": plan.rootfs_image.display().to_string(),
            },
            "planned_steps": plan.planned_steps,
            "resource_policy": plan.resource_policy,
            "network_policy": plan.network_policy,
            "filesystem_policy": plan.filesystem_policy,
            "proves_microvm_boot": false,
        })
    );
    Ok(())
}

pub(crate) fn firecracker_host_preflight_command() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&firecracker_host_preflight())?
    );
    Ok(())
}

pub(crate) fn firecracker_guest_agent_preflight_command() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&firecracker_guest_agent_preflight())?
    );
    Ok(())
}

pub(crate) fn firecracker_guest_launch_plan_command(adapter: Option<&str>) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&firecracker_guest_launch_plan(adapter))?
    );
    Ok(())
}

pub(crate) fn firecracker_guest_agent_probe_entrypoint() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "protocol_version": FirecrackerGuestAgentHandshake::PROTOCOL_VERSION,
            "ready": true,
            "rpc_channel": "stdio-json-lines",
            "guest_agent_version": env!("CARGO_PKG_VERSION"),
        }))?
    );
    Ok(())
}

pub(crate) fn firecracker_guest_agent_start_entrypoint() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let request: FirecrackerGuestRpcStartRequest = serde_json::from_slice(&input)?;
    request
        .validate_for_guest_agent()
        .map_err(|reason| anyhow::anyhow!("invalid guest start request: {reason}"))?;
    println!(
        "{}",
        serde_json::to_string(&FirecrackerGuestRpcStartResponse::not_implemented_for_request(
            &request,
            "agent-worker guest agent entrypoint is wired; framework handler execution is not implemented yet",
        ))?
    );
    Ok(())
}

pub(crate) fn firecracker_microvm_provision(
    timeout_millis: u64,
    vcpu_count: u8,
    mem_size_mib: u32,
) -> Result<FirecrackerMicroVm, FirecrackerBootSmokeError> {
    let preflight = firecracker_host_preflight();
    if !preflight.ready() {
        return Err(FirecrackerBootSmokeError::new(
            "preflight_failed",
            preflight.failure_summary(),
        ));
    }
    let bundle = firecracker_prepare_plan()
        .map_err(|error| FirecrackerBootSmokeError::new("bundle_unavailable", error.to_string()))?;
    let options = FirecrackerBootSmokeOptions {
        timeout: Duration::from_millis(timeout_millis),
        vcpu_count,
        mem_size_mib,
    };
    let artifacts = FirecrackerMicroVmArtifacts::new().map_err(|error| {
        FirecrackerBootSmokeError::new("run_dir_create_failed", error.to_string())
    })?;
    let started = start_firecracker_microvm(&bundle, artifacts, &options)?;
    Ok(started)
}

/// Deployment-level marker that every managed workload on this worker REQUIRES
/// Firecracker microVM isolation (#280 acceptance 2). When set, provisioning
/// must fail closed with a distinct `microvm_required_backend_unavailable`
/// error whenever the Firecracker/KVM preflight is unavailable — it must never
/// degrade silently to local_process or docker.
pub(crate) const REQUIRE_MICROVM_ENV: &str = "AGENT_WORKER_REQUIRE_MICROVM_ISOLATION";

/// Stable marker prefix for the fail-closed microVM-required degradation
/// error. Tests and operators match on this exact value.
pub(crate) const MICROVM_REQUIRED_UNAVAILABLE: &str = "microvm_required_backend_unavailable";

pub(crate) fn microvm_isolation_required() -> bool {
    env::var(REQUIRE_MICROVM_ENV)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// `agent-worker firecracker-agent-exec-smoke` (#280): the acceptance-evidence
/// generator for real agent execution inside a Firecracker microVM.
///
/// On a KVM host with the guest agent staged in the rootfs it: boots a real
/// microVM through the governed provision path, then over the vsock guest
/// channel runs (a) an ALLOWED workload (capability granted by the envelope;
/// must execute in-guest) and (b) a DENIED workload (capability withheld; the
/// guest agent must enforce the denial and never spawn it). It prints one JSON
/// report with both outcomes plus boot evidence, then tears the microVM down.
///
/// Without KVM (or without the bundle) it fails closed exactly like every
/// other microVM-required workload: an explicit
/// `microvm_required_backend_unavailable` report — never a silent
/// local_process fallback.
pub(crate) fn firecracker_agent_exec_smoke_command(
    timeout_millis: u64,
    vcpu_count: u8,
    mem_size_mib: u32,
    vsock_port: Option<u32>,
) -> Result<()> {
    use crate::firecracker_guest_exec::{
        firecracker_guest_vsock_exec, FirecrackerGuestCapabilityEnvelope,
        FirecrackerGuestWorkloadSpec, DEFAULT_GUEST_VSOCK_PORT,
    };

    let port = vsock_port
        .or_else(crate::firecracker_guest_exec::configured_guest_vsock_port)
        .unwrap_or(DEFAULT_GUEST_VSOCK_PORT);
    let fail_closed_report = |stage: &str, reason: String| {
        println!(
            "{}",
            json!({
                "process": "agent-worker",
                "smoke": "firecracker_agent_exec",
                "backend_name": "firecracker",
                "backend_kind": "firecracker_micro_vm",
                "host_lifecycle_owner": "agent-worker",
                "ready": false,
                "fail_closed": true,
                "degradation": MICROVM_REQUIRED_UNAVAILABLE,
                "local_process_fallback": false,
                "failure_stage": stage,
                "failure_reason": reason,
                "proves_microvm_boot": false,
                "proves_handler_execution": false,
                "capability_denial_enforced": false,
            })
        );
        Ok(())
    };

    let mut microvm = match firecracker_microvm_provision(timeout_millis, vcpu_count, mem_size_mib)
    {
        Ok(microvm) => microvm,
        Err(error) => return fail_closed_report(error.stage, error.reason),
    };
    let instance_id = microvm.instance_id.clone();
    let boot_markers = microvm.evidence.marker_summary();
    let guest_rpc_socket = microvm.guest_rpc_socket_path();
    let smoke_envelope = firecracker_agent_exec_smoke_envelope();
    let exec_timeout = crate::firecracker_guest_exec::guest_vsock_exec_timeout();

    let workload = |marker: &str| FirecrackerGuestWorkloadSpec {
        capability_action: "cli".to_string(),
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), format!("echo {marker}")],
        timeout_millis: 10_000,
        output_limit_bytes: 4_096,
    };

    // (a) ALLOWED: the envelope grants `cli`; the workload must really run
    // inside the guest.
    let allowed_request = firecracker_guest_vsock_start_request(
        &smoke_envelope,
        &instance_id,
        workload("ferrogate-firecracker-guest-exec-allowed"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            format!("cap:allowed:{instance_id}"),
            vec!["cli".to_string()],
        ),
    );
    // Retry while the guest boots and the guest agent starts listening.
    let allowed_deadline = Instant::now() + Duration::from_millis(timeout_millis.max(1));
    let allowed = loop {
        match firecracker_guest_vsock_exec(&guest_rpc_socket, port, &allowed_request, exec_timeout)
        {
            Ok(outcome) => break Ok(outcome),
            Err(error) if Instant::now() >= allowed_deadline => break Err(error),
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    };
    let allowed = match allowed {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = microvm.stop();
            return fail_closed_report(error.outcome(), error.reason().to_string());
        }
    };

    // (b) DENIED: the envelope grants NOTHING; the guest agent must enforce
    // the denial inside the VM boundary and never spawn the workload.
    let denied_request = firecracker_guest_vsock_start_request(
        &smoke_envelope,
        &instance_id,
        workload("ferrogate-firecracker-guest-exec-denied"),
        FirecrackerGuestCapabilityEnvelope::enforced(
            format!("cap:denied:{instance_id}"),
            Vec::new(),
        ),
    );
    let denied =
        firecracker_guest_vsock_exec(&guest_rpc_socket, port, &denied_request, exec_timeout);
    let denied = match denied {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = microvm.stop();
            return fail_closed_report(error.outcome(), error.reason().to_string());
        }
    };

    let stop = microvm.stop();
    let allowed_result = allowed.response.workload_result().cloned();
    let denied_result = denied.response.workload_result().cloned();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "process": "agent-worker",
            "smoke": "firecracker_agent_exec",
            "backend_name": "firecracker",
            "backend_kind": "firecracker_micro_vm",
            "host_lifecycle_owner": "agent-worker",
            "ready": true,
            "fail_closed": false,
            "isolation_instance_id": instance_id,
            "serial_boot_markers": boot_markers,
            "proves_microvm_boot": true,
            "vsock_port": port,
            "guest_agent_version": allowed.handshake.guest_agent_version(),
            "allowed": {
                "status": allowed.response.status(),
                "proves_handler_execution": allowed.response.proves_handler_execution(),
                "workload_result": allowed_result,
                "event_kinds": allowed.event_kinds(),
                "elapsed_millis": allowed.elapsed_millis,
            },
            "denied": {
                "status": denied.response.status(),
                "proves_handler_execution": denied.response.proves_handler_execution(),
                "workload_result": denied_result,
                "event_kinds": denied.event_kinds(),
                "elapsed_millis": denied.elapsed_millis,
            },
            "teardown": stop.summary(),
        }))?
    );
    Ok(())
}

/// Deterministic identity for the agent-exec smoke's guest requests. Only the
/// identity fields are read on this path; the security block is inert.
fn firecracker_agent_exec_smoke_envelope() -> ferrogate_runtime::AgentWorkerManagementEnvelope {
    ferrogate_runtime::AgentWorkerManagementEnvelope {
        protocol_version: ferrogate_runtime::AGENT_WORKER_PROTOCOL_VERSION,
        action: ferrogate_runtime::AgentWorkerManagementAction::ExecOrAttach,
        request_id: "agent-worker-firecracker-agent-exec-smoke-request".to_string(),
        idempotency_key: "agent-worker-firecracker-agent-exec-smoke-idempotency".to_string(),
        issued_at_unix_millis: 0,
        deadline_unix_millis: 0,
        tenant_id: "agent-worker-smoke-tenant".to_string(),
        workspace_id: "agent-worker-smoke-workspace".to_string(),
        worker_id: "agent-worker-smoke-worker".to_string(),
        session_id: Some("agent-worker-firecracker-agent-exec-smoke-session".to_string()),
        run_id: Some("agent-worker-firecracker-agent-exec-smoke-run".to_string()),
        framework_adapter: Some("native-harness".to_string()),
        security: ferrogate_runtime::AgentWorkerManagementSecurity {
            key_id: "agent-worker-smoke-key".to_string(),
            nonce: "agent-worker-firecracker-agent-exec-smoke-nonce".to_string(),
            signature: String::new(),
            algorithm: ferrogate_runtime::AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: ferrogate_runtime::AgentWorkerTransportSecurity::LocalUnixSocket,
            encrypted: false,
        },
    }
}

pub(crate) fn firecracker_boot_smoke_command(
    timeout_millis: u64,
    vcpu_count: u8,
    mem_size_mib: u32,
) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&firecracker_boot_smoke(FirecrackerBootSmokeOptions {
            timeout: Duration::from_millis(timeout_millis),
            vcpu_count,
            mem_size_mib,
        }))?
    );
    Ok(())
}

pub(crate) fn firecracker_host_preflight() -> FirecrackerHostPreflight {
    let firecracker_bin = configured_file_check(
        Some("AGENT_WORKER_FIRECRACKER_BIN"),
        "Firecracker binary path",
        true,
    );
    let jailer_bin = configured_file_check(
        Some("AGENT_WORKER_FIRECRACKER_JAILER"),
        "Firecracker jailer binary path",
        true,
    );
    let kernel_image = configured_file_check(
        Some("AGENT_WORKER_FIRECRACKER_KERNEL"),
        "Firecracker kernel image",
        false,
    );
    let rootfs_image = configured_file_check(
        Some("AGENT_WORKER_FIRECRACKER_ROOTFS"),
        "Firecracker rootfs image",
        false,
    );
    let kvm_device = kvm_device_check();
    let mut failure_reasons = Vec::new();
    for check in [
        &firecracker_bin,
        &jailer_bin,
        &kernel_image,
        &rootfs_image,
        &kvm_device,
    ] {
        if let Some(reason) = &check.reason {
            failure_reasons.push(reason.clone());
        }
    }
    FirecrackerHostPreflight {
        process: "agent-worker".to_string(),
        backend_name: "firecracker".to_string(),
        backend_kind: "firecracker_micro_vm".to_string(),
        host_lifecycle_owner: "agent-worker".to_string(),
        gateway_controls_firecracker: false,
        bundle: FirecrackerBundlePreflight {
            firecracker_bin,
            jailer_bin,
            kernel_image,
            rootfs_image,
        },
        host: FirecrackerHostCapabilityPreflight { kvm_device },
        ready: failure_reasons.is_empty(),
        failure_reasons,
        proves_microvm_boot: false,
    }
}

pub(crate) fn firecracker_guest_agent_preflight() -> FirecrackerGuestAgentPreflight {
    let command_channel = configured_file_check(
        Some("AGENT_WORKER_FIRECRACKER_GUEST_AGENT"),
        "Firecracker guest agent command path",
        true,
    );
    let workspace = configured_directory_check(
        Some("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE"),
        "Firecracker guest workspace",
    );
    let gateway_endpoint = configured_non_empty_env_check(
        "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
        "Firecracker guest gateway authorizer endpoint",
    );
    let mut failure_reasons = Vec::new();
    for reason in [
        command_channel.reason.as_ref(),
        workspace.reason.as_ref(),
        gateway_endpoint.reason.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        failure_reasons.push(reason.clone());
    }
    FirecrackerGuestAgentPreflight {
        process: "agent-worker".to_string(),
        backend_name: "firecracker".to_string(),
        backend_kind: "firecracker_micro_vm".to_string(),
        host_lifecycle_owner: "agent-worker".to_string(),
        gateway_controls_firecracker: false,
        channel_kind: "guest_agent_command".to_string(),
        command_channel,
        workspace,
        gateway_endpoint,
        ready: failure_reasons.is_empty(),
        failure_reasons,
        proves_microvm_boot: false,
        proves_handler_execution: false,
    }
}

pub(crate) fn firecracker_guest_launch_plan(adapter: Option<&str>) -> FirecrackerGuestLaunchPlan {
    let guest_agent = firecracker_guest_agent_preflight();
    let adapter = normalize_guest_launch_adapter(adapter);
    FirecrackerGuestLaunchPlan {
        process: "agent-worker".to_string(),
        backend_name: "firecracker".to_string(),
        backend_kind: "firecracker_micro_vm".to_string(),
        host_lifecycle_owner: "agent-worker".to_string(),
        gateway_controls_firecracker: false,
        adapter: adapter.to_string(),
        ready: guest_agent.ready(),
        guest_agent,
        planned_steps: vec![
            "verify_retained_microvm",
            "stage_guest_workspace",
            "build_gateway_capability_envelope",
            "invoke_guest_agent_command",
            "open_guest_handler_rpc_channel",
            "start_framework_handler_inside_microvm",
            "stream_normalized_framework_events",
            "collect_guest_artifacts",
            "return_lifecycle_evidence",
        ],
        required_gateway_capabilities: guest_launch_capabilities(adapter),
        guest_network_policy: "gateway_control_channel_only_no_direct_public_egress".to_string(),
        filesystem_policy: "prepared_workspace_only_with_read_only_runtime_bundle".to_string(),
        artifact_policy: "guest_artifacts_must_return_as_artifact_created_events".to_string(),
        checkpoint_policy:
            "guest_checkpoint_requests_must_return_as_snapshot_or_checkpoint_evidence".to_string(),
        proves_microvm_boot: false,
        proves_handler_execution: false,
        implementation_status: "guest_handler_rpc_not_implemented".to_string(),
    }
}

pub(crate) fn firecracker_guest_agent_launch_attempt(
) -> Result<FirecrackerGuestAgentLaunchAttempt, FirecrackerGuestAgentLaunchAttemptError> {
    let guest_agent = firecracker_guest_agent_preflight();
    if !guest_agent.ready() {
        return Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_agent_channel_unavailable",
            guest_agent.failure_summary(),
        ));
    }
    let command = guest_agent.command_channel.path.clone().ok_or_else(|| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_agent_channel_unavailable",
            "Firecracker guest agent command path was not configured".to_string(),
        )
    })?;
    let workspace = guest_agent.workspace.path.clone().ok_or_else(|| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_agent_channel_unavailable",
            "Firecracker guest workspace was not configured".to_string(),
        )
    })?;
    let gateway_endpoint =
        env::var("AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT").map_err(|_| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_agent_channel_unavailable",
                "Firecracker guest gateway authorizer endpoint was not configured".to_string(),
            )
        })?;
    if gateway_endpoint.trim().is_empty() {
        return Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_agent_channel_unavailable",
            "Firecracker guest gateway authorizer endpoint was not configured".to_string(),
        ));
    }
    let timeout = parse_guest_agent_launch_timeout();
    let mut child = Command::new(&command)
        .arg("--ferrogate-guest-agent-probe")
        .current_dir(&workspace)
        .env_clear()
        .env(
            "FERROGATE_AGENT_WORKER_GUEST_GATEWAY_ENDPOINT",
            &gateway_endpoint,
        )
        .env("FERROGATE_AGENT_WORKER_GUEST_WORKSPACE", &workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_agent_launch_failed",
                format!("failed to start Firecracker guest agent command {command}: {error}"),
            )
        })?;
    let started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let elapsed_millis = started_at.elapsed().as_millis();
                if status.success() {
                    let output = child.wait_with_output().map_err(|error| {
                        FirecrackerGuestAgentLaunchAttemptError::new(
                            "guest_agent_launch_failed",
                            format!(
                                "failed to collect Firecracker guest agent command output from {command}: {error}"
                            ),
                        )
                    })?;
                    let handshake = FirecrackerGuestAgentHandshake::parse(&output.stdout)
                        .map_err(|reason| {
                            FirecrackerGuestAgentLaunchAttemptError::new(
                                "guest_agent_handshake_unavailable",
                                format!(
                                    "Firecracker guest agent command {command} exited successfully but did not return a valid guest RPC handshake: {reason}"
                                ),
                            )
                        })?;
                    return Ok(FirecrackerGuestAgentLaunchAttempt {
                        command,
                        workspace,
                        gateway_endpoint,
                        elapsed_millis,
                        exit_status: status.to_string(),
                        handshake,
                        proves_microvm_boot: false,
                        proves_handler_execution: false,
                    });
                }
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_agent_launch_failed",
                    format!(
                        "Firecracker guest agent command {command} exited before handler RPC channel was available: status={status}; elapsed_millis={elapsed_millis}"
                    ),
                ));
            }
            Ok(None) if started_at.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_agent_launch_failed",
                    format!(
                        "Firecracker guest agent command {command} did not return a handler RPC channel before timeout_millis={}",
                        timeout.as_millis()
                    ),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_agent_launch_failed",
                    format!("Firecracker guest agent command status check failed: {error}"),
                ));
            }
        }
    }
}

fn parse_guest_agent_launch_timeout() -> Duration {
    let millis = env::var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT_TIMEOUT_MILLIS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1_000);
    Duration::from_millis(millis)
}

pub(crate) fn firecracker_guest_rpc_start_request(
    envelope: &ferrogate_runtime::AgentWorkerManagementEnvelope,
    handshake: &FirecrackerGuestAgentHandshake,
    isolation_instance_id: &str,
) -> FirecrackerGuestRpcStartRequest {
    let adapter = normalize_guest_launch_adapter(envelope.framework_adapter.as_deref());
    FirecrackerGuestRpcStartRequest {
        protocol_version: FirecrackerGuestAgentHandshake::PROTOCOL_VERSION.to_string(),
        action: "start_handler".to_string(),
        tenant_id: envelope.tenant_id.clone(),
        workspace_id: envelope.workspace_id.clone(),
        worker_id: envelope.worker_id.clone(),
        session_id: envelope.session_id.clone().unwrap_or_default(),
        run_id: envelope.run_id.clone().unwrap_or_default(),
        framework_adapter: adapter.to_string(),
        adapter_launch_profile: adapter_launch_profile(adapter),
        isolation_backend: "firecracker".to_string(),
        isolation_instance_id: isolation_instance_id.to_string(),
        rpc_channel: handshake.rpc_channel().to_string(),
        required_gateway_capabilities: guest_launch_capabilities(adapter)
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
        workload: None,
        capability_envelope: None,
    }
}

/// Build the real vsock guest execution request (#280): the same
/// identity/policy-bound `start_handler` contract as the bridge probe, plus
/// the bounded command envelope and the gateway capability envelope the guest
/// agent enforces at the microVM boundary.
pub(crate) fn firecracker_guest_vsock_start_request(
    envelope: &ferrogate_runtime::AgentWorkerManagementEnvelope,
    isolation_instance_id: &str,
    workload: crate::firecracker_guest_exec::FirecrackerGuestWorkloadSpec,
    capability_envelope: crate::firecracker_guest_exec::FirecrackerGuestCapabilityEnvelope,
) -> FirecrackerGuestRpcStartRequest {
    let adapter = normalize_guest_launch_adapter(envelope.framework_adapter.as_deref());
    FirecrackerGuestRpcStartRequest {
        protocol_version: FirecrackerGuestAgentHandshake::PROTOCOL_VERSION.to_string(),
        action: "start_handler".to_string(),
        tenant_id: envelope.tenant_id.clone(),
        workspace_id: envelope.workspace_id.clone(),
        worker_id: envelope.worker_id.clone(),
        session_id: envelope.session_id.clone().unwrap_or_default(),
        run_id: envelope.run_id.clone().unwrap_or_default(),
        framework_adapter: adapter.to_string(),
        adapter_launch_profile: adapter_launch_profile(adapter),
        isolation_backend: "firecracker".to_string(),
        isolation_instance_id: isolation_instance_id.to_string(),
        rpc_channel: crate::firecracker_guest_exec::VSOCK_RPC_CHANNEL.to_string(),
        required_gateway_capabilities: guest_launch_capabilities(adapter)
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
        workload: Some(workload),
        capability_envelope: Some(capability_envelope),
    }
}

pub(crate) fn firecracker_guest_rpc_start_attempt(
    launch_attempt: &FirecrackerGuestAgentLaunchAttempt,
    request: &FirecrackerGuestRpcStartRequest,
) -> Result<FirecrackerGuestRpcStartResponse, FirecrackerGuestAgentLaunchAttemptError> {
    match launch_attempt.handshake.rpc_channel() {
        "stdio-json-lines" => {
            firecracker_guest_rpc_start_attempt_over_stdio_command(launch_attempt, request)
        }
        "unix-json-lines" => {
            firecracker_guest_rpc_start_attempt_over_unix_socket(launch_attempt, request)
        }
        channel => Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!("unsupported Firecracker guest RPC channel {channel}"),
        )),
    }
}

fn firecracker_guest_rpc_start_attempt_over_stdio_command(
    launch_attempt: &FirecrackerGuestAgentLaunchAttempt,
    request: &FirecrackerGuestRpcStartRequest,
) -> Result<FirecrackerGuestRpcStartResponse, FirecrackerGuestAgentLaunchAttemptError> {
    let timeout = parse_guest_agent_launch_timeout();
    let mut child = Command::new(&launch_attempt.command)
        .arg("--ferrogate-guest-agent-start")
        .current_dir(&launch_attempt.workspace)
        .env_clear()
        .env(
            "FERROGATE_AGENT_WORKER_GUEST_GATEWAY_ENDPOINT",
            &launch_attempt.gateway_endpoint,
        )
        .env(
            "FERROGATE_AGENT_WORKER_GUEST_WORKSPACE",
            &launch_attempt.workspace,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                format!(
                    "failed to start Firecracker guest-agent start RPC command {}: {error}",
                    launch_attempt.command
                ),
            )
        })?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                "Firecracker guest-agent start RPC stdin was unavailable".to_string(),
            )
        })?;
        serde_json::to_writer(&mut stdin, request).map_err(|error| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                format!("failed to serialize Firecracker guest start request: {error}"),
            )
        })?;
        stdin.write_all(b"\n").map_err(|error| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                format!("failed to write Firecracker guest start request: {error}"),
            )
        })?;
    }
    let started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let elapsed_millis = started_at.elapsed().as_millis();
                let output = child.wait_with_output().map_err(|error| {
                    FirecrackerGuestAgentLaunchAttemptError::new(
                        "guest_handler_rpc_unavailable",
                        format!("failed to collect Firecracker guest start RPC output: {error}"),
                    )
                })?;
                if !status.success() {
                    return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                        "guest_handler_rpc_unavailable",
                        format!(
                            "Firecracker guest start RPC command exited with status={status}; elapsed_millis={elapsed_millis}"
                        ),
                    ));
                }
                return parse_firecracker_guest_rpc_start_response(
                    &output.stdout,
                    elapsed_millis,
                    request,
                );
            }
            Ok(None) if started_at.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_handler_rpc_unavailable",
                    format!(
                        "Firecracker guest start RPC timed out after timeout_millis={}",
                        timeout.as_millis()
                    ),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                    "guest_handler_rpc_unavailable",
                    format!("Firecracker guest start RPC status check failed: {error}"),
                ));
            }
        }
    }
}

fn firecracker_guest_rpc_start_attempt_over_unix_socket(
    launch_attempt: &FirecrackerGuestAgentLaunchAttempt,
    request: &FirecrackerGuestRpcStartRequest,
) -> Result<FirecrackerGuestRpcStartResponse, FirecrackerGuestAgentLaunchAttemptError> {
    let socket_path = launch_attempt.handshake.rpc_socket_path().ok_or_else(|| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            "Firecracker guest unix-json-lines RPC channel did not provide rpc_socket_path"
                .to_string(),
        )
    })?;
    let timeout = parse_guest_agent_launch_timeout();
    let started_at = Instant::now();
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "failed to connect Firecracker guest start RPC unix socket {socket_path}: {error}"
            ),
        )
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "failed to configure Firecracker guest start RPC unix socket read timeout for {socket_path}: {error}"
            ),
        )
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "failed to configure Firecracker guest start RPC unix socket write timeout for {socket_path}: {error}"
            ),
        )
    })?;
    serde_json::to_writer(&mut stream, request).map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!("failed to serialize Firecracker guest start request: {error}"),
        )
    })?;
    stream.write_all(b"\n").map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "failed to write Firecracker guest start RPC request to unix socket {socket_path}: {error}"
            ),
        )
    })?;
    stream.flush().map_err(|error| {
        FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "failed to flush Firecracker guest start RPC request to unix socket {socket_path}: {error}"
            ),
        )
    })?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|error| {
            FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                format!(
                    "failed to read Firecracker guest start RPC response from unix socket {socket_path}: {error}"
                ),
            )
        })?;
    if response.trim().is_empty() {
        return Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "Firecracker guest start RPC unix socket {socket_path} returned an empty response"
            ),
        ));
    }
    parse_firecracker_guest_rpc_start_response(
        response.as_bytes(),
        started_at.elapsed().as_millis(),
        request,
    )
}

fn parse_firecracker_guest_rpc_start_response(
    stdout: &[u8],
    elapsed_millis: u128,
    request: &FirecrackerGuestRpcStartRequest,
) -> Result<FirecrackerGuestRpcStartResponse, FirecrackerGuestAgentLaunchAttemptError> {
    let parsed_response = FirecrackerGuestRpcStartResponse::parse(stdout, elapsed_millis, request);
    let response = match parsed_response {
        Ok(response) => response,
        Err(reason) => {
            let reason = format!("Firecracker guest start RPC returned invalid response: {reason}");
            return Err(FirecrackerGuestAgentLaunchAttemptError::new(
                "guest_handler_rpc_unavailable",
                reason,
            ));
        }
    };
    if response.status != "not_implemented" {
        return Err(FirecrackerGuestAgentLaunchAttemptError::new(
            "guest_handler_rpc_unavailable",
            format!(
                "Firecracker guest start RPC returned unsupported status {}; real handler execution is not wired yet",
                response.status
            ),
        ));
    }
    Ok(response)
}

fn firecracker_boot_smoke(options: FirecrackerBootSmokeOptions) -> FirecrackerBootSmokeReport {
    let preflight = firecracker_host_preflight();
    if !preflight.ready() {
        return FirecrackerBootSmokeReport::failed(
            "preflight_failed",
            preflight.failure_summary(),
            None,
            None,
            preflight,
        );
    }
    let Ok(bundle) = firecracker_prepare_plan() else {
        return FirecrackerBootSmokeReport::failed(
            "bundle_unavailable",
            "Firecracker bundle was not available after preflight".to_string(),
            None,
            None,
            preflight,
        );
    };
    let artifacts = match FirecrackerMicroVmArtifacts::new() {
        Ok(artifacts) => artifacts,
        Err(error) => {
            return FirecrackerBootSmokeReport::failed(
                "run_dir_create_failed",
                error.to_string(),
                None,
                None,
                preflight,
            );
        }
    };
    let result = start_firecracker_microvm(&bundle, artifacts, &options);
    let mut report = match result {
        Ok(mut microvm) => {
            let evidence = microvm.evidence.clone();
            let artifacts = microvm.artifacts.to_report_paths();
            let _ = microvm.stop();
            FirecrackerBootSmokeReport {
                process: "agent-worker".to_string(),
                backend_name: "firecracker".to_string(),
                backend_kind: "firecracker_micro_vm".to_string(),
                host_lifecycle_owner: "agent-worker".to_string(),
                gateway_controls_firecracker: false,
                ready: true,
                boot_observed: true,
                proves_microvm_boot: true,
                vcpu_count: options.vcpu_count,
                mem_size_mib: options.mem_size_mib,
                evidence: Some(evidence),
                failure_stage: None,
                failure_reason: None,
                artifacts,
                preflight,
            }
        }
        Err(error) => FirecrackerBootSmokeReport::failed(
            error.stage,
            error.reason,
            error.artifacts.map(|artifacts| *artifacts),
            error.evidence.map(|evidence| *evidence),
            preflight,
        ),
    };
    if !report.boot_observed {
        report.proves_microvm_boot = false;
    }
    report
}

fn firecracker_registered_backend() -> RegisteredIsolationBackend {
    let requirements = [
        ("AGENT_WORKER_FIRECRACKER_BIN", "Firecracker binary path"),
        (
            "AGENT_WORKER_FIRECRACKER_JAILER",
            "Firecracker jailer binary path",
        ),
        (
            "AGENT_WORKER_FIRECRACKER_KERNEL",
            "Firecracker kernel image",
        ),
        (
            "AGENT_WORKER_FIRECRACKER_ROOTFS",
            "Firecracker rootfs image",
        ),
    ];
    let missing = requirements
        .iter()
        .filter_map(|(env_var, label)| configured_file_error(env_var, label))
        .collect::<Vec<_>>();

    let (ready, backend_version, readiness_reason) = if missing.is_empty() {
        (
            true,
            "external_bundle",
            Some(
                "Firecracker binary, jailer binary, kernel image, and rootfs image are configured"
                    .to_string(),
            ),
        )
    } else {
        (false, "unknown", Some(missing.join("; ")))
    };

    RegisteredIsolationBackend {
        descriptor: IsolationBackendDescriptor {
            backend_name: "firecracker".to_string(),
            backend_version: backend_version.to_string(),
            kind: IsolationBackendKind::FirecrackerMicroVm,
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            capabilities: IsolationBackendCapabilities::full(),
        },
        implementation: IsolationBackendImplementation::HostImplemented,
        ready,
        readiness_reason,
    }
}

fn configured_file_error(env_var: &str, label: &str) -> Option<String> {
    match env::var(env_var) {
        Ok(path) if path.trim().is_empty() => Some(format!("{label} was not configured")),
        Ok(path) if Path::new(&path).is_file() => None,
        Ok(path) => Some(format!("{env_var} does not point to a file: {path}")),
        Err(_) => Some(format!("{label} was not configured")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirecrackerPreparePlan {
    firecracker_bin: PathBuf,
    jailer_bin: PathBuf,
    kernel_image: PathBuf,
    rootfs_image: PathBuf,
    planned_steps: Vec<&'static str>,
    resource_policy: &'static str,
    network_policy: &'static str,
    filesystem_policy: &'static str,
}

fn firecracker_prepare_plan() -> Result<FirecrackerPreparePlan> {
    let firecracker_bin =
        required_configured_file("AGENT_WORKER_FIRECRACKER_BIN", "Firecracker binary path")?;
    let jailer_bin = required_configured_file(
        "AGENT_WORKER_FIRECRACKER_JAILER",
        "Firecracker jailer binary path",
    )?;
    let kernel_image = required_configured_file(
        "AGENT_WORKER_FIRECRACKER_KERNEL",
        "Firecracker kernel image",
    )?;
    let rootfs_image = required_configured_file(
        "AGENT_WORKER_FIRECRACKER_ROOTFS",
        "Firecracker rootfs image",
    )?;
    Ok(FirecrackerPreparePlan {
        firecracker_bin,
        jailer_bin,
        kernel_image,
        rootfs_image,
        planned_steps: vec![
            "prepare_runtime_bundle",
            "configure_jailer",
            "configure_network_namespace",
            "configure_tap_device",
            "configure_resource_limits",
            "configure_read_only_rootfs",
            "start_microvm",
            "attach_agent_handler",
            "collect_logs_and_artifacts",
            "cleanup_host_resources",
        ],
        resource_policy: "bounded_cpu_memory_disk_from_gateway_envelope",
        network_policy: "no_direct_public_egress_without_gateway_capability",
        filesystem_policy: "read_only_rootfs_with_prepared_workspace",
    })
}

fn required_configured_file(env_var: &str, label: &str) -> Result<PathBuf> {
    let path = env::var(env_var).unwrap_or_default();
    if path.trim().is_empty() {
        bail!("{label} was not configured");
    }
    let path = PathBuf::from(path.trim());
    if !path.is_file() {
        bail!("{env_var} does not point to a file: {}", path.display());
    }
    Ok(path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirecrackerHostPreflight {
    process: String,
    backend_name: String,
    backend_kind: String,
    host_lifecycle_owner: String,
    gateway_controls_firecracker: bool,
    bundle: FirecrackerBundlePreflight,
    host: FirecrackerHostCapabilityPreflight,
    ready: bool,
    failure_reasons: Vec<String>,
    proves_microvm_boot: bool,
}

impl FirecrackerHostPreflight {
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn failure_summary(&self) -> String {
        if self.failure_reasons.is_empty() {
            "Firecracker host preflight passed; microVM boot is still not proven".to_string()
        } else {
            format!(
                "Firecracker host preflight failed: {}",
                self.failure_reasons.join("; ")
            )
        }
    }

    #[cfg(test)]
    pub(crate) fn success_summary(&self) -> String {
        let firecracker_version = self
            .bundle
            .firecracker_bin
            .version_output
            .as_deref()
            .unwrap_or("unknown-firecracker-version");
        let jailer_version = self
            .bundle
            .jailer_bin
            .version_output
            .as_deref()
            .unwrap_or("unknown-jailer-version");
        let kernel_size = self.bundle.kernel_image.size_bytes.unwrap_or_default();
        let rootfs_size = self.bundle.rootfs_image.size_bytes.unwrap_or_default();
        format!(
            "Firecracker host preflight passed with {firecracker_version}, {jailer_version}, kernel_size_bytes={kernel_size}, rootfs_size_bytes={rootfs_size}; microVM boot is still not proven"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerBundlePreflight {
    firecracker_bin: FirecrackerPathCheck,
    jailer_bin: FirecrackerPathCheck,
    kernel_image: FirecrackerPathCheck,
    rootfs_image: FirecrackerPathCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerHostCapabilityPreflight {
    kvm_device: FirecrackerPathCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirecrackerGuestAgentPreflight {
    process: String,
    backend_name: String,
    backend_kind: String,
    host_lifecycle_owner: String,
    gateway_controls_firecracker: bool,
    channel_kind: String,
    command_channel: FirecrackerPathCheck,
    workspace: FirecrackerPathCheck,
    gateway_endpoint: FirecrackerEnvCheck,
    ready: bool,
    failure_reasons: Vec<String>,
    proves_microvm_boot: bool,
    proves_handler_execution: bool,
}

impl FirecrackerGuestAgentPreflight {
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn failure_summary(&self) -> String {
        if self.failure_reasons.is_empty() {
            "Firecracker guest agent preflight passed; handler execution inside the microVM is still not proven".to_string()
        } else {
            format!(
                "Firecracker guest agent preflight failed: {}",
                self.failure_reasons.join("; ")
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirecrackerGuestLaunchPlan {
    process: String,
    backend_name: String,
    backend_kind: String,
    host_lifecycle_owner: String,
    gateway_controls_firecracker: bool,
    adapter: String,
    ready: bool,
    guest_agent: FirecrackerGuestAgentPreflight,
    planned_steps: Vec<&'static str>,
    required_gateway_capabilities: Vec<&'static str>,
    guest_network_policy: String,
    filesystem_policy: String,
    artifact_policy: String,
    checkpoint_policy: String,
    proves_microvm_boot: bool,
    proves_handler_execution: bool,
    implementation_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerGuestAgentLaunchAttempt {
    pub(crate) command: String,
    pub(crate) workspace: String,
    pub(crate) gateway_endpoint: String,
    pub(crate) elapsed_millis: u128,
    pub(crate) exit_status: String,
    pub(crate) handshake: FirecrackerGuestAgentHandshake,
    pub(crate) proves_microvm_boot: bool,
    pub(crate) proves_handler_execution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct FirecrackerGuestAgentHandshake {
    protocol_version: String,
    ready: bool,
    rpc_channel: String,
    rpc_socket_path: Option<String>,
    guest_agent_version: Option<String>,
}

impl FirecrackerGuestAgentHandshake {
    pub(crate) const PROTOCOL_VERSION: &'static str = "ferrogate.agent-worker.guest.v1";

    pub(crate) fn parse(stdout: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(stdout).map_err(|error| error.to_string())?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| "stdout was empty".to_string())?;
        let handshake: Self = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if handshake.protocol_version != Self::PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol_version {}; expected {}",
                handshake.protocol_version,
                Self::PROTOCOL_VERSION
            ));
        }
        if !handshake.ready {
            return Err("handshake ready flag was false".to_string());
        }
        if handshake.rpc_channel.trim().is_empty() {
            return Err("handshake rpc_channel was empty".to_string());
        }
        if handshake.rpc_channel == "unix-json-lines"
            && handshake
                .rpc_socket_path
                .as_deref()
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .is_none()
        {
            return Err("unix-json-lines handshake rpc_socket_path was empty".to_string());
        }
        Ok(handshake)
    }

    pub(crate) fn rpc_channel(&self) -> &str {
        &self.rpc_channel
    }

    pub(crate) fn guest_agent_version(&self) -> Option<&str> {
        self.guest_agent_version.as_deref()
    }

    pub(crate) fn rpc_socket_path(&self) -> Option<&str> {
        self.rpc_socket_path.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerGuestAgentLaunchAttemptError {
    outcome: &'static str,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FirecrackerGuestRpcStartRequest {
    protocol_version: String,
    action: String,
    tenant_id: String,
    workspace_id: String,
    worker_id: String,
    session_id: String,
    run_id: String,
    framework_adapter: String,
    adapter_launch_profile: FirecrackerGuestAdapterLaunchProfile,
    isolation_backend: String,
    isolation_instance_id: String,
    rpc_channel: String,
    required_gateway_capabilities: Vec<String>,
    network_policy: String,
    filesystem_policy: String,
    artifact_policy: String,
    checkpoint_policy: String,
    proves_microvm_boot: bool,
    proves_handler_execution: bool,
    /// Real guest execution (#280): the bounded command envelope to run
    /// inside the microVM. Absent for legacy contract-probe requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload: Option<crate::firecracker_guest_exec::FirecrackerGuestWorkloadSpec>,
    /// Real guest execution (#280): the gateway capability envelope the guest
    /// agent enforces at the VM boundary. Required whenever `workload` is
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_envelope: Option<crate::firecracker_guest_exec::FirecrackerGuestCapabilityEnvelope>,
}

impl FirecrackerGuestRpcStartRequest {
    pub(crate) fn validate_for_guest_agent(&self) -> Result<(), String> {
        if self.protocol_version != FirecrackerGuestAgentHandshake::PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol_version {}; expected {}",
                self.protocol_version,
                FirecrackerGuestAgentHandshake::PROTOCOL_VERSION
            ));
        }
        if self.action != "start_handler" {
            return Err(format!("unsupported action {}", self.action));
        }
        for (field, value) in [
            ("tenant_id", &self.tenant_id),
            ("workspace_id", &self.workspace_id),
            ("worker_id", &self.worker_id),
            ("session_id", &self.session_id),
            ("run_id", &self.run_id),
            ("framework_adapter", &self.framework_adapter),
            ("isolation_backend", &self.isolation_backend),
            ("isolation_instance_id", &self.isolation_instance_id),
            ("rpc_channel", &self.rpc_channel),
            ("network_policy", &self.network_policy),
            ("filesystem_policy", &self.filesystem_policy),
            ("artifact_policy", &self.artifact_policy),
            ("checkpoint_policy", &self.checkpoint_policy),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{field} was empty"));
            }
        }
        if self.required_gateway_capabilities.is_empty() {
            return Err("required_gateway_capabilities was empty".to_string());
        }
        if self.proves_handler_execution {
            return Err("start request cannot claim handler execution".to_string());
        }
        if let Some(workload) = &self.workload {
            workload.validate()?;
            let Some(envelope) = &self.capability_envelope else {
                return Err(
                    "workload was present without a gateway capability envelope; the guest agent \
                     cannot execute without an enforceable envelope"
                        .to_string(),
                );
            };
            envelope.validate()?;
        }
        Ok(())
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn framework_adapter(&self) -> &str {
        &self.framework_adapter
    }

    pub(crate) fn isolation_instance_id(&self) -> &str {
        &self.isolation_instance_id
    }

    pub(crate) fn workload(
        &self,
    ) -> Option<&crate::firecracker_guest_exec::FirecrackerGuestWorkloadSpec> {
        self.workload.as_ref()
    }

    pub(crate) fn capability_envelope(
        &self,
    ) -> Option<&crate::firecracker_guest_exec::FirecrackerGuestCapabilityEnvelope> {
        self.capability_envelope.as_ref()
    }

    pub(crate) fn summary(&self) -> String {
        format!(
            "guest_rpc_start_request(protocol_version={}, action={}, worker_id={}, adapter={}, launch_profile={}, isolation_backend={}, isolation_instance_id={}, rpc_channel={}, required_gateway_capabilities={}, network_policy={}, filesystem_policy={}, proves_microvm_boot={}, proves_handler_execution={}, workload_present={}, capability_envelope_present={})",
            self.protocol_version,
            self.action,
            self.worker_id,
            self.framework_adapter,
            self.adapter_launch_profile.summary(),
            self.isolation_backend,
            self.isolation_instance_id,
            self.rpc_channel,
            self.required_gateway_capabilities.join("|"),
            self.network_policy,
            self.filesystem_policy,
            self.proves_microvm_boot,
            self.proves_handler_execution,
            self.workload.is_some(),
            self.capability_envelope.is_some()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FirecrackerGuestRpcStartResponse {
    protocol_version: String,
    action: String,
    worker_id: String,
    session_id: String,
    run_id: String,
    framework_adapter: String,
    adapter_launch_profile: FirecrackerGuestAdapterLaunchProfile,
    isolation_backend: String,
    isolation_instance_id: String,
    required_gateway_capabilities: Vec<String>,
    network_policy: String,
    filesystem_policy: String,
    artifact_policy: String,
    checkpoint_policy: String,
    status: String,
    message: Option<String>,
    proves_handler_execution: bool,
    /// Real guest execution (#280): what happened to the workload envelope
    /// inside the microVM. Absent for legacy contract-probe responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload_result: Option<crate::firecracker_guest_exec::FirecrackerGuestWorkloadResult>,
    #[serde(skip)]
    elapsed_millis: u128,
}

impl FirecrackerGuestRpcStartResponse {
    fn not_implemented_for_request(
        request: &FirecrackerGuestRpcStartRequest,
        message: impl Into<String>,
    ) -> Self {
        Self::for_guest_request(request, "not_implemented", message, None, false)
    }

    /// Build an identity/policy-bound response for a guest session. The guest
    /// agent uses this for every terminal state; the host verifies the echo
    /// with `verify_binding` before trusting any of it.
    pub(crate) fn for_guest_request(
        request: &FirecrackerGuestRpcStartRequest,
        status: &str,
        message: impl Into<String>,
        workload_result: Option<crate::firecracker_guest_exec::FirecrackerGuestWorkloadResult>,
        proves_handler_execution: bool,
    ) -> Self {
        Self {
            protocol_version: request.protocol_version.clone(),
            action: request.action.clone(),
            worker_id: request.worker_id.clone(),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            framework_adapter: request.framework_adapter.clone(),
            adapter_launch_profile: request.adapter_launch_profile.clone(),
            isolation_backend: request.isolation_backend.clone(),
            isolation_instance_id: request.isolation_instance_id.clone(),
            required_gateway_capabilities: request.required_gateway_capabilities.clone(),
            network_policy: request.network_policy.clone(),
            filesystem_policy: request.filesystem_policy.clone(),
            artifact_policy: request.artifact_policy.clone(),
            checkpoint_policy: request.checkpoint_policy.clone(),
            status: status.to_string(),
            message: Some(message.into()),
            proves_handler_execution,
            workload_result,
            elapsed_millis: 0,
        }
    }

    pub(crate) fn status(&self) -> &str {
        &self.status
    }

    pub(crate) fn proves_handler_execution(&self) -> bool {
        self.proves_handler_execution
    }

    pub(crate) fn workload_result(
        &self,
    ) -> Option<&crate::firecracker_guest_exec::FirecrackerGuestWorkloadResult> {
        self.workload_result.as_ref()
    }

    pub(crate) fn with_elapsed_millis(mut self, elapsed_millis: u128) -> Self {
        self.elapsed_millis = elapsed_millis;
        self
    }

    fn parse(
        stdout: &[u8],
        elapsed_millis: u128,
        request: &FirecrackerGuestRpcStartRequest,
    ) -> Result<Self, String> {
        let text = std::str::from_utf8(stdout).map_err(|error| error.to_string())?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| "stdout was empty".to_string())?;
        let mut response: Self = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if response.protocol_version != FirecrackerGuestAgentHandshake::PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol_version {}; expected {}",
                response.protocol_version,
                FirecrackerGuestAgentHandshake::PROTOCOL_VERSION
            ));
        }
        if response.status.trim().is_empty() {
            return Err("status was empty".to_string());
        }
        response.verify_binding(request)?;
        if response.proves_handler_execution {
            return Err(
                "response claimed handler execution before in-guest execution is wired".to_string(),
            );
        }
        response.elapsed_millis = elapsed_millis;
        Ok(response)
    }

    /// Require the response to echo the exact identity, adapter, capability,
    /// and policy shape of the request it answers. Shared by the legacy
    /// command-bridge transport and the real vsock guest execution transport;
    /// any mismatch fails closed.
    pub(crate) fn verify_binding(
        &self,
        request: &FirecrackerGuestRpcStartRequest,
    ) -> Result<(), String> {
        if self.protocol_version != FirecrackerGuestAgentHandshake::PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol_version {}; expected {}",
                self.protocol_version,
                FirecrackerGuestAgentHandshake::PROTOCOL_VERSION
            ));
        }
        if self.status.trim().is_empty() {
            return Err("status was empty".to_string());
        }
        Self::require_matches("action", &self.action, &request.action)?;
        Self::require_matches("worker_id", &self.worker_id, &request.worker_id)?;
        Self::require_matches("session_id", &self.session_id, &request.session_id)?;
        Self::require_matches("run_id", &self.run_id, &request.run_id)?;
        Self::require_matches(
            "framework_adapter",
            &self.framework_adapter,
            &request.framework_adapter,
        )?;
        Self::require_matches(
            "adapter_launch_profile",
            &self.adapter_launch_profile.summary(),
            &request.adapter_launch_profile.summary(),
        )?;
        Self::require_matches(
            "isolation_backend",
            &self.isolation_backend,
            &request.isolation_backend,
        )?;
        Self::require_matches(
            "isolation_instance_id",
            &self.isolation_instance_id,
            &request.isolation_instance_id,
        )?;
        Self::require_vec_matches(
            "required_gateway_capabilities",
            &self.required_gateway_capabilities,
            &request.required_gateway_capabilities,
        )?;
        Self::require_matches(
            "network_policy",
            &self.network_policy,
            &request.network_policy,
        )?;
        Self::require_matches(
            "filesystem_policy",
            &self.filesystem_policy,
            &request.filesystem_policy,
        )?;
        Self::require_matches(
            "artifact_policy",
            &self.artifact_policy,
            &request.artifact_policy,
        )?;
        Self::require_matches(
            "checkpoint_policy",
            &self.checkpoint_policy,
            &request.checkpoint_policy,
        )?;
        Ok(())
    }

    pub(crate) fn summary(&self) -> String {
        format!(
            "guest_rpc_start_response(status={}, action={}, worker_id={}, session_id={}, run_id={}, adapter={}, launch_profile={}, isolation_backend={}, isolation_instance_id={}, required_gateway_capabilities={}, network_policy={}, filesystem_policy={}, artifact_policy={}, checkpoint_policy={}, message={}, proves_handler_execution={}, elapsed_millis={})",
            self.status,
            self.action,
            self.worker_id,
            self.session_id,
            self.run_id,
            self.framework_adapter,
            self.adapter_launch_profile.summary(),
            self.isolation_backend,
            self.isolation_instance_id,
            self.required_gateway_capabilities.join("|"),
            self.network_policy,
            self.filesystem_policy,
            self.artifact_policy,
            self.checkpoint_policy,
            self.message.as_deref().unwrap_or(""),
            self.proves_handler_execution,
            self.elapsed_millis
        )
    }

    fn require_matches(field: &str, actual: &str, expected: &str) -> Result<(), String> {
        if actual == expected {
            return Ok(());
        }
        Err(format!(
            "{field} mismatch: response={actual}; request={expected}"
        ))
    }

    fn require_vec_matches(
        field: &str,
        actual: &[String],
        expected: &[String],
    ) -> Result<(), String> {
        if actual == expected {
            return Ok(());
        }
        Err(format!(
            "{field} mismatch: response={}; request={}",
            actual.join("|"),
            expected.join("|")
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FirecrackerGuestAdapterLaunchProfile {
    framework: String,
    entrypoint: String,
    event_stream: String,
    external_action_mode: String,
}

impl FirecrackerGuestAdapterLaunchProfile {
    fn summary(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.framework, self.entrypoint, self.event_stream, self.external_action_mode
        )
    }
}

impl FirecrackerGuestAgentLaunchAttemptError {
    pub(crate) fn new(outcome: &'static str, reason: String) -> Self {
        Self { outcome, reason }
    }

    pub(crate) fn outcome(&self) -> &'static str {
        self.outcome
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

fn normalize_guest_launch_adapter(adapter: Option<&str>) -> &'static str {
    match adapter.unwrap_or("native-harness") {
        "codex" => "codex",
        "claude-code" | "claude_code" => "claude-code",
        "hermes" => "hermes",
        _ => "native-harness",
    }
}

fn guest_launch_capabilities(adapter: &str) -> Vec<&'static str> {
    match adapter {
        "codex" | "claude-code" => vec!["cli", "filesystem", "tools", "artifacts", "checkpoint"],
        "hermes" => vec![
            "memory.read",
            "memory.write",
            "subagents",
            "artifacts",
            "checkpoint",
        ],
        _ => vec!["tools", "artifacts", "checkpoint"],
    }
}

fn adapter_launch_profile(adapter: &str) -> FirecrackerGuestAdapterLaunchProfile {
    match adapter {
        "codex" => FirecrackerGuestAdapterLaunchProfile {
            framework: "codex".to_string(),
            entrypoint: "codex_exec".to_string(),
            event_stream: "normalized_jsonl".to_string(),
            external_action_mode: "gateway_mediated_cli_filesystem_tools".to_string(),
        },
        "claude-code" => FirecrackerGuestAdapterLaunchProfile {
            framework: "claude_code".to_string(),
            entrypoint: "claude_code_non_interactive".to_string(),
            event_stream: "normalized_jsonl".to_string(),
            external_action_mode: "gateway_mediated_cli_filesystem_tools".to_string(),
        },
        "hermes" => FirecrackerGuestAdapterLaunchProfile {
            framework: "hermes".to_string(),
            entrypoint: "hermes_oneshot".to_string(),
            event_stream: "normalized_jsonl".to_string(),
            external_action_mode: "gateway_mediated_memory_subagents".to_string(),
        },
        _ => FirecrackerGuestAdapterLaunchProfile {
            framework: "native_harness".to_string(),
            entrypoint: "native_harness_task".to_string(),
            event_stream: "normalized_jsonl".to_string(),
            external_action_mode: "gateway_mediated_tools".to_string(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerPathCheck {
    env_var: Option<&'static str>,
    label: &'static str,
    path: Option<String>,
    configured: bool,
    exists: bool,
    file: bool,
    size_bytes: Option<u64>,
    executable: Option<bool>,
    version_output: Option<String>,
    char_device: Option<bool>,
    open_read_write: Option<bool>,
    writable: Option<bool>,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerEnvCheck {
    env_var: &'static str,
    label: &'static str,
    configured: bool,
    value_present: bool,
    reason: Option<String>,
}

fn configured_file_check(
    env_var: Option<&'static str>,
    label: &'static str,
    must_be_executable: bool,
) -> FirecrackerPathCheck {
    let Some(env_var) = env_var else {
        return path_check_failure(
            None,
            label,
            None,
            false,
            "path was not configured".to_string(),
        );
    };
    let path = env::var(env_var).unwrap_or_default();
    if path.trim().is_empty() {
        return path_check_failure(
            Some(env_var),
            label,
            None,
            false,
            format!("{label} was not configured"),
        );
    }
    let path = PathBuf::from(path.trim());
    let path_display = path.display().to_string();
    match fs::metadata(&path) {
        Ok(metadata) => {
            let file = metadata.is_file();
            let executable = (metadata.permissions().mode() & 0o111) != 0;
            let version_output = if file && must_be_executable && executable {
                executable_version_output(&path)
            } else {
                None
            };
            let reason = if !file {
                Some(format!(
                    "{env_var} does not point to a file: {path_display}"
                ))
            } else if must_be_executable && !executable {
                Some(format!("{env_var} is not executable: {path_display}"))
            } else if must_be_executable && version_output.is_none() {
                Some(format!(
                    "{env_var} is executable but did not return version output: {path_display}"
                ))
            } else {
                None
            };
            FirecrackerPathCheck {
                env_var: Some(env_var),
                label,
                path: Some(path_display),
                configured: true,
                exists: true,
                file,
                size_bytes: Some(metadata.len()),
                executable: Some(executable),
                version_output,
                char_device: None,
                open_read_write: None,
                writable: None,
                reason,
            }
        }
        Err(_) => path_check_failure(
            Some(env_var),
            label,
            Some(path_display.clone()),
            true,
            format!("{env_var} does not point to a file: {path_display}"),
        ),
    }
}

fn configured_directory_check(
    env_var: Option<&'static str>,
    label: &'static str,
) -> FirecrackerPathCheck {
    let Some(env_var) = env_var else {
        return path_check_failure(
            None,
            label,
            None,
            false,
            "path was not configured".to_string(),
        );
    };
    let path = env::var(env_var).unwrap_or_default();
    if path.trim().is_empty() {
        return path_check_failure(
            Some(env_var),
            label,
            None,
            false,
            format!("{label} was not configured"),
        );
    }
    let path = PathBuf::from(path.trim());
    let path_display = path.display().to_string();
    match fs::metadata(&path) {
        Ok(metadata) => {
            let directory = metadata.is_dir();
            let writable = if directory {
                Some(directory_write_probe(&path))
            } else {
                None
            };
            let reason = if !directory {
                Some(format!(
                    "{env_var} does not point to a directory: {path_display}"
                ))
            } else if writable == Some(false) {
                Some(format!(
                    "{env_var} is not writable by agent-worker: {path_display}"
                ))
            } else {
                None
            };
            FirecrackerPathCheck {
                env_var: Some(env_var),
                label,
                path: Some(path_display),
                configured: true,
                exists: true,
                file: metadata.is_file(),
                size_bytes: None,
                executable: None,
                version_output: None,
                char_device: None,
                open_read_write: None,
                writable,
                reason,
            }
        }
        Err(_) => path_check_failure(
            Some(env_var),
            label,
            Some(path_display.clone()),
            true,
            format!("{env_var} does not point to a directory: {path_display}"),
        ),
    }
}

fn configured_non_empty_env_check(
    env_var: &'static str,
    label: &'static str,
) -> FirecrackerEnvCheck {
    match env::var(env_var) {
        Ok(value) if !value.trim().is_empty() => FirecrackerEnvCheck {
            env_var,
            label,
            configured: true,
            value_present: true,
            reason: None,
        },
        Ok(_) => FirecrackerEnvCheck {
            env_var,
            label,
            configured: true,
            value_present: false,
            reason: Some(format!("{label} was not configured")),
        },
        Err(_) => FirecrackerEnvCheck {
            env_var,
            label,
            configured: false,
            value_present: false,
            reason: Some(format!("{label} was not configured")),
        },
    }
}

fn kvm_device_check() -> FirecrackerPathCheck {
    let env_var = "AGENT_WORKER_FIRECRACKER_KVM_DEVICE";
    let path = env::var(env_var).unwrap_or_else(|_| "/dev/kvm".to_string());
    let path = path.trim();
    if path.is_empty() {
        return path_check_failure(
            Some(env_var),
            "KVM device",
            None,
            false,
            "KVM device path was not configured".to_string(),
        );
    }
    let path_buf = PathBuf::from(path);
    let path_display = path_buf.display().to_string();
    match fs::metadata(&path_buf) {
        Ok(metadata) => {
            let char_device = metadata.file_type().is_char_device();
            let open_read_write = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path_buf)
                .is_ok();
            let reason = if !char_device {
                Some(format!("{path_display} is not a character device"))
            } else if !open_read_write {
                Some(format!(
                    "{path_display} is not readable and writable by agent-worker"
                ))
            } else {
                None
            };
            FirecrackerPathCheck {
                env_var: Some(env_var),
                label: "KVM device",
                path: Some(path_display),
                configured: true,
                exists: true,
                file: false,
                size_bytes: None,
                executable: None,
                version_output: None,
                char_device: Some(char_device),
                open_read_write: Some(open_read_write),
                writable: None,
                reason,
            }
        }
        Err(_) => path_check_failure(
            Some(env_var),
            "KVM device",
            Some(path_display.clone()),
            true,
            format!("{path_display} does not exist"),
        ),
    }
}

fn path_check_failure(
    env_var: Option<&'static str>,
    label: &'static str,
    path: Option<String>,
    configured: bool,
    reason: String,
) -> FirecrackerPathCheck {
    FirecrackerPathCheck {
        env_var,
        label,
        path,
        configured,
        exists: false,
        file: false,
        size_bytes: None,
        executable: None,
        version_output: None,
        char_device: None,
        open_read_write: None,
        writable: None,
        reason: Some(reason),
    }
}

fn directory_write_probe(path: &Path) -> bool {
    let probe = path.join(format!(
        ".ferrogate-agent-worker-write-probe-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(mut file) => {
            let write_ok = file.write_all(b"ferrogate-agent-worker").is_ok();
            drop(file);
            let cleanup_ok = fs::remove_file(&probe).is_ok();
            write_ok && cleanup_ok
        }
        Err(_) => false,
    }
}

fn executable_version_output(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }
    if text.is_empty() {
        None
    } else {
        Some(text.lines().next().unwrap_or_default().to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FirecrackerBootSmokeOptions {
    timeout: Duration,
    vcpu_count: u8,
    mem_size_mib: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerBootSmokeReport {
    process: String,
    backend_name: String,
    backend_kind: String,
    host_lifecycle_owner: String,
    gateway_controls_firecracker: bool,
    ready: bool,
    boot_observed: bool,
    proves_microvm_boot: bool,
    vcpu_count: u8,
    mem_size_mib: u32,
    evidence: Option<FirecrackerBootEvidence>,
    failure_stage: Option<String>,
    failure_reason: Option<String>,
    artifacts: FirecrackerBootSmokeArtifactReport,
    preflight: FirecrackerHostPreflight,
}

impl FirecrackerBootSmokeReport {
    fn failed(
        stage: impl Into<String>,
        reason: impl Into<String>,
        artifacts: Option<FirecrackerBootSmokeArtifactReport>,
        evidence: Option<FirecrackerBootEvidence>,
        preflight: FirecrackerHostPreflight,
    ) -> Self {
        Self {
            process: "agent-worker".to_string(),
            backend_name: "firecracker".to_string(),
            backend_kind: "firecracker_micro_vm".to_string(),
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_firecracker: false,
            ready: false,
            boot_observed: false,
            proves_microvm_boot: false,
            vcpu_count: 0,
            mem_size_mib: 0,
            evidence,
            failure_stage: Some(stage.into()),
            failure_reason: Some(reason.into()),
            artifacts: artifacts.unwrap_or_default(),
            preflight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirecrackerBootEvidence {
    serial_boot_markers: Vec<&'static str>,
    serial_excerpt: String,
    firecracker_log_excerpt: String,
}

#[derive(Debug)]
pub(crate) struct FirecrackerMicroVm {
    pub(crate) instance_id: String,
    pub(crate) evidence: FirecrackerBootEvidence,
    pub(crate) artifacts: FirecrackerMicroVmArtifacts,
    child: Child,
}

impl FirecrackerMicroVm {
    pub(crate) fn is_running(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none()
    }

    /// Host-side Unix socket of the microVM's `guest-rpc` vsock device — the
    /// transport anchor for real guest execution (#280).
    pub(crate) fn guest_rpc_socket_path(&self) -> PathBuf {
        self.artifacts.guest_rpc_socket.clone()
    }

    pub(crate) fn artifact_results(&self) -> Vec<AgentWorkerFrameworkArtifactResult> {
        self.artifacts.to_artifact_results(&self.instance_id)
    }

    pub(crate) fn artifact_events(
        &self,
        session_id: &str,
        run_id: &str,
    ) -> Vec<AgentWorkerFrameworkEventResult> {
        self.artifact_results()
            .into_iter()
            .map(|artifact| {
                firecracker_artifact_event(session_id, run_id, &self.instance_id, artifact)
            })
            .collect()
    }

    pub(crate) fn stop(&mut self) -> FirecrackerStopReport {
        let process = stop_firecracker_child(&mut self.child);
        let api_socket_removed = remove_firecracker_host_file(&self.artifacts.api_socket);
        let guest_rpc_socket_removed =
            remove_firecracker_host_file(&self.artifacts.guest_rpc_socket);
        // Per-VM writable workspace backing file (#227): reclaim it on
        // teardown; it is private to this VM's run dir.
        let workspace_image_removed =
            remove_firecracker_host_file(&self.artifacts.workspace_image_path());
        FirecrackerStopReport {
            was_running: process.was_running,
            process_outcome: process.outcome,
            api_socket_removed,
            guest_rpc_socket_removed,
            workspace_image_removed,
        }
    }

    pub(crate) fn cleanup(&mut self) -> FirecrackerStopReport {
        self.stop()
    }

    pub(crate) fn snapshot_or_checkpoint(&mut self) -> FirecrackerSnapshotReport {
        let snapshot = self.artifacts.snapshot_path();
        let memory = self.artifacts.snapshot_memory_path();
        let mut steps = Vec::new();
        let result = (|| {
            firecracker_patch_json(
                &self.artifacts.api_socket,
                "/vm",
                json!({ "state": "Paused" }),
                Duration::from_secs(10),
            )
            .map_err(|error| {
                FirecrackerSnapshotError::new("pause_vm", error.summary(), &snapshot, &memory)
            })?;
            steps.push("paused");
            firecracker_put_json_with_timeout(
                &self.artifacts.api_socket,
                "/snapshot/create",
                json!({
                    "snapshot_type": "Full",
                    "snapshot_path": snapshot.display().to_string(),
                    "mem_file_path": memory.display().to_string(),
                }),
                Duration::from_secs(30),
            )
            .map_err(|error| {
                FirecrackerSnapshotError::new(
                    "create_snapshot",
                    error.summary(),
                    &snapshot,
                    &memory,
                )
            })?;
            steps.push("snapshot_created");
            Ok(())
        })();
        let resume = firecracker_patch_json(
            &self.artifacts.api_socket,
            "/vm",
            json!({ "state": "Resumed" }),
            Duration::from_secs(10),
        );
        match resume {
            Ok(()) => steps.push("resumed"),
            Err(error) => {
                if result.is_ok() {
                    return FirecrackerSnapshotReport::failed(
                        FirecrackerSnapshotError::new(
                            "resume_vm",
                            error.summary(),
                            &snapshot,
                            &memory,
                        ),
                        steps,
                    );
                }
            }
        }
        match result {
            Ok(()) => FirecrackerSnapshotReport {
                outcome: "snapshot_created".to_string(),
                snapshot_path: snapshot,
                memory_path: memory,
                snapshot_bytes: file_len(&self.artifacts.snapshot_path()),
                memory_bytes: file_len(&self.artifacts.snapshot_memory_path()),
                steps,
                failure_stage: None,
                failure_reason: None,
            },
            Err(error) => FirecrackerSnapshotReport::failed(error, steps),
        }
    }
}

impl Drop for FirecrackerMicroVm {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn firecracker_artifact_event(
    session_id: &str,
    run_id: &str,
    instance_id: &str,
    artifact: AgentWorkerFrameworkArtifactResult,
) -> AgentWorkerFrameworkEventResult {
    let mut metadata = HashMap::new();
    metadata.insert("artifact_id".to_string(), artifact.artifact_id);
    metadata.insert("artifact_name".to_string(), artifact.name);
    metadata.insert("media_type".to_string(), artifact.media_type);
    metadata.insert("byte_len".to_string(), artifact.byte_len.to_string());
    metadata.insert("isolation_backend".to_string(), "firecracker".to_string());
    metadata.insert("isolation_instance_id".to_string(), instance_id.to_string());
    metadata.insert("handler_owner".to_string(), "agent-worker".to_string());
    AgentWorkerFrameworkEventResult {
        session_id: session_id.to_string(),
        run_id: run_id.to_string(),
        adapter_name: "firecracker".to_string(),
        adapter_version: "external_bundle".to_string(),
        framework: "firecracker".to_string(),
        mode: "managed".to_string(),
        kind: "artifact.created".to_string(),
        message: Some("Firecracker microVM artifact collected by agent-worker".to_string()),
        metadata,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerMicroVmArtifacts {
    run_dir: PathBuf,
    api_socket: PathBuf,
    guest_rpc_socket: PathBuf,
    firecracker_log: PathBuf,
    serial_output: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerStopReport {
    pub(crate) was_running: bool,
    pub(crate) process_outcome: FirecrackerProcessStopOutcome,
    pub(crate) api_socket_removed: Result<bool, String>,
    pub(crate) guest_rpc_socket_removed: Result<bool, String>,
    pub(crate) workspace_image_removed: Result<bool, String>,
}

impl FirecrackerStopReport {
    pub(crate) fn cleanup_succeeded(&self) -> bool {
        self.api_socket_removed.is_ok()
            && self.guest_rpc_socket_removed.is_ok()
            && self.workspace_image_removed.is_ok()
    }

    pub(crate) fn summary(&self) -> String {
        let api_socket = match &self.api_socket_removed {
            Ok(true) => "api_socket_removed=true".to_string(),
            Ok(false) => "api_socket_removed=false".to_string(),
            Err(error) => format!("api_socket_remove_error={error}"),
        };
        let guest_rpc_socket = match &self.guest_rpc_socket_removed {
            Ok(true) => "guest_rpc_socket_removed=true".to_string(),
            Ok(false) => "guest_rpc_socket_removed=false".to_string(),
            Err(error) => format!("guest_rpc_socket_remove_error={error}"),
        };
        let workspace_image = match &self.workspace_image_removed {
            Ok(true) => "workspace_image_removed=true".to_string(),
            Ok(false) => "workspace_image_removed=false".to_string(),
            Err(error) => format!("workspace_image_remove_error={error}"),
        };
        format!(
            "was_running={}; process_outcome={}; {api_socket}; {guest_rpc_socket}; {workspace_image}",
            self.was_running,
            self.process_outcome.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirecrackerProcessStopOutcome {
    AlreadyExited(String),
    Killed(String),
    KillFailed(String),
    WaitFailed(String),
}

impl FirecrackerProcessStopOutcome {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::AlreadyExited(_) => "already_exited",
            Self::Killed(_) => "killed",
            Self::KillFailed(_) => "kill_failed",
            Self::WaitFailed(_) => "wait_failed",
        }
    }
}

impl FirecrackerMicroVmArtifacts {
    fn new() -> Result<Self, std::io::Error> {
        // Monotonic per-process counter: two microVMs provisioned in the same
        // millisecond must still get distinct run dirs (each run dir holds the
        // VM's private writable workspace image — see #227).
        static RUN_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let run_dir = env::temp_dir().join(format!(
            "ferrogate-agent-worker-firecracker-microvm-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            RUN_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&run_dir)?;
        Ok(Self {
            run_dir: run_dir.clone(),
            api_socket: run_dir.join("firecracker.sock"),
            guest_rpc_socket: run_dir.join("firecracker-guest-rpc.sock"),
            firecracker_log: run_dir.join("firecracker.log"),
            serial_output: run_dir.join("serial.log"),
            stdout: run_dir.join("firecracker.stdout"),
            stderr: run_dir.join("firecracker.stderr"),
        })
    }

    fn to_report_paths(&self) -> FirecrackerBootSmokeArtifactReport {
        FirecrackerBootSmokeArtifactReport {
            api_socket: Some(self.api_socket.display().to_string()),
            guest_rpc_socket: Some(self.guest_rpc_socket.display().to_string()),
            firecracker_log: Some(self.firecracker_log.display().to_string()),
            serial_output: Some(self.serial_output.display().to_string()),
            stdout: Some(self.stdout.display().to_string()),
            stderr: Some(self.stderr.display().to_string()),
        }
    }

    /// Per-VM writable workspace backing file. Lives inside the VM's private
    /// run dir, so two microVMs can never share it; removed on teardown.
    fn workspace_image_path(&self) -> PathBuf {
        self.run_dir.join("workspace.ext4")
    }

    fn snapshot_path(&self) -> PathBuf {
        self.run_dir.join("firecracker.snapshot")
    }

    fn snapshot_memory_path(&self) -> PathBuf {
        self.run_dir.join("firecracker.mem")
    }

    fn to_artifact_results(&self, instance_id: &str) -> Vec<AgentWorkerFrameworkArtifactResult> {
        [
            ("firecracker-log", "firecracker.log", &self.firecracker_log),
            ("serial-output", "serial.log", &self.serial_output),
            ("firecracker-stdout", "firecracker.stdout", &self.stdout),
            ("firecracker-stderr", "firecracker.stderr", &self.stderr),
        ]
        .into_iter()
        .map(|(suffix, name, path)| AgentWorkerFrameworkArtifactResult {
            artifact_id: format!("{instance_id}-{suffix}"),
            name: name.to_string(),
            media_type: "text/plain".to_string(),
            byte_len: file_len(path),
        })
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerSnapshotReport {
    pub(crate) outcome: String,
    pub(crate) snapshot_path: PathBuf,
    pub(crate) memory_path: PathBuf,
    pub(crate) snapshot_bytes: u64,
    pub(crate) memory_bytes: u64,
    pub(crate) steps: Vec<&'static str>,
    pub(crate) failure_stage: Option<&'static str>,
    pub(crate) failure_reason: Option<String>,
}

impl FirecrackerSnapshotReport {
    fn failed(error: FirecrackerSnapshotError, steps: Vec<&'static str>) -> Self {
        Self {
            outcome: "snapshot_failed".to_string(),
            snapshot_path: error.snapshot_path,
            memory_path: error.memory_path,
            snapshot_bytes: 0,
            memory_bytes: 0,
            steps,
            failure_stage: Some(error.stage),
            failure_reason: Some(error.reason),
        }
    }

    pub(crate) fn succeeded(&self) -> bool {
        self.failure_stage.is_none() && self.snapshot_bytes > 0 && self.memory_bytes > 0
    }

    pub(crate) fn summary(&self) -> String {
        let mut parts = vec![
            format!("outcome={}", self.outcome),
            format!("snapshot_path={}", self.snapshot_path.display()),
            format!("snapshot_bytes={}", self.snapshot_bytes),
            format!("memory_path={}", self.memory_path.display()),
            format!("memory_bytes={}", self.memory_bytes),
            format!("steps={}", self.steps.join(",")),
        ];
        if let Some(stage) = self.failure_stage {
            parts.push(format!("failure_stage={stage}"));
        }
        if let Some(reason) = &self.failure_reason {
            parts.push(format!("failure_reason={reason}"));
        }
        parts.join("; ")
    }

    pub(crate) fn artifact_results(
        &self,
        instance_id: &str,
    ) -> Vec<AgentWorkerFrameworkArtifactResult> {
        vec![
            AgentWorkerFrameworkArtifactResult {
                artifact_id: format!("{instance_id}-snapshot-state"),
                name: "firecracker.snapshot".to_string(),
                media_type: "application/octet-stream".to_string(),
                byte_len: self.snapshot_bytes,
            },
            AgentWorkerFrameworkArtifactResult {
                artifact_id: format!("{instance_id}-snapshot-memory"),
                name: "firecracker.mem".to_string(),
                media_type: "application/octet-stream".to_string(),
                byte_len: self.memory_bytes,
            },
        ]
    }

    pub(crate) fn artifact_events(
        &self,
        session_id: &str,
        run_id: &str,
        instance_id: &str,
    ) -> Vec<AgentWorkerFrameworkEventResult> {
        self.artifact_results(instance_id)
            .into_iter()
            .map(|artifact| firecracker_artifact_event(session_id, run_id, instance_id, artifact))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirecrackerSnapshotError {
    stage: &'static str,
    reason: String,
    snapshot_path: PathBuf,
    memory_path: PathBuf,
}

impl FirecrackerSnapshotError {
    fn new(
        stage: &'static str,
        reason: impl Into<String>,
        snapshot_path: &Path,
        memory_path: &Path,
    ) -> Self {
        Self {
            stage,
            reason: reason.into(),
            snapshot_path: snapshot_path.to_path_buf(),
            memory_path: memory_path.to_path_buf(),
        }
    }
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct FirecrackerBootSmokeArtifactReport {
    api_socket: Option<String>,
    guest_rpc_socket: Option<String>,
    firecracker_log: Option<String>,
    serial_output: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerBootSmokeError {
    stage: &'static str,
    reason: String,
    evidence: Option<Box<FirecrackerBootEvidence>>,
    artifacts: Option<Box<FirecrackerBootSmokeArtifactReport>>,
}

impl FirecrackerBootSmokeError {
    fn new(stage: &'static str, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: reason.into(),
            evidence: None,
            artifacts: None,
        }
    }

    fn with_evidence(
        stage: &'static str,
        reason: impl Into<String>,
        evidence: FirecrackerBootEvidence,
    ) -> Self {
        Self {
            stage,
            reason: reason.into(),
            evidence: Some(Box::new(evidence)),
            artifacts: None,
        }
    }

    fn with_artifacts(mut self, artifacts: &FirecrackerMicroVmArtifacts) -> Self {
        self.artifacts = Some(Box::new(artifacts.to_report_paths()));
        self
    }

    pub(crate) fn summary(&self) -> String {
        format!("{}: {}", self.stage, self.reason)
    }
}

impl FirecrackerBootEvidence {
    pub(crate) fn marker_summary(&self) -> String {
        self.serial_boot_markers.join(",")
    }
}

#[cfg(test)]
pub(crate) fn test_firecracker_microvm(
    instance_id: &str,
    run_dir: &Path,
) -> std::io::Result<FirecrackerMicroVm> {
    fs::create_dir_all(run_dir)?;
    let artifacts = FirecrackerMicroVmArtifacts {
        run_dir: run_dir.to_path_buf(),
        api_socket: run_dir.join("firecracker.sock"),
        guest_rpc_socket: run_dir.join("firecracker-guest-rpc.sock"),
        firecracker_log: run_dir.join("firecracker.log"),
        serial_output: run_dir.join("serial.log"),
        stdout: run_dir.join("firecracker.stdout"),
        stderr: run_dir.join("firecracker.stderr"),
    };
    fs::write(&artifacts.firecracker_log, b"firecracker log\n")?;
    fs::write(&artifacts.serial_output, b"serial boot log\n")?;
    fs::write(&artifacts.stdout, b"stdout\n")?;
    fs::write(&artifacts.stderr, b"stderr\n")?;
    Ok(FirecrackerMicroVm {
        instance_id: instance_id.to_string(),
        evidence: FirecrackerBootEvidence {
            serial_boot_markers: vec!["linux_version", "rootfs_mounted", "systemd_started"],
            serial_excerpt: "serial boot log".to_string(),
            firecracker_log_excerpt: "firecracker log".to_string(),
        },
        artifacts,
        child: Command::new("sleep").arg("60").spawn()?,
    })
}

fn start_firecracker_microvm(
    bundle: &FirecrackerPreparePlan,
    artifacts: FirecrackerMicroVmArtifacts,
    options: &FirecrackerBootSmokeOptions,
) -> Result<FirecrackerMicroVm, FirecrackerBootSmokeError> {
    let stdout = File::create(&artifacts.stdout).map_err(|error| {
        FirecrackerBootSmokeError::new("open_stdout_artifact", error.to_string())
            .with_artifacts(&artifacts)
    })?;
    let stderr = File::create(&artifacts.stderr).map_err(|error| {
        FirecrackerBootSmokeError::new("open_stderr_artifact", error.to_string())
            .with_artifacts(&artifacts)
    })?;
    let mut child = Command::new(&bundle.firecracker_bin)
        .arg("--api-sock")
        .arg(&artifacts.api_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| {
            FirecrackerBootSmokeError::new("spawn_firecracker", error.to_string())
                .with_artifacts(&artifacts)
        })?;
    match configure_and_start_firecracker(bundle, &artifacts, options, &mut child) {
        Ok(evidence) => Ok(FirecrackerMicroVm {
            instance_id: artifacts
                .run_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("firecracker-microvm")
                .to_string(),
            evidence,
            artifacts,
            child,
        }),
        Err(error) => {
            stop_firecracker_child(&mut child);
            Err(error.with_artifacts(&artifacts))
        }
    }
}

fn configure_and_start_firecracker(
    bundle: &FirecrackerPreparePlan,
    artifacts: &FirecrackerMicroVmArtifacts,
    options: &FirecrackerBootSmokeOptions,
    child: &mut Child,
) -> Result<FirecrackerBootEvidence, FirecrackerBootSmokeError> {
    let deadline = Instant::now() + options.timeout.max(Duration::from_millis(1));
    wait_for_api_socket(&artifacts.api_socket, deadline, child)?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/logger",
        json!({
            "log_path": artifacts.firecracker_log.display().to_string(),
            "level": "Info",
            "show_level": true,
            "show_log_origin": true,
        }),
        deadline,
    )?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/serial",
        json!({
            "serial_out_path": artifacts.serial_output.display().to_string(),
        }),
        deadline,
    )?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/machine-config",
        json!({
            "vcpu_count": options.vcpu_count,
            "mem_size_mib": options.mem_size_mib,
            "smt": false,
        }),
        deadline,
    )?;
    // SECURITY / ISOLATION (#227): the shared host rootfs image is now attached
    // read-only (`is_read_only: true` + `root=/dev/vda ro`) and every microVM
    // gets its OWN writable workspace drive backed by a file inside the VM's
    // private run dir, honoring the declared
    // IsolationFilesystemPolicy { read_only_rootfs: true, writable_workspace:
    // true } / `read_only_rootfs_with_prepared_workspace`. Concurrent microVMs
    // no longer share a writable backing file. Remaining (tracked in #227):
    // guest boot with this drive layout still needs validation on a real
    // Firecracker host (the guest init may need tuning to mount /dev/vdb as
    // its workspace / provide a tmpfs overlay for transient rootfs writes).
    let attachment = plan_firecracker_rootfs_attachment(
        &bundle.rootfs_image,
        artifacts,
        &firecracker_filesystem_policy(),
    );
    if let Some(workspace_image) = &attachment.workspace_image {
        prepare_firecracker_workspace_image(workspace_image).map_err(|error| {
            FirecrackerBootSmokeError::new(
                "prepare_workspace_image",
                format!("{}: {error}", workspace_image.display()),
            )
        })?;
    }
    firecracker_put_json(
        &artifacts.api_socket,
        "/boot-source",
        json!({
            "kernel_image_path": bundle.kernel_image.display().to_string(),
            "boot_args": attachment.boot_args,
        }),
        deadline,
    )?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/drives/rootfs",
        attachment.rootfs_drive,
        deadline,
    )?;
    if let Some(workspace_drive) = attachment.workspace_drive {
        firecracker_put_json(
            &artifacts.api_socket,
            "/drives/workspace",
            workspace_drive,
            deadline,
        )?;
    }
    firecracker_put_json(
        &artifacts.api_socket,
        "/vsock",
        firecracker_guest_rpc_vsock_config(artifacts),
        deadline,
    )?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/actions",
        json!({
            "action_type": "InstanceStart",
        }),
        deadline,
    )?;
    wait_for_serial_boot_evidence(artifacts, deadline, child)
}

/// The filesystem policy the Firecracker backend enforces for every microVM.
///
/// This is the runtime contract declared as
/// `read_only_rootfs_with_prepared_workspace` in `firecracker_prepare_plan`:
/// the shared rootfs image is immutable and each VM gets a private writable
/// workspace. Mirrors `IsolationFilesystemPolicy::default()` from
/// ferrogate-runtime so the drive layout and the declared policy cannot drift
/// apart silently.
fn firecracker_filesystem_policy() -> IsolationFilesystemPolicy {
    IsolationFilesystemPolicy::default()
}

/// Sparse size of the per-VM writable workspace image. Sized conservatively;
/// real-host validation (#227) may tune this or make it envelope-driven.
const FIRECRACKER_WORKSPACE_IMAGE_SIZE_BYTES: u64 = 512 * 1024 * 1024;

/// Rootfs/workspace drive layout for one microVM, derived from the isolation
/// filesystem policy.
///
/// Chosen design (#227): attach the SHARED host rootfs image read-only and
/// give each microVM a per-VM writable workspace drive (`/dev/vdb`) backed by
/// a file inside the VM's private run dir — rather than a per-VM copy of the
/// whole rootfs. This matches the declared
/// `read_only_rootfs_with_prepared_workspace` policy, costs O(workspace)
/// instead of O(rootfs) disk per VM, and guarantees no two VMs ever open the
/// same backing file writable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirecrackerRootfsAttachment {
    /// Kernel boot args; `root=/dev/vda ro` when the policy demands a
    /// read-only rootfs, `rw` otherwise.
    boot_args: String,
    /// Firecracker `/drives/rootfs` body; `is_read_only` mirrors
    /// `IsolationFilesystemPolicy.read_only_rootfs`.
    rootfs_drive: serde_json::Value,
    /// Firecracker `/drives/workspace` body when the policy grants a writable
    /// workspace.
    workspace_drive: Option<serde_json::Value>,
    /// Host path of the per-VM writable workspace backing file (inside the
    /// VM's private run dir; removed on teardown).
    workspace_image: Option<PathBuf>,
}

fn plan_firecracker_rootfs_attachment(
    rootfs_image: &Path,
    artifacts: &FirecrackerMicroVmArtifacts,
    policy: &IsolationFilesystemPolicy,
) -> FirecrackerRootfsAttachment {
    let root_mode = if policy.read_only_rootfs { "ro" } else { "rw" };
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda {root_mode} random.trust_cpu=on"
    );
    let rootfs_drive = json!({
        "drive_id": "rootfs",
        "path_on_host": rootfs_image.display().to_string(),
        "is_root_device": true,
        "is_read_only": policy.read_only_rootfs,
    });
    let workspace_image = policy
        .writable_workspace
        .then(|| artifacts.workspace_image_path());
    let workspace_drive = workspace_image.as_ref().map(|path| {
        json!({
            "drive_id": "workspace",
            "path_on_host": path.display().to_string(),
            "is_root_device": false,
            "is_read_only": false,
        })
    });
    FirecrackerRootfsAttachment {
        boot_args,
        rootfs_drive,
        workspace_drive,
        workspace_image,
    }
}

/// Creates the per-VM writable workspace backing file (sparse) and formats it
/// as ext4 when `mkfs.ext4` is available. The format step is best-effort so
/// hermetic sandbox tests do not depend on host tooling; a real Firecracker
/// host (where boot validation for #227 happens) is expected to have
/// `mkfs.ext4`, and the guest mount will fail loudly there if formatting was
/// skipped.
fn prepare_firecracker_workspace_image(path: &Path) -> std::io::Result<()> {
    let file = File::create(path)?;
    file.set_len(FIRECRACKER_WORKSPACE_IMAGE_SIZE_BYTES)?;
    drop(file);
    let _ = Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

fn firecracker_guest_rpc_vsock_config(
    artifacts: &FirecrackerMicroVmArtifacts,
) -> serde_json::Value {
    json!({
        "vsock_id": "guest-rpc",
        "guest_cid": 3,
        "uds_path": artifacts.guest_rpc_socket.display().to_string(),
    })
}

fn wait_for_api_socket(
    socket_path: &Path,
    deadline: Instant,
    child: &mut Child,
) -> Result<(), FirecrackerBootSmokeError> {
    while Instant::now() < deadline {
        if socket_path.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            FirecrackerBootSmokeError::new("poll_firecracker", error.to_string())
        })? {
            return Err(FirecrackerBootSmokeError::new(
                "wait_api_socket",
                format!("Firecracker exited before API socket was ready: {status}"),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(FirecrackerBootSmokeError::new(
        "wait_api_socket",
        format!("timed out waiting for {}", socket_path.display()),
    ))
}

fn firecracker_put_json(
    socket_path: &Path,
    path: &str,
    body: serde_json::Value,
    deadline: Instant,
) -> Result<(), FirecrackerBootSmokeError> {
    firecracker_json("PUT", socket_path, path, body, deadline)
}

fn firecracker_put_json_with_timeout(
    socket_path: &Path,
    path: &str,
    body: serde_json::Value,
    timeout: Duration,
) -> Result<(), FirecrackerBootSmokeError> {
    firecracker_json("PUT", socket_path, path, body, Instant::now() + timeout)
}

fn firecracker_patch_json(
    socket_path: &Path,
    path: &str,
    body: serde_json::Value,
    timeout: Duration,
) -> Result<(), FirecrackerBootSmokeError> {
    firecracker_json("PATCH", socket_path, path, body, Instant::now() + timeout)
}

fn firecracker_json(
    method: &str,
    socket_path: &Path,
    path: &str,
    body: serde_json::Value,
    deadline: Instant,
) -> Result<(), FirecrackerBootSmokeError> {
    if Instant::now() >= deadline {
        return Err(FirecrackerBootSmokeError::new(
            "firecracker_api",
            format!("deadline exceeded before {method} {path}"),
        ));
    }
    let body = body.to_string();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        FirecrackerBootSmokeError::new(
            "firecracker_api_connect",
            format!("{}: {error}", socket_path.display()),
        )
    })?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(1));
    stream
        .set_read_timeout(Some(remaining.min(Duration::from_secs(2))))
        .map_err(|error| {
            FirecrackerBootSmokeError::new("firecracker_api_timeout", error.to_string())
        })?;
    stream
        .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
        .map_err(|error| {
            FirecrackerBootSmokeError::new("firecracker_api_timeout", error.to_string())
        })?;
    stream.write_all(request.as_bytes()).map_err(|error| {
        FirecrackerBootSmokeError::new("firecracker_api_write", format!("{method} {path}: {error}"))
    })?;
    let response = read_firecracker_http_response(&mut stream, method, path)?;
    let status = response.lines().next().unwrap_or_default();
    if status.contains(" 204 ") || status.ends_with(" 204 No Content") {
        return Ok(());
    }
    Err(FirecrackerBootSmokeError::new(
        "firecracker_api_status",
        format!(
            "{method} {path} failed: {}",
            first_non_empty_line(&response)
        ),
    ))
}

fn read_firecracker_http_response(
    stream: &mut UnixStream,
    method: &str,
    path: &str,
) -> Result<String, FirecrackerBootSmokeError> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !response.is_empty() {
                    break;
                }
                return Err(FirecrackerBootSmokeError::new(
                    "firecracker_api_read",
                    format!("{method} {path}: {error}"),
                ));
            }
            Err(error) => {
                return Err(FirecrackerBootSmokeError::new(
                    "firecracker_api_read",
                    format!("{method} {path}: {error}"),
                ));
            }
        }
    }
    Ok(String::from_utf8_lossy(&response).to_string())
}

fn wait_for_serial_boot_evidence(
    artifacts: &FirecrackerMicroVmArtifacts,
    deadline: Instant,
    child: &mut Child,
) -> Result<FirecrackerBootEvidence, FirecrackerBootSmokeError> {
    while Instant::now() < deadline {
        if let Some(evidence) = read_boot_evidence(artifacts) {
            return Ok(evidence);
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            FirecrackerBootSmokeError::new("poll_firecracker", error.to_string())
        })? {
            let evidence = partial_boot_evidence(artifacts);
            return Err(FirecrackerBootSmokeError::with_evidence(
                "wait_serial_boot_evidence",
                format!("Firecracker exited before serial boot evidence was complete: {status}"),
                evidence,
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    let evidence = partial_boot_evidence(artifacts);
    Err(FirecrackerBootSmokeError::with_evidence(
        "wait_serial_boot_evidence",
        "timed out waiting for guest serial boot markers",
        evidence,
    ))
}

fn read_boot_evidence(artifacts: &FirecrackerMicroVmArtifacts) -> Option<FirecrackerBootEvidence> {
    let serial = fs::read_to_string(&artifacts.serial_output).ok()?;
    let markers = serial_boot_markers(&serial);
    if !serial_has_microvm_userspace_evidence(&markers) {
        return None;
    }
    Some(FirecrackerBootEvidence {
        serial_boot_markers: markers,
        serial_excerpt: excerpt(&serial, 16),
        firecracker_log_excerpt: excerpt(
            &fs::read_to_string(&artifacts.firecracker_log).unwrap_or_default(),
            12,
        ),
    })
}

fn partial_boot_evidence(artifacts: &FirecrackerMicroVmArtifacts) -> FirecrackerBootEvidence {
    let serial = fs::read_to_string(&artifacts.serial_output).unwrap_or_default();
    FirecrackerBootEvidence {
        serial_boot_markers: serial_boot_markers(&serial),
        serial_excerpt: excerpt(&serial, 16),
        firecracker_log_excerpt: excerpt(
            &fs::read_to_string(&artifacts.firecracker_log).unwrap_or_default(),
            12,
        ),
    }
}

fn serial_boot_markers(serial: &str) -> Vec<&'static str> {
    let mut markers = Vec::new();
    if serial.contains("Linux version ") {
        markers.push("linux_version");
    }
    if serial.contains("Hypervisor detected: KVM")
        || serial.contains("Booting paravirtualized kernel on KVM")
    {
        markers.push("kvm_hypervisor");
    }
    if serial.contains("FIRECK") || serial.contains("Firecracker") {
        markers.push("firecracker_platform");
    }
    if serial.contains("console [ttyS0] enabled") {
        markers.push("serial_console");
    }
    if serial.contains("VFS: Mounted root ") {
        markers.push("rootfs_mounted");
        // #227: prove the guest kernel honored `root=/dev/vda ro` — the kernel
        // annotates the mount line "readonly" (older kernels: "read-only") when
        // the root device is mounted read-only. Line-scoped so an unrelated
        // "readonly" elsewhere in the log cannot spoof this evidence.
        let read_only_root = serial.lines().any(|line| {
            line.contains("VFS: Mounted root ")
                && (line.contains("readonly") || line.contains("read-only"))
        });
        if read_only_root {
            markers.push("rootfs_mounted_readonly");
        }
    }
    if serial.contains(" as init process") {
        markers.push("init_started");
    }
    if serial.contains("systemd[1]:") {
        markers.push("systemd_started");
    }
    if serial.contains("Reached target")
        && (serial.contains("multi-user.target") || serial.contains("basic.target"))
    {
        markers.push("userspace_target_reached");
    }
    if serial.contains(" login:") || serial.contains(" automatic login") {
        markers.push("login_prompt");
    }
    if serial.contains("root@") && serial.contains(":~#") {
        markers.push("root_shell_prompt");
    }
    markers
}

fn serial_has_microvm_userspace_evidence(markers: &[&str]) -> bool {
    markers.contains(&"linux_version")
        && markers.contains(&"kvm_hypervisor")
        && markers.contains(&"rootfs_mounted")
        && markers.contains(&"init_started")
        && (markers.contains(&"systemd_started")
            || markers.contains(&"userspace_target_reached")
            || markers.contains(&"login_prompt")
            || markers.contains(&"root_shell_prompt"))
}

fn excerpt(text: &str, max_lines: usize) -> String {
    text.lines().take(max_lines).collect::<Vec<_>>().join("\n")
}

fn first_non_empty_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("<empty response>")
        .to_string()
}

struct FirecrackerChildStopReport {
    was_running: bool,
    outcome: FirecrackerProcessStopOutcome,
}

fn stop_firecracker_child(child: &mut Child) -> FirecrackerChildStopReport {
    match child.try_wait() {
        Ok(Some(status)) => FirecrackerChildStopReport {
            was_running: false,
            outcome: FirecrackerProcessStopOutcome::AlreadyExited(status.to_string()),
        },
        Ok(None) => match child.kill() {
            Ok(()) => match child.wait() {
                Ok(status) => FirecrackerChildStopReport {
                    was_running: true,
                    outcome: FirecrackerProcessStopOutcome::Killed(status.to_string()),
                },
                Err(error) => FirecrackerChildStopReport {
                    was_running: true,
                    outcome: FirecrackerProcessStopOutcome::WaitFailed(error.to_string()),
                },
            },
            Err(error) => FirecrackerChildStopReport {
                was_running: true,
                outcome: FirecrackerProcessStopOutcome::KillFailed(error.to_string()),
            },
        },
        Err(error) => FirecrackerChildStopReport {
            was_running: false,
            outcome: FirecrackerProcessStopOutcome::WaitFailed(error.to_string()),
        },
    }
}

fn remove_firecracker_host_file(path: &Path) -> Result<bool, String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(test)]
#[path = "backends_test.rs"]
mod tests;
