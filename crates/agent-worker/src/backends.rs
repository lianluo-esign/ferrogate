// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Result};
use ferrogate_runtime::{
    AgentWorkerFrameworkArtifactResult, AgentWorkerFrameworkEventResult,
    AgentWorkerIsolationBackendReport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub(crate) fn isolation_backends() -> Vec<AgentWorkerIsolationBackendReport> {
    vec![probed_firecracker_backend()]
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
    }
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

fn probed_firecracker_backend() -> AgentWorkerIsolationBackendReport {
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

    if missing.is_empty() {
        AgentWorkerIsolationBackendReport {
            backend_name: "firecracker".to_string(),
            backend_version: "external_bundle".to_string(),
            kind: "firecracker_micro_vm".to_string(),
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            ready: true,
            readiness_reason: Some(
                "Firecracker binary, jailer binary, kernel image, and rootfs image are configured"
                    .to_string(),
            ),
        }
    } else {
        AgentWorkerIsolationBackendReport {
            backend_name: "firecracker".to_string(),
            backend_version: "unknown".to_string(),
            kind: "firecracker_micro_vm".to_string(),
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            ready: false,
            readiness_reason: Some(missing.join("; ")),
        }
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
    guest_agent_version: Option<String>,
}

impl FirecrackerGuestAgentHandshake {
    const PROTOCOL_VERSION: &'static str = "ferrogate.agent-worker.guest.v1";

    fn parse(stdout: &[u8]) -> Result<Self, String> {
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
        Ok(handshake)
    }

    pub(crate) fn rpc_channel(&self) -> &str {
        &self.rpc_channel
    }

    pub(crate) fn guest_agent_version(&self) -> Option<&str> {
        self.guest_agent_version.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirecrackerGuestAgentLaunchAttemptError {
    outcome: &'static str,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}

impl FirecrackerGuestRpcStartRequest {
    pub(crate) fn summary(&self) -> String {
        format!(
            "guest_rpc_start_request(protocol_version={}, action={}, worker_id={}, adapter={}, launch_profile={}, isolation_backend={}, isolation_instance_id={}, rpc_channel={}, required_gateway_capabilities={}, network_policy={}, filesystem_policy={}, proves_microvm_boot={}, proves_handler_execution={})",
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
            self.proves_handler_execution
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FirecrackerGuestAdapterLaunchProfile {
    framework: &'static str,
    entrypoint: &'static str,
    event_stream: &'static str,
    external_action_mode: &'static str,
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
    fn new(outcome: &'static str, reason: String) -> Self {
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
            framework: "codex",
            entrypoint: "codex_exec",
            event_stream: "normalized_jsonl",
            external_action_mode: "gateway_mediated_cli_filesystem_tools",
        },
        "claude-code" => FirecrackerGuestAdapterLaunchProfile {
            framework: "claude_code",
            entrypoint: "claude_code_non_interactive",
            event_stream: "normalized_jsonl",
            external_action_mode: "gateway_mediated_cli_filesystem_tools",
        },
        "hermes" => FirecrackerGuestAdapterLaunchProfile {
            framework: "hermes",
            entrypoint: "hermes_oneshot",
            event_stream: "normalized_jsonl",
            external_action_mode: "gateway_mediated_memory_subagents",
        },
        _ => FirecrackerGuestAdapterLaunchProfile {
            framework: "native_harness",
            entrypoint: "native_harness_task",
            event_stream: "normalized_jsonl",
            external_action_mode: "gateway_mediated_tools",
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
        let api_socket_removed = remove_firecracker_api_socket(&self.artifacts.api_socket);
        FirecrackerStopReport {
            was_running: process.was_running,
            process_outcome: process.outcome,
            api_socket_removed,
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
}

impl FirecrackerStopReport {
    pub(crate) fn cleanup_succeeded(&self) -> bool {
        self.api_socket_removed.is_ok()
    }

    pub(crate) fn summary(&self) -> String {
        let socket = match &self.api_socket_removed {
            Ok(true) => "api_socket_removed=true".to_string(),
            Ok(false) => "api_socket_removed=false".to_string(),
            Err(error) => format!("api_socket_remove_error={error}"),
        };
        format!(
            "was_running={}; process_outcome={}; {socket}",
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
        let run_dir = env::temp_dir().join(format!(
            "ferrogate-agent-worker-firecracker-microvm-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        ));
        fs::create_dir_all(&run_dir)?;
        Ok(Self {
            run_dir: run_dir.clone(),
            api_socket: run_dir.join("firecracker.sock"),
            firecracker_log: run_dir.join("firecracker.log"),
            serial_output: run_dir.join("serial.log"),
            stdout: run_dir.join("firecracker.stdout"),
            stderr: run_dir.join("firecracker.stderr"),
        })
    }

    fn to_report_paths(&self) -> FirecrackerBootSmokeArtifactReport {
        FirecrackerBootSmokeArtifactReport {
            api_socket: Some(self.api_socket.display().to_string()),
            firecracker_log: Some(self.firecracker_log.display().to_string()),
            serial_output: Some(self.serial_output.display().to_string()),
            stdout: Some(self.stdout.display().to_string()),
            stderr: Some(self.stderr.display().to_string()),
        }
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
    firecracker_put_json(
        &artifacts.api_socket,
        "/boot-source",
        json!({
            "kernel_image_path": bundle.kernel_image.display().to_string(),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw random.trust_cpu=on",
        }),
        deadline,
    )?;
    firecracker_put_json(
        &artifacts.api_socket,
        "/drives/rootfs",
        json!({
            "drive_id": "rootfs",
            "path_on_host": bundle.rootfs_image.display().to_string(),
            "is_root_device": true,
            "is_read_only": false,
        }),
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

fn remove_firecracker_api_socket(socket_path: &Path) -> Result<bool, String> {
    match fs::remove_file(socket_path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", socket_path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::lock_firecracker_env;

    #[test]
    fn backend_registry_reports_firecracker_ready_only_from_configured_bundle() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        let jailer_path = temp.path().join("jailer");
        let kernel_path = temp.path().join("vmlinux");
        let rootfs_path = temp.path().join("rootfs.ext4");
        write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
        write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
        std::fs::write(&kernel_path, b"not executed").unwrap();
        std::fs::write(&rootfs_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

        let backends = isolation_backends();

        clear_firecracker_env();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].backend_name, "firecracker");
        assert_eq!(backends[0].kind, "firecracker_micro_vm");
        assert_eq!(backends[0].host_lifecycle_owner, "agent-worker");
        assert!(!backends[0].gateway_controls_backend);
        assert!(backends[0].ready);
        assert_eq!(backends[0].backend_version, "external_bundle");
        assert!(backends[0]
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("kernel image")));

        env::set_var(
            "AGENT_WORKER_FIRECRACKER_BIN",
            temp.path().join("missing-firecracker"),
        );
        env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
        let missing = isolation_backends();
        clear_firecracker_env();
        assert!(!missing[0].ready);
        assert!(missing[0]
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not point to a file")));
    }

    #[test]
    fn backend_registry_requires_firecracker_kernel_and_rootfs() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
        env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
        env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");

        let backends = isolation_backends();

        clear_firecracker_env();
        assert!(!backends[0].ready);
        let reason = backends[0].readiness_reason.as_deref().unwrap();
        assert!(reason.contains("Firecracker kernel image was not configured"));
        assert!(reason.contains("Firecracker rootfs image was not configured"));
    }

    #[test]
    fn firecracker_prepare_plan_is_worker_owned_and_does_not_boot_microvm() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        let jailer_path = temp.path().join("jailer");
        let kernel_path = temp.path().join("vmlinux");
        let rootfs_path = temp.path().join("rootfs.ext4");
        write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
        write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
        std::fs::write(&kernel_path, b"not executed").unwrap();
        std::fs::write(&rootfs_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

        let plan = firecracker_prepare_plan().unwrap();

        clear_firecracker_env();
        assert_eq!(plan.firecracker_bin, firecracker_path);
        assert_eq!(plan.jailer_bin, jailer_path);
        assert_eq!(plan.kernel_image, kernel_path);
        assert_eq!(plan.rootfs_image, rootfs_path);
        assert_eq!(plan.planned_steps[0], "prepare_runtime_bundle");
        assert!(plan.planned_steps.contains(&"start_microvm"));
        assert_eq!(
            plan.network_policy,
            "no_direct_public_egress_without_gateway_capability"
        );
        assert_eq!(
            plan.filesystem_policy,
            "read_only_rootfs_with_prepared_workspace"
        );
    }

    #[test]
    fn firecracker_prepare_plan_fails_closed_without_bundle() {
        let _env_lock = lock_firecracker_env();
        clear_firecracker_env();

        let error = firecracker_prepare_plan().unwrap_err().to_string();

        assert!(error.contains("Firecracker binary path was not configured"));
    }

    #[test]
    fn firecracker_host_preflight_reports_jailer_kvm_and_does_not_boot_microvm() {
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
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE", &kvm_path);

        let preflight = firecracker_host_preflight();

        clear_firecracker_env();
        assert!(!preflight.ready());
        assert!(!preflight.proves_microvm_boot);
        assert!(preflight
            .failure_summary()
            .contains("AGENT_WORKER_FIRECRACKER_BIN is not executable"));
        assert!(preflight
            .failure_summary()
            .contains("AGENT_WORKER_FIRECRACKER_JAILER is not executable"));
        assert!(preflight
            .failure_summary()
            .contains("not a character device"));
    }

    #[test]
    fn firecracker_host_preflight_reports_binary_versions_and_bundle_sizes() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        let jailer_path = temp.path().join("jailer");
        let kernel_path = temp.path().join("vmlinux");
        let rootfs_path = temp.path().join("rootfs.ext4");
        write_executable_version_script(&firecracker_path, "Firecracker v.test").unwrap();
        write_executable_version_script(&jailer_path, "Jailer v.test").unwrap();
        std::fs::write(&kernel_path, b"kernel-bytes").unwrap();
        std::fs::write(&rootfs_path, b"rootfs-bytes").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_JAILER", &jailer_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);
        env::set_var(
            "AGENT_WORKER_FIRECRACKER_KVM_DEVICE",
            temp.path().join("missing-kvm"),
        );

        let preflight = firecracker_host_preflight();

        clear_firecracker_env();
        assert_eq!(
            preflight.bundle.firecracker_bin.version_output.as_deref(),
            Some("Firecracker v.test")
        );
        assert_eq!(
            preflight.bundle.jailer_bin.version_output.as_deref(),
            Some("Jailer v.test")
        );
        assert_eq!(preflight.bundle.kernel_image.size_bytes, Some(12));
        assert_eq!(preflight.bundle.rootfs_image.size_bytes, Some(12));
        assert!(!preflight.proves_microvm_boot);
        assert!(preflight.success_summary().contains("Firecracker v.test"));
        assert!(preflight.success_summary().contains("Jailer v.test"));
        assert!(preflight.success_summary().contains("kernel_size_bytes=12"));
        assert!(preflight.success_summary().contains("rootfs_size_bytes=12"));
        assert!(preflight
            .success_summary()
            .contains("microVM boot is still not proven"));
    }

    #[test]
    fn firecracker_guest_agent_preflight_fails_closed_without_channel_contract() {
        let _env_lock = lock_firecracker_env();
        clear_firecracker_env();

        let preflight = firecracker_guest_agent_preflight();

        assert!(!preflight.ready());
        assert!(!preflight.proves_microvm_boot);
        assert!(!preflight.proves_handler_execution);
        assert_eq!(preflight.channel_kind, "guest_agent_command");
        assert!(preflight
            .failure_summary()
            .contains("Firecracker guest agent command path was not configured"));
        assert!(preflight
            .failure_summary()
            .contains("Firecracker guest workspace was not configured"));
        assert!(preflight
            .failure_summary()
            .contains("Firecracker guest gateway authorizer endpoint was not configured"));
    }

    #[test]
    fn firecracker_guest_agent_preflight_reports_ready_without_claiming_execution() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let guest_agent = temp.path().join("ferrogate-guest-agent");
        let workspace = temp.path().join("workspace");
        write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
        std::fs::create_dir(&workspace).unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
        env::set_var(
            "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
            "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
        );

        let preflight = firecracker_guest_agent_preflight();

        clear_firecracker_env();
        assert!(preflight.ready());
        assert!(!preflight.proves_microvm_boot);
        assert!(!preflight.proves_handler_execution);
        assert_eq!(
            preflight.command_channel.path.as_deref(),
            Some(guest_agent.to_str().unwrap())
        );
        assert_eq!(
            preflight.workspace.path.as_deref(),
            Some(workspace.to_str().unwrap())
        );
        assert_eq!(preflight.workspace.writable, Some(true));
        assert!(preflight
            .failure_summary()
            .contains("handler execution inside the microVM is still not proven"));
    }

    #[test]
    fn firecracker_guest_agent_preflight_requires_workspace_directory() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let guest_agent = temp.path().join("ferrogate-guest-agent");
        let workspace_file = temp.path().join("workspace-file");
        write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
        std::fs::write(&workspace_file, b"not a directory").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace_file);
        env::set_var(
            "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
            "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
        );

        let preflight = firecracker_guest_agent_preflight();

        clear_firecracker_env();
        assert!(!preflight.ready());
        assert_eq!(preflight.workspace.writable, None);
        assert!(preflight
            .failure_summary()
            .contains("does not point to a directory"));
        assert!(!preflight.proves_handler_execution);
    }

    #[test]
    fn firecracker_guest_launch_plan_fails_closed_without_guest_channel() {
        let _env_lock = lock_firecracker_env();
        clear_firecracker_env();

        let plan = firecracker_guest_launch_plan(Some("codex"));

        assert!(!plan.ready);
        assert_eq!(plan.adapter, "codex");
        assert_eq!(plan.host_lifecycle_owner, "agent-worker");
        assert!(!plan.gateway_controls_firecracker);
        assert!(!plan.proves_microvm_boot);
        assert!(!plan.proves_handler_execution);
        assert_eq!(
            plan.implementation_status,
            "guest_handler_rpc_not_implemented"
        );
        assert!(plan.required_gateway_capabilities.contains(&"filesystem"));
        assert!(plan
            .guest_agent
            .failure_summary()
            .contains("Firecracker guest agent command path was not configured"));
    }

    #[test]
    fn firecracker_guest_launch_plan_records_adapter_capabilities_without_claiming_execution() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let guest_agent = temp.path().join("ferrogate-guest-agent");
        let workspace = temp.path().join("workspace");
        write_executable_version_script(&guest_agent, "ferrogate guest agent v.test").unwrap();
        std::fs::create_dir(&workspace).unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT", &guest_agent);
        env::set_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE", &workspace);
        env::set_var(
            "AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT",
            "https://gateway.example.test/v1/agent-worker/external-actions/authorize",
        );

        let codex = firecracker_guest_launch_plan(Some("codex"));
        let hermes = firecracker_guest_launch_plan(Some("hermes"));

        clear_firecracker_env();
        assert!(codex.ready);
        assert_eq!(codex.adapter, "codex");
        assert!(codex.planned_steps.contains(&"invoke_guest_agent_command"));
        assert!(codex
            .planned_steps
            .contains(&"start_framework_handler_inside_microvm"));
        assert_eq!(
            codex.guest_network_policy,
            "gateway_control_channel_only_no_direct_public_egress"
        );
        assert!(codex.required_gateway_capabilities.contains(&"cli"));
        assert!(codex.required_gateway_capabilities.contains(&"checkpoint"));
        assert!(!codex.proves_microvm_boot);
        assert!(!codex.proves_handler_execution);
        assert_eq!(hermes.adapter, "hermes");
        assert!(hermes
            .required_gateway_capabilities
            .contains(&"memory.read"));
        assert!(hermes.required_gateway_capabilities.contains(&"subagents"));
    }

    #[test]
    fn adapter_launch_profiles_are_framework_specific_without_claiming_execution() {
        let codex = adapter_launch_profile("codex");
        let claude = adapter_launch_profile("claude-code");
        let hermes = adapter_launch_profile("hermes");
        let native = adapter_launch_profile("native-harness");

        assert_eq!(codex.framework, "codex");
        assert_eq!(codex.entrypoint, "codex_exec");
        assert_eq!(
            codex.external_action_mode,
            "gateway_mediated_cli_filesystem_tools"
        );
        assert_eq!(claude.framework, "claude_code");
        assert_eq!(claude.entrypoint, "claude_code_non_interactive");
        assert_eq!(hermes.framework, "hermes");
        assert_eq!(hermes.entrypoint, "hermes_oneshot");
        assert_eq!(
            hermes.external_action_mode,
            "gateway_mediated_memory_subagents"
        );
        assert_eq!(native.framework, "native_harness");
        assert_eq!(native.event_stream, "normalized_jsonl");
    }

    #[test]
    fn firecracker_boot_smoke_fails_closed_when_preflight_fails() {
        let _env_lock = lock_firecracker_env();
        clear_firecracker_env();

        let report = firecracker_boot_smoke(FirecrackerBootSmokeOptions {
            timeout: Duration::from_millis(1),
            vcpu_count: 1,
            mem_size_mib: 256,
        });

        assert!(!report.ready);
        assert!(!report.boot_observed);
        assert!(!report.proves_microvm_boot);
        assert_eq!(report.failure_stage.as_deref(), Some("preflight_failed"));
        assert!(report
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Firecracker binary path was not configured")));
    }

    #[test]
    fn firecracker_api_socket_cleanup_reports_host_resource_failure() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("firecracker.sock");
        std::fs::create_dir(&socket_path).unwrap();

        let result = remove_firecracker_api_socket(&socket_path);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains(socket_path.to_str().unwrap()));
    }

    #[test]
    fn firecracker_snapshot_report_projects_snapshot_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = temp.path().join("firecracker.snapshot");
        let memory_path = temp.path().join("firecracker.mem");
        std::fs::write(&snapshot_path, b"snapshot-state").unwrap();
        std::fs::write(&memory_path, b"snapshot-memory").unwrap();
        let report = FirecrackerSnapshotReport {
            outcome: "snapshot_created".to_string(),
            snapshot_path,
            memory_path,
            snapshot_bytes: 14,
            memory_bytes: 15,
            steps: vec!["paused", "snapshot_created", "resumed"],
            failure_stage: None,
            failure_reason: None,
        };

        let artifacts = report.artifact_results("microvm-1");
        let events = report.artifact_events("session-1", "run-1", "microvm-1");

        assert!(report.succeeded());
        assert_eq!(artifacts.len(), 2);
        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_id == "microvm-1-snapshot-state"
                && artifact.name == "firecracker.snapshot"
                && artifact.media_type == "application/octet-stream"
        }));
        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_id == "microvm-1-snapshot-memory"
                && artifact.name == "firecracker.mem"
                && artifact.media_type == "application/octet-stream"
        }));
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| {
            event.kind == "artifact.created"
                && event
                    .metadata
                    .get("isolation_instance_id")
                    .map(String::as_str)
                    == Some("microvm-1")
        }));
    }

    #[test]
    fn serial_boot_markers_require_real_guest_boot_evidence() {
        let markers = serial_boot_markers(
            "[    0.000000] Linux version 6.1.174\n\
             [    0.000000] Hypervisor detected: KVM\n\
             [    0.000113] ACPI: RSDP 0x00000000000E0000 000024 (v02 FIRECK)\n\
             [    0.054831] printk: console [ttyS0] enabled\n\
             [    0.673622] VFS: Mounted root (ext4 filesystem) on device 254:0.\n\
             [    0.676346] Run /sbin/init as init process\n\
             [    0.692980] systemd[1]: systemd 255.4 running in system mode\n\
             [    1.000000] Reached target multi-user.target - Multi-User System.\n\
             ubuntu-fc-uvm login: root (automatic login)\n\
             root@ubuntu-fc-uvm:~# \n",
        );

        assert_eq!(
            markers,
            vec![
                "linux_version",
                "kvm_hypervisor",
                "firecracker_platform",
                "serial_console",
                "rootfs_mounted",
                "init_started",
                "systemd_started",
                "userspace_target_reached",
                "login_prompt",
                "root_shell_prompt"
            ]
        );
        assert!(serial_has_microvm_userspace_evidence(&markers));
        let process_only_markers = serial_boot_markers("Firecracker process started");
        assert_eq!(process_only_markers, vec!["firecracker_platform"]);
        assert!(!process_only_markers.contains(&"linux_version"));
        assert!(!process_only_markers.contains(&"kvm_hypervisor"));
        assert!(!serial_has_microvm_userspace_evidence(
            &process_only_markers
        ));
        assert!(!serial_has_microvm_userspace_evidence(&[
            "linux_version",
            "kvm_hypervisor",
            "firecracker_platform",
            "serial_console"
        ]));
    }

    fn write_executable_version_script(path: &Path, version: &str) -> std::io::Result<()> {
        std::fs::write(
            path,
            format!("#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then echo '{version}'; exit 0; fi\nexit 0\n"),
        )?;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)
    }

    fn clear_firecracker_env() {
        env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
        env::remove_var("AGENT_WORKER_FIRECRACKER_JAILER");
        env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
        env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
        env::remove_var("AGENT_WORKER_FIRECRACKER_KVM_DEVICE");
        env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_AGENT");
        env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_WORKSPACE");
        env::remove_var("AGENT_WORKER_FIRECRACKER_GUEST_GATEWAY_ENDPOINT");
    }
}
