// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
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
use ferrogate_runtime::{AgentWorkerFrameworkArtifactResult, AgentWorkerIsolationBackendReport};
use serde::Serialize;
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
        reason: Some(reason),
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

    pub(crate) fn stop(&mut self) -> bool {
        let was_running = self.is_running();
        stop_firecracker_child(&mut self.child);
        let _ = fs::remove_file(&self.artifacts.api_socket);
        was_running
    }
}

impl Drop for FirecrackerMicroVm {
    fn drop(&mut self) {
        let _ = self.stop();
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
    if Instant::now() >= deadline {
        return Err(FirecrackerBootSmokeError::new(
            "firecracker_api",
            format!("deadline exceeded before PUT {path}"),
        ));
    }
    let body = body.to_string();
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        FirecrackerBootSmokeError::new("firecracker_api_write", format!("PUT {path}: {error}"))
    })?;
    let response = read_firecracker_http_response(&mut stream, path)?;
    let status = response.lines().next().unwrap_or_default();
    if status.contains(" 204 ") || status.ends_with(" 204 No Content") {
        return Ok(());
    }
    Err(FirecrackerBootSmokeError::new(
        "firecracker_api_status",
        format!("PUT {path} failed: {}", first_non_empty_line(&response)),
    ))
}

fn read_firecracker_http_response(
    stream: &mut UnixStream,
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
                    format!("PUT {path}: {error}"),
                ));
            }
            Err(error) => {
                return Err(FirecrackerBootSmokeError::new(
                    "firecracker_api_read",
                    format!("PUT {path}: {error}"),
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

fn stop_firecracker_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
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
    }
}
