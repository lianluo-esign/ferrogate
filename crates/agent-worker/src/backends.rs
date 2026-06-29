// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    fs::{self, OpenOptions},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Result};
use ferrogate_runtime::AgentWorkerIsolationBackendReport;
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
