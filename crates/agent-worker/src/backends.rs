// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use ferrogate_runtime::AgentWorkerIsolationBackendReport;
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

fn probed_firecracker_backend() -> AgentWorkerIsolationBackendReport {
    let requirements = [
        ("AGENT_WORKER_FIRECRACKER_BIN", "Firecracker binary path"),
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
            ready: true,
            readiness_reason: Some(
                "Firecracker binary, kernel image, and rootfs image are configured".to_string(),
            ),
        }
    } else {
        AgentWorkerIsolationBackendReport {
            backend_name: "firecracker".to_string(),
            backend_version: "unknown".to_string(),
            kind: "firecracker_micro_vm".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::lock_firecracker_env;

    #[test]
    fn backend_registry_reports_firecracker_ready_only_from_configured_bundle() {
        let _env_lock = lock_firecracker_env();
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        let kernel_path = temp.path().join("vmlinux");
        let rootfs_path = temp.path().join("rootfs.ext4");
        std::fs::write(&firecracker_path, b"not executed").unwrap();
        std::fs::write(&kernel_path, b"not executed").unwrap();
        std::fs::write(&rootfs_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

        let backends = isolation_backends();

        clear_firecracker_env();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].backend_name, "firecracker");
        assert_eq!(backends[0].kind, "firecracker_micro_vm");
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
        std::fs::write(&firecracker_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
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
        let kernel_path = temp.path().join("vmlinux");
        let rootfs_path = temp.path().join("rootfs.ext4");
        std::fs::write(&firecracker_path, b"not executed").unwrap();
        std::fs::write(&kernel_path, b"not executed").unwrap();
        std::fs::write(&rootfs_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_KERNEL", &kernel_path);
        env::set_var("AGENT_WORKER_FIRECRACKER_ROOTFS", &rootfs_path);

        let plan = firecracker_prepare_plan().unwrap();

        clear_firecracker_env();
        assert_eq!(plan.firecracker_bin, firecracker_path);
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

    fn clear_firecracker_env() {
        env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
        env::remove_var("AGENT_WORKER_FIRECRACKER_KERNEL");
        env::remove_var("AGENT_WORKER_FIRECRACKER_ROOTFS");
    }
}
