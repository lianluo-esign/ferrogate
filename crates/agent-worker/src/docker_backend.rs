// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Rootless/Docker isolation backend for the low-risk managed worker tier.
//!
//! This is a second, real implementation of the runtime
//! [`IsolationBackendLifecycle`] contract next to Firecracker. It proves the
//! backend interface is genuinely replaceable: the gateway/control plane does
//! not change, only the host-side `agent-worker` lifecycle implementation.
//!
//! Every lifecycle operation shells out to the `docker` CLI. Managed workers
//! run with `--network none` so they have no direct public network egress; the
//! gateway-mediated capability path (see #86) is the only sanctioned egress.
//! Resource limits and filesystem policy are enforced with explicit `docker`
//! flags, and cleanup force-removes the container so no host resource leaks.

use std::{
    env,
    process::{Command, Output},
};

use ferrogate_runtime::{
    CollectedIsolationArtifacts, CollectedIsolationLogs, IsolationArtifact,
    IsolationBackendCapabilities, IsolationBackendDescriptor, IsolationBackendKind,
    IsolationBackendLifecycle, IsolationCleanupOutcome, IsolationError, IsolationExecOutcome,
    IsolationExecRequest, IsolationFilesystemPolicy, IsolationLifecycleEvidence,
    IsolationNetworkPolicy, IsolationPolicy, IsolationPrepareRequest, IsolationPrepared,
    IsolationResourceLimits, IsolationResult, IsolationSnapshotOutcome, IsolationStarted,
    IsolationStopOutcome,
};

const DEFAULT_DOCKER_BIN: &str = "docker";
const DEFAULT_WORKER_IMAGE: &str = "alpine:latest";
const WORKSPACE_PATH: &str = "/workspace";

/// Name of the docker binary the backend should drive.
pub(crate) fn docker_bin() -> String {
    env::var("AGENT_WORKER_DOCKER_BIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_DOCKER_BIN.to_string())
}

/// The rootfs image the worker runs the agent workload inside.
fn worker_image() -> String {
    env::var("AGENT_WORKER_DOCKER_IMAGE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WORKER_IMAGE.to_string())
}

/// Whether an operator has explicitly enabled the low-risk Docker tier. Docker
/// is weaker isolation than Firecracker, so it must never be selected by
/// accident just because a daemon happens to be running — enabling it is an
/// explicit, opt-in operator decision. This keeps backend selection
/// fail-closed: absent the flag, Docker is registered but not selectable.
pub(crate) fn docker_backend_enabled() -> bool {
    env::var("AGENT_WORKER_ENABLE_DOCKER_BACKEND")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Probe whether a usable docker daemon is reachable. Used both by the backend
/// registry (readiness) and by the real-container integration test gate.
pub(crate) fn docker_backend_readiness() -> Result<String, String> {
    let bin = docker_bin();
    let output = Command::new(&bin)
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map_err(|error| format!("{bin} could not be executed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{bin} daemon is not reachable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        return Err(format!("{bin} did not report a server version"));
    }
    Ok(version)
}

/// Capabilities the Docker backend actually implements. Snapshot is a
/// filesystem commit, not a live memory checkpoint; secret injection is not
/// implemented here and is left to the gateway-mediated path, so it stays off.
pub(crate) fn docker_backend_capabilities() -> IsolationBackendCapabilities {
    IsolationBackendCapabilities {
        prepare: true,
        start: true,
        exec_or_attach: true,
        stop: true,
        snapshot_or_checkpoint: true,
        collect_logs: true,
        collect_artifacts: true,
        cleanup: true,
        governed_egress: true,
        secret_injection: false,
    }
}

pub(crate) fn docker_backend_descriptor(version: &str) -> IsolationBackendDescriptor {
    IsolationBackendDescriptor {
        backend_name: "rootless-docker".to_string(),
        backend_version: version.to_string(),
        kind: IsolationBackendKind::RootlessDocker,
        host_lifecycle_owner: "agent-worker".to_string(),
        gateway_controls_backend: false,
        capabilities: docker_backend_capabilities(),
    }
}

/// A worker-owned Docker isolation backend. Each instance drives one container
/// lifecycle through the `docker` CLI.
#[derive(Debug)]
pub(crate) struct DockerIsolationBackend {
    descriptor: IsolationBackendDescriptor,
    agent_worker_id: String,
    docker_bin: String,
    image: String,
    policy: Option<IsolationPolicy>,
    capability_envelope_id: Option<String>,
    container_id: Option<String>,
    instance_id: Option<String>,
}

impl DockerIsolationBackend {
    pub(crate) fn new(agent_worker_id: &str, version: &str) -> Self {
        Self {
            descriptor: docker_backend_descriptor(version),
            agent_worker_id: agent_worker_id.to_string(),
            docker_bin: docker_bin(),
            image: worker_image(),
            policy: None,
            capability_envelope_id: None,
            container_id: None,
            instance_id: None,
        }
    }

    /// The descriptor this backend was constructed from, for evidence/identity.
    pub(crate) fn backend_descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    /// The isolation instance id assigned at `start`, if the container is up.
    pub(crate) fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    /// Whether the backend currently owns a running container.
    pub(crate) fn is_running(&self) -> bool {
        self.container_id.is_some()
    }

    fn run_docker(&self, args: &[&str]) -> IsolationResult<Output> {
        Command::new(&self.docker_bin)
            .args(args)
            .output()
            .map_err(|error| {
                IsolationError::Backend(format!(
                    "{} {:?} failed to spawn: {error}",
                    self.docker_bin, args
                ))
            })
    }

    fn checked_docker(&self, args: &[&str]) -> IsolationResult<String> {
        let output = self.run_docker(args)?;
        if !output.status.success() {
            return Err(IsolationError::Backend(format!(
                "{} {:?} failed: {}",
                self.docker_bin,
                args,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn policy(&self) -> IsolationResult<&IsolationPolicy> {
        self.policy
            .as_ref()
            .ok_or_else(|| IsolationError::Backend("docker backend was not prepared".to_string()))
    }

    fn container_id(&self) -> IsolationResult<&str> {
        self.container_id.as_deref().ok_or_else(|| {
            IsolationError::Backend("docker backend has no running container".to_string())
        })
    }

    fn evidence(
        &self,
        instance_id: Option<&str>,
        outcome: &str,
    ) -> IsolationResult<IsolationLifecycleEvidence> {
        let policy = self.policy()?;
        Ok(IsolationLifecycleEvidence {
            backend_name: self.descriptor.backend_name.clone(),
            backend_version: self.descriptor.backend_version.clone(),
            agent_worker_id: self.agent_worker_id.clone(),
            isolation_instance_id: instance_id.map(ToOwned::to_owned),
            resource_limits: policy.resource_limits.clone(),
            network_policy: policy.network_policy.clone(),
            filesystem_policy: policy.filesystem_policy.clone(),
            capability_envelope_id: self.capability_envelope_id.clone().unwrap_or_default(),
            outcome: outcome.to_string(),
            failure_reason: None,
        })
    }

    /// Build the `docker run` argument vector that enforces the isolation
    /// policy: no direct network egress, cpu/memory limits, read-only rootfs,
    /// and a writable workspace tmpfs.
    fn run_args(
        &self,
        limits: &IsolationResourceLimits,
        network: &IsolationNetworkPolicy,
        filesystem: &IsolationFilesystemPolicy,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec!["run".to_string(), "-d".to_string()];

        // Managed workers get no direct public network. Gateway-mediated egress
        // (#86) is the only sanctioned path, so the container itself is sealed.
        if network.direct_public_egress {
            args.push("--network".to_string());
            args.push("bridge".to_string());
        } else {
            args.push("--network".to_string());
            args.push("none".to_string());
        }

        args.push("--cpus".to_string());
        args.push(limits.cpu_count.max(1).to_string());
        args.push("--memory".to_string());
        args.push(format!("{}m", limits.memory_mib.max(6)));
        args.push("--pids-limit".to_string());
        args.push("256".to_string());

        if filesystem.read_only_rootfs {
            args.push("--read-only".to_string());
        }
        if filesystem.writable_workspace {
            args.push("--tmpfs".to_string());
            args.push(format!("{WORKSPACE_PATH}:rw,size=64m"));
        }

        args.push(self.image.clone());
        // Keep the container alive so the worker can exec the agent workload.
        args.push("sleep".to_string());
        args.push("3600".to_string());
        args
    }
}

impl IsolationBackendLifecycle for DockerIsolationBackend {
    fn descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared> {
        request.policy.validate()?;
        self.capability_envelope_id = Some(request.capability_envelope_id.clone());
        self.policy = Some(request.policy);
        Ok(IsolationPrepared {
            prepared_id: format!("docker-prepared-{}", request.run_id),
            evidence: self.evidence(None, "prepared")?,
        })
    }

    fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted> {
        let policy = self.policy()?.clone();
        let args = self.run_args(
            &policy.resource_limits,
            &policy.network_policy,
            &policy.filesystem_policy,
        );
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let container_id = self.checked_docker(&arg_refs)?;
        if container_id.is_empty() {
            return Err(IsolationError::Backend(
                "docker run did not return a container id".to_string(),
            ));
        }
        let instance_id = format!("docker-{}", &container_id[..container_id.len().min(12)]);
        self.container_id = Some(container_id);
        self.instance_id = Some(instance_id.clone());
        let _ = prepared;
        let evidence = self.evidence(Some(&instance_id), "started")?;
        Ok(IsolationStarted {
            instance_id,
            evidence,
        })
    }

    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> IsolationResult<IsolationExecOutcome> {
        let container = self.container_id()?.to_string();
        let mut args = vec!["exec", &container];
        let workload_args = request.args.iter().map(String::as_str).collect::<Vec<_>>();
        args.extend(workload_args);
        let output = self.run_docker(&args)?;
        let exit_code = output.status.code();
        let message = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            String::from_utf8_lossy(&output.stderr).trim().to_string()
        };
        let evidence = self.evidence(Some(&request.instance_id), "executed")?;
        Ok(IsolationExecOutcome {
            instance_id: request.instance_id,
            exit_code,
            message,
            evidence,
        })
    }

    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome> {
        let container = self.container_id()?.to_string();
        self.checked_docker(&["stop", &container])?;
        let evidence = self.evidence(Some(instance_id), &format!("stopped:{reason}"))?;
        Ok(IsolationStopOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }

    fn snapshot_or_checkpoint(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<IsolationSnapshotOutcome> {
        let container = self.container_id()?.to_string();
        // Docker live checkpoint needs experimental CRIU; commit the container
        // filesystem as an honest, always-available checkpoint image instead.
        let image_id = self.checked_docker(&["commit", &container])?;
        let evidence = self.evidence(Some(instance_id), "checkpointed")?;
        Ok(IsolationSnapshotOutcome {
            instance_id: instance_id.to_string(),
            checkpoint_id: Some(image_id),
            evidence,
        })
    }

    fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs> {
        let container = self.container_id()?.to_string();
        let output = self.run_docker(&["logs", &container])?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lines = combined
            .lines()
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let evidence = self.evidence(Some(instance_id), "logs_collected")?;
        Ok(CollectedIsolationLogs {
            instance_id: instance_id.to_string(),
            lines,
            evidence,
        })
    }

    fn collect_artifacts(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<CollectedIsolationArtifacts> {
        let container = self.container_id()?.to_string();
        let listing = self.checked_docker(&["exec", &container, "ls", "-1", WORKSPACE_PATH])?;
        let artifacts = listing
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|name| IsolationArtifact {
                id: format!("artifact-{instance_id}-{name}"),
                path: format!("{WORKSPACE_PATH}/{name}"),
                content_type: None,
            })
            .collect();
        let evidence = self.evidence(Some(instance_id), "artifacts_collected")?;
        Ok(CollectedIsolationArtifacts {
            instance_id: instance_id.to_string(),
            artifacts,
            evidence,
        })
    }

    fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome> {
        if let Some(container) = self.container_id.take() {
            // Force-remove so a stopped or running container never leaks.
            self.checked_docker(&["rm", "-f", &container])?;
        }
        self.instance_id = None;
        let evidence = self.evidence(Some(instance_id), "cleaned_up")?;
        Ok(IsolationCleanupOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }
}

#[cfg(test)]
#[path = "docker_backend_test.rs"]
mod tests;
