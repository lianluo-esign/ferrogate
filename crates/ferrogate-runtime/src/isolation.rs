// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Managed worker isolation contract.
//!
//! This module describes the boundary that the host-side `agent-worker`
//! process must implement. The gateway/control plane can select policy and
//! record evidence, but Firecracker jailer setup and other host lifecycle
//! details belong behind this contract.

use std::{error::Error, fmt};

pub type IsolationResult<T> = Result<T, IsolationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationBackendKind {
    FirecrackerMicroVm,
    KataContainers,
    Gvisor,
    RootlessDocker,
    /// Cloudflare Containers / Sandbox tier (issue #415): a per-tenant isolated
    /// instance (a Durable Object–backed `Container`, or a `@cloudflare/sandbox`
    /// sandbox for untrusted agent-generated code). Its host lifecycle is NOT
    /// owned by the local `agent-worker`; it is driven REMOTELY through the
    /// fronting agent-gateway Worker (Cloudflare exposes no public container
    /// lifecycle REST API). Isolation is stronger than a namespaced local
    /// process, so it ranks above [`Self::LocalProcess`] but below the
    /// host-owned micro-VM / container tiers.
    CloudflareContainer,
    /// Namespaced local host process (unshare user/mount/pid/net + rlimits).
    /// Weakest sanctioned tier: sandbox/CI substitute where no daemon or
    /// hypervisor is available. Always ranked last for selection.
    LocalProcess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationBackendCapabilities {
    pub prepare: bool,
    pub start: bool,
    pub exec_or_attach: bool,
    pub stop: bool,
    pub snapshot_or_checkpoint: bool,
    pub collect_logs: bool,
    pub collect_artifacts: bool,
    pub cleanup: bool,
    pub governed_egress: bool,
    pub secret_injection: bool,
}

impl IsolationBackendCapabilities {
    pub fn full() -> Self {
        Self {
            prepare: true,
            start: true,
            exec_or_attach: true,
            stop: true,
            snapshot_or_checkpoint: true,
            collect_logs: true,
            collect_artifacts: true,
            cleanup: true,
            governed_egress: true,
            secret_injection: true,
        }
    }

    /// A backend that advertises no lifecycle capability at all. Used for a
    /// backend that is part of the replaceable contract but has no host
    /// implementation yet, so it can never satisfy a policy's required
    /// capabilities and can never be selected. This keeps selection
    /// fail-closed by construction, independent of any readiness filtering.
    pub fn none() -> Self {
        Self {
            prepare: false,
            start: false,
            exec_or_attach: false,
            stop: false,
            snapshot_or_checkpoint: false,
            collect_logs: false,
            collect_artifacts: false,
            cleanup: false,
            governed_egress: false,
            secret_injection: false,
        }
    }

    pub fn supports(&self, required: &Self) -> bool {
        (!required.prepare || self.prepare)
            && (!required.start || self.start)
            && (!required.exec_or_attach || self.exec_or_attach)
            && (!required.stop || self.stop)
            && (!required.snapshot_or_checkpoint || self.snapshot_or_checkpoint)
            && (!required.collect_logs || self.collect_logs)
            && (!required.collect_artifacts || self.collect_artifacts)
            && (!required.cleanup || self.cleanup)
            && (!required.governed_egress || self.governed_egress)
            && (!required.secret_injection || self.secret_injection)
    }
}

impl Default for IsolationBackendCapabilities {
    fn default() -> Self {
        Self {
            prepare: true,
            start: true,
            exec_or_attach: true,
            stop: true,
            snapshot_or_checkpoint: false,
            collect_logs: true,
            collect_artifacts: true,
            cleanup: true,
            governed_egress: true,
            secret_injection: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationBackendDescriptor {
    pub backend_name: String,
    pub backend_version: String,
    pub kind: IsolationBackendKind,
    pub host_lifecycle_owner: String,
    pub gateway_controls_backend: bool,
    pub capabilities: IsolationBackendCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationResourceLimits {
    pub cpu_count: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub max_runtime_millis: Option<u64>,
}

impl Default for IsolationResourceLimits {
    fn default() -> Self {
        Self {
            cpu_count: 1,
            memory_mib: 512,
            disk_mib: 1024,
            max_runtime_millis: Some(30_000),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationNetworkPolicy {
    pub direct_public_egress: bool,
    pub gateway_control_channel: bool,
    pub governed_egress: bool,
}

impl Default for IsolationNetworkPolicy {
    fn default() -> Self {
        Self {
            direct_public_egress: false,
            gateway_control_channel: true,
            governed_egress: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationFilesystemPolicy {
    pub read_only_rootfs: bool,
    pub writable_workspace: bool,
    pub host_path_mounts: bool,
}

impl Default for IsolationFilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only_rootfs: true,
            writable_workspace: true,
            host_path_mounts: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsolationPolicy {
    pub allowed_kinds: Vec<IsolationBackendKind>,
    pub required_capabilities: IsolationBackendCapabilities,
    pub resource_limits: IsolationResourceLimits,
    pub network_policy: IsolationNetworkPolicy,
    pub filesystem_policy: IsolationFilesystemPolicy,
}

impl IsolationPolicy {
    pub fn validate(&self) -> IsolationResult<()> {
        if self.resource_limits.cpu_count == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.cpu_count must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.memory_mib == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.memory_mib must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.disk_mib == 0 {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.disk_mib must be greater than zero".to_string(),
            ));
        }
        if self.resource_limits.max_runtime_millis == Some(0) {
            return Err(IsolationError::InvalidPolicy(
                "resource_limits.max_runtime_millis must be greater than zero".to_string(),
            ));
        }
        if self.network_policy.direct_public_egress {
            return Err(IsolationError::InvalidPolicy(
                "managed workers must not allow direct public egress".to_string(),
            ));
        }
        if !self.network_policy.gateway_control_channel {
            return Err(IsolationError::InvalidPolicy(
                "managed workers require the gateway control channel".to_string(),
            ));
        }
        if self.filesystem_policy.host_path_mounts {
            return Err(IsolationError::InvalidPolicy(
                "managed workers must not mount arbitrary host paths".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn select_isolation_backend<'a>(
    policy: &IsolationPolicy,
    candidates: &'a [IsolationBackendDescriptor],
) -> IsolationResult<&'a IsolationBackendDescriptor> {
    policy.validate()?;

    candidates
        .iter()
        .filter(|candidate| {
            (policy.allowed_kinds.is_empty() || policy.allowed_kinds.contains(&candidate.kind))
                && candidate
                    .capabilities
                    .supports(&policy.required_capabilities)
        })
        .min_by_key(|candidate| isolation_preference_rank(&candidate.kind))
        .ok_or_else(|| {
            IsolationError::NoCompatibleBackend(
                "no isolation backend matches policy and capability requirements".to_string(),
            )
        })
}

fn isolation_preference_rank(kind: &IsolationBackendKind) -> u8 {
    match kind {
        IsolationBackendKind::FirecrackerMicroVm => 0,
        IsolationBackendKind::KataContainers => 1,
        IsolationBackendKind::Gvisor => 2,
        IsolationBackendKind::RootlessDocker => 3,
        IsolationBackendKind::CloudflareContainer => 4,
        IsolationBackendKind::LocalProcess => 5,
    }
}

pub trait IsolationBackendLifecycle {
    fn descriptor(&self) -> &IsolationBackendDescriptor;
    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared>;
    fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted>;
    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> IsolationResult<IsolationExecOutcome>;
    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome>;
    fn snapshot_or_checkpoint(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<IsolationSnapshotOutcome>;
    fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs>;
    fn collect_artifacts(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<CollectedIsolationArtifacts>;
    fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPrepareRequest {
    pub session_id: String,
    pub run_id: String,
    pub worker_template_id: String,
    pub framework_adapter: String,
    pub capability_envelope_id: String,
    pub policy: IsolationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPrepared {
    pub prepared_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationStarted {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationExecRequest {
    pub instance_id: String,
    pub workload_ref: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationExecOutcome {
    pub instance_id: String,
    pub exit_code: Option<i32>,
    pub message: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationStopOutcome {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationSnapshotOutcome {
    pub instance_id: String,
    pub checkpoint_id: Option<String>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIsolationLogs {
    pub instance_id: String,
    pub lines: Vec<String>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationArtifact {
    pub id: String,
    pub path: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIsolationArtifacts {
    pub instance_id: String,
    pub artifacts: Vec<IsolationArtifact>,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationCleanupOutcome {
    pub instance_id: String,
    pub evidence: IsolationLifecycleEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationLifecycleEvidence {
    pub backend_name: String,
    pub backend_version: String,
    pub agent_worker_id: String,
    pub isolation_instance_id: Option<String>,
    pub resource_limits: IsolationResourceLimits,
    pub network_policy: IsolationNetworkPolicy,
    pub filesystem_policy: IsolationFilesystemPolicy,
    pub capability_envelope_id: String,
    pub outcome: String,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationError {
    InvalidPolicy(String),
    NoCompatibleBackend(String),
    Backend(String),
}

impl fmt::Display for IsolationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(message) => {
                write!(formatter, "invalid isolation policy: {message}")
            }
            Self::NoCompatibleBackend(message) => {
                write!(formatter, "no compatible isolation backend: {message}")
            }
            Self::Backend(message) => write!(formatter, "isolation backend failed: {message}"),
        }
    }
}

impl Error for IsolationError {}

#[cfg(test)]
#[path = "isolation_test.rs"]
mod tests;
