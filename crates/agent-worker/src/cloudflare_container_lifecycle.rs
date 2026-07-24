// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare Containers/Sandbox remote-provisioning dispatch for agent-worker
//   (issue #442). Mirrors the Docker isolation tier's provision/exec/stop/artifacts/cleanup
//   control flow, but drives the #415 ContainerControlClient through the fronting agent-gateway
//   Worker instead of a worker-owned host lifecycle. Split out of lifecycle.rs to keep that
//   module under the engineering-standards line cap.

//! Cloudflare Containers/Sandbox remote-provisioning dispatch (issue #442).
//!
//! This is the gateway-driven sibling of the Docker/local-process tiers in
//! [`crate::lifecycle`]. It mirrors `provision_docker` exactly — prepare then
//! start, store the backend keyed by session/run, and thread the assigned
//! instance id through exec/stop/logs/artifacts/cleanup — but the lifecycle is
//! **not owned by this host**: every verb drives the #415
//! [`ferrogate_runtime::ContainerControlClient`] against the fronting
//! agent-gateway Worker's `/container/*` routes.
//!
//! Fail-closed posture (inherited from #415):
//!
//! * This tier is reachable ONLY when an operator explicitly pins it
//!   (`AGENT_WORKER_PROVISION_ISOLATION_BACKEND=cloudflare_container`); the
//!   automatic on-host `select_isolation_backend` ranking never returns a
//!   gateway-driven backend.
//! * `snapshot_or_checkpoint` has no Cloudflare primitive, so the backend
//!   advertises it off and [`snapshot_cloudflare_container`] surfaces the
//!   backend's honest error rather than fabricating a checkpoint.
//!
//! The production entry [`provision_cloudflare_container`] builds a real
//! block-on HTTP client via [`ferrogate_runtime::ContainerControlClient::production`];
//! offline unit tests call [`provision_cloudflare_container_backend`] directly
//! with a backend built over a mock [`ferrogate_runtime::GatewayControlTransport`],
//! so no test touches the network. Live-CF end-to-end provisioning is the test
//! gate's coverage.

use ferrogate_runtime::{
    AgentWorkerFrameworkArtifactResult, AgentWorkerManagementEnvelope,
    AgentWorkerManagementErrorCode, AgentWorkerManagementResult, ContainerControlClient,
    IsolationBackendDescriptor, IsolationError, IsolationExecRequest, ManagedWorkerError,
    ManagedWorkerSessionStatus,
};

use crate::{
    cloudflare_container_backend::{
        cloudflare_container_backend_config, CloudflareContainerIsolationBackend,
        ManagedContainerBackend,
    },
    lifecycle::{
        isolation_prepare_request, lifecycle_result_for_backend, lifecycle_run_id,
        lifecycle_session_id, LifecycleBackendIdentity,
    },
    state::AgentWorkerStateStore,
};

fn cloudflare_container_lifecycle_error(
    code: AgentWorkerManagementErrorCode,
    operation: &str,
    error: IsolationError,
) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        code,
        format!("agent-worker Cloudflare container {operation} failed: {error}"),
    )
}

fn cloudflare_container_missing_backend_error(operation: &str) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::IncompatibleBackend,
        format!(
            "agent-worker Cloudflare container {operation} found no provisioned instance for this \
             session/run"
        ),
    )
}

/// Production provision entry: read the operator's fronting-Worker config, build
/// the real block-on control client, and drive the same prepare/start flow the
/// Docker tier uses. Config errors fail closed; the actual HTTP round-trip is
/// exercised only against a live Worker (Not-tested here).
pub(crate) fn provision_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    selected: &IsolationBackendDescriptor,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let config = cloudflare_container_backend_config().map_err(|reason| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::IncompatibleBackend,
            format!("agent-worker Cloudflare container provision refused (fail closed): {reason}"),
        )
    })?;
    let client = ContainerControlClient::production(&config.gateway_url, &config.control_token)
        .map_err(|error| {
            ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::ProvisionFailed,
                format!(
                    "agent-worker Cloudflare container provision could not build the \
                     fronting-Worker control transport: {error}"
                ),
            )
        })?;
    let backend = CloudflareContainerIsolationBackend::new(
        &envelope.tenant_id,
        &envelope.worker_id,
        &selected.backend_version,
        client,
        &config.image,
        config.tier,
    );
    provision_cloudflare_container_backend(state, envelope, selected, backend)
}

/// Transport-agnostic provision core: prepare + start the (already-constructed)
/// backend, store it behind the [`ManagedContainerBackend`] handle keyed by
/// session/run, and record the lifecycle evidence — exactly mirroring
/// `provision_docker`. Split from [`provision_cloudflare_container`] so unit
/// tests inject a mock-transport backend without any network.
pub(crate) fn provision_cloudflare_container_backend<B>(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    selected: &IsolationBackendDescriptor,
    mut backend: B,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError>
where
    B: ManagedContainerBackend + 'static,
{
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    let identity = LifecycleBackendIdentity::from_descriptor(selected);

    if state
        .get_cloudflare_container_backend_mut(&session_id, &run_id)
        .is_some()
    {
        let lifecycle = lifecycle_result_for_backend(
            envelope,
            ManagedWorkerSessionStatus::Running,
            "already_running",
            "Cloudflare container isolation backend already provisioned for this session/run",
            &identity,
            None,
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let prepared = backend
        .prepare(isolation_prepare_request(envelope, &session_id, &run_id))
        .map_err(|error| {
            cloudflare_container_lifecycle_error(
                AgentWorkerManagementErrorCode::ProvisionFailed,
                "provision",
                error,
            )
        })?;
    let started = backend.start(prepared).map_err(|error| {
        cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::ProvisionFailed,
            "provision",
            error,
        )
    })?;
    let instance_id = started.instance_id.clone();
    state.put_cloudflare_container_backend(session_id, run_id, Box::new(backend));
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Running,
        "provisioned",
        &format!(
            "Cloudflare container instance {instance_id} provisioned by agent-worker through the \
             fronting agent-gateway Worker with deny-by-default egress"
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

pub(crate) fn exec_or_attach_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_cloudflare_container_backend_mut(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("exec_or_attach"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.descriptor());
    let instance_id = backend.stored_instance_id().map(ToOwned::to_owned);
    // Managed workload dispatch runs through the framework adapter handler and
    // the gateway-mediated capability path; here we prove the provisioned
    // instance is attachable with the same deterministic readiness probe the
    // Docker/local-process tiers use.
    let exec = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: instance_id.clone().unwrap_or_default(),
            workload_ref: "agent://managed/readiness".to_string(),
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo agent-worker-cloudflare-container-ready".to_string(),
            ],
        })
        .map_err(|error| {
            cloudflare_container_lifecycle_error(
                AgentWorkerManagementErrorCode::Cancelled,
                "exec_or_attach",
                error,
            )
        })?;
    let succeeded = exec.exit_code == Some(0);
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        if succeeded {
            ManagedWorkerSessionStatus::Running
        } else {
            ManagedWorkerSessionStatus::Failed
        },
        if succeeded { "executed" } else { "exec_failed" },
        &format!(
            "Cloudflare container instance {} exec by agent-worker; exit_code={:?}; output={}",
            instance_id.as_deref().unwrap_or("unknown"),
            exec.exit_code,
            exec.message
        ),
        &identity,
        instance_id,
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

pub(crate) fn stream_status_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_cloudflare_container_backend_mut(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("stream_status"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.descriptor());
    let instance_id = backend.stored_instance_id().map(ToOwned::to_owned);
    // The instance is a remote Durable Object; we report the last known state
    // from the provisioned handle (started ⇒ running). A live status probe is
    // the fronting Worker's concern (Not-tested here).
    let running = instance_id.is_some();
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        if running {
            ManagedWorkerSessionStatus::Running
        } else {
            ManagedWorkerSessionStatus::Failed
        },
        if running { "running" } else { "exited" },
        &format!(
            "Cloudflare container instance {} status reported by agent-worker; running={running}",
            instance_id.as_deref().unwrap_or("unknown")
        ),
        &identity,
        instance_id,
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

pub(crate) fn collect_artifacts_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_cloudflare_container_backend_mut(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("collect_artifacts"))?;
    let instance_id = backend
        .stored_instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let collected = backend.collect_artifacts(&instance_id).map_err(|error| {
        cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::CleanupFailed,
            "collect_artifacts",
            error,
        )
    })?;
    let artifacts = collected
        .artifacts
        .into_iter()
        .map(|artifact| AgentWorkerFrameworkArtifactResult {
            artifact_id: artifact.id,
            name: artifact.path,
            media_type: artifact
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            byte_len: 0,
        })
        .collect();
    let _ = envelope;
    Ok(Some(AgentWorkerManagementResult::HandlerArtifacts {
        artifacts,
        events: Vec::new(),
    }))
}

pub(crate) fn stop_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_cloudflare_container_backend_mut(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("stop"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.descriptor());
    let instance_id = backend
        .stored_instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    // Signal the instance but keep the backend record so cleanup can destroy it.
    let report = backend.stop(&instance_id, "stopped").map_err(|error| {
        cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::Cancelled,
            "stop",
            error,
        )
    })?;
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Cancelled,
        "stopped",
        &format!(
            "Cloudflare container instance {} stopped by agent-worker; outcome={}",
            instance_id, report.evidence.outcome
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

pub(crate) fn snapshot_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    _envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_cloudflare_container_backend_mut(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("snapshot_or_checkpoint"))?;
    let instance_id = backend
        .stored_instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    // Fail closed: Cloudflare exposes no container checkpoint primitive, so the
    // backend advertises snapshot_or_checkpoint = false and returns an honest
    // error. Surface that (never fabricate a checkpoint). The Ok arm cannot
    // happen for this backend, but is handled defensively.
    match backend.snapshot_or_checkpoint(&instance_id) {
        Ok(_) => Err(cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::IncompatibleBackend,
            "snapshot_or_checkpoint",
            IsolationError::Backend(
                "cloudflare container backend unexpectedly produced a checkpoint".to_string(),
            ),
        )),
        Err(error) => Err(cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::IncompatibleBackend,
            "snapshot_or_checkpoint",
            error,
        )),
    }
}

pub(crate) fn cleanup_cloudflare_container(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let mut backend = state
        .remove_cloudflare_container_backend(session_id, run_id)
        .ok_or_else(|| cloudflare_container_missing_backend_error("cleanup"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.descriptor());
    let instance_id = backend
        .stored_instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let cleanup = backend.cleanup(&instance_id).map_err(|error| {
        cloudflare_container_lifecycle_error(
            AgentWorkerManagementErrorCode::CleanupFailed,
            "cleanup",
            error,
        )
    })?;
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::CleanedUp,
        "cleaned_up",
        &format!(
            "Cloudflare container instance {} cleaned up by agent-worker; outcome={}",
            instance_id, cleanup.evidence.outcome
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

#[cfg(test)]
#[path = "cloudflare_container_lifecycle_test.rs"]
mod tests;
