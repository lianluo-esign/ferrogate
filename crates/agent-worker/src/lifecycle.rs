// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker-owned lifecycle dispatch for managed sessions.
//!
//! This module is intentionally inside the standalone `agent-worker` process.
//! Gateway code may call the management API, but it must not own Firecracker
//! lifecycle operations or framework handler execution.

use std::env;

use ferrogate_runtime::{
    select_isolation_backend, AgentWorkerFrameworkArtifactResult, AgentWorkerLifecycleResult,
    AgentWorkerManagementAction, AgentWorkerManagementEnvelope, AgentWorkerManagementErrorCode,
    AgentWorkerManagementResult, IsolationBackendDescriptor, IsolationBackendKind,
    IsolationBackendLifecycle, IsolationExecRequest, IsolationPolicy, IsolationPrepareRequest,
    ManagedWorkerError, ManagedWorkerSessionStatus,
};

use crate::{
    backends::{
        firecracker_guest_agent_launch_attempt, firecracker_guest_agent_preflight,
        firecracker_guest_rpc_start_attempt, firecracker_guest_rpc_start_request,
        firecracker_host_preflight, firecracker_microvm_provision, isolation_backend_kind_wire,
        isolation_backends, selectable_isolation_backend_descriptors,
    },
    docker_backend::DockerIsolationBackend,
    external_actions::GatewayExternalActionAuthorizer,
    handler_runtime::{
        cancel_native_harness, cleanup_native_harness, collect_native_harness_artifacts,
        stream_native_harness_status,
    },
    state::AgentWorkerStateStore,
};

pub(crate) fn dispatch_lifecycle_action(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    external_action_authorizer: Option<&dyn GatewayExternalActionAuthorizer>,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    match envelope.action {
        AgentWorkerManagementAction::Provision => provision(state, envelope),
        AgentWorkerManagementAction::ExecOrAttach => {
            exec_or_attach(state, envelope, external_action_authorizer)
        }
        AgentWorkerManagementAction::Stop => stop(state, envelope),
        AgentWorkerManagementAction::SnapshotOrCheckpoint => {
            snapshot_or_checkpoint(state, envelope)
        }
        AgentWorkerManagementAction::Cleanup => cleanup(state, envelope),
        AgentWorkerManagementAction::StreamStatus => stream_status(state, envelope),
        AgentWorkerManagementAction::CollectArtifacts => collect_artifacts(state, envelope),
        AgentWorkerManagementAction::ProbeHandlers | AgentWorkerManagementAction::ListBackends => {
            Ok(None)
        }
    }
}

fn provision(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    // Choose the isolation backend through the replaceable-registry contract
    // rather than hardcoding Firecracker. Only backends whose host lifecycle is
    // implemented and configured are selectable, so an unimplemented or
    // unconfigured backend can never be provisioned — the path fails closed.
    let selectable = selectable_isolation_backend_descriptors();
    let selected = match select_isolation_backend(&IsolationPolicy::default(), &selectable) {
        Ok(descriptor) => descriptor.clone(),
        Err(_) => {
            // Nothing selectable. Surface the Firecracker readiness reason when
            // we have one so the operator learns why, instead of a generic error.
            let reason = isolation_backends()
                .into_iter()
                .find(|backend| backend.backend_name == "firecracker")
                .and_then(|backend| backend.readiness_reason)
                .unwrap_or_else(|| "no isolation backend is ready for provisioning".to_string());
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::IncompatibleBackend,
                reason,
            ));
        }
    };

    // Dispatch to the host lifecycle for the selected backend. Firecracker is
    // the high-isolation managed default; Docker is the opt-in low-risk tier.
    // Any other kind fails closed instead of silently doing nothing.
    match selected.kind {
        IsolationBackendKind::FirecrackerMicroVm => {}
        IsolationBackendKind::RootlessDocker => {
            return provision_docker(state, envelope, &selected);
        }
        _ => {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::IncompatibleBackend,
                format!(
                    "selected isolation backend {} has no host lifecycle in this agent-worker build",
                    selected.backend_name
                ),
            ));
        }
    }

    // Record the backend that was actually selected as run evidence, so the
    // lifecycle result reflects the real selection rather than a constant.
    let backend_identity = LifecycleBackendIdentity::from_descriptor(&selected);

    let preflight = firecracker_host_preflight();
    if !preflight.ready() {
        let message = preflight.failure_summary();
        let lifecycle = lifecycle_result_for_backend(
            envelope,
            ManagedWorkerSessionStatus::Failed,
            "host_preflight_failed",
            &message,
            &backend_identity,
            None,
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        let running = existing.is_running();
        let lifecycle = lifecycle_result_for_backend(
            envelope,
            if running {
                ManagedWorkerSessionStatus::Running
            } else {
                ManagedWorkerSessionStatus::Failed
            },
            if running { "already_running" } else { "exited" },
            &format!(
                "Firecracker microVM {} already exists; running={running}",
                existing.instance_id
            ),
            &backend_identity,
            Some(existing.instance_id.clone()),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let resources = firecracker_lifecycle_resources()?;
    let mut microvm = firecracker_microvm_provision(
        resources.provision_timeout_millis,
        resources.vcpu_count,
        resources.mem_size_mib,
    )
    .map_err(|error| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::ProvisionFailed,
            format!(
                "agent-worker Firecracker provision failed: {}",
                error.summary()
            ),
        )
    })?;
    let instance_id = microvm.instance_id.clone();
    let markers = microvm.evidence.marker_summary();
    let running = microvm.is_running();
    state.put_firecracker_microvm(session_id, run_id, microvm);
    let message = format!(
        "Firecracker microVM provisioned by agent-worker; running={running}; markers={markers}"
    );
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Running,
        "provisioned",
        &message,
        &backend_identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

// ---- Docker isolation backend lifecycle (opt-in low-risk tier) ----
//
// Every operation drives the worker-owned DockerIsolationBackend, which
// implements the same runtime IsolationBackendLifecycle contract as the
// Firecracker path. The gateway/control plane and the management wire result
// are identical regardless of which backend serviced the session — that is the
// replaceability #82 requires.

fn docker_prepare_request(
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> IsolationPrepareRequest {
    IsolationPrepareRequest {
        session_id: session_id.to_string(),
        run_id: run_id.to_string(),
        worker_template_id: envelope.worker_id.clone(),
        framework_adapter: envelope
            .framework_adapter
            .clone()
            .unwrap_or_else(|| "native_harness".to_string()),
        capability_envelope_id: format!("cap:{session_id}:{run_id}"),
        policy: IsolationPolicy::default(),
    }
}

fn docker_lifecycle_error(
    code: AgentWorkerManagementErrorCode,
    operation: &str,
    error: ferrogate_runtime::IsolationError,
) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        code,
        format!("agent-worker Docker {operation} failed: {error}"),
    )
}

fn docker_missing_backend_error(operation: &str) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::IncompatibleBackend,
        format!(
            "agent-worker Docker {operation} found no provisioned container for this session/run"
        ),
    )
}

fn provision_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    selected: &IsolationBackendDescriptor,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    let identity = LifecycleBackendIdentity::from_descriptor(selected);

    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        let lifecycle = lifecycle_result_for_backend(
            envelope,
            ManagedWorkerSessionStatus::Running,
            "already_running",
            "Docker isolation backend already provisioned for this session/run",
            &identity,
            None,
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let mut backend = DockerIsolationBackend::new(&envelope.worker_id, &selected.backend_version);
    let prepared = backend
        .prepare(docker_prepare_request(envelope, &session_id, &run_id))
        .map_err(|error| {
            docker_lifecycle_error(
                AgentWorkerManagementErrorCode::ProvisionFailed,
                "provision",
                error,
            )
        })?;
    let started = backend.start(prepared).map_err(|error| {
        docker_lifecycle_error(
            AgentWorkerManagementErrorCode::ProvisionFailed,
            "provision",
            error,
        )
    })?;
    let instance_id = started.instance_id.clone();
    state.put_docker_backend(session_id, run_id, backend);
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Running,
        "provisioned",
        &format!(
            "Docker container {instance_id} provisioned by agent-worker with sealed network and enforced resource limits"
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn exec_or_attach_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_docker_backend_mut(session_id, run_id)
        .ok_or_else(|| docker_missing_backend_error("exec_or_attach"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.backend_descriptor());
    let instance_id = backend.instance_id().map(ToOwned::to_owned);
    // Managed agent workload dispatch runs through the framework adapter handler
    // (#84) and the gateway-mediated capability path (#86). Here we prove the
    // provisioned container is attachable and executes a deterministic probe.
    let exec = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: instance_id.clone().unwrap_or_default(),
            workload_ref: "agent://managed/readiness".to_string(),
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo agent-worker-docker-ready".to_string(),
            ],
        })
        .map_err(|error| {
            docker_lifecycle_error(
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
            "Docker container {} exec by agent-worker; exit_code={:?}; output={}",
            instance_id.as_deref().unwrap_or("unknown"),
            exec.exit_code,
            exec.message
        ),
        &identity,
        instance_id,
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn collect_artifacts_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_docker_backend_mut(session_id, run_id)
        .ok_or_else(|| docker_missing_backend_error("collect_artifacts"))?;
    let instance_id = backend
        .instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let collected = backend.collect_artifacts(&instance_id).map_err(|error| {
        docker_lifecycle_error(
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

fn stop_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_docker_backend_mut(session_id, run_id)
        .ok_or_else(|| docker_missing_backend_error("stop"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.backend_descriptor());
    let instance_id = backend
        .instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    // Stop the container but keep the backend record so cleanup can force-remove
    // it — a stopped container still holds host resources until cleanup.
    let report = backend.stop(&instance_id, "stopped").map_err(|error| {
        docker_lifecycle_error(AgentWorkerManagementErrorCode::Cancelled, "stop", error)
    })?;
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Cancelled,
        "stopped",
        &format!(
            "Docker container {} stopped by agent-worker; outcome={}",
            instance_id, report.evidence.outcome
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn snapshot_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let backend = state
        .get_docker_backend_mut(session_id, run_id)
        .ok_or_else(|| docker_missing_backend_error("snapshot_or_checkpoint"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.backend_descriptor());
    let instance_id = backend
        .instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let snapshot = backend
        .snapshot_or_checkpoint(&instance_id)
        .map_err(|error| {
            docker_lifecycle_error(
                AgentWorkerManagementErrorCode::ProvisionFailed,
                "snapshot_or_checkpoint",
                error,
            )
        })?;
    let lifecycle = lifecycle_result_for_backend(
        envelope,
        ManagedWorkerSessionStatus::Running,
        "checkpointed",
        &format!(
            "Docker container {} checkpointed by agent-worker via commit; checkpoint_id={}",
            instance_id,
            snapshot.checkpoint_id.as_deref().unwrap_or("unknown")
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn cleanup_docker(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    session_id: &str,
    run_id: &str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let mut backend = state
        .remove_docker_backend(session_id, run_id)
        .ok_or_else(|| docker_missing_backend_error("cleanup"))?;
    let identity = LifecycleBackendIdentity::from_descriptor(backend.backend_descriptor());
    let instance_id = backend
        .instance_id()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let cleanup = backend.cleanup(&instance_id).map_err(|error| {
        docker_lifecycle_error(
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
            "Docker container {} cleaned up by agent-worker; outcome={}",
            instance_id, cleanup.evidence.outcome
        ),
        &identity,
        Some(instance_id),
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FirecrackerLifecycleResources {
    provision_timeout_millis: u64,
    vcpu_count: u8,
    mem_size_mib: u32,
}

fn firecracker_lifecycle_resources() -> Result<FirecrackerLifecycleResources, ManagedWorkerError> {
    Ok(FirecrackerLifecycleResources {
        provision_timeout_millis: parse_env_u64(
            "AGENT_WORKER_FIRECRACKER_PROVISION_TIMEOUT_MILLIS",
            30_000,
        )?,
        vcpu_count: parse_env_u8("AGENT_WORKER_FIRECRACKER_VCPU_COUNT", 1)?,
        mem_size_mib: parse_env_u32("AGENT_WORKER_FIRECRACKER_MEM_SIZE_MIB", 512)?,
    })
}

fn parse_env_u64(name: &'static str, default: u64) -> Result<u64, ManagedWorkerError> {
    match env::var(name) {
        Ok(value) => parse_positive_u64(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(resource_config_error(name, error.to_string())),
    }
}

fn parse_env_u8(name: &'static str, default: u8) -> Result<u8, ManagedWorkerError> {
    match env::var(name) {
        Ok(value) => {
            let parsed = parse_positive_u64(name, &value)?;
            u8::try_from(parsed).map_err(|_| {
                resource_config_error(name, format!("{name} must be less than or equal to 255"))
            })
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(resource_config_error(name, error.to_string())),
    }
}

fn parse_env_u32(name: &'static str, default: u32) -> Result<u32, ManagedWorkerError> {
    match env::var(name) {
        Ok(value) => {
            let parsed = parse_positive_u64(name, &value)?;
            u32::try_from(parsed).map_err(|_| {
                resource_config_error(
                    name,
                    format!("{name} must be less than or equal to {}", u32::MAX),
                )
            })
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(resource_config_error(name, error.to_string())),
    }
}

fn parse_positive_u64(name: &'static str, value: &str) -> Result<u64, ManagedWorkerError> {
    let parsed = value.trim().parse::<u64>().map_err(|error| {
        resource_config_error(name, format!("{name} must be a positive integer: {error}"))
    })?;
    if parsed == 0 {
        return Err(resource_config_error(
            name,
            format!("{name} must be greater than zero"),
        ));
    }
    Ok(parsed)
}

fn resource_config_error(name: &'static str, reason: String) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::ProvisionFailed,
        format!("invalid Firecracker resource config {name}: {reason}"),
    )
}

fn exec_or_attach(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    _external_action_authorizer: Option<&dyn GatewayExternalActionAuthorizer>,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(existing) = state.get_handler_run_state(&session_id, &run_id) {
        return Ok(Some(stream_native_harness_status(&existing)));
    }
    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        return exec_or_attach_docker(state, envelope, &session_id, &run_id);
    }
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        let running = existing.is_running();
        let guest_agent = firecracker_guest_agent_preflight();
        if !guest_agent.ready() {
            let lifecycle = lifecycle_result_with_instance(
                envelope,
                ManagedWorkerSessionStatus::Failed,
                "guest_agent_channel_unavailable",
                &format!(
                    "Firecracker microVM {} is provisioned with running={running}, but agent-worker cannot launch a guest handler until the guest agent channel is configured: {}",
                    existing.instance_id,
                    guest_agent.failure_summary()
                ),
                Some(existing.instance_id.clone()),
            )?;
            return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
        }
        let launch_attempt = match firecracker_guest_agent_launch_attempt() {
            Ok(attempt) => attempt,
            Err(error) => {
                let lifecycle = lifecycle_result_with_instance(
                    envelope,
                    ManagedWorkerSessionStatus::Failed,
                    error.outcome(),
                    &format!(
                        "Firecracker microVM {} is provisioned with running={running}, but agent-worker could not establish the guest handler launch path: {}",
                        existing.instance_id,
                        error.reason()
                    ),
                    Some(existing.instance_id.clone()),
                )?;
                return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
            }
        };
        let guest_rpc_start_request = firecracker_guest_rpc_start_request(
            envelope,
            &launch_attempt.handshake,
            &existing.instance_id,
        );
        let guest_rpc_start_response = match firecracker_guest_rpc_start_attempt(
            &launch_attempt,
            &guest_rpc_start_request,
        ) {
            Ok(response) => response,
            Err(error) => {
                let lifecycle = lifecycle_result_with_instance(
                    envelope,
                    ManagedWorkerSessionStatus::Failed,
                    error.outcome(),
                    &format!(
                        "Firecracker microVM {} is provisioned with running={running}, but agent-worker could not complete the guest start RPC: {}; {}",
                        existing.instance_id,
                        error.reason(),
                        guest_rpc_start_request.summary()
                    ),
                    Some(existing.instance_id.clone()),
                )?;
                return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
            }
        };
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            ManagedWorkerSessionStatus::Failed,
            "guest_handler_rpc_not_implemented",
            &format!(
                "Firecracker microVM {} is provisioned with running={running}; guest agent command launched from {} in {} and exited with {}; elapsed_millis={}; gateway_endpoint_configured={}; guest_rpc_channel={}; guest_agent_version={}; {}; {}; proves_microvm_boot={}; proves_handler_execution={}; agent-worker guest handler RPC is not implemented yet",
                existing.instance_id,
                launch_attempt.command,
                launch_attempt.workspace,
                launch_attempt.exit_status,
                launch_attempt.elapsed_millis,
                !launch_attempt.gateway_endpoint.is_empty(),
                launch_attempt.handshake.rpc_channel(),
                launch_attempt
                    .handshake
                    .guest_agent_version()
                    .unwrap_or("unknown"),
                guest_rpc_start_request.summary(),
                guest_rpc_start_response.summary(),
                launch_attempt.proves_microvm_boot,
                launch_attempt.proves_handler_execution
            ),
            Some(existing.instance_id.clone()),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    let lifecycle = lifecycle_result(
        envelope,
        ManagedWorkerSessionStatus::Failed,
        "not_started",
        "agent-worker cannot exec_or_attach a managed handler before Firecracker microVM provision succeeds; local framework shims are test harness adapters, not managed microVM execution",
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn stream_status(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(backend) = state.get_docker_backend_mut(&session_id, &run_id) {
        let identity = LifecycleBackendIdentity::from_descriptor(backend.backend_descriptor());
        let running = backend.is_running();
        let instance_id = backend.instance_id().map(ToOwned::to_owned);
        let lifecycle = lifecycle_result_for_backend(
            envelope,
            if running {
                ManagedWorkerSessionStatus::Running
            } else {
                ManagedWorkerSessionStatus::Failed
            },
            if running { "running" } else { "exited" },
            &format!(
                "Docker container {} status checked by agent-worker; running={running}",
                instance_id.as_deref().unwrap_or("unknown")
            ),
            &identity,
            instance_id,
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        let running = existing.is_running();
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            if running {
                ManagedWorkerSessionStatus::Running
            } else {
                ManagedWorkerSessionStatus::Failed
            },
            if running { "running" } else { "exited" },
            &format!(
                "Firecracker microVM {} status checked by agent-worker; running={running}",
                existing.instance_id
            ),
            Some(existing.instance_id.clone()),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    if let Some(existing) = state.get_handler_run_state(&session_id, &run_id) {
        return Ok(Some(stream_native_harness_status(&existing)));
    }
    lifecycle_status(envelope)
}

fn collect_artifacts(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        return collect_artifacts_docker(state, envelope, &session_id, &run_id);
    }
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        return Ok(Some(AgentWorkerManagementResult::HandlerArtifacts {
            artifacts: existing.artifact_results(),
            events: existing.artifact_events(&session_id, &run_id),
        }));
    }
    let Some(existing) = state.get_handler_run_state(&session_id, &run_id) else {
        return lifecycle_not_started(
            envelope,
            AgentWorkerManagementErrorCode::CleanupFailed,
            "agent-worker cannot collect artifacts before handler execution starts",
        );
    };
    Ok(Some(collect_native_harness_artifacts(&existing)))
}

fn stop(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        return stop_docker(state, envelope, &session_id, &run_id);
    }
    if let Some(mut existing) = state.remove_firecracker_microvm(&session_id, &run_id) {
        let instance_id = existing.instance_id.clone();
        let report = existing.stop();
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            ManagedWorkerSessionStatus::Cancelled,
            "stopped",
            &format!(
                "Firecracker microVM {instance_id} stopped by agent-worker; {}",
                report.summary()
            ),
            Some(instance_id),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    let Some(mut existing) = state.get_handler_run_state(&session_id, &run_id) else {
        return lifecycle_not_started(
            envelope,
            AgentWorkerManagementErrorCode::Cancelled,
            "agent-worker cannot stop a session before handler execution starts",
        );
    };
    let result = cancel_native_harness(&mut existing)?;
    state.put_handler_run_state(existing);
    Ok(Some(result))
}

fn snapshot_or_checkpoint(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        return snapshot_docker(state, envelope, &session_id, &run_id);
    }
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        let running = existing.is_running();
        if !running {
            let lifecycle = lifecycle_result_with_instance(
                envelope,
                ManagedWorkerSessionStatus::Failed,
                "exited",
                &format!(
                    "Firecracker microVM {} cannot be snapshotted because it is not running",
                    existing.instance_id
                ),
                Some(existing.instance_id.clone()),
            )?;
            return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
        }
        let instance_id = existing.instance_id.clone();
        let snapshot = existing.snapshot_or_checkpoint();
        if snapshot.succeeded() {
            return Ok(Some(AgentWorkerManagementResult::HandlerArtifacts {
                artifacts: snapshot.artifact_results(&instance_id),
                events: snapshot.artifact_events(&session_id, &run_id, &instance_id),
            }));
        }
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            ManagedWorkerSessionStatus::Failed,
            &snapshot.outcome,
            &format!(
                "Firecracker microVM {instance_id} snapshot/checkpoint failed in agent-worker; {}",
                snapshot.summary()
            ),
            Some(instance_id),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    let lifecycle = lifecycle_result(
        envelope,
        ManagedWorkerSessionStatus::Failed,
        "not_started",
        "agent-worker cannot snapshot_or_checkpoint before Firecracker microVM provision succeeds",
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn cleanup(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if state.get_docker_backend_mut(&session_id, &run_id).is_some() {
        return cleanup_docker(state, envelope, &session_id, &run_id);
    }
    if let Some(mut existing) = state.remove_firecracker_microvm(&session_id, &run_id) {
        let instance_id = existing.instance_id.clone();
        let report = existing.cleanup();
        let (status, outcome) = if report.cleanup_succeeded() {
            (ManagedWorkerSessionStatus::CleanedUp, "cleaned_up")
        } else {
            (ManagedWorkerSessionStatus::Failed, "cleanup_failed")
        };
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            status,
            outcome,
            &format!(
                "Firecracker microVM {instance_id} cleanup handled by agent-worker; {}",
                report.summary()
            ),
            Some(instance_id),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }
    if let Some(mut existing) = state.get_handler_run_state(&session_id, &run_id) {
        let result = cleanup_native_harness(&mut existing)?;
        state.put_handler_run_state(existing);
        return Ok(Some(result));
    }
    let lifecycle = lifecycle_result(
        envelope,
        ManagedWorkerSessionStatus::CleanedUp,
        "not_started",
        "cleanup accepted as no-op because no Firecracker instance was provisioned",
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn lifecycle_status(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let lifecycle = lifecycle_result(
        envelope,
        ManagedWorkerSessionStatus::Failed,
        "not_started",
        "Firecracker lifecycle status is unavailable before provision succeeds",
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }))
}

fn lifecycle_not_started(
    envelope: &AgentWorkerManagementEnvelope,
    code: AgentWorkerManagementErrorCode,
    message: &'static str,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    Err(ManagedWorkerError::management_protocol_error(
        code,
        format!(
            "{} for session_id={} run_id={}",
            message,
            lifecycle_session_id(envelope)?,
            lifecycle_run_id(envelope)?
        ),
    ))
}

/// Identity of the isolation backend recorded as run evidence in a lifecycle
/// result. Provision records the backend actually selected through the
/// registry contract; pre-provision status paths report the managed default
/// with an empty version, meaning "no backend selected yet".
struct LifecycleBackendIdentity {
    name: String,
    kind: String,
    version: String,
}

impl LifecycleBackendIdentity {
    /// The managed default for lifecycle results emitted before a backend has
    /// been selected (status, not-started, preflight failures).
    fn managed_default() -> Self {
        Self {
            name: "firecracker".to_string(),
            kind: isolation_backend_kind_wire(&IsolationBackendKind::FirecrackerMicroVm)
                .to_string(),
            version: String::new(),
        }
    }

    fn from_descriptor(descriptor: &IsolationBackendDescriptor) -> Self {
        Self {
            name: descriptor.backend_name.clone(),
            kind: isolation_backend_kind_wire(&descriptor.kind).to_string(),
            version: descriptor.backend_version.clone(),
        }
    }
}

fn lifecycle_result(
    envelope: &AgentWorkerManagementEnvelope,
    status: ManagedWorkerSessionStatus,
    outcome: &str,
    message: &str,
) -> Result<AgentWorkerLifecycleResult, ManagedWorkerError> {
    lifecycle_result_for_backend(
        envelope,
        status,
        outcome,
        message,
        &LifecycleBackendIdentity::managed_default(),
        None,
    )
}

fn lifecycle_result_with_instance(
    envelope: &AgentWorkerManagementEnvelope,
    status: ManagedWorkerSessionStatus,
    outcome: &str,
    message: &str,
    isolation_instance_id: Option<String>,
) -> Result<AgentWorkerLifecycleResult, ManagedWorkerError> {
    lifecycle_result_for_backend(
        envelope,
        status,
        outcome,
        message,
        &LifecycleBackendIdentity::managed_default(),
        isolation_instance_id,
    )
}

fn lifecycle_result_for_backend(
    envelope: &AgentWorkerManagementEnvelope,
    status: ManagedWorkerSessionStatus,
    outcome: &str,
    message: &str,
    backend: &LifecycleBackendIdentity,
    isolation_instance_id: Option<String>,
) -> Result<AgentWorkerLifecycleResult, ManagedWorkerError> {
    Ok(AgentWorkerLifecycleResult {
        session_id: lifecycle_session_id(envelope)?,
        run_id: lifecycle_run_id(envelope)?,
        worker_id: envelope.worker_id.clone(),
        action: envelope.action,
        status,
        backend_name: backend.name.clone(),
        backend_kind: backend.kind.clone(),
        backend_version: backend.version.clone(),
        isolation_instance_id,
        outcome: outcome.to_string(),
        message: message.to_string(),
    })
}

fn lifecycle_session_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.session_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "session_id is required for lifecycle dispatch",
        )
    })
}

fn lifecycle_run_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.run_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "run_id is required for lifecycle dispatch",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE_ENV: [&str; 3] = [
        "AGENT_WORKER_FIRECRACKER_PROVISION_TIMEOUT_MILLIS",
        "AGENT_WORKER_FIRECRACKER_VCPU_COUNT",
        "AGENT_WORKER_FIRECRACKER_MEM_SIZE_MIB",
    ];

    #[test]
    fn firecracker_lifecycle_resources_default_to_current_smoke_values() {
        let _env_lock = crate::test_support::lock_firecracker_env();
        clear_resource_env();

        let resources = firecracker_lifecycle_resources().unwrap();

        assert_eq!(
            resources,
            FirecrackerLifecycleResources {
                provision_timeout_millis: 30_000,
                vcpu_count: 1,
                mem_size_mib: 512,
            }
        );
    }

    #[test]
    fn firecracker_lifecycle_resources_accept_worker_env_overrides() {
        let _env_lock = crate::test_support::lock_firecracker_env();
        clear_resource_env();
        env::set_var("AGENT_WORKER_FIRECRACKER_PROVISION_TIMEOUT_MILLIS", "45000");
        env::set_var("AGENT_WORKER_FIRECRACKER_VCPU_COUNT", "2");
        env::set_var("AGENT_WORKER_FIRECRACKER_MEM_SIZE_MIB", "1024");

        let resources = firecracker_lifecycle_resources().unwrap();

        clear_resource_env();
        assert_eq!(
            resources,
            FirecrackerLifecycleResources {
                provision_timeout_millis: 45_000,
                vcpu_count: 2,
                mem_size_mib: 1024,
            }
        );
    }

    #[test]
    fn firecracker_lifecycle_resources_reject_invalid_values_before_provision() {
        let _env_lock = crate::test_support::lock_firecracker_env();
        clear_resource_env();
        env::set_var("AGENT_WORKER_FIRECRACKER_VCPU_COUNT", "0");

        let error = firecracker_lifecycle_resources().unwrap_err();

        clear_resource_env();
        assert_eq!(
            error.management_error().code,
            AgentWorkerManagementErrorCode::ProvisionFailed
        );
        assert!(error
            .to_string()
            .contains("AGENT_WORKER_FIRECRACKER_VCPU_COUNT"));
    }

    fn clear_resource_env() {
        for name in RESOURCE_ENV {
            env::remove_var(name);
        }
    }
}
