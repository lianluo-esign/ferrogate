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

use ferrogate_runtime::{
    AgentWorkerLifecycleResult, AgentWorkerManagementAction, AgentWorkerManagementEnvelope,
    AgentWorkerManagementErrorCode, AgentWorkerManagementResult, ManagedWorkerError,
    ManagedWorkerSessionStatus,
};

use crate::{
    backends::{firecracker_host_preflight, firecracker_microvm_provision, isolation_backends},
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
    let Some(backend) = isolation_backends()
        .into_iter()
        .find(|backend| backend.backend_name == "firecracker")
    else {
        return Err(ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::IncompatibleBackend,
            "agent-worker Firecracker backend registry returned no firecracker backend",
        ));
    };

    if !backend.ready {
        return Err(ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::IncompatibleBackend,
            backend
                .readiness_reason
                .unwrap_or_else(|| "Firecracker backend is not ready".to_string()),
        ));
    }

    let preflight = firecracker_host_preflight();
    if !preflight.ready() {
        let message = preflight.failure_summary();
        let lifecycle = lifecycle_result(
            envelope,
            ManagedWorkerSessionStatus::Failed,
            "host_preflight_failed",
            &message,
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(existing) = state.get_firecracker_microvm_mut(&session_id, &run_id) {
        let running = existing.is_running();
        let lifecycle = lifecycle_result_with_instance(
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
            Some(existing.instance_id.clone()),
        )?;
        return Ok(Some(AgentWorkerManagementResult::Lifecycle { lifecycle }));
    }

    let mut microvm = firecracker_microvm_provision(30_000, 1, 512).map_err(|error| {
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
    let lifecycle = lifecycle_result(
        envelope,
        ManagedWorkerSessionStatus::Running,
        "provisioned",
        &message,
    )?;
    Ok(Some(AgentWorkerManagementResult::Lifecycle {
        lifecycle: AgentWorkerLifecycleResult {
            isolation_instance_id: Some(instance_id),
            ..lifecycle
        },
    }))
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

fn cleanup(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(mut existing) = state.remove_firecracker_microvm(&session_id, &run_id) {
        let instance_id = existing.instance_id.clone();
        let was_running = existing.stop();
        let lifecycle = lifecycle_result_with_instance(
            envelope,
            ManagedWorkerSessionStatus::CleanedUp,
            "cleaned_up",
            &format!(
                "Firecracker microVM {instance_id} cleaned up by agent-worker; was_running={was_running}"
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

fn lifecycle_result(
    envelope: &AgentWorkerManagementEnvelope,
    status: ManagedWorkerSessionStatus,
    outcome: &str,
    message: &str,
) -> Result<AgentWorkerLifecycleResult, ManagedWorkerError> {
    Ok(AgentWorkerLifecycleResult {
        session_id: lifecycle_session_id(envelope)?,
        run_id: lifecycle_run_id(envelope)?,
        worker_id: envelope.worker_id.clone(),
        action: envelope.action,
        status,
        backend_name: "firecracker".to_string(),
        backend_kind: "firecracker_micro_vm".to_string(),
        isolation_instance_id: None,
        outcome: outcome.to_string(),
        message: message.to_string(),
    })
}

fn lifecycle_result_with_instance(
    envelope: &AgentWorkerManagementEnvelope,
    status: ManagedWorkerSessionStatus,
    outcome: &str,
    message: &str,
    isolation_instance_id: Option<String>,
) -> Result<AgentWorkerLifecycleResult, ManagedWorkerError> {
    Ok(AgentWorkerLifecycleResult {
        isolation_instance_id,
        ..lifecycle_result(envelope, status, outcome, message)?
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
