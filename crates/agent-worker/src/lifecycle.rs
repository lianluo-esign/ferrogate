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
    backends::isolation_backends,
    external_actions::GatewayExternalActionAuthorizer,
    handler_runtime::{
        cancel_native_harness, cleanup_native_harness, collect_native_harness_artifacts,
        exec_or_attach_framework_handler_with_authorizer, stream_native_harness_status,
    },
    state::AgentWorkerStateStore,
};

pub(crate) fn dispatch_lifecycle_action(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    external_action_authorizer: Option<&dyn GatewayExternalActionAuthorizer>,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    match envelope.action {
        AgentWorkerManagementAction::Provision => provision(envelope),
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
    _envelope: &AgentWorkerManagementEnvelope,
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

    Err(ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::ProvisionFailed,
        "Firecracker backend is configured, but microVM provision/start lifecycle is not implemented in agent-worker yet",
    ))
}

fn exec_or_attach(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
    external_action_authorizer: Option<&dyn GatewayExternalActionAuthorizer>,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
    if let Some(existing) = state.get_handler_run_state(&session_id, &run_id) {
        return Ok(Some(stream_native_harness_status(&existing)));
    }
    let (handler_state, result) =
        exec_or_attach_framework_handler_with_authorizer(envelope, external_action_authorizer)?;
    state.put_handler_run_state(handler_state);
    Ok(Some(result))
}

fn stream_status(
    state: &mut impl AgentWorkerStateStore,
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    let session_id = lifecycle_session_id(envelope)?;
    let run_id = lifecycle_run_id(envelope)?;
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
