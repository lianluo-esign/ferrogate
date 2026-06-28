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

use crate::backends::isolation_backends;

pub(crate) fn dispatch_lifecycle_action(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    match envelope.action {
        AgentWorkerManagementAction::Provision => provision(envelope),
        AgentWorkerManagementAction::ExecOrAttach => lifecycle_not_started(
            envelope,
            AgentWorkerManagementErrorCode::RunFailed,
            "agent-worker cannot exec_or_attach before Firecracker provision succeeds",
        ),
        AgentWorkerManagementAction::Stop => lifecycle_not_started(
            envelope,
            AgentWorkerManagementErrorCode::Cancelled,
            "agent-worker cannot stop a session before Firecracker provision succeeds",
        ),
        AgentWorkerManagementAction::Cleanup => cleanup(envelope),
        AgentWorkerManagementAction::StreamStatus => lifecycle_status(envelope),
        AgentWorkerManagementAction::CollectArtifacts => lifecycle_not_started(
            envelope,
            AgentWorkerManagementErrorCode::CleanupFailed,
            "agent-worker cannot collect artifacts before Firecracker provision succeeds",
        ),
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

fn cleanup(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
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
