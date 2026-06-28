// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker-owned framework handler execution.
//!
//! This module is deliberately inside `agent-worker`. The gateway management
//! API may ask for lifecycle actions, but framework handler execution and event
//! normalization stay on the worker side.

use std::collections::HashMap;

use ferrogate_runtime::{
    AgentWorkerFrameworkArtifactResult, AgentWorkerFrameworkEventResult,
    AgentWorkerManagementEnvelope, AgentWorkerManagementErrorCode, AgentWorkerManagementResult,
    FrameworkAdapter, FrameworkAdapterArtifact, FrameworkAdapterArtifactRequest,
    FrameworkAdapterCapabilities, FrameworkAdapterMode, FrameworkAdapterRunRequest,
    FrameworkAdapterSession, FrameworkAdapterSessionRequest, ManagedWorkerError,
    NativeHarnessAdapter, NormalizedFrameworkEvent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerRunState {
    pub(crate) session: FrameworkAdapterSession,
    pub(crate) events: Vec<NormalizedFrameworkEvent>,
    pub(crate) artifacts: Vec<FrameworkAdapterArtifact>,
    pub(crate) closed: bool,
}

pub(crate) fn exec_or_attach_native_harness(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<(HandlerRunState, AgentWorkerManagementResult), ManagedWorkerError> {
    let mut adapter = NativeHarnessAdapter::default();
    let session_request = FrameworkAdapterSessionRequest {
        session_id: lifecycle_session_id(envelope)?,
        run_id: lifecycle_run_id(envelope)?,
        tenant_id: envelope.tenant_id.clone(),
        workspace_id: envelope.workspace_id.clone(),
        worker_id: envelope.worker_id.clone(),
        isolation_backend: "firecracker".to_string(),
        mode: FrameworkAdapterMode::Managed,
        required_capabilities: FrameworkAdapterCapabilities {
            tools: true,
            checkpoint: true,
            artifacts: true,
            streaming: true,
            ..FrameworkAdapterCapabilities::default()
        },
    };
    let (session, started) = adapter
        .start_session(session_request)
        .map_err(handler_runtime_error)?;
    let mut events = vec![started];
    events.extend(
        adapter
            .submit_run(FrameworkAdapterRunRequest {
                session: session.clone(),
                input_ref: format!("managed://{}/{}", session.session_id, session.run_id),
            })
            .map_err(handler_runtime_error)?,
    );
    let artifacts = adapter
        .collect_artifacts(FrameworkAdapterArtifactRequest {
            session: session.clone(),
            artifact_id: Some("native-artifact".to_string()),
        })
        .map_err(handler_runtime_error)?;
    events.push(artifacts.event.clone());
    let closed = adapter
        .close_session(&session)
        .map_err(handler_runtime_error)?;
    events.push(closed);
    let state = HandlerRunState {
        session,
        events: events.clone(),
        artifacts: artifacts.artifacts.clone(),
        closed: true,
    };
    Ok((
        state,
        AgentWorkerManagementResult::HandlerEvents {
            events: events.into_iter().map(event_result).collect(),
        },
    ))
}

pub(crate) fn stream_native_harness_status(state: &HandlerRunState) -> AgentWorkerManagementResult {
    AgentWorkerManagementResult::HandlerEvents {
        events: state.events.iter().cloned().map(event_result).collect(),
    }
}

pub(crate) fn collect_native_harness_artifacts(
    state: &HandlerRunState,
) -> AgentWorkerManagementResult {
    AgentWorkerManagementResult::HandlerArtifacts {
        artifacts: state
            .artifacts
            .iter()
            .cloned()
            .map(artifact_result)
            .collect(),
        events: state.events.iter().cloned().map(event_result).collect(),
    }
}

pub(crate) fn cancel_native_harness(
    state: &mut HandlerRunState,
) -> Result<AgentWorkerManagementResult, ManagedWorkerError> {
    let mut adapter = NativeHarnessAdapter::default();
    let cancelled = adapter
        .cancel_run(&state.session)
        .map_err(handler_runtime_error)?;
    state.events.push(cancelled.clone());
    Ok(AgentWorkerManagementResult::HandlerEvents {
        events: vec![event_result(cancelled)],
    })
}

pub(crate) fn cleanup_native_harness(
    state: &mut HandlerRunState,
) -> Result<AgentWorkerManagementResult, ManagedWorkerError> {
    if state.closed {
        return Ok(AgentWorkerManagementResult::HandlerEvents { events: vec![] });
    }
    let mut adapter = NativeHarnessAdapter::default();
    let closed = adapter
        .close_session(&state.session)
        .map_err(handler_runtime_error)?;
    state.closed = true;
    state.events.push(closed.clone());
    Ok(AgentWorkerManagementResult::HandlerEvents {
        events: vec![event_result(closed)],
    })
}

fn event_result(event: NormalizedFrameworkEvent) -> AgentWorkerFrameworkEventResult {
    AgentWorkerFrameworkEventResult {
        session_id: event.session_id,
        run_id: event.run_id,
        adapter_name: event.adapter_name,
        adapter_version: event.adapter_version,
        framework: event.framework.as_str().to_string(),
        mode: event.mode.as_str().to_string(),
        kind: event.kind.as_str().to_string(),
        message: event.message,
        metadata: event.metadata.into_iter().collect::<HashMap<_, _>>(),
    }
}

fn artifact_result(artifact: FrameworkAdapterArtifact) -> AgentWorkerFrameworkArtifactResult {
    AgentWorkerFrameworkArtifactResult {
        artifact_id: artifact.artifact_id,
        name: artifact.name,
        media_type: artifact.media_type,
        byte_len: artifact.byte_len,
    }
}

fn handler_runtime_error(error: ferrogate_runtime::FrameworkAdapterError) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::RunFailed,
        format!("agent-worker native harness handler failed: {error}"),
    )
}

fn lifecycle_session_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.session_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "session_id is required for handler execution",
        )
    })
}

fn lifecycle_run_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.run_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "run_id is required for handler execution",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{
        AgentWorkerManagementAction, AgentWorkerManagementSecurity, AgentWorkerSecurityAlgorithm,
        AgentWorkerTransportSecurity, AGENT_WORKER_PROTOCOL_VERSION,
    };

    #[test]
    fn native_harness_execution_returns_normalized_worker_events() {
        let envelope = envelope();

        let (state, result) = exec_or_attach_native_harness(&envelope).unwrap();

        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert_eq!(state.session.adapter_name, "native-harness");
        assert!(state.closed);
        assert!(events.iter().any(|event| event.kind == "session.started"
            && event.framework == "native_harness"
            && event.mode == "managed"));
        assert!(events.iter().any(|event| event.kind == "run.completed"));
        assert!(events.iter().any(|event| event.kind == "session.closed"));
        assert_eq!(state.artifacts[0].artifact_id, "native-artifact");
    }

    #[test]
    fn native_harness_artifacts_reuse_recorded_worker_state() {
        let (state, _) = exec_or_attach_native_harness(&envelope()).unwrap();

        let result = collect_native_harness_artifacts(&state);

        let AgentWorkerManagementResult::HandlerArtifacts { artifacts, events } = result else {
            panic!("expected handler artifacts");
        };
        assert_eq!(artifacts[0].artifact_id, "native-artifact");
        assert!(events.iter().any(|event| event.kind == "artifact.created"));
    }

    fn envelope() -> AgentWorkerManagementEnvelope {
        AgentWorkerManagementEnvelope {
            protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
            action: AgentWorkerManagementAction::ExecOrAttach,
            request_id: "handler-request".to_string(),
            idempotency_key: "handler-idempotency".to_string(),
            issued_at_unix_millis: 900,
            deadline_unix_millis: 2_000,
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            session_id: Some("session-1".to_string()),
            run_id: Some("run-1".to_string()),
            security: AgentWorkerManagementSecurity {
                key_id: "key-1".to_string(),
                nonce: "nonce-1".to_string(),
                signature: "signature-1".to_string(),
                algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
                transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
                encrypted: true,
            },
        }
    }
}
