// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker-owned management state.
//!
//! This module keeps idempotent action outcomes and lifecycle observations
//! inside the `agent-worker` process boundary. It is deliberately shaped as a
//! store trait so a Postgres/Supabase-backed implementation can replace the
//! in-memory smoke implementation without moving lifecycle behavior into the
//! gateway.

use std::collections::HashMap;

use ferrogate_runtime::{
    AgentWorkerLifecycleResult, AgentWorkerManagementAction, AgentWorkerManagementEnvelope,
    AgentWorkerManagementResponse, AgentWorkerManagementResult, ManagedWorkerError,
};

use crate::{backends::FirecrackerMicroVm, handler_runtime::HandlerRunState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredLifecycleEvent {
    pub(crate) tenant_id: String,
    pub(crate) workspace_id: String,
    pub(crate) worker_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) action: AgentWorkerManagementAction,
    pub(crate) outcome: String,
    pub(crate) status: ferrogate_runtime::ManagedWorkerSessionStatus,
    pub(crate) isolation_instance_id: Option<String>,
}

impl StoredLifecycleEvent {
    fn from_lifecycle(
        envelope: &AgentWorkerManagementEnvelope,
        lifecycle: &AgentWorkerLifecycleResult,
    ) -> Self {
        Self {
            tenant_id: envelope.tenant_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            worker_id: lifecycle.worker_id.clone(),
            session_id: lifecycle.session_id.clone(),
            run_id: lifecycle.run_id.clone(),
            action: lifecycle.action,
            outcome: lifecycle.outcome.clone(),
            status: lifecycle.status,
            isolation_instance_id: lifecycle.isolation_instance_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordedManagementOutcome {
    Fresh(AgentWorkerManagementResponse),
    Duplicate(AgentWorkerManagementResponse),
}

impl RecordedManagementOutcome {
    pub(crate) fn into_response(self) -> AgentWorkerManagementResponse {
        match self {
            Self::Fresh(response) | Self::Duplicate(response) => response,
        }
    }
}

pub(crate) trait AgentWorkerStateStore {
    fn replay_idempotent_response(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
        current_response: &AgentWorkerManagementResponse,
    ) -> Option<AgentWorkerManagementResponse>;

    fn record_management_response(
        &mut self,
        envelope: &AgentWorkerManagementEnvelope,
        response: AgentWorkerManagementResponse,
    ) -> Result<RecordedManagementOutcome, ManagedWorkerError>;

    fn get_handler_run_state(&self, session_id: &str, run_id: &str) -> Option<HandlerRunState>;

    fn put_handler_run_state(&mut self, state: HandlerRunState);

    fn get_firecracker_microvm_mut(
        &mut self,
        session_id: &str,
        run_id: &str,
    ) -> Option<&mut FirecrackerMicroVm>;

    fn put_firecracker_microvm(
        &mut self,
        session_id: String,
        run_id: String,
        vm: FirecrackerMicroVm,
    );

    fn remove_firecracker_microvm(
        &mut self,
        session_id: &str,
        run_id: &str,
    ) -> Option<FirecrackerMicroVm>;

    #[cfg(test)]
    fn lifecycle_events(&self) -> Vec<StoredLifecycleEvent>;
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryAgentWorkerStateStore {
    idempotent_responses: HashMap<String, AgentWorkerManagementResponse>,
    lifecycle_events: Vec<StoredLifecycleEvent>,
    handler_runs: HashMap<String, HandlerRunState>,
    firecracker_vms: HashMap<String, FirecrackerMicroVm>,
}

impl InMemoryAgentWorkerStateStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn scoped_idempotency_key(envelope: &AgentWorkerManagementEnvelope) -> String {
        [
            envelope.tenant_id.clone(),
            envelope.workspace_id.clone(),
            envelope.idempotency_key.clone(),
        ]
        .join("\n")
    }

    fn response_for_duplicate(
        previous: &AgentWorkerManagementResponse,
        current: &AgentWorkerManagementResponse,
    ) -> AgentWorkerManagementResponse {
        let mut response = previous.clone();
        response.protocol_version = current.protocol_version;
        response.request_id = current.request_id.clone();
        response.idempotency_key = current.idempotency_key.clone();
        response.action = current.action;
        response.tenant_id = current.tenant_id.clone();
        response.workspace_id = current.workspace_id.clone();
        response.worker_id = current.worker_id.clone();
        response.session_id = current.session_id.clone();
        response.run_id = current.run_id.clone();
        response.duplicate_idempotency_key = true;
        response
    }

    fn record_lifecycle_event_if_present(
        &mut self,
        envelope: &AgentWorkerManagementEnvelope,
        response: &AgentWorkerManagementResponse,
    ) {
        if let Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) = &response.result {
            self.lifecycle_events
                .push(StoredLifecycleEvent::from_lifecycle(envelope, lifecycle));
        }
    }

    fn handler_run_key(session_id: &str, run_id: &str) -> String {
        [session_id, run_id].join("\n")
    }

    fn microvm_key(session_id: &str, run_id: &str) -> String {
        [session_id, run_id].join("\n")
    }
}

impl AgentWorkerStateStore for InMemoryAgentWorkerStateStore {
    fn replay_idempotent_response(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
        current_response: &AgentWorkerManagementResponse,
    ) -> Option<AgentWorkerManagementResponse> {
        let key = Self::scoped_idempotency_key(envelope);
        self.idempotent_responses
            .get(&key)
            .map(|previous| Self::response_for_duplicate(previous, current_response))
    }

    fn record_management_response(
        &mut self,
        envelope: &AgentWorkerManagementEnvelope,
        response: AgentWorkerManagementResponse,
    ) -> Result<RecordedManagementOutcome, ManagedWorkerError> {
        let key = Self::scoped_idempotency_key(envelope);
        if let Some(previous) = self.idempotent_responses.get(&key) {
            return Ok(RecordedManagementOutcome::Duplicate(
                Self::response_for_duplicate(previous, &response),
            ));
        }

        self.record_lifecycle_event_if_present(envelope, &response);
        self.idempotent_responses.insert(key, response.clone());
        Ok(RecordedManagementOutcome::Fresh(response))
    }

    fn get_handler_run_state(&self, session_id: &str, run_id: &str) -> Option<HandlerRunState> {
        self.handler_runs
            .get(&Self::handler_run_key(session_id, run_id))
            .cloned()
    }

    fn put_handler_run_state(&mut self, state: HandlerRunState) {
        self.handler_runs.insert(
            Self::handler_run_key(&state.session.session_id, &state.session.run_id),
            state,
        );
    }

    fn get_firecracker_microvm_mut(
        &mut self,
        session_id: &str,
        run_id: &str,
    ) -> Option<&mut FirecrackerMicroVm> {
        self.firecracker_vms
            .get_mut(&Self::microvm_key(session_id, run_id))
    }

    fn put_firecracker_microvm(
        &mut self,
        session_id: String,
        run_id: String,
        vm: FirecrackerMicroVm,
    ) {
        self.firecracker_vms
            .insert(Self::microvm_key(&session_id, &run_id), vm);
    }

    fn remove_firecracker_microvm(
        &mut self,
        session_id: &str,
        run_id: &str,
    ) -> Option<FirecrackerMicroVm> {
        self.firecracker_vms
            .remove(&Self::microvm_key(session_id, run_id))
    }

    #[cfg(test)]
    fn lifecycle_events(&self) -> Vec<StoredLifecycleEvent> {
        self.lifecycle_events.clone()
    }
}
