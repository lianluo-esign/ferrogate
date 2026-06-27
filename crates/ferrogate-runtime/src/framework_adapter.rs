// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker framework adapter contract.
//!
//! Adapters translate framework-specific behavior into the FerroGate worker
//! protocol. Public control-plane APIs should depend on these normalized
//! capabilities and events, not on Claude Code, Codex, Hermes, or native
//! harness internals.

use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedFramework {
    ClaudeCode,
    Codex,
    Hermes,
    NativeHarness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameworkAdapterMode {
    Managed,
    SelfHosted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameworkAdapterCapabilities {
    pub tools: bool,
    pub mcp: bool,
    pub memory_read: bool,
    pub memory_write: bool,
    pub checkpoint: bool,
    pub artifacts: bool,
    pub subagents: bool,
    pub filesystem: bool,
    pub shell: bool,
    pub browser: bool,
    pub rest_egress: bool,
    pub secrets_read: bool,
    pub streaming: bool,
}

impl FrameworkAdapterCapabilities {
    pub fn supports(&self, required: &Self) -> bool {
        (!required.tools || self.tools)
            && (!required.mcp || self.mcp)
            && (!required.memory_read || self.memory_read)
            && (!required.memory_write || self.memory_write)
            && (!required.checkpoint || self.checkpoint)
            && (!required.artifacts || self.artifacts)
            && (!required.subagents || self.subagents)
            && (!required.filesystem || self.filesystem)
            && (!required.shell || self.shell)
            && (!required.browser || self.browser)
            && (!required.rest_egress || self.rest_egress)
            && (!required.secrets_read || self.secrets_read)
            && (!required.streaming || self.streaming)
    }

    pub fn native_harness() -> Self {
        Self {
            tools: true,
            mcp: true,
            checkpoint: true,
            artifacts: true,
            streaming: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterDescriptor {
    pub name: String,
    pub version: String,
    pub framework: SupportedFramework,
    pub capabilities: FrameworkAdapterCapabilities,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterSessionRequest {
    pub session_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub mode: FrameworkAdapterMode,
    pub required_capabilities: FrameworkAdapterCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterSession {
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub adapter_version: String,
    pub framework: SupportedFramework,
    pub mode: FrameworkAdapterMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterRunRequest {
    pub session: FrameworkAdapterSession,
    pub input_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameworkAdapterEventKind {
    SessionStarted,
    RunStarted,
    CapabilityRequested,
    CapabilityAllowed,
    CapabilityDenied,
    ModelRequested,
    ToolRequested,
    ToolApproved,
    ToolDenied,
    ToolCompleted,
    McpToolRequested,
    CliRequested,
    RestRequested,
    MemoryRead,
    MemoryWrite,
    CheckpointCreated,
    ArtifactCreated,
    RunCompleted,
    RunFailed,
    RunCancelled,
    SessionClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFrameworkEvent {
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub adapter_version: String,
    pub framework: SupportedFramework,
    pub mode: FrameworkAdapterMode,
    pub kind: FrameworkAdapterEventKind,
    pub message: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

pub trait FrameworkAdapter {
    fn descriptor(&self) -> &FrameworkAdapterDescriptor;
    fn start_session(
        &mut self,
        request: FrameworkAdapterSessionRequest,
    ) -> Result<(FrameworkAdapterSession, NormalizedFrameworkEvent), FrameworkAdapterError>;
    fn submit_run(
        &mut self,
        request: FrameworkAdapterRunRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>;
    fn cancel_run(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError>;
    fn close_session(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError>;
}

#[derive(Debug, Clone)]
pub struct NativeHarnessAdapter {
    descriptor: FrameworkAdapterDescriptor,
}

impl Default for NativeHarnessAdapter {
    fn default() -> Self {
        Self {
            descriptor: FrameworkAdapterDescriptor {
                name: "native-harness".to_string(),
                version: "1".to_string(),
                framework: SupportedFramework::NativeHarness,
                capabilities: FrameworkAdapterCapabilities::native_harness(),
                enabled: true,
            },
        }
    }
}

impl FrameworkAdapter for NativeHarnessAdapter {
    fn descriptor(&self) -> &FrameworkAdapterDescriptor {
        &self.descriptor
    }

    fn start_session(
        &mut self,
        request: FrameworkAdapterSessionRequest,
    ) -> Result<(FrameworkAdapterSession, NormalizedFrameworkEvent), FrameworkAdapterError> {
        validate_session_request(&request)?;
        validate_descriptor(&self.descriptor)?;
        if !self
            .descriptor
            .capabilities
            .supports(&request.required_capabilities)
        {
            return Err(FrameworkAdapterError::CapabilityDenied(
                "adapter does not satisfy required capabilities".to_string(),
            ));
        }
        let session = FrameworkAdapterSession {
            session_id: request.session_id,
            run_id: request.run_id,
            adapter_name: self.descriptor.name.clone(),
            adapter_version: self.descriptor.version.clone(),
            framework: self.descriptor.framework,
            mode: request.mode,
        };
        let event = normalized_event(
            &session,
            FrameworkAdapterEventKind::SessionStarted,
            Some("native harness session started".to_string()),
            [("worker_id", request.worker_id.as_str())],
        );
        Ok((session, event))
    }

    fn submit_run(
        &mut self,
        request: FrameworkAdapterRunRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        if request.input_ref.trim().is_empty() {
            return Err(FrameworkAdapterError::InvalidRequest(
                "input_ref must not be empty".to_string(),
            ));
        }
        let session = request.session;
        Ok(vec![
            normalized_event(
                &session,
                FrameworkAdapterEventKind::RunStarted,
                Some("native harness run started".to_string()),
                [("input_ref", request.input_ref.as_str())],
            ),
            normalized_event(
                &session,
                FrameworkAdapterEventKind::ToolRequested,
                Some("native harness requested governed tool dispatch".to_string()),
                [("tool", "native.echo")],
            ),
            normalized_event(
                &session,
                FrameworkAdapterEventKind::CheckpointCreated,
                Some("native harness checkpoint created".to_string()),
                [("checkpoint_id", "native-checkpoint")],
            ),
            normalized_event(
                &session,
                FrameworkAdapterEventKind::ArtifactCreated,
                Some("native harness artifact created".to_string()),
                [("artifact_id", "native-artifact")],
            ),
            normalized_event(
                &session,
                FrameworkAdapterEventKind::RunCompleted,
                Some("native harness run completed".to_string()),
                [],
            ),
        ])
    }

    fn cancel_run(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
        Ok(normalized_event(
            session,
            FrameworkAdapterEventKind::RunCancelled,
            Some("native harness run cancelled".to_string()),
            [],
        ))
    }

    fn close_session(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
        Ok(normalized_event(
            session,
            FrameworkAdapterEventKind::SessionClosed,
            Some("native harness session closed".to_string()),
            [],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameworkAdapterError {
    InvalidDescriptor(String),
    InvalidRequest(String),
    CapabilityDenied(String),
}

impl fmt::Display for FrameworkAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDescriptor(message) => {
                write!(formatter, "invalid framework adapter descriptor: {message}")
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid framework adapter request: {message}")
            }
            Self::CapabilityDenied(message) => {
                write!(formatter, "framework adapter capability denied: {message}")
            }
        }
    }
}

impl Error for FrameworkAdapterError {}

fn validate_descriptor(
    descriptor: &FrameworkAdapterDescriptor,
) -> Result<(), FrameworkAdapterError> {
    if !descriptor.enabled {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "adapter is disabled".to_string(),
        ));
    }
    if descriptor.name.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "name must not be empty".to_string(),
        ));
    }
    if descriptor.version.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "version must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_session_request(
    request: &FrameworkAdapterSessionRequest,
) -> Result<(), FrameworkAdapterError> {
    require_request_field("session_id", &request.session_id)?;
    require_request_field("run_id", &request.run_id)?;
    require_request_field("tenant_id", &request.tenant_id)?;
    require_request_field("workspace_id", &request.workspace_id)?;
    require_request_field("worker_id", &request.worker_id)?;
    Ok(())
}

fn require_request_field(field: &str, value: &str) -> Result<(), FrameworkAdapterError> {
    if value.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn normalized_event<'a>(
    session: &FrameworkAdapterSession,
    kind: FrameworkAdapterEventKind,
    message: Option<String>,
    metadata: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> NormalizedFrameworkEvent {
    NormalizedFrameworkEvent {
        session_id: session.session_id.clone(),
        run_id: session.run_id.clone(),
        adapter_name: session.adapter_name.clone(),
        adapter_version: session.adapter_version.clone(),
        framework: session.framework,
        mode: session.mode,
        kind,
        message,
        metadata: metadata
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_harness_adapter_emits_normalized_event_stream() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, started) = adapter.start_session(session_request()).unwrap();
        let events = adapter
            .submit_run(FrameworkAdapterRunRequest {
                session: session.clone(),
                input_ref: "input://run-1".to_string(),
            })
            .unwrap();
        let closed = adapter.close_session(&session).unwrap();

        assert_eq!(started.kind, FrameworkAdapterEventKind::SessionStarted);
        assert_eq!(started.framework, SupportedFramework::NativeHarness);
        assert_eq!(started.mode, FrameworkAdapterMode::Managed);
        assert_eq!(
            events.iter().map(|event| event.kind).collect::<Vec<_>>(),
            vec![
                FrameworkAdapterEventKind::RunStarted,
                FrameworkAdapterEventKind::ToolRequested,
                FrameworkAdapterEventKind::CheckpointCreated,
                FrameworkAdapterEventKind::ArtifactCreated,
                FrameworkAdapterEventKind::RunCompleted,
            ]
        );
        assert!(events
            .iter()
            .all(|event| event.adapter_name == "native-harness"
                && event.session_id == "session-1"
                && event.run_id == "run-1"));
        assert_eq!(closed.kind, FrameworkAdapterEventKind::SessionClosed);
    }

    #[test]
    fn denies_session_when_required_capability_is_missing() {
        let mut adapter = NativeHarnessAdapter::default();
        let request = FrameworkAdapterSessionRequest {
            required_capabilities: FrameworkAdapterCapabilities {
                shell: true,
                ..FrameworkAdapterCapabilities::default()
            },
            ..session_request()
        };

        let error = adapter.start_session(request).unwrap_err();

        assert!(matches!(error, FrameworkAdapterError::CapabilityDenied(_)));
    }

    #[test]
    fn validates_descriptor_before_session_start() {
        let mut adapter = NativeHarnessAdapter {
            descriptor: FrameworkAdapterDescriptor {
                enabled: false,
                ..NativeHarnessAdapter::default().descriptor
            },
        };

        let error = adapter.start_session(session_request()).unwrap_err();

        assert!(matches!(error, FrameworkAdapterError::InvalidDescriptor(_)));
    }

    #[test]
    fn self_hosted_mode_keeps_same_normalized_event_schema() {
        let mut adapter = NativeHarnessAdapter::default();
        let request = FrameworkAdapterSessionRequest {
            mode: FrameworkAdapterMode::SelfHosted,
            ..session_request()
        };

        let (session, event) = adapter.start_session(request).unwrap();

        assert_eq!(session.mode, FrameworkAdapterMode::SelfHosted);
        assert_eq!(event.mode, FrameworkAdapterMode::SelfHosted);
        assert_eq!(event.kind, FrameworkAdapterEventKind::SessionStarted);
        assert_eq!(
            event.metadata.get("worker_id").map(String::as_str),
            Some("worker-1")
        );
    }

    fn session_request() -> FrameworkAdapterSessionRequest {
        FrameworkAdapterSessionRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            mode: FrameworkAdapterMode::Managed,
            required_capabilities: FrameworkAdapterCapabilities {
                tools: true,
                checkpoint: true,
                artifacts: true,
                ..FrameworkAdapterCapabilities::default()
            },
        }
    }
}
