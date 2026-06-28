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

use crate::{
    self_hosted_trust_level_for_capability_report, CapabilityAction,
    CapabilityAuthorizationDecision, CapabilityAuthorizationEvidence, CapabilityAuthorizer,
    ManagedCapabilityRequest, SelfHostedTelemetryTrustLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedFramework {
    ClaudeCode,
    Codex,
    Hermes,
    NativeHarness,
}

impl SupportedFramework {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::Hermes => "hermes",
            Self::NativeHarness => "native_harness",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameworkAdapterMode {
    Managed,
    SelfHosted,
}

impl FrameworkAdapterMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::SelfHosted => "self_hosted",
        }
    }
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

    pub fn code_process_shim() -> Self {
        Self {
            tools: true,
            mcp: true,
            checkpoint: true,
            artifacts: true,
            filesystem: true,
            shell: true,
            streaming: true,
            ..Self::default()
        }
    }

    pub fn hermes_process_shim() -> Self {
        Self {
            tools: true,
            mcp: true,
            memory_read: true,
            memory_write: true,
            checkpoint: true,
            artifacts: true,
            subagents: true,
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
    pub isolation_backend: String,
    pub mode: FrameworkAdapterMode,
    pub required_capabilities: FrameworkAdapterCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterSession {
    pub session_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub isolation_backend: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterResumeRequest {
    pub session: FrameworkAdapterSession,
    pub checkpoint_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterStreamRequest {
    pub session: FrameworkAdapterSession,
    pub after_event_id: Option<String>,
    pub max_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterArtifactRequest {
    pub session: FrameworkAdapterSession,
    pub artifact_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterArtifact {
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkAdapterArtifacts {
    pub artifacts: Vec<FrameworkAdapterArtifact>,
    pub event: NormalizedFrameworkEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkCapabilityRequest {
    pub session: FrameworkAdapterSession,
    pub action: CapabilityAction,
    pub target: String,
    pub high_risk: bool,
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

impl FrameworkAdapterEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionStarted => "session.started",
            Self::RunStarted => "run.started",
            Self::CapabilityRequested => "capability.requested",
            Self::CapabilityAllowed => "capability.allowed",
            Self::CapabilityDenied => "capability.denied",
            Self::ModelRequested => "model.requested",
            Self::ToolRequested => "tool.requested",
            Self::ToolApproved => "tool.approved",
            Self::ToolDenied => "tool.denied",
            Self::ToolCompleted => "tool.completed",
            Self::McpToolRequested => "mcp.tool.requested",
            Self::CliRequested => "cli.requested",
            Self::RestRequested => "rest.requested",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::CheckpointCreated => "checkpoint.created",
            Self::ArtifactCreated => "artifact.created",
            Self::RunCompleted => "run.completed",
            Self::RunFailed => "run.failed",
            Self::RunCancelled => "run.cancelled",
            Self::SessionClosed => "session.closed",
        }
    }
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

impl NormalizedFrameworkEvent {
    pub fn timeline_record(&self) -> Result<FrameworkEventTimelineRecord, FrameworkAdapterError> {
        validate_event_field("session_id", &self.session_id)?;
        validate_event_field("run_id", &self.run_id)?;
        validate_event_field("adapter_name", &self.adapter_name)?;
        validate_event_field("adapter_version", &self.adapter_version)?;
        let event_json = serde_json::to_string(&self.canonical_json())
            .map_err(|error| FrameworkAdapterError::InvalidRequest(error.to_string()))?;
        let event_hash = fnv1a64_hex(&event_json);
        Ok(FrameworkEventTimelineRecord {
            event_id: format!(
                "framework:{}:{}:{}:{}:{}",
                self.run_id,
                self.session_id,
                self.adapter_name,
                self.kind.as_str(),
                event_hash
            ),
            run_id: self.run_id.clone(),
            kind: self.kind.as_str().to_string(),
            target: self.timeline_target(),
            outcome: self.timeline_outcome().to_string(),
            message: self.message.clone(),
            event_json,
        })
    }

    pub fn canonical_json(&self) -> serde_json::Value {
        serde_json::json!({
            "session_id": self.session_id,
            "run_id": self.run_id,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "framework": self.framework.as_str(),
            "mode": self.mode.as_str(),
            "kind": self.kind.as_str(),
            "message": self.message,
            "metadata": self.metadata,
        })
    }

    fn timeline_target(&self) -> String {
        if let Some(target) = self
            .metadata
            .get("target")
            .filter(|value| !value.is_empty())
        {
            return target.clone();
        }
        if let Some(tool) = self.metadata.get("tool").filter(|value| !value.is_empty()) {
            return format!("tool:{tool}");
        }
        if let Some(artifact_id) = self
            .metadata
            .get("artifact_id")
            .filter(|value| !value.is_empty())
        {
            return format!("artifact:{artifact_id}");
        }
        if let Some(checkpoint_id) = self
            .metadata
            .get("checkpoint_id")
            .filter(|value| !value.is_empty())
        {
            return format!("checkpoint:{checkpoint_id}");
        }
        format!("adapter:{}", self.adapter_name)
    }

    fn timeline_outcome(&self) -> &'static str {
        if let Some(decision) = self.metadata.get("decision") {
            return match decision.as_str() {
                "allowed" => "allowed",
                "denied" => "denied",
                "approval_required" => "approval_required",
                _ => "recorded",
            };
        }
        match self.kind {
            FrameworkAdapterEventKind::SessionStarted
            | FrameworkAdapterEventKind::RunStarted
            | FrameworkAdapterEventKind::CapabilityRequested
            | FrameworkAdapterEventKind::ModelRequested
            | FrameworkAdapterEventKind::ToolRequested
            | FrameworkAdapterEventKind::McpToolRequested
            | FrameworkAdapterEventKind::CliRequested
            | FrameworkAdapterEventKind::RestRequested => "requested",
            FrameworkAdapterEventKind::CapabilityAllowed
            | FrameworkAdapterEventKind::ToolApproved => "allowed",
            FrameworkAdapterEventKind::CapabilityDenied | FrameworkAdapterEventKind::ToolDenied => {
                "denied"
            }
            FrameworkAdapterEventKind::ToolCompleted
            | FrameworkAdapterEventKind::MemoryRead
            | FrameworkAdapterEventKind::MemoryWrite
            | FrameworkAdapterEventKind::CheckpointCreated
            | FrameworkAdapterEventKind::ArtifactCreated
            | FrameworkAdapterEventKind::RunCompleted
            | FrameworkAdapterEventKind::SessionClosed => "success",
            FrameworkAdapterEventKind::RunFailed => "failed",
            FrameworkAdapterEventKind::RunCancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkEventTimelineRecord {
    pub event_id: String,
    pub run_id: String,
    pub kind: String,
    pub target: String,
    pub outcome: String,
    pub message: Option<String>,
    pub event_json: String,
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
    fn resume_run(
        &mut self,
        request: FrameworkAdapterResumeRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>;
    fn stream_events(
        &mut self,
        request: FrameworkAdapterStreamRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>;
    fn collect_artifacts(
        &mut self,
        request: FrameworkAdapterArtifactRequest,
    ) -> Result<FrameworkAdapterArtifacts, FrameworkAdapterError>;
    fn cancel_run(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError>;
    fn close_session(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFrameworkLaunch {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub working_dir: Option<String>,
}

impl ProcessFrameworkLaunch {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            working_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessFrameworkAdapter {
    descriptor: FrameworkAdapterDescriptor,
    launch: ProcessFrameworkLaunch,
}

impl ProcessFrameworkAdapter {
    pub fn claude_code() -> Self {
        Self::new(
            FrameworkAdapterDescriptor {
                name: "claude-code".to_string(),
                version: "1".to_string(),
                framework: SupportedFramework::ClaudeCode,
                capabilities: FrameworkAdapterCapabilities::code_process_shim(),
                enabled: true,
            },
            ProcessFrameworkLaunch::new("claude"),
        )
    }

    pub fn codex() -> Self {
        Self::new(
            FrameworkAdapterDescriptor {
                name: "codex".to_string(),
                version: "1".to_string(),
                framework: SupportedFramework::Codex,
                capabilities: FrameworkAdapterCapabilities::code_process_shim(),
                enabled: true,
            },
            ProcessFrameworkLaunch::new("codex"),
        )
    }

    pub fn hermes() -> Self {
        Self::new(
            FrameworkAdapterDescriptor {
                name: "hermes".to_string(),
                version: "1".to_string(),
                framework: SupportedFramework::Hermes,
                capabilities: FrameworkAdapterCapabilities::hermes_process_shim(),
                enabled: true,
            },
            ProcessFrameworkLaunch::new("hermes"),
        )
    }

    pub fn new(descriptor: FrameworkAdapterDescriptor, launch: ProcessFrameworkLaunch) -> Self {
        Self { descriptor, launch }
    }

    pub fn launch(&self) -> &ProcessFrameworkLaunch {
        &self.launch
    }
}

impl FrameworkAdapter for ProcessFrameworkAdapter {
    fn descriptor(&self) -> &FrameworkAdapterDescriptor {
        &self.descriptor
    }

    fn start_session(
        &mut self,
        request: FrameworkAdapterSessionRequest,
    ) -> Result<(FrameworkAdapterSession, NormalizedFrameworkEvent), FrameworkAdapterError> {
        validate_session_request(&request)?;
        validate_descriptor(&self.descriptor)?;
        validate_process_launch(&self.launch)?;
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
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            worker_id: request.worker_id.clone(),
            isolation_backend: request.isolation_backend,
            adapter_name: self.descriptor.name.clone(),
            adapter_version: self.descriptor.version.clone(),
            framework: self.descriptor.framework,
            mode: request.mode,
        };
        let event = normalized_event_owned(
            &session,
            FrameworkAdapterEventKind::SessionStarted,
            Some(format!(
                "{} process shim session prepared",
                self.descriptor.name
            )),
            self.process_metadata([
                ("worker_id".to_string(), request.worker_id),
                (
                    "handshake".to_string(),
                    "process_launch_prepared".to_string(),
                ),
            ]),
        );
        Ok((session, event))
    }

    fn submit_run(
        &mut self,
        request: FrameworkAdapterRunRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        require_request_field("input_ref", &request.input_ref)?;
        validate_process_launch(&self.launch)?;
        let session = request.session;
        Ok(vec![
            normalized_event_owned(
                &session,
                FrameworkAdapterEventKind::RunStarted,
                Some(format!(
                    "{} process shim run dispatch prepared",
                    self.descriptor.name
                )),
                self.process_metadata([("input_ref".to_string(), request.input_ref)]),
            ),
            normalized_event_owned(
                &session,
                FrameworkAdapterEventKind::ModelRequested,
                Some(format!(
                    "{} process shim model boundary prepared",
                    self.descriptor.name
                )),
                self.process_metadata([(
                    "target".to_string(),
                    format!("framework:{}", self.descriptor.framework.as_str()),
                )]),
            ),
        ])
    }

    fn resume_run(
        &mut self,
        request: FrameworkAdapterResumeRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        require_request_field("checkpoint_id", &request.checkpoint_id)?;
        validate_process_launch(&self.launch)?;
        let session = request.session;
        Ok(vec![normalized_event_owned(
            &session,
            FrameworkAdapterEventKind::RunStarted,
            Some(format!(
                "{} process shim resume prepared",
                self.descriptor.name
            )),
            self.process_metadata([("checkpoint_id".to_string(), request.checkpoint_id)]),
        )])
    }

    fn stream_events(
        &mut self,
        request: FrameworkAdapterStreamRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        if request.max_events == 0 {
            return Err(FrameworkAdapterError::InvalidRequest(
                "max_events must be greater than zero".to_string(),
            ));
        }
        validate_process_launch(&self.launch)?;
        let session = request.session;
        Ok(vec![normalized_event_owned(
            &session,
            FrameworkAdapterEventKind::RunStarted,
            Some(format!(
                "{} process shim stream replay prepared",
                self.descriptor.name
            )),
            self.process_metadata([
                (
                    "after_event_id".to_string(),
                    request.after_event_id.unwrap_or_default(),
                ),
                ("max_events".to_string(), request.max_events.to_string()),
            ]),
        )])
    }

    fn collect_artifacts(
        &mut self,
        request: FrameworkAdapterArtifactRequest,
    ) -> Result<FrameworkAdapterArtifacts, FrameworkAdapterError> {
        validate_process_launch(&self.launch)?;
        let artifact_id = request
            .artifact_id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("{}-artifact-manifest", self.descriptor.name));
        let event = normalized_event_owned(
            &request.session,
            FrameworkAdapterEventKind::ArtifactCreated,
            Some(format!(
                "{} process shim artifact manifest prepared",
                self.descriptor.name
            )),
            self.process_metadata([("artifact_id".to_string(), artifact_id.clone())]),
        );
        Ok(FrameworkAdapterArtifacts {
            artifacts: vec![FrameworkAdapterArtifact {
                artifact_id,
                name: format!("{}-artifact-manifest.json", self.descriptor.name),
                media_type: "application/json".to_string(),
                byte_len: 0,
            }],
            event,
        })
    }

    fn cancel_run(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
        validate_process_launch(&self.launch)?;
        Ok(normalized_event_owned(
            session,
            FrameworkAdapterEventKind::RunCancelled,
            Some(format!(
                "{} process shim cancel prepared",
                self.descriptor.name
            )),
            self.process_metadata([]),
        ))
    }

    fn close_session(
        &mut self,
        session: &FrameworkAdapterSession,
    ) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
        validate_process_launch(&self.launch)?;
        Ok(normalized_event_owned(
            session,
            FrameworkAdapterEventKind::SessionClosed,
            Some(format!(
                "{} process shim session closed",
                self.descriptor.name
            )),
            self.process_metadata([]),
        ))
    }
}

impl ProcessFrameworkAdapter {
    fn process_metadata(
        &self,
        extra: impl IntoIterator<Item = (String, String)>,
    ) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            ("process_shim".to_string(), "true".to_string()),
            ("sdk_bound".to_string(), "false".to_string()),
            ("launch_command".to_string(), self.launch.command.clone()),
            ("launch_args".to_string(), self.launch.args.join(" ")),
            (
                "launch_env_keys".to_string(),
                self.launch
                    .env
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "working_dir".to_string(),
                self.launch.working_dir.clone().unwrap_or_default(),
            ),
        ]);
        metadata.extend(extra);
        metadata
    }
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
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            worker_id: request.worker_id.clone(),
            isolation_backend: request.isolation_backend,
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

    fn resume_run(
        &mut self,
        request: FrameworkAdapterResumeRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        require_request_field("checkpoint_id", &request.checkpoint_id)?;
        let session = request.session;
        Ok(vec![
            normalized_event(
                &session,
                FrameworkAdapterEventKind::RunStarted,
                Some("native harness run resumed".to_string()),
                [("checkpoint_id", request.checkpoint_id.as_str())],
            ),
            normalized_event(
                &session,
                FrameworkAdapterEventKind::RunCompleted,
                Some("native harness resumed run completed".to_string()),
                [],
            ),
        ])
    }

    fn stream_events(
        &mut self,
        request: FrameworkAdapterStreamRequest,
    ) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError> {
        if request.max_events == 0 {
            return Err(FrameworkAdapterError::InvalidRequest(
                "max_events must be greater than zero".to_string(),
            ));
        }
        let session = request.session;
        Ok(vec![normalized_event(
            &session,
            FrameworkAdapterEventKind::RunStarted,
            Some("native harness stream replay".to_string()),
            [
                (
                    "after_event_id",
                    request.after_event_id.as_deref().unwrap_or(""),
                ),
                ("max_events", &request.max_events.to_string()),
            ],
        )])
    }

    fn collect_artifacts(
        &mut self,
        request: FrameworkAdapterArtifactRequest,
    ) -> Result<FrameworkAdapterArtifacts, FrameworkAdapterError> {
        let artifact_id = request
            .artifact_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or("native-artifact");
        let event = normalized_event(
            &request.session,
            FrameworkAdapterEventKind::ArtifactCreated,
            Some("native harness artifact collected".to_string()),
            [("artifact_id", artifact_id)],
        );
        Ok(FrameworkAdapterArtifacts {
            artifacts: vec![FrameworkAdapterArtifact {
                artifact_id: artifact_id.to_string(),
                name: "native-artifact.txt".to_string(),
                media_type: "text/plain".to_string(),
                byte_len: 0,
            }],
            event,
        })
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

pub fn authorize_framework_capability<A>(
    authorizer: &A,
    request: FrameworkCapabilityRequest,
) -> Result<(CapabilityAuthorizationEvidence, NormalizedFrameworkEvent), FrameworkAdapterError>
where
    A: CapabilityAuthorizer,
{
    if request.session.mode == FrameworkAdapterMode::SelfHosted {
        return Err(FrameworkAdapterError::InvalidRequest(
            "self-hosted adapters report capability telemetry; they do not use managed authorization"
                .to_string(),
        ));
    }
    let outcome = authorizer
        .authorize(ManagedCapabilityRequest {
            tenant_id: request.session.tenant_id.clone(),
            workspace_id: request.session.workspace_id.clone(),
            worker_id: request.session.worker_id.clone(),
            session_id: request.session.session_id.clone(),
            run_id: request.session.run_id.clone(),
            adapter_name: request.session.adapter_name.clone(),
            isolation_backend: request.session.isolation_backend.clone(),
            action: request.action,
            target: request.target,
            high_risk: request.high_risk,
        })
        .map_err(|error| FrameworkAdapterError::CapabilityDenied(error.to_string()))?;
    let kind = match outcome.decision {
        CapabilityAuthorizationDecision::Allowed => FrameworkAdapterEventKind::CapabilityAllowed,
        CapabilityAuthorizationDecision::Denied => FrameworkAdapterEventKind::CapabilityDenied,
        CapabilityAuthorizationDecision::ApprovalRequired => {
            FrameworkAdapterEventKind::CapabilityRequested
        }
    };
    let event = capability_authorization_event(&request.session, kind, &outcome.evidence);
    Ok((outcome.evidence, event))
}

pub fn self_hosted_framework_capability_report(
    request: FrameworkCapabilityRequest,
) -> Result<NormalizedFrameworkEvent, FrameworkAdapterError> {
    let trust_level = self_hosted_trust_level_for_capability_report(request.session.mode)
        .ok_or_else(|| {
            FrameworkAdapterError::InvalidRequest(
                "managed adapters require gateway capability authorization".to_string(),
            )
        })?;
    Ok(self_hosted_capability_report_event(
        &request.session,
        request.action,
        &request.target,
        trust_level,
    ))
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

fn validate_process_launch(launch: &ProcessFrameworkLaunch) -> Result<(), FrameworkAdapterError> {
    if launch.command.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "process launch command must not be empty".to_string(),
        ));
    }
    if launch.args.iter().any(|arg| arg.trim().is_empty()) {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "process launch args must not contain empty values".to_string(),
        ));
    }
    if launch.env.keys().any(|key| key.trim().is_empty()) {
        return Err(FrameworkAdapterError::InvalidDescriptor(
            "process launch env keys must not be empty".to_string(),
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
    require_request_field("isolation_backend", &request.isolation_backend)?;
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

fn validate_event_field(field: &str, value: &str) -> Result<(), FrameworkAdapterError> {
    if value.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "framework event {field} must not be empty"
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

fn normalized_event_owned(
    session: &FrameworkAdapterSession,
    kind: FrameworkAdapterEventKind,
    message: Option<String>,
    metadata: BTreeMap<String, String>,
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
        metadata,
    }
}

fn capability_authorization_event(
    session: &FrameworkAdapterSession,
    kind: FrameworkAdapterEventKind,
    evidence: &CapabilityAuthorizationEvidence,
) -> NormalizedFrameworkEvent {
    normalized_event(
        session,
        kind,
        Some(evidence.reason.clone()),
        [
            ("tenant_id", evidence.tenant_id.as_str()),
            ("workspace_id", evidence.workspace_id.as_str()),
            ("worker_id", evidence.worker_id.as_str()),
            ("action", evidence.action.as_str()),
            ("target", evidence.target.as_str()),
            ("decision", capability_decision_label(evidence.decision)),
            ("isolation_backend", evidence.isolation_backend.as_str()),
        ],
    )
}

fn self_hosted_capability_report_event(
    session: &FrameworkAdapterSession,
    action: CapabilityAction,
    target: &str,
    trust_level: SelfHostedTelemetryTrustLevel,
) -> NormalizedFrameworkEvent {
    normalized_event(
        session,
        FrameworkAdapterEventKind::CapabilityRequested,
        Some("self-hosted adapter reported capability use".to_string()),
        [
            ("tenant_id", session.tenant_id.as_str()),
            ("workspace_id", session.workspace_id.as_str()),
            ("worker_id", session.worker_id.as_str()),
            ("action", action.as_str()),
            ("target", target),
            ("trust_level", self_hosted_trust_level_label(trust_level)),
        ],
    )
}

fn capability_decision_label(decision: CapabilityAuthorizationDecision) -> &'static str {
    match decision {
        CapabilityAuthorizationDecision::Allowed => "allowed",
        CapabilityAuthorizationDecision::Denied => "denied",
        CapabilityAuthorizationDecision::ApprovalRequired => "approval_required",
    }
}

fn self_hosted_trust_level_label(trust_level: SelfHostedTelemetryTrustLevel) -> &'static str {
    match trust_level {
        SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker => {
            "reported_by_self_hosted_worker"
        }
    }
}

fn fnv1a64_hex(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
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
        assert_eq!(session.tenant_id, "tenant-1");
        assert_eq!(session.workspace_id, "workspace-1");
        assert_eq!(session.worker_id, "worker-1");
        assert_eq!(closed.kind, FrameworkAdapterEventKind::SessionClosed);
    }

    #[test]
    fn native_harness_resume_stream_and_artifact_contracts_are_normalized() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();

        let resumed = adapter
            .resume_run(FrameworkAdapterResumeRequest {
                session: session.clone(),
                checkpoint_id: "native-checkpoint".to_string(),
            })
            .unwrap();
        let streamed = adapter
            .stream_events(FrameworkAdapterStreamRequest {
                session: session.clone(),
                after_event_id: Some("event-1".to_string()),
                max_events: 1,
            })
            .unwrap();
        let artifacts = adapter
            .collect_artifacts(FrameworkAdapterArtifactRequest {
                session,
                artifact_id: Some("native-artifact".to_string()),
            })
            .unwrap();

        assert_eq!(
            resumed.iter().map(|event| event.kind).collect::<Vec<_>>(),
            vec![
                FrameworkAdapterEventKind::RunStarted,
                FrameworkAdapterEventKind::RunCompleted,
            ]
        );
        assert_eq!(streamed.len(), 1);
        assert_eq!(
            streamed[0]
                .metadata
                .get("after_event_id")
                .map(String::as_str),
            Some("event-1")
        );
        assert_eq!(
            artifacts.event.kind,
            FrameworkAdapterEventKind::ArtifactCreated
        );
        assert_eq!(artifacts.artifacts[0].artifact_id, "native-artifact");
        assert_eq!(artifacts.artifacts[0].media_type, "text/plain");
    }

    #[test]
    fn native_harness_event_stream_matches_golden_fixture() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, started) = adapter.start_session(session_request()).unwrap();
        let mut events = vec![started];
        events.extend(
            adapter
                .submit_run(FrameworkAdapterRunRequest {
                    session: session.clone(),
                    input_ref: "input://run-1".to_string(),
                })
                .unwrap(),
        );
        events.push(adapter.close_session(&session).unwrap());

        let actual = serde_json::to_value(
            events
                .iter()
                .map(NormalizedFrameworkEvent::canonical_json)
                .collect::<Vec<serde_json::Value>>(),
        )
        .unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native_harness_events.golden.json"
        ))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn process_framework_adapters_prepare_launch_handshake_events() {
        let mut adapters = vec![
            (
                ProcessFrameworkAdapter::claude_code(),
                SupportedFramework::ClaudeCode,
                "claude",
            ),
            (
                ProcessFrameworkAdapter::codex(),
                SupportedFramework::Codex,
                "codex",
            ),
            (
                ProcessFrameworkAdapter::hermes(),
                SupportedFramework::Hermes,
                "hermes",
            ),
        ];

        for (adapter, framework, command) in &mut adapters {
            assert_eq!(adapter.descriptor().framework, *framework);
            assert_eq!(adapter.launch().command, *command);
            let (session, started) = adapter.start_session(session_request()).unwrap();
            let events = adapter
                .submit_run(FrameworkAdapterRunRequest {
                    session,
                    input_ref: "input://run-1".to_string(),
                })
                .unwrap();

            assert_eq!(started.kind, FrameworkAdapterEventKind::SessionStarted);
            assert_eq!(started.framework, *framework);
            assert_eq!(
                started.metadata.get("process_shim").map(String::as_str),
                Some("true")
            );
            assert_eq!(
                started.metadata.get("sdk_bound").map(String::as_str),
                Some("false")
            );
            assert_eq!(
                started.metadata.get("launch_command").map(String::as_str),
                Some(*command)
            );
            assert_eq!(
                started.metadata.get("handshake").map(String::as_str),
                Some("process_launch_prepared")
            );
            assert_eq!(
                events.iter().map(|event| event.kind).collect::<Vec<_>>(),
                vec![
                    FrameworkAdapterEventKind::RunStarted,
                    FrameworkAdapterEventKind::ModelRequested,
                ]
            );
            assert!(events.iter().all(|event| event.framework == *framework
                && event.metadata.get("process_shim").map(String::as_str) == Some("true")));
        }
    }

    #[test]
    fn process_framework_adapter_event_stream_matches_golden_fixture() {
        let mut events = Vec::new();
        for mut adapter in [
            ProcessFrameworkAdapter::claude_code(),
            ProcessFrameworkAdapter::codex(),
            ProcessFrameworkAdapter::hermes(),
        ] {
            let (session, started) = adapter.start_session(session_request()).unwrap();
            events.push(started);
            events.extend(
                adapter
                    .submit_run(FrameworkAdapterRunRequest {
                        session: session.clone(),
                        input_ref: "input://run-1".to_string(),
                    })
                    .unwrap(),
            );
            events.push(adapter.close_session(&session).unwrap());
        }

        let actual = serde_json::to_value(
            events
                .iter()
                .map(NormalizedFrameworkEvent::canonical_json)
                .collect::<Vec<serde_json::Value>>(),
        )
        .unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/process_framework_adapter_events.golden.json"
        ))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn process_framework_adapter_validates_launch_contract() {
        let mut adapter = ProcessFrameworkAdapter::new(
            FrameworkAdapterDescriptor {
                name: "codex".to_string(),
                version: "1".to_string(),
                framework: SupportedFramework::Codex,
                capabilities: FrameworkAdapterCapabilities::code_process_shim(),
                enabled: true,
            },
            ProcessFrameworkLaunch::new(""),
        );

        let error = adapter.start_session(session_request()).unwrap_err();

        assert!(matches!(error, FrameworkAdapterError::InvalidDescriptor(_)));
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

    #[test]
    fn managed_adapter_capability_request_uses_gateway_authorizer() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = crate::SimpleCapabilityAuthorizer::new(crate::CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Tool]),
            ..crate::CapabilityPolicy::default()
        });

        let (evidence, event) = authorize_framework_capability(
            &authorizer,
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Tool,
                target: "native.echo".to_string(),
                high_risk: false,
            },
        )
        .unwrap();

        assert_eq!(evidence.decision, CapabilityAuthorizationDecision::Allowed);
        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityAllowed);
        assert_eq!(event.kind.as_str(), "capability.allowed");
        assert_eq!(
            event.metadata.get("decision").map(String::as_str),
            Some("allowed")
        );
        assert_eq!(
            event.metadata.get("isolation_backend").map(String::as_str),
            Some("firecracker")
        );
    }

    #[test]
    fn managed_adapter_capability_denial_is_normalized_evidence() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = crate::SimpleCapabilityAuthorizer::default();

        let (evidence, event) = authorize_framework_capability(
            &authorizer,
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Cli,
                target: "bash".to_string(),
                high_risk: false,
            },
        )
        .unwrap();

        assert_eq!(evidence.decision, CapabilityAuthorizationDecision::Denied);
        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityDenied);
        assert_eq!(event.kind.as_str(), "capability.denied");
        assert_eq!(
            event.metadata.get("decision").map(String::as_str),
            Some("denied")
        );
    }

    #[test]
    fn managed_adapter_approval_required_is_normalized_evidence() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = crate::SimpleCapabilityAuthorizer::new(crate::CapabilityPolicy {
            allowed_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
            approval_required_actions: std::collections::BTreeSet::from([CapabilityAction::Cli]),
            ..crate::CapabilityPolicy::default()
        });

        let (evidence, event) = authorize_framework_capability(
            &authorizer,
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Cli,
                target: "bash -lc cargo test".to_string(),
                high_risk: true,
            },
        )
        .unwrap();

        assert_eq!(
            evidence.decision,
            CapabilityAuthorizationDecision::ApprovalRequired
        );
        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityRequested);
        assert_eq!(event.kind.as_str(), "capability.requested");
        assert_eq!(
            event.metadata.get("decision").map(String::as_str),
            Some("approval_required")
        );
        assert_eq!(
            event.metadata.get("action").map(String::as_str),
            Some("cli")
        );
        assert_eq!(
            event.metadata.get("target").map(String::as_str),
            Some("bash -lc cargo test")
        );
        assert_eq!(
            event.metadata.get("tenant_id").map(String::as_str),
            Some("tenant-1")
        );
        assert_eq!(
            event.metadata.get("worker_id").map(String::as_str),
            Some("worker-1")
        );
        assert_eq!(
            event.metadata.get("isolation_backend").map(String::as_str),
            Some("firecracker")
        );
    }

    #[test]
    fn self_hosted_adapter_capability_report_is_reported_telemetry() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter
            .start_session(FrameworkAdapterSessionRequest {
                mode: FrameworkAdapterMode::SelfHosted,
                ..session_request()
            })
            .unwrap();

        let event = self_hosted_framework_capability_report(FrameworkCapabilityRequest {
            session,
            action: CapabilityAction::Cli,
            target: "local-shell".to_string(),
            high_risk: true,
        })
        .unwrap();

        assert_eq!(event.kind, FrameworkAdapterEventKind::CapabilityRequested);
        assert_eq!(event.kind.as_str(), "capability.requested");
        assert_eq!(
            event.metadata.get("trust_level").map(String::as_str),
            Some("reported_by_self_hosted_worker")
        );
    }

    #[test]
    fn managed_capability_event_projects_to_timeline_record() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter.start_session(session_request()).unwrap();
        let authorizer = crate::SimpleCapabilityAuthorizer::default();

        let (_, event) = authorize_framework_capability(
            &authorizer,
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Cli,
                target: "bash".to_string(),
                high_risk: false,
            },
        )
        .unwrap();

        let record = event.timeline_record().unwrap();

        assert_eq!(
            record.event_id.split(':').take(5).collect::<Vec<_>>(),
            vec![
                "framework",
                "run-1",
                "session-1",
                "native-harness",
                "capability.denied"
            ]
        );
        assert_eq!(record.event_id.rsplit(':').next().unwrap().len(), 16);
        assert_eq!(record.run_id, "run-1");
        assert_eq!(record.kind, "capability.denied");
        assert_eq!(record.target, "bash");
        assert_eq!(record.outcome, "denied");
        assert!(record
            .message
            .as_deref()
            .unwrap()
            .contains("not allowed by capability policy"));
        let event_json: serde_json::Value = serde_json::from_str(&record.event_json).unwrap();
        assert_eq!(event_json["framework"], "native_harness");
        assert_eq!(event_json["mode"], "managed");
        assert_eq!(event_json["kind"], "capability.denied");
        assert_eq!(event_json["metadata"]["decision"], "denied");
        assert_eq!(event_json["metadata"]["isolation_backend"], "firecracker");
    }

    fn session_request() -> FrameworkAdapterSessionRequest {
        FrameworkAdapterSessionRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            isolation_backend: "firecracker".to_string(),
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
