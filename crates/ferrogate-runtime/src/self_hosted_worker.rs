// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Self-hosted worker identity and telemetry contract.
//!
//! Self-hosted workers run on customer-owned hosts. FerroGate can validate
//! identity envelopes and ingest reported telemetry, but those events are not
//! proof that FerroGate enforced the local execution environment.

use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerRegistration {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub framework_adapter: String,
    pub token_id: String,
    pub token_secret: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerIdentity {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub token_id: String,
    pub token_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSelfHostedWorker {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub framework_adapter: String,
    pub token_id: String,
    token_secret: String,
    pub capabilities: Vec<String>,
    pub active: bool,
}

impl RegisteredSelfHostedWorker {
    pub fn identity(&self) -> SelfHostedWorkerIdentity {
        SelfHostedWorkerIdentity {
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            worker_id: self.worker_id.clone(),
            token_id: self.token_id.clone(),
            token_secret: self.token_secret.clone(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SelfHostedWorkerRegistry {
    workers: BTreeMap<String, RegisteredSelfHostedWorker>,
}

impl SelfHostedWorkerRegistry {
    pub fn register(
        &mut self,
        registration: SelfHostedWorkerRegistration,
    ) -> Result<RegisteredSelfHostedWorker, SelfHostedWorkerError> {
        validate_registration(&registration)?;
        let key = worker_key(
            &registration.tenant_id,
            &registration.workspace_id,
            &registration.worker_id,
        );
        if self.workers.contains_key(&key) {
            return Err(SelfHostedWorkerError::DuplicateWorker(format!(
                "self-hosted worker {} already exists in tenant/workspace",
                registration.worker_id
            )));
        }
        let worker = RegisteredSelfHostedWorker {
            tenant_id: registration.tenant_id,
            workspace_id: registration.workspace_id,
            worker_id: registration.worker_id,
            framework_adapter: registration.framework_adapter,
            token_id: registration.token_id,
            token_secret: registration.token_secret,
            capabilities: normalized_capabilities(registration.capabilities),
            active: true,
        };
        self.workers.insert(key, worker.clone());
        Ok(worker)
    }

    pub fn validate_identity(
        &self,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<&RegisteredSelfHostedWorker, SelfHostedWorkerError> {
        validate_identity_shape(identity)?;
        let key = worker_key(
            &identity.tenant_id,
            &identity.workspace_id,
            &identity.worker_id,
        );
        let worker = self
            .workers
            .get(&key)
            .ok_or_else(|| SelfHostedWorkerError::UnknownWorker(identity.worker_id.clone()))?;
        if !worker.active {
            return Err(SelfHostedWorkerError::InactiveWorker(
                identity.worker_id.clone(),
            ));
        }
        if worker.token_id != identity.token_id || worker.token_secret != identity.token_secret {
            return Err(SelfHostedWorkerError::InvalidIdentity(
                "worker token does not match registered identity envelope".to_string(),
            ));
        }
        Ok(worker)
    }

    pub fn rotate_token(
        &mut self,
        identity: &SelfHostedWorkerIdentity,
        new_token_id: String,
        new_token_secret: String,
    ) -> Result<SelfHostedWorkerIdentity, SelfHostedWorkerError> {
        self.validate_identity(identity)?;
        if new_token_id.trim().is_empty() {
            return Err(SelfHostedWorkerError::InvalidRegistration(
                "new token_id must not be empty".to_string(),
            ));
        }
        if new_token_secret.trim().is_empty() {
            return Err(SelfHostedWorkerError::InvalidRegistration(
                "new token_secret must not be empty".to_string(),
            ));
        }
        let key = worker_key(
            &identity.tenant_id,
            &identity.workspace_id,
            &identity.worker_id,
        );
        let worker = self
            .workers
            .get_mut(&key)
            .expect("validated worker should be present for token rotation");
        worker.token_id = new_token_id;
        worker.token_secret = new_token_secret;
        Ok(worker.identity())
    }

    pub fn list(&self) -> Vec<RegisteredSelfHostedWorker> {
        self.workers.values().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerHeartbeat {
    pub worker_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub status: String,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunDispatch {
    pub dispatch_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub framework_adapter: String,
    pub required_capabilities: Vec<String>,
    pub workload_ref: String,
    pub queued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunPollRequest {
    pub identity: SelfHostedWorkerIdentity,
    pub supported_capabilities: Vec<String>,
    pub now_unix: u64,
    pub lease_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunLease {
    pub dispatch_id: String,
    pub lease_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub framework_adapter: String,
    pub required_capabilities: Vec<String>,
    pub workload_ref: String,
    pub attempt: u32,
    pub lease_expires_at_unix: u64,
    pub trust_level: SelfHostedTelemetryTrustLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunAckRequest {
    pub identity: SelfHostedWorkerIdentity,
    pub dispatch_id: String,
    pub lease_id: String,
    pub run_id: String,
    pub status: SelfHostedRunAckStatus,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHostedRunAckStatus {
    Accepted,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunAck {
    pub dispatch_id: String,
    pub lease_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub run_id: String,
    pub status: SelfHostedRunAckStatus,
    pub accepted_at_unix: u64,
    pub trust_level: SelfHostedTelemetryTrustLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedSelfHostedRun {
    dispatch: SelfHostedRunDispatch,
    assigned_worker_id: Option<String>,
    lease_id: Option<String>,
    lease_expires_at_unix: Option<u64>,
    attempt: u32,
    acknowledged: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemorySelfHostedRunQueue {
    runs: BTreeMap<String, QueuedSelfHostedRun>,
}

impl InMemorySelfHostedRunQueue {
    pub fn enqueue_run(
        &mut self,
        dispatch: SelfHostedRunDispatch,
    ) -> Result<(), SelfHostedWorkerError> {
        validate_run_dispatch(&dispatch)?;
        if self.runs.contains_key(&dispatch.dispatch_id) {
            return Err(SelfHostedWorkerError::InvalidTransport(format!(
                "dispatch {} already exists",
                dispatch.dispatch_id
            )));
        }
        self.runs.insert(
            dispatch.dispatch_id.clone(),
            QueuedSelfHostedRun {
                dispatch,
                assigned_worker_id: None,
                lease_id: None,
                lease_expires_at_unix: None,
                attempt: 0,
                acknowledged: false,
            },
        );
        Ok(())
    }

    pub fn poll_run(
        &mut self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError> {
        let worker = registry.validate_identity(&request.identity)?;
        validate_run_poll_request(&request)?;
        let supported_capabilities = normalized_capabilities(request.supported_capabilities);
        let Some((_, queued)) = self.runs.iter_mut().find(|(_, queued)| {
            queued.can_lease_to(worker, &supported_capabilities, request.now_unix)
        }) else {
            return Ok(None);
        };

        queued.attempt = queued.attempt.saturating_add(1);
        let lease_id = format!("{}:attempt-{}", queued.dispatch.dispatch_id, queued.attempt);
        let lease_expires_at_unix = request.now_unix.saturating_add(request.lease_duration_secs);
        queued.assigned_worker_id = Some(worker.worker_id.clone());
        queued.lease_id = Some(lease_id.clone());
        queued.lease_expires_at_unix = Some(lease_expires_at_unix);

        Ok(Some(SelfHostedRunLease {
            dispatch_id: queued.dispatch.dispatch_id.clone(),
            lease_id,
            tenant_id: queued.dispatch.tenant_id.clone(),
            workspace_id: queued.dispatch.workspace_id.clone(),
            worker_id: worker.worker_id.clone(),
            session_id: queued.dispatch.session_id.clone(),
            run_id: queued.dispatch.run_id.clone(),
            framework_adapter: queued.dispatch.framework_adapter.clone(),
            required_capabilities: queued.dispatch.required_capabilities.clone(),
            workload_ref: queued.dispatch.workload_ref.clone(),
            attempt: queued.attempt,
            lease_expires_at_unix,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
        }))
    }

    pub fn ack_run(
        &mut self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError> {
        let worker = registry.validate_identity(&request.identity)?;
        validate_run_ack_request(&request)?;
        let queued = self.runs.get_mut(&request.dispatch_id).ok_or_else(|| {
            SelfHostedWorkerError::InvalidTransport("unknown dispatch".to_string())
        })?;
        if queued.dispatch.tenant_id != worker.tenant_id
            || queued.dispatch.workspace_id != worker.workspace_id
        {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "worker identity is outside dispatch tenant/workspace scope".to_string(),
            ));
        }
        if queued.dispatch.run_id != request.run_id {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "ack run_id does not match dispatch".to_string(),
            ));
        }
        if queued.assigned_worker_id.as_deref() != Some(worker.worker_id.as_str()) {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "ack worker does not own the active lease".to_string(),
            ));
        }
        if queued.lease_id.as_deref() != Some(request.lease_id.as_str()) {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "ack lease_id does not match active lease".to_string(),
            ));
        }
        queued.acknowledged = true;
        Ok(SelfHostedRunAck {
            dispatch_id: queued.dispatch.dispatch_id.clone(),
            lease_id: request.lease_id,
            tenant_id: worker.tenant_id.clone(),
            workspace_id: worker.workspace_id.clone(),
            worker_id: worker.worker_id.clone(),
            run_id: request.run_id,
            status: request.status,
            accepted_at_unix: request.reported_at_unix,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
        })
    }
}

impl QueuedSelfHostedRun {
    fn can_lease_to(
        &self,
        worker: &RegisteredSelfHostedWorker,
        supported_capabilities: &[String],
        now_unix: u64,
    ) -> bool {
        !self.acknowledged
            && self.dispatch.tenant_id == worker.tenant_id
            && self.dispatch.workspace_id == worker.workspace_id
            && self.dispatch.framework_adapter == worker.framework_adapter
            && required_capabilities_supported(
                &self.dispatch.required_capabilities,
                supported_capabilities,
            )
            && required_capabilities_supported(
                &self.dispatch.required_capabilities,
                &worker.capabilities,
            )
            && self
                .lease_expires_at_unix
                .map(|expires_at| expires_at <= now_unix)
                .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedArtifactUploadRequest {
    pub identity: SelfHostedWorkerIdentity,
    pub session_id: String,
    pub run_id: String,
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
    pub byte_len: usize,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedArtifactUpload {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
    pub byte_len: usize,
    pub trust_level: SelfHostedTelemetryTrustLevel,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedCheckpointFetchRequest {
    pub identity: SelfHostedWorkerIdentity,
    pub session_id: String,
    pub run_id: String,
    pub checkpoint_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedCheckpointReference {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub checkpoint_id: String,
    pub trust_level: SelfHostedTelemetryTrustLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedTelemetryRequest {
    pub identity: SelfHostedWorkerIdentity,
    pub session_id: String,
    pub run_id: String,
    pub event_id: String,
    pub kind: SelfHostedTelemetryKind,
    pub message: Option<String>,
    pub artifact_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub reported_at_unix: u64,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHostedTelemetryKind {
    Lifecycle,
    Log,
    ToolCall,
    McpCall,
    CliCommand,
    SkillInvocation,
    Artifact,
    Checkpoint,
    Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHostedTelemetryTrustLevel {
    ReportedBySelfHostedWorker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedTelemetryEvent {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub event_id: String,
    pub kind: SelfHostedTelemetryKind,
    pub trust_level: SelfHostedTelemetryTrustLevel,
    pub message: Option<String>,
    pub artifact_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedTelemetryIngestor {
    max_payload_bytes: usize,
}

impl Default for SelfHostedTelemetryIngestor {
    fn default() -> Self {
        Self {
            max_payload_bytes: 64 * 1024,
        }
    }
}

impl SelfHostedTelemetryIngestor {
    pub fn new(max_payload_bytes: usize) -> Result<Self, SelfHostedWorkerError> {
        if max_payload_bytes == 0 {
            return Err(SelfHostedWorkerError::InvalidTelemetry(
                "max_payload_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(Self { max_payload_bytes })
    }

    pub fn heartbeat(
        &self,
        registry: &SelfHostedWorkerRegistry,
        identity: &SelfHostedWorkerIdentity,
        status: &str,
        reported_at_unix: u64,
    ) -> Result<SelfHostedWorkerHeartbeat, SelfHostedWorkerError> {
        let worker = registry.validate_identity(identity)?;
        if status.trim().is_empty() {
            return Err(SelfHostedWorkerError::InvalidTelemetry(
                "heartbeat status must not be empty".to_string(),
            ));
        }
        if reported_at_unix == 0 {
            return Err(SelfHostedWorkerError::InvalidTelemetry(
                "reported_at_unix must be greater than zero".to_string(),
            ));
        }
        Ok(SelfHostedWorkerHeartbeat {
            worker_id: worker.worker_id.clone(),
            tenant_id: worker.tenant_id.clone(),
            workspace_id: worker.workspace_id.clone(),
            status: status.to_string(),
            reported_at_unix,
        })
    }

    pub fn ingest(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedTelemetryRequest,
    ) -> Result<SelfHostedTelemetryEvent, SelfHostedWorkerError> {
        let worker = registry.validate_identity(&request.identity)?;
        validate_telemetry_request(&request, self.max_payload_bytes)?;
        Ok(SelfHostedTelemetryEvent {
            tenant_id: worker.tenant_id.clone(),
            workspace_id: worker.workspace_id.clone(),
            worker_id: worker.worker_id.clone(),
            session_id: request.session_id,
            run_id: request.run_id,
            event_id: request.event_id,
            kind: request.kind,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
            message: request.message,
            artifact_id: request.artifact_id,
            checkpoint_id: request.checkpoint_id,
            reported_at_unix: request.reported_at_unix,
        })
    }
}

pub trait SelfHostedWorkerTransport {
    fn probe_worker(
        &self,
        registry: &SelfHostedWorkerRegistry,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<RegisteredSelfHostedWorker, SelfHostedWorkerError>;
    fn heartbeat(
        &self,
        registry: &SelfHostedWorkerRegistry,
        identity: &SelfHostedWorkerIdentity,
        status: &str,
        reported_at_unix: u64,
    ) -> Result<SelfHostedWorkerHeartbeat, SelfHostedWorkerError>;
    fn stream_events(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedTelemetryRequest,
    ) -> Result<SelfHostedTelemetryEvent, SelfHostedWorkerError>;
    fn upload_artifact(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedArtifactUploadRequest,
    ) -> Result<SelfHostedArtifactUpload, SelfHostedWorkerError>;
    fn fetch_checkpoint(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedCheckpointFetchRequest,
    ) -> Result<SelfHostedCheckpointReference, SelfHostedWorkerError>;
    fn poll_run(
        &self,
        registry: &SelfHostedWorkerRegistry,
        queue: &mut InMemorySelfHostedRunQueue,
        request: SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError>;
    fn ack_run(
        &self,
        registry: &SelfHostedWorkerRegistry,
        queue: &mut InMemorySelfHostedRunQueue,
        request: SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemorySelfHostedWorkerTransport {
    ingestor: SelfHostedTelemetryIngestor,
    max_artifact_bytes: usize,
}

impl InMemorySelfHostedWorkerTransport {
    pub fn new(
        max_payload_bytes: usize,
        max_artifact_bytes: usize,
    ) -> Result<Self, SelfHostedWorkerError> {
        if max_artifact_bytes == 0 {
            return Err(SelfHostedWorkerError::InvalidTelemetry(
                "max_artifact_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            ingestor: SelfHostedTelemetryIngestor::new(max_payload_bytes)?,
            max_artifact_bytes,
        })
    }
}

impl Default for InMemorySelfHostedWorkerTransport {
    fn default() -> Self {
        Self {
            ingestor: SelfHostedTelemetryIngestor::default(),
            max_artifact_bytes: 16 * 1024 * 1024,
        }
    }
}

impl SelfHostedWorkerTransport for InMemorySelfHostedWorkerTransport {
    fn probe_worker(
        &self,
        registry: &SelfHostedWorkerRegistry,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<RegisteredSelfHostedWorker, SelfHostedWorkerError> {
        registry.validate_identity(identity).cloned()
    }

    fn heartbeat(
        &self,
        registry: &SelfHostedWorkerRegistry,
        identity: &SelfHostedWorkerIdentity,
        status: &str,
        reported_at_unix: u64,
    ) -> Result<SelfHostedWorkerHeartbeat, SelfHostedWorkerError> {
        self.ingestor
            .heartbeat(registry, identity, status, reported_at_unix)
    }

    fn stream_events(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedTelemetryRequest,
    ) -> Result<SelfHostedTelemetryEvent, SelfHostedWorkerError> {
        self.ingestor.ingest(registry, request)
    }

    fn upload_artifact(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedArtifactUploadRequest,
    ) -> Result<SelfHostedArtifactUpload, SelfHostedWorkerError> {
        let worker = registry.validate_identity(&request.identity)?;
        validate_artifact_upload(&request, self.max_artifact_bytes)?;
        Ok(SelfHostedArtifactUpload {
            tenant_id: worker.tenant_id.clone(),
            workspace_id: worker.workspace_id.clone(),
            worker_id: worker.worker_id.clone(),
            session_id: request.session_id,
            run_id: request.run_id,
            artifact_id: request.artifact_id,
            name: request.name,
            media_type: request.media_type,
            byte_len: request.byte_len,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
            reported_at_unix: request.reported_at_unix,
        })
    }

    fn fetch_checkpoint(
        &self,
        registry: &SelfHostedWorkerRegistry,
        request: SelfHostedCheckpointFetchRequest,
    ) -> Result<SelfHostedCheckpointReference, SelfHostedWorkerError> {
        let worker = registry.validate_identity(&request.identity)?;
        validate_checkpoint_fetch(&request)?;
        Ok(SelfHostedCheckpointReference {
            tenant_id: worker.tenant_id.clone(),
            workspace_id: worker.workspace_id.clone(),
            worker_id: worker.worker_id.clone(),
            session_id: request.session_id,
            run_id: request.run_id,
            checkpoint_id: request.checkpoint_id,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
        })
    }

    fn poll_run(
        &self,
        registry: &SelfHostedWorkerRegistry,
        queue: &mut InMemorySelfHostedRunQueue,
        request: SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError> {
        queue.poll_run(registry, request)
    }

    fn ack_run(
        &self,
        registry: &SelfHostedWorkerRegistry,
        queue: &mut InMemorySelfHostedRunQueue,
        request: SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError> {
        queue.ack_run(registry, request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfHostedWorkerError {
    InvalidRegistration(String),
    DuplicateWorker(String),
    UnknownWorker(String),
    InactiveWorker(String),
    InvalidIdentity(String),
    InvalidTelemetry(String),
    InvalidTransport(String),
}

impl fmt::Display for SelfHostedWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRegistration(message) => {
                write!(
                    formatter,
                    "invalid self-hosted worker registration: {message}"
                )
            }
            Self::DuplicateWorker(message) => {
                write!(formatter, "duplicate self-hosted worker: {message}")
            }
            Self::UnknownWorker(worker_id) => {
                write!(formatter, "unknown self-hosted worker: {worker_id}")
            }
            Self::InactiveWorker(worker_id) => {
                write!(formatter, "inactive self-hosted worker: {worker_id}")
            }
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid self-hosted worker identity: {message}")
            }
            Self::InvalidTelemetry(message) => {
                write!(formatter, "invalid self-hosted worker telemetry: {message}")
            }
            Self::InvalidTransport(message) => {
                write!(formatter, "invalid self-hosted worker transport: {message}")
            }
        }
    }
}

impl Error for SelfHostedWorkerError {}

fn validate_registration(
    registration: &SelfHostedWorkerRegistration,
) -> Result<(), SelfHostedWorkerError> {
    require_non_empty("tenant_id", &registration.tenant_id)?;
    require_non_empty("workspace_id", &registration.workspace_id)?;
    require_non_empty("worker_id", &registration.worker_id)?;
    require_non_empty("framework_adapter", &registration.framework_adapter)?;
    require_non_empty("token_id", &registration.token_id)?;
    require_non_empty("token_secret", &registration.token_secret)?;
    if registration
        .capabilities
        .iter()
        .any(|item| item.trim().is_empty())
    {
        return Err(SelfHostedWorkerError::InvalidRegistration(
            "capabilities must not contain empty values".to_string(),
        ));
    }
    Ok(())
}

fn validate_identity_shape(
    identity: &SelfHostedWorkerIdentity,
) -> Result<(), SelfHostedWorkerError> {
    require_identity_non_empty("tenant_id", &identity.tenant_id)?;
    require_identity_non_empty("workspace_id", &identity.workspace_id)?;
    require_identity_non_empty("worker_id", &identity.worker_id)?;
    require_identity_non_empty("token_id", &identity.token_id)?;
    require_identity_non_empty("token_secret", &identity.token_secret)?;
    Ok(())
}

fn validate_telemetry_request(
    request: &SelfHostedTelemetryRequest,
    max_payload_bytes: usize,
) -> Result<(), SelfHostedWorkerError> {
    if request.payload_bytes > max_payload_bytes {
        return Err(SelfHostedWorkerError::InvalidTelemetry(format!(
            "payload exceeds maximum size of {max_payload_bytes} bytes"
        )));
    }
    require_telemetry_non_empty("session_id", &request.session_id)?;
    require_telemetry_non_empty("run_id", &request.run_id)?;
    require_telemetry_non_empty("event_id", &request.event_id)?;
    if request.reported_at_unix == 0 {
        return Err(SelfHostedWorkerError::InvalidTelemetry(
            "reported_at_unix must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_artifact_upload(
    request: &SelfHostedArtifactUploadRequest,
    max_artifact_bytes: usize,
) -> Result<(), SelfHostedWorkerError> {
    require_telemetry_non_empty("session_id", &request.session_id)?;
    require_telemetry_non_empty("run_id", &request.run_id)?;
    require_telemetry_non_empty("artifact_id", &request.artifact_id)?;
    require_telemetry_non_empty("name", &request.name)?;
    require_telemetry_non_empty("media_type", &request.media_type)?;
    if request.byte_len == 0 {
        return Err(SelfHostedWorkerError::InvalidTelemetry(
            "artifact byte_len must be greater than zero".to_string(),
        ));
    }
    if request.byte_len > max_artifact_bytes {
        return Err(SelfHostedWorkerError::InvalidTelemetry(format!(
            "artifact exceeds maximum size of {max_artifact_bytes} bytes"
        )));
    }
    if request.reported_at_unix == 0 {
        return Err(SelfHostedWorkerError::InvalidTelemetry(
            "reported_at_unix must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_run_dispatch(dispatch: &SelfHostedRunDispatch) -> Result<(), SelfHostedWorkerError> {
    require_transport_non_empty("dispatch_id", &dispatch.dispatch_id)?;
    require_transport_non_empty("tenant_id", &dispatch.tenant_id)?;
    require_transport_non_empty("workspace_id", &dispatch.workspace_id)?;
    require_transport_non_empty("session_id", &dispatch.session_id)?;
    require_transport_non_empty("run_id", &dispatch.run_id)?;
    require_transport_non_empty("framework_adapter", &dispatch.framework_adapter)?;
    require_transport_non_empty("workload_ref", &dispatch.workload_ref)?;
    if dispatch.queued_at_unix == 0 {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "queued_at_unix must be greater than zero".to_string(),
        ));
    }
    if dispatch
        .required_capabilities
        .iter()
        .any(|item| item.trim().is_empty())
    {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "required_capabilities must not contain empty values".to_string(),
        ));
    }
    Ok(())
}

fn validate_run_poll_request(
    request: &SelfHostedRunPollRequest,
) -> Result<(), SelfHostedWorkerError> {
    if request.now_unix == 0 {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "now_unix must be greater than zero".to_string(),
        ));
    }
    if request.lease_duration_secs == 0 {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "lease_duration_secs must be greater than zero".to_string(),
        ));
    }
    if request
        .supported_capabilities
        .iter()
        .any(|item| item.trim().is_empty())
    {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "supported_capabilities must not contain empty values".to_string(),
        ));
    }
    Ok(())
}

fn validate_run_ack_request(
    request: &SelfHostedRunAckRequest,
) -> Result<(), SelfHostedWorkerError> {
    require_transport_non_empty("dispatch_id", &request.dispatch_id)?;
    require_transport_non_empty("lease_id", &request.lease_id)?;
    require_transport_non_empty("run_id", &request.run_id)?;
    if request.reported_at_unix == 0 {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "reported_at_unix must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_checkpoint_fetch(
    request: &SelfHostedCheckpointFetchRequest,
) -> Result<(), SelfHostedWorkerError> {
    require_telemetry_non_empty("session_id", &request.session_id)?;
    require_telemetry_non_empty("run_id", &request.run_id)?;
    require_telemetry_non_empty("checkpoint_id", &request.checkpoint_id)?;
    Ok(())
}

fn normalized_capabilities(mut capabilities: Vec<String>) -> Vec<String> {
    capabilities.iter_mut().for_each(|item| {
        *item = item.trim().to_string();
    });
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn required_capabilities_supported(required: &[String], supported: &[String]) -> bool {
    required
        .iter()
        .all(|capability| supported.iter().any(|item| item == capability))
}

fn worker_key(tenant_id: &str, workspace_id: &str, worker_id: &str) -> String {
    format!("{tenant_id}/{workspace_id}/{worker_id}")
}

fn require_non_empty(field: &str, value: &str) -> Result<(), SelfHostedWorkerError> {
    if value.trim().is_empty() {
        return Err(SelfHostedWorkerError::InvalidRegistration(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_identity_non_empty(field: &str, value: &str) -> Result<(), SelfHostedWorkerError> {
    if value.trim().is_empty() {
        return Err(SelfHostedWorkerError::InvalidIdentity(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_telemetry_non_empty(field: &str, value: &str) -> Result<(), SelfHostedWorkerError> {
    if value.trim().is_empty() {
        return Err(SelfHostedWorkerError::InvalidTelemetry(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_transport_non_empty(field: &str, value: &str) -> Result<(), SelfHostedWorkerError> {
    if value.trim().is_empty() {
        return Err(SelfHostedWorkerError::InvalidTransport(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_worker_and_normalizes_capabilities() {
        let mut registry = SelfHostedWorkerRegistry::default();

        let worker = registry.register(registration()).unwrap();

        assert_eq!(worker.tenant_id, "tenant-1");
        assert_eq!(worker.workspace_id, "workspace-1");
        assert_eq!(worker.worker_id, "worker-1");
        assert_eq!(worker.framework_adapter, "codex");
        assert_eq!(worker.capabilities, vec!["artifacts", "heartbeat", "logs"]);
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn rotates_worker_token_and_rejects_old_identity() {
        let mut registry = registered_registry();
        let old_identity = registry.list()[0].identity();

        let new_identity = registry
            .rotate_token(&old_identity, "token-2".to_string(), "secret-2".to_string())
            .unwrap();

        assert!(registry.validate_identity(&old_identity).is_err());
        assert!(registry.validate_identity(&new_identity).is_ok());
    }

    #[test]
    fn ingests_reported_telemetry_with_self_hosted_trust_level() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let ingestor = SelfHostedTelemetryIngestor::default();

        let event = ingestor
            .ingest(
                &registry,
                SelfHostedTelemetryRequest {
                    identity,
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    event_id: "event-1".to_string(),
                    kind: SelfHostedTelemetryKind::ToolCall,
                    message: Some("tool reported by worker".to_string()),
                    artifact_id: None,
                    checkpoint_id: None,
                    reported_at_unix: 1_725_000_000,
                    payload_bytes: 512,
                },
            )
            .unwrap();

        assert_eq!(event.tenant_id, "tenant-1");
        assert_eq!(event.workspace_id, "workspace-1");
        assert_eq!(event.worker_id, "worker-1");
        assert_eq!(
            event.trust_level,
            SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker
        );
    }

    #[test]
    fn rejects_cross_tenant_telemetry_spoofing() {
        let registry = registered_registry();
        let mut identity = registry.list()[0].identity();
        identity.tenant_id = "tenant-2".to_string();
        let ingestor = SelfHostedTelemetryIngestor::default();

        let error = ingestor
            .ingest(
                &registry,
                SelfHostedTelemetryRequest {
                    identity,
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    event_id: "event-1".to_string(),
                    kind: SelfHostedTelemetryKind::Lifecycle,
                    message: None,
                    artifact_id: None,
                    checkpoint_id: None,
                    reported_at_unix: 1_725_000_000,
                    payload_bytes: 64,
                },
            )
            .unwrap_err();

        assert!(matches!(error, SelfHostedWorkerError::UnknownWorker(_)));
    }

    #[test]
    fn rejects_oversized_telemetry_payload() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let ingestor = SelfHostedTelemetryIngestor::new(128).unwrap();

        let error = ingestor
            .ingest(
                &registry,
                SelfHostedTelemetryRequest {
                    identity,
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    event_id: "event-1".to_string(),
                    kind: SelfHostedTelemetryKind::Artifact,
                    message: None,
                    artifact_id: Some("artifact-1".to_string()),
                    checkpoint_id: None,
                    reported_at_unix: 1_725_000_000,
                    payload_bytes: 129,
                },
            )
            .unwrap_err();

        assert!(matches!(error, SelfHostedWorkerError::InvalidTelemetry(_)));
        assert!(error.to_string().contains("maximum size"));
    }

    #[test]
    fn records_heartbeat_with_registered_attribution() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let ingestor = SelfHostedTelemetryIngestor::default();

        let heartbeat = ingestor
            .heartbeat(&registry, &identity, "online", 1_725_000_001)
            .unwrap();

        assert_eq!(heartbeat.tenant_id, "tenant-1");
        assert_eq!(heartbeat.workspace_id, "workspace-1");
        assert_eq!(heartbeat.worker_id, "worker-1");
        assert_eq!(heartbeat.status, "online");
    }

    #[test]
    fn transport_probes_heartbeats_streams_events_and_reports_artifacts() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let transport = InMemorySelfHostedWorkerTransport::default();

        let worker = transport.probe_worker(&registry, &identity).unwrap();
        let heartbeat = transport
            .heartbeat(&registry, &identity, "online", 1_725_000_001)
            .unwrap();
        let event = transport
            .stream_events(
                &registry,
                SelfHostedTelemetryRequest {
                    identity: identity.clone(),
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    event_id: "event-transport-1".to_string(),
                    kind: SelfHostedTelemetryKind::Log,
                    message: Some("log line".to_string()),
                    artifact_id: None,
                    checkpoint_id: None,
                    reported_at_unix: 1_725_000_002,
                    payload_bytes: 256,
                },
            )
            .unwrap();
        let artifact = transport
            .upload_artifact(
                &registry,
                SelfHostedArtifactUploadRequest {
                    identity: identity.clone(),
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    artifact_id: "artifact-1".to_string(),
                    name: "report.txt".to_string(),
                    media_type: "text/plain".to_string(),
                    byte_len: 128,
                    reported_at_unix: 1_725_000_003,
                },
            )
            .unwrap();
        let checkpoint = transport
            .fetch_checkpoint(
                &registry,
                SelfHostedCheckpointFetchRequest {
                    identity,
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    checkpoint_id: "checkpoint-1".to_string(),
                },
            )
            .unwrap();

        assert_eq!(worker.worker_id, "worker-1");
        assert_eq!(heartbeat.status, "online");
        assert_eq!(event.kind, SelfHostedTelemetryKind::Log);
        assert_eq!(artifact.artifact_id, "artifact-1");
        assert_eq!(
            artifact.trust_level,
            SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker
        );
        assert_eq!(checkpoint.checkpoint_id, "checkpoint-1");
        assert_eq!(
            checkpoint.trust_level,
            SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker
        );
    }

    #[test]
    fn transport_rejects_oversized_artifact_uploads() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let transport = InMemorySelfHostedWorkerTransport::new(1024, 128).unwrap();

        let error = transport
            .upload_artifact(
                &registry,
                SelfHostedArtifactUploadRequest {
                    identity,
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    artifact_id: "artifact-1".to_string(),
                    name: "report.txt".to_string(),
                    media_type: "text/plain".to_string(),
                    byte_len: 129,
                    reported_at_unix: 1_725_000_003,
                },
            )
            .unwrap_err();

        assert!(matches!(error, SelfHostedWorkerError::InvalidTelemetry(_)));
        assert!(error.to_string().contains("artifact exceeds maximum size"));
    }

    #[test]
    fn worker_poll_leases_matching_dispatch_and_acknowledges_it() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        let lease = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("matching worker should receive a run lease");

        assert_eq!(lease.dispatch_id, "dispatch-1");
        assert_eq!(lease.lease_id, "dispatch-1:attempt-1");
        assert_eq!(lease.worker_id, "worker-1");
        assert_eq!(lease.attempt, 1);
        assert_eq!(lease.lease_expires_at_unix, 1_725_000_040);
        assert_eq!(
            lease.trust_level,
            SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker
        );

        let ack = transport
            .ack_run(
                &registry,
                &mut queue,
                SelfHostedRunAckRequest {
                    identity,
                    dispatch_id: lease.dispatch_id.clone(),
                    lease_id: lease.lease_id.clone(),
                    run_id: lease.run_id.clone(),
                    status: SelfHostedRunAckStatus::Accepted,
                    reported_at_unix: 1_725_000_011,
                },
            )
            .unwrap();

        assert_eq!(ack.dispatch_id, "dispatch-1");
        assert_eq!(ack.lease_id, "dispatch-1:attempt-1");
        assert_eq!(ack.worker_id, "worker-1");
        assert_eq!(ack.status, SelfHostedRunAckStatus::Accepted);
    }

    #[test]
    fn worker_poll_holds_unacked_lease_until_expiry_then_redelivers() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        let first = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .unwrap();
        let during_active_lease = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_039,
                    lease_duration_secs: 30,
                },
            )
            .unwrap();
        let after_expiry = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    identity,
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_040,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .unwrap();

        assert_eq!(first.lease_id, "dispatch-1:attempt-1");
        assert!(during_active_lease.is_none());
        assert_eq!(after_expiry.lease_id, "dispatch-1:attempt-2");
        assert_eq!(after_expiry.attempt, 2);
    }

    #[test]
    fn worker_poll_rejects_mismatched_scope_adapter_and_capabilities() {
        let mut registry = SelfHostedWorkerRegistry::default();
        registry.register(registration()).unwrap();
        registry
            .register(SelfHostedWorkerRegistration {
                tenant_id: "tenant-2".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-2".to_string(),
                framework_adapter: "codex".to_string(),
                token_id: "token-2".to_string(),
                token_secret: "secret-2".to_string(),
                capabilities: vec!["logs".to_string(), "artifacts".to_string()],
            })
            .unwrap();
        registry
            .register(SelfHostedWorkerRegistration {
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-3".to_string(),
                framework_adapter: "hermes".to_string(),
                token_id: "token-3".to_string(),
                token_secret: "secret-3".to_string(),
                capabilities: vec!["logs".to_string(), "artifacts".to_string()],
            })
            .unwrap();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        for identity in [
            registry.list()[1].identity(),
            registry.list()[2].identity(),
            registry.list()[0].identity(),
        ] {
            let capabilities = if identity.worker_id == "worker-1" {
                vec!["logs".to_string()]
            } else {
                vec!["logs".to_string(), "artifacts".to_string()]
            };
            let lease = transport
                .poll_run(
                    &registry,
                    &mut queue,
                    SelfHostedRunPollRequest {
                        identity,
                        supported_capabilities: capabilities,
                        now_unix: 1_725_000_010,
                        lease_duration_secs: 30,
                    },
                )
                .unwrap();
            assert!(lease.is_none());
        }
    }

    #[test]
    fn worker_poll_requires_capabilities_registered_on_worker_identity() {
        let mut registry = SelfHostedWorkerRegistry::default();
        registry
            .register(SelfHostedWorkerRegistration {
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-1".to_string(),
                framework_adapter: "codex".to_string(),
                token_id: "token-1".to_string(),
                token_secret: "secret-1".to_string(),
                capabilities: vec!["logs".to_string()],
            })
            .unwrap();
        let identity = registry.list()[0].identity();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        let lease = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    identity,
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap();

        assert!(lease.is_none());
    }

    #[test]
    fn worker_ack_rejects_wrong_worker_and_wrong_lease() {
        let mut registry = registered_registry();
        registry
            .register(SelfHostedWorkerRegistration {
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-2".to_string(),
                framework_adapter: "codex".to_string(),
                token_id: "token-2".to_string(),
                token_secret: "secret-2".to_string(),
                capabilities: vec!["logs".to_string(), "artifacts".to_string()],
            })
            .unwrap();
        let worker_1 = registry.list()[0].identity();
        let worker_2 = registry.list()[1].identity();
        let mut wrong_worker_queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        wrong_worker_queue.enqueue_run(dispatch()).unwrap();
        let lease = transport
            .poll_run(
                &registry,
                &mut wrong_worker_queue,
                SelfHostedRunPollRequest {
                    identity: worker_1.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .unwrap();

        let wrong_worker = transport
            .ack_run(
                &registry,
                &mut wrong_worker_queue,
                SelfHostedRunAckRequest {
                    identity: worker_2.clone(),
                    dispatch_id: lease.dispatch_id.clone(),
                    lease_id: lease.lease_id.clone(),
                    run_id: lease.run_id.clone(),
                    status: SelfHostedRunAckStatus::Accepted,
                    reported_at_unix: 1_725_000_011,
                },
            )
            .unwrap_err();
        let mut wrong_lease_queue = InMemorySelfHostedRunQueue::default();
        wrong_lease_queue.enqueue_run(dispatch()).unwrap();
        let lease = transport
            .poll_run(
                &registry,
                &mut wrong_lease_queue,
                SelfHostedRunPollRequest {
                    identity: worker_1.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .unwrap();
        let wrong_lease = transport
            .ack_run(
                &registry,
                &mut wrong_lease_queue,
                SelfHostedRunAckRequest {
                    identity: worker_1,
                    dispatch_id: lease.dispatch_id,
                    lease_id: "dispatch-1:attempt-999".to_string(),
                    run_id: lease.run_id,
                    status: SelfHostedRunAckStatus::Accepted,
                    reported_at_unix: 1_725_000_011,
                },
            )
            .unwrap_err();

        assert!(wrong_worker.to_string().contains("active lease"));
        assert!(wrong_lease.to_string().contains("lease_id"));
    }

    fn registered_registry() -> SelfHostedWorkerRegistry {
        let mut registry = SelfHostedWorkerRegistry::default();
        registry.register(registration()).unwrap();
        registry
    }

    fn registration() -> SelfHostedWorkerRegistration {
        SelfHostedWorkerRegistration {
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            framework_adapter: "codex".to_string(),
            token_id: "token-1".to_string(),
            token_secret: "secret-1".to_string(),
            capabilities: vec![
                "logs".to_string(),
                "heartbeat".to_string(),
                "logs".to_string(),
                " artifacts ".to_string(),
            ],
        }
    }

    fn dispatch() -> SelfHostedRunDispatch {
        SelfHostedRunDispatch {
            dispatch_id: "dispatch-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            framework_adapter: "codex".to_string(),
            required_capabilities: vec!["artifacts".to_string(), "logs".to_string()],
            workload_ref: "queue://runs/run-1".to_string(),
            queued_at_unix: 1_725_000_000,
        }
    }
}
