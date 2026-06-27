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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfHostedWorkerError {
    InvalidRegistration(String),
    DuplicateWorker(String),
    UnknownWorker(String),
    InactiveWorker(String),
    InvalidIdentity(String),
    InvalidTelemetry(String),
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

fn normalized_capabilities(mut capabilities: Vec<String>) -> Vec<String> {
    capabilities.iter_mut().for_each(|item| {
        *item = item.trim().to_string();
    });
    capabilities.sort();
    capabilities.dedup();
    capabilities
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
}
