// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Managed worker scheduling boundary.
//!
//! The scheduler validates control-plane policy and then delegates host-level
//! lifecycle work to an `agent-worker` control client. It must not own
//! Firecracker or other isolation backend implementation details.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
};
#[cfg(unix)]
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use blake2::{
    digest::{KeyInit, Mac},
    Blake2bMac512,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    XChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};

use crate::{
    select_isolation_backend, IsolationBackendDescriptor, IsolationCleanupOutcome, IsolationError,
    IsolationExecOutcome, IsolationExecRequest, IsolationPolicy, IsolationPrepareRequest,
    IsolationStarted, IsolationStopOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTemplate {
    pub id: String,
    pub framework_adapter: String,
    pub isolation_policy: IsolationPolicy,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSchedulerConfig {
    pub max_tenant_sessions: u32,
    pub max_workspace_sessions: u32,
}

impl Default for ManagedWorkerSchedulerConfig {
    fn default() -> Self {
        Self {
            max_tenant_sessions: 1,
            max_workspace_sessions: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSessionRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub requested_framework_adapter: String,
    pub capability_envelope_id: String,
    pub active_tenant_sessions: u32,
    pub active_workspace_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerRunRequest {
    pub workload_ref: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerSession {
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub worker_template_id: String,
    pub framework_adapter: String,
    pub capability_envelope_id: String,
    pub selected_backend: IsolationBackendDescriptor,
    pub instance_id: String,
    pub status: ManagedWorkerSessionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedWorkerSessionStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
    CleanedUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerExecution {
    pub session: ManagedWorkerSession,
    pub exec: IsolationExecOutcome,
    pub stop: IsolationStopOutcome,
    pub cleanup: IsolationCleanupOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerFailedExecution {
    pub session: ManagedWorkerSession,
    pub error: ManagedWorkerError,
    pub stop: Option<IsolationStopOutcome>,
    pub cleanup: IsolationCleanupOutcome,
}

pub type ManagedWorkerFailure = Box<ManagedWorkerFailedExecution>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerCancellation {
    pub session: ManagedWorkerSession,
    pub stop: IsolationStopOutcome,
    pub cleanup: IsolationCleanupOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkerLifecycleRecord {
    pub session_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_template_id: String,
    pub agent_worker_id: String,
    pub isolation_backend_kind: crate::IsolationBackendKind,
    pub isolation_instance_id: Option<String>,
    pub capability_envelope_id: String,
    pub status: ManagedWorkerSessionStatus,
    pub action: ManagedWorkerLifecycleAction,
    pub outcome: String,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedWorkerLifecycleAction {
    ExecOrAttach,
    Stop,
    Cleanup,
    Failure,
}

pub const AGENT_WORKER_PROTOCOL_VERSION: u32 = 1;
pub const AGENT_WORKER_CLOCK_SKEW_MILLIS: u64 = 30_000;
pub const AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const AGENT_WORKER_SYMMETRIC_AEAD_ALGORITHM: &str = "xchacha20poly1305";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkerManagementAction {
    ProbeHandlers,
    ListBackends,
    Provision,
    ExecOrAttach,
    Stop,
    Cleanup,
    StreamStatus,
    CollectArtifacts,
}

impl AgentWorkerManagementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProbeHandlers => "probe_handlers",
            Self::ListBackends => "list_backends",
            Self::Provision => "provision",
            Self::ExecOrAttach => "exec_or_attach",
            Self::Stop => "stop",
            Self::Cleanup => "cleanup",
            Self::StreamStatus => "stream_status",
            Self::CollectArtifacts => "collect_artifacts",
        }
    }

    pub fn requires_lifecycle_context(self) -> bool {
        matches!(
            self,
            Self::Provision
                | Self::ExecOrAttach
                | Self::Stop
                | Self::Cleanup
                | Self::StreamStatus
                | Self::CollectArtifacts
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkerManagementErrorCode {
    InvalidRequest,
    UnsupportedProtocolVersion,
    UnsupportedAction,
    MissingRequiredField,
    TransportSecurityRequired,
    PolicyDenied,
    QuotaExceeded,
    IncompatibleBackend,
    HandlerUnavailable,
    WorkerBusy,
    ProvisionFailed,
    RunFailed,
    Timeout,
    Cancelled,
    CleanupFailed,
    InvalidDeadline,
    DeadlineExpired,
    ClockSkewExceeded,
    InvalidMacKey,
    UnsupportedSignatureAlgorithm,
    InvalidSignature,
    UnknownKey,
    NonceReplay,
    IdempotencyConflict,
    MessageTooLarge,
    InvalidFrame,
    DecryptionFailed,
}

impl AgentWorkerManagementErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::UnsupportedAction => "unsupported_action",
            Self::MissingRequiredField => "missing_required_field",
            Self::TransportSecurityRequired => "transport_security_required",
            Self::PolicyDenied => "policy_denied",
            Self::QuotaExceeded => "quota_exceeded",
            Self::IncompatibleBackend => "incompatible_backend",
            Self::HandlerUnavailable => "handler_unavailable",
            Self::WorkerBusy => "worker_busy",
            Self::ProvisionFailed => "provision_failed",
            Self::RunFailed => "run_failed",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::CleanupFailed => "cleanup_failed",
            Self::InvalidDeadline => "invalid_deadline",
            Self::DeadlineExpired => "deadline_expired",
            Self::ClockSkewExceeded => "clock_skew_exceeded",
            Self::InvalidMacKey => "invalid_mac_key",
            Self::UnsupportedSignatureAlgorithm => "unsupported_signature_algorithm",
            Self::InvalidSignature => "invalid_signature",
            Self::UnknownKey => "unknown_key",
            Self::NonceReplay => "nonce_replay",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::MessageTooLarge => "message_too_large",
            Self::InvalidFrame => "invalid_frame",
            Self::DecryptionFailed => "decryption_failed",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::DeadlineExpired
                | Self::ClockSkewExceeded
                | Self::WorkerBusy
                | Self::ProvisionFailed
                | Self::Timeout
                | Self::CleanupFailed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementSecurity {
    pub key_id: String,
    pub nonce: String,
    pub signature: String,
    pub algorithm: AgentWorkerSecurityAlgorithm,
    #[serde(default = "default_agent_worker_transport_security")]
    pub transport_security: AgentWorkerTransportSecurity,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementFrame {
    pub protocol_version: u32,
    pub action: AgentWorkerManagementAction,
    pub request_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_adapter: Option<String>,
    pub encoding: AgentWorkerManagementFrameEncoding,
    pub plaintext_json: Option<String>,
    pub encrypted_payload: Option<AgentWorkerEncryptedPayload>,
}

impl AgentWorkerManagementFrame {
    pub fn from_plaintext_envelope(
        envelope: &AgentWorkerManagementEnvelope,
    ) -> Result<Self, ManagedWorkerError> {
        envelope.validate_message_size()?;
        Ok(Self {
            protocol_version: envelope.protocol_version,
            action: envelope.action,
            request_id: envelope.request_id.clone(),
            tenant_id: envelope.tenant_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            worker_id: envelope.worker_id.clone(),
            session_id: envelope.session_id.clone(),
            run_id: envelope.run_id.clone(),
            framework_adapter: envelope.framework_adapter.clone(),
            encoding: AgentWorkerManagementFrameEncoding::PlaintextJson,
            plaintext_json: Some(serde_json::to_string(envelope).map_err(|error| {
                ManagedWorkerError::management_protocol(
                    AgentWorkerManagementErrorCode::InvalidFrame,
                    format!("agent-worker management envelope serialization failed: {error}"),
                )
            })?),
            encrypted_payload: None,
        })
    }

    pub fn encrypt_envelope(
        envelope: &AgentWorkerManagementEnvelope,
        shared_secret: &str,
        nonce: [u8; 24],
    ) -> Result<Self, ManagedWorkerError> {
        envelope.validate_message_size()?;
        if envelope.security.transport_security != AgentWorkerTransportSecurity::SymmetricAead
            || !envelope.security.encrypted
        {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::TransportSecurityRequired,
                "agent-worker encrypted frames require symmetric_aead transport_security and encrypted=true",
            ));
        }
        let plaintext = serde_json::to_vec(envelope).map_err(|error| {
            ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidFrame,
                format!("agent-worker management envelope serialization failed: {error}"),
            )
        })?;
        let aad = envelope.frame_associated_data();
        let cipher = management_aead_cipher(shared_secret)?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                ManagedWorkerError::management_protocol(
                    AgentWorkerManagementErrorCode::InvalidFrame,
                    "agent-worker management frame encryption failed".to_string(),
                )
            })?;
        Ok(Self {
            protocol_version: envelope.protocol_version,
            action: envelope.action,
            request_id: envelope.request_id.clone(),
            tenant_id: envelope.tenant_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            worker_id: envelope.worker_id.clone(),
            session_id: envelope.session_id.clone(),
            run_id: envelope.run_id.clone(),
            framework_adapter: envelope.framework_adapter.clone(),
            encoding: AgentWorkerManagementFrameEncoding::EncryptedJson,
            plaintext_json: None,
            encrypted_payload: Some(AgentWorkerEncryptedPayload {
                algorithm: AGENT_WORKER_SYMMETRIC_AEAD_ALGORITHM.to_string(),
                nonce: BASE64_STANDARD.encode(nonce),
                ciphertext: BASE64_STANDARD.encode(ciphertext),
            }),
        })
    }

    pub fn decode_envelope(
        &self,
        shared_secret: &str,
    ) -> Result<AgentWorkerManagementEnvelope, ManagedWorkerError> {
        match self.encoding {
            AgentWorkerManagementFrameEncoding::PlaintextJson => {
                if self.encrypted_payload.is_some() {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "plaintext agent-worker frame must not carry encrypted_payload",
                    ));
                }
                let Some(plaintext_json) = &self.plaintext_json else {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "plaintext agent-worker frame missing plaintext_json",
                    ));
                };
                if plaintext_json.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::MessageTooLarge,
                        "agent-worker plaintext frame exceeds maximum message size",
                    ));
                }
                let envelope: AgentWorkerManagementEnvelope = serde_json::from_str(plaintext_json)
                    .map_err(|error| {
                        ManagedWorkerError::management_protocol(
                            AgentWorkerManagementErrorCode::InvalidFrame,
                            format!("agent-worker plaintext frame decode failed: {error}"),
                        )
                    })?;
                self.validate_envelope_identity(&envelope)?;
                Ok(envelope)
            }
            AgentWorkerManagementFrameEncoding::EncryptedJson => {
                if self.plaintext_json.is_some() {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "encrypted agent-worker frame must not carry plaintext_json",
                    ));
                }
                let Some(payload) = &self.encrypted_payload else {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "encrypted agent-worker frame missing encrypted_payload",
                    ));
                };
                if payload.algorithm != AGENT_WORKER_SYMMETRIC_AEAD_ALGORITHM {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        format!(
                            "unsupported agent-worker AEAD algorithm {}",
                            payload.algorithm
                        ),
                    ));
                }
                let nonce = BASE64_STANDARD.decode(&payload.nonce).map_err(|_| {
                    ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "agent-worker encrypted frame nonce is not valid base64",
                    )
                })?;
                if nonce.len() != 24 {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "agent-worker encrypted frame nonce must be 24 bytes",
                    ));
                }
                let nonce: [u8; 24] = nonce.try_into().map_err(|_| {
                    ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "agent-worker encrypted frame nonce must be 24 bytes",
                    )
                })?;
                let ciphertext = BASE64_STANDARD.decode(&payload.ciphertext).map_err(|_| {
                    ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::InvalidFrame,
                        "agent-worker encrypted frame ciphertext is not valid base64",
                    )
                })?;
                if ciphertext.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::MessageTooLarge,
                        "agent-worker encrypted frame exceeds maximum message size",
                    ));
                }
                let cipher = management_aead_cipher(shared_secret)?;
                let plaintext = cipher
                    .decrypt(
                        (&nonce).into(),
                        Payload {
                            msg: &ciphertext,
                            aad: self.associated_data().as_bytes(),
                        },
                    )
                    .map_err(|_| {
                        ManagedWorkerError::management_protocol(
                            AgentWorkerManagementErrorCode::DecryptionFailed,
                            "agent-worker encrypted management frame failed authentication",
                        )
                    })?;
                if plaintext.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
                    return Err(ManagedWorkerError::management_protocol(
                        AgentWorkerManagementErrorCode::MessageTooLarge,
                        "agent-worker decrypted frame exceeds maximum message size",
                    ));
                }
                let envelope: AgentWorkerManagementEnvelope = serde_json::from_slice(&plaintext)
                    .map_err(|error| {
                        ManagedWorkerError::management_protocol(
                            AgentWorkerManagementErrorCode::InvalidFrame,
                            format!(
                                "agent-worker encrypted frame plaintext decode failed: {error}"
                            ),
                        )
                    })?;
                self.validate_envelope_identity(&envelope)?;
                Ok(envelope)
            }
        }
    }

    pub fn associated_data(&self) -> String {
        [
            self.protocol_version.to_string(),
            self.action.as_str().to_string(),
            self.request_id.clone(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
            self.worker_id.clone(),
            self.session_id.clone().unwrap_or_default(),
            self.run_id.clone().unwrap_or_default(),
            self.framework_adapter.clone().unwrap_or_default(),
        ]
        .join("\n")
    }

    fn validate_envelope_identity(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
    ) -> Result<(), ManagedWorkerError> {
        if self.protocol_version != envelope.protocol_version
            || self.action != envelope.action
            || self.request_id != envelope.request_id
            || self.tenant_id != envelope.tenant_id
            || self.workspace_id != envelope.workspace_id
            || self.worker_id != envelope.worker_id
            || self.session_id != envelope.session_id
            || self.run_id != envelope.run_id
            || self.framework_adapter != envelope.framework_adapter
        {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidFrame,
                "agent-worker management frame identity does not match enclosed envelope",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkerManagementFrameEncoding {
    PlaintextJson,
    EncryptedJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerEncryptedPayload {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkerSecurityAlgorithm {
    SharedSecretBlake2b,
    MtlsBoundBlake2b,
}

impl AgentWorkerSecurityAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedSecretBlake2b => "shared_secret_blake2b",
            Self::MtlsBoundBlake2b => "mtls_bound_blake2b",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkerTransportSecurity {
    LocalUnixSocket,
    MutualTls,
    SymmetricAead,
}

impl AgentWorkerTransportSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalUnixSocket => "local_unix_socket",
            Self::MutualTls => "mutual_tls",
            Self::SymmetricAead => "symmetric_aead",
        }
    }

    pub fn is_secure_process_boundary(self) -> bool {
        matches!(
            self,
            Self::LocalUnixSocket | Self::MutualTls | Self::SymmetricAead
        )
    }
}

fn default_agent_worker_transport_security() -> AgentWorkerTransportSecurity {
    AgentWorkerTransportSecurity::SymmetricAead
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementEnvelope {
    pub protocol_version: u32,
    pub action: AgentWorkerManagementAction,
    pub request_id: String,
    pub idempotency_key: String,
    pub issued_at_unix_millis: u64,
    pub deadline_unix_millis: u64,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_adapter: Option<String>,
    pub security: AgentWorkerManagementSecurity,
}

impl AgentWorkerManagementEnvelope {
    pub fn validate(&self, now_unix_millis: u64) -> Result<(), ManagedWorkerError> {
        self.validate_message_size()?;
        if self.protocol_version != AGENT_WORKER_PROTOCOL_VERSION {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::UnsupportedProtocolVersion,
                format!(
                    "unsupported agent-worker protocol version {}",
                    self.protocol_version
                ),
            ));
        }
        require_management_non_empty("request_id", &self.request_id)?;
        require_management_non_empty("idempotency_key", &self.idempotency_key)?;
        require_management_non_empty("tenant_id", &self.tenant_id)?;
        require_management_non_empty("workspace_id", &self.workspace_id)?;
        require_management_non_empty("worker_id", &self.worker_id)?;
        require_management_non_empty("security.key_id", &self.security.key_id)?;
        require_management_non_empty("security.nonce", &self.security.nonce)?;
        require_management_non_empty("security.signature", &self.security.signature)?;
        if self.action.requires_lifecycle_context() {
            require_management_non_empty(
                "session_id",
                self.session_id.as_deref().unwrap_or_default(),
            )?;
            require_management_non_empty("run_id", self.run_id.as_deref().unwrap_or_default())?;
        }
        if !self
            .security
            .transport_security
            .is_secure_process_boundary()
        {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::TransportSecurityRequired,
                "agent-worker management requests must use a local Unix socket, mTLS, or symmetric AEAD transport".to_string(),
            ));
        }
        if self.security.transport_security == AgentWorkerTransportSecurity::SymmetricAead
            && !self.security.encrypted
        {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::TransportSecurityRequired,
                "agent-worker symmetric AEAD management transport must carry encrypted payloads"
                    .to_string(),
            ));
        }
        if self.deadline_unix_millis <= self.issued_at_unix_millis {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidDeadline,
                "deadline_unix_millis must be after issued_at_unix_millis".to_string(),
            ));
        }
        if now_unix_millis > self.deadline_unix_millis {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::DeadlineExpired,
                "agent-worker management request deadline expired".to_string(),
            ));
        }
        if self.issued_at_unix_millis
            > now_unix_millis.saturating_add(AGENT_WORKER_CLOCK_SKEW_MILLIS)
        {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::ClockSkewExceeded,
                "agent-worker management request issued_at is too far in the future".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_message_size(&self) -> Result<(), ManagedWorkerError> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidFrame,
                format!("agent-worker management envelope serialization failed: {error}"),
            )
        })?;
        if encoded.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::MessageTooLarge,
                "agent-worker management envelope exceeds maximum message size",
            ));
        }
        Ok(())
    }

    pub fn canonical_signature_input(&self) -> String {
        [
            self.protocol_version.to_string(),
            self.action.as_str().to_string(),
            self.request_id.clone(),
            self.idempotency_key.clone(),
            self.issued_at_unix_millis.to_string(),
            self.deadline_unix_millis.to_string(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
            self.worker_id.clone(),
            self.session_id.clone().unwrap_or_default(),
            self.run_id.clone().unwrap_or_default(),
            self.framework_adapter.clone().unwrap_or_default(),
            self.security.key_id.clone(),
            self.security.nonce.clone(),
            self.security.algorithm.as_str().to_string(),
            self.security.transport_security.as_str().to_string(),
            self.security.encrypted.to_string(),
        ]
        .join("\n")
    }

    pub fn frame_associated_data(&self) -> String {
        AgentWorkerManagementFrame {
            protocol_version: self.protocol_version,
            action: self.action,
            request_id: self.request_id.clone(),
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            worker_id: self.worker_id.clone(),
            session_id: self.session_id.clone(),
            run_id: self.run_id.clone(),
            framework_adapter: self.framework_adapter.clone(),
            encoding: AgentWorkerManagementFrameEncoding::EncryptedJson,
            plaintext_json: None,
            encrypted_payload: None,
        }
        .associated_data()
    }

    pub fn shared_secret_signature(
        &self,
        shared_secret: &str,
    ) -> Result<String, ManagedWorkerError> {
        require_non_empty("shared_secret", shared_secret)?;
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| {
                ManagedWorkerError::management_protocol(
                    AgentWorkerManagementErrorCode::InvalidMacKey,
                    "shared_secret is not a valid MAC key".to_string(),
                )
            })?;
        mac.update(self.canonical_signature_input().as_bytes());
        Ok(format!(
            "blake2b-mac:{}",
            encode_hex(&mac.finalize().into_bytes())
        ))
    }

    pub fn verify_shared_secret_signature(
        &self,
        shared_secret: &str,
    ) -> Result<(), ManagedWorkerError> {
        if !matches!(
            self.security.algorithm,
            AgentWorkerSecurityAlgorithm::SharedSecretBlake2b
                | AgentWorkerSecurityAlgorithm::MtlsBoundBlake2b
        ) {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::UnsupportedSignatureAlgorithm,
                "unsupported agent-worker signature algorithm".to_string(),
            ));
        }
        let expected = self.shared_secret_signature(shared_secret)?;
        if !constant_time_eq(expected.as_bytes(), self.security.signature.as_bytes()) {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidSignature,
                "agent-worker management request signature verification failed".to_string(),
            ));
        }
        Ok(())
    }

    fn idempotency_fingerprint(&self) -> String {
        [
            self.protocol_version.to_string(),
            self.action.as_str().to_string(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
            self.worker_id.clone(),
            self.session_id.clone().unwrap_or_default(),
            self.run_id.clone().unwrap_or_default(),
            self.framework_adapter.clone().unwrap_or_default(),
        ]
        .join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementKey {
    pub key_id: String,
    pub shared_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementVerification {
    pub request_id: String,
    pub idempotency_key: String,
    pub key_id: String,
    pub nonce: String,
    pub action: AgentWorkerManagementAction,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub framework_adapter: Option<String>,
    pub duplicate_idempotency_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementError {
    pub code: AgentWorkerManagementErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl AgentWorkerManagementError {
    pub fn new(code: AgentWorkerManagementErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.retryable(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerManagementResponse {
    pub protocol_version: u32,
    pub request_id: String,
    pub idempotency_key: String,
    pub action: AgentWorkerManagementAction,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_adapter: Option<String>,
    pub accepted: bool,
    pub duplicate_idempotency_key: bool,
    pub result: Option<AgentWorkerManagementResult>,
    pub error: Option<AgentWorkerManagementError>,
}

impl AgentWorkerManagementResponse {
    pub fn accepted(verification: AgentWorkerManagementVerification) -> Self {
        Self {
            protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
            request_id: verification.request_id,
            idempotency_key: verification.idempotency_key,
            action: verification.action,
            tenant_id: verification.tenant_id,
            workspace_id: verification.workspace_id,
            worker_id: verification.worker_id,
            session_id: verification.session_id,
            run_id: verification.run_id,
            framework_adapter: verification.framework_adapter,
            accepted: true,
            duplicate_idempotency_key: verification.duplicate_idempotency_key,
            result: None,
            error: None,
        }
    }

    pub fn with_result(mut self, result: AgentWorkerManagementResult) -> Self {
        self.result = Some(result);
        self
    }

    pub fn rejected(envelope: &AgentWorkerManagementEnvelope, error: &ManagedWorkerError) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            request_id: envelope.request_id.clone(),
            idempotency_key: envelope.idempotency_key.clone(),
            action: envelope.action,
            tenant_id: envelope.tenant_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            worker_id: envelope.worker_id.clone(),
            session_id: envelope.session_id.clone(),
            run_id: envelope.run_id.clone(),
            framework_adapter: envelope.framework_adapter.clone(),
            accepted: false,
            duplicate_idempotency_key: false,
            result: None,
            error: Some(error.management_error()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentWorkerManagementResult {
    FrameworkHandlers {
        handlers: Vec<AgentWorkerFrameworkHandler>,
    },
    IsolationBackends {
        registry_implemented: bool,
        backends: Vec<AgentWorkerIsolationBackendReport>,
    },
    Lifecycle {
        lifecycle: AgentWorkerLifecycleResult,
    },
    HandlerEvents {
        events: Vec<AgentWorkerFrameworkEventResult>,
    },
    HandlerArtifacts {
        artifacts: Vec<AgentWorkerFrameworkArtifactResult>,
        events: Vec<AgentWorkerFrameworkEventResult>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerFrameworkEventResult {
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub adapter_version: String,
    pub framework: String,
    pub mode: String,
    pub kind: String,
    pub message: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerFrameworkArtifactResult {
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerIsolationBackendReport {
    pub backend_name: String,
    pub backend_version: String,
    pub kind: String,
    pub ready: bool,
    pub readiness_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerLifecycleResult {
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub action: AgentWorkerManagementAction,
    pub status: ManagedWorkerSessionStatus,
    pub backend_name: String,
    pub backend_kind: String,
    pub isolation_instance_id: Option<String>,
    pub outcome: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct AgentWorkerManagementVerifier {
    shared_secrets: HashMap<String, String>,
    seen_nonces: HashSet<String>,
    idempotency_bindings: HashMap<String, String>,
}

impl AgentWorkerManagementVerifier {
    pub fn new(keys: Vec<AgentWorkerManagementKey>) -> Result<Self, ManagedWorkerError> {
        let mut shared_secrets = HashMap::new();
        for key in keys {
            require_non_empty("management_key.key_id", &key.key_id)?;
            require_non_empty("management_key.shared_secret", &key.shared_secret)?;
            if shared_secrets
                .insert(key.key_id.clone(), key.shared_secret)
                .is_some()
            {
                return Err(ManagedWorkerError::InvalidConfig(format!(
                    "duplicate agent-worker management key_id {}",
                    key.key_id
                )));
            }
        }
        if shared_secrets.is_empty() {
            return Err(ManagedWorkerError::InvalidConfig(
                "at least one agent-worker management key is required".to_string(),
            ));
        }
        Ok(Self {
            shared_secrets,
            seen_nonces: HashSet::new(),
            idempotency_bindings: HashMap::new(),
        })
    }

    pub fn verify(
        &mut self,
        envelope: &AgentWorkerManagementEnvelope,
        now_unix_millis: u64,
    ) -> Result<AgentWorkerManagementVerification, ManagedWorkerError> {
        envelope.validate(now_unix_millis)?;
        let Some(shared_secret) = self.shared_secrets.get(&envelope.security.key_id) else {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::UnknownKey,
                format!(
                    "unknown agent-worker management key_id {}",
                    envelope.security.key_id
                ),
            ));
        };
        envelope.verify_shared_secret_signature(shared_secret)?;

        let nonce_key = format!("{}\n{}", envelope.security.key_id, envelope.security.nonce);
        if self.seen_nonces.contains(&nonce_key) {
            return Err(ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::NonceReplay,
                "agent-worker management nonce replayed".to_string(),
            ));
        }

        let idempotency_key = self.scoped_idempotency_key(envelope);
        let fingerprint = envelope.idempotency_fingerprint();
        let duplicate_idempotency_key = match self.idempotency_bindings.get(&idempotency_key) {
            Some(previous) if previous == &fingerprint => true,
            Some(_) => {
                return Err(ManagedWorkerError::management_protocol(
                    AgentWorkerManagementErrorCode::IdempotencyConflict,
                    "idempotency_key reused for a different agent-worker management request"
                        .to_string(),
                ));
            }
            None => {
                self.idempotency_bindings
                    .insert(idempotency_key, fingerprint);
                false
            }
        };

        self.seen_nonces.insert(nonce_key);
        Ok(AgentWorkerManagementVerification {
            request_id: envelope.request_id.clone(),
            idempotency_key: envelope.idempotency_key.clone(),
            key_id: envelope.security.key_id.clone(),
            nonce: envelope.security.nonce.clone(),
            action: envelope.action,
            tenant_id: envelope.tenant_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            worker_id: envelope.worker_id.clone(),
            session_id: envelope.session_id.clone(),
            run_id: envelope.run_id.clone(),
            framework_adapter: envelope.framework_adapter.clone(),
            duplicate_idempotency_key,
        })
    }

    fn scoped_idempotency_key(&self, envelope: &AgentWorkerManagementEnvelope) -> String {
        [
            envelope.tenant_id.clone(),
            envelope.workspace_id.clone(),
            envelope.idempotency_key.clone(),
        ]
        .join("\n")
    }
}

pub trait AgentWorkerManagementTransport {
    fn accept_management_request(
        &mut self,
        envelope: AgentWorkerManagementEnvelope,
        now_unix_millis: u64,
    ) -> AgentWorkerManagementResponse;
}

#[derive(Debug, Clone)]
pub struct InMemoryAgentWorkerManagementTransport {
    verifier: AgentWorkerManagementVerifier,
    responses: Vec<AgentWorkerManagementResponse>,
}

impl InMemoryAgentWorkerManagementTransport {
    pub fn new(verifier: AgentWorkerManagementVerifier) -> Self {
        Self {
            verifier,
            responses: Vec::new(),
        }
    }

    pub fn responses(&self) -> &[AgentWorkerManagementResponse] {
        &self.responses
    }
}

impl AgentWorkerManagementTransport for InMemoryAgentWorkerManagementTransport {
    fn accept_management_request(
        &mut self,
        envelope: AgentWorkerManagementEnvelope,
        now_unix_millis: u64,
    ) -> AgentWorkerManagementResponse {
        let response = match self.verifier.verify(&envelope, now_unix_millis) {
            Ok(verification) => AgentWorkerManagementResponse::accepted(verification),
            Err(error) => AgentWorkerManagementResponse::rejected(&envelope, &error),
        };
        self.responses.push(response.clone());
        response
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkerHttpManagementClient {
    endpoint: SocketAddr,
}

impl AgentWorkerHttpManagementClient {
    pub fn new(endpoint: SocketAddr) -> Self {
        Self { endpoint }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn send_management_request_over_mtls(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
    ) -> Result<AgentWorkerManagementResponse, ManagedWorkerError> {
        if envelope.security.transport_security != AgentWorkerTransportSecurity::MutualTls
            || envelope.security.encrypted
        {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::TransportSecurityRequired,
                "agent-worker HTTP mTLS management requests require mutual_tls transport_security and encrypted=false",
            ));
        }
        let request = serde_json::to_string(envelope).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management request serialization failed: {error}"
            ))
        })?;
        self.send_json_request(&request, AgentWorkerTransportSecurity::MutualTls)
    }

    pub fn send_encrypted_management_request(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
        shared_secret: &str,
        nonce: [u8; 24],
    ) -> Result<AgentWorkerManagementResponse, ManagedWorkerError> {
        let frame = AgentWorkerManagementFrame::encrypt_envelope(envelope, shared_secret, nonce)?;
        let request = serde_json::to_string(&frame).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP encrypted management frame serialization failed: {error}"
            ))
        })?;
        self.send_json_request(&request, AgentWorkerTransportSecurity::SymmetricAead)
    }

    fn send_json_request(
        &self,
        body: &str,
        transport_security: AgentWorkerTransportSecurity,
    ) -> Result<AgentWorkerManagementResponse, ManagedWorkerError> {
        if body.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::MessageTooLarge,
                "agent-worker HTTP management request exceeds maximum message size",
            ));
        }
        let mut stream = TcpStream::connect(self.endpoint).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management connect failed at {}: {error}",
                self.endpoint
            ))
        })?;
        let request = format!(
            "POST /v1/agent-worker/management HTTP/1.1\r\n\
             host: {}\r\n\
             content-type: application/json\r\n\
             x-ferrogate-transport-security: {}\r\n\
             content-length: {}\r\n\
             connection: close\r\n\
             \r\n\
             {}",
            self.endpoint,
            transport_security.as_str(),
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management request write failed: {error}"
            ))
        })?;
        stream.shutdown(Shutdown::Write).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management request shutdown failed: {error}"
            ))
        })?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management response read failed: {error}"
            ))
        })?;
        if response.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::MessageTooLarge,
                "agent-worker HTTP management response exceeds maximum message size",
            ));
        }
        decode_http_management_response(&response)
    }
}

fn decode_http_management_response(
    response: &[u8],
) -> Result<AgentWorkerManagementResponse, ManagedWorkerError> {
    let response = std::str::from_utf8(response).map_err(|_| {
        ManagedWorkerError::AgentWorker(
            "agent-worker HTTP management response is not valid UTF-8".to_string(),
        )
    })?;
    let Some(header_end) = response.find("\r\n\r\n") else {
        return Err(ManagedWorkerError::AgentWorker(
            "agent-worker HTTP management response missing header terminator".to_string(),
        ));
    };
    let (headers, body) = response.split_at(header_end);
    let body = &body[4..];
    let mut header_lines = headers.lines();
    let status_line = header_lines.next().unwrap_or_default();
    let status_code = parse_http_status_code(status_line)?;
    if status_code != 200 {
        return Err(ManagedWorkerError::AgentWorker(format!(
            "agent-worker HTTP management response returned status {status_code}"
        )));
    }
    serde_json::from_str(body.trim()).map_err(|error| {
        ManagedWorkerError::AgentWorker(format!(
            "agent-worker HTTP management response decode failed: {error}"
        ))
    })
}

fn parse_http_status_code(status_line: &str) -> Result<u16, ManagedWorkerError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(ManagedWorkerError::AgentWorker(format!(
            "agent-worker HTTP management response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker HTTP management response has invalid status code: {status_line}"
            ))
        })
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkerUnixManagementClient {
    socket_path: PathBuf,
}

#[cfg(unix)]
impl AgentWorkerUnixManagementClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn send_management_request(
        &self,
        envelope: &AgentWorkerManagementEnvelope,
    ) -> Result<AgentWorkerManagementResponse, ManagedWorkerError> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management connect failed at {}: {error}",
                self.socket_path.display()
            ))
        })?;
        let request = serde_json::to_string(envelope).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management request serialization failed: {error}"
            ))
        })?;
        if request.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::MessageTooLarge,
                "agent-worker Unix management request exceeds maximum message size",
            ));
        }
        stream.write_all(request.as_bytes()).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management request write failed: {error}"
            ))
        })?;
        stream.shutdown(Shutdown::Write).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management request shutdown failed: {error}"
            ))
        })?;
        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management response read failed: {error}"
            ))
        })?;
        if response.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Err(ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::MessageTooLarge,
                "agent-worker Unix management response exceeds maximum message size",
            ));
        }
        serde_json::from_str(response.trim()).map_err(|error| {
            ManagedWorkerError::AgentWorker(format!(
                "agent-worker Unix management response decode failed: {error}"
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerFrameworkHandler {
    pub adapter_name: String,
    pub framework: String,
    pub version: String,
    pub ready: bool,
    pub readiness_reason: Option<String>,
}

pub trait AgentWorkerControlClient {
    fn framework_handlers(&mut self) -> &[AgentWorkerFrameworkHandler];
    fn backends(&mut self) -> &[IsolationBackendDescriptor];
    fn provision_managed_worker(
        &mut self,
        request: IsolationPrepareRequest,
    ) -> Result<IsolationStarted, ManagedWorkerError>;
    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> Result<IsolationExecOutcome, ManagedWorkerError>;
    fn stop_managed_worker(
        &mut self,
        instance_id: &str,
        reason: &str,
    ) -> Result<IsolationStopOutcome, ManagedWorkerError>;
    fn cleanup_managed_worker(
        &mut self,
        instance_id: &str,
    ) -> Result<IsolationCleanupOutcome, ManagedWorkerError>;
}

#[derive(Debug, Clone)]
pub struct ManagedWorkerScheduler {
    config: ManagedWorkerSchedulerConfig,
    templates: Vec<WorkerTemplate>,
}

impl ManagedWorkerScheduler {
    pub fn new(
        config: ManagedWorkerSchedulerConfig,
        templates: Vec<WorkerTemplate>,
    ) -> Result<Self, ManagedWorkerError> {
        if config.max_tenant_sessions == 0 {
            return Err(ManagedWorkerError::InvalidConfig(
                "max_tenant_sessions must be greater than zero".to_string(),
            ));
        }
        if config.max_workspace_sessions == 0 {
            return Err(ManagedWorkerError::InvalidConfig(
                "max_workspace_sessions must be greater than zero".to_string(),
            ));
        }
        if templates.is_empty() {
            return Err(ManagedWorkerError::InvalidConfig(
                "at least one worker template is required".to_string(),
            ));
        }
        Ok(Self { config, templates })
    }

    pub fn start_session<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerSession, ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        self.validate_request(&request)?;
        self.check_concurrency(&request)?;
        let template = self.select_template(&request)?;
        self.check_framework_handler(template, agent_worker)?;
        let selected_backend =
            select_isolation_backend(&template.isolation_policy, agent_worker.backends())
                .map_err(ManagedWorkerError::Isolation)?
                .clone();

        let started = agent_worker.provision_managed_worker(IsolationPrepareRequest {
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            worker_template_id: template.id.clone(),
            framework_adapter: template.framework_adapter.clone(),
            capability_envelope_id: request.capability_envelope_id.clone(),
            policy: template.isolation_policy.clone(),
        })?;

        Ok(ManagedWorkerSession {
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            session_id: request.session_id,
            run_id: request.run_id,
            worker_template_id: template.id.clone(),
            framework_adapter: template.framework_adapter.clone(),
            capability_envelope_id: request.capability_envelope_id,
            selected_backend,
            instance_id: started.instance_id,
            status: ManagedWorkerSessionStatus::Running,
        })
    }

    pub fn run_to_completion<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        run: ManagedWorkerRunRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerExecution, ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        let mut session = self.start_session(request, agent_worker)?;
        let exec = agent_worker.exec_or_attach(IsolationExecRequest {
            instance_id: session.instance_id.clone(),
            workload_ref: run.workload_ref,
            args: run.args,
        })?;
        let stop = agent_worker.stop_managed_worker(&session.instance_id, "completed")?;
        let cleanup = agent_worker.cleanup_managed_worker(&session.instance_id)?;
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerExecution {
            session,
            exec,
            stop,
            cleanup,
        })
    }

    pub fn run_with_cleanup<C>(
        &self,
        request: ManagedWorkerSessionRequest,
        run: ManagedWorkerRunRequest,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerExecution, ManagedWorkerFailure>
    where
        C: AgentWorkerControlClient,
    {
        let mut session = self.start_session(request, agent_worker).map_err(|error| {
            Box::new(ManagedWorkerFailedExecution {
                session: ManagedWorkerSession::failed_before_start(),
                error,
                stop: None,
                cleanup: IsolationCleanupOutcome::not_started(),
            })
        })?;
        let exec = match agent_worker.exec_or_attach(IsolationExecRequest {
            instance_id: session.instance_id.clone(),
            workload_ref: run.workload_ref,
            args: run.args,
        }) {
            Ok(exec) => exec,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let stop = match agent_worker.stop_managed_worker(&session.instance_id, "completed") {
            Ok(stop) => stop,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => cleanup,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(Box::new(ManagedWorkerFailedExecution {
                    session,
                    error,
                    stop: Some(stop),
                    cleanup: IsolationCleanupOutcome::not_started(),
                }));
            }
        };
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerExecution {
            session,
            exec,
            stop,
            cleanup,
        })
    }

    pub fn cancel_session<C>(
        &self,
        mut session: ManagedWorkerSession,
        reason: &str,
        agent_worker: &mut C,
    ) -> Result<ManagedWorkerCancellation, ManagedWorkerFailure>
    where
        C: AgentWorkerControlClient,
    {
        if reason.trim().is_empty() {
            return Err(Box::new(ManagedWorkerFailedExecution {
                session,
                error: ManagedWorkerError::InvalidRequest(
                    "cancel reason must not be empty".to_string(),
                ),
                stop: None,
                cleanup: IsolationCleanupOutcome::not_started(),
            }));
        }
        let stop = match agent_worker.stop_managed_worker(&session.instance_id, reason) {
            Ok(stop) => stop,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(self.cleanup_failed_session(session, error, agent_worker));
            }
        };
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => cleanup,
            Err(error) => {
                session.status = ManagedWorkerSessionStatus::Failed;
                return Err(Box::new(ManagedWorkerFailedExecution {
                    session,
                    error,
                    stop: Some(stop),
                    cleanup: IsolationCleanupOutcome::not_started(),
                }));
            }
        };
        session.status = ManagedWorkerSessionStatus::CleanedUp;
        Ok(ManagedWorkerCancellation {
            session,
            stop,
            cleanup,
        })
    }

    fn cleanup_failed_session<C>(
        &self,
        mut session: ManagedWorkerSession,
        error: ManagedWorkerError,
        agent_worker: &mut C,
    ) -> ManagedWorkerFailure
    where
        C: AgentWorkerControlClient,
    {
        let stop = agent_worker
            .stop_managed_worker(&session.instance_id, "failed")
            .ok();
        let cleanup = match agent_worker.cleanup_managed_worker(&session.instance_id) {
            Ok(cleanup) => {
                session.status = ManagedWorkerSessionStatus::CleanedUp;
                cleanup
            }
            Err(_) => IsolationCleanupOutcome::not_started(),
        };
        Box::new(ManagedWorkerFailedExecution {
            session,
            error,
            stop,
            cleanup,
        })
    }

    fn validate_request(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<(), ManagedWorkerError> {
        if request.tenant_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "tenant_id must not be empty".to_string(),
            ));
        }
        if request.workspace_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "workspace_id must not be empty".to_string(),
            ));
        }
        if request.session_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "session_id must not be empty".to_string(),
            ));
        }
        if request.run_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "run_id must not be empty".to_string(),
            ));
        }
        if request.requested_framework_adapter.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "requested_framework_adapter must not be empty".to_string(),
            ));
        }
        if request.capability_envelope_id.trim().is_empty() {
            return Err(ManagedWorkerError::InvalidRequest(
                "capability_envelope_id must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn check_concurrency(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<(), ManagedWorkerError> {
        if request.active_tenant_sessions >= self.config.max_tenant_sessions {
            return Err(ManagedWorkerError::QuotaExceeded(
                "tenant managed worker concurrency exceeded".to_string(),
            ));
        }
        if request.active_workspace_sessions >= self.config.max_workspace_sessions {
            return Err(ManagedWorkerError::QuotaExceeded(
                "workspace managed worker concurrency exceeded".to_string(),
            ));
        }
        Ok(())
    }

    fn select_template(
        &self,
        request: &ManagedWorkerSessionRequest,
    ) -> Result<&WorkerTemplate, ManagedWorkerError> {
        self.templates
            .iter()
            .find(|template| {
                template.enabled
                    && template.framework_adapter == request.requested_framework_adapter
            })
            .ok_or_else(|| {
                ManagedWorkerError::NoCompatibleTemplate(format!(
                    "no enabled worker template supports framework adapter {}",
                    request.requested_framework_adapter
                ))
            })
    }

    fn check_framework_handler<C>(
        &self,
        template: &WorkerTemplate,
        agent_worker: &mut C,
    ) -> Result<(), ManagedWorkerError>
    where
        C: AgentWorkerControlClient,
    {
        let handlers = agent_worker.framework_handlers();
        let Some(handler) = handlers
            .iter()
            .find(|handler| handler.adapter_name == template.framework_adapter)
        else {
            return Err(ManagedWorkerError::NoCompatibleTemplate(format!(
                "agent-worker reported no handler for framework adapter {}",
                template.framework_adapter
            )));
        };
        if !handler.ready {
            return Err(ManagedWorkerError::NoCompatibleTemplate(format!(
                "agent-worker handler {} is not ready: {}",
                handler.adapter_name,
                handler
                    .readiness_reason
                    .as_deref()
                    .unwrap_or("readiness reason was not reported")
            )));
        }
        Ok(())
    }
}

impl ManagedWorkerSession {
    fn failed_before_start() -> Self {
        Self {
            tenant_id: String::new(),
            workspace_id: String::new(),
            session_id: String::new(),
            run_id: String::new(),
            worker_template_id: String::new(),
            framework_adapter: String::new(),
            capability_envelope_id: String::new(),
            selected_backend: IsolationBackendDescriptor {
                backend_name: String::new(),
                backend_version: String::new(),
                kind: crate::IsolationBackendKind::FirecrackerMicroVm,
                capabilities: crate::IsolationBackendCapabilities::default(),
            },
            instance_id: String::new(),
            status: ManagedWorkerSessionStatus::Failed,
        }
    }
}

impl ManagedWorkerExecution {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        [
            (
                ManagedWorkerLifecycleAction::ExecOrAttach,
                &self.exec.evidence,
            ),
            (ManagedWorkerLifecycleAction::Stop, &self.stop.evidence),
            (
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ),
        ]
        .into_iter()
        .map(|(action, evidence)| self.session.lifecycle_record(action, evidence))
        .collect()
    }
}

impl ManagedWorkerCancellation {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        [
            (ManagedWorkerLifecycleAction::Stop, &self.stop.evidence),
            (
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ),
        ]
        .into_iter()
        .map(|(action, evidence)| self.session.lifecycle_record(action, evidence))
        .collect()
    }
}

impl ManagedWorkerFailedExecution {
    pub fn lifecycle_records(&self) -> Vec<ManagedWorkerLifecycleRecord> {
        let mut records = Vec::new();
        if let Some(stop) = &self.stop {
            records.push(
                self.session
                    .lifecycle_record(ManagedWorkerLifecycleAction::Stop, &stop.evidence),
            );
        }
        if self.cleanup.evidence.outcome == "not_started" {
            let mut record = self.session.lifecycle_record(
                ManagedWorkerLifecycleAction::Failure,
                &self.cleanup.evidence,
            );
            record.outcome = "failed".to_string();
            record.failure_reason = Some(self.error.to_string());
            records.push(record);
        } else {
            records.push(self.session.lifecycle_record(
                ManagedWorkerLifecycleAction::Cleanup,
                &self.cleanup.evidence,
            ));
        }
        records
    }
}

impl ManagedWorkerSession {
    fn lifecycle_record(
        &self,
        action: ManagedWorkerLifecycleAction,
        evidence: &crate::IsolationLifecycleEvidence,
    ) -> ManagedWorkerLifecycleRecord {
        ManagedWorkerLifecycleRecord {
            session_id: self.session_id.clone(),
            run_id: self.run_id.clone(),
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            worker_template_id: self.worker_template_id.clone(),
            agent_worker_id: evidence.agent_worker_id.clone(),
            isolation_backend_kind: self.selected_backend.kind.clone(),
            isolation_instance_id: evidence
                .isolation_instance_id
                .clone()
                .or_else(|| Some(self.instance_id.clone()).filter(|value| !value.is_empty())),
            capability_envelope_id: evidence.capability_envelope_id.clone(),
            status: self.status,
            action,
            outcome: evidence.outcome.clone(),
            failure_reason: evidence.failure_reason.clone(),
        }
    }
}

impl IsolationCleanupOutcome {
    fn not_started() -> Self {
        Self {
            instance_id: String::new(),
            evidence: crate::IsolationLifecycleEvidence {
                backend_name: String::new(),
                backend_version: String::new(),
                agent_worker_id: String::new(),
                isolation_instance_id: None,
                resource_limits: crate::IsolationResourceLimits::default(),
                network_policy: crate::IsolationNetworkPolicy::default(),
                filesystem_policy: crate::IsolationFilesystemPolicy::default(),
                capability_envelope_id: String::new(),
                outcome: "not_started".to_string(),
                failure_reason: Some("session was not provisioned".to_string()),
            },
        }
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ManagedWorkerError> {
    if value.trim().is_empty() {
        return Err(ManagedWorkerError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_management_non_empty(field: &str, value: &str) -> Result<(), ManagedWorkerError> {
    if value.trim().is_empty() {
        return Err(ManagedWorkerError::management_protocol(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn management_aead_cipher(shared_secret: &str) -> Result<XChaCha20Poly1305, ManagedWorkerError> {
    require_non_empty("shared_secret", shared_secret)?;
    let mut mac =
        <Blake2bMac512 as KeyInit>::new_from_slice(shared_secret.as_bytes()).map_err(|_| {
            ManagedWorkerError::management_protocol(
                AgentWorkerManagementErrorCode::InvalidMacKey,
                "shared_secret is not a valid AEAD key source".to_string(),
            )
        })?;
    mac.update(b"ferrogate-agent-worker-management-aead-v1");
    let derived = mac.finalize().into_bytes();
    <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&derived[..32]).map_err(|_| {
        ManagedWorkerError::management_protocol(
            AgentWorkerManagementErrorCode::InvalidMacKey,
            "derived agent-worker AEAD key is invalid".to_string(),
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedWorkerError {
    InvalidConfig(String),
    InvalidRequest(String),
    ManagementProtocol(AgentWorkerManagementError),
    QuotaExceeded(String),
    NoCompatibleTemplate(String),
    Isolation(IsolationError),
    AgentWorker(String),
}

impl ManagedWorkerError {
    fn management_protocol(
        code: AgentWorkerManagementErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self::management_protocol_error(code, message)
    }

    pub fn management_protocol_error(
        code: AgentWorkerManagementErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self::ManagementProtocol(AgentWorkerManagementError::new(code, message))
    }

    pub fn management_error(&self) -> AgentWorkerManagementError {
        match self {
            Self::ManagementProtocol(error) => error.clone(),
            Self::InvalidRequest(message) => AgentWorkerManagementError::new(
                AgentWorkerManagementErrorCode::InvalidRequest,
                message.clone(),
            ),
            Self::InvalidConfig(message) => AgentWorkerManagementError::new(
                AgentWorkerManagementErrorCode::InvalidRequest,
                message.clone(),
            ),
            Self::QuotaExceeded(message) => AgentWorkerManagementError {
                code: AgentWorkerManagementErrorCode::InvalidRequest,
                message: message.clone(),
                retryable: true,
            },
            Self::NoCompatibleTemplate(message) => AgentWorkerManagementError {
                code: AgentWorkerManagementErrorCode::InvalidRequest,
                message: message.clone(),
                retryable: false,
            },
            Self::Isolation(error) => AgentWorkerManagementError {
                code: AgentWorkerManagementErrorCode::InvalidRequest,
                message: error.to_string(),
                retryable: true,
            },
            Self::AgentWorker(message) => AgentWorkerManagementError {
                code: AgentWorkerManagementErrorCode::InvalidRequest,
                message: message.clone(),
                retryable: true,
            },
        }
    }
}

impl fmt::Display for ManagedWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid managed worker config: {message}")
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid managed worker request: {message}")
            }
            Self::ManagementProtocol(error) => {
                write!(
                    formatter,
                    "agent-worker management protocol rejected request: {} ({})",
                    error.message,
                    error.code.as_str()
                )
            }
            Self::QuotaExceeded(message) => {
                write!(formatter, "managed worker quota exceeded: {message}")
            }
            Self::NoCompatibleTemplate(message) => {
                write!(
                    formatter,
                    "no compatible managed worker template: {message}"
                )
            }
            Self::Isolation(error) => write!(formatter, "managed worker isolation failed: {error}"),
            Self::AgentWorker(message) => {
                write!(formatter, "agent-worker control failed: {message}")
            }
        }
    }
}

impl Error for ManagedWorkerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Isolation(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IsolationBackendCapabilities, IsolationBackendKind, IsolationFilesystemPolicy,
        IsolationLifecycleEvidence, IsolationNetworkPolicy, IsolationResourceLimits,
    };
    use std::{net::TcpListener, thread};

    #[test]
    fn schedules_managed_session_through_agent_worker_control_client() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);

        let execution = scheduler
            .run_to_completion(session_request(), run_request(), &mut agent_worker)
            .unwrap();

        assert_eq!(
            agent_worker.calls,
            vec![
                "framework_handlers",
                "backends",
                "provision_managed_worker",
                "exec_or_attach",
                "stop_managed_worker",
                "cleanup_managed_worker",
            ]
        );
        assert_eq!(
            execution.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert_eq!(
            execution.session.selected_backend.kind,
            IsolationBackendKind::FirecrackerMicroVm
        );
        assert_eq!(execution.session.worker_template_id, "template-codex");
        assert_eq!(execution.session.capability_envelope_id, "capability-1");
        assert_eq!(execution.exec.exit_code, Some(0));
        assert_eq!(
            execution.cleanup.evidence.agent_worker_id,
            "agent-worker-fake-1"
        );
        assert_eq!(
            execution.cleanup.evidence.isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        let records = execution.lifecycle_records();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[0].action,
            ManagedWorkerLifecycleAction::ExecOrAttach
        );
        assert_eq!(records[0].session_id, "session-1");
        assert_eq!(records[0].run_id, "run-1");
        assert_eq!(records[0].tenant_id, "tenant-1");
        assert_eq!(records[0].workspace_id, "workspace-1");
        assert_eq!(records[0].worker_template_id, "template-codex");
        assert_eq!(records[0].agent_worker_id, "agent-worker-fake-1");
        assert_eq!(
            records[0].isolation_backend_kind,
            IsolationBackendKind::FirecrackerMicroVm
        );
        assert_eq!(
            records[0].isolation_instance_id.as_deref(),
            Some("instance-run-1")
        );
        assert_eq!(records[0].capability_envelope_id, "capability-1");
        assert_eq!(records[2].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[2].outcome, "cleaned_up");
    }

    #[test]
    fn rejects_request_before_agent_worker_when_tenant_concurrency_is_exceeded() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            active_tenant_sessions: 1,
            ..session_request()
        };

        let error = scheduler
            .start_session(request, &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::QuotaExceeded(_)));
        assert!(agent_worker.calls.is_empty());
    }

    #[test]
    fn rejects_session_when_agent_worker_handler_is_not_ready() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        agent_worker.handlers[0].ready = false;
        agent_worker.handlers[0].readiness_reason = Some("codex binary missing".to_string());

        let error = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::NoCompatibleTemplate(_)));
        assert_eq!(agent_worker.calls, vec!["framework_handlers"]);
        assert!(error.to_string().contains("codex binary missing"));
    }

    #[test]
    fn failed_before_start_projects_auditable_failure_lifecycle_record() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            active_tenant_sessions: 1,
            ..session_request()
        };

        let failure = scheduler
            .run_with_cleanup(request, run_request(), &mut agent_worker)
            .unwrap_err();

        assert!(agent_worker.calls.is_empty());
        let records = failure.lifecycle_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Failure);
        assert_eq!(records[0].outcome, "failed");
        assert!(records[0]
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("tenant managed worker concurrency exceeded")));
    }

    #[test]
    fn fails_closed_when_no_template_supports_framework_adapter() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let request = ManagedWorkerSessionRequest {
            requested_framework_adapter: "unknown".to_string(),
            ..session_request()
        };

        let error = scheduler
            .start_session(request, &mut agent_worker)
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::NoCompatibleTemplate(_)));
        assert!(agent_worker.calls.is_empty());
    }

    #[test]
    fn fails_closed_when_agent_worker_has_no_compatible_backend() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "rootless-docker",
            IsolationBackendKind::RootlessDocker,
        )]);

        let error = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap_err();

        assert!(matches!(
            error,
            ManagedWorkerError::Isolation(IsolationError::NoCompatibleBackend(_))
        ));
        assert_eq!(agent_worker.calls, vec!["framework_handlers", "backends"]);
    }

    #[test]
    fn run_with_cleanup_stops_and_cleans_up_after_exec_failure() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        agent_worker.fail_exec = true;

        let failure = scheduler
            .run_with_cleanup(session_request(), run_request(), &mut agent_worker)
            .unwrap_err();

        assert_eq!(
            agent_worker.calls,
            vec![
                "framework_handlers",
                "backends",
                "provision_managed_worker",
                "exec_or_attach",
                "stop_managed_worker",
                "cleanup_managed_worker",
            ]
        );
        assert!(matches!(failure.error, ManagedWorkerError::AgentWorker(_)));
        assert_eq!(
            failure.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert!(failure.stop.is_some());
        assert_eq!(failure.cleanup.evidence.outcome, "cleaned_up");
        let records = failure.lifecycle_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Stop);
        assert_eq!(records[1].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[1].outcome, "cleaned_up");
    }

    #[test]
    fn cancel_session_stops_and_cleans_up_through_agent_worker() {
        let scheduler = scheduler();
        let mut agent_worker = FakeAgentWorker::new(vec![backend(
            "firecracker",
            IsolationBackendKind::FirecrackerMicroVm,
        )]);
        let session = scheduler
            .start_session(session_request(), &mut agent_worker)
            .unwrap();
        agent_worker.calls.clear();

        let cancellation = scheduler
            .cancel_session(session, "operator_cancelled", &mut agent_worker)
            .unwrap();

        assert_eq!(
            agent_worker.calls,
            vec!["stop_managed_worker", "cleanup_managed_worker"]
        );
        assert_eq!(
            cancellation.session.status,
            ManagedWorkerSessionStatus::CleanedUp
        );
        assert_eq!(
            cancellation.stop.evidence.outcome,
            "stopped:operator_cancelled"
        );
        assert_eq!(cancellation.cleanup.evidence.outcome, "cleaned_up");
        let records = cancellation.lifecycle_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, ManagedWorkerLifecycleAction::Stop);
        assert_eq!(records[0].outcome, "stopped:operator_cancelled");
        assert_eq!(records[1].action, ManagedWorkerLifecycleAction::Cleanup);
        assert_eq!(records[1].outcome, "cleaned_up");
    }

    #[test]
    fn rejects_invalid_scheduler_config() {
        let error = ManagedWorkerScheduler::new(
            ManagedWorkerSchedulerConfig {
                max_tenant_sessions: 0,
                max_workspace_sessions: 1,
            },
            vec![template()],
        )
        .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::InvalidConfig(_)));
    }

    #[test]
    fn agent_worker_management_envelope_requires_stable_secure_fields() {
        let envelope = management_envelope(AgentWorkerManagementAction::Provision);

        envelope.validate(1_000).unwrap();
        envelope
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        assert_eq!(envelope.action.as_str(), "provision");
        assert_eq!(
            envelope.security.algorithm.as_str(),
            "shared_secret_blake2b"
        );
        assert_eq!(
            envelope.security.transport_security.as_str(),
            "local_unix_socket"
        );
        assert!(envelope
            .canonical_signature_input()
            .contains("provision\nrequest-1\nidempotency-1"));
        assert!(envelope.canonical_signature_input().contains("\ncodex\n"));
        assert!(envelope
            .canonical_signature_input()
            .contains("shared_secret_blake2b\nlocal_unix_socket\ntrue"));
        assert!(envelope.security.signature.starts_with("blake2b-mac:"));

        let mut tampered_adapter = envelope.clone();
        tampered_adapter.framework_adapter = Some("claude-code".to_string());
        assert!(tampered_adapter
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));

        let mut missing_signature = envelope.clone();
        missing_signature.security.signature.clear();
        assert!(missing_signature
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("security.signature"));

        let mut unencrypted = envelope.clone();
        unencrypted.security.encrypted = false;
        unencrypted.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
        unencrypted.security.signature = unencrypted
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        assert!(unencrypted
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("symmetric AEAD"));
        assert_eq!(
            unencrypted.security.transport_security.as_str(),
            "symmetric_aead"
        );

        let mut unsigned_transport = envelope.clone();
        unsigned_transport.security.encrypted = false;
        unsigned_transport.security.transport_security =
            AgentWorkerTransportSecurity::LocalUnixSocket;
        unsigned_transport.security.signature = unsigned_transport
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        assert!(unsigned_transport.validate(1_000).is_ok());

        let mut wrong_signature = envelope.clone();
        wrong_signature.security.signature = "blake2b-mac:bad".to_string();
        assert!(wrong_signature
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));

        assert!(envelope
            .verify_shared_secret_signature("wrong-secret")
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));

        let mut expired = envelope.clone();
        expired.deadline_unix_millis = 999;
        assert!(expired
            .validate(1_000)
            .unwrap_err()
            .to_string()
            .contains("deadline expired"));
    }

    #[test]
    fn management_verifier_rejects_unknown_keys_replays_and_idempotency_conflicts() {
        let mut verifier = AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-key-1".to_string(),
            shared_secret: "agent-worker-shared-secret".to_string(),
        }])
        .unwrap();

        let envelope = management_envelope(AgentWorkerManagementAction::Provision);
        let verified = verifier.verify(&envelope, 1_000).unwrap();
        assert_eq!(verified.action, AgentWorkerManagementAction::Provision);
        assert_eq!(verified.request_id, "request-1");
        assert_eq!(verified.idempotency_key, "idempotency-1");
        assert_eq!(verified.key_id, "agent-worker-key-1");
        assert_eq!(verified.nonce, "nonce-1");
        assert_eq!(verified.tenant_id, "tenant-1");
        assert_eq!(verified.workspace_id, "workspace-1");
        assert_eq!(verified.worker_id, "agent-worker-fake-1");
        assert_eq!(verified.session_id.as_deref(), Some("session-1"));
        assert_eq!(verified.run_id.as_deref(), Some("run-1"));
        assert!(!verified.duplicate_idempotency_key);

        let replayed_nonce = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-2",
            "idempotency-2",
            "nonce-1",
        );
        assert!(verifier
            .verify(&replayed_nonce, 1_000)
            .unwrap_err()
            .to_string()
            .contains("nonce replayed"));

        let duplicate_idempotency = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-3",
            "idempotency-1",
            "nonce-3",
        );
        let verified = verifier.verify(&duplicate_idempotency, 1_000).unwrap();
        assert!(verified.duplicate_idempotency_key);

        let conflicting_idempotency = management_envelope_with(
            AgentWorkerManagementAction::Cleanup,
            "request-4",
            "idempotency-1",
            "nonce-4",
        );
        assert!(verifier
            .verify(&conflicting_idempotency, 1_000)
            .unwrap_err()
            .to_string()
            .contains("idempotency_key reused"));

        let mut unknown_key = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-5",
            "idempotency-5",
            "nonce-5",
        );
        unknown_key.security.key_id = "unknown-key".to_string();
        unknown_key.security.signature = unknown_key
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        assert!(verifier
            .verify(&unknown_key, 1_000)
            .unwrap_err()
            .to_string()
            .contains("unknown agent-worker management key_id"));
    }

    #[test]
    fn management_responses_standardize_acceptance_and_rejection_errors() {
        let mut verifier = management_verifier();

        let envelope = management_envelope(AgentWorkerManagementAction::Provision);
        let response =
            AgentWorkerManagementResponse::accepted(verifier.verify(&envelope, 1_000).unwrap());
        assert!(response.accepted);
        assert_eq!(response.protocol_version, AGENT_WORKER_PROTOCOL_VERSION);
        assert_eq!(response.request_id, "request-1");
        assert_eq!(response.idempotency_key, "idempotency-1");
        assert_eq!(response.action, AgentWorkerManagementAction::Provision);
        assert_eq!(response.tenant_id, "tenant-1");
        assert_eq!(response.workspace_id, "workspace-1");
        assert_eq!(response.worker_id, "agent-worker-fake-1");
        assert_eq!(response.session_id.as_deref(), Some("session-1"));
        assert_eq!(response.run_id.as_deref(), Some("run-1"));
        assert!(!response.duplicate_idempotency_key);
        assert!(response.result.is_none());
        assert!(response.error.is_none());

        let response_with_result =
            response
                .clone()
                .with_result(AgentWorkerManagementResult::FrameworkHandlers {
                    handlers: vec![AgentWorkerFrameworkHandler {
                        adapter_name: "native-harness".to_string(),
                        framework: "native_harness".to_string(),
                        version: "test".to_string(),
                        ready: true,
                        readiness_reason: Some(
                            "native harness is built into the worker".to_string(),
                        ),
                    }],
                });
        let result_json = serde_json::to_value(&response_with_result).unwrap();
        assert_eq!(result_json["result"]["kind"], "framework_handlers");
        assert_eq!(
            result_json["result"]["handlers"][0]["adapter_name"],
            "native-harness"
        );

        let backend_result_json = serde_json::to_value(response.clone().with_result(
            AgentWorkerManagementResult::IsolationBackends {
                registry_implemented: true,
                backends: vec![AgentWorkerIsolationBackendReport {
                    backend_name: "firecracker".to_string(),
                    backend_version: "not-wired".to_string(),
                    kind: "firecracker_micro_vm".to_string(),
                    ready: false,
                    readiness_reason: Some(
                        "Firecracker backend registry is not implemented".to_string(),
                    ),
                }],
            },
        ))
        .unwrap();
        assert_eq!(backend_result_json["result"]["kind"], "isolation_backends");
        assert_eq!(backend_result_json["result"]["registry_implemented"], true);
        assert_eq!(
            backend_result_json["result"]["backends"][0]["kind"],
            "firecracker_micro_vm"
        );

        let lifecycle_result_json = serde_json::to_value(response.clone().with_result(
            AgentWorkerManagementResult::Lifecycle {
                lifecycle: AgentWorkerLifecycleResult {
                    session_id: "session-1".to_string(),
                    run_id: "run-1".to_string(),
                    worker_id: "agent-worker-fake-1".to_string(),
                    action: AgentWorkerManagementAction::Cleanup,
                    status: ManagedWorkerSessionStatus::CleanedUp,
                    backend_name: "firecracker".to_string(),
                    backend_kind: "firecracker_micro_vm".to_string(),
                    isolation_instance_id: None,
                    outcome: "not_started".to_string(),
                    message: "cleanup accepted as no-op".to_string(),
                },
            },
        ))
        .unwrap();
        assert_eq!(lifecycle_result_json["result"]["kind"], "lifecycle");
        assert_eq!(
            lifecycle_result_json["result"]["lifecycle"]["status"],
            "cleaned_up"
        );
        assert_eq!(
            lifecycle_result_json["result"]["lifecycle"]["backend_kind"],
            "firecracker_micro_vm"
        );
        assert_eq!(
            lifecycle_result_json["result"]["lifecycle"]["isolation_instance_id"],
            serde_json::Value::Null
        );

        let duplicate_idempotency = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-2",
            "idempotency-1",
            "nonce-2",
        );
        let retry_response = AgentWorkerManagementResponse::accepted(
            verifier.verify(&duplicate_idempotency, 1_000).unwrap(),
        );
        assert!(retry_response.accepted);
        assert!(retry_response.duplicate_idempotency_key);

        let mut wrong_signature = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-3",
            "idempotency-3",
            "nonce-3",
        );
        wrong_signature.security.signature = "blake2b-mac:bad".to_string();
        let error = verifier.verify(&wrong_signature, 1_000).unwrap_err();
        let rejected = AgentWorkerManagementResponse::rejected(&wrong_signature, &error);
        assert!(!rejected.accepted);
        let rejected_error = rejected.error.unwrap();
        assert_eq!(
            rejected_error.code,
            AgentWorkerManagementErrorCode::InvalidSignature
        );
        assert_eq!(rejected_error.code.as_str(), "invalid_signature");
        assert!(!rejected_error.retryable);

        let mut expired = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-4",
            "idempotency-4",
            "nonce-4",
        );
        expired.deadline_unix_millis = 999;
        expired.security.signature = expired
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let error = verifier.verify(&expired, 1_000).unwrap_err();
        let rejected = AgentWorkerManagementResponse::rejected(&expired, &error);
        let rejected_error = rejected.error.unwrap();
        assert_eq!(
            rejected_error.code,
            AgentWorkerManagementErrorCode::DeadlineExpired
        );
        assert!(rejected_error.retryable);

        let mut unsupported_version = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-5",
            "idempotency-5",
            "nonce-5",
        );
        unsupported_version.protocol_version = AGENT_WORKER_PROTOCOL_VERSION + 1;
        unsupported_version.security.signature = unsupported_version
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let error = verifier.verify(&unsupported_version, 1_000).unwrap_err();
        let rejected = AgentWorkerManagementResponse::rejected(&unsupported_version, &error);
        let rejected_error = rejected.error.unwrap();
        assert_eq!(
            rejected_error.code,
            AgentWorkerManagementErrorCode::UnsupportedProtocolVersion
        );
        assert_eq!(rejected_error.code.as_str(), "unsupported_protocol_version");
        assert!(!rejected_error.retryable);
    }

    #[test]
    fn management_transport_wraps_verifier_into_recorded_responses() {
        let mut transport = InMemoryAgentWorkerManagementTransport::new(management_verifier());

        let accepted = transport.accept_management_request(
            management_envelope(AgentWorkerManagementAction::Provision),
            1_000,
        );
        assert!(accepted.accepted);
        assert!(accepted.error.is_none());

        let duplicate = transport.accept_management_request(
            management_envelope_with(
                AgentWorkerManagementAction::Provision,
                "request-2",
                "idempotency-1",
                "nonce-2",
            ),
            1_000,
        );
        assert!(duplicate.accepted);
        assert!(duplicate.duplicate_idempotency_key);

        let mut wrong_signature = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-3",
            "idempotency-3",
            "nonce-3",
        );
        wrong_signature.security.signature = "blake2b-mac:bad".to_string();
        let rejected = transport.accept_management_request(wrong_signature, 1_000);
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.error.as_ref().map(|error| error.code),
            Some(AgentWorkerManagementErrorCode::InvalidSignature)
        );

        assert_eq!(transport.responses().len(), 3);
        assert!(transport.responses()[0].accepted);
        assert!(transport.responses()[1].duplicate_idempotency_key);
        assert_eq!(
            transport.responses()[2]
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("invalid_signature")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_management_client_reports_missing_socket_as_agent_worker_error() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("missing-agent-worker.sock");
        let client = AgentWorkerUnixManagementClient::new(&socket_path);

        let error = client
            .send_management_request(&management_envelope(
                AgentWorkerManagementAction::ProbeHandlers,
            ))
            .unwrap_err();

        assert!(matches!(error, ManagedWorkerError::AgentWorker(_)));
        assert!(error
            .to_string()
            .contains("agent-worker Unix management connect failed"));
        assert!(error.to_string().contains("missing-agent-worker.sock"));
    }

    #[test]
    fn http_management_client_sends_signed_envelope_over_mtls_contract() {
        let mut envelope = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        envelope.security.transport_security = AgentWorkerTransportSecurity::MutualTls;
        envelope.security.encrypted = false;
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let expected_response =
            AgentWorkerManagementResponse::accepted(AgentWorkerManagementVerification {
                request_id: envelope.request_id.clone(),
                idempotency_key: envelope.idempotency_key.clone(),
                key_id: envelope.security.key_id.clone(),
                nonce: envelope.security.nonce.clone(),
                action: envelope.action,
                tenant_id: envelope.tenant_id.clone(),
                workspace_id: envelope.workspace_id.clone(),
                worker_id: envelope.worker_id.clone(),
                session_id: envelope.session_id.clone(),
                run_id: envelope.run_id.clone(),
                framework_adapter: envelope.framework_adapter.clone(),
                duplicate_idempotency_key: false,
            });
        let expected_envelope = envelope.clone();
        let server = spawn_http_management_contract_server(
            move |request| {
                assert!(request.starts_with("POST /v1/agent-worker/management HTTP/1.1\r\n"));
                assert!(request.contains("\r\ncontent-type: application/json\r\n"));
                assert!(request.contains("\r\nx-ferrogate-transport-security: mutual_tls\r\n"));
                let body = http_request_body(&request);
                let received: AgentWorkerManagementEnvelope = serde_json::from_str(body).unwrap();
                assert_eq!(received, expected_envelope);
            },
            expected_response.clone(),
            200,
        );
        let client = AgentWorkerHttpManagementClient::new(server.endpoint);

        let response = client.send_management_request_over_mtls(&envelope).unwrap();
        server.join();

        assert_eq!(response, expected_response);
    }

    #[test]
    fn http_management_client_sends_encrypted_frame_over_symmetric_aead_contract() {
        let mut envelope = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
        envelope.security.encrypted = true;
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let expected_response =
            AgentWorkerManagementResponse::accepted(AgentWorkerManagementVerification {
                request_id: envelope.request_id.clone(),
                idempotency_key: envelope.idempotency_key.clone(),
                key_id: envelope.security.key_id.clone(),
                nonce: envelope.security.nonce.clone(),
                action: envelope.action,
                tenant_id: envelope.tenant_id.clone(),
                workspace_id: envelope.workspace_id.clone(),
                worker_id: envelope.worker_id.clone(),
                session_id: envelope.session_id.clone(),
                run_id: envelope.run_id.clone(),
                framework_adapter: envelope.framework_adapter.clone(),
                duplicate_idempotency_key: false,
            });
        let expected_envelope = envelope.clone();
        let server = spawn_http_management_contract_server(
            move |request| {
                assert!(request.starts_with("POST /v1/agent-worker/management HTTP/1.1\r\n"));
                assert!(request.contains("\r\ncontent-type: application/json\r\n"));
                assert!(request.contains("\r\nx-ferrogate-transport-security: symmetric_aead\r\n"));
                let body = http_request_body(&request);
                let frame: AgentWorkerManagementFrame = serde_json::from_str(body).unwrap();
                assert_eq!(
                    frame.encoding,
                    AgentWorkerManagementFrameEncoding::EncryptedJson
                );
                assert!(frame.plaintext_json.is_none());
                let decoded = frame.decode_envelope("agent-worker-shared-secret").unwrap();
                assert_eq!(decoded, expected_envelope);
            },
            expected_response.clone(),
            200,
        );
        let client = AgentWorkerHttpManagementClient::new(server.endpoint);

        let response = client
            .send_encrypted_management_request(&envelope, "agent-worker-shared-secret", [11_u8; 24])
            .unwrap();
        server.join();

        assert_eq!(response, expected_response);
    }

    #[test]
    fn http_management_client_rejects_non_success_status() {
        let mut envelope = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        envelope.security.transport_security = AgentWorkerTransportSecurity::MutualTls;
        envelope.security.encrypted = false;
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let rejected = AgentWorkerManagementResponse::rejected(
            &envelope,
            &ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::InvalidRequest,
                "bad request",
            ),
        );
        let server = spawn_http_management_contract_server(|_| {}, rejected, 400);
        let client = AgentWorkerHttpManagementClient::new(server.endpoint);

        let error = client
            .send_management_request_over_mtls(&envelope)
            .unwrap_err();
        server.join();

        assert!(matches!(error, ManagedWorkerError::AgentWorker(_)));
        assert!(error
            .to_string()
            .contains("agent-worker HTTP management response returned status 400"));
    }

    #[test]
    fn management_wire_json_round_trips_signed_envelope_and_response_codes() {
        let envelope = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(encoded.contains(r#""action":"probe_handlers""#));
        assert!(encoded.contains(r#""algorithm":"shared_secret_blake2b""#));
        assert!(encoded.contains(r#""transport_security":"local_unix_socket""#));

        let decoded: AgentWorkerManagementEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        decoded
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap();

        let mut verifier = management_verifier();
        let mut wrong_signature = management_envelope_with(
            AgentWorkerManagementAction::Provision,
            "request-wire",
            "idempotency-wire",
            "nonce-wire",
        );
        wrong_signature.security.signature = "blake2b-mac:bad".to_string();
        let error = verifier.verify(&wrong_signature, 1_000).unwrap_err();
        let rejected = AgentWorkerManagementResponse::rejected(&wrong_signature, &error);
        let rejected_json = serde_json::to_value(&rejected).unwrap();

        assert_eq!(rejected_json["accepted"], false);
        assert_eq!(rejected_json["action"], "provision");
        assert_eq!(rejected_json["result"], serde_json::Value::Null);
        assert_eq!(rejected_json["error"]["code"], "invalid_signature");
        assert_eq!(rejected_json["error"]["retryable"], false);

        let unsupported_action = AgentWorkerManagementResponse::rejected(
            &envelope,
            &ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::UnsupportedAction,
                "agent-worker management action provision is not implemented",
            ),
        );
        let unsupported_json = serde_json::to_value(&unsupported_action).unwrap();
        assert_eq!(unsupported_json["error"]["code"], "unsupported_action");
        assert_eq!(unsupported_json["error"]["retryable"], false);

        let standardized_codes = [
            (
                AgentWorkerManagementErrorCode::PolicyDenied,
                "policy_denied",
                false,
            ),
            (
                AgentWorkerManagementErrorCode::QuotaExceeded,
                "quota_exceeded",
                false,
            ),
            (
                AgentWorkerManagementErrorCode::IncompatibleBackend,
                "incompatible_backend",
                false,
            ),
            (
                AgentWorkerManagementErrorCode::HandlerUnavailable,
                "handler_unavailable",
                false,
            ),
            (
                AgentWorkerManagementErrorCode::WorkerBusy,
                "worker_busy",
                true,
            ),
            (
                AgentWorkerManagementErrorCode::ProvisionFailed,
                "provision_failed",
                true,
            ),
            (
                AgentWorkerManagementErrorCode::RunFailed,
                "run_failed",
                false,
            ),
            (AgentWorkerManagementErrorCode::Timeout, "timeout", true),
            (
                AgentWorkerManagementErrorCode::Cancelled,
                "cancelled",
                false,
            ),
            (
                AgentWorkerManagementErrorCode::CleanupFailed,
                "cleanup_failed",
                true,
            ),
        ];
        for (code, expected_wire_code, expected_retryable) in standardized_codes {
            let rejected = AgentWorkerManagementResponse::rejected(
                &envelope,
                &ManagedWorkerError::management_protocol_error(code, "standardized failure"),
            );
            let rejected_json = serde_json::to_value(&rejected).unwrap();
            assert_eq!(rejected_json["error"]["code"], expected_wire_code);
            assert_eq!(rejected_json["error"]["retryable"], expected_retryable);
        }
    }

    #[test]
    fn lifecycle_actions_require_session_and_run_context() {
        let mut lifecycle = management_envelope(AgentWorkerManagementAction::Provision);
        lifecycle.session_id = None;
        lifecycle.security.signature = lifecycle
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();

        let error = lifecycle.validate(1_000).unwrap_err();

        assert!(error.to_string().contains("session_id"));

        let mut probe = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        probe.session_id = None;
        probe.run_id = None;
        probe.security.signature = probe
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();

        probe.validate(1_000).unwrap();
    }

    #[test]
    fn management_frame_encrypts_envelope_with_context_bound_aead() {
        let mut envelope = management_envelope(AgentWorkerManagementAction::Provision);
        envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
        envelope.security.encrypted = true;
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let frame = AgentWorkerManagementFrame::encrypt_envelope(
            &envelope,
            "agent-worker-shared-secret",
            [7_u8; 24],
        )
        .unwrap();

        assert_eq!(
            frame.encoding,
            AgentWorkerManagementFrameEncoding::EncryptedJson
        );
        assert!(frame.plaintext_json.is_none());
        assert_eq!(
            frame
                .encrypted_payload
                .as_ref()
                .map(|payload| payload.algorithm.as_str()),
            Some(AGENT_WORKER_SYMMETRIC_AEAD_ALGORITHM)
        );

        let decoded = frame.decode_envelope("agent-worker-shared-secret").unwrap();

        assert_eq!(decoded, envelope);
        decoded.validate(1_000).unwrap();
        decoded
            .verify_shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
    }

    #[test]
    fn management_frame_rejects_tampered_aad_or_wrong_secret() {
        let mut envelope = management_envelope(AgentWorkerManagementAction::Provision);
        envelope.security.transport_security = AgentWorkerTransportSecurity::SymmetricAead;
        envelope.security.encrypted = true;
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        let mut frame = AgentWorkerManagementFrame::encrypt_envelope(
            &envelope,
            "agent-worker-shared-secret",
            [9_u8; 24],
        )
        .unwrap();

        assert_eq!(
            frame
                .decode_envelope("wrong-agent-worker-shared-secret")
                .unwrap_err()
                .management_error()
                .code,
            AgentWorkerManagementErrorCode::DecryptionFailed
        );

        frame.worker_id = "other-agent-worker".to_string();
        assert_eq!(
            frame
                .decode_envelope("agent-worker-shared-secret")
                .unwrap_err()
                .management_error()
                .code,
            AgentWorkerManagementErrorCode::DecryptionFailed
        );
    }

    #[test]
    fn plaintext_management_frame_rejects_identity_mismatch() {
        let envelope = management_envelope(AgentWorkerManagementAction::ProbeHandlers);
        let mut frame = AgentWorkerManagementFrame::from_plaintext_envelope(&envelope).unwrap();
        frame.request_id = "different-request".to_string();

        let error = frame
            .decode_envelope("agent-worker-shared-secret")
            .unwrap_err();

        assert_eq!(
            error.management_error().code,
            AgentWorkerManagementErrorCode::InvalidFrame
        );
    }

    fn scheduler() -> ManagedWorkerScheduler {
        ManagedWorkerScheduler::new(ManagedWorkerSchedulerConfig::default(), vec![template()])
            .unwrap()
    }

    fn template() -> WorkerTemplate {
        WorkerTemplate {
            id: "template-codex".to_string(),
            framework_adapter: "codex".to_string(),
            isolation_policy: IsolationPolicy {
                allowed_kinds: vec![IsolationBackendKind::FirecrackerMicroVm],
                ..IsolationPolicy::default()
            },
            enabled: true,
        }
    }

    fn session_request() -> ManagedWorkerSessionRequest {
        ManagedWorkerSessionRequest {
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            requested_framework_adapter: "codex".to_string(),
            capability_envelope_id: "capability-1".to_string(),
            active_tenant_sessions: 0,
            active_workspace_sessions: 0,
        }
    }

    fn run_request() -> ManagedWorkerRunRequest {
        ManagedWorkerRunRequest {
            workload_ref: "agent://codex/run".to_string(),
            args: vec!["--task".to_string(), "smoke".to_string()],
        }
    }

    fn management_envelope(action: AgentWorkerManagementAction) -> AgentWorkerManagementEnvelope {
        management_envelope_with(action, "request-1", "idempotency-1", "nonce-1")
    }

    fn management_verifier() -> AgentWorkerManagementVerifier {
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-key-1".to_string(),
            shared_secret: "agent-worker-shared-secret".to_string(),
        }])
        .unwrap()
    }

    fn management_envelope_with(
        action: AgentWorkerManagementAction,
        request_id: &str,
        idempotency_key: &str,
        nonce: &str,
    ) -> AgentWorkerManagementEnvelope {
        let mut envelope = AgentWorkerManagementEnvelope {
            protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
            action,
            request_id: request_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            issued_at_unix_millis: 900,
            deadline_unix_millis: 2_000,
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "agent-worker-fake-1".to_string(),
            session_id: Some("session-1".to_string()),
            run_id: Some("run-1".to_string()),
            framework_adapter: Some("codex".to_string()),
            security: AgentWorkerManagementSecurity {
                key_id: "agent-worker-key-1".to_string(),
                nonce: nonce.to_string(),
                signature: String::new(),
                algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
                transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
                encrypted: true,
            },
        };
        envelope.security.signature = envelope
            .shared_secret_signature("agent-worker-shared-secret")
            .unwrap();
        envelope
    }

    fn backend(name: &str, kind: IsolationBackendKind) -> IsolationBackendDescriptor {
        IsolationBackendDescriptor {
            backend_name: name.to_string(),
            backend_version: "test-1".to_string(),
            kind,
            capabilities: IsolationBackendCapabilities::full(),
        }
    }

    struct HttpManagementContractServer {
        endpoint: SocketAddr,
        handle: thread::JoinHandle<()>,
    }

    impl HttpManagementContractServer {
        fn join(self) {
            self.handle.join().unwrap();
        }
    }

    fn spawn_http_management_contract_server<F>(
        inspect_request: F,
        response: AgentWorkerManagementResponse,
        status_code: u16,
    ) -> HttpManagementContractServer
    where
        F: FnOnce(String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            inspect_request(request);
            let body = serde_json::to_string(&response).unwrap();
            let reason = match status_code {
                200 => "OK",
                400 => "Bad Request",
                _ => "Error",
            };
            let response = format!(
                "HTTP/1.1 {status_code} {reason}\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        HttpManagementContractServer { endpoint, handle }
    }

    fn http_request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default()
    }

    struct FakeAgentWorker {
        handlers: Vec<AgentWorkerFrameworkHandler>,
        backends: Vec<IsolationBackendDescriptor>,
        calls: Vec<&'static str>,
        fail_exec: bool,
        fail_stop: bool,
        fail_cleanup: bool,
    }

    impl FakeAgentWorker {
        fn new(backends: Vec<IsolationBackendDescriptor>) -> Self {
            Self {
                handlers: vec![AgentWorkerFrameworkHandler {
                    adapter_name: "codex".to_string(),
                    framework: "codex".to_string(),
                    version: "test-1".to_string(),
                    ready: true,
                    readiness_reason: None,
                }],
                backends,
                calls: Vec::new(),
                fail_exec: false,
                fail_stop: false,
                fail_cleanup: false,
            }
        }

        fn evidence(&self, instance_id: &str, outcome: &str) -> IsolationLifecycleEvidence {
            IsolationLifecycleEvidence {
                backend_name: "firecracker".to_string(),
                backend_version: "test-1".to_string(),
                agent_worker_id: "agent-worker-fake-1".to_string(),
                isolation_instance_id: Some(instance_id.to_string()),
                resource_limits: IsolationResourceLimits::default(),
                network_policy: IsolationNetworkPolicy::default(),
                filesystem_policy: IsolationFilesystemPolicy::default(),
                capability_envelope_id: "capability-1".to_string(),
                outcome: outcome.to_string(),
                failure_reason: None,
            }
        }
    }

    impl AgentWorkerControlClient for FakeAgentWorker {
        fn framework_handlers(&mut self) -> &[AgentWorkerFrameworkHandler] {
            self.calls.push("framework_handlers");
            &self.handlers
        }

        fn backends(&mut self) -> &[IsolationBackendDescriptor] {
            self.calls.push("backends");
            &self.backends
        }

        fn provision_managed_worker(
            &mut self,
            request: IsolationPrepareRequest,
        ) -> Result<IsolationStarted, ManagedWorkerError> {
            self.calls.push("provision_managed_worker");
            Ok(IsolationStarted {
                instance_id: format!("instance-{}", request.run_id),
                evidence: self.evidence(&format!("instance-{}", request.run_id), "started"),
            })
        }

        fn exec_or_attach(
            &mut self,
            request: IsolationExecRequest,
        ) -> Result<IsolationExecOutcome, ManagedWorkerError> {
            self.calls.push("exec_or_attach");
            if self.fail_exec {
                return Err(ManagedWorkerError::AgentWorker(
                    "exec failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationExecOutcome {
                instance_id: request.instance_id.clone(),
                exit_code: Some(0),
                message: format!("executed {}", request.workload_ref),
                evidence: self.evidence(&request.instance_id, "executed"),
            })
        }

        fn stop_managed_worker(
            &mut self,
            instance_id: &str,
            reason: &str,
        ) -> Result<IsolationStopOutcome, ManagedWorkerError> {
            self.calls.push("stop_managed_worker");
            if self.fail_stop {
                return Err(ManagedWorkerError::AgentWorker(
                    "stop failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationStopOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(instance_id, &format!("stopped:{reason}")),
            })
        }

        fn cleanup_managed_worker(
            &mut self,
            instance_id: &str,
        ) -> Result<IsolationCleanupOutcome, ManagedWorkerError> {
            self.calls.push("cleanup_managed_worker");
            if self.fail_cleanup {
                return Err(ManagedWorkerError::AgentWorker(
                    "cleanup failed in fake agent-worker".to_string(),
                ));
            }
            Ok(IsolationCleanupOutcome {
                instance_id: instance_id.to_string(),
                evidence: self.evidence(instance_id, "cleaned_up"),
            })
        }
    }
}
