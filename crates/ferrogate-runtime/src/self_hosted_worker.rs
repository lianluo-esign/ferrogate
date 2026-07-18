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

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Compare two secrets without leaking the position of the first differing byte
/// through timing. Length is compared first; secret length is not itself secret.
fn constant_time_secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.ct_eq(b).into()
}

const SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const SELF_HOSTED_WORKER_SYMMETRIC_AEAD_ALGORITHM: &str = "xchacha20poly1305";
/// Minimum accepted length for a transport shared secret. The provisioned
/// secret is 64 hex chars (256 bits); this floor fails closed on an empty or
/// truncated/legacy secret so a weak value can never key the cipher.
const SELF_HOSTED_WORKER_TRANSPORT_SECRET_MIN_LEN: usize = 32;
/// HKDF salt + info for deriving the transport AEAD key (RFC 5869 domain
/// separation). Bumping the info string rotates the derived key space.
const SELF_HOSTED_WORKER_TRANSPORT_HKDF_SALT: &[u8] =
    b"ferrogate/self-hosted-worker/transport-aead";
const SELF_HOSTED_WORKER_TRANSPORT_HKDF_INFO: &[u8] = b"ferrogate-self-hosted-worker-transport-v1";
static SELF_HOSTED_TRANSPORT_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Provision a fresh, high-entropy transport secret for a self-hosted worker:
/// 256 bits from the OS CSPRNG, hex-encoded (64 chars).
///
/// This is the value the symmetric-AEAD transport keys off. It MUST NOT be
/// derived from or equal to any public value -- the `identity_fingerprint` /
/// `token_id` are non-secret lookup keys returned in admin listings and carried
/// in cleartext in every frame, so reusing them (as the pre-fix wiring did)
/// makes the AEAD/bearer secret public and lets anyone forge and decrypt frames.
pub fn generate_transport_token_secret() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG must be available to provision a self-hosted worker transport secret");
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
pub const SELF_HOSTED_WORKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerRegistration {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub framework_adapter: String,
    pub token_id: String,
    pub token_secret: String,
    pub identity_expires_at_unix: Option<u64>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedWorkerIdentity {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub token_id: String,
    pub token_secret: String,
    #[serde(default)]
    pub observed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSelfHostedWorker {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub framework_adapter: String,
    pub token_id: String,
    token_secret: String,
    pub identity_expires_at_unix: Option<u64>,
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
            observed_at_unix: None,
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
            identity_expires_at_unix: registration.identity_expires_at_unix,
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
        // Security (#114): compare the bearer secret in constant time so a
        // differing-prefix attempt cannot be distinguished from a differing-suffix
        // one by response timing. token_id is a non-secret lookup key.
        if worker.token_id != identity.token_id
            || !constant_time_secret_eq(&worker.token_secret, &identity.token_secret)
        {
            return Err(SelfHostedWorkerError::InvalidIdentity(
                "worker token does not match registered identity envelope".to_string(),
            ));
        }
        if worker
            .identity_expires_at_unix
            .zip(identity.observed_at_unix)
            .is_some_and(|(expires_at, observed_at)| observed_at >= expires_at)
        {
            return Err(SelfHostedWorkerError::InvalidIdentity(
                "worker identity has expired".to_string(),
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
    pub action: SelfHostedRunAction,
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub framework_adapter: String,
    pub required_capabilities: Vec<String>,
    pub workload_ref: String,
    pub queued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfHostedRunAction {
    StartRun,
    CancelRun,
    ResumeRun,
    CloseSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedRunPollRequest {
    pub protocol_version: u32,
    pub identity: SelfHostedWorkerIdentity,
    pub supported_capabilities: Vec<String>,
    pub now_unix: u64,
    pub lease_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedRunLease {
    pub dispatch_id: String,
    pub action: SelfHostedRunAction,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedRunAckRequest {
    pub protocol_version: u32,
    pub identity: SelfHostedWorkerIdentity,
    pub dispatch_id: String,
    pub action: SelfHostedRunAction,
    pub lease_id: String,
    pub run_id: String,
    pub status: SelfHostedRunAckStatus,
    pub reported_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfHostedRunAckStatus {
    Accepted,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedRunAck {
    pub dispatch_id: String,
    pub action: SelfHostedRunAction,
    pub lease_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub run_id: String,
    pub status: SelfHostedRunAckStatus,
    pub accepted_at_unix: u64,
    pub trust_level: SelfHostedTelemetryTrustLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHostedWorkerHttpTransportSecurity {
    MutualTls,
    SymmetricAead,
}

impl SelfHostedWorkerHttpTransportSecurity {
    fn as_str(self) -> &'static str {
        match self {
            Self::MutualTls => "mutual_tls",
            Self::SymmetricAead => "symmetric_aead",
        }
    }
}

/// Whether verified production mutual-TLS admission (client-certificate
/// validation + proof of an encrypted, mutually authenticated channel) is
/// implemented in this build.
///
/// This is the single source of truth for the `production_mtls_transport_implemented`
/// contract flag surfaced by the admin runtime listing. It is deliberately a
/// `const fn` returning `false`: the design in
/// `docs/security/self-hosted-mtls-transport.md` defers the PKI/mTLS listener to
/// a reviewed Phase 2. Do NOT flip this to `true` without landing verified-mTLS
/// channel validation and its conformance tests.
pub const fn production_mtls_transport_implemented() -> bool {
    false
}

/// Transport security posture for the self-hosted worker ingress.
///
/// See `docs/security/self-hosted-mtls-transport.md` for the full threat model
/// and rationale. The posture governs whether the marker/AEAD transport paths
/// are admitted (pre-production) or rejected as downgrades (production).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelfHostedTransportPosture {
    /// Pre-production contract posture (default). The gateway accepts both the
    /// application-layer AEAD frame path and the (unverified) `mutual_tls`
    /// marker path. The `mutual_tls` marker here is a claim only -- it is NOT
    /// proof of a verified mTLS channel.
    #[default]
    MarkerContract,
    /// Production posture: a verified mutual-TLS channel is required, and the
    /// AEAD / unverified-marker downgrade paths are rejected. Verified-mTLS
    /// admission itself is NOT yet implemented (see the design doc), so enabling
    /// this posture fails closed for every currently shippable channel. This is
    /// the honest security boundary: better to reject than to accept an
    /// unverifiable claim as production-grade.
    RequireProductionMtls,
}

/// The transport channel the gateway actually observed for an inbound request.
///
/// There is deliberately no `VerifiedMutualTls` variant yet: proving a mutually
/// authenticated, encrypted channel requires the PKI/mTLS listener that Phase 2
/// of the design introduces. Until then the gateway can only observe a *claimed*
/// marker header or an application-layer AEAD frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHostedTransportChannel {
    /// `x-ferrogate-transport-security: mutual_tls` -- a claim only. The gateway
    /// has not validated a client certificate or a real TLS handshake for this
    /// request.
    UnverifiedMutualTlsMarker,
    /// `x-ferrogate-transport-security: symmetric_aead` -- application-layer
    /// AEAD over an otherwise unauthenticated transport channel.
    SymmetricAead,
}

/// Why a request was refused by the transport-security policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfHostedTransportAdmissionError {
    /// A weaker, non-production channel was presented while production mTLS is
    /// required. This is an active downgrade and is rejected.
    DowngradeRejected(String),
    /// The request claims mutual TLS, but verified-mTLS admission (certificate
    /// validation + channel-encryption proof) is not implemented in this build.
    /// Honest not-implemented boundary; see the Phase 2 design.
    ProductionMtlsNotImplemented(String),
}

impl fmt::Display for SelfHostedTransportAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DowngradeRejected(message) => {
                write!(
                    formatter,
                    "self-hosted worker transport downgrade rejected: {message}"
                )
            }
            Self::ProductionMtlsNotImplemented(message) => {
                write!(
                    formatter,
                    "self-hosted worker production mTLS not implemented: {message}"
                )
            }
        }
    }
}

impl Error for SelfHostedTransportAdmissionError {}

/// Policy that decides whether an observed transport channel may be admitted.
///
/// The policy is a pure, infra-free decision function so it can be unit tested
/// without any PKI, TLS listener, or network. The gateway constructs it from a
/// configuration flag (`require_production_mtls`) and consults it before
/// dispatching a self-hosted worker transport request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelfHostedTransportPolicy {
    posture: SelfHostedTransportPosture,
}

impl SelfHostedTransportPolicy {
    /// Construct a policy for an explicit posture.
    pub const fn new(posture: SelfHostedTransportPosture) -> Self {
        Self { posture }
    }

    /// Construct a policy from the `require_production_mtls` configuration flag.
    pub const fn from_require_production_mtls(require_production_mtls: bool) -> Self {
        let posture = if require_production_mtls {
            SelfHostedTransportPosture::RequireProductionMtls
        } else {
            SelfHostedTransportPosture::MarkerContract
        };
        Self::new(posture)
    }

    pub const fn posture(&self) -> SelfHostedTransportPosture {
        self.posture
    }

    /// Whether this policy requires a verified production mTLS channel.
    pub const fn requires_production_mtls(&self) -> bool {
        matches!(
            self.posture,
            SelfHostedTransportPosture::RequireProductionMtls
        )
    }

    /// Decide whether an observed transport channel may be admitted.
    ///
    /// Under `MarkerContract` both channels are admitted (preserving the
    /// pre-production contract behaviour). Under `RequireProductionMtls`:
    ///
    /// * `SymmetricAead` is an explicit downgrade and is rejected.
    /// * `UnverifiedMutualTlsMarker` is a *claim* of mutual TLS the gateway
    ///   cannot yet verify; it is rejected as not-implemented rather than
    ///   silently trusted.
    ///
    /// Consequently, enabling production mode fails closed for every channel
    /// this build can produce -- by design, until Phase 2 lands verified-mTLS
    /// admission.
    pub fn admit(
        &self,
        channel: SelfHostedTransportChannel,
    ) -> Result<(), SelfHostedTransportAdmissionError> {
        match self.posture {
            SelfHostedTransportPosture::MarkerContract => Ok(()),
            SelfHostedTransportPosture::RequireProductionMtls => match channel {
                SelfHostedTransportChannel::SymmetricAead => {
                    Err(SelfHostedTransportAdmissionError::DowngradeRejected(
                        "symmetric_aead transport is a downgrade path; production mode requires a \
                         verified mutual-TLS channel for self-hosted worker transport"
                            .to_string(),
                    ))
                }
                SelfHostedTransportChannel::UnverifiedMutualTlsMarker => Err(
                    SelfHostedTransportAdmissionError::ProductionMtlsNotImplemented(
                        "the mutual_tls header is an unverified marker; verified mTLS channel \
                         admission (certificate validation + encrypted-channel proof) is not \
                         implemented in this build"
                            .to_string(),
                    ),
                ),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedWorkerTransportFrame {
    pub protocol_version: u32,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub token_id: String,
    pub encoding: SelfHostedWorkerTransportFrameEncoding,
    pub encrypted_payload: SelfHostedWorkerEncryptedPayload,
}

impl SelfHostedWorkerTransportFrame {
    pub fn encrypt_json(
        protocol_version: u32,
        identity: &SelfHostedWorkerIdentity,
        plaintext_json: &str,
        shared_secret: &str,
        nonce: [u8; 24],
    ) -> Result<Self, SelfHostedWorkerError> {
        validate_self_hosted_transport_shared_secret(shared_secret)?;
        if plaintext_json.len() > SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker encrypted transport plaintext exceeds maximum size".to_string(),
            ));
        }
        let frame = Self {
            protocol_version,
            tenant_id: identity.tenant_id.clone(),
            workspace_id: identity.workspace_id.clone(),
            worker_id: identity.worker_id.clone(),
            token_id: identity.token_id.clone(),
            encoding: SelfHostedWorkerTransportFrameEncoding::EncryptedJson,
            encrypted_payload: SelfHostedWorkerEncryptedPayload {
                algorithm: SELF_HOSTED_WORKER_SYMMETRIC_AEAD_ALGORITHM.to_string(),
                nonce: BASE64_STANDARD.encode(nonce),
                ciphertext: String::new(),
            },
        };
        let aad = frame.associated_data();
        let ciphertext = self_hosted_transport_aead_cipher(shared_secret)?
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext_json.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                SelfHostedWorkerError::InvalidTransport(
                    "self-hosted worker encrypted transport frame encryption failed".to_string(),
                )
            })?;
        Ok(Self {
            encrypted_payload: SelfHostedWorkerEncryptedPayload {
                algorithm: SELF_HOSTED_WORKER_SYMMETRIC_AEAD_ALGORITHM.to_string(),
                nonce: BASE64_STANDARD.encode(nonce),
                ciphertext: BASE64_STANDARD.encode(ciphertext),
            },
            ..frame
        })
    }

    pub fn encrypt_json_with_generated_nonce(
        protocol_version: u32,
        identity: &SelfHostedWorkerIdentity,
        plaintext_json: &str,
        shared_secret: &str,
    ) -> Result<Self, SelfHostedWorkerError> {
        Self::encrypt_json(
            protocol_version,
            identity,
            plaintext_json,
            shared_secret,
            next_self_hosted_transport_nonce(),
        )
    }

    pub fn decode_json<T>(&self, shared_secret: &str) -> Result<T, SelfHostedWorkerError>
    where
        T: for<'de> Deserialize<'de> + SelfHostedWorkerTransportIdentity,
    {
        let plaintext_json = self.decrypt_json(shared_secret)?;
        let request: T = serde_json::from_str(&plaintext_json).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "invalid self-hosted worker encrypted transport JSON body: {error}"
            ))
        })?;
        self.validate_identity(request.transport_identity())?;
        Ok(request)
    }

    pub fn decrypt_json(&self, shared_secret: &str) -> Result<String, SelfHostedWorkerError> {
        validate_self_hosted_transport_shared_secret(shared_secret)?;
        if self.encoding != SelfHostedWorkerTransportFrameEncoding::EncryptedJson {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker symmetric AEAD transport requires encrypted_json frame"
                    .to_string(),
            ));
        }
        if self.encrypted_payload.algorithm != SELF_HOSTED_WORKER_SYMMETRIC_AEAD_ALGORITHM {
            return Err(SelfHostedWorkerError::InvalidTransport(format!(
                "unsupported self-hosted worker AEAD algorithm {}",
                self.encrypted_payload.algorithm
            )));
        }
        let nonce = BASE64_STANDARD
            .decode(&self.encrypted_payload.nonce)
            .map_err(|_| {
                SelfHostedWorkerError::InvalidTransport(
                    "self-hosted worker encrypted frame nonce is not valid base64".to_string(),
                )
            })?;
        if nonce.len() != 24 {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker encrypted frame nonce must be 24 bytes".to_string(),
            ));
        }
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| {
            SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker encrypted frame nonce must be 24 bytes".to_string(),
            )
        })?;
        let ciphertext = BASE64_STANDARD
            .decode(&self.encrypted_payload.ciphertext)
            .map_err(|_| {
                SelfHostedWorkerError::InvalidTransport(
                    "self-hosted worker encrypted frame ciphertext is not valid base64".to_string(),
                )
            })?;
        if ciphertext.len() > SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker encrypted frame exceeds maximum size".to_string(),
            ));
        }
        let plaintext = self_hosted_transport_aead_cipher(shared_secret)?
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: self.associated_data().as_bytes(),
                },
            )
            .map_err(|_| {
                SelfHostedWorkerError::InvalidTransport(
                    "self-hosted worker encrypted transport frame failed authentication"
                        .to_string(),
                )
            })?;
        if plaintext.len() > SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker decrypted frame exceeds maximum size".to_string(),
            ));
        }
        String::from_utf8(plaintext).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker decrypted frame is not UTF-8 JSON: {error}"
            ))
        })
    }

    fn associated_data(&self) -> String {
        [
            self.protocol_version.to_string(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
            self.worker_id.clone(),
            self.token_id.clone(),
        ]
        .join("\n")
    }

    fn validate_identity(
        &self,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<(), SelfHostedWorkerError> {
        if self.tenant_id != identity.tenant_id
            || self.workspace_id != identity.workspace_id
            || self.worker_id != identity.worker_id
            || self.token_id != identity.token_id
        {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker encrypted frame identity does not match enclosed request"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfHostedWorkerTransportFrameEncoding {
    EncryptedJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfHostedWorkerEncryptedPayload {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub trait SelfHostedWorkerTransportIdentity {
    fn transport_identity(&self) -> &SelfHostedWorkerIdentity;
}

impl SelfHostedWorkerTransportIdentity for SelfHostedRunPollRequest {
    fn transport_identity(&self) -> &SelfHostedWorkerIdentity {
        &self.identity
    }
}

impl SelfHostedWorkerTransportIdentity for SelfHostedRunAckRequest {
    fn transport_identity(&self) -> &SelfHostedWorkerIdentity {
        &self.identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerHttpTransportClient {
    endpoint: SocketAddr,
    transport_security: SelfHostedWorkerHttpTransportSecurity,
}

impl SelfHostedWorkerHttpTransportClient {
    pub fn new_mtls(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            transport_security: SelfHostedWorkerHttpTransportSecurity::MutualTls,
        }
    }

    pub fn new_symmetric_aead(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            transport_security: SelfHostedWorkerHttpTransportSecurity::SymmetricAead,
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn transport_security(&self) -> SelfHostedWorkerHttpTransportSecurity {
        self.transport_security
    }

    pub fn poll_run(
        &self,
        request: &SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError> {
        validate_run_poll_request(request)?;
        let body = self.encode_request_body(
            SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            &request.identity,
            request,
        )?;
        let response = self.send_json_request("/v1/self-hosted-workers/runs/poll", &body)?;
        if response.trim().is_empty() || response.trim() == "null" {
            return Ok(None);
        }
        serde_json::from_str(response.trim())
            .map(Some)
            .map_err(|error| {
                SelfHostedWorkerError::InvalidTransport(format!(
                    "self-hosted worker HTTP poll response decode failed: {error}"
                ))
            })
    }

    pub fn ack_run(
        &self,
        request: &SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError> {
        validate_run_ack_request(request)?;
        let body = self.encode_request_body(
            SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            &request.identity,
            request,
        )?;
        let response = self.send_json_request("/v1/self-hosted-workers/runs/ack", &body)?;
        serde_json::from_str(response.trim()).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP ack response decode failed: {error}"
            ))
        })
    }

    fn encode_request_body<T>(
        &self,
        protocol_version: u32,
        identity: &SelfHostedWorkerIdentity,
        request: &T,
    ) -> Result<String, SelfHostedWorkerError>
    where
        T: Serialize,
    {
        let plaintext_json =
            serde_json::to_string(request).map_err(self_hosted_http_serialization_error)?;
        match self.transport_security {
            SelfHostedWorkerHttpTransportSecurity::MutualTls => Ok(plaintext_json),
            SelfHostedWorkerHttpTransportSecurity::SymmetricAead => {
                let frame = SelfHostedWorkerTransportFrame::encrypt_json(
                    protocol_version,
                    identity,
                    &plaintext_json,
                    &identity.token_secret,
                    next_self_hosted_transport_nonce(),
                )?;
                serde_json::to_string(&frame).map_err(self_hosted_http_serialization_error)
            }
        }
    }

    fn send_json_request(&self, path: &str, body: &str) -> Result<String, SelfHostedWorkerError> {
        if body.len() > SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker HTTP request exceeds maximum message size".to_string(),
            ));
        }
        let mut stream = TcpStream::connect(self.endpoint).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP transport connect failed at {}: {error}",
                self.endpoint
            ))
        })?;
        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             host: {}\r\n\
             content-type: application/json\r\n\
             x-ferrogate-transport-security: {}\r\n\
             content-length: {}\r\n\
             connection: close\r\n\
             \r\n\
             {}",
            self.endpoint,
            self.transport_security.as_str(),
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP request write failed: {error}"
            ))
        })?;
        stream.shutdown(Shutdown::Write).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP request shutdown failed: {error}"
            ))
        })?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|error| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP response read failed: {error}"
            ))
        })?;
        if response.len() > SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker HTTP response exceeds maximum message size".to_string(),
            ));
        }
        decode_self_hosted_http_body(&response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedSelfHostedRun {
    dispatch: SelfHostedRunDispatch,
    assigned_worker_id: Option<String>,
    lease_id: Option<String>,
    lease_expires_at_unix: Option<u64>,
    attempt: u32,
    acknowledged_status: Option<SelfHostedRunAckStatus>,
    acknowledged_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedRunQueueRecord {
    pub dispatch: SelfHostedRunDispatch,
    pub assigned_worker_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_expires_at_unix: Option<u64>,
    pub attempt: u32,
    pub acknowledged_status: Option<SelfHostedRunAckStatus>,
    pub acknowledged_at_unix: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemorySelfHostedRunQueue {
    runs: BTreeMap<String, QueuedSelfHostedRun>,
}

impl InMemorySelfHostedRunQueue {
    pub fn restore_runs(
        &mut self,
        records: Vec<SelfHostedRunQueueRecord>,
    ) -> Result<(), SelfHostedWorkerError> {
        let mut restored = BTreeMap::new();
        for record in records {
            validate_run_dispatch(&record.dispatch)?;
            if restored.contains_key(&record.dispatch.dispatch_id) {
                return Err(SelfHostedWorkerError::InvalidTransport(format!(
                    "dispatch {} already exists",
                    record.dispatch.dispatch_id
                )));
            }
            restored.insert(
                record.dispatch.dispatch_id.clone(),
                QueuedSelfHostedRun {
                    dispatch: record.dispatch,
                    assigned_worker_id: record.assigned_worker_id,
                    lease_id: record.lease_id,
                    lease_expires_at_unix: record.lease_expires_at_unix,
                    attempt: record.attempt,
                    acknowledged_status: record.acknowledged_status,
                    acknowledged_at_unix: record.acknowledged_at_unix,
                },
            );
        }
        self.runs = restored;
        Ok(())
    }

    pub fn run_records(&self) -> Vec<SelfHostedRunQueueRecord> {
        self.runs
            .values()
            .map(|queued| SelfHostedRunQueueRecord {
                dispatch: queued.dispatch.clone(),
                assigned_worker_id: queued.assigned_worker_id.clone(),
                lease_id: queued.lease_id.clone(),
                lease_expires_at_unix: queued.lease_expires_at_unix,
                attempt: queued.attempt,
                acknowledged_status: queued.acknowledged_status,
                acknowledged_at_unix: queued.acknowledged_at_unix,
            })
            .collect()
    }

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
                acknowledged_status: None,
                acknowledged_at_unix: None,
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
            action: queued.dispatch.action,
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
        if queued.dispatch.action != request.action {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "ack action does not match dispatch".to_string(),
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
        if queued
            .lease_expires_at_unix
            .map(|expires_at| request.reported_at_unix > expires_at)
            .unwrap_or(true)
        {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "ack lease has expired".to_string(),
            ));
        }
        if queued.acknowledged_status.is_some() {
            return Err(SelfHostedWorkerError::InvalidTransport(
                "dispatch lease was already acknowledged".to_string(),
            ));
        }
        queued.acknowledged_status = Some(request.status);
        queued.acknowledged_at_unix = Some(request.reported_at_unix);
        Ok(SelfHostedRunAck {
            dispatch_id: queued.dispatch.dispatch_id.clone(),
            action: queued.dispatch.action,
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
        self.acknowledged_status.is_none()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    validate_worker_protocol_version(request.protocol_version)?;
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
    validate_worker_protocol_version(request.protocol_version)?;
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

fn validate_worker_protocol_version(protocol_version: u32) -> Result<(), SelfHostedWorkerError> {
    if protocol_version == SELF_HOSTED_WORKER_PROTOCOL_VERSION {
        return Ok(());
    }
    Err(SelfHostedWorkerError::InvalidTransport(format!(
        "unsupported self-hosted worker protocol_version {protocol_version}; expected {SELF_HOSTED_WORKER_PROTOCOL_VERSION}"
    )))
}

fn validate_checkpoint_fetch(
    request: &SelfHostedCheckpointFetchRequest,
) -> Result<(), SelfHostedWorkerError> {
    require_telemetry_non_empty("session_id", &request.session_id)?;
    require_telemetry_non_empty("run_id", &request.run_id)?;
    require_telemetry_non_empty("checkpoint_id", &request.checkpoint_id)?;
    Ok(())
}

fn self_hosted_http_serialization_error(error: serde_json::Error) -> SelfHostedWorkerError {
    SelfHostedWorkerError::InvalidTransport(format!(
        "self-hosted worker HTTP request serialization failed: {error}"
    ))
}

fn decode_self_hosted_http_body(response: &[u8]) -> Result<String, SelfHostedWorkerError> {
    let response = std::str::from_utf8(response).map_err(|_| {
        SelfHostedWorkerError::InvalidTransport(
            "self-hosted worker HTTP response is not valid UTF-8".to_string(),
        )
    })?;
    let Some(header_end) = response.find("\r\n\r\n") else {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "self-hosted worker HTTP response missing header terminator".to_string(),
        ));
    };
    let (headers, body) = response.split_at(header_end);
    let status_code = parse_self_hosted_http_status(headers.lines().next().unwrap_or_default())?;
    if status_code != 200 {
        return Err(SelfHostedWorkerError::InvalidTransport(format!(
            "self-hosted worker HTTP response returned status {status_code}"
        )));
    }
    Ok(body[4..].to_string())
}

fn validate_self_hosted_transport_shared_secret(
    shared_secret: &str,
) -> Result<(), SelfHostedWorkerError> {
    if shared_secret.trim().is_empty() {
        return Err(SelfHostedWorkerError::InvalidTransport(
            "self-hosted worker symmetric AEAD transport requires a non-empty shared secret"
                .to_string(),
        ));
    }
    // Fail closed on a truncated/legacy secret: a worker registered before the
    // provisioned-secret migration has an empty `token_secret`, and any short
    // value lacks the entropy to safely key the cipher.
    if shared_secret.len() < SELF_HOSTED_WORKER_TRANSPORT_SECRET_MIN_LEN {
        return Err(SelfHostedWorkerError::InvalidTransport(format!(
            "self-hosted worker symmetric AEAD transport secret must be at least {SELF_HOSTED_WORKER_TRANSPORT_SECRET_MIN_LEN} characters"
        )));
    }
    Ok(())
}

fn self_hosted_transport_aead_cipher(
    shared_secret: &str,
) -> Result<XChaCha20Poly1305, SelfHostedWorkerError> {
    validate_self_hosted_transport_shared_secret(shared_secret)?;
    // Derive the 32-byte XChaCha20Poly1305 key from the provisioned secret via
    // HKDF-SHA256 (RFC 5869) with domain separation, rather than zero-padding /
    // truncating the raw secret string. The pre-fix zero-pad both required a
    // >=32-byte secret to get full-width key material and made the key simply
    // the secret's first 32 bytes; HKDF removes both problems.
    let hkdf = Hkdf::<Sha256>::new(
        Some(SELF_HOSTED_WORKER_TRANSPORT_HKDF_SALT),
        shared_secret.as_bytes(),
    );
    let mut key = [0_u8; 32];
    hkdf.expand(SELF_HOSTED_WORKER_TRANSPORT_HKDF_INFO, &mut key)
        .map_err(|_| {
            SelfHostedWorkerError::InvalidTransport(
                "self-hosted worker transport key derivation failed".to_string(),
            )
        })?;
    Ok(XChaCha20Poly1305::new((&key).into()))
}

fn next_self_hosted_transport_nonce() -> [u8; 24] {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = SELF_HOSTED_TRANSPORT_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(&now_nanos.to_le_bytes());
    nonce[16..24].copy_from_slice(&(counter ^ u64::from(pid)).to_le_bytes());
    nonce
}

fn parse_self_hosted_http_status(status_line: &str) -> Result<u16, SelfHostedWorkerError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(SelfHostedWorkerError::InvalidTransport(format!(
            "self-hosted worker HTTP response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            SelfHostedWorkerError::InvalidTransport(format!(
                "self-hosted worker HTTP response has invalid status code: {status_line}"
            ))
        })
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
#[path = "self_hosted_worker_security_test.rs"]
mod self_hosted_worker_security_test;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{TcpListener, TcpStream},
        thread,
    };

    #[test]
    fn default_transport_policy_admits_both_marker_paths() {
        let policy = SelfHostedTransportPolicy::default();
        assert_eq!(policy.posture(), SelfHostedTransportPosture::MarkerContract);
        assert!(!policy.requires_production_mtls());
        assert_eq!(
            policy.admit(SelfHostedTransportChannel::SymmetricAead),
            Ok(())
        );
        assert_eq!(
            policy.admit(SelfHostedTransportChannel::UnverifiedMutualTlsMarker),
            Ok(())
        );
    }

    #[test]
    fn marker_contract_policy_admits_both_marker_paths() {
        let policy = SelfHostedTransportPolicy::from_require_production_mtls(false);
        assert_eq!(policy.posture(), SelfHostedTransportPosture::MarkerContract);
        assert_eq!(
            policy.admit(SelfHostedTransportChannel::SymmetricAead),
            Ok(())
        );
        assert_eq!(
            policy.admit(SelfHostedTransportChannel::UnverifiedMutualTlsMarker),
            Ok(())
        );
    }

    #[test]
    fn production_policy_rejects_symmetric_aead_as_downgrade() {
        let policy = SelfHostedTransportPolicy::from_require_production_mtls(true);
        assert_eq!(
            policy.posture(),
            SelfHostedTransportPosture::RequireProductionMtls
        );
        assert!(policy.requires_production_mtls());
        let error = policy
            .admit(SelfHostedTransportChannel::SymmetricAead)
            .expect_err("symmetric_aead must be rejected in production mode");
        assert!(matches!(
            error,
            SelfHostedTransportAdmissionError::DowngradeRejected(_)
        ));
        assert!(error.to_string().contains("downgrade"));
    }

    #[test]
    fn production_policy_rejects_unverified_mtls_marker_as_not_implemented() {
        let policy =
            SelfHostedTransportPolicy::new(SelfHostedTransportPosture::RequireProductionMtls);
        let error = policy
            .admit(SelfHostedTransportChannel::UnverifiedMutualTlsMarker)
            .expect_err("unverified mutual_tls marker must not be trusted in production mode");
        assert!(matches!(
            error,
            SelfHostedTransportAdmissionError::ProductionMtlsNotImplemented(_)
        ));
        assert!(error.to_string().contains("not implemented"));
    }

    #[test]
    fn production_mtls_transport_is_not_yet_implemented() {
        // Honest boundary: verified mTLS admission is deferred to the reviewed
        // Phase 2 PKI work. This must stay false until that lands.
        assert!(!production_mtls_transport_implemented());
    }

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
    fn validates_self_hosted_worker_identity_expiry() {
        let mut registry = SelfHostedWorkerRegistry::default();
        let worker = registry
            .register(SelfHostedWorkerRegistration {
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-1".to_string(),
                framework_adapter: "codex".to_string(),
                token_id: "token-1".to_string(),
                token_secret: "secret-1".to_string(),
                identity_expires_at_unix: Some(100),
                capabilities: vec!["logs".to_string()],
            })
            .unwrap();

        let mut valid_identity = worker.identity();
        valid_identity.observed_at_unix = Some(99);
        registry.validate_identity(&valid_identity).unwrap();

        let mut expired_identity = worker.identity();
        expired_identity.observed_at_unix = Some(100);
        let error = registry.validate_identity(&expired_identity).unwrap_err();

        assert!(matches!(error, SelfHostedWorkerError::InvalidIdentity(_)));
        assert!(error.to_string().contains("expired"));
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity,
                    dispatch_id: lease.dispatch_id.clone(),
                    action: lease.action,
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
    fn worker_ack_rejects_duplicate_ack_for_same_lease() {
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("matching worker should receive a run lease");
        let first_ack = SelfHostedRunAckRequest {
            protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            identity: identity.clone(),
            dispatch_id: lease.dispatch_id.clone(),
            action: lease.action,
            lease_id: lease.lease_id.clone(),
            run_id: lease.run_id.clone(),
            status: SelfHostedRunAckStatus::Accepted,
            reported_at_unix: 1_725_000_011,
        };

        transport
            .ack_run(&registry, &mut queue, first_ack.clone())
            .unwrap();
        let duplicate = transport
            .ack_run(
                &registry,
                &mut queue,
                SelfHostedRunAckRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    status: SelfHostedRunAckStatus::Completed,
                    reported_at_unix: 1_725_000_012,
                    ..first_ack
                },
            )
            .unwrap_err();

        assert!(duplicate.to_string().contains("already acknowledged"));
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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

    // Durable-lease resume (#244): an in-flight lease persisted before a gateway
    // restart is rebuilt from storage into a FRESH queue and must not be
    // double-delivered while its deadline holds, and its original ack must still
    // be honored (no drop). `run_records()`/`restore_runs()` are the exact
    // write-through/reload snapshot boundary the durable store persists across.
    #[test]
    fn restored_in_flight_lease_resumes_without_double_delivery_or_drop() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let transport = InMemorySelfHostedWorkerTransport::default();

        // Pre-restart runtime: lease the dispatch to worker-1 (attempt 1, unacked).
        let mut before_restart = InMemorySelfHostedRunQueue::default();
        before_restart.enqueue_run(dispatch()).unwrap();
        let lease = transport
            .poll_run(
                &registry,
                &mut before_restart,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("matching worker should receive a run lease");
        assert_eq!(lease.lease_id, "dispatch-1:attempt-1");

        // Simulate a gateway restart: rebuild a fresh queue purely from the
        // persisted snapshot (no in-memory carryover from `before_restart`).
        let persisted = before_restart.run_records();
        let mut after_restart = InMemorySelfHostedRunQueue::default();
        after_restart.restore_runs(persisted).unwrap();

        // No double-deliver: a poll before the lease deadline lapses -- even from
        // a fully-capable worker -- must NOT re-lease the already-leased run.
        let during_active_lease = transport
            .poll_run(
                &registry,
                &mut after_restart,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_020,
                    lease_duration_secs: 30,
                },
            )
            .unwrap();
        assert!(
            during_active_lease.is_none(),
            "a restored in-flight lease must not be re-delivered before its deadline"
        );

        // No drop: the original lease is still ack-able after the restart.
        let ack = transport
            .ack_run(
                &registry,
                &mut after_restart,
                SelfHostedRunAckRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity,
                    dispatch_id: lease.dispatch_id.clone(),
                    action: lease.action,
                    lease_id: lease.lease_id.clone(),
                    run_id: lease.run_id.clone(),
                    status: SelfHostedRunAckStatus::Completed,
                    reported_at_unix: 1_725_000_025,
                },
            )
            .unwrap();

        assert_eq!(ack.lease_id, "dispatch-1:attempt-1");
        assert_eq!(ack.worker_id, "worker-1");
        assert_eq!(ack.status, SelfHostedRunAckStatus::Completed);
    }

    // Durable-lease resume (#244): if a leased run is never acked and the gateway
    // restarts, the reloaded queue must still redeliver it ONCE the deadline
    // lapses -- and as the NEXT attempt, proving the attempt counter survived the
    // restart rather than resetting (which would mask duplicate delivery).
    #[test]
    fn restored_unacked_lease_redelivers_as_next_attempt_after_deadline() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let transport = InMemorySelfHostedWorkerTransport::default();

        let mut before_restart = InMemorySelfHostedRunQueue::default();
        before_restart.enqueue_run(dispatch()).unwrap();
        let first = transport
            .poll_run(
                &registry,
                &mut before_restart,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.attempt, 1);

        let mut after_restart = InMemorySelfHostedRunQueue::default();
        after_restart
            .restore_runs(before_restart.run_records())
            .unwrap();

        let redelivered = transport
            .poll_run(
                &registry,
                &mut after_restart,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity,
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_040,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("an expired lease must be redeliverable after a restart");

        assert_eq!(redelivered.lease_id, "dispatch-1:attempt-2");
        assert_eq!(redelivered.attempt, 2);
    }

    #[test]
    fn worker_poll_and_ack_reject_unsupported_protocol_version() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        let poll_error = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    protocol_version: 0,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap_err();

        assert!(poll_error.to_string().contains("protocol_version"));

        let lease = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("supported protocol version should receive a run lease");

        let ack_error = transport
            .ack_run(
                &registry,
                &mut queue,
                SelfHostedRunAckRequest {
                    protocol_version: 0,
                    identity,
                    dispatch_id: lease.dispatch_id.clone(),
                    action: lease.action,
                    lease_id: lease.lease_id.clone(),
                    run_id: lease.run_id.clone(),
                    status: SelfHostedRunAckStatus::Accepted,
                    reported_at_unix: 1_725_000_011,
                },
            )
            .unwrap_err();

        assert!(ack_error.to_string().contains("protocol_version"));
    }

    #[test]
    fn worker_ack_rejects_expired_lease_before_redelivery() {
        let registry = registered_registry();
        let identity = registry.list()[0].identity();
        let mut queue = InMemorySelfHostedRunQueue::default();
        let transport = InMemorySelfHostedWorkerTransport::default();
        queue.enqueue_run(dispatch()).unwrap();

        let expired_lease = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_010,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("matching worker should receive a run lease");

        let late_ack = transport
            .ack_run(
                &registry,
                &mut queue,
                SelfHostedRunAckRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: identity.clone(),
                    dispatch_id: expired_lease.dispatch_id.clone(),
                    action: expired_lease.action,
                    lease_id: expired_lease.lease_id.clone(),
                    run_id: expired_lease.run_id.clone(),
                    status: SelfHostedRunAckStatus::Accepted,
                    reported_at_unix: 1_725_000_041,
                },
            )
            .unwrap_err();

        assert!(late_ack.to_string().contains("lease has expired"));

        let redelivered = transport
            .poll_run(
                &registry,
                &mut queue,
                SelfHostedRunPollRequest {
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity,
                    supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                    now_unix: 1_725_000_041,
                    lease_duration_secs: 30,
                },
            )
            .unwrap()
            .expect("expired lease should be available for redelivery");

        assert_eq!(redelivered.lease_id, "dispatch-1:attempt-2");
        assert_eq!(redelivered.attempt, 2);
    }

    #[test]
    fn worker_dispatch_actions_cover_cancel_resume_and_close_contracts() {
        for action in [
            SelfHostedRunAction::CancelRun,
            SelfHostedRunAction::ResumeRun,
            SelfHostedRunAction::CloseSession,
        ] {
            let registry = registered_registry();
            let identity = registry.list()[0].identity();
            let mut queue = InMemorySelfHostedRunQueue::default();
            let transport = InMemorySelfHostedWorkerTransport::default();
            let mut dispatch = dispatch();
            dispatch.action = action;
            dispatch.dispatch_id = format!("{}-dispatch", action.as_str_for_test());
            queue.enqueue_run(dispatch).unwrap();

            let lease = transport
                .poll_run(
                    &registry,
                    &mut queue,
                    SelfHostedRunPollRequest {
                        protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                        identity: identity.clone(),
                        supported_capabilities: vec!["logs".to_string(), "artifacts".to_string()],
                        now_unix: 1_725_000_010,
                        lease_duration_secs: 30,
                    },
                )
                .unwrap()
                .expect("matching worker should receive control action lease");

            assert_eq!(lease.action, action);

            let ack = transport
                .ack_run(
                    &registry,
                    &mut queue,
                    SelfHostedRunAckRequest {
                        protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                        identity: identity.clone(),
                        dispatch_id: lease.dispatch_id.clone(),
                        action,
                        lease_id: lease.lease_id.clone(),
                        run_id: lease.run_id.clone(),
                        status: SelfHostedRunAckStatus::Accepted,
                        reported_at_unix: 1_725_000_011,
                    },
                )
                .unwrap();

            assert_eq!(ack.action, action);
        }
    }

    impl SelfHostedRunAction {
        fn as_str_for_test(self) -> &'static str {
            match self {
                Self::StartRun => "start-run",
                Self::CancelRun => "cancel-run",
                Self::ResumeRun => "resume-run",
                Self::CloseSession => "close-session",
            }
        }
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
                identity_expires_at_unix: None,
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
                identity_expires_at_unix: None,
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
                        protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                identity_expires_at_unix: None,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                identity_expires_at_unix: None,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: worker_2.clone(),
                    dispatch_id: lease.dispatch_id.clone(),
                    action: lease.action,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
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
                    protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                    identity: worker_1,
                    dispatch_id: lease.dispatch_id,
                    action: lease.action,
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

    #[test]
    fn http_transport_client_polls_and_acks_over_mtls_contract() {
        let identity = registration_identity();
        let lease = SelfHostedRunLease {
            dispatch_id: "dispatch-1".to_string(),
            action: SelfHostedRunAction::StartRun,
            lease_id: "dispatch-1:attempt-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            framework_adapter: "codex".to_string(),
            required_capabilities: vec!["logs".to_string()],
            workload_ref: "queue://runs/run-1".to_string(),
            attempt: 1,
            lease_expires_at_unix: 1_725_000_040,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
        };
        let ack = SelfHostedRunAck {
            dispatch_id: lease.dispatch_id.clone(),
            action: lease.action,
            lease_id: lease.lease_id.clone(),
            tenant_id: lease.tenant_id.clone(),
            workspace_id: lease.workspace_id.clone(),
            worker_id: lease.worker_id.clone(),
            run_id: lease.run_id.clone(),
            status: SelfHostedRunAckStatus::Accepted,
            accepted_at_unix: 1_725_000_012,
            trust_level: SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker,
        };
        let server = spawn_self_hosted_http_contract_server(vec![
            (
                "/v1/self-hosted-workers/runs/poll",
                serde_json::to_string(&lease).unwrap(),
                200,
            ),
            (
                "/v1/self-hosted-workers/runs/ack",
                serde_json::to_string(&ack).unwrap(),
                200,
            ),
        ]);
        let client = SelfHostedWorkerHttpTransportClient::new_mtls(server.endpoint);

        let received_lease = client
            .poll_run(&SelfHostedRunPollRequest {
                protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                identity: identity.clone(),
                supported_capabilities: vec!["logs".to_string()],
                now_unix: 1_725_000_010,
                lease_duration_secs: 30,
            })
            .unwrap()
            .unwrap();
        let received_ack = client
            .ack_run(&SelfHostedRunAckRequest {
                protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                identity,
                dispatch_id: received_lease.dispatch_id.clone(),
                action: received_lease.action,
                lease_id: received_lease.lease_id.clone(),
                run_id: received_lease.run_id.clone(),
                status: SelfHostedRunAckStatus::Accepted,
                reported_at_unix: 1_725_000_012,
            })
            .unwrap();
        let requests = server.join();

        assert_eq!(received_lease, lease);
        assert_eq!(received_ack, ack);
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /v1/self-hosted-workers/runs/poll HTTP/1.1\r\n"));
        assert!(requests[0].contains("\r\nx-ferrogate-transport-security: mutual_tls\r\n"));
        assert!(requests[0].contains("\r\ncontent-type: application/json\r\n"));
        let poll_body: SelfHostedRunPollRequest =
            serde_json::from_str(http_request_body(&requests[0])).unwrap();
        assert_eq!(
            poll_body.protocol_version,
            SELF_HOSTED_WORKER_PROTOCOL_VERSION
        );
        assert_eq!(poll_body.identity.worker_id, "worker-1");
        assert_eq!(poll_body.supported_capabilities, vec!["logs"]);
        assert!(requests[1].starts_with("POST /v1/self-hosted-workers/runs/ack HTTP/1.1\r\n"));
        let ack_body: SelfHostedRunAckRequest =
            serde_json::from_str(http_request_body(&requests[1])).unwrap();
        assert_eq!(
            ack_body.protocol_version,
            SELF_HOSTED_WORKER_PROTOCOL_VERSION
        );
        assert_eq!(ack_body.lease_id, "dispatch-1:attempt-1");
        assert_eq!(ack_body.status, SelfHostedRunAckStatus::Accepted);
    }

    #[test]
    fn http_transport_client_treats_empty_poll_body_as_no_work() {
        let server = spawn_self_hosted_http_contract_server(vec![(
            "/v1/self-hosted-workers/runs/poll",
            "null".to_string(),
            200,
        )]);
        let client = SelfHostedWorkerHttpTransportClient::new_mtls(server.endpoint);

        let lease = client
            .poll_run(&SelfHostedRunPollRequest {
                protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                identity: registration_identity(),
                supported_capabilities: vec!["logs".to_string()],
                now_unix: 1_725_000_010,
                lease_duration_secs: 30,
            })
            .unwrap();
        server.join();

        assert!(lease.is_none());
    }

    // Full-width transport secrets (>= 32 chars), the shape
    // `generate_transport_token_secret` provisions. Distinct values so the
    // wrong-secret case exercises a real AEAD authentication failure rather
    // than the minimum-length guard.
    const TEST_TRANSPORT_SECRET: &str = "transport-secret-aaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_TRANSPORT_SECRET_OTHER: &str = "transport-secret-bbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn self_hosted_transport_frame_encrypts_request_with_context_bound_aead() {
        let identity = registration_identity();
        let request = SelfHostedRunPollRequest {
            protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            identity: identity.clone(),
            supported_capabilities: vec!["logs".to_string()],
            now_unix: 1_725_000_010,
            lease_duration_secs: 30,
        };
        let plaintext_json = serde_json::to_string(&request).unwrap();
        let frame = SelfHostedWorkerTransportFrame::encrypt_json(
            SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            &identity,
            &plaintext_json,
            TEST_TRANSPORT_SECRET,
            [3_u8; 24],
        )
        .unwrap();

        assert_eq!(
            frame.encoding,
            SelfHostedWorkerTransportFrameEncoding::EncryptedJson
        );
        assert_eq!(frame.tenant_id, "tenant-1");
        assert_eq!(frame.token_id, "token-1");

        let decoded: SelfHostedRunPollRequest = frame.decode_json(TEST_TRANSPORT_SECRET).unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn self_hosted_transport_frame_rejects_wrong_secret_or_tampered_identity() {
        let identity = registration_identity();
        let request = SelfHostedRunAckRequest {
            protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            identity: identity.clone(),
            dispatch_id: "dispatch-1".to_string(),
            action: SelfHostedRunAction::StartRun,
            lease_id: "dispatch-1:attempt-1".to_string(),
            run_id: "run-1".to_string(),
            status: SelfHostedRunAckStatus::Accepted,
            reported_at_unix: 1_725_000_011,
        };
        let plaintext_json = serde_json::to_string(&request).unwrap();
        let mut frame = SelfHostedWorkerTransportFrame::encrypt_json(
            SELF_HOSTED_WORKER_PROTOCOL_VERSION,
            &identity,
            &plaintext_json,
            TEST_TRANSPORT_SECRET,
            [4_u8; 24],
        )
        .unwrap();

        // A different (valid-length) secret must fail AEAD authentication.
        assert!(frame
            .decode_json::<SelfHostedRunAckRequest>(TEST_TRANSPORT_SECRET_OTHER)
            .is_err());

        frame.worker_id = "other-worker".to_string();

        assert!(frame
            .decode_json::<SelfHostedRunAckRequest>(TEST_TRANSPORT_SECRET)
            .is_err());
    }

    #[test]
    fn generated_transport_secret_is_high_entropy_and_short_secrets_are_rejected() {
        let secret = generate_transport_token_secret();
        // 256 bits, hex-encoded.
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
        // Two draws must differ (CSPRNG, not a constant).
        assert_ne!(secret, generate_transport_token_secret());
        assert!(secret.len() >= SELF_HOSTED_WORKER_TRANSPORT_SECRET_MIN_LEN);

        // The AEAD refuses to key on an empty or truncated secret (fail closed
        // for pre-migration registrations that carry no provisioned secret).
        assert!(self_hosted_transport_aead_cipher("").is_err());
        assert!(self_hosted_transport_aead_cipher("too-short").is_err());
        assert!(self_hosted_transport_aead_cipher(&secret).is_ok());
    }

    #[test]
    fn http_transport_client_fails_closed_on_non_success_status() {
        let server = spawn_self_hosted_http_contract_server(vec![(
            "/v1/self-hosted-workers/runs/poll",
            r#"{"error":"denied"}"#.to_string(),
            403,
        )]);
        let client = SelfHostedWorkerHttpTransportClient::new_mtls(server.endpoint);

        let error = client
            .poll_run(&SelfHostedRunPollRequest {
                protocol_version: SELF_HOSTED_WORKER_PROTOCOL_VERSION,
                identity: registration_identity(),
                supported_capabilities: vec!["logs".to_string()],
                now_unix: 1_725_000_010,
                lease_duration_secs: 30,
            })
            .unwrap_err();
        server.join();

        assert!(matches!(error, SelfHostedWorkerError::InvalidTransport(_)));
        assert!(error.to_string().contains("status 403"));
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
            identity_expires_at_unix: None,
            capabilities: vec![
                "logs".to_string(),
                "heartbeat".to_string(),
                "logs".to_string(),
                " artifacts ".to_string(),
            ],
        }
    }

    fn registration_identity() -> SelfHostedWorkerIdentity {
        SelfHostedWorkerIdentity {
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            token_id: "token-1".to_string(),
            token_secret: "secret-1".to_string(),
            observed_at_unix: None,
        }
    }

    fn dispatch() -> SelfHostedRunDispatch {
        SelfHostedRunDispatch {
            dispatch_id: "dispatch-1".to_string(),
            action: SelfHostedRunAction::StartRun,
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

    struct SelfHostedHttpContractServer {
        endpoint: SocketAddr,
        handle: thread::JoinHandle<Vec<String>>,
    }

    impl SelfHostedHttpContractServer {
        fn join(self) -> Vec<String> {
            self.handle.join().unwrap()
        }
    }

    fn spawn_self_hosted_http_contract_server(
        responses: Vec<(&'static str, String, u16)>,
    ) -> SelfHostedHttpContractServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::with_capacity(responses.len());
            for (expected_path, body, status_code) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
                assert!(request.contains("\r\nx-ferrogate-transport-security: mutual_tls\r\n"));
                let reason = match status_code {
                    200 => "OK",
                    403 => "Forbidden",
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
                requests.push(request);
            }
            requests
        });
        SelfHostedHttpContractServer { endpoint, handle }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(request).unwrap()
    }

    fn http_request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default()
    }
}
