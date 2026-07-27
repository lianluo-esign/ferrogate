// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use bytes::Bytes;
use http::{header, StatusCode};
use pingora::{http::ResponseHeader, proxy::Session, ErrorType, OrErr, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_runtime::SelfHostedWorkerIdentity;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io::Read,
    sync::{Arc, Mutex, OnceLock},
};

/// Origin reflected as `Access-Control-Allow-Origin` on every locally-handled
/// response (config.admin.cors_allowed_origin), set once at process start by
/// `gateway::serve`. A `OnceLock` rather than threading the value through
/// every `write_json_response`-family call site (500+ of them) keeps this a
/// self-contained, centralized change; the tradeoff is that it does not pick
/// up `/admin/v1/config/reload` changes without a restart.
static CORS_ALLOWED_ORIGIN: OnceLock<Option<String>> = OnceLock::new();

pub(crate) fn set_cors_allowed_origin(origin: Option<String>) {
    let _ = CORS_ALLOWED_ORIGIN.set(origin);
}

pub(crate) fn cors_allowed_origin() -> Option<&'static str> {
    CORS_ALLOWED_ORIGIN.get().and_then(|o| o.as_deref())
}

fn apply_cors_headers(response: &mut ResponseHeader) -> PingoraResult<()> {
    if let Some(origin) = cors_allowed_origin() {
        response.insert_header("access-control-allow-origin", origin)?;
        response.insert_header("vary", "origin")?;
    }
    Ok(())
}

/// Answers a CORS `OPTIONS` preflight for a locally-handled admin route.
/// Only called when `cors_allowed_origin()` is set; the caller is expected to
/// gate on that first.
pub(crate) async fn write_cors_preflight_response(session: &mut Session) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(StatusCode::NO_CONTENT, Some(3))?;
    response.insert_header(header::CONTENT_LENGTH, "0")?;
    apply_cors_headers(&mut response)?;
    response.insert_header(
        "access-control-allow-methods",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    )?;
    response.insert_header(
        "access-control-allow-headers",
        "authorization, content-type, x-api-key",
    )?;
    response.insert_header("access-control-max-age", "600")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(None, true).await
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse<'a> {
    pub(crate) status: &'a str,
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadinessResponse<'a> {
    pub(crate) status: &'a str,
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) cluster: crate::state::ClusterStatus,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminStatus<'a> {
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) snapshot: String,
    pub(crate) providers: usize,
    pub(crate) enabled_providers: usize,
    pub(crate) models: usize,
    pub(crate) enabled_models: usize,
    pub(crate) api_keys: usize,
    pub(crate) prompt_templates: usize,
    pub(crate) upstreams: usize,
    pub(crate) enabled_upstreams: usize,
    pub(crate) routes: usize,
    pub(crate) enabled_routes: usize,
    pub(crate) plugins: usize,
    pub(crate) active_plugins: usize,
    pub(crate) extensions: usize,
    pub(crate) active_extensions: usize,
    pub(crate) tools: usize,
    pub(crate) auth_required: bool,
    pub(crate) storage: ferrogate_storage::StorageBackendEvidence,
    pub(crate) analytics: crate::state::AnalyticsStatus,
    pub(crate) cluster: crate::state::ClusterStatus,
    pub(crate) observability: Vec<crate::state::ObservabilityStatus>,
    pub(crate) acme: Option<AdminAcmeStatus>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct AdminAcmeStatus {
    pub(crate) enabled: bool,
    pub(crate) domains: Vec<String>,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) certificate_expires_at_unix: Option<u64>,
    pub(crate) renewal_window_secs: u64,
    pub(crate) renewal_due: bool,
    pub(crate) last_renewal_status: &'static str,
    pub(crate) last_renewal_at_unix: Option<u64>,
    pub(crate) last_renewal_error: Option<String>,
    pub(crate) next_check_at_unix: Option<u64>,
    pub(crate) reload_required: bool,
    pub(crate) reload_mode: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminList<T> {
    pub(crate) object: &'static str,
    pub(crate) data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerRuntime {
    pub(crate) id: &'static str,
    pub(crate) status: &'static str,
    pub(crate) process_name: &'static str,
    pub(crate) process_boundary: &'static str,
    pub(crate) gateway_role: &'static str,
    pub(crate) agent_worker_role: &'static str,
    pub(crate) lifecycle_actions: Vec<&'static str>,
    pub(crate) isolation_backends: Vec<AdminManagedWorkerIsolationBackend>,
    pub(crate) capability_boundary: &'static str,
    pub(crate) capability_policy: AdminManagedWorkerCapabilityPolicy,
    pub(crate) persistence: AdminManagedWorkerPersistence,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerCapabilityPolicy {
    pub(crate) revision: String,
    pub(crate) class_only_policy_mode: &'static str,
    pub(crate) target_level_enforced: bool,
    pub(crate) action_fingerprint_contract: &'static str,
    pub(crate) exact_action_approval_enforced: bool,
    pub(crate) target_grants: Vec<AdminManagedWorkerTargetGrant>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerTargetGrant {
    pub(crate) selector_id: String,
    pub(crate) permission_key: String,
    pub(crate) action: &'static str,
    pub(crate) selector: ferrogate_runtime::CapabilityTargetSelector,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerIsolationBackend {
    pub(crate) kind: &'static str,
    pub(crate) backend_name: &'static str,
    pub(crate) commercial_preference: u8,
    pub(crate) host_lifecycle_owner: &'static str,
    pub(crate) gateway_controls_backend: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerPersistence {
    pub(crate) provider: ferrogate_storage::StorageProviderKind,
    pub(crate) durable: bool,
    pub(crate) implemented: bool,
    pub(crate) timeline_evidence_implemented: bool,
    pub(crate) session_lifecycle_schema_ready: bool,
    pub(crate) session_lifecycle_implemented: bool,
    pub(crate) agent_worker_transport_implemented: bool,
    pub(crate) contract_version: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerSession {
    pub(crate) id: String,
    pub(crate) run_id: String,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) workspace_id: String,
    pub(crate) worker_template_id: String,
    pub(crate) agent_worker_instance_id: Option<String>,
    pub(crate) status: String,
    pub(crate) isolation_backend_kind: String,
    pub(crate) microvm_id: Option<String>,
    pub(crate) capability_envelope_id: String,
    pub(crate) requested_at_unix: Option<u64>,
    pub(crate) started_at_unix: Option<u64>,
    pub(crate) completed_at_unix: Option<u64>,
    pub(crate) cleanup_completed_at_unix: Option<u64>,
    pub(crate) lifecycle_events: Vec<AdminManagedWorkerLifecycleEvent>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedWorkerLifecycleEvent {
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) status: String,
    pub(crate) action: String,
    pub(crate) outcome: String,
    pub(crate) occurred_at_unix: Option<u64>,
    pub(crate) agent_worker_instance_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminFrameworkAdapterRuntime {
    pub(crate) id: &'static str,
    pub(crate) framework: &'static str,
    pub(crate) adapter_name: &'static str,
    pub(crate) adapter_version: &'static str,
    pub(crate) enabled: bool,
    pub(crate) integration_status: &'static str,
    pub(crate) modes: Vec<&'static str>,
    pub(crate) capabilities: Vec<&'static str>,
    pub(crate) event_schema: &'static str,
    pub(crate) managed_capability_boundary: &'static str,
    pub(crate) self_hosted_trust_level: &'static str,
    pub(crate) public_api_exposes_framework_details: bool,
    pub(crate) persistence: AdminFrameworkAdapterPersistence,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminFrameworkAdapterPersistence {
    pub(crate) implemented: bool,
    pub(crate) provider: &'static str,
    pub(crate) session_table: &'static str,
    pub(crate) lifecycle_event_table: &'static str,
    pub(crate) normalized_event_table: &'static str,
    pub(crate) session_records_implemented: bool,
    pub(crate) lifecycle_event_records_implemented: bool,
    pub(crate) normalized_event_records_implemented: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerRuntime {
    pub(crate) id: &'static str,
    pub(crate) status: &'static str,
    pub(crate) execution_owner: &'static str,
    pub(crate) enforcement_boundary: &'static str,
    pub(crate) trust_level: &'static str,
    pub(crate) identity_scope: Vec<&'static str>,
    pub(crate) transport_actions: Vec<&'static str>,
    pub(crate) telemetry_kinds: Vec<&'static str>,
    pub(crate) dispatch_contract: AdminSelfHostedWorkerDispatchContract,
    pub(crate) registration_api: AdminSelfHostedWorkerSurface,
    pub(crate) persistence: AdminSelfHostedWorkerPersistence,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerDispatchContract {
    pub(crate) implemented: bool,
    pub(crate) transport_shape: &'static str,
    pub(crate) current_protocol_version: u32,
    pub(crate) minimum_supported_protocol_version: u32,
    pub(crate) lease_ack_implemented: bool,
    pub(crate) inbound_customer_host_required: bool,
    pub(crate) production_mtls_transport_implemented: bool,
    pub(crate) actions: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerSurface {
    pub(crate) implemented: bool,
    pub(crate) planned_paths: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerPersistence {
    pub(crate) provider: ferrogate_storage::StorageProviderKind,
    pub(crate) durable: bool,
    pub(crate) implemented: bool,
    pub(crate) registration_implemented: bool,
    pub(crate) detail_implemented: bool,
    pub(crate) heartbeat_implemented: bool,
    pub(crate) telemetry_event_implemented: bool,
    pub(crate) artifact_metadata_implemented: bool,
    pub(crate) checkpoint_metadata_implemented: bool,
    pub(crate) identity_fingerprint_rotation_implemented: bool,
    pub(crate) stale_visibility_implemented: bool,
    pub(crate) worker_transport_implemented: bool,
    pub(crate) worker_transport_paths: Vec<&'static str>,
    pub(crate) contract_version: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerRecord {
    pub(crate) id: String,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) workspace_id: String,
    pub(crate) worker_name: String,
    pub(crate) status: String,
    pub(crate) identity_fingerprint: String,
    pub(crate) identity_expires_at_unix: Option<u64>,
    pub(crate) orchestration_enabled: bool,
    pub(crate) registered_at_unix: Option<u64>,
    pub(crate) last_seen_at_unix: Option<u64>,
    pub(crate) trust_level: String,
    pub(crate) stale: bool,
    pub(crate) stale_after_unix: Option<u64>,
    pub(crate) stale_threshold_secs: u64,
    pub(crate) latest_heartbeat: Option<AdminSelfHostedWorkerHeartbeat>,
    pub(crate) telemetry_event_count: usize,
    pub(crate) artifact_count: usize,
    pub(crate) checkpoint_count: usize,
    pub(crate) latest_event_at_unix: Option<u64>,
    pub(crate) latest_artifact_at_unix: Option<u64>,
    pub(crate) latest_checkpoint_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminSelfHostedWorkerHeartbeat {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) reported_at_unix: Option<u64>,
    pub(crate) observed_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerRegistrationRequest {
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) workspace_id: String,
    pub(crate) worker_name: String,
    pub(crate) identity_fingerprint: String,
    #[serde(default)]
    pub(crate) identity_expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) orchestration_enabled: bool,
    #[serde(default)]
    pub(crate) capability_envelope_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerRegistrationResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    /// The provisioned symmetric-AEAD transport secret, returned exactly once
    /// at registration. Never present on the worker record surfaced by
    /// GET/list -- the worker operator must capture it here.
    pub(crate) transport_token_secret: String,
    /// The verified-mTLS client certificate bound to the worker's SPIFFE 4-tuple,
    /// minted by the configured issuing CA and returned exactly once (issue #249).
    /// `None` when no self-hosted worker issuing CA is configured (the deployment
    /// runs the pre-production marker/AEAD posture); present when a CA is
    /// configured so the operator can install it on the worker for production
    /// mutual-TLS admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_certificate: Option<AdminSelfHostedWorkerClientCertificate>,
}

/// A freshly-minted self-hosted worker client certificate, returned exactly once
/// (at registration or identity rotation). The private key is never persisted
/// server-side; only the fingerprint is retained for revocation (issue #249).
#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerClientCertificate {
    /// SPIFFE URI SAN the leaf binds to
    /// (`spiffe://ferrogate/self-hosted/{tenant}/{workspace}/{worker}/{token}`).
    pub(crate) spiffe_id: String,
    /// PEM-encoded leaf certificate.
    pub(crate) certificate_pem: String,
    /// PEM-encoded PKCS#8 private key. Returned once; never stored server-side.
    pub(crate) private_key_pem: String,
    /// SHA-256 fingerprint (lowercase hex) of the leaf cert DER, retained by the
    /// control plane for revocation.
    pub(crate) fingerprint: String,
    /// Hex-encoded certificate serial number.
    pub(crate) serial: String,
    /// Server-clock `notAfter` (unix seconds) of the leaf certificate.
    pub(crate) not_after_unix: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerRotateRequest {
    pub(crate) identity_fingerprint: String,
    #[serde(default)]
    pub(crate) identity_expires_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerRotateResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    /// The freshly-issued transport secret, returned exactly once on rotation.
    pub(crate) transport_token_secret: String,
    /// A fresh verified-mTLS client certificate bound to the rotated 4-tuple,
    /// returned exactly once (issue #249). `None` when no issuing CA is
    /// configured. Rotation changes the SPIFFE `token_id` segment, so a new cert
    /// is minted to match; the previous cert should be revoked by the operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_certificate: Option<AdminSelfHostedWorkerClientCertificate>,
    pub(crate) previous_identity_fingerprint: String,
    pub(crate) previous_identity_expires_at_unix: Option<u64>,
    pub(crate) rotated_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerHeartbeatRequest {
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) reported_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) heartbeat_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerHeartbeatResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    pub(crate) heartbeat: AdminSelfHostedWorkerHeartbeat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelfHostedWorkerHeartbeatTransportRequest {
    pub(crate) identity: SelfHostedWorkerIdentity,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) reported_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) heartbeat_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelfHostedWorkerTelemetryEventTransportRequest {
    pub(crate) identity: SelfHostedWorkerIdentity,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) occurred_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) event_json: Option<String>,
    // #329: the dispatch lease's correlation identity, stamped by the worker
    // onto the evidence it reports for the run so the self-hosted leg emits the
    // SAME {request_id, trace_id, agent_run_id} triple (#305) +
    // `parent_action_fingerprint` (#307) the control plane persisted on the
    // dispatch. `serde(default)` keeps this wire-compatible: an older worker
    // omits the keys and they deserialize as None (a keyless run) — never
    // fabricated. This is the internal encrypted-frame transport (opaque
    // `MachineTransportRequest` in the OpenAPI contract), so the additive fields
    // need no contract change.
    #[serde(default)]
    pub(crate) request_id: Option<String>,
    #[serde(default)]
    pub(crate) trace_id: Option<String>,
    #[serde(default)]
    pub(crate) agent_run_id: Option<String>,
    #[serde(default)]
    pub(crate) parent_action_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerTelemetryEvent {
    pub(crate) id: String,
    pub(crate) worker_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) trust_level: String,
    pub(crate) occurred_at_unix: Option<u64>,
    pub(crate) ingested_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerTelemetryEventRequest {
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) occurred_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) event_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerTelemetryEventResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    pub(crate) event: AdminSelfHostedWorkerTelemetryEvent,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminSelfHostedWorkerEventStream {
    pub(crate) object: &'static str,
    pub(crate) worker_id: String,
    pub(crate) trust_level: &'static str,
    pub(crate) data: Vec<AdminSelfHostedRunEvent>,
    pub(crate) total: usize,
    pub(crate) limit: usize,
    pub(crate) after_event_id: Option<String>,
    pub(crate) next_after_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminSelfHostedRunEvent {
    pub(crate) id: String,
    pub(crate) worker_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) trust_level: String,
    pub(crate) occurred_at_unix: Option<u64>,
    pub(crate) ingested_at_unix: Option<u64>,
    pub(crate) event_json: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminSelfHostedRunTimeline {
    pub(crate) object: &'static str,
    pub(crate) run_id: String,
    pub(crate) session_ids: Vec<String>,
    pub(crate) worker_ids: Vec<String>,
    pub(crate) trust_level: &'static str,
    pub(crate) reported_event_count: usize,
    pub(crate) lifecycle_event_count: usize,
    pub(crate) first_seen_unix: Option<u64>,
    pub(crate) last_seen_unix: Option<u64>,
    pub(crate) latest_lifecycle_state: Option<String>,
    pub(crate) events: Vec<AdminSelfHostedRunEvent>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerArtifact {
    pub(crate) id: String,
    pub(crate) worker_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) artifact_name: String,
    pub(crate) content_type: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) trust_level: String,
    pub(crate) created_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerArtifactRequest {
    pub(crate) artifact_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) artifact_name: String,
    #[serde(default)]
    pub(crate) content_type: Option<String>,
    pub(crate) size_bytes: u64,
    #[serde(default)]
    pub(crate) created_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) artifact_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelfHostedWorkerArtifactTransportRequest {
    pub(crate) identity: SelfHostedWorkerIdentity,
    pub(crate) artifact_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) artifact_name: String,
    #[serde(default)]
    pub(crate) content_type: Option<String>,
    pub(crate) size_bytes: u64,
    #[serde(default)]
    pub(crate) created_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) artifact_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerArtifactResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    pub(crate) artifact: AdminSelfHostedWorkerArtifact,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerCheckpoint {
    pub(crate) id: String,
    pub(crate) worker_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) checkpoint_name: String,
    pub(crate) size_bytes: u64,
    pub(crate) trust_level: String,
    pub(crate) created_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminSelfHostedWorkerCheckpointRequest {
    pub(crate) checkpoint_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) checkpoint_name: String,
    pub(crate) size_bytes: u64,
    #[serde(default)]
    pub(crate) created_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) checkpoint_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelfHostedWorkerCheckpointTransportRequest {
    pub(crate) identity: SelfHostedWorkerIdentity,
    pub(crate) checkpoint_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) checkpoint_name: String,
    pub(crate) size_bytes: u64,
    #[serde(default)]
    pub(crate) created_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) checkpoint_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSelfHostedWorkerCheckpointResponse {
    pub(crate) object: &'static str,
    pub(crate) worker: AdminSelfHostedWorkerRecord,
    pub(crate) checkpoint: AdminSelfHostedWorkerCheckpoint,
}

#[derive(Debug, Serialize)]
pub(crate) struct SelfHostedWorkerRunLeaseResponse {
    pub(crate) object: &'static str,
    #[serde(flatten)]
    pub(crate) lease: ferrogate_runtime::SelfHostedRunLease,
}

#[derive(Debug, Serialize)]
pub(crate) struct SelfHostedWorkerRunAckResponse {
    pub(crate) object: &'static str,
    #[serde(flatten)]
    pub(crate) ack: ferrogate_runtime::SelfHostedRunAck,
}

impl<T> AdminList<T> {
    pub(crate) fn new(data: Vec<T>) -> Self {
        Self {
            object: "list",
            data,
            total: None,
            offset: None,
            limit: None,
        }
    }

    pub(crate) fn paginated(data: Vec<T>, total: usize, offset: usize, limit: usize) -> Self {
        Self {
            object: "list",
            data,
            total: Some(total),
            offset: Some(offset),
            limit: Some(limit),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProvider {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) compatibility: &'static str,
    pub(crate) base_url: String,
    pub(crate) has_api_key: bool,
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProviderModelCatalog {
    pub(crate) provider: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) enabled: bool,
    pub(crate) status: String,
    pub(crate) models: Vec<AdminProviderModelCandidate>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProviderModelCandidate {
    pub(crate) id: String,
    pub(crate) owned_by: Option<String>,
    pub(crate) created: Option<u64>,
    pub(crate) context_window: Option<u64>,
    pub(crate) capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminGatewayConfigProfile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) revision: u32,
    pub(crate) enabled: bool,
    pub(crate) api_key_ids: Vec<String>,
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminGatewayConfigMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) revision: Option<u32>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) api_key_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminGatewayConfigMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) gateway_config: AdminGatewayConfigProfile,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAgentWorkflow {
    pub(crate) workflow: crate::config::AgentWorkflowPolicy,
    pub(crate) counters: AdminAgentWorkflowCounters,
}

#[derive(Debug, Serialize, Default)]
pub(crate) struct AdminAgentWorkflowCounters {
    pub(crate) request_count: u64,
    pub(crate) error_count: u64,
    pub(crate) billing_event_count: u64,
    pub(crate) audit_event_count: u64,
    pub(crate) estimated_tokens: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAgentWorkflowMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) agent_workflow: AdminAgentWorkflow,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSkillPackage {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) compatibility: crate::config::SkillPackageCompatibility,
    pub(crate) permissions: crate::config::ExtensionPermissions,
    pub(crate) capabilities: Vec<crate::config::SkillPackageCapability>,
    pub(crate) resources: crate::config::SkillPackageResources,
    pub(crate) api_key_ids: Vec<String>,
    pub(crate) metadata: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminSkillPackageMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) skill_package: AdminSkillPackage,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAgentUpstream {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) protocol: crate::config::AgentUpstreamProtocol,
    pub(crate) endpoint: String,
    pub(crate) tenant_ids: Vec<String>,
    pub(crate) capabilities: Vec<crate::config::AgentUpstreamCapability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminAgentUpstreamMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) protocol: Option<crate::config::AgentUpstreamProtocol>,
    pub(crate) endpoint: Option<String>,
    #[serde(default)]
    pub(crate) auth: Option<crate::config::AgentUpstreamAuth>,
    #[serde(default)]
    pub(crate) tenant_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) capabilities: Option<Vec<crate::config::AgentUpstreamCapability>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAgentUpstreamMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) agent_upstream: AdminAgentUpstream,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentUpstreamDiscovery<'a> {
    pub(crate) object: &'static str,
    pub(crate) id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) description: Option<&'a str>,
    pub(crate) protocol: crate::config::AgentUpstreamProtocol,
    pub(crate) endpoint: &'a str,
    pub(crate) capabilities: &'a [crate::config::AgentUpstreamCapability],
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentSkillPackage {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: Option<String>,
    pub(crate) capabilities: Vec<crate::config::SkillPackageCapability>,
    pub(crate) compatibility: crate::config::SkillPackageCompatibility,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPlugin {
    pub(crate) id: String,
    pub(crate) kind: crate::config::ExtensionKind,
    pub(crate) version: String,
    pub(crate) manifest: crate::config::PluginManifest,
    pub(crate) compatibility: crate::config::PluginCompatibility,
    pub(crate) enabled: bool,
    pub(crate) source: String,
    pub(crate) order: u32,
    pub(crate) approval_policy: ferrogate_core::ApprovalPolicy,
    pub(crate) permissions: crate::config::ExtensionPermissions,
    pub(crate) config: BTreeMap<String, toml::Value>,
    pub(crate) capabilities: Vec<String>,
    pub(crate) tools: Vec<String>,
    pub(crate) active: bool,
    pub(crate) lifecycle: &'static str,
    pub(crate) health: &'static str,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminPluginMutation {
    pub(crate) id: Option<String>,
    pub(crate) kind: crate::config::ExtensionKind,
    #[serde(default)]
    pub(crate) version: Option<String>,
    #[serde(default)]
    pub(crate) manifest: Option<crate::config::PluginManifest>,
    #[serde(default)]
    pub(crate) compatibility: Option<crate::config::PluginCompatibility>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) source: Option<String>,
    #[serde(default)]
    pub(crate) order: Option<u32>,
    #[serde(default)]
    pub(crate) approval_policy: Option<ferrogate_core::ApprovalPolicy>,
    #[serde(default)]
    pub(crate) permissions: Option<crate::config::ExtensionPermissions>,
    #[serde(default)]
    pub(crate) config: Option<BTreeMap<String, toml::Value>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPluginMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) plugin: AdminPlugin,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPromptTemplate {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: crate::config::PromptTemplateStatus,
    pub(crate) target: crate::config::PromptTemplateTarget,
    pub(crate) model: String,
    pub(crate) variables: Vec<crate::config::PromptTemplateVariable>,
    pub(crate) active_revision: Option<u32>,
    pub(crate) versions: Vec<crate::config::PromptTemplateVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminPromptTemplateMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<crate::config::PromptTemplateStatus>,
    #[serde(default)]
    pub(crate) target: Option<crate::config::PromptTemplateTarget>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) variables: Option<Vec<crate::config::PromptTemplateVariable>>,
    #[serde(default)]
    pub(crate) version: Option<crate::config::PromptTemplateVersion>,
    #[serde(default)]
    pub(crate) versions: Option<Vec<crate::config::PromptTemplateVersion>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPromptTemplateMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) prompt_template: AdminPromptTemplate,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplateRenderRequest {
    #[serde(default)]
    pub(crate) variables: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub(crate) revision: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminApiKey {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) key_source: &'static str,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_models: Vec<String>,
    pub(crate) denied_models: Vec<String>,
    pub(crate) allowed_providers: Vec<String>,
    pub(crate) denied_providers: Vec<String>,
    pub(crate) organization_id: Option<String>,
    /// #515: surfaced so an operator (and the console, when it catches up) can
    /// SEE which keys hold platform root instead of inferring it from a null
    /// `organization_id`. `false` here means "not root"; `true` means the key
    /// declared it.
    pub(crate) platform_operator: bool,
    pub(crate) team_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) workspace_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    pub(crate) expires_at_unix: Option<u64>,
    pub(crate) log_bodies: bool,
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminApiKeyMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) key_env: Option<String>,
    #[serde(default)]
    pub(crate) key: Option<String>,
    #[serde(default)]
    pub(crate) key_hash: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) denied_models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) denied_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    /// Explicit platform-root opt-in (issue #515), mirroring
    /// [`crate::config::ApiKey::platform_operator`]. Mutually exclusive with
    /// `organization_id`; omitted leaves the key on the deployment-wide
    /// `[tenancy] implicit_platform_operator` answer.
    #[serde(default)]
    pub(crate) platform_operator: Option<bool>,
    #[serde(default)]
    pub(crate) team_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) workspace_id: Option<String>,
    #[serde(default)]
    pub(crate) user_id: Option<String>,
    #[serde(default)]
    pub(crate) monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub(crate) request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) log_bodies: Option<bool>,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminApiKeyMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) key: AdminApiKey,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminDeleteResponse {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) deleted: bool,
}

// --- Sellable subscription plans/tiers (issue #168) ---

/// A named, sellable subscription tier: a bundle of feature flags plus
/// default quota values that seeds the effective-quota merge chain as its
/// floor, below any explicit scope-level `quota_policies` row -- see
/// `ferrogate_policy::resolve_effective_quota`.
#[derive(Debug, Serialize)]
pub(crate) struct AdminPlan {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) mcp_enabled: bool,
    pub(crate) self_hosted_workers_enabled: bool,
    pub(crate) admin_console_seats: Option<u32>,
    pub(crate) default_model_allowlist: Vec<String>,
    pub(crate) default_rpm_limit: Option<u64>,
    pub(crate) default_tpm_limit: Option<u64>,
    pub(crate) default_monthly_budget_usd: Option<f64>,
    pub(crate) asset_hosting_enabled: bool,
    pub(crate) default_asset_storage_quota_bytes: Option<u64>,
    /// #259: per-object (not cumulative) default asset byte ceiling, independent
    /// of `default_asset_storage_quota_bytes`.
    pub(crate) default_asset_max_object_bytes: Option<u64>,
    /// #428: tenant-wide default monthly USD ceiling on CF-hosted-agent runtime
    /// cost; a monetary value that mirrors `default_monthly_budget_usd`.
    pub(crate) default_agent_cost_budget_usd: Option<f64>,
    pub(crate) extension_tools_enabled: bool,
    /// #262: tenant-wide default monthly egress byte budget / download RPM.
    pub(crate) default_monthly_egress_bytes_budget: Option<u64>,
    pub(crate) default_download_rpm_limit: Option<u64>,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

/// POST create / PUT replace / PATCH merge payload for `/admin/v1/plans`.
/// All fields optional so PATCH can carry only the fields being changed;
/// PUT/POST treat an absent field as "reset to default" the same way
/// `AdminQuotaPolicyMutation` does.
#[derive(Debug, Deserialize)]
pub(crate) struct AdminPlanMutation {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) slug: Option<String>,
    #[serde(default)]
    pub(crate) mcp_enabled: Option<bool>,
    #[serde(default)]
    pub(crate) self_hosted_workers_enabled: Option<bool>,
    #[serde(default)]
    pub(crate) admin_console_seats: Option<u32>,
    #[serde(default)]
    pub(crate) default_model_allowlist: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) default_rpm_limit: Option<u64>,
    #[serde(default)]
    pub(crate) default_tpm_limit: Option<u64>,
    #[serde(default)]
    pub(crate) default_monthly_budget_usd: Option<f64>,
    #[serde(default)]
    pub(crate) asset_hosting_enabled: Option<bool>,
    #[serde(default)]
    pub(crate) default_asset_storage_quota_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) default_asset_max_object_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) default_agent_cost_budget_usd: Option<f64>,
    #[serde(default)]
    pub(crate) extension_tools_enabled: Option<bool>,
    #[serde(default)]
    pub(crate) default_monthly_egress_bytes_budget: Option<u64>,
    #[serde(default)]
    pub(crate) default_download_rpm_limit: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPlanMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) plan: AdminPlan,
}

/// `POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay` (issue
/// #388): the result of re-enqueuing a dead-lettered billing report for
/// redelivery. `id` is the ledger-entry idempotency key the billing service
/// dedups on (so replay never double-bills); `attempts`/`next_attempt_unix`
/// echo the reset delivery schedule as inspectable evidence.
#[derive(Debug, Serialize)]
pub(crate) struct AdminBillingOutboxReplayResponse {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) replayed: bool,
    pub(crate) dead_lettered: bool,
    pub(crate) attempts: i64,
    pub(crate) next_attempt_unix: i64,
}

// --- Prepaid-credit wallets and payment methods (issue #169) ---

#[derive(Debug, Serialize)]
pub(crate) struct AdminWallet {
    pub(crate) tenant_id: String,
    pub(crate) balance_credits: i64,
    pub(crate) auto_recharge_threshold_credits: Option<i64>,
    pub(crate) auto_recharge_amount_credits: Option<i64>,
    pub(crate) dunning: bool,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

/// POST create / PATCH merge payload for `/admin/v1/wallets`. Deliberately
/// has no `balance_credits` field -- balance only ever changes through the
/// atomic `POST /admin/v1/wallets/{tenant_id}/adjust` endpoint
/// (`AdminWalletAdjustRequest`), never a blind overwrite, so a wallet's
/// balance can't accidentally be reset by an unrelated config update.
#[derive(Debug, Deserialize)]
pub(crate) struct AdminWalletMutation {
    #[serde(default)]
    pub(crate) tenant_id: Option<String>,
    #[serde(default)]
    pub(crate) auto_recharge_threshold_credits: Option<i64>,
    #[serde(default)]
    pub(crate) auto_recharge_amount_credits: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminWalletAdjustRequest {
    /// Positive to credit (top-up), negative to debit. Applied atomically
    /// against the wallet's current balance -- never a blind overwrite.
    pub(crate) delta_credits: i64,
}

/// Triggers a real payment-provider charge (issue #169), crediting the
/// wallet with the resulting credits on success. Distinct from
/// `AdminWalletAdjustRequest`, which changes the balance directly with no
/// payment-provider involvement (an operator-issued credit/correction).
#[derive(Debug, Deserialize)]
pub(crate) struct AdminWalletChargeRequest {
    pub(crate) payment_method_id: Option<String>,
    pub(crate) amount_usd_cents: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminWalletChargeResponse {
    pub(crate) object: &'static str,
    pub(crate) succeeded: bool,
    pub(crate) provider_charge_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) decline_reason: Option<String>,
    pub(crate) wallet: AdminWallet,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminWalletMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) wallet: AdminWallet,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPaymentMethod {
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) provider: String,
    pub(crate) provider_customer_id: String,
    pub(crate) provider_payment_method_id: String,
    pub(crate) is_default: bool,
    pub(crate) created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminPaymentMethodCreateRequest {
    pub(crate) tenant_id: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) provider_customer_id: Option<String>,
    pub(crate) provider_payment_method_id: Option<String>,
    #[serde(default)]
    pub(crate) is_default: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPaymentMethodMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) payment_method: AdminPaymentMethod,
}

// --- Multi-tenant hierarchy + durable virtual API keys (TOK-11 / TOK-12) ---

#[derive(Debug, Serialize)]
pub(crate) struct AdminTenantAccount {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) status: String,
    pub(crate) plan_id: String,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminTenantAccountCreateRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) slug: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
    #[serde(default)]
    pub(crate) plan_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminTenantAccountMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) tenant: AdminTenantAccount,
}

/// `PUT /admin/v1/tenant-accounts/{tenant_id}/plan` (issue #388): the
/// focused plan-assignment payload the #364 CLI drives, distinct from the
/// general `AdminTenantAccountCreateRequest` merge -- assigning a plan is a
/// single, named, platform-operator action rather than a whole-account edit.
#[derive(Debug, Deserialize)]
pub(crate) struct AdminTenantPlanAssignmentRequest {
    pub(crate) plan_id: Option<String>,
}

/// `GET /admin/v1/tenant-accounts/{id}/resolved-defaults` (issue #168):
/// the merged, effective quota and feature entitlements a request
/// attributed to this tenant alone (no project/workspace/key overrides)
/// would actually get -- i.e. the tenant's plan defaults as they apply
/// today, not just the plan_id pointer. `effective_quota` mirrors
/// `ferrogate_policy::EffectiveQuota`; `None` fields mean "no limit
/// configured at any scope in the chain", not zero.
#[derive(Debug, Serialize)]
pub(crate) struct AdminTenantResolvedDefaults {
    pub(crate) object: &'static str,
    pub(crate) tenant_id: String,
    pub(crate) plan_id: String,
    pub(crate) model_allowlist: Option<Vec<String>>,
    pub(crate) rpm_limit: Option<u64>,
    pub(crate) tpm_limit: Option<u64>,
    pub(crate) monthly_budget_usd: Option<f64>,
    pub(crate) mcp_enabled: bool,
    pub(crate) extension_tools_enabled: bool,
    pub(crate) self_hosted_workers_enabled: bool,
    pub(crate) asset_hosting_enabled: bool,
    pub(crate) default_asset_storage_quota_bytes: Option<u64>,
    /// #259: the plan's per-object (not cumulative) default asset byte ceiling.
    pub(crate) default_asset_max_object_bytes: Option<u64>,
    /// #428: the plan's default monthly USD ceiling on CF-hosted-agent runtime
    /// cost (mirrors `default_monthly_budget_usd`).
    pub(crate) default_agent_cost_budget_usd: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProject {
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) status: String,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminProjectCreateRequest {
    pub(crate) id: Option<String>,
    pub(crate) tenant_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) slug: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProjectMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) project: AdminProject,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminWorkspace {
    pub(crate) id: String,
    pub(crate) project_id: String,
    pub(crate) tenant_id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) environment: String,
    pub(crate) status: String,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminWorkspaceCreateRequest {
    pub(crate) id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) slug: Option<String>,
    #[serde(default)]
    pub(crate) environment: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminWorkspaceMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) workspace: AdminWorkspace,
}

/// Redacted view of a durable Supabase-backed virtual API key: never carries
/// `key_hash` or the plaintext secret.
#[derive(Debug, Serialize)]
pub(crate) struct AdminVirtualApiKey {
    pub(crate) id: String,
    pub(crate) workspace_id: String,
    pub(crate) tenant_id: String,
    pub(crate) project_id: String,
    pub(crate) name: String,
    pub(crate) key_prefix: String,
    pub(crate) last4: String,
    pub(crate) enabled: bool,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_models: Vec<String>,
    pub(crate) allowed_providers: Vec<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    pub(crate) created_at_unix: u64,
    pub(crate) updated_at_unix: u64,
    pub(crate) rotated_at_unix: Option<u64>,
    pub(crate) expires_at_unix: Option<u64>,
    pub(crate) revoked_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminVirtualApiKeyCreateRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) workspace_id: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub(crate) request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<u64>,
}

/// `secret` is populated only in the response to create/rotate; every other
/// read of a virtual key (list/get/enable/disable/revoke) omits it.
#[derive(Debug, Serialize)]
pub(crate) struct AdminVirtualApiKeyMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) key: AdminVirtualApiKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<String>,
}

/// A quota/rate-limit policy at one scope (tenant/project/workspace/key) in
/// the P1-3 multi-level hierarchy.
#[derive(Debug, Serialize)]
pub(crate) struct AdminQuotaPolicy {
    pub(crate) id: String,
    pub(crate) scope_type: String,
    pub(crate) scope_id: String,
    pub(crate) model_allowlist: Vec<String>,
    pub(crate) rpm_limit: Option<u64>,
    pub(crate) tpm_limit: Option<u64>,
    pub(crate) monthly_budget_usd: Option<f64>,
    /// Tenant-only override of `StoredPlan.default_asset_storage_quota_bytes`
    /// (issue #188). `None` means the tenant's plan default applies.
    pub(crate) asset_storage_quota_bytes: Option<u64>,
    /// Tenant-only override of `StoredPlan.default_asset_max_object_bytes`
    /// (issue #259): a per-object (not cumulative) ceiling, independent of
    /// `asset_storage_quota_bytes`. `None` means the plan default applies.
    pub(crate) asset_max_object_bytes: Option<u64>,
    /// #428: per-scope monthly USD ceiling on CF-hosted-agent runtime cost, a
    /// monetary value merged `min`-across-the-chain like `monthly_budget_usd`
    /// (settable at any scope, not tenant-only). `None` means no cap here.
    pub(crate) agent_cost_budget_usd: Option<f64>,
    /// Percent-of-`monthly_budget_usd` tiers (e.g. `[50, 90]`) that fire a
    /// one-time proactive alert webhook when spend first crosses them
    /// (issue #170) -- distinct from the unconditional 100% hard-deny in
    /// `AppState::monthly_budget_exceeded`.
    pub(crate) alert_threshold_pcts: Vec<u8>,
    /// #262: per-scope monthly egress byte budget / download RPM cap, merged
    /// `min`-across-the-chain like `rpm_limit`/`monthly_budget_usd`.
    pub(crate) monthly_egress_bytes_budget: Option<u64>,
    pub(crate) download_rpm_limit: Option<u64>,
    pub(crate) enabled: bool,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminQuotaPolicyMutation {
    #[serde(default)]
    pub(crate) scope_type: Option<String>,
    #[serde(default)]
    pub(crate) scope_id: Option<String>,
    #[serde(default)]
    pub(crate) model_allowlist: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) rpm_limit: Option<u64>,
    #[serde(default)]
    pub(crate) tpm_limit: Option<u64>,
    #[serde(default)]
    pub(crate) monthly_budget_usd: Option<f64>,
    #[serde(default)]
    pub(crate) asset_storage_quota_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) asset_max_object_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) agent_cost_budget_usd: Option<f64>,
    #[serde(default)]
    pub(crate) alert_threshold_pcts: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) monthly_egress_bytes_budget: Option<u64>,
    #[serde(default)]
    pub(crate) download_rpm_limit: Option<u64>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminQuotaPolicyMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) policy: AdminQuotaPolicy,
}

// --- Static asset hosting (issue #176/#177) ---

/// Metadata for one tenant-scoped static asset -- deliberately excludes
/// `content`: list/mutation responses return this summary, and only the
/// dedicated content-fetch endpoint returns raw bytes.
#[derive(Debug, Serialize)]
pub(crate) struct AssetSummary {
    pub(crate) id: String,
    pub(crate) asset_type: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) content_type: String,
    pub(crate) content_hash: String,
    pub(crate) size_bytes: u64,
    /// `true` when this asset's bytes live in an S3-compatible bucket
    /// (issue #176) rather than inline in Postgres. Exposes whether
    /// bucket storage is in play without leaking the raw bucket/key
    /// reference (`storage_uri`) itself.
    pub(crate) storage_backed: bool,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

/// One WITHHELD asset row for the operator-only inspection surface (issue #379,
/// follow-up to #366). Carries the ordinary [`AssetSummary`] metadata plus the
/// two things an operator needs to triage an asset consumers can never see: the
/// durable `visibility` state (`pending_scan` = deferred async scan not yet run;
/// `quarantined` = the scanner flagged it or a fail-closed-unavailable policy
/// withheld it), and the `screening_evidence` recorded at push/commit time --
/// the scan/signature/approval verdict + verification manifest from #366's push
/// screening. `screening_evidence` is `None` when the originating push audit
/// event is no longer retained (best-effort correlation, never fabricated).
#[derive(Debug, Serialize)]
pub(crate) struct WithheldAssetSummary {
    #[serde(flatten)]
    pub(crate) asset: AssetSummary,
    /// The durable trust-screening state on the asset row: `pending_scan` or
    /// `quarantined`. A `visible` asset is never listed here.
    pub(crate) visibility: &'static str,
    /// The screening evidence detail (scan outcome, signature status,
    /// cross-tenant approval state, verification manifest) captured on the
    /// asset's push/commit audit event. `None` when that audit row is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) screening_evidence: Option<String>,
}

/// Authoritative tenant-level asset storage usage and the effective upload
/// limits applied by the gateway. Usage comes from the configured repository,
/// not from summing a client-side page of asset summaries.
#[derive(Debug, Serialize)]
pub(crate) struct AssetStorageSummary {
    pub(crate) object: &'static str,
    pub(crate) used_bytes: u64,
    pub(crate) quota_bytes: Option<u64>,
    pub(crate) remaining_bytes: Option<u64>,
    pub(crate) inline_upload_max_bytes: u64,
    pub(crate) presigned_upload: AssetPresignedUploadConstraints,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssetPresignedUploadConstraints {
    pub(crate) enabled: bool,
    pub(crate) max_object_bytes: Option<u64>,
    pub(crate) url_ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssetMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) asset: AssetSummary,
}

/// Operator-supplied completed out-of-band scan result that drives a
/// `pending_scan -> visible|quarantined` promotion (issue #378, follow-up to
/// #366). `scan_outcome` is the terminal verdict (`clean` publishes the asset,
/// `quarantined` withholds it permanently); an unknown value is rejected
/// fail-closed and never promotes. `evidence` is the durable, human-readable
/// justification (scanner id, verdict detail, ticket) recorded verbatim in the
/// audit event so the promotion is explainable after the fact.
#[derive(Debug, Deserialize)]
pub(crate) struct AssetVisibilityPromotionRequest {
    pub(crate) scan_outcome: String,
    #[serde(default)]
    pub(crate) evidence: String,
    /// Optional identifier of the out-of-band scanner/backend that produced the
    /// verdict, echoed into the audit evidence when present.
    #[serde(default)]
    pub(crate) scanner: Option<String>,
}

/// Result of a completed-scan visibility promotion (issue #378). Echoes the
/// resulting durable `visibility` and the `scan_outcome` that drove it
/// alongside the promoted asset summary, so a caller can confirm the exact
/// terminal state the gateway persisted.
#[derive(Debug, Serialize)]
pub(crate) struct AssetVisibilityPromotionResponse {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) visibility: &'static str,
    pub(crate) scan_outcome: &'static str,
    pub(crate) asset: AssetSummary,
}

// --- Artifact registry semantics (issue #260) ---

/// One channel pointer (`latest`/`stable`/`canary` or a free-form tag) and the
/// concrete version it currently resolves to.
#[derive(Debug, Serialize)]
pub(crate) struct AssetChannelSummary {
    pub(crate) channel: String,
    pub(crate) version: String,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssetChannelMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) asset_type: String,
    pub(crate) name: String,
    pub(crate) channel: AssetChannelSummary,
}

/// One platform/arch artifact of a logical version, with its own hash/size.
#[derive(Debug, Serialize)]
pub(crate) struct AssetManifestVariant {
    pub(crate) variant: String,
    pub(crate) content_type: String,
    pub(crate) content_hash: String,
    pub(crate) size_bytes: u64,
    pub(crate) storage_backed: bool,
}

/// One logical version, its yank state, and every platform/arch variant it
/// carries.
#[derive(Debug, Serialize)]
pub(crate) struct AssetManifestVersion {
    pub(crate) version: String,
    pub(crate) yanked: bool,
    pub(crate) variants: Vec<AssetManifestVariant>,
}

/// The single self-serve document an agent needs: every version, channel, and
/// variant (with hashes) for one `{asset_type}/{name}` (issue #260).
#[derive(Debug, Serialize)]
pub(crate) struct AssetManifest {
    pub(crate) object: &'static str,
    pub(crate) asset_type: String,
    pub(crate) name: String,
    pub(crate) channels: Vec<AssetChannelSummary>,
    pub(crate) versions: Vec<AssetManifestVersion>,
}

// --- Tenant-level RBAC entitlements (issue #182) ---

#[derive(Debug, Serialize)]
pub(crate) struct AdminPermission {
    pub(crate) id: String,
    pub(crate) key: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminPermissionMutation {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) key: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPermissionMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) permission: AdminPermission,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminRole {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) description: String,
    pub(crate) permission_keys: Vec<String>,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminRoleMutation {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) slug: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) permission_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminRoleMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) role: AdminRole,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminTenantRoleBinding {
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) role_id: String,
    pub(crate) created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminTenantRoleBindingRequest {
    pub(crate) role_id: String,
}

/// One row of the P1-4 usage/cost report: either a raw per-scope-per-month
/// rollup, or (when `group_by` is requested) a sum across every rollup
/// sharing that row's `scope_type`/`scope_id`/`period_month` key -- whichever
/// of those three the request did not group by is reported as `None`.
#[derive(Debug, Serialize)]
pub(crate) struct AdminUsageReportRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) period_month: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope_id: Option<String>,
    /// Present only for `group_by=metadata.<key>` rows (issue #171) --
    /// `metadata_key` is the requested key, `metadata_value` is the
    /// distinct value this row aggregates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metadata_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metadata_value: Option<String>,
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) total_tokens: u64,
    pub(crate) cost_usd: f64,
    pub(crate) request_count: u64,
    pub(crate) error_count: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminMcpServerMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) server: ferrogate_mcp::McpServerStatus,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminPolicyMutation {
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) effect: Option<String>,
    #[serde(default)]
    pub(crate) organization_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) project_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) api_key_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) code: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPolicyMutationResponse<T> {
    pub(crate) object: &'static str,
    pub(crate) policy: T,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AdminTenantRef {
    pub(crate) organization_id: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) api_key_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminConfigValidateRequest {
    #[serde(default)]
    pub(crate) config_toml: Option<String>,
    #[serde(default)]
    pub(crate) config_yaml: Option<String>,
    #[serde(default)]
    pub(crate) config_caddyfile: Option<String>,
    #[serde(default)]
    pub(crate) filename: Option<String>,
    #[serde(default)]
    pub(crate) source: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminConfigValidateResponse {
    pub(crate) valid: bool,
    pub(crate) snapshot: Option<String>,
    pub(crate) reload_mode: Option<&'static str>,
    pub(crate) listener_reload_required: bool,
    pub(crate) reload_reason: Option<String>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminConfigReloadResponse {
    pub(crate) valid: bool,
    pub(crate) committed: bool,
    pub(crate) mode: &'static str,
    pub(crate) active_snapshot: Option<String>,
    pub(crate) candidate_snapshot: Option<String>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminDrainRequest {
    pub(crate) drain: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminDrainResponse {
    pub(crate) object: &'static str,
    pub(crate) draining: bool,
    pub(crate) accepting_new_requests: bool,
    pub(crate) drain_reason: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiModelList {
    pub(crate) object: &'static str,
    pub(crate) data: Vec<OpenAiModel>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiModel {
    pub(crate) id: String,
    pub(crate) object: &'static str,
    pub(crate) created: u64,
    pub(crate) owned_by: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorObject,
}

#[derive(Debug, Serialize)]
struct ErrorObject {
    message: String,
    #[serde(rename = "type")]
    kind: &'static str,
    code: String,
    request_id: Option<String>,
}

pub(crate) async fn write_json_response<T: Serialize>(
    session: &mut Session,
    status: StatusCode,
    value: &T,
    request_id: &str,
) -> PingoraResult<()> {
    let body = serde_json::to_vec(value).expect("JSON serialization should not fail");
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, "application/json")?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

pub(crate) async fn write_empty_response(
    session: &mut Session,
    status: StatusCode,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_LENGTH, "0")?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(None, true).await
}

pub(crate) async fn write_raw_response(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    body: Bytes,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, content_type)?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

/// HTTP caching metadata attached to an asset/site GET response
/// (issue #258): a strong validator derived from the stored sha256, a
/// `Last-Modified` timestamp, and a `Cache-Control` policy, so conditional
/// (`If-None-Match`/`If-Modified-Since`) and `Range` requests can be answered
/// with `304`/`206` instead of always re-transmitting the whole body.
pub(crate) struct AssetCacheHeaders<'a> {
    pub(crate) content_type: &'a str,
    /// Strong ETag validator, already quoted (e.g. `"<sha256hex>"`).
    pub(crate) etag: String,
    pub(crate) last_modified_unix: i64,
    pub(crate) cache_control: &'a str,
}

/// The outcome of evaluating conditional/range request headers against a
/// stored asset's validators. Kept pure (and unit-tested) so the async writer
/// below stays a thin translation from decision to pingora response bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConditionalOutcome {
    /// Validators matched the client's cached copy -> 304, no body.
    NotModified,
    /// Serve the whole representation -> 200.
    Full,
    /// Serve a single inclusive byte range `[start, end]` -> 206.
    Range { start: usize, end: usize },
    /// A syntactically valid range that falls outside the body -> 416.
    RangeNotSatisfiable,
}

/// Decides how to answer a GET given its conditional/range headers. `If-None-Match`
/// takes precedence over `If-Modified-Since` (RFC 7232 §6); a satisfiable `Range`
/// yields a 206, an out-of-bounds one a 416, and an unparseable/multi range is
/// ignored (falls back to a full 200) per RFC 7233 §4.
pub(crate) fn evaluate_conditional_request(
    req_headers: &http::HeaderMap,
    etag: &str,
    last_modified_unix: i64,
    total_len: usize,
) -> ConditionalOutcome {
    if let Some(if_none_match) = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        if if_none_match_matches(if_none_match, etag) {
            return ConditionalOutcome::NotModified;
        }
    } else if let Some(if_modified_since) = req_headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    {
        if let Some(since_unix) = parse_http_date(if_modified_since) {
            if last_modified_unix > 0 && last_modified_unix <= since_unix {
                return ConditionalOutcome::NotModified;
            }
        }
    }
    if let Some(range) = req_headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
    {
        return parse_single_byte_range(range, total_len);
    }
    ConditionalOutcome::Full
}

/// `true` when an `If-None-Match` header (a comma-separated list, `*`, or a
/// weak/strong tag) matches `etag`. Weak comparison is used (the `W/` prefix is
/// ignored), which is what conditional GETs on immutable content want.
fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    let normalized_etag = etag.trim_start_matches("W/");
    if_none_match.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate.trim_start_matches("W/") == normalized_etag
    })
}

fn parse_single_byte_range(header_value: &str, total_len: usize) -> ConditionalOutcome {
    let Some(spec) = header_value.trim().strip_prefix("bytes=") else {
        return ConditionalOutcome::Full;
    };
    // Only single-range requests are supported; a multi-range request degrades
    // to a full response rather than a `multipart/byteranges` body.
    if spec.contains(',') {
        return ConditionalOutcome::Full;
    }
    let Some((start_spec, end_spec)) = spec.split_once('-') else {
        return ConditionalOutcome::Full;
    };
    let start_spec = start_spec.trim();
    let end_spec = end_spec.trim();
    if total_len == 0 {
        return ConditionalOutcome::RangeNotSatisfiable;
    }
    let last = total_len - 1;
    let (start, end) = if start_spec.is_empty() {
        // Suffix range: the final N bytes (`bytes=-N`).
        let Ok(suffix) = end_spec.parse::<usize>() else {
            return ConditionalOutcome::Full;
        };
        if suffix == 0 {
            return ConditionalOutcome::RangeNotSatisfiable;
        }
        let suffix = suffix.min(total_len);
        (total_len - suffix, last)
    } else {
        let Ok(start) = start_spec.parse::<usize>() else {
            return ConditionalOutcome::Full;
        };
        let end = if end_spec.is_empty() {
            last
        } else {
            match end_spec.parse::<usize>() {
                Ok(end) => end.min(last),
                Err(_) => return ConditionalOutcome::Full,
            }
        };
        (start, end)
    };
    if start > last || start > end {
        return ConditionalOutcome::RangeNotSatisfiable;
    }
    ConditionalOutcome::Range { start, end }
}

/// Formats a Unix timestamp as an RFC 7231 IMF-fixdate (`Last-Modified`).
fn format_http_date(unix_secs: i64) -> Option<String> {
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0)?;
    Some(datetime.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// Parses an IMF-fixdate `If-Modified-Since` header back to a Unix timestamp.
fn parse_http_date(value: &str) -> Option<i64> {
    let naive =
        chrono::NaiveDateTime::parse_from_str(value.trim(), "%a, %d %b %Y %H:%M:%S GMT").ok()?;
    Some(naive.and_utc().timestamp())
}

fn apply_asset_validators(
    response: &mut ResponseHeader,
    cache: &AssetCacheHeaders<'_>,
) -> PingoraResult<()> {
    response.insert_header(header::ETAG, cache.etag.as_str())?;
    response.insert_header(header::CACHE_CONTROL, cache.cache_control)?;
    if let Some(last_modified) = format_http_date(cache.last_modified_unix) {
        response.insert_header(header::LAST_MODIFIED, last_modified)?;
    }
    response.insert_header("accept-ranges", "bytes")?;
    Ok(())
}

fn apply_common_headers(response: &mut ResponseHeader, request_id: &str) -> PingoraResult<()> {
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(response)
}

/// Attaches caller-supplied response headers (issue #301) — the asset pull
/// path's `x-ferrogate-asset-*` resolution metadata and yank `warning` — to a
/// cacheable response arm.
fn apply_extra_headers(
    response: &mut ResponseHeader,
    extra_headers: &[(&'static str, String)],
) -> PingoraResult<()> {
    for (name, value) in extra_headers {
        response.insert_header(*name, value)?;
    }
    Ok(())
}

/// Serves `body` with HTTP caching semantics (issue #258): strong `ETag`,
/// `Last-Modified`, `Cache-Control`, `Accept-Ranges`, `304 Not Modified` for a
/// matching conditional GET, and `206 Partial Content` / `416` for a `Range`
/// request. `HEAD` gets the full header set with no body. Shared by the
/// authenticated `/v1/assets/*` pull path and the `/sites/*` serve mode.
///
/// `extra_headers` are caller-supplied response headers attached to every arm
/// (issue #301): the pull path uses them to carry its registry-resolution
/// metadata (`x-ferrogate-asset-*`) and the yank `warning` header alongside the
/// conditional-caching behaviour, so a re-pull still short-circuits to `304`
/// without dropping the resolution headers.
pub(crate) async fn write_cacheable_response(
    session: &mut Session,
    req_headers: &http::HeaderMap,
    method: &http::Method,
    body: Bytes,
    cache: &AssetCacheHeaders<'_>,
    request_id: &str,
    extra_headers: &[(&'static str, String)],
) -> PingoraResult<StatusCode> {
    let total_len = body.len();
    let is_head = *method == http::Method::HEAD;
    let outcome = evaluate_conditional_request(
        req_headers,
        &cache.etag,
        cache.last_modified_unix,
        total_len,
    );
    match outcome {
        ConditionalOutcome::NotModified => {
            let mut response = ResponseHeader::build(StatusCode::NOT_MODIFIED, Some(8))?;
            apply_asset_validators(&mut response, cache)?;
            apply_common_headers(&mut response, request_id)?;
            apply_extra_headers(&mut response, extra_headers)?;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            session.write_response_body(None, true).await?;
            Ok(StatusCode::NOT_MODIFIED)
        }
        ConditionalOutcome::RangeNotSatisfiable => {
            let mut response = ResponseHeader::build(StatusCode::RANGE_NOT_SATISFIABLE, Some(8))?;
            response.insert_header(header::CONTENT_TYPE, cache.content_type)?;
            response.insert_header(header::CONTENT_RANGE, format!("bytes */{total_len}"))?;
            apply_asset_validators(&mut response, cache)?;
            apply_common_headers(&mut response, request_id)?;
            apply_extra_headers(&mut response, extra_headers)?;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            session.write_response_body(None, true).await?;
            Ok(StatusCode::RANGE_NOT_SATISFIABLE)
        }
        ConditionalOutcome::Range { start, end } => {
            let len = end - start + 1;
            let mut response = ResponseHeader::build(StatusCode::PARTIAL_CONTENT, Some(9))?;
            response.insert_header(header::CONTENT_TYPE, cache.content_type)?;
            response.insert_header(header::CONTENT_LENGTH, len.to_string())?;
            response.insert_header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total_len}"),
            )?;
            apply_asset_validators(&mut response, cache)?;
            apply_common_headers(&mut response, request_id)?;
            apply_extra_headers(&mut response, extra_headers)?;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            let out_body = if is_head {
                None
            } else {
                Some(body.slice(start..end + 1))
            };
            session.write_response_body(out_body, true).await?;
            Ok(StatusCode::PARTIAL_CONTENT)
        }
        ConditionalOutcome::Full => {
            let mut response = ResponseHeader::build(StatusCode::OK, Some(8))?;
            response.insert_header(header::CONTENT_TYPE, cache.content_type)?;
            response.insert_header(header::CONTENT_LENGTH, total_len.to_string())?;
            apply_asset_validators(&mut response, cache)?;
            apply_common_headers(&mut response, request_id)?;
            apply_extra_headers(&mut response, extra_headers)?;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            let out_body = if is_head { None } else { Some(body) };
            session.write_response_body(out_body, true).await?;
            Ok(StatusCode::OK)
        }
    }
}

/// Async source of provider streaming-body chunks (issue #311). Replaces the
/// old blocking sync-`Read` shim: implementors surface the upstream
/// bytes natively on the async runtime, so no blocking-pool thread is parked
/// per active stream.
pub(crate) trait StreamingBodySource: Send {
    fn next_chunk(&mut self) -> impl Future<Output = std::io::Result<Option<Bytes>>> + Send + '_;
}

#[derive(Default)]
struct StreamingFeedState {
    chunks: VecDeque<Bytes>,
    finished: bool,
}

/// Sender half of the chunkwise feed between the async pump and the
/// synchronous `Read`-based transform tower (SSE normalizers, capture
/// readers). Holds only the chunks pushed since the transform last drained
/// it -- never the whole stream.
pub(crate) struct StreamingBodyUpstream<S> {
    source: S,
    feed: Arc<Mutex<StreamingFeedState>>,
}

impl<S: StreamingBodySource> StreamingBodyUpstream<S> {
    /// Pulls the next upstream chunk into the feed. Returns `Ok(false)` once
    /// the upstream body is exhausted (the feed then reports EOF to the
    /// transform tower).
    pub(crate) async fn advance(&mut self) -> std::io::Result<bool> {
        match self.source.next_chunk().await? {
            Some(chunk) => {
                if let Ok(mut state) = self.feed.lock() {
                    if !chunk.is_empty() {
                        state.chunks.push_back(chunk);
                    }
                }
                Ok(true)
            }
            None => {
                if let Ok(mut state) = self.feed.lock() {
                    state.finished = true;
                }
                Ok(false)
            }
        }
    }
}

/// Reader half of the chunkwise feed: the innermost `Read` of the transform
/// tower. Reports `ErrorKind::WouldBlock` when no chunk has been fed yet
/// (the pump's cue to await the next upstream chunk) and `Ok(0)` only at
/// true upstream EOF -- so the incremental SSE parsers above it observe the
/// exact byte sequence and EOF the old blocking reader produced.
pub(crate) struct StreamingBodyFeedReader {
    feed: Arc<Mutex<StreamingFeedState>>,
}

impl Read for StreamingBodyFeedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Ok(mut state) = self.feed.lock() else {
            return Err(std::io::Error::other("streaming body feed lock poisoned"));
        };
        let Some(front) = state.chunks.front_mut() else {
            return if state.finished {
                Ok(0)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            };
        };
        let read = front.len().min(buffer.len());
        buffer[..read].copy_from_slice(&front[..read]);
        if read < front.len() {
            let _ = front.split_to(read);
        } else {
            state.chunks.pop_front();
        }
        Ok(read)
    }
}

/// Builds the chunkwise feed pair for one provider stream: the async
/// upstream half that pulls from `source`, and the `Read` half the SSE
/// transform tower wraps.
pub(crate) fn streaming_body_channel<S: StreamingBodySource>(
    source: S,
) -> (StreamingBodyUpstream<S>, StreamingBodyFeedReader) {
    let feed = Arc::new(Mutex::new(StreamingFeedState::default()));
    (
        StreamingBodyUpstream {
            source,
            feed: Arc::clone(&feed),
        },
        StreamingBodyFeedReader { feed },
    )
}

/// Streams a provider response to the client fully on the async runtime
/// (issue #311): chunks are pulled from `upstream`, run through the
/// `Read`-based `transform` tower chunk-by-chunk via the in-memory feed, and
/// written to the session as soon as the transform releases bytes. A failed
/// downstream write (client disconnect) propagates immediately: this
/// function returns, dropping `upstream` and with it the provider
/// connection.
pub(crate) async fn write_streaming_response<S, R>(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    initial_body: Vec<u8>,
    mut upstream: StreamingBodyUpstream<S>,
    mut transform: R,
    request_id: &str,
) -> PingoraResult<()>
where
    S: StreamingBodySource,
    R: Read + Send,
{
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, content_type)?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;

    if !initial_body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(initial_body)), false)
            .await?;
    }

    let mut buffer = [0_u8; 8192];
    let mut upstream_done = false;
    'stream: loop {
        // Drain everything the transform can produce from the chunks fed so
        // far; `WouldBlock` is the feed's "need more upstream data" signal,
        // never a failure.
        loop {
            match transform.read(&mut buffer) {
                Ok(0) => break 'stream,
                Ok(read) => {
                    session
                        .write_response_body(Some(Bytes::copy_from_slice(&buffer[..read])), false)
                        .await?
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    return Err(error)
                        .or_err(ErrorType::ReadError, "reading provider streaming response")
                }
            }
        }
        if upstream_done {
            // Defensive: the transform asked for more input after upstream
            // EOF was fed; nothing further can arrive, so end the stream.
            break;
        }
        upstream_done = !upstream
            .advance()
            .await
            .or_err(ErrorType::ReadError, "reading provider streaming response")?;
    }
    session.write_response_body(None, true).await
}

pub(crate) async fn write_streaming_bytes_response(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, content_type)?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    if !body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(body)), false)
            .await?;
    }
    session.write_response_body(None, true).await
}

pub(crate) async fn write_json_error(
    session: &mut Session,
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code: code.into(),
            request_id: Some(request_id.to_string()),
        },
    };
    write_json_response(session, status, &body, request_id).await
}

pub(crate) async fn write_json_error_and_close(
    session: &mut Session,
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code: code.into(),
            request_id: Some(request_id.to_string()),
        },
    };
    let body = serde_json::to_vec(&body).expect("JSON serialization should not fail");
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, "application/json")?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header(header::CONNECTION, "close")?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    apply_cors_headers(&mut response)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use http::HeaderMap;

    const ETAG: &str = "\"abc123\"";

    fn headers(pairs: &[(http::HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(name.clone(), value.parse().unwrap());
        }
        map
    }

    #[test]
    fn no_conditional_headers_serves_full_body() {
        let outcome = evaluate_conditional_request(&HeaderMap::new(), ETAG, 1000, 100);
        assert_eq!(outcome, ConditionalOutcome::Full);
    }

    #[test]
    fn matching_if_none_match_is_not_modified() {
        let map = headers(&[(header::IF_NONE_MATCH, ETAG)]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 100),
            ConditionalOutcome::NotModified
        );
    }

    #[test]
    fn wildcard_and_list_if_none_match_match() {
        let star = headers(&[(header::IF_NONE_MATCH, "*")]);
        assert_eq!(
            evaluate_conditional_request(&star, ETAG, 1000, 100),
            ConditionalOutcome::NotModified
        );
        let list = headers(&[(header::IF_NONE_MATCH, "\"other\", \"abc123\"")]);
        assert_eq!(
            evaluate_conditional_request(&list, ETAG, 1000, 100),
            ConditionalOutcome::NotModified
        );
    }

    #[test]
    fn non_matching_if_none_match_serves_full() {
        let map = headers(&[(header::IF_NONE_MATCH, "\"different\"")]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 100),
            ConditionalOutcome::Full
        );
    }

    #[test]
    fn if_modified_since_not_modified_and_modified() {
        // Stored at epoch 1000; a client copy dated after that -> 304.
        let after = format_http_date(2000).unwrap();
        let map = headers(&[(header::IF_MODIFIED_SINCE, after.as_str())]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 100),
            ConditionalOutcome::NotModified
        );
        // A client copy dated before the stored mtime -> full body.
        let before = format_http_date(500).unwrap();
        let map = headers(&[(header::IF_MODIFIED_SINCE, before.as_str())]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 100),
            ConditionalOutcome::Full
        );
    }

    #[test]
    fn if_none_match_wins_over_if_modified_since() {
        // Even with a stale If-Modified-Since, a non-matching ETag serves full.
        let map = headers(&[
            (header::IF_NONE_MATCH, "\"different\""),
            (
                header::IF_MODIFIED_SINCE,
                format_http_date(9999).unwrap().as_str(),
            ),
        ]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 100),
            ConditionalOutcome::Full
        );
    }

    #[test]
    fn byte_range_is_parsed() {
        let map = headers(&[(header::RANGE, "bytes=0-99")]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 500),
            ConditionalOutcome::Range { start: 0, end: 99 }
        );
    }

    #[test]
    fn open_ended_and_suffix_ranges_clamp_to_body() {
        let open = headers(&[(header::RANGE, "bytes=100-")]);
        assert_eq!(
            evaluate_conditional_request(&open, ETAG, 1000, 500),
            ConditionalOutcome::Range {
                start: 100,
                end: 499
            }
        );
        let suffix = headers(&[(header::RANGE, "bytes=-100")]);
        assert_eq!(
            evaluate_conditional_request(&suffix, ETAG, 1000, 500),
            ConditionalOutcome::Range {
                start: 400,
                end: 499
            }
        );
        let over_end = headers(&[(header::RANGE, "bytes=0-9999")]);
        assert_eq!(
            evaluate_conditional_request(&over_end, ETAG, 1000, 500),
            ConditionalOutcome::Range { start: 0, end: 499 }
        );
    }

    #[test]
    fn out_of_bounds_range_is_not_satisfiable() {
        let map = headers(&[(header::RANGE, "bytes=600-700")]);
        assert_eq!(
            evaluate_conditional_request(&map, ETAG, 1000, 500),
            ConditionalOutcome::RangeNotSatisfiable
        );
    }

    #[test]
    fn unparseable_or_multi_range_falls_back_to_full() {
        let bad_unit = headers(&[(header::RANGE, "items=0-1")]);
        assert_eq!(
            evaluate_conditional_request(&bad_unit, ETAG, 1000, 500),
            ConditionalOutcome::Full
        );
        let multi = headers(&[(header::RANGE, "bytes=0-1,2-3")]);
        assert_eq!(
            evaluate_conditional_request(&multi, ETAG, 1000, 500),
            ConditionalOutcome::Full
        );
    }

    #[test]
    fn http_date_round_trips() {
        let formatted = format_http_date(1_700_000_000).unwrap();
        assert_eq!(parse_http_date(&formatted), Some(1_700_000_000));
    }
}
