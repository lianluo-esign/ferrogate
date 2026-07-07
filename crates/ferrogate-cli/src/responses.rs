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
use std::{collections::BTreeMap, io::Read, sync::OnceLock};
use tokio::{sync::mpsc, task};

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
    pub(crate) persistence: AdminManagedWorkerPersistence,
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
    pub(crate) team_id: Option<String>,
    pub(crate) project_id: Option<String>,
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
    #[serde(default)]
    pub(crate) team_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
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
    pub(crate) extension_tools_enabled: bool,
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
    pub(crate) extension_tools_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPlanMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) plan: AdminPlan,
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
    /// Percent-of-`monthly_budget_usd` tiers (e.g. `[50, 90]`) that fire a
    /// one-time proactive alert webhook when spend first crosses them
    /// (issue #170) -- distinct from the unconditional 100% hard-deny in
    /// `AppState::monthly_budget_exceeded`.
    pub(crate) alert_threshold_pcts: Vec<u8>,
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
    pub(crate) alert_threshold_pcts: Option<Vec<u8>>,
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
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssetMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) asset: AssetSummary,
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

pub(crate) async fn write_streaming_response<R: Read + Send + 'static>(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    initial_body: Vec<u8>,
    reader: R,
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

    if !initial_body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(initial_body)), false)
            .await?;
    }

    let (sender, mut receiver) = mpsc::channel::<std::io::Result<Bytes>>(8);
    let read_task = task::spawn_blocking(move || {
        read_streaming_body_chunks(reader, sender);
    });

    while let Some(chunk) = receiver.recv().await {
        let chunk = chunk.or_err(ErrorType::ReadError, "reading provider streaming response")?;
        session.write_response_body(Some(chunk), false).await?;
    }

    read_task
        .await
        .or_err(ErrorType::ReadError, "joining provider streaming reader")?;
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

fn read_streaming_body_chunks<R: Read>(
    mut reader: R,
    sender: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => {
                if sender
                    .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(error));
                return;
            }
        }
    }
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
