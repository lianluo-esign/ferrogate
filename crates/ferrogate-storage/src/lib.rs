// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Repository boundaries for FerroGate control-plane storage.
//!
//! High-write request logs, traces, usage metrics, and metering analytics belong
//! to the analytics delivery boundary. This crate keeps small in-memory
//! append-only views only for local Admin API compatibility and tests.

use std::{
    collections::{HashMap, VecDeque},
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::{TenantContext, WorkspaceScope};
use mysql::prelude::Queryable;
use mysql::{
    params, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, PooledConn, SslOpts, TxOpts,
};
use native_tls::{Certificate as NativeTlsCertificate, TlsConnector};
use postgres::config::SslMode as PostgresSslMode;
use postgres::row::Row as PostgresRow;
use postgres::Transaction as PostgresTransaction;
use postgres::{Client as PostgresClient, NoTls};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DURABLE_PROVIDER_ORDER: &[StorageProviderKind] = &[
    StorageProviderKind::Supabase,
    StorageProviderKind::Postgres,
    StorageProviderKind::Mysql,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProviderKind {
    #[default]
    Memory,
    Supabase,
    TursoLibsql,
    Postgres,
    Mysql,
}

impl StorageProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageProviderKind::Memory => "memory",
            StorageProviderKind::Supabase => "supabase",
            StorageProviderKind::TursoLibsql => "turso_libsql",
            StorageProviderKind::Postgres => "postgres",
            StorageProviderKind::Mysql => "mysql",
        }
    }

    pub fn is_durable(self) -> bool {
        !matches!(self, StorageProviderKind::Memory)
    }

    pub fn implemented(self) -> bool {
        matches!(
            self,
            StorageProviderKind::Memory
                | StorageProviderKind::Supabase
                | StorageProviderKind::Postgres
                | StorageProviderKind::Mysql
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageProviderConfig {
    pub kind: StorageProviderKind,
    pub required: bool,
}

impl StorageProviderConfig {
    pub fn memory() -> Self {
        Self {
            kind: StorageProviderKind::Memory,
            required: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresTlsMode {
    #[default]
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl PostgresTlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PostgresTlsMode::Disable => "disable",
            PostgresTlsMode::Prefer => "prefer",
            PostgresTlsMode::Require => "require",
            PostgresTlsMode::VerifyCa => "verify_ca",
            PostgresTlsMode::VerifyFull => "verify_full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresStorageConfig {
    pub dsn: String,
    pub pool_size: usize,
    pub tls_mode: PostgresTlsMode,
    pub tls_ca_cert_path: Option<String>,
    pub connect_timeout_secs: u64,
    pub statement_timeout_millis: u64,
    pub schema: Option<String>,
    pub search_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlStorageConfig {
    pub dsn: String,
    pub pool_size: usize,
    pub tls_mode: MySqlTlsMode,
    pub tls_ca_cert_path: Option<String>,
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneDocuments {
    pub api_keys: Vec<(String, String)>,
    pub tenants: Vec<(String, String)>,
    pub policies: Vec<(String, String)>,
    pub gateway_configs: Vec<(String, String)>,
    pub agent_workflows: Vec<(String, String)>,
    pub skill_packages: Vec<(String, String)>,
    pub prompt_templates: Vec<(String, String)>,
    pub plugin_registrations: Vec<(String, String)>,
    pub mcp_servers: Vec<(String, String)>,
    pub agent_upstreams: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageMigrationSnapshot {
    pub control_plane: ControlPlaneDocuments,
    pub api_key_records: Vec<StoredApiKey>,
    pub tool_approvals: Vec<(String, String)>,
    pub billing_events: Vec<BillingEvent>,
    pub usage_aggregates: Vec<StoredUsageAggregate>,
    pub request_logs: Vec<StoredRequestLog>,
    pub audit_events: Vec<StoredAuditEvent>,
    pub agent_runs: Vec<StoredAgentRun>,
    pub agent_run_events: Vec<StoredAgentRunEvent>,
    pub managed_worker_templates: Vec<StoredManagedWorkerTemplate>,
    pub agent_worker_instances: Vec<StoredAgentWorkerInstance>,
    pub managed_worker_sessions: Vec<StoredManagedWorkerSession>,
    pub managed_worker_lifecycle_events: Vec<StoredManagedWorkerLifecycleEvent>,
    pub managed_worker_isolation_selections: Vec<StoredManagedWorkerIsolationSelection>,
    pub managed_worker_isolation_policies: Vec<StoredManagedWorkerIsolationPolicy>,
    pub managed_worker_isolation_evidence: Vec<StoredManagedWorkerIsolationEvidence>,
    pub self_hosted_worker_registrations: Vec<StoredSelfHostedWorkerRegistration>,
    pub self_hosted_worker_heartbeats: Vec<StoredSelfHostedWorkerHeartbeat>,
    pub self_hosted_worker_telemetry_events: Vec<StoredSelfHostedWorkerTelemetryEvent>,
    pub self_hosted_worker_artifacts: Vec<StoredSelfHostedWorkerArtifact>,
    pub self_hosted_worker_checkpoints: Vec<StoredSelfHostedWorkerCheckpoint>,
    pub self_hosted_run_dispatches: Vec<StoredSelfHostedRunDispatch>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMigrationCounts {
    pub api_keys: usize,
    pub api_key_records: usize,
    pub tenants: usize,
    pub policies: usize,
    pub gateway_configs: usize,
    pub agent_workflows: usize,
    pub skill_packages: usize,
    pub prompt_templates: usize,
    pub plugin_registrations: usize,
    pub mcp_servers: usize,
    pub agent_upstreams: usize,
    pub tool_approvals: usize,
    pub billing_events: usize,
    pub usage_aggregates: usize,
    pub request_logs: usize,
    pub audit_events: usize,
    pub agent_runs: usize,
    pub agent_run_events: usize,
    pub managed_worker_templates: usize,
    pub agent_worker_instances: usize,
    pub managed_worker_sessions: usize,
    pub managed_worker_lifecycle_events: usize,
    pub managed_worker_isolation_selections: usize,
    pub managed_worker_isolation_policies: usize,
    pub managed_worker_isolation_evidence: usize,
    pub self_hosted_worker_registrations: usize,
    pub self_hosted_worker_heartbeats: usize,
    pub self_hosted_worker_telemetry_events: usize,
    pub self_hosted_worker_artifacts: usize,
    pub self_hosted_worker_checkpoints: usize,
    pub self_hosted_run_dispatches: usize,
}

impl StorageMigrationSnapshot {
    pub fn counts(&self) -> StorageMigrationCounts {
        StorageMigrationCounts {
            api_keys: self.control_plane.api_keys.len(),
            api_key_records: self.api_key_records.len(),
            tenants: self.control_plane.tenants.len(),
            policies: self.control_plane.policies.len(),
            gateway_configs: self.control_plane.gateway_configs.len(),
            agent_workflows: self.control_plane.agent_workflows.len(),
            skill_packages: self.control_plane.skill_packages.len(),
            prompt_templates: self.control_plane.prompt_templates.len(),
            plugin_registrations: self.control_plane.plugin_registrations.len(),
            mcp_servers: self.control_plane.mcp_servers.len(),
            agent_upstreams: self.control_plane.agent_upstreams.len(),
            tool_approvals: self.tool_approvals.len(),
            billing_events: self.billing_events.len(),
            usage_aggregates: self.usage_aggregates.len(),
            request_logs: self.request_logs.len(),
            audit_events: self.audit_events.len(),
            agent_runs: self.agent_runs.len(),
            agent_run_events: self.agent_run_events.len(),
            managed_worker_templates: self.managed_worker_templates.len(),
            agent_worker_instances: self.agent_worker_instances.len(),
            managed_worker_sessions: self.managed_worker_sessions.len(),
            managed_worker_lifecycle_events: self.managed_worker_lifecycle_events.len(),
            managed_worker_isolation_selections: self.managed_worker_isolation_selections.len(),
            managed_worker_isolation_policies: self.managed_worker_isolation_policies.len(),
            managed_worker_isolation_evidence: self.managed_worker_isolation_evidence.len(),
            self_hosted_worker_registrations: self.self_hosted_worker_registrations.len(),
            self_hosted_worker_heartbeats: self.self_hosted_worker_heartbeats.len(),
            self_hosted_worker_telemetry_events: self.self_hosted_worker_telemetry_events.len(),
            self_hosted_worker_artifacts: self.self_hosted_worker_artifacts.len(),
            self_hosted_worker_checkpoints: self.self_hosted_worker_checkpoints.len(),
            self_hosted_run_dispatches: self.self_hosted_run_dispatches.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStorageOptions {
    pub provider_order: Vec<StorageProviderKind>,
    pub required: bool,
    pub initialize_schema: bool,
    pub migration_mode: String,
    pub control_plane: ControlPlaneDocuments,
    pub request_log_retention_records: usize,
    pub audit_event_retention_records: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MySqlTlsMode {
    #[default]
    Disable,
    Require,
    VerifyCa,
    VerifyFull,
}

impl MySqlTlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MySqlTlsMode::Disable => "disable",
            MySqlTlsMode::Require => "require",
            MySqlTlsMode::VerifyCa => "verify_ca",
            MySqlTlsMode::VerifyFull => "verify_full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackendEvidence {
    pub provider: StorageProviderKind,
    pub durable: bool,
    pub implemented: bool,
    pub required: bool,
    pub migration_mode: String,
    pub health: String,
    pub provider_order: Vec<StorageProviderKind>,
    pub contract_version: u32,
    pub schema: Option<StorageSchemaEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSchemaEvidence {
    pub engine: String,
    pub version: u64,
    pub name: String,
    pub checksum: String,
    pub validated: bool,
}

impl StorageSchemaEvidence {
    fn postgres_expected() -> Self {
        Self {
            engine: "postgres".into(),
            version: POSTGRES_SCHEMA_VERSION,
            name: POSTGRES_SCHEMA_NAME.into(),
            checksum: fnv1a64_hex(POSTGRES_SCHEMA_SQL),
            validated: true,
        }
    }
}

const POSTGRES_SCHEMA_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");
const POSTGRES_SCHEMA_VERSION: u64 = 10;
const POSTGRES_SCHEMA_NAME: &str = "010_virtual_api_keys";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStorageBackend {
    provider: StorageProviderKind,
    required: bool,
    migration_mode: String,
    health: String,
    provider_order: Vec<StorageProviderKind>,
    contract_version: u32,
}

impl RuntimeStorageBackend {
    pub fn new(
        provider: StorageProviderKind,
        required: bool,
        provider_order: Vec<StorageProviderKind>,
    ) -> Result<Self, StorageError> {
        Self::new_with_migration_mode(provider, required, provider_order, "disabled".into())
    }

    pub fn new_with_migration_mode(
        provider: StorageProviderKind,
        required: bool,
        provider_order: Vec<StorageProviderKind>,
        migration_mode: String,
    ) -> Result<Self, StorageError> {
        if !provider.implemented() {
            return Err(StorageError::UnsupportedProvider { provider, required });
        }
        Ok(Self {
            provider,
            required,
            migration_mode,
            health: "ok".into(),
            provider_order,
            contract_version: 1,
        })
    }

    pub fn in_memory(provider_order: Vec<StorageProviderKind>) -> Self {
        Self {
            provider: StorageProviderKind::Memory,
            required: false,
            migration_mode: "disabled".into(),
            health: "ok".into(),
            provider_order,
            contract_version: 1,
        }
    }

    pub fn evidence(&self) -> StorageBackendEvidence {
        StorageBackendEvidence {
            provider: self.provider,
            durable: self.provider.is_durable(),
            implemented: self.provider.implemented(),
            required: self.required,
            migration_mode: self.migration_mode.clone(),
            health: self.health.clone(),
            provider_order: self.provider_order.clone(),
            contract_version: self.contract_version,
            schema: None,
        }
    }

    pub fn provider(&self) -> StorageProviderKind {
        self.provider
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    UnsupportedProvider {
        provider: StorageProviderKind,
        required: bool,
    },
    Postgres(String),
    Mysql(String),
    Runtime(String),
    Serialization(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::UnsupportedProvider { provider, required } => {
                write!(
                    formatter,
                    "storage provider {} is not implemented yet (required={required})",
                    provider.as_str()
                )
            }
            StorageError::Postgres(error) => write!(formatter, "postgres storage error: {error}"),
            StorageError::Mysql(error) => write!(formatter, "mysql storage error: {error}"),
            StorageError::Runtime(error) => write!(formatter, "storage runtime error: {error}"),
            StorageError::Serialization(error) => {
                write!(formatter, "storage serialization error: {error}")
            }
        }
    }
}

impl std::error::Error for StorageError {}

pub trait Repository<T> {
    fn get(&self, id: &str) -> Option<T>;
    fn list(&self) -> Vec<T>;
}

pub trait ApiKeyRepository: Repository<StoredApiKey> {}

pub trait TenantRepository: Repository<StoredTenant> {}

pub trait PolicyRepository: Repository<StoredPolicyRule> {}

pub trait RequestLogRepository: AppendRepository<StoredRequestLog> {}

pub trait AuditLogRepository: AppendRepository<StoredAuditEvent> {}

pub trait BillingEventRepository: AppendRepository<BillingEvent> {}

pub trait UsageAggregateRepository: Repository<StoredUsageAggregate> {}

pub trait AgentRunRepository: Repository<StoredAgentRun> {}

pub trait AgentRunEventRepository: AppendRepository<StoredAgentRunEvent> {}

pub trait ManagedWorkerTemplateRepository: Repository<StoredManagedWorkerTemplate> {}

pub trait AgentWorkerInstanceRepository: Repository<StoredAgentWorkerInstance> {}

pub trait ManagedWorkerSessionRepository: Repository<StoredManagedWorkerSession> {}

pub trait ManagedWorkerLifecycleEventRepository:
    AppendRepository<StoredManagedWorkerLifecycleEvent>
{
}

pub trait SelfHostedWorkerRegistrationRepository:
    Repository<StoredSelfHostedWorkerRegistration>
{
}

pub trait SelfHostedWorkerHeartbeatRepository:
    AppendRepository<StoredSelfHostedWorkerHeartbeat>
{
}

pub trait SelfHostedWorkerTelemetryEventRepository:
    AppendRepository<StoredSelfHostedWorkerTelemetryEvent>
{
}

pub trait SelfHostedWorkerArtifactRepository: Repository<StoredSelfHostedWorkerArtifact> {}

pub trait SelfHostedWorkerCheckpointRepository:
    Repository<StoredSelfHostedWorkerCheckpoint>
{
}

pub trait SelfHostedRunDispatchRepository: Repository<StoredSelfHostedRunDispatch> {}

pub trait AppendRepository<T> {
    fn append(&mut self, record: T);
    fn list(&self) -> Vec<T>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredControlPlaneResource {
    pub kind: String,
    pub id: String,
    pub document_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneSnapshot {
    pub api_keys: Vec<String>,
    pub tenants: Vec<String>,
    pub policies: Vec<String>,
    pub gateway_configs: Vec<String>,
    pub agent_workflows: Vec<String>,
    pub skill_packages: Vec<String>,
    pub prompt_templates: Vec<String>,
    pub plugin_registrations: Vec<String>,
    pub mcp_servers: Vec<String>,
    pub agent_upstreams: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentRun {
    pub id: String,
    pub request_id: String,
    pub trace_id: Option<String>,
    pub tenant: TenantContext,
    pub status: String,
    pub provider: String,
    pub turns_executed: u32,
    pub output_recorded: bool,
    pub started_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentRunEvent {
    pub id: String,
    pub run_id: String,
    pub request_id: String,
    pub trace_id: Option<String>,
    pub tenant: TenantContext,
    pub turn: u32,
    pub kind: String,
    pub target: String,
    pub outcome: String,
    pub tool_call_id: Option<String>,
    pub message: Option<String>,
    pub occurred_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerTemplate {
    pub id: String,
    pub framework_adapter: String,
    pub isolation_backend_kind: String,
    pub enabled: bool,
    pub max_tenant_sessions: Option<u32>,
    pub max_workspace_sessions: Option<u32>,
    pub created_at_unix: Option<u64>,
    pub updated_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentWorkerInstance {
    pub id: String,
    pub process_name: String,
    pub host_id: Option<String>,
    pub worker_version: Option<String>,
    pub status: String,
    pub started_at_unix: Option<u64>,
    pub last_seen_at_unix: Option<u64>,
    pub process_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerSession {
    pub id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub worker_template_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub status: String,
    pub isolation_backend_kind: String,
    pub microvm_id: Option<String>,
    pub capability_envelope_id: String,
    pub requested_at_unix: Option<u64>,
    pub started_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
    pub cleanup_completed_at_unix: Option<u64>,
    pub capability_envelope_json: String,
    pub resource_limits_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerLifecycleEvent {
    pub id: String,
    pub session_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub status: String,
    pub action: String,
    pub outcome: String,
    pub occurred_at_unix: Option<u64>,
    pub evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationSelection {
    pub session_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub backend_name: String,
    pub backend_version: String,
    pub backend_kind: String,
    pub host_lifecycle_owner: String,
    pub gateway_controls_backend: bool,
    pub capability_envelope_id: String,
    pub selected_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationPolicy {
    pub session_id: String,
    pub cpu_count: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub max_runtime_millis: Option<u64>,
    pub direct_public_egress: bool,
    pub gateway_control_channel: bool,
    pub governed_egress: bool,
    pub read_only_rootfs: bool,
    pub writable_workspace: bool,
    pub host_path_mounts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationEvidence {
    pub id: String,
    pub session_id: String,
    pub lifecycle_event_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub isolation_instance_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub occurred_at_unix: Option<u64>,
    pub evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerRegistration {
    pub id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub worker_name: String,
    pub status: String,
    pub identity_fingerprint: String,
    pub identity_expires_at_unix: Option<u64>,
    pub orchestration_enabled: bool,
    pub registered_at_unix: Option<u64>,
    pub last_seen_at_unix: Option<u64>,
    pub trust_level: String,
    pub capability_envelope_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerHeartbeat {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub status: String,
    pub reported_at_unix: Option<u64>,
    pub observed_at_unix: Option<u64>,
    pub heartbeat_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerTelemetryEvent {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub kind: String,
    pub trust_level: String,
    pub occurred_at_unix: Option<u64>,
    pub ingested_at_unix: Option<u64>,
    pub event_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerArtifact {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub artifact_name: String,
    pub content_type: Option<String>,
    pub size_bytes: u64,
    pub trust_level: String,
    pub created_at_unix: Option<u64>,
    pub artifact_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerCheckpoint {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub checkpoint_name: String,
    pub size_bytes: u64,
    pub trust_level: String,
    pub created_at_unix: Option<u64>,
    pub checkpoint_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedRunDispatch {
    pub dispatch_id: String,
    pub action: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub framework_adapter: String,
    pub required_capabilities: Vec<String>,
    pub workload_ref: String,
    pub queued_at_unix: Option<u64>,
    pub assigned_worker_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_expires_at_unix: Option<u64>,
    pub attempt: u32,
    pub acknowledged_status: Option<String>,
    pub acknowledged_at_unix: Option<u64>,
}

#[derive(Debug)]
pub struct RuntimeControlPlaneState {
    api_keys: InMemoryRepository<StoredControlPlaneResource>,
    api_key_records: InMemoryRepository<StoredApiKey>,
    tenants: InMemoryRepository<StoredControlPlaneResource>,
    policies: InMemoryRepository<StoredControlPlaneResource>,
    gateway_configs: InMemoryRepository<StoredControlPlaneResource>,
    agent_workflows: InMemoryRepository<StoredControlPlaneResource>,
    skill_packages: InMemoryRepository<StoredControlPlaneResource>,
    prompt_templates: InMemoryRepository<StoredControlPlaneResource>,
    plugin_registrations: InMemoryRepository<StoredControlPlaneResource>,
    mcp_servers: InMemoryRepository<StoredControlPlaneResource>,
    agent_upstreams: InMemoryRepository<StoredControlPlaneResource>,
    tool_approvals: InMemoryRepository<StoredControlPlaneResource>,
    tenant_accounts: InMemoryRepository<StoredTenantAccount>,
    projects: InMemoryRepository<StoredProject>,
    workspaces: InMemoryRepository<StoredWorkspace>,
}

struct PostgresControlPlaneStore {
    pool: Arc<PostgresClientPool>,
    schema: StorageSchemaEvidence,
}

struct MySqlControlPlaneStore {
    pool: Pool,
}

struct PostgresClientPool {
    clients: Mutex<Vec<PostgresClient>>,
    available: Condvar,
}

impl std::fmt::Debug for PostgresControlPlaneStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresControlPlaneStore")
            .field("client", &"<redacted>")
            .finish()
    }
}

impl PostgresControlPlaneStore {
    fn connect(
        config: PostgresStorageConfig,
        bootstrap: ControlPlaneDocuments,
        initialize_schema: bool,
    ) -> Result<Self, StorageError> {
        let mut clients = Vec::with_capacity(config.pool_size);
        for _ in 0..config.pool_size {
            clients.push(connect_postgres_client(&config)?);
        }
        let store = Self {
            pool: Arc::new(PostgresClientPool {
                clients: Mutex::new(clients),
                available: Condvar::new(),
            }),
            schema: StorageSchemaEvidence::postgres_expected(),
        };
        if initialize_schema {
            store.initialize_schema()?;
        }
        store.validate_schema()?;
        store.seed_missing_resources("api_key", bootstrap.api_keys)?;
        store.seed_missing_resources("tenant", bootstrap.tenants)?;
        store.seed_missing_resources("policy", bootstrap.policies)?;
        store.seed_missing_resources("gateway_config", bootstrap.gateway_configs)?;
        store.seed_missing_resources("agent_workflow", bootstrap.agent_workflows)?;
        store.seed_missing_resources("skill_package", bootstrap.skill_packages)?;
        store.seed_missing_resources("prompt_template", bootstrap.prompt_templates)?;
        store.seed_missing_resources("plugin_registration", bootstrap.plugin_registrations)?;
        store.seed_missing_resources("mcp_server", bootstrap.mcp_servers)?;
        store.seed_missing_resources("agent_upstream", bootstrap.agent_upstreams)?;
        Ok(store)
    }

    fn connect_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        let mut clients = Vec::with_capacity(config.pool_size);
        for _ in 0..config.pool_size {
            clients.push(connect_postgres_client(&config)?);
        }
        let store = Self {
            pool: Arc::new(PostgresClientPool {
                clients: Mutex::new(clients),
                available: Condvar::new(),
            }),
            schema: StorageSchemaEvidence::postgres_expected(),
        };
        if initialize_schema {
            store.initialize_schema()?;
        }
        if validate_schema {
            store.validate_schema()?;
        }
        Ok(store)
    }

    fn initialize_schema(&self) -> Result<(), StorageError> {
        self.with_client(|client| client.batch_execute(POSTGRES_SCHEMA_SQL))?;
        Ok(())
    }

    fn validate_schema(&self) -> Result<(), StorageError> {
        self.with_client_storage(validate_postgres_schema)
    }

    fn schema_evidence(&self) -> StorageSchemaEvidence {
        self.schema.clone()
    }

    fn seed_missing_resources(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        self.with_client(|client| {
            for (id, document_json) in records {
                client.execute(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3::text::jsonb) \
                     ON CONFLICT (resource_kind, resource_id) DO NOTHING",
                    &[&kind, &id, &document_json],
                )?;
            }
            Ok(())
        })
    }

    fn snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        Ok(ControlPlaneSnapshot {
            api_keys: self.list_documents("api_key")?,
            tenants: self.list_documents("tenant")?,
            policies: self.list_documents("policy")?,
            gateway_configs: self.list_documents("gateway_config")?,
            agent_workflows: self.list_documents("agent_workflow")?,
            skill_packages: self.list_documents("skill_package")?,
            prompt_templates: self.list_documents("prompt_template")?,
            plugin_registrations: self.list_documents("plugin_registration")?,
            mcp_servers: self.list_documents("mcp_server")?,
            agent_upstreams: self.list_documents("agent_upstream")?,
        })
    }

    fn documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(ControlPlaneDocuments {
            api_keys: self.list_resource_documents("api_key")?,
            tenants: self.list_resource_documents("tenant")?,
            policies: self.list_resource_documents("policy")?,
            gateway_configs: self.list_resource_documents("gateway_config")?,
            agent_workflows: self.list_resource_documents("agent_workflow")?,
            skill_packages: self.list_resource_documents("skill_package")?,
            prompt_templates: self.list_resource_documents("prompt_template")?,
            plugin_registrations: self.list_resource_documents("plugin_registration")?,
            mcp_servers: self.list_resource_documents("mcp_server")?,
            agent_upstreams: self.list_resource_documents("agent_upstream")?,
        })
    }

    fn list_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT resource_id, document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 ORDER BY resource_id ASC",
                &[&kind],
            )?;
            Ok(rows
                .into_iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                .collect())
        })
    }

    fn list_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 ORDER BY resource_id ASC",
                &[&kind],
            )?;
            Ok(rows
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect())
        })
    }

    fn get_document(&self, kind: &'static str, id: String) -> Result<Option<String>, StorageError> {
        self.with_client(|client| {
            let row = client.query_opt(
                "SELECT document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 AND resource_id = $2",
                &[&kind, &id],
            )?;
            Ok(row.map(|row| row.get::<_, String>(0)))
        })
    }

    fn upsert(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO control_plane_resources \
                 (resource_kind, resource_id, document_json, revision, updated_at_unix) \
                 VALUES ($1, $2, $3::text::jsonb, 1, EXTRACT(EPOCH FROM NOW())::BIGINT) \
                 ON CONFLICT (resource_kind, resource_id) DO UPDATE SET \
                 document_json = EXCLUDED.document_json, \
                 revision = control_plane_resources.revision + 1, \
                 updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
                &[&kind, &id, &document_json],
            )?;
            Ok(())
        })
    }

    fn replace_kind(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        self.with_client(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "DELETE FROM control_plane_resources WHERE resource_kind = $1",
                &[&kind],
            )?;
            for (id, document_json) in records {
                transaction.execute(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3::text::jsonb)",
                    &[&kind, &id, &document_json],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn delete(&self, kind: &'static str, id: String) -> Result<bool, StorageError> {
        self.with_client(|client| {
            let rows_changed = client.execute(
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = $1 AND resource_id = $2",
                &[&kind, &id],
            )?;
            Ok(rows_changed > 0)
        })
    }

    fn upsert_api_key_record(&self, api_key: &StoredApiKey) -> Result<(), StorageError> {
        let scopes_json = serialize_storage_document(&api_key.scopes)?;
        let created_at_unix = saturating_i64(api_key.created_at_unix);
        let updated_at_unix = saturating_i64(api_key.updated_at_unix);
        let rotated_at_unix = api_key.rotated_at_unix.map(saturating_i64);
        let expires_at_unix = api_key.expires_at_unix.map(saturating_i64);
        let revoked_at_unix = api_key.revoked_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO api_keys \
                 (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
                  enabled, scopes_json, created_at_unix, updated_at_unix, rotated_at_unix, \
                  expires_at_unix, revoked_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb, $11, $12, $13, $14, $15) \
                 ON CONFLICT (id) DO UPDATE SET \
                 workspace_id = EXCLUDED.workspace_id, tenant_id = EXCLUDED.tenant_id, \
                 project_id = EXCLUDED.project_id, name = EXCLUDED.name, \
                 key_prefix = EXCLUDED.key_prefix, key_hash = EXCLUDED.key_hash, \
                 last4 = EXCLUDED.last4, enabled = EXCLUDED.enabled, \
                 scopes_json = EXCLUDED.scopes_json, updated_at_unix = EXCLUDED.updated_at_unix, \
                 rotated_at_unix = EXCLUDED.rotated_at_unix, \
                 expires_at_unix = EXCLUDED.expires_at_unix, revoked_at_unix = EXCLUDED.revoked_at_unix",
                &[
                    &api_key.id,
                    &api_key.workspace_id,
                    &api_key.tenant_id,
                    &api_key.project_id,
                    &api_key.name,
                    &api_key.key_prefix,
                    &api_key.key_hash,
                    &api_key.last4,
                    &api_key.enabled,
                    &scopes_json,
                    &created_at_unix,
                    &updated_at_unix,
                    &rotated_at_unix,
                    &expires_at_unix,
                    &revoked_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        let row = self.with_client(|client| {
            client.query_opt(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix \
                 FROM api_keys WHERE id = $1",
                &[&id],
            )
        })?;
        row.as_ref().map(api_key_from_row).transpose()
    }

    fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix \
                 FROM api_keys ORDER BY id ASC",
                &[],
            )
        })?;
        rows.iter().map(api_key_from_row).collect()
    }

    fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix \
                 FROM api_keys WHERE key_prefix = $1 ORDER BY id ASC",
                &[&key_prefix],
            )
        })?;
        rows.iter().map(api_key_from_row).collect()
    }

    fn upsert_tenant_account(&self, account: &StoredTenantAccount) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO tenants (id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (id) DO UPDATE SET \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, status = EXCLUDED.status, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &account.id,
                    &account.name,
                    &account.slug,
                    &account.status,
                    &account.created_at_unix,
                    &account.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn get_tenant_account(&self, id: &str) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.with_client(|client| {
            let row = client.query_opt(
                "SELECT id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM tenants WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(tenant_account_from_row))
        })
    }

    fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM tenants ORDER BY id ASC",
                &[],
            )?;
            Ok(rows.iter().map(tenant_account_from_row).collect())
        })
    }

    fn upsert_project(&self, project: &StoredProject) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO projects \
                 (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 tenant_id = EXCLUDED.tenant_id, name = EXCLUDED.name, slug = EXCLUDED.slug, \
                 status = EXCLUDED.status, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &project.id,
                    &project.tenant_id,
                    &project.name,
                    &project.slug,
                    &project.status,
                    &project.created_at_unix,
                    &project.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.with_client(|client| {
            let row = client.query_opt(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(project_from_row))
        })
    }

    fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects ORDER BY id ASC",
                &[],
            )?;
            Ok(rows.iter().map(project_from_row).collect())
        })
    }

    fn upsert_workspace(&self, workspace: &StoredWorkspace) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO workspaces \
                 (id, project_id, tenant_id, name, slug, environment, status, \
                  created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO UPDATE SET \
                 project_id = EXCLUDED.project_id, tenant_id = EXCLUDED.tenant_id, \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, environment = EXCLUDED.environment, \
                 status = EXCLUDED.status, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &workspace.id,
                    &workspace.project_id,
                    &workspace.tenant_id,
                    &workspace.name,
                    &workspace.slug,
                    &workspace.environment,
                    &workspace.status,
                    &workspace.created_at_unix,
                    &workspace.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.with_client(|client| {
            let row = client.query_opt(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(workspace_from_row))
        })
    }

    fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces ORDER BY id ASC",
                &[],
            )?;
            Ok(rows.iter().map(workspace_from_row).collect())
        })
    }

    fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        self.with_client(|client| {
            let row = client.query_opt(
                "SELECT tenant_id, project_id, id FROM workspaces WHERE id = $1",
                &[&workspace_id],
            )?;
            Ok(row.map(|row| {
                WorkspaceScope::new(
                    row.get::<_, String>(0),
                    row.get::<_, String>(1),
                    row.get::<_, String>(2),
                )
            }))
        })
    }

    fn append_billing_event(&self, event: &BillingEvent) -> Result<bool, StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix = event.occurred_at_unix.unwrap_or_else(now_unix_seconds);
        let workflow_version = event.workflow_version.map(|value| value as i32);
        let prompt_tokens = saturating_i64(event.usage.prompt_tokens);
        let completion_tokens = saturating_i64(event.usage.completion_tokens);
        let total_tokens = saturating_i64(event.usage.total_tokens);
        let status_code = i32::from(event.status_code);
        let usage_source = event.usage_source.as_str();
        self.with_client(|client| {
            let mut transaction = client.transaction()?;
            upsert_tenant_context(&mut transaction, &tenant_context_id, &event.tenant)?;
            let inserted = transaction.execute(
                "INSERT INTO metering_events \
                 (request_id, tenant_context_id, trace_id, agent_run_id, workflow_id, \
                  workflow_version, workflow_node_id, cluster_id, node_id, status_code, \
                  occurred_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (request_id) DO NOTHING",
                &[
                    &event.request_id,
                    &tenant_context_id,
                    &event.trace_id,
                    &event.agent_run_id,
                    &event.workflow_id,
                    &workflow_version,
                    &event.workflow_node_id,
                    &event.cluster_id,
                    &event.node_id,
                    &status_code,
                    &saturating_i64(occurred_at_unix),
                ],
            )?;
            if inserted == 1 {
                transaction.execute(
                    "INSERT INTO metering_event_routes \
                     (request_id, logical_model, provider, provider_model) \
                     VALUES ($1, $2, $3, $4)",
                    &[
                        &event.request_id,
                        &event.logical_model,
                        &event.provider,
                        &event.provider_model,
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO metering_event_usage \
                     (request_id, prompt_tokens, completion_tokens, total_tokens, usage_source) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[
                        &event.request_id,
                        &prompt_tokens,
                        &completion_tokens,
                        &total_tokens,
                        &usage_source,
                    ],
                )?;
                let rollup = UsageRollupUpsert {
                    id: &usage_aggregate_id(&event.tenant, &event.logical_model, &event.provider),
                    tenant_context_id: &tenant_context_id,
                    logical_model: &event.logical_model,
                    provider: &event.provider,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                };
                upsert_usage_rollup_delta(&mut transaction, &rollup)?;
            }
            transaction.commit()?;
            Ok(inserted == 1)
        })
    }

    fn append_request_log(&self, log: &StoredRequestLog) -> Result<(), StorageError> {
        let request_json = serialize_storage_document(log)?;
        let tenant_context_id = tenant_storage_key(&log.tenant);
        let workflow_version = log.workflow_version.map(|value| value.to_string());
        let gateway_config_revision = log.gateway_config_revision.map(|value| value as i64);
        let status_code = i32::from(log.status_code);
        let started_at_unix = saturating_i64(log.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = log.completed_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO request_logs \
                 (request_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                  workflow_node_id, cluster_id, node_id, tenant, route, provider, logical_model, \
                  provider_model, gateway_config_id, gateway_config_revision, status_code, \
                  error_code, cache_status, started_at_unix, completed_at_unix, request_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16, $17, $18, $19, $20, $21::text::jsonb) \
                 ON CONFLICT (request_id) DO UPDATE SET \
                 trace_id = EXCLUDED.trace_id, \
                 agent_run_id = EXCLUDED.agent_run_id, \
                 workflow_id = EXCLUDED.workflow_id, \
                 workflow_version = EXCLUDED.workflow_version, \
                 workflow_node_id = EXCLUDED.workflow_node_id, \
                 cluster_id = EXCLUDED.cluster_id, \
                 node_id = EXCLUDED.node_id, \
                 tenant = EXCLUDED.tenant, \
                 route = EXCLUDED.route, \
                 provider = EXCLUDED.provider, \
                 logical_model = EXCLUDED.logical_model, \
                 provider_model = EXCLUDED.provider_model, \
                 gateway_config_id = EXCLUDED.gateway_config_id, \
                 gateway_config_revision = EXCLUDED.gateway_config_revision, \
                 status_code = EXCLUDED.status_code, \
                 error_code = EXCLUDED.error_code, \
                 cache_status = EXCLUDED.cache_status, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 request_json = EXCLUDED.request_json",
                &[
                    &log.request_id,
                    &log.trace_id,
                    &log.agent_run_id,
                    &log.workflow_id,
                    &workflow_version,
                    &log.workflow_node_id,
                    &log.cluster_id,
                    &log.node_id,
                    &tenant_context_id,
                    &log.route,
                    &log.provider,
                    &log.logical_model,
                    &log.provider_model,
                    &log.gateway_config_id,
                    &gateway_config_revision,
                    &status_code,
                    &log.error_code,
                    &log.cache_status,
                    &started_at_unix,
                    &completed_at_unix,
                    &request_json,
                ],
            )?;
            Ok(())
        })
    }

    fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredRequestLog>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT request_json::text, count(*) OVER() \
                     FROM request_logs \
                     ORDER BY started_at_unix ASC, request_id ASC \
                     OFFSET $1 LIMIT $2",
                    &[&offset, &limit],
                )
                .map_err(postgres_error)?;
            let total = rows
                .first()
                .map(|row| row.get::<_, i64>(1))
                .unwrap_or_default();
            let mut data = Vec::with_capacity(rows.len());
            for row in rows {
                data.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(StoragePage {
                data,
                total: usize::try_from(total).unwrap_or(usize::MAX),
                offset: usize::try_from(offset).unwrap_or(usize::MAX),
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            })
        })
    }

    fn request_logs(&self) -> Result<Vec<StoredRequestLog>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT request_json::text \
                     FROM request_logs \
                     ORDER BY started_at_unix ASC, request_id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let mut logs = Vec::with_capacity(rows.len());
            for row in rows {
                logs.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(logs)
        })
    }

    fn append_audit_event(&self, event: &StoredAuditEvent) -> Result<(), StorageError> {
        let audit_json = serialize_storage_document(event)?;
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let workflow_version = event.workflow_version.map(|value| value.to_string());
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO audit_events \
                 (id, request_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                  workflow_node_id, cluster_id, node_id, actor_api_key_id, tenant, action, target, \
                  outcome, occurred_at_unix, audit_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.request_id,
                    &event.trace_id,
                    &event.agent_run_id,
                    &event.workflow_id,
                    &workflow_version,
                    &event.workflow_node_id,
                    &event.cluster_id,
                    &event.node_id,
                    &event.actor_api_key_id,
                    &tenant_context_id,
                    &event.action,
                    &event.target,
                    &event.outcome,
                    &occurred_at_unix,
                    &audit_json,
                ],
            )?;
            Ok(())
        })
    }

    fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredAuditEvent>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT audit_json::text, count(*) OVER() \
                     FROM audit_events \
                     ORDER BY occurred_at_unix ASC, id ASC \
                     OFFSET $1 LIMIT $2",
                    &[&offset, &limit],
                )
                .map_err(postgres_error)?;
            let total = rows
                .first()
                .map(|row| row.get::<_, i64>(1))
                .unwrap_or_default();
            let mut data = Vec::with_capacity(rows.len());
            for row in rows {
                data.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(StoragePage {
                data,
                total: usize::try_from(total).unwrap_or(usize::MAX),
                offset: usize::try_from(offset).unwrap_or(usize::MAX),
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            })
        })
    }

    fn audit_events(&self) -> Result<Vec<StoredAuditEvent>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT audit_json::text \
                     FROM audit_events \
                     ORDER BY occurred_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                events.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(events)
        })
    }

    fn upsert_agent_run(&self, run: &StoredAgentRun) -> Result<(), StorageError> {
        let run_json = serialize_storage_document(run)?;
        let tenant_context_id = tenant_storage_key(&run.tenant);
        let started_at_unix = saturating_i64(run.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = run.completed_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO agent_runs \
                 (id, request_id, trace_id, tenant, status, provider, started_at_unix, \
                  completed_at_unix, run_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 request_id = EXCLUDED.request_id, \
                 trace_id = EXCLUDED.trace_id, \
                 tenant = EXCLUDED.tenant, \
                 status = EXCLUDED.status, \
                 provider = EXCLUDED.provider, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 run_json = EXCLUDED.run_json",
                &[
                    &run.id,
                    &run.request_id,
                    &run.trace_id,
                    &tenant_context_id,
                    &run.status,
                    &run.provider,
                    &started_at_unix,
                    &completed_at_unix,
                    &run_json,
                ],
            )?;
            Ok(())
        })
    }

    fn agent_run(&self, id: &str) -> Result<Option<StoredAgentRun>, StorageError> {
        self.with_client_storage(|client| {
            let row = client
                .query_opt(
                    "SELECT run_json::text FROM agent_runs WHERE id = $1",
                    &[&id],
                )
                .map_err(postgres_error)?;
            row.map(|row| deserialize_storage_document(row.get::<_, String>(0).as_str()))
                .transpose()
        })
    }

    fn agent_runs(&self) -> Result<Vec<StoredAgentRun>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT run_json::text \
                     FROM agent_runs \
                     ORDER BY started_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let mut runs = Vec::with_capacity(rows.len());
            for row in rows {
                runs.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(runs)
        })
    }

    fn append_agent_run_event(&self, event: &StoredAgentRunEvent) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let turn = saturating_i64(u64::from(event.turn));
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO agent_run_events \
                 (id, run_id, request_id, trace_id, tenant, turn, kind, target, outcome, \
                  occurred_at_unix, event_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.run_id,
                    &event.request_id,
                    &event.trace_id,
                    &tenant_context_id,
                    &turn,
                    &event.kind,
                    &event.target,
                    &event.outcome,
                    &occurred_at_unix,
                    &event_json,
                ],
            )?;
            Ok(())
        })
    }

    fn agent_run_events(&self) -> Result<Vec<StoredAgentRunEvent>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT event_json::text \
                     FROM agent_run_events \
                     ORDER BY occurred_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                events.push(deserialize_storage_document(
                    row.get::<_, String>(0).as_str(),
                )?);
            }
            Ok(events)
        })
    }

    fn upsert_managed_worker_template(
        &self,
        template: &StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        let max_tenant_sessions = template.max_tenant_sessions.map(i64::from);
        let max_workspace_sessions = template.max_workspace_sessions.map(i64::from);
        let created_at_unix =
            saturating_i64(template.created_at_unix.unwrap_or_else(now_unix_seconds));
        let updated_at_unix =
            saturating_i64(template.updated_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_templates \
                 (id, framework_adapter, isolation_backend_kind, enabled, max_tenant_sessions, \
                  max_workspace_sessions, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO UPDATE SET \
                 framework_adapter = EXCLUDED.framework_adapter, \
                 isolation_backend_kind = EXCLUDED.isolation_backend_kind, \
                 enabled = EXCLUDED.enabled, \
                 max_tenant_sessions = EXCLUDED.max_tenant_sessions, \
                 max_workspace_sessions = EXCLUDED.max_workspace_sessions, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &template.id,
                    &template.framework_adapter,
                    &template.isolation_backend_kind,
                    &template.enabled,
                    &max_tenant_sessions,
                    &max_workspace_sessions,
                    &created_at_unix,
                    &updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_templates(&self) -> Result<Vec<StoredManagedWorkerTemplate>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, framework_adapter, isolation_backend_kind, enabled, \
                        max_tenant_sessions, max_workspace_sessions, created_at_unix, \
                        updated_at_unix \
                     FROM managed_worker_templates \
                     ORDER BY id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_template_from_row)
                .collect())
        })
    }

    fn upsert_agent_worker_instance(
        &self,
        instance: &StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        let started_at_unix =
            saturating_i64(instance.started_at_unix.unwrap_or_else(now_unix_seconds));
        let last_seen_at_unix = instance.last_seen_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO agent_worker_instances \
                 (id, process_name, host_id, worker_version, status, started_at_unix, \
                  last_seen_at_unix, process_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 process_name = EXCLUDED.process_name, \
                 host_id = EXCLUDED.host_id, \
                 worker_version = EXCLUDED.worker_version, \
                 status = EXCLUDED.status, \
                 last_seen_at_unix = EXCLUDED.last_seen_at_unix, \
                 process_json = EXCLUDED.process_json",
                &[
                    &instance.id,
                    &instance.process_name,
                    &instance.host_id,
                    &instance.worker_version,
                    &instance.status,
                    &started_at_unix,
                    &last_seen_at_unix,
                    &instance.process_json,
                ],
            )?;
            Ok(())
        })
    }

    fn agent_worker_instances(&self) -> Result<Vec<StoredAgentWorkerInstance>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, process_name, host_id, worker_version, status, started_at_unix, \
                        last_seen_at_unix, process_json::text \
                     FROM agent_worker_instances \
                     ORDER BY started_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(agent_worker_instance_from_row)
                .collect())
        })
    }

    fn upsert_managed_worker_session(
        &self,
        session: &StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&session.tenant);
        let requested_at_unix =
            saturating_i64(session.requested_at_unix.unwrap_or_else(now_unix_seconds));
        let started_at_unix = session.started_at_unix.map(saturating_i64);
        let completed_at_unix = session.completed_at_unix.map(saturating_i64);
        let cleanup_completed_at_unix = session.cleanup_completed_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_sessions \
                 (id, run_id, tenant, workspace_id, worker_template_id, \
                  agent_worker_instance_id, status, isolation_backend_kind, microvm_id, \
                  capability_envelope_id, requested_at_unix, started_at_unix, completed_at_unix, \
                  cleanup_completed_at_unix, capability_envelope_json, resource_limits_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                         $15::text::jsonb, $16::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 worker_template_id = EXCLUDED.worker_template_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 status = EXCLUDED.status, \
                 isolation_backend_kind = EXCLUDED.isolation_backend_kind, \
                 microvm_id = EXCLUDED.microvm_id, \
                 capability_envelope_id = EXCLUDED.capability_envelope_id, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 cleanup_completed_at_unix = EXCLUDED.cleanup_completed_at_unix, \
                 capability_envelope_json = EXCLUDED.capability_envelope_json, \
                 resource_limits_json = EXCLUDED.resource_limits_json",
                &[
                    &session.id,
                    &session.run_id,
                    &tenant_context_id,
                    &session.workspace_id,
                    &session.worker_template_id,
                    &session.agent_worker_instance_id,
                    &session.status,
                    &session.isolation_backend_kind,
                    &session.microvm_id,
                    &session.capability_envelope_id,
                    &requested_at_unix,
                    &started_at_unix,
                    &completed_at_unix,
                    &cleanup_completed_at_unix,
                    &session.capability_envelope_json,
                    &session.resource_limits_json,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_sessions(&self) -> Result<Vec<StoredManagedWorkerSession>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, run_id, tenant, workspace_id, worker_template_id, \
                        agent_worker_instance_id, status, isolation_backend_kind, microvm_id, \
                        capability_envelope_id, requested_at_unix, started_at_unix, \
                        completed_at_unix, cleanup_completed_at_unix, \
                        capability_envelope_json::text, resource_limits_json::text \
                     FROM managed_worker_sessions \
                     ORDER BY requested_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_session_from_row)
                .collect())
        })
    }

    fn append_managed_worker_lifecycle_event(
        &self,
        event: &StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_lifecycle_events \
                 (id, session_id, run_id, tenant, workspace_id, agent_worker_instance_id, status, \
                  action, outcome, occurred_at_unix, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.session_id,
                    &event.run_id,
                    &tenant_context_id,
                    &event.workspace_id,
                    &event.agent_worker_instance_id,
                    &event.status,
                    &event.action,
                    &event.outcome,
                    &occurred_at_unix,
                    &event.evidence_json,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_lifecycle_events(
        &self,
    ) -> Result<Vec<StoredManagedWorkerLifecycleEvent>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, session_id, run_id, tenant, workspace_id, \
                        agent_worker_instance_id, status, action, outcome, occurred_at_unix, \
                        evidence_json::text \
                     FROM managed_worker_lifecycle_events \
                     ORDER BY occurred_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_lifecycle_event_from_row)
                .collect())
        })
    }

    fn upsert_managed_worker_isolation_selection(
        &self,
        selection: &StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&selection.tenant);
        let selected_at_unix =
            saturating_i64(selection.selected_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_isolation_selections \
                 (session_id, run_id, tenant, workspace_id, agent_worker_instance_id, \
                  backend_name, backend_version, backend_kind, host_lifecycle_owner, \
                  gateway_controls_backend, capability_envelope_id, selected_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (session_id) DO UPDATE SET \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 backend_name = EXCLUDED.backend_name, \
                 backend_version = EXCLUDED.backend_version, \
                 backend_kind = EXCLUDED.backend_kind, \
                 host_lifecycle_owner = EXCLUDED.host_lifecycle_owner, \
                 gateway_controls_backend = EXCLUDED.gateway_controls_backend, \
                 capability_envelope_id = EXCLUDED.capability_envelope_id, \
                 selected_at_unix = EXCLUDED.selected_at_unix",
                &[
                    &selection.session_id,
                    &selection.run_id,
                    &tenant_context_id,
                    &selection.workspace_id,
                    &selection.agent_worker_instance_id,
                    &selection.backend_name,
                    &selection.backend_version,
                    &selection.backend_kind,
                    &selection.host_lifecycle_owner,
                    &selection.gateway_controls_backend,
                    &selection.capability_envelope_id,
                    &selected_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_isolation_selections(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationSelection>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT session_id, run_id, tenant, workspace_id, agent_worker_instance_id, \
                        backend_name, backend_version, backend_kind, host_lifecycle_owner, \
                        gateway_controls_backend, capability_envelope_id, selected_at_unix \
                     FROM managed_worker_isolation_selections \
                     ORDER BY selected_at_unix ASC, session_id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_isolation_selection_from_row)
                .collect())
        })
    }

    fn upsert_managed_worker_isolation_policy(
        &self,
        policy: &StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        let cpu_count = i32::from(policy.cpu_count);
        let memory_mib = saturating_i32(u64::from(policy.memory_mib));
        let disk_mib = saturating_i32(u64::from(policy.disk_mib));
        let max_runtime_millis = policy.max_runtime_millis.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_isolation_policies \
                 (session_id, cpu_count, memory_mib, disk_mib, max_runtime_millis, \
                  direct_public_egress, gateway_control_channel, governed_egress, \
                  read_only_rootfs, writable_workspace, host_path_mounts) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (session_id) DO UPDATE SET \
                 cpu_count = EXCLUDED.cpu_count, \
                 memory_mib = EXCLUDED.memory_mib, \
                 disk_mib = EXCLUDED.disk_mib, \
                 max_runtime_millis = EXCLUDED.max_runtime_millis, \
                 direct_public_egress = EXCLUDED.direct_public_egress, \
                 gateway_control_channel = EXCLUDED.gateway_control_channel, \
                 governed_egress = EXCLUDED.governed_egress, \
                 read_only_rootfs = EXCLUDED.read_only_rootfs, \
                 writable_workspace = EXCLUDED.writable_workspace, \
                 host_path_mounts = EXCLUDED.host_path_mounts",
                &[
                    &policy.session_id,
                    &cpu_count,
                    &memory_mib,
                    &disk_mib,
                    &max_runtime_millis,
                    &policy.direct_public_egress,
                    &policy.gateway_control_channel,
                    &policy.governed_egress,
                    &policy.read_only_rootfs,
                    &policy.writable_workspace,
                    &policy.host_path_mounts,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_isolation_policies(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationPolicy>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT session_id, cpu_count, memory_mib, disk_mib, max_runtime_millis, \
                        direct_public_egress, gateway_control_channel, governed_egress, \
                        read_only_rootfs, writable_workspace, host_path_mounts \
                     FROM managed_worker_isolation_policies \
                     ORDER BY session_id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_isolation_policy_from_row)
                .collect())
        })
    }

    fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: &StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&evidence.tenant);
        let occurred_at_unix =
            saturating_i64(evidence.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO managed_worker_isolation_evidence \
                 (id, session_id, lifecycle_event_id, run_id, tenant, workspace_id, \
                  agent_worker_instance_id, isolation_instance_id, action, outcome, \
                  failure_reason, occurred_at_unix, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 session_id = EXCLUDED.session_id, \
                 lifecycle_event_id = EXCLUDED.lifecycle_event_id, \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 isolation_instance_id = EXCLUDED.isolation_instance_id, \
                 action = EXCLUDED.action, \
                 outcome = EXCLUDED.outcome, \
                 failure_reason = EXCLUDED.failure_reason, \
                 occurred_at_unix = EXCLUDED.occurred_at_unix, \
                 evidence_json = EXCLUDED.evidence_json",
                &[
                    &evidence.id,
                    &evidence.session_id,
                    &evidence.lifecycle_event_id,
                    &evidence.run_id,
                    &tenant_context_id,
                    &evidence.workspace_id,
                    &evidence.agent_worker_instance_id,
                    &evidence.isolation_instance_id,
                    &evidence.action,
                    &evidence.outcome,
                    &evidence.failure_reason,
                    &occurred_at_unix,
                    &evidence.evidence_json,
                ],
            )?;
            Ok(())
        })
    }

    fn managed_worker_isolation_evidence(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationEvidence>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, session_id, lifecycle_event_id, run_id, tenant, workspace_id, \
                        agent_worker_instance_id, isolation_instance_id, action, outcome, \
                        failure_reason, occurred_at_unix, evidence_json::text \
                     FROM managed_worker_isolation_evidence \
                     ORDER BY occurred_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(managed_worker_isolation_evidence_from_row)
                .collect())
        })
    }

    fn upsert_self_hosted_worker_registration(
        &self,
        registration: &StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&registration.tenant);
        let registered_at_unix = saturating_i64(
            registration
                .registered_at_unix
                .unwrap_or_else(now_unix_seconds),
        );
        let last_seen_at_unix = registration.last_seen_at_unix.map(saturating_i64);
        let identity_expires_at_unix = registration.identity_expires_at_unix.map(saturating_i64);
        self.with_client(|client| {
            client.execute(
                "INSERT INTO self_hosted_worker_registrations \
                 (id, tenant, workspace_id, worker_name, status, identity_fingerprint, \
                  identity_expires_at_unix, orchestration_enabled, registered_at_unix, \
                  last_seen_at_unix, trust_level, capability_envelope_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 worker_name = EXCLUDED.worker_name, \
                 status = EXCLUDED.status, \
                 identity_fingerprint = EXCLUDED.identity_fingerprint, \
                 identity_expires_at_unix = EXCLUDED.identity_expires_at_unix, \
                 orchestration_enabled = EXCLUDED.orchestration_enabled, \
                 last_seen_at_unix = EXCLUDED.last_seen_at_unix, \
                 trust_level = EXCLUDED.trust_level, \
                 capability_envelope_json = EXCLUDED.capability_envelope_json",
                &[
                    &registration.id,
                    &tenant_context_id,
                    &registration.workspace_id,
                    &registration.worker_name,
                    &registration.status,
                    &registration.identity_fingerprint,
                    &identity_expires_at_unix,
                    &registration.orchestration_enabled,
                    &registered_at_unix,
                    &last_seen_at_unix,
                    &registration.trust_level,
                    &registration.capability_envelope_json,
                ],
            )?;
            Ok(())
        })
    }

    fn self_hosted_worker_registrations(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerRegistration>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, tenant, workspace_id, worker_name, status, identity_fingerprint, \
                        identity_expires_at_unix, orchestration_enabled, registered_at_unix, \
                        last_seen_at_unix, trust_level, capability_envelope_json::text \
                     FROM self_hosted_worker_registrations \
                     ORDER BY registered_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(self_hosted_worker_registration_from_row)
                .collect())
        })
    }

    fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: &StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&heartbeat.tenant);
        let reported_at_unix =
            saturating_i64(heartbeat.reported_at_unix.unwrap_or_else(now_unix_seconds));
        let observed_at_unix =
            saturating_i64(heartbeat.observed_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO self_hosted_worker_heartbeats \
                 (id, worker_id, tenant, workspace_id, status, reported_at_unix, \
                  observed_at_unix, heartbeat_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &heartbeat.id,
                    &heartbeat.worker_id,
                    &tenant_context_id,
                    &heartbeat.workspace_id,
                    &heartbeat.status,
                    &reported_at_unix,
                    &observed_at_unix,
                    &heartbeat.heartbeat_json,
                ],
            )?;
            Ok(())
        })
    }

    fn self_hosted_worker_heartbeats(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerHeartbeat>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, worker_id, tenant, workspace_id, status, reported_at_unix, \
                        observed_at_unix, heartbeat_json::text \
                     FROM self_hosted_worker_heartbeats \
                     ORDER BY reported_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(self_hosted_worker_heartbeat_from_row)
                .collect())
        })
    }

    fn append_self_hosted_worker_telemetry_event(
        &self,
        event: &StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let ingested_at_unix =
            saturating_i64(event.ingested_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO self_hosted_worker_telemetry_events \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, kind, trust_level, \
                  occurred_at_unix, ingested_at_unix, event_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.worker_id,
                    &tenant_context_id,
                    &event.workspace_id,
                    &event.session_id,
                    &event.run_id,
                    &event.kind,
                    &event.trust_level,
                    &occurred_at_unix,
                    &ingested_at_unix,
                    &event.event_json,
                ],
            )?;
            Ok(())
        })
    }

    fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, kind, \
                        trust_level, occurred_at_unix, ingested_at_unix, event_json::text \
                     FROM self_hosted_worker_telemetry_events \
                     ORDER BY occurred_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(self_hosted_worker_telemetry_event_from_row)
                .collect())
        })
    }

    fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: &StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&artifact.tenant);
        let size_bytes = saturating_i64(artifact.size_bytes);
        let created_at_unix =
            saturating_i64(artifact.created_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO self_hosted_worker_artifacts \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, artifact_name, \
                  content_type, size_bytes, trust_level, created_at_unix, artifact_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 worker_id = EXCLUDED.worker_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 session_id = EXCLUDED.session_id, \
                 run_id = EXCLUDED.run_id, \
                 artifact_name = EXCLUDED.artifact_name, \
                 content_type = EXCLUDED.content_type, \
                 size_bytes = EXCLUDED.size_bytes, \
                 trust_level = EXCLUDED.trust_level, \
                 artifact_json = EXCLUDED.artifact_json",
                &[
                    &artifact.id,
                    &artifact.worker_id,
                    &tenant_context_id,
                    &artifact.workspace_id,
                    &artifact.session_id,
                    &artifact.run_id,
                    &artifact.artifact_name,
                    &artifact.content_type,
                    &size_bytes,
                    &artifact.trust_level,
                    &created_at_unix,
                    &artifact.artifact_json,
                ],
            )?;
            Ok(())
        })
    }

    fn self_hosted_worker_artifacts(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerArtifact>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                        artifact_name, content_type, size_bytes, trust_level, created_at_unix, \
                        artifact_json::text \
                     FROM self_hosted_worker_artifacts \
                     ORDER BY created_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(self_hosted_worker_artifact_from_row)
                .collect())
        })
    }

    fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: &StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&checkpoint.tenant);
        let size_bytes = saturating_i64(checkpoint.size_bytes);
        let created_at_unix =
            saturating_i64(checkpoint.created_at_unix.unwrap_or_else(now_unix_seconds));
        self.with_client(|client| {
            client.execute(
                "INSERT INTO self_hosted_worker_checkpoints \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, checkpoint_name, \
                  size_bytes, trust_level, created_at_unix, checkpoint_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 worker_id = EXCLUDED.worker_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 session_id = EXCLUDED.session_id, \
                 run_id = EXCLUDED.run_id, \
                 checkpoint_name = EXCLUDED.checkpoint_name, \
                 size_bytes = EXCLUDED.size_bytes, \
                 trust_level = EXCLUDED.trust_level, \
                 checkpoint_json = EXCLUDED.checkpoint_json",
                &[
                    &checkpoint.id,
                    &checkpoint.worker_id,
                    &tenant_context_id,
                    &checkpoint.workspace_id,
                    &checkpoint.session_id,
                    &checkpoint.run_id,
                    &checkpoint.checkpoint_name,
                    &size_bytes,
                    &checkpoint.trust_level,
                    &created_at_unix,
                    &checkpoint.checkpoint_json,
                ],
            )?;
            Ok(())
        })
    }

    fn self_hosted_worker_checkpoints(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerCheckpoint>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                        checkpoint_name, size_bytes, trust_level, created_at_unix, \
                        checkpoint_json::text \
                     FROM self_hosted_worker_checkpoints \
                     ORDER BY created_at_unix ASC, id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            Ok(rows
                .into_iter()
                .map(self_hosted_worker_checkpoint_from_row)
                .collect())
        })
    }

    fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: &StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        let tenant_context_id = dispatch.tenant_id.clone();
        let queued_at_unix =
            saturating_i64(dispatch.queued_at_unix.unwrap_or_else(now_unix_seconds));
        let lease_expires_at_unix = dispatch.lease_expires_at_unix.map(saturating_i64);
        let acknowledged_at_unix = dispatch.acknowledged_at_unix.map(saturating_i64);
        let attempt = saturating_i64(u64::from(dispatch.attempt));
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(postgres_error)?;
            transaction
                .execute(
                    "INSERT INTO self_hosted_run_dispatches \
                     (dispatch_id, action, tenant, workspace_id, session_id, run_id, \
                      framework_adapter, workload_ref, queued_at_unix, assigned_worker_id, \
                      lease_id, lease_expires_at_unix, attempt, acknowledged_status, \
                      acknowledged_at_unix) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                     ON CONFLICT (dispatch_id) DO UPDATE SET \
                     action = EXCLUDED.action, \
                     tenant = EXCLUDED.tenant, \
                     workspace_id = EXCLUDED.workspace_id, \
                     session_id = EXCLUDED.session_id, \
                     run_id = EXCLUDED.run_id, \
                     framework_adapter = EXCLUDED.framework_adapter, \
                     workload_ref = EXCLUDED.workload_ref, \
                     queued_at_unix = EXCLUDED.queued_at_unix, \
                     assigned_worker_id = EXCLUDED.assigned_worker_id, \
                     lease_id = EXCLUDED.lease_id, \
                     lease_expires_at_unix = EXCLUDED.lease_expires_at_unix, \
                     attempt = EXCLUDED.attempt, \
                     acknowledged_status = EXCLUDED.acknowledged_status, \
                     acknowledged_at_unix = EXCLUDED.acknowledged_at_unix",
                    &[
                        &dispatch.dispatch_id,
                        &dispatch.action,
                        &tenant_context_id,
                        &dispatch.workspace_id,
                        &dispatch.session_id,
                        &dispatch.run_id,
                        &dispatch.framework_adapter,
                        &dispatch.workload_ref,
                        &queued_at_unix,
                        &dispatch.assigned_worker_id,
                        &dispatch.lease_id,
                        &lease_expires_at_unix,
                        &attempt,
                        &dispatch.acknowledged_status,
                        &acknowledged_at_unix,
                    ],
                )
                .map_err(postgres_error)?;
            transaction
                .execute(
                    "DELETE FROM self_hosted_run_dispatch_capabilities WHERE dispatch_id = $1",
                    &[&dispatch.dispatch_id],
                )
                .map_err(postgres_error)?;
            for capability in &dispatch.required_capabilities {
                transaction
                    .execute(
                        "INSERT INTO self_hosted_run_dispatch_capabilities \
                         (dispatch_id, capability) VALUES ($1, $2) \
                         ON CONFLICT (dispatch_id, capability) DO NOTHING",
                        &[&dispatch.dispatch_id, capability],
                    )
                    .map_err(postgres_error)?;
            }
            transaction.commit().map_err(postgres_error)?;
            Ok(())
        })
    }

    fn self_hosted_run_dispatches(&self) -> Result<Vec<StoredSelfHostedRunDispatch>, StorageError> {
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT dispatch_id, action, tenant, workspace_id, session_id, run_id, \
                        framework_adapter, workload_ref, queued_at_unix, assigned_worker_id, \
                        lease_id, lease_expires_at_unix, attempt, acknowledged_status, \
                        acknowledged_at_unix \
                     FROM self_hosted_run_dispatches \
                     ORDER BY queued_at_unix ASC, dispatch_id ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let capability_rows = client
                .query(
                    "SELECT dispatch_id, capability \
                     FROM self_hosted_run_dispatch_capabilities \
                     ORDER BY dispatch_id ASC, capability ASC",
                    &[],
                )
                .map_err(postgres_error)?;
            let mut capabilities = HashMap::<String, Vec<String>>::new();
            for row in capability_rows {
                capabilities
                    .entry(row.get::<_, String>(0))
                    .or_default()
                    .push(row.get(1));
            }
            Ok(rows
                .into_iter()
                .map(|row| self_hosted_run_dispatch_from_row(row, &capabilities))
                .collect())
        })
    }

    fn billing_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<BillingEvent>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        self.with_client_storage(|client| {
            let rows = client
                .query(
                    "SELECT e.request_id, e.trace_id, e.agent_run_id, e.workflow_id, \
                        e.workflow_version, e.workflow_node_id, e.cluster_id, e.node_id, \
                        e.status_code, e.occurred_at_unix, \
                        t.organization_id, t.team_id, t.project_id, t.user_id, t.api_key_id, \
                        r.logical_model, r.provider, r.provider_model, \
                        u.prompt_tokens, u.completion_tokens, u.total_tokens, u.usage_source, \
                        count(*) OVER() \
                 FROM metering_events e \
                 JOIN tenant_contexts t ON t.id = e.tenant_context_id \
                 JOIN metering_event_routes r ON r.request_id = e.request_id \
                 JOIN metering_event_usage u ON u.request_id = e.request_id \
                 ORDER BY e.occurred_at_unix ASC, e.request_id ASC \
                 OFFSET $1 LIMIT $2",
                    &[&offset, &limit],
                )
                .map_err(postgres_error)?;
            let total = rows
                .first()
                .map(|row| row.get::<_, i64>(22))
                .unwrap_or_default();
            Ok(StoragePage {
                data: rows.into_iter().map(billing_event_from_row).collect(),
                total: usize::try_from(total).unwrap_or(usize::MAX),
                offset: usize::try_from(offset).unwrap_or(usize::MAX),
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            })
        })
    }

    fn billing_events(&self) -> Result<Vec<BillingEvent>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT e.request_id, e.trace_id, e.agent_run_id, e.workflow_id, \
                        e.workflow_version, e.workflow_node_id, e.cluster_id, e.node_id, \
                        e.status_code, e.occurred_at_unix, \
                        t.organization_id, t.team_id, t.project_id, t.user_id, t.api_key_id, \
                        r.logical_model, r.provider, r.provider_model, \
                        u.prompt_tokens, u.completion_tokens, u.total_tokens, u.usage_source \
                 FROM metering_events e \
                 JOIN tenant_contexts t ON t.id = e.tenant_context_id \
                 JOIN metering_event_routes r ON r.request_id = e.request_id \
                 JOIN metering_event_usage u ON u.request_id = e.request_id \
                 ORDER BY e.occurred_at_unix ASC, e.request_id ASC",
                &[],
            )?;
            Ok(rows.into_iter().map(billing_event_from_row).collect())
        })
    }

    fn upsert_usage_aggregate(&self, aggregate: &StoredUsageAggregate) -> Result<(), StorageError> {
        let tenant_context_id = tenant_parts_storage_key(
            aggregate.organization_id.as_deref(),
            None,
            aggregate.project_id.as_deref(),
            None,
            aggregate.api_key_id.as_deref(),
        );
        let prompt_tokens = saturating_i64(aggregate.usage.prompt_tokens);
        let completion_tokens = saturating_i64(aggregate.usage.completion_tokens);
        let total_tokens = saturating_i64(aggregate.usage.total_tokens);
        self.with_client(|client| {
            let mut transaction = client.transaction()?;
            upsert_tenant_context_parts(
                &mut transaction,
                &tenant_context_id,
                aggregate.organization_id.as_deref(),
                None,
                aggregate.project_id.as_deref(),
                None,
                aggregate.api_key_id.as_deref(),
            )?;
            let rollup = UsageRollupUpsert {
                id: &aggregate.id,
                tenant_context_id: &tenant_context_id,
                logical_model: &aggregate.logical_model,
                provider: &aggregate.provider,
                prompt_tokens,
                completion_tokens,
                total_tokens,
            };
            replace_usage_rollup(&mut transaction, &rollup)?;
            transaction.commit()?;
            Ok(())
        })
    }

    fn usage_aggregates(&self) -> Result<Vec<StoredUsageAggregate>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT a.id, t.organization_id, t.project_id, t.api_key_id, \
                        a.logical_model, a.provider, \
                        a.prompt_tokens, a.completion_tokens, a.total_tokens \
                 FROM usage_aggregate_rollups a \
                 JOIN tenant_contexts t ON t.id = a.tenant_context_id \
                 ORDER BY a.id ASC",
                &[],
            )?;
            Ok(rows.into_iter().map(usage_aggregate_from_row).collect())
        })
    }

    fn with_client<T: Send>(
        &self,
        action: impl FnOnce(&mut PostgresClient) -> Result<T, postgres::Error> + Send,
    ) -> Result<T, StorageError> {
        self.with_client_storage(|client| action(client).map_err(postgres_error))
    }

    fn with_client_storage<T: Send>(
        &self,
        action: impl FnOnce(&mut PostgresClient) -> Result<T, StorageError> + Send,
    ) -> Result<T, StorageError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut client = self.pool.acquire()?;
                    let result = action(&mut client);
                    self.pool.release(client);
                    result
                })
                .join()
                .map_err(|_| StorageError::Postgres("postgres storage thread panicked".into()))?
        })
    }
}

impl Drop for PostgresControlPlaneStore {
    fn drop(&mut self) {
        let Ok(mut clients) = self.pool.clients.lock() else {
            return;
        };
        let clients = std::mem::take(&mut *clients);
        if clients.is_empty() {
            return;
        }
        let _ = std::thread::spawn(move || drop(clients)).join();
    }
}

impl PostgresClientPool {
    fn acquire(&self) -> Result<PostgresClient, StorageError> {
        let mut clients = self.clients.lock().map_err(|_| {
            StorageError::Postgres("postgres control-plane client pool mutex is poisoned".into())
        })?;
        loop {
            if let Some(client) = clients.pop() {
                return Ok(client);
            }
            clients = self.available.wait(clients).map_err(|_| {
                StorageError::Postgres(
                    "postgres control-plane client pool mutex is poisoned".into(),
                )
            })?;
        }
    }

    fn release(&self, client: PostgresClient) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.push(client);
            self.available.notify_one();
        }
    }
}

impl std::fmt::Debug for MySqlControlPlaneStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MySqlControlPlaneStore")
            .field("pool", &"<redacted>")
            .finish()
    }
}

impl MySqlControlPlaneStore {
    fn connect(
        config: MySqlStorageConfig,
        bootstrap: ControlPlaneDocuments,
        initialize_schema: bool,
    ) -> Result<Self, StorageError> {
        let opts = mysql_opts(&config)?;
        let pool = Pool::new(opts).map_err(mysql_error)?;
        let store = Self { pool };
        store.with_conn(|conn| {
            conn.query_drop("SELECT 1")?;
            Ok(())
        })?;
        if initialize_schema {
            store.initialize_schema()?;
        }
        store.seed_missing_resources("api_key", bootstrap.api_keys)?;
        store.seed_missing_resources("tenant", bootstrap.tenants)?;
        store.seed_missing_resources("policy", bootstrap.policies)?;
        store.seed_missing_resources("gateway_config", bootstrap.gateway_configs)?;
        store.seed_missing_resources("agent_workflow", bootstrap.agent_workflows)?;
        store.seed_missing_resources("skill_package", bootstrap.skill_packages)?;
        store.seed_missing_resources("prompt_template", bootstrap.prompt_templates)?;
        store.seed_missing_resources("plugin_registration", bootstrap.plugin_registrations)?;
        store.seed_missing_resources("mcp_server", bootstrap.mcp_servers)?;
        store.seed_missing_resources("agent_upstream", bootstrap.agent_upstreams)?;
        Ok(store)
    }

    fn initialize_schema(&self) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            for statement in include_str!("../../../sql/001_init_mysql.sql")
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                conn.query_drop(statement)?;
            }
            Ok(())
        })
    }

    fn seed_missing_resources(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            for (id, document_json) in records {
                conn.exec_drop(
                    "INSERT IGNORE INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) \
                     VALUES (:kind, :id, :document_json)",
                    params! {
                        "kind" => kind,
                        "id" => id,
                        "document_json" => document_json,
                    },
                )?;
            }
            Ok(())
        })
    }

    fn snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        Ok(ControlPlaneSnapshot {
            api_keys: self.list_documents("api_key")?,
            tenants: self.list_documents("tenant")?,
            policies: self.list_documents("policy")?,
            gateway_configs: self.list_documents("gateway_config")?,
            agent_workflows: self.list_documents("agent_workflow")?,
            skill_packages: self.list_documents("skill_package")?,
            prompt_templates: self.list_documents("prompt_template")?,
            plugin_registrations: self.list_documents("plugin_registration")?,
            mcp_servers: self.list_documents("mcp_server")?,
            agent_upstreams: self.list_documents("agent_upstream")?,
        })
    }

    fn documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(ControlPlaneDocuments {
            api_keys: self.list_resource_documents("api_key")?,
            tenants: self.list_resource_documents("tenant")?,
            policies: self.list_resource_documents("policy")?,
            gateway_configs: self.list_resource_documents("gateway_config")?,
            agent_workflows: self.list_resource_documents("agent_workflow")?,
            skill_packages: self.list_resource_documents("skill_package")?,
            prompt_templates: self.list_resource_documents("prompt_template")?,
            plugin_registrations: self.list_resource_documents("plugin_registration")?,
            mcp_servers: self.list_resource_documents("mcp_server")?,
            agent_upstreams: self.list_resource_documents("agent_upstream")?,
        })
    }

    fn list_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        self.with_conn(|conn| {
            conn.exec_map(
                "SELECT resource_id, CAST(document_json AS CHAR) FROM control_plane_resources \
                 WHERE resource_kind = :kind ORDER BY resource_id ASC",
                params! {
                    "kind" => kind,
                },
                |(id, document_json): (String, String)| (id, document_json),
            )
        })
    }

    fn list_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        self.with_conn(|conn| {
            conn.exec_map(
                "SELECT CAST(document_json AS CHAR) FROM control_plane_resources \
                 WHERE resource_kind = :kind ORDER BY resource_id ASC",
                params! {
                    "kind" => kind,
                },
                |document_json: String| document_json,
            )
        })
    }

    fn get_document(&self, kind: &'static str, id: String) -> Result<Option<String>, StorageError> {
        self.with_conn(|conn| {
            conn.exec_first(
                "SELECT CAST(document_json AS CHAR) FROM control_plane_resources \
                 WHERE resource_kind = :kind AND resource_id = :id",
                params! {
                    "kind" => kind,
                    "id" => id,
                },
            )
        })
    }

    fn upsert(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            conn.exec_drop(
                "INSERT INTO control_plane_resources \
                 (resource_kind, resource_id, document_json, revision, updated_at_unix) \
                 VALUES (:kind, :id, :document_json, 1, UNIX_TIMESTAMP()) \
                 ON DUPLICATE KEY UPDATE \
                 document_json = VALUES(document_json), \
                 revision = revision + 1, \
                 updated_at_unix = UNIX_TIMESTAMP()",
                params! {
                    "kind" => kind,
                    "id" => id,
                    "document_json" => document_json,
                },
            )?;
            Ok(())
        })
    }

    fn replace_kind(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            let mut transaction = conn.start_transaction(TxOpts::default())?;
            transaction.exec_drop(
                "DELETE FROM control_plane_resources WHERE resource_kind = :kind",
                params! {
                    "kind" => kind,
                },
            )?;
            for (id, document_json) in records {
                transaction.exec_drop(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) \
                     VALUES (:kind, :id, :document_json)",
                    params! {
                        "kind" => kind,
                        "id" => id,
                        "document_json" => document_json,
                    },
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn delete(&self, kind: &'static str, id: String) -> Result<bool, StorageError> {
        self.with_conn(|conn| {
            conn.exec_drop(
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = :kind AND resource_id = :id",
                params! {
                    "kind" => kind,
                    "id" => id,
                },
            )?;
            Ok(conn.affected_rows() > 0)
        })
    }

    fn upsert_tenant_account(&self, account: &StoredTenantAccount) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            conn.exec_drop(
                "INSERT INTO tenants (id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES (:id, :name, :slug, :status, :created_at_unix, :updated_at_unix) \
                 ON DUPLICATE KEY UPDATE \
                 name = VALUES(name), slug = VALUES(slug), status = VALUES(status), \
                 updated_at_unix = VALUES(updated_at_unix)",
                params! {
                    "id" => &account.id,
                    "name" => &account.name,
                    "slug" => &account.slug,
                    "status" => &account.status,
                    "created_at_unix" => account.created_at_unix,
                    "updated_at_unix" => account.updated_at_unix,
                },
            )
        })
    }

    fn get_tenant_account(&self, id: &str) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.with_conn(|conn| {
            let row: Option<(String, String, String, String, i64, i64)> = conn.exec_first(
                "SELECT id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM tenants WHERE id = :id",
                params! { "id" => id },
            )?;
            Ok(row.map(tenant_account_from_tuple))
        })
    }

    fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        self.with_conn(|conn| {
            let rows: Vec<(String, String, String, String, i64, i64)> = conn.exec(
                "SELECT id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM tenants ORDER BY id ASC",
                (),
            )?;
            Ok(rows.into_iter().map(tenant_account_from_tuple).collect())
        })
    }

    fn upsert_project(&self, project: &StoredProject) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            conn.exec_drop(
                "INSERT INTO projects \
                 (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES (:id, :tenant_id, :name, :slug, :status, :created_at_unix, \
                 :updated_at_unix) \
                 ON DUPLICATE KEY UPDATE \
                 tenant_id = VALUES(tenant_id), name = VALUES(name), slug = VALUES(slug), \
                 status = VALUES(status), updated_at_unix = VALUES(updated_at_unix)",
                params! {
                    "id" => &project.id,
                    "tenant_id" => &project.tenant_id,
                    "name" => &project.name,
                    "slug" => &project.slug,
                    "status" => &project.status,
                    "created_at_unix" => project.created_at_unix,
                    "updated_at_unix" => project.updated_at_unix,
                },
            )
        })
    }

    fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.with_conn(|conn| {
            let row: Option<(String, String, String, String, String, i64, i64)> = conn.exec_first(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects WHERE id = :id",
                params! { "id" => id },
            )?;
            Ok(row.map(project_from_tuple))
        })
    }

    fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        self.with_conn(|conn| {
            let rows: Vec<(String, String, String, String, String, i64, i64)> = conn.exec(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects ORDER BY id ASC",
                (),
            )?;
            Ok(rows.into_iter().map(project_from_tuple).collect())
        })
    }

    fn upsert_workspace(&self, workspace: &StoredWorkspace) -> Result<(), StorageError> {
        self.with_conn(|conn| {
            conn.exec_drop(
                "INSERT INTO workspaces \
                 (id, project_id, tenant_id, name, slug, environment, status, \
                  created_at_unix, updated_at_unix) \
                 VALUES (:id, :project_id, :tenant_id, :name, :slug, :environment, :status, \
                 :created_at_unix, :updated_at_unix) \
                 ON DUPLICATE KEY UPDATE \
                 project_id = VALUES(project_id), tenant_id = VALUES(tenant_id), \
                 name = VALUES(name), slug = VALUES(slug), environment = VALUES(environment), \
                 status = VALUES(status), updated_at_unix = VALUES(updated_at_unix)",
                params! {
                    "id" => &workspace.id,
                    "project_id" => &workspace.project_id,
                    "tenant_id" => &workspace.tenant_id,
                    "name" => &workspace.name,
                    "slug" => &workspace.slug,
                    "environment" => &workspace.environment,
                    "status" => &workspace.status,
                    "created_at_unix" => workspace.created_at_unix,
                    "updated_at_unix" => workspace.updated_at_unix,
                },
            )
        })
    }

    fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.with_conn(|conn| {
            let row: Option<WorkspaceRow> = conn.exec_first(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces WHERE id = :id",
                params! { "id" => id },
            )?;
            Ok(row.map(workspace_from_tuple))
        })
    }

    fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        self.with_conn(|conn| {
            let rows: Vec<WorkspaceRow> = conn.exec(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces ORDER BY id ASC",
                (),
            )?;
            Ok(rows.into_iter().map(workspace_from_tuple).collect())
        })
    }

    fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        self.with_conn(|conn| {
            let row: Option<(String, String, String)> = conn.exec_first(
                "SELECT tenant_id, project_id, id FROM workspaces WHERE id = :id",
                params! { "id" => workspace_id },
            )?;
            Ok(row
                .map(|(tenant_id, project_id, id)| WorkspaceScope::new(tenant_id, project_id, id)))
        })
    }

    fn with_conn<T: Send>(
        &self,
        action: impl FnOnce(&mut PooledConn) -> Result<T, mysql::Error> + Send,
    ) -> Result<T, StorageError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut conn = self.pool.get_conn().map_err(mysql_error)?;
                    action(&mut conn).map_err(mysql_error)
                })
                .join()
                .map_err(|_| StorageError::Mysql("mysql storage thread panicked".into()))?
        })
    }
}

fn mysql_opts(config: &MySqlStorageConfig) -> Result<Opts, StorageError> {
    let opts =
        Opts::from_url(&config.dsn).map_err(|error| StorageError::Mysql(error.to_string()))?;
    let constraints = PoolConstraints::new(0, config.pool_size).ok_or_else(|| {
        StorageError::Mysql(format!(
            "invalid storage.mysql_pool_size {}",
            config.pool_size
        ))
    })?;
    let pool_opts = PoolOpts::default().with_constraints(constraints);
    let mut builder = OptsBuilder::from_opts(opts)
        .pool_opts(Some(pool_opts))
        .tcp_connect_timeout(Some(Duration::from_secs(config.connect_timeout_secs)));

    if !matches!(config.tls_mode, MySqlTlsMode::Disable) {
        builder = builder.ssl_opts(Some(mysql_ssl_opts(config)?));
    }

    Ok(builder.into())
}

fn mysql_ssl_opts(config: &MySqlStorageConfig) -> Result<SslOpts, StorageError> {
    let mut ssl_opts = SslOpts::default();
    if let Some(path) = config.tls_ca_cert_path.as_deref() {
        if !std::path::Path::new(path).exists() {
            return Err(StorageError::Mysql(format!(
                "failed to read storage.mysql_tls_ca_cert_path {path}: file does not exist"
            )));
        }
        ssl_opts = ssl_opts.with_root_cert_path(Some(std::path::Path::new(path).to_path_buf()));
    }
    match config.tls_mode {
        MySqlTlsMode::Disable | MySqlTlsMode::VerifyFull => {}
        MySqlTlsMode::Require => {
            ssl_opts = ssl_opts
                .with_danger_accept_invalid_certs(true)
                .with_danger_skip_domain_validation(true);
        }
        MySqlTlsMode::VerifyCa => {
            ssl_opts = ssl_opts.with_danger_skip_domain_validation(true);
        }
    }
    Ok(ssl_opts)
}

fn connect_postgres_client(config: &PostgresStorageConfig) -> Result<PostgresClient, StorageError> {
    let mut pg_config = postgres::Config::from_str(&config.dsn).map_err(postgres_error)?;
    pg_config.connect_timeout(Duration::from_secs(config.connect_timeout_secs));
    pg_config.ssl_mode(match config.tls_mode {
        PostgresTlsMode::Disable => PostgresSslMode::Disable,
        PostgresTlsMode::Prefer => PostgresSslMode::Prefer,
        PostgresTlsMode::Require => PostgresSslMode::Require,
        PostgresTlsMode::VerifyCa | PostgresTlsMode::VerifyFull => PostgresSslMode::Require,
    });

    let mut client = match config.tls_mode {
        PostgresTlsMode::Disable => pg_config
            .connect(NoTls)
            .map_err(postgres_connection_error)?,
        PostgresTlsMode::Prefer
        | PostgresTlsMode::Require
        | PostgresTlsMode::VerifyCa
        | PostgresTlsMode::VerifyFull => {
            let connector = build_postgres_tls_connector(config)?;
            pg_config
                .connect(connector)
                .map_err(postgres_connection_error)?
        }
    };
    initialize_postgres_session(&mut client, config)?;
    Ok(client)
}

fn build_postgres_tls_connector(
    config: &PostgresStorageConfig,
) -> Result<MakeTlsConnector, StorageError> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = config.tls_ca_cert_path.as_deref() {
        let bytes = std::fs::read(path).map_err(|error| {
            StorageError::Postgres(format!(
                "failed to read storage.postgres_tls_ca_cert_path {path}: {error}"
            ))
        })?;
        let certificate = NativeTlsCertificate::from_pem(&bytes)
            .or_else(|_| NativeTlsCertificate::from_der(&bytes))
            .map_err(|error| {
                StorageError::Postgres(format!(
                    "failed to parse storage.postgres_tls_ca_cert_path {path}: {error}"
                ))
            })?;
        builder.add_root_certificate(certificate);
    }

    match config.tls_mode {
        PostgresTlsMode::Disable | PostgresTlsMode::Prefer | PostgresTlsMode::VerifyFull => {}
        PostgresTlsMode::Require => {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        PostgresTlsMode::VerifyCa => {
            builder.danger_accept_invalid_hostnames(true);
        }
    }

    let connector = builder.build().map_err(|error| {
        StorageError::Postgres(format!("postgres TLS connector error: {error}"))
    })?;
    Ok(MakeTlsConnector::new(connector))
}

fn initialize_postgres_session(
    client: &mut PostgresClient,
    config: &PostgresStorageConfig,
) -> Result<(), StorageError> {
    client
        .batch_execute(&format!(
            "SET statement_timeout = {}",
            config.statement_timeout_millis
        ))
        .map_err(postgres_error)?;

    if let Some(schema) = config.schema.as_deref() {
        client
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {}; SET search_path TO {};",
                quote_postgres_identifier(schema),
                postgres_search_path_sql(config)
            ))
            .map_err(postgres_error)?;
    } else if !config.search_path.is_empty() {
        client
            .batch_execute(&format!(
                "SET search_path TO {};",
                postgres_search_path_sql(config)
            ))
            .map_err(postgres_error)?;
    }
    Ok(())
}

fn postgres_search_path_sql(config: &PostgresStorageConfig) -> String {
    let mut path = Vec::new();
    if let Some(schema) = config.schema.as_deref() {
        path.push(schema.to_string());
    }
    path.extend(config.search_path.iter().cloned());
    path.into_iter()
        .map(|item| quote_postgres_identifier(&item))
        .collect::<Vec<_>>()
        .join(", ")
}

fn quote_postgres_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn validate_postgres_schema(client: &mut PostgresClient) -> Result<(), StorageError> {
    const TABLES: &[&str] = &[
        "control_plane_resources",
        "agent_runs",
        "agent_run_events",
        "managed_worker_templates",
        "agent_worker_instances",
        "managed_worker_sessions",
        "managed_worker_lifecycle_events",
        "managed_worker_isolation_selections",
        "managed_worker_isolation_policies",
        "managed_worker_isolation_evidence",
        "self_hosted_worker_registrations",
        "self_hosted_worker_heartbeats",
        "self_hosted_worker_telemetry_events",
        "self_hosted_worker_artifacts",
        "self_hosted_worker_checkpoints",
        "self_hosted_run_dispatches",
        "self_hosted_run_dispatch_capabilities",
        "request_logs",
        "audit_events",
        "billing_metering_events",
        "usage_aggregates",
        "tenant_contexts",
        "metering_events",
        "metering_event_routes",
        "metering_event_usage",
        "usage_aggregate_rollups",
        "tenants",
        "projects",
        "workspaces",
        "api_keys",
        "storage_schema_migrations",
    ];
    for table in TABLES {
        let exists = client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[table])
            .map_err(postgres_error)?
            .get::<_, bool>(0);
        if !exists {
            return Err(StorageError::Postgres(format!(
                "required schema table {table} is missing"
            )));
        }
    }

    const JSONB_COLUMNS: &[(&str, &str)] = &[
        ("control_plane_resources", "document_json"),
        ("agent_runs", "run_json"),
        ("agent_run_events", "event_json"),
        ("agent_worker_instances", "process_json"),
        ("managed_worker_sessions", "capability_envelope_json"),
        ("managed_worker_sessions", "resource_limits_json"),
        ("managed_worker_lifecycle_events", "evidence_json"),
        ("managed_worker_isolation_evidence", "evidence_json"),
        (
            "self_hosted_worker_registrations",
            "capability_envelope_json",
        ),
        ("self_hosted_worker_heartbeats", "heartbeat_json"),
        ("self_hosted_worker_telemetry_events", "event_json"),
        ("self_hosted_worker_artifacts", "artifact_json"),
        ("self_hosted_worker_checkpoints", "checkpoint_json"),
        ("request_logs", "request_json"),
        ("audit_events", "audit_json"),
        ("api_keys", "scopes_json"),
    ];
    for (table, column) in JSONB_COLUMNS {
        let data_type = client
            .query_opt(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 \
                   AND column_name = $2",
                &[table, column],
            )
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        if data_type.as_deref() != Some("jsonb") {
            return Err(StorageError::Postgres(format!(
                "required schema column {table}.{column} must be jsonb"
            )));
        }
    }

    const BIGINT_COLUMNS: &[(&str, &str)] = &[(
        "self_hosted_worker_registrations",
        "identity_expires_at_unix",
    )];
    for (table, column) in BIGINT_COLUMNS {
        let data_type = client
            .query_opt(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 \
                   AND column_name = $2",
                &[table, column],
            )
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        if data_type.as_deref() != Some("bigint") {
            return Err(StorageError::Postgres(format!(
                "required schema column {table}.{column} must be bigint"
            )));
        }
    }

    const INDEXES: &[&str] = &[
        "idx_control_plane_resources_document_gin",
        "idx_agent_runs_tenant_started",
        "idx_agent_run_events_run_time",
        "idx_managed_worker_templates_enabled_adapter",
        "idx_agent_worker_instances_status_seen",
        "idx_managed_worker_sessions_tenant_status",
        "idx_managed_worker_lifecycle_session_time",
        "idx_managed_worker_isolation_selection_backend",
        "idx_managed_worker_isolation_policy_egress",
        "idx_managed_worker_isolation_evidence_session_time",
        "idx_self_hosted_worker_registrations_tenant_status",
        "idx_self_hosted_worker_registrations_identity_expiry",
        "idx_self_hosted_worker_heartbeats_worker_time",
        "idx_self_hosted_worker_telemetry_worker_time",
        "idx_self_hosted_worker_artifacts_run",
        "idx_self_hosted_worker_checkpoints_run",
        "idx_self_hosted_run_dispatches_tenant_queue",
        "idx_self_hosted_run_dispatches_worker_lease",
        "idx_self_hosted_run_dispatch_capabilities_capability",
        "idx_request_logs_model_provider_started",
        "idx_audit_events_actor_time",
        "idx_billing_metering_model_provider_time",
        "idx_usage_aggregates_tenant_model_provider",
        "idx_tenant_contexts_api_key",
        "idx_metering_events_tenant_time",
        "idx_metering_event_routes_model_provider",
        "idx_usage_rollups_tenant_model_provider",
        "idx_api_keys_workspace",
        "idx_api_keys_tenant_project",
        "idx_api_keys_prefix",
    ];
    for index in INDEXES {
        let count = client
            .query_one(
                "SELECT count(*) FROM pg_indexes \
                 WHERE schemaname = current_schema() AND indexname = $1",
                &[index],
            )
            .map_err(postgres_error)?
            .get::<_, i64>(0);
        if count != 1 {
            return Err(StorageError::Postgres(format!(
                "required schema index {index} is missing"
            )));
        }
    }

    let row = client
        .query_opt(
            "SELECT name FROM storage_schema_migrations WHERE version = $1",
            &[&(POSTGRES_SCHEMA_VERSION as i64)],
        )
        .map_err(postgres_error)?;
    let name = row.map(|row| row.get::<_, String>(0));
    if name.as_deref() != Some(POSTGRES_SCHEMA_NAME) {
        return Err(StorageError::Postgres(format!(
            "required schema migration {POSTGRES_SCHEMA_VERSION}:{POSTGRES_SCHEMA_NAME} is missing"
        )));
    }
    Ok(())
}

fn fnv1a64_hex(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn saturating_i32(value: u64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn nonnegative_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn nonnegative_u32(value: i64) -> u32 {
    u32::try_from(value).unwrap_or_default()
}

fn serialize_storage_document<T: Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|error| StorageError::Serialization(error.to_string()))
}

fn deserialize_storage_document<T: for<'de> Deserialize<'de>>(
    value: &str,
) -> Result<T, StorageError> {
    serde_json::from_str(value).map_err(|error| StorageError::Serialization(error.to_string()))
}

fn api_key_records_supabase_only_error() -> StorageError {
    StorageError::Runtime(
        "virtual API key records are Supabase/Postgres-only; set storage.provider = supabase"
            .into(),
    )
}

fn tenant_account_from_row(row: &PostgresRow) -> StoredTenantAccount {
    StoredTenantAccount {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        status: row.get::<_, String>(3),
        created_at_unix: row.get::<_, i64>(4),
        updated_at_unix: row.get::<_, i64>(5),
    }
}

fn api_key_from_row(row: &PostgresRow) -> Result<StoredApiKey, StorageError> {
    let id = row.get::<_, String>(0);
    let workspace_id = row.get::<_, String>(1);
    let tenant_id = row.get::<_, String>(2);
    let project_id = row.get::<_, String>(3);
    let scopes = deserialize_storage_document(&row.get::<_, String>(9))?;
    Ok(StoredApiKey {
        id: id.clone(),
        workspace_id: workspace_id.clone(),
        tenant_id: tenant_id.clone(),
        project_id: project_id.clone(),
        name: row.get::<_, String>(4),
        key_prefix: row.get::<_, String>(5),
        key_hash: row.get::<_, String>(6),
        last4: row.get::<_, String>(7),
        enabled: row.get::<_, bool>(8),
        scopes,
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
        tenant: api_key_tenant_context(&id, &tenant_id, &project_id, &workspace_id),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        created_at_unix: nonnegative_u64(row.get::<_, i64>(10)),
        updated_at_unix: nonnegative_u64(row.get::<_, i64>(11)),
        rotated_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        expires_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        revoked_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
    })
}

fn project_from_row(row: &PostgresRow) -> StoredProject {
    StoredProject {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        name: row.get::<_, String>(2),
        slug: row.get::<_, String>(3),
        status: row.get::<_, String>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

fn workspace_from_row(row: &PostgresRow) -> StoredWorkspace {
    StoredWorkspace {
        id: row.get::<_, String>(0),
        project_id: row.get::<_, String>(1),
        tenant_id: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        slug: row.get::<_, String>(4),
        environment: row.get::<_, String>(5),
        status: row.get::<_, String>(6),
        created_at_unix: row.get::<_, i64>(7),
        updated_at_unix: row.get::<_, i64>(8),
    }
}

fn tenant_account_from_tuple(
    row: (String, String, String, String, i64, i64),
) -> StoredTenantAccount {
    let (id, name, slug, status, created_at_unix, updated_at_unix) = row;
    StoredTenantAccount {
        id,
        name,
        slug,
        status,
        created_at_unix,
        updated_at_unix,
    }
}

fn project_from_tuple(row: (String, String, String, String, String, i64, i64)) -> StoredProject {
    let (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) = row;
    StoredProject {
        id,
        tenant_id,
        name,
        slug,
        status,
        created_at_unix,
        updated_at_unix,
    }
}

/// MySQL row shape for the `workspaces` table, in SELECT column order.
type WorkspaceRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
);

fn workspace_from_tuple(row: WorkspaceRow) -> StoredWorkspace {
    let (
        id,
        project_id,
        tenant_id,
        name,
        slug,
        environment,
        status,
        created_at_unix,
        updated_at_unix,
    ) = row;
    StoredWorkspace {
        id,
        project_id,
        tenant_id,
        name,
        slug,
        environment,
        status,
        created_at_unix,
        updated_at_unix,
    }
}

fn resolve_scope_from_workspace(workspace: &StoredWorkspace) -> WorkspaceScope {
    WorkspaceScope::new(
        workspace.tenant_id.clone(),
        workspace.project_id.clone(),
        workspace.id.clone(),
    )
}

fn api_key_tenant_context(
    id: &str,
    tenant_id: &str,
    project_id: &str,
    workspace_id: &str,
) -> TenantContext {
    TenantContext {
        organization_id: Some(tenant_id.to_string()),
        team_id: None,
        project_id: Some(project_id.to_string()),
        workspace_id: Some(workspace_id.to_string()),
        user_id: None,
        api_key_id: Some(id.to_string()),
    }
}

fn tenant_storage_key(tenant: &TenantContext) -> String {
    tenant_parts_storage_key(
        tenant.organization_id.as_deref(),
        tenant.team_id.as_deref(),
        tenant.project_id.as_deref(),
        tenant.user_id.as_deref(),
        tenant.api_key_id.as_deref(),
    )
}

fn tenant_parts_storage_key(
    organization_id: Option<&str>,
    team_id: Option<&str>,
    project_id: Option<&str>,
    user_id: Option<&str>,
    api_key_id: Option<&str>,
) -> String {
    [
        ("org", organization_id),
        ("team", team_id),
        ("project", project_id),
        ("user", user_id),
        ("api_key", api_key_id),
    ]
    .into_iter()
    .map(|(name, value)| format!("{name}:{}", value.unwrap_or("")))
    .collect::<Vec<_>>()
    .join("|")
}

fn usage_aggregate_id(tenant: &TenantContext, logical_model: &str, provider: &str) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        tenant.organization_id.as_deref().unwrap_or("_"),
        tenant.project_id.as_deref().unwrap_or("_"),
        tenant.api_key_id.as_deref().unwrap_or("_"),
        logical_model,
        provider
    )
}

fn upsert_tenant_context(
    transaction: &mut PostgresTransaction<'_>,
    id: &str,
    tenant: &TenantContext,
) -> Result<(), postgres::Error> {
    upsert_tenant_context_parts(
        transaction,
        id,
        tenant.organization_id.as_deref(),
        tenant.team_id.as_deref(),
        tenant.project_id.as_deref(),
        tenant.user_id.as_deref(),
        tenant.api_key_id.as_deref(),
    )
}

fn upsert_tenant_context_parts(
    transaction: &mut PostgresTransaction<'_>,
    id: &str,
    organization_id: Option<&str>,
    team_id: Option<&str>,
    project_id: Option<&str>,
    user_id: Option<&str>,
    api_key_id: Option<&str>,
) -> Result<(), postgres::Error> {
    transaction.execute(
        "INSERT INTO tenant_contexts \
         (id, organization_id, team_id, project_id, user_id, api_key_id) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (id) DO NOTHING",
        &[
            &id,
            &organization_id,
            &team_id,
            &project_id,
            &user_id,
            &api_key_id,
        ],
    )?;
    Ok(())
}

fn upsert_usage_rollup_delta(
    transaction: &mut PostgresTransaction<'_>,
    rollup: &UsageRollupUpsert<'_>,
) -> Result<(), postgres::Error> {
    transaction.execute(
        "INSERT INTO usage_aggregate_rollups \
         (id, tenant_context_id, logical_model, provider, prompt_tokens, completion_tokens, \
          total_tokens, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (id) DO UPDATE SET \
         prompt_tokens = usage_aggregate_rollups.prompt_tokens + EXCLUDED.prompt_tokens, \
         completion_tokens = usage_aggregate_rollups.completion_tokens + EXCLUDED.completion_tokens, \
         total_tokens = usage_aggregate_rollups.total_tokens + EXCLUDED.total_tokens, \
         updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
        &[
            &rollup.id,
            &rollup.tenant_context_id,
            &rollup.logical_model,
            &rollup.provider,
            &rollup.prompt_tokens,
            &rollup.completion_tokens,
            &rollup.total_tokens,
        ],
    )?;
    Ok(())
}

fn replace_usage_rollup(
    transaction: &mut PostgresTransaction<'_>,
    rollup: &UsageRollupUpsert<'_>,
) -> Result<(), postgres::Error> {
    transaction.execute(
        "INSERT INTO usage_aggregate_rollups \
         (id, tenant_context_id, logical_model, provider, prompt_tokens, completion_tokens, \
          total_tokens, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (id) DO UPDATE SET \
         tenant_context_id = EXCLUDED.tenant_context_id, \
         logical_model = EXCLUDED.logical_model, \
         provider = EXCLUDED.provider, \
         prompt_tokens = EXCLUDED.prompt_tokens, \
         completion_tokens = EXCLUDED.completion_tokens, \
         total_tokens = EXCLUDED.total_tokens, \
         updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
        &[
            &rollup.id,
            &rollup.tenant_context_id,
            &rollup.logical_model,
            &rollup.provider,
            &rollup.prompt_tokens,
            &rollup.completion_tokens,
            &rollup.total_tokens,
        ],
    )?;
    Ok(())
}

struct UsageRollupUpsert<'a> {
    id: &'a str,
    tenant_context_id: &'a str,
    logical_model: &'a str,
    provider: &'a str,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
}

fn billing_event_from_row(row: PostgresRow) -> BillingEvent {
    BillingEvent {
        request_id: row.get(0),
        trace_id: row.get(1),
        agent_run_id: row.get(2),
        workflow_id: row.get(3),
        workflow_version: row.get::<_, Option<i32>>(4).map(|value| value as u32),
        workflow_node_id: row.get(5),
        cluster_id: row.get(6),
        node_id: row.get(7),
        status_code: row.get::<_, i32>(8).clamp(0, i32::from(u16::MAX)) as u16,
        occurred_at_unix: Some(nonnegative_u64(row.get(9))),
        tenant: TenantContext {
            workspace_id: None,
            organization_id: row.get(10),
            team_id: row.get(11),
            project_id: row.get(12),
            user_id: row.get(13),
            api_key_id: row.get(14),
        },
        logical_model: row.get(15),
        provider: row.get(16),
        provider_model: row.get(17),
        usage: TokenUsage {
            prompt_tokens: nonnegative_u64(row.get(18)),
            completion_tokens: nonnegative_u64(row.get(19)),
            total_tokens: nonnegative_u64(row.get(20)),
        },
        usage_source: billing_usage_source_from_str(row.get::<_, String>(21).as_str()),
    }
}

fn usage_aggregate_from_row(row: PostgresRow) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: row.get(0),
        organization_id: row.get(1),
        project_id: row.get(2),
        api_key_id: row.get(3),
        logical_model: row.get(4),
        provider: row.get(5),
        usage: TokenUsage {
            prompt_tokens: nonnegative_u64(row.get(6)),
            completion_tokens: nonnegative_u64(row.get(7)),
            total_tokens: nonnegative_u64(row.get(8)),
        },
    }
}

fn managed_worker_template_from_row(row: PostgresRow) -> StoredManagedWorkerTemplate {
    StoredManagedWorkerTemplate {
        id: row.get(0),
        framework_adapter: row.get(1),
        isolation_backend_kind: row.get(2),
        enabled: row.get(3),
        max_tenant_sessions: row
            .get::<_, Option<i64>>(4)
            .and_then(|value| u32::try_from(value).ok()),
        max_workspace_sessions: row
            .get::<_, Option<i64>>(5)
            .and_then(|value| u32::try_from(value).ok()),
        created_at_unix: Some(nonnegative_u64(row.get(6))),
        updated_at_unix: Some(nonnegative_u64(row.get(7))),
    }
}

fn agent_worker_instance_from_row(row: PostgresRow) -> StoredAgentWorkerInstance {
    StoredAgentWorkerInstance {
        id: row.get(0),
        process_name: row.get(1),
        host_id: row.get(2),
        worker_version: row.get(3),
        status: row.get(4),
        started_at_unix: Some(nonnegative_u64(row.get(5))),
        last_seen_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        process_json: row.get(7),
    }
}

fn managed_worker_session_from_row(row: PostgresRow) -> StoredManagedWorkerSession {
    StoredManagedWorkerSession {
        id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        worker_template_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        isolation_backend_kind: row.get(7),
        microvm_id: row.get(8),
        capability_envelope_id: row.get(9),
        requested_at_unix: Some(nonnegative_u64(row.get(10))),
        started_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        completed_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        cleanup_completed_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        capability_envelope_json: row.get(14),
        resource_limits_json: row.get(15),
    }
}

fn managed_worker_lifecycle_event_from_row(row: PostgresRow) -> StoredManagedWorkerLifecycleEvent {
    StoredManagedWorkerLifecycleEvent {
        id: row.get(0),
        session_id: row.get(1),
        run_id: row.get(2),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(3).as_deref()),
        workspace_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        action: row.get(7),
        outcome: row.get(8),
        occurred_at_unix: Some(nonnegative_u64(row.get(9))),
        evidence_json: row.get(10),
    }
}

fn managed_worker_isolation_selection_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationSelection {
    StoredManagedWorkerIsolationSelection {
        session_id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        agent_worker_instance_id: row.get(4),
        backend_name: row.get(5),
        backend_version: row.get(6),
        backend_kind: row.get(7),
        host_lifecycle_owner: row.get(8),
        gateway_controls_backend: row.get(9),
        capability_envelope_id: row.get(10),
        selected_at_unix: Some(nonnegative_u64(row.get(11))),
    }
}

fn managed_worker_isolation_policy_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationPolicy {
    StoredManagedWorkerIsolationPolicy {
        session_id: row.get(0),
        cpu_count: u16::try_from(row.get::<_, i32>(1)).unwrap_or_default(),
        memory_mib: u32::try_from(row.get::<_, i32>(2)).unwrap_or_default(),
        disk_mib: u32::try_from(row.get::<_, i32>(3)).unwrap_or_default(),
        max_runtime_millis: row.get::<_, Option<i64>>(4).map(nonnegative_u64),
        direct_public_egress: row.get(5),
        gateway_control_channel: row.get(6),
        governed_egress: row.get(7),
        read_only_rootfs: row.get(8),
        writable_workspace: row.get(9),
        host_path_mounts: row.get(10),
    }
}

fn managed_worker_isolation_evidence_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationEvidence {
    StoredManagedWorkerIsolationEvidence {
        id: row.get(0),
        session_id: row.get(1),
        lifecycle_event_id: row.get(2),
        run_id: row.get(3),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(4).as_deref()),
        workspace_id: row.get(5),
        agent_worker_instance_id: row.get(6),
        isolation_instance_id: row.get(7),
        action: row.get(8),
        outcome: row.get(9),
        failure_reason: row.get(10),
        occurred_at_unix: Some(nonnegative_u64(row.get(11))),
        evidence_json: row.get(12),
    }
}

fn self_hosted_worker_registration_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerRegistration {
    StoredSelfHostedWorkerRegistration {
        id: row.get(0),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(1).as_deref()),
        workspace_id: row.get(2),
        worker_name: row.get(3),
        status: row.get(4),
        identity_fingerprint: row.get(5),
        identity_expires_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        orchestration_enabled: row.get(7),
        registered_at_unix: Some(nonnegative_u64(row.get(8))),
        last_seen_at_unix: row.get::<_, Option<i64>>(9).map(nonnegative_u64),
        trust_level: row.get(10),
        capability_envelope_json: row.get(11),
    }
}

fn self_hosted_worker_heartbeat_from_row(row: PostgresRow) -> StoredSelfHostedWorkerHeartbeat {
    StoredSelfHostedWorkerHeartbeat {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        status: row.get(4),
        reported_at_unix: Some(nonnegative_u64(row.get(5))),
        observed_at_unix: Some(nonnegative_u64(row.get(6))),
        heartbeat_json: row.get(7),
    }
}

fn self_hosted_worker_telemetry_event_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerTelemetryEvent {
    StoredSelfHostedWorkerTelemetryEvent {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        kind: row.get(6),
        trust_level: row.get(7),
        occurred_at_unix: Some(nonnegative_u64(row.get(8))),
        ingested_at_unix: Some(nonnegative_u64(row.get(9))),
        event_json: row.get(10),
    }
}

fn self_hosted_worker_artifact_from_row(row: PostgresRow) -> StoredSelfHostedWorkerArtifact {
    StoredSelfHostedWorkerArtifact {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        artifact_name: row.get(6),
        content_type: row.get(7),
        size_bytes: nonnegative_u64(row.get(8)),
        trust_level: row.get(9),
        created_at_unix: Some(nonnegative_u64(row.get(10))),
        artifact_json: row.get(11),
    }
}

fn self_hosted_worker_checkpoint_from_row(row: PostgresRow) -> StoredSelfHostedWorkerCheckpoint {
    StoredSelfHostedWorkerCheckpoint {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        checkpoint_name: row.get(6),
        size_bytes: nonnegative_u64(row.get(7)),
        trust_level: row.get(8),
        created_at_unix: Some(nonnegative_u64(row.get(9))),
        checkpoint_json: row.get(10),
    }
}

fn self_hosted_run_dispatch_from_row(
    row: PostgresRow,
    capabilities: &HashMap<String, Vec<String>>,
) -> StoredSelfHostedRunDispatch {
    let dispatch_id = row.get::<_, String>(0);
    StoredSelfHostedRunDispatch {
        required_capabilities: capabilities.get(&dispatch_id).cloned().unwrap_or_default(),
        dispatch_id,
        action: row.get(1),
        tenant_id: row.get::<_, Option<String>>(2).unwrap_or_default(),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        framework_adapter: row.get(6),
        workload_ref: row.get(7),
        queued_at_unix: Some(nonnegative_u64(row.get(8))),
        assigned_worker_id: row.get(9),
        lease_id: row.get(10),
        lease_expires_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        attempt: nonnegative_u32(row.get(12)),
        acknowledged_status: row.get(13),
        acknowledged_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
    }
}

fn tenant_from_storage_key(value: Option<&str>) -> TenantContext {
    let mut tenant = TenantContext::default();
    let Some(value) = value else {
        return tenant;
    };
    for part in value.split('|') {
        let Some((name, raw_value)) = part.split_once(':') else {
            continue;
        };
        let parsed = if raw_value.is_empty() {
            None
        } else {
            Some(raw_value.to_string())
        };
        match name {
            "org" => tenant.organization_id = parsed,
            "team" => tenant.team_id = parsed,
            "project" => tenant.project_id = parsed,
            "user" => tenant.user_id = parsed,
            "api_key" => tenant.api_key_id = parsed,
            _ => {}
        }
    }
    tenant
}

fn billing_usage_source_from_str(value: &str) -> ferrogate_billing::BillingUsageSource {
    match value {
        "gateway_estimate" => ferrogate_billing::BillingUsageSource::GatewayEstimate,
        _ => ferrogate_billing::BillingUsageSource::ProviderUsage,
    }
}

#[derive(Debug)]
enum RuntimeControlPlaneBackend {
    Memory(Box<Mutex<RuntimeControlPlaneState>>),
    Postgres(Arc<PostgresControlPlaneStore>),
    Mysql(Arc<MySqlControlPlaneStore>),
}

impl RuntimeControlPlaneState {
    pub fn new() -> Self {
        Self {
            api_keys: InMemoryRepository::new(),
            api_key_records: InMemoryRepository::new(),
            tenants: InMemoryRepository::new(),
            policies: InMemoryRepository::new(),
            gateway_configs: InMemoryRepository::new(),
            agent_workflows: InMemoryRepository::new(),
            skill_packages: InMemoryRepository::new(),
            prompt_templates: InMemoryRepository::new(),
            plugin_registrations: InMemoryRepository::new(),
            mcp_servers: InMemoryRepository::new(),
            agent_upstreams: InMemoryRepository::new(),
            tool_approvals: InMemoryRepository::new(),
            tenant_accounts: InMemoryRepository::new(),
            projects: InMemoryRepository::new(),
            workspaces: InMemoryRepository::new(),
        }
    }

    pub fn upsert_tenant_account(&mut self, account: StoredTenantAccount) {
        self.tenant_accounts.insert(account.id.clone(), account);
    }

    pub fn get_tenant_account(&self, id: &str) -> Option<StoredTenantAccount> {
        self.tenant_accounts.get(id)
    }

    pub fn list_tenant_accounts(&self) -> Vec<StoredTenantAccount> {
        self.tenant_accounts.list()
    }

    pub fn delete_tenant_account(&mut self, id: &str) -> bool {
        self.tenant_accounts.remove(id).is_some()
    }

    pub fn upsert_project(&mut self, project: StoredProject) {
        self.projects.insert(project.id.clone(), project);
    }

    pub fn get_project(&self, id: &str) -> Option<StoredProject> {
        self.projects.get(id)
    }

    pub fn list_projects(&self) -> Vec<StoredProject> {
        self.projects.list()
    }

    pub fn delete_project(&mut self, id: &str) -> bool {
        self.projects.remove(id).is_some()
    }

    pub fn upsert_workspace(&mut self, workspace: StoredWorkspace) {
        self.workspaces.insert(workspace.id.clone(), workspace);
    }

    pub fn get_workspace(&self, id: &str) -> Option<StoredWorkspace> {
        self.workspaces.get(id)
    }

    pub fn list_workspaces(&self) -> Vec<StoredWorkspace> {
        self.workspaces.list()
    }

    pub fn delete_workspace(&mut self, id: &str) -> bool {
        self.workspaces.remove(id).is_some()
    }

    /// Resolve a workspace id to its full attribution chain using the workspace's
    /// stored `tenant_id`/`project_id`. Returns `None` when the workspace is unknown.
    pub fn resolve_workspace_scope(&self, workspace_id: &str) -> Option<WorkspaceScope> {
        self.workspaces
            .get(workspace_id)
            .map(|workspace| resolve_scope_from_workspace(&workspace))
    }

    pub fn from_documents(documents: ControlPlaneDocuments) -> Self {
        let mut state = Self::new();
        for (id, document_json) in documents.api_keys {
            state.upsert_api_key(id, document_json);
        }
        for (id, document_json) in documents.tenants {
            state.upsert_tenant(id, document_json);
        }
        for (id, document_json) in documents.policies {
            state.upsert_policy(id, document_json);
        }
        for (id, document_json) in documents.gateway_configs {
            state.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in documents.agent_workflows {
            state.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in documents.skill_packages {
            state.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in documents.prompt_templates {
            state.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in documents.plugin_registrations {
            state.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in documents.mcp_servers {
            state.upsert_mcp_server(id, document_json);
        }
        for (id, document_json) in documents.agent_upstreams {
            state.upsert_agent_upstream(id, document_json);
        }
        state
    }

    pub fn replace_config_documents(&mut self, documents: ControlPlaneDocuments) {
        self.api_keys = InMemoryRepository::new();
        self.tenants = InMemoryRepository::new();
        self.policies = InMemoryRepository::new();
        self.gateway_configs = InMemoryRepository::new();
        self.agent_workflows = InMemoryRepository::new();
        self.skill_packages = InMemoryRepository::new();
        self.prompt_templates = InMemoryRepository::new();
        self.plugin_registrations = InMemoryRepository::new();
        self.mcp_servers = InMemoryRepository::new();
        self.agent_upstreams = InMemoryRepository::new();
        for (id, document_json) in documents.api_keys {
            self.upsert_api_key(id, document_json);
        }
        for (id, document_json) in documents.tenants {
            self.upsert_tenant(id, document_json);
        }
        for (id, document_json) in documents.policies {
            self.upsert_policy(id, document_json);
        }
        for (id, document_json) in documents.gateway_configs {
            self.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in documents.agent_workflows {
            self.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in documents.skill_packages {
            self.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in documents.prompt_templates {
            self.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in documents.plugin_registrations {
            self.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in documents.mcp_servers {
            self.upsert_mcp_server(id, document_json);
        }
        for (id, document_json) in documents.agent_upstreams {
            self.upsert_agent_upstream(id, document_json);
        }
    }

    pub fn snapshot(&self) -> ControlPlaneSnapshot {
        let documents = self.documents();
        ControlPlaneSnapshot {
            api_keys: into_document_json(documents.api_keys),
            tenants: into_document_json(documents.tenants),
            policies: into_document_json(documents.policies),
            gateway_configs: into_document_json(documents.gateway_configs),
            agent_workflows: into_document_json(documents.agent_workflows),
            skill_packages: into_document_json(documents.skill_packages),
            prompt_templates: into_document_json(documents.prompt_templates),
            plugin_registrations: into_document_json(documents.plugin_registrations),
            mcp_servers: into_document_json(documents.mcp_servers),
            agent_upstreams: into_document_json(documents.agent_upstreams),
        }
    }

    pub fn documents(&self) -> ControlPlaneDocuments {
        ControlPlaneDocuments {
            api_keys: sorted_control_plane_documents(&self.api_keys),
            tenants: sorted_control_plane_documents(&self.tenants),
            policies: sorted_control_plane_documents(&self.policies),
            gateway_configs: sorted_control_plane_documents(&self.gateway_configs),
            agent_workflows: sorted_control_plane_documents(&self.agent_workflows),
            skill_packages: sorted_control_plane_documents(&self.skill_packages),
            prompt_templates: sorted_control_plane_documents(&self.prompt_templates),
            plugin_registrations: sorted_control_plane_documents(&self.plugin_registrations),
            mcp_servers: sorted_control_plane_documents(&self.mcp_servers),
            agent_upstreams: sorted_control_plane_documents(&self.agent_upstreams),
        }
    }

    pub fn upsert_api_key(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.api_keys.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "api_key".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_api_key(&mut self, id: &str) -> bool {
        self.api_keys.remove(id).is_some()
    }

    pub fn upsert_api_key_record(&mut self, api_key: StoredApiKey) {
        self.api_key_records.insert(api_key.id.clone(), api_key);
    }

    pub fn get_api_key_record(&self, id: &str) -> Option<StoredApiKey> {
        self.api_key_records.get(id)
    }

    pub fn list_api_key_records(&self) -> Vec<StoredApiKey> {
        self.api_key_records.list()
    }

    pub fn find_api_key_records_by_prefix(&self, key_prefix: &str) -> Vec<StoredApiKey> {
        self.api_key_records
            .list()
            .into_iter()
            .filter(|api_key| api_key.key_prefix == key_prefix)
            .collect()
    }

    pub fn upsert_tenant(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.tenants.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "tenant".into(),
                id,
                document_json,
            },
        );
    }

    pub fn upsert_policy(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.policies.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "policy".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_policy(&mut self, id: &str) -> bool {
        self.policies.remove(id).is_some()
    }

    pub fn upsert_gateway_config(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.gateway_configs.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "gateway_config".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_gateway_config(&mut self, id: &str) -> bool {
        self.gateway_configs.remove(id).is_some()
    }

    pub fn upsert_agent_workflow(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.agent_workflows.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "agent_workflow".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_agent_workflow(&mut self, id: &str) -> bool {
        self.agent_workflows.remove(id).is_some()
    }

    pub fn upsert_skill_package(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.skill_packages.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "skill_package".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_skill_package(&mut self, id: &str) -> bool {
        self.skill_packages.remove(id).is_some()
    }

    pub fn upsert_prompt_template(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.prompt_templates.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "prompt_template".into(),
                id,
                document_json,
            },
        );
    }

    pub fn upsert_mcp_server(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.mcp_servers.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "mcp_server".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_mcp_server(&mut self, id: &str) -> bool {
        self.mcp_servers.remove(id).is_some()
    }

    pub fn upsert_agent_upstream(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.agent_upstreams.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "agent_upstream".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_agent_upstream(&mut self, id: &str) -> bool {
        self.agent_upstreams.remove(id).is_some()
    }

    pub fn upsert_plugin_registration(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.plugin_registrations.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "plugin_registration".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_plugin_registration(&mut self, id: &str) -> bool {
        self.plugin_registrations.remove(id).is_some()
    }

    pub fn upsert_tool_approval(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.tool_approvals.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "tool_approval".into(),
                id,
                document_json,
            },
        );
    }

    pub fn tool_approval(&self, id: &str) -> Option<String> {
        self.tool_approvals
            .get(id)
            .map(|resource| resource.document_json)
    }

    pub fn tool_approvals(&self) -> Vec<String> {
        into_document_json(self.tool_approval_documents())
    }

    pub fn tool_approval_documents(&self) -> Vec<(String, String)> {
        sorted_control_plane_documents(&self.tool_approvals)
    }
}

impl Default for RuntimeControlPlaneState {
    fn default() -> Self {
        Self::new()
    }
}

fn sorted_control_plane_documents(
    repository: &InMemoryRepository<StoredControlPlaneResource>,
) -> Vec<(String, String)> {
    let mut documents = repository
        .list()
        .into_iter()
        .map(|resource| (resource.id, resource.document_json))
        .collect::<Vec<_>>();
    documents.sort_by(|left, right| left.0.cmp(&right.0));
    documents
}

fn into_document_json(documents: Vec<(String, String)>) -> Vec<String> {
    documents
        .into_iter()
        .map(|(_, document_json)| document_json)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredApiKey {
    pub id: String,
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub key_prefix: String,
    pub key_hash: String,
    #[serde(default)]
    pub last4: String,
    pub enabled: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub tenant: TenantContext,
    #[serde(default)]
    pub monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
    #[serde(default)]
    pub rotated_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTenant {
    pub id: String,
    pub name: String,
    pub tenant: TenantContext,
}

/// Top-level tenant account (billing / isolation boundary) in the
/// Tenant -> Project -> Workspace hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTenantAccount {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Project (business line) nested under a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProject {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Workspace (environment such as dev/staging/prod) nested under a project.
/// `tenant_id` is stored redundantly so top-level isolation and aggregation can
/// filter workspaces without a join back through `projects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkspace {
    pub id: String,
    pub project_id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

fn default_active_status() -> String {
    "active".to_string()
}

fn default_environment() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPolicyRule {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub organization_ids: Vec<String>,
    pub project_ids: Vec<String>,
    pub api_key_ids: Vec<String>,
    pub models: Vec<String>,
    pub providers: Vec<String>,
    pub code: String,
    pub message: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequestLog {
    pub request_id: String,
    pub trace_id: Option<String>,
    #[serde(default)]
    pub agent_run_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow_version: Option<u32>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    pub cluster_id: Option<String>,
    pub node_id: Option<String>,
    pub tenant: TenantContext,
    pub route: Option<String>,
    pub provider: Option<String>,
    pub logical_model: Option<String>,
    pub provider_model: Option<String>,
    #[serde(default)]
    pub gateway_config_id: Option<String>,
    #[serde(default)]
    pub gateway_config_revision: Option<u32>,
    pub status_code: u16,
    pub error_code: Option<String>,
    pub prompt_recorded: bool,
    pub response_recorded: bool,
    pub prompt_body: Option<String>,
    pub response_body: Option<String>,
    #[serde(default)]
    pub cache_status: Option<String>,
    pub started_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAuditEvent {
    pub id: String,
    pub request_id: String,
    pub trace_id: Option<String>,
    #[serde(default)]
    pub agent_run_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow_version: Option<u32>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    pub cluster_id: Option<String>,
    pub node_id: Option<String>,
    pub actor_api_key_id: Option<String>,
    #[serde(default)]
    pub tenant: TenantContext,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub message: String,
    pub occurred_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredUsageAggregate {
    pub id: String,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub logical_model: String,
    pub provider: String,
    pub usage: TokenUsage,
}

#[derive(Debug, Default)]
pub struct InMemoryRepository<T> {
    records: HashMap<String, T>,
}

impl<T> InMemoryRepository<T> {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn insert(&mut self, id: impl Into<String>, record: T) {
        self.records.insert(id.into(), record);
    }

    pub fn remove(&mut self, id: &str) -> Option<T> {
        self.records.remove(id)
    }
}

impl<T: Clone> Repository<T> for InMemoryRepository<T> {
    fn get(&self, id: &str) -> Option<T> {
        self.records.get(id).cloned()
    }

    fn list(&self) -> Vec<T> {
        self.records.values().cloned().collect()
    }
}

impl ApiKeyRepository for InMemoryRepository<StoredApiKey> {}

impl TenantRepository for InMemoryRepository<StoredTenant> {}

impl PolicyRepository for InMemoryRepository<StoredPolicyRule> {}

impl UsageAggregateRepository for InMemoryRepository<StoredUsageAggregate> {}

impl AgentRunRepository for InMemoryRepository<StoredAgentRun> {}

impl ManagedWorkerTemplateRepository for InMemoryRepository<StoredManagedWorkerTemplate> {}

impl AgentWorkerInstanceRepository for InMemoryRepository<StoredAgentWorkerInstance> {}

impl ManagedWorkerSessionRepository for InMemoryRepository<StoredManagedWorkerSession> {}

#[derive(Debug, Default)]
pub struct InMemoryAppendRepository<T> {
    records: VecDeque<T>,
    retention_limit: Option<usize>,
    appended_total: u64,
}

impl<T> InMemoryAppendRepository<T> {
    pub fn new() -> Self {
        Self {
            records: VecDeque::new(),
            retention_limit: None,
            appended_total: 0,
        }
    }

    pub fn with_retention_limit(retention_limit: usize) -> Self {
        Self {
            records: VecDeque::new(),
            retention_limit: Some(retention_limit),
            appended_total: 0,
        }
    }

    pub fn set_retention_limit(&mut self, retention_limit: usize) {
        self.retention_limit = Some(retention_limit);
        self.enforce_retention_limit();
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn appended_total(&self) -> u64 {
        self.appended_total
    }

    pub fn list_paginated(&self, offset: usize, limit: usize) -> Vec<T>
    where
        T: Clone,
    {
        self.records
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    fn enforce_retention_limit(&mut self) {
        if let Some(limit) = self.retention_limit {
            while self.records.len() > limit {
                self.records.pop_front();
            }
        }
    }
}

impl<T: Clone> AppendRepository<T> for InMemoryAppendRepository<T> {
    fn append(&mut self, record: T) {
        self.records.push_back(record);
        self.appended_total = self.appended_total.saturating_add(1);
        self.enforce_retention_limit();
    }

    fn list(&self) -> Vec<T> {
        self.records.iter().cloned().collect()
    }
}

impl RequestLogRepository for InMemoryAppendRepository<StoredRequestLog> {}

impl AuditLogRepository for InMemoryAppendRepository<StoredAuditEvent> {}

impl BillingEventRepository for InMemoryAppendRepository<BillingEvent> {}

impl AgentRunEventRepository for InMemoryAppendRepository<StoredAgentRunEvent> {}

impl ManagedWorkerLifecycleEventRepository
    for InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>
{
}

impl SelfHostedWorkerRegistrationRepository
    for InMemoryRepository<StoredSelfHostedWorkerRegistration>
{
}

impl SelfHostedWorkerHeartbeatRepository
    for InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>
{
}

impl SelfHostedWorkerTelemetryEventRepository
    for InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>
{
}

impl SelfHostedWorkerArtifactRepository for InMemoryRepository<StoredSelfHostedWorkerArtifact> {}

impl SelfHostedWorkerCheckpointRepository for InMemoryRepository<StoredSelfHostedWorkerCheckpoint> {}

impl SelfHostedRunDispatchRepository for InMemoryRepository<StoredSelfHostedRunDispatch> {}

#[derive(Debug)]
pub struct RuntimeStorageRepositories {
    backend: RuntimeStorageBackend,
    control_plane: RuntimeControlPlaneBackend,
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    agent_run_events: Mutex<InMemoryAppendRepository<StoredAgentRunEvent>>,
    managed_worker_templates: Mutex<InMemoryRepository<StoredManagedWorkerTemplate>>,
    agent_worker_instances: Mutex<InMemoryRepository<StoredAgentWorkerInstance>>,
    managed_worker_sessions: Mutex<InMemoryRepository<StoredManagedWorkerSession>>,
    managed_worker_lifecycle_events:
        Mutex<InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>>,
    managed_worker_isolation_selections:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationSelection>>,
    managed_worker_isolation_policies:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationPolicy>>,
    managed_worker_isolation_evidence:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationEvidence>>,
    self_hosted_worker_registrations: Mutex<InMemoryRepository<StoredSelfHostedWorkerRegistration>>,
    self_hosted_worker_heartbeats: Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>>,
    self_hosted_worker_telemetry_events:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>>,
    self_hosted_worker_artifacts: Mutex<InMemoryRepository<StoredSelfHostedWorkerArtifact>>,
    self_hosted_worker_checkpoints: Mutex<InMemoryRepository<StoredSelfHostedWorkerCheckpoint>>,
    self_hosted_run_dispatches: Mutex<InMemoryRepository<StoredSelfHostedRunDispatch>>,
}

struct RuntimeStorageRepositorySets {
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    agent_run_events: Mutex<InMemoryAppendRepository<StoredAgentRunEvent>>,
    managed_worker_templates: Mutex<InMemoryRepository<StoredManagedWorkerTemplate>>,
    agent_worker_instances: Mutex<InMemoryRepository<StoredAgentWorkerInstance>>,
    managed_worker_sessions: Mutex<InMemoryRepository<StoredManagedWorkerSession>>,
    managed_worker_lifecycle_events:
        Mutex<InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>>,
    managed_worker_isolation_selections:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationSelection>>,
    managed_worker_isolation_policies:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationPolicy>>,
    managed_worker_isolation_evidence:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationEvidence>>,
    self_hosted_worker_registrations: Mutex<InMemoryRepository<StoredSelfHostedWorkerRegistration>>,
    self_hosted_worker_heartbeats: Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>>,
    self_hosted_worker_telemetry_events:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>>,
    self_hosted_worker_artifacts: Mutex<InMemoryRepository<StoredSelfHostedWorkerArtifact>>,
    self_hosted_worker_checkpoints: Mutex<InMemoryRepository<StoredSelfHostedWorkerCheckpoint>>,
    self_hosted_run_dispatches: Mutex<InMemoryRepository<StoredSelfHostedRunDispatch>>,
}

impl RuntimeStorageRepositorySets {
    fn new(request_log_retention_records: usize, audit_event_retention_records: usize) -> Self {
        Self {
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            agent_run_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_templates: Mutex::new(InMemoryRepository::new()),
            agent_worker_instances: Mutex::new(InMemoryRepository::new()),
            managed_worker_sessions: Mutex::new(InMemoryRepository::new()),
            managed_worker_lifecycle_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_isolation_selections: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_policies: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_evidence: Mutex::new(InMemoryRepository::new()),
            self_hosted_worker_registrations: Mutex::new(InMemoryRepository::new()),
            self_hosted_worker_heartbeats: Mutex::new(InMemoryAppendRepository::new()),
            self_hosted_worker_telemetry_events: Mutex::new(InMemoryAppendRepository::new()),
            self_hosted_worker_artifacts: Mutex::new(InMemoryRepository::new()),
            self_hosted_worker_checkpoints: Mutex::new(InMemoryRepository::new()),
            self_hosted_run_dispatches: Mutex::new(InMemoryRepository::new()),
        }
    }
}

impl RuntimeStorageRepositories {
    pub fn new(
        backend: RuntimeStorageBackend,
        control_plane: RuntimeControlPlaneState,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        let repositories = RuntimeStorageRepositorySets::new(
            request_log_retention_records,
            audit_event_retention_records,
        );
        Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Memory(Box::new(Mutex::new(control_plane))),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
        }
    }

    pub fn in_memory(
        provider_order: Vec<StorageProviderKind>,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        Self::new(
            RuntimeStorageBackend::in_memory(provider_order),
            RuntimeControlPlaneState::new(),
            request_log_retention_records,
            audit_event_retention_records,
        )
    }

    pub fn postgres(
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        Self::postgres_with_provider(StorageProviderKind::Postgres, config, options)
    }

    pub fn supabase(
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        Self::postgres_with_provider(StorageProviderKind::Supabase, config, options)
    }

    fn postgres_with_provider(
        provider: StorageProviderKind,
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            provider,
            options.required,
            options.provider_order,
            options.migration_mode,
        )?;
        let request_log_retention_records = options.request_log_retention_records;
        let audit_event_retention_records = options.audit_event_retention_records;
        let bootstrap = options.control_plane;
        let initialize_schema = options.initialize_schema;
        let control_plane = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    PostgresControlPlaneStore::connect(config, bootstrap, initialize_schema)
                })
                .join()
                .map_err(|_| {
                    StorageError::Postgres("postgres storage connect thread panicked".into())
                })?
        })?;
        let repositories = RuntimeStorageRepositorySets::new(
            request_log_retention_records,
            audit_event_retention_records,
        );
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
        })
    }

    pub fn supabase_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        Self::postgres_wire_for_migration(
            StorageProviderKind::Supabase,
            config,
            initialize_schema,
            validate_schema,
        )
    }

    pub fn postgres_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        Self::postgres_wire_for_migration(
            StorageProviderKind::Postgres,
            config,
            initialize_schema,
            validate_schema,
        )
    }

    pub fn mysql_for_migration(
        config: MySqlStorageConfig,
        initialize_schema: bool,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            StorageProviderKind::Mysql,
            true,
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            if initialize_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
        )?;
        let control_plane = MySqlControlPlaneStore::connect(
            config,
            ControlPlaneDocuments::default(),
            initialize_schema,
        )?;
        let repositories = RuntimeStorageRepositorySets::new(0, 0);
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Mysql(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
        })
    }

    fn postgres_wire_for_migration(
        provider: StorageProviderKind,
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            provider,
            true,
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            if initialize_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
        )?;
        let control_plane = PostgresControlPlaneStore::connect_for_migration(
            config,
            initialize_schema,
            validate_schema,
        )?;
        let repositories = RuntimeStorageRepositorySets::new(0, 0);
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
        })
    }

    pub fn mysql(
        config: MySqlStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            StorageProviderKind::Mysql,
            options.required,
            options.provider_order,
            options.migration_mode,
        )?;
        let request_log_retention_records = options.request_log_retention_records;
        let audit_event_retention_records = options.audit_event_retention_records;
        let bootstrap = options.control_plane;
        let initialize_schema = options.initialize_schema;
        let control_plane = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    MySqlControlPlaneStore::connect(config, bootstrap, initialize_schema)
                })
                .join()
                .map_err(|_| StorageError::Mysql("mysql storage connect thread panicked".into()))?
        })?;
        let repositories = RuntimeStorageRepositorySets::new(
            request_log_retention_records,
            audit_event_retention_records,
        );
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Mysql(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
        })
    }

    pub fn backend_evidence(&self) -> StorageBackendEvidence {
        let mut evidence = self.backend.evidence();
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            evidence.schema = Some(control_plane.schema_evidence());
        }
        evidence
    }

    pub fn control_plane_snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.snapshot())
                .unwrap_or_else(|_| ControlPlaneSnapshot {
                    api_keys: Vec::new(),
                    tenants: Vec::new(),
                    policies: Vec::new(),
                    gateway_configs: Vec::new(),
                    agent_workflows: Vec::new(),
                    skill_packages: Vec::new(),
                    prompt_templates: Vec::new(),
                    plugin_registrations: Vec::new(),
                    mcp_servers: Vec::new(),
                    agent_upstreams: Vec::new(),
                })),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.snapshot(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.snapshot(),
        }
    }

    pub fn replace_control_plane(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.replace_config_documents(documents);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.replace_kind("api_key", documents.api_keys)?;
                control_plane.replace_kind("tenant", documents.tenants)?;
                control_plane.replace_kind("policy", documents.policies)?;
                control_plane.replace_kind("gateway_config", documents.gateway_configs)?;
                control_plane.replace_kind("agent_workflow", documents.agent_workflows)?;
                control_plane.replace_kind("skill_package", documents.skill_packages)?;
                control_plane.replace_kind("prompt_template", documents.prompt_templates)?;
                control_plane
                    .replace_kind("plugin_registration", documents.plugin_registrations)?;
                control_plane.replace_kind("mcp_server", documents.mcp_servers)?;
                control_plane.replace_kind("agent_upstream", documents.agent_upstreams)?;
                Ok(())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.replace_kind("api_key", documents.api_keys)?;
                control_plane.replace_kind("tenant", documents.tenants)?;
                control_plane.replace_kind("policy", documents.policies)?;
                control_plane.replace_kind("gateway_config", documents.gateway_configs)?;
                control_plane.replace_kind("agent_workflow", documents.agent_workflows)?;
                control_plane.replace_kind("skill_package", documents.skill_packages)?;
                control_plane.replace_kind("prompt_template", documents.prompt_templates)?;
                control_plane
                    .replace_kind("plugin_registration", documents.plugin_registrations)?;
                control_plane.replace_kind("mcp_server", documents.mcp_servers)?;
                control_plane.replace_kind("agent_upstream", documents.agent_upstreams)?;
                Ok(())
            }
        }
    }

    pub fn export_migration_snapshot(&self) -> Result<StorageMigrationSnapshot, StorageError> {
        let control_plane = match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.documents())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.documents()?,
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.documents()?,
        };
        Ok(StorageMigrationSnapshot {
            control_plane,
            api_key_records: self.list_api_key_records()?,
            tool_approvals: self.control_plane_tool_approval_documents()?,
            billing_events: self.billing_events(),
            usage_aggregates: self.usage_aggregates(),
            request_logs: self.request_logs(),
            audit_events: self.audit_events(),
            agent_runs: self.agent_runs(),
            agent_run_events: self.agent_run_events(),
            managed_worker_templates: self.managed_worker_templates(),
            agent_worker_instances: self.agent_worker_instances(),
            managed_worker_sessions: self.managed_worker_sessions(),
            managed_worker_lifecycle_events: self.managed_worker_lifecycle_events(),
            managed_worker_isolation_selections: self.managed_worker_isolation_selections(),
            managed_worker_isolation_policies: self.managed_worker_isolation_policies(),
            managed_worker_isolation_evidence: self.managed_worker_isolation_evidence(),
            self_hosted_worker_registrations: self.self_hosted_worker_registrations(),
            self_hosted_worker_heartbeats: self.self_hosted_worker_heartbeats(),
            self_hosted_worker_telemetry_events: self.self_hosted_worker_telemetry_events(),
            self_hosted_worker_artifacts: self.self_hosted_worker_artifacts(),
            self_hosted_worker_checkpoints: self.self_hosted_worker_checkpoints(),
            self_hosted_run_dispatches: self.self_hosted_run_dispatches(),
        })
    }

    pub fn import_migration_snapshot(
        &self,
        snapshot: StorageMigrationSnapshot,
    ) -> Result<(), StorageError> {
        self.replace_control_plane(snapshot.control_plane)?;
        for api_key in snapshot.api_key_records {
            self.upsert_api_key_record(api_key)?;
        }
        for (id, document_json) in snapshot.tool_approvals {
            self.upsert_control_plane_tool_approval(id, document_json)?;
        }
        for event in snapshot.billing_events {
            self.append_billing_event(event)?;
        }
        for aggregate in snapshot.usage_aggregates {
            self.replace_usage_aggregate(aggregate)?;
        }
        for log in snapshot.request_logs {
            self.append_request_log(log);
        }
        for event in snapshot.audit_events {
            self.append_audit_event(event);
        }
        for run in snapshot.agent_runs {
            self.upsert_agent_run(run)?;
        }
        for event in snapshot.agent_run_events {
            self.append_agent_run_event(event)?;
        }
        for template in snapshot.managed_worker_templates {
            self.upsert_managed_worker_template(template)?;
        }
        for instance in snapshot.agent_worker_instances {
            self.upsert_agent_worker_instance(instance)?;
        }
        for session in snapshot.managed_worker_sessions {
            self.upsert_managed_worker_session(session)?;
        }
        for event in snapshot.managed_worker_lifecycle_events {
            self.append_managed_worker_lifecycle_event(event)?;
        }
        for selection in snapshot.managed_worker_isolation_selections {
            self.upsert_managed_worker_isolation_selection(selection)?;
        }
        for policy in snapshot.managed_worker_isolation_policies {
            self.upsert_managed_worker_isolation_policy(policy)?;
        }
        for evidence in snapshot.managed_worker_isolation_evidence {
            self.upsert_managed_worker_isolation_evidence(evidence)?;
        }
        for registration in snapshot.self_hosted_worker_registrations {
            self.upsert_self_hosted_worker_registration(registration)?;
        }
        for heartbeat in snapshot.self_hosted_worker_heartbeats {
            self.append_self_hosted_worker_heartbeat(heartbeat)?;
        }
        for event in snapshot.self_hosted_worker_telemetry_events {
            self.append_self_hosted_worker_telemetry_event(event)?;
        }
        for artifact in snapshot.self_hosted_worker_artifacts {
            self.upsert_self_hosted_worker_artifact(artifact)?;
        }
        for checkpoint in snapshot.self_hosted_worker_checkpoints {
            self.upsert_self_hosted_worker_checkpoint(checkpoint)?;
        }
        for dispatch in snapshot.self_hosted_run_dispatches {
            self.upsert_self_hosted_run_dispatch(dispatch)?;
        }
        Ok(())
    }

    pub fn upsert_control_plane_api_key(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_api_key(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("api_key", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("api_key", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_api_key(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_api_key(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("api_key", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("api_key", id.to_string())
            }
        }
    }

    // --- Durable virtual API keys bound to workspaces ---

    pub fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_api_key_record(api_key);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_api_key_record(&api_key)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(api_key_records_supabase_only_error()),
        }
    }

    pub fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_api_key_record(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_api_key_record(id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(api_key_records_supabase_only_error()),
        }
    }

    pub fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_api_key_records())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_api_key_records()
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(api_key_records_supabase_only_error()),
        }
    }

    pub fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.find_api_key_records_by_prefix(key_prefix))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.find_api_key_records_by_prefix(key_prefix)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(api_key_records_supabase_only_error()),
        }
    }

    // --- Multi-tenant hierarchy: Tenant -> Project -> Workspace ---

    pub fn upsert_tenant_account(&self, account: StoredTenantAccount) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_tenant_account(account);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_tenant_account(&account)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert_tenant_account(&account)
            }
        }
    }

    pub fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_tenant_account(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_tenant_account(id)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.get_tenant_account(id)
            }
        }
    }

    pub fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_tenant_accounts())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_tenant_accounts()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.list_tenant_accounts()
            }
        }
    }

    pub fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_project(project);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_project(&project)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert_project(&project)
            }
        }
    }

    pub fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_project(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.get_project(id),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.get_project(id),
        }
    }

    pub fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_projects())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_projects(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.list_projects(),
        }
    }

    pub fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_workspace(workspace);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_workspace(&workspace)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert_workspace(&workspace)
            }
        }
    }

    pub fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_workspace(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.get_workspace(id),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.get_workspace(id),
        }
    }

    pub fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_workspaces())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_workspaces(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.list_workspaces(),
        }
    }

    /// Resolve a workspace id to its full `tenant -> project -> workspace`
    /// attribution chain. Returns `None` when the workspace does not exist.
    pub fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.resolve_workspace_scope(workspace_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.resolve_workspace_scope(workspace_id)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.resolve_workspace_scope(workspace_id)
            }
        }
    }

    pub fn upsert_control_plane_policy(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_policy(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("policy", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("policy", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_policy(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_policy(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("policy", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("policy", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_gateway_config(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_gateway_config(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("gateway_config", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("gateway_config", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_gateway_config(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_gateway_config(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("gateway_config", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("gateway_config", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_agent_workflow(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_agent_workflow(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("agent_workflow", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("agent_workflow", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_agent_workflow(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_agent_workflow(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("agent_workflow", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("agent_workflow", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_skill_package(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_skill_package(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("skill_package", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("skill_package", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_skill_package(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_skill_package(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("skill_package", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("skill_package", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_prompt_template(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_prompt_template(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("prompt_template", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("prompt_template", id.into(), document_json)
            }
        }
    }

    pub fn upsert_control_plane_plugin_registration(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_plugin_registration(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("plugin_registration", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("plugin_registration", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_plugin_registration(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_plugin_registration(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("plugin_registration", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("plugin_registration", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_mcp_server(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_mcp_server(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("mcp_server", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("mcp_server", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_mcp_server(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_mcp_server(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("mcp_server", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("mcp_server", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_agent_upstream(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_agent_upstream(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("agent_upstream", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("agent_upstream", id.into(), document_json)
            }
        }
    }

    pub fn delete_control_plane_agent_upstream(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_agent_upstream(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("agent_upstream", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("agent_upstream", id.to_string())
            }
        }
    }

    pub fn upsert_control_plane_tool_approval(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_tool_approval(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("tool_approval", id.into(), document_json)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("tool_approval", id.into(), document_json)
            }
        }
    }

    pub fn control_plane_tool_approval(&self, id: &str) -> Result<Option<String>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .ok()
                .and_then(|control_plane| control_plane.tool_approval(id))),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_document("tool_approval", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.get_document("tool_approval", id.to_string())
            }
        }
    }

    pub fn control_plane_tool_approvals(&self) -> Result<Vec<String>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.tool_approvals())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_documents("tool_approval")
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.list_documents("tool_approval")
            }
        }
    }

    pub fn control_plane_tool_approval_documents(
        &self,
    ) -> Result<Vec<(String, String)>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.tool_approval_documents())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_resource_documents("tool_approval")
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.list_resource_documents("tool_approval")
            }
        }
    }

    pub fn set_retention_limits(
        &self,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) {
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.set_retention_limit(request_log_retention_records);
        }
        if let Ok(mut events) = self.audit_events.lock() {
            events.set_retention_limit(audit_event_retention_records);
        }
    }

    pub fn append_request_log(&self, log: StoredRequestLog) {
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            let _ = control_plane.append_request_log(&log);
            return;
        }
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    pub fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_billing_event(&event)
            }
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => {
                self.upsert_in_memory_usage_aggregate(&event);
                Ok(true)
            }
        }
    }

    fn upsert_in_memory_usage_aggregate(&self, event: &BillingEvent) {
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let id = usage_aggregate_id(&event.tenant, &event.logical_model, &event.provider);
            let existing = aggregates.get(&id);
            let mut aggregate = existing.unwrap_or_else(|| StoredUsageAggregate {
                id: id.clone(),
                organization_id: event.tenant.organization_id.clone(),
                project_id: event.tenant.project_id.clone(),
                api_key_id: event.tenant.api_key_id.clone(),
                logical_model: event.logical_model.clone(),
                provider: event.provider.clone(),
                usage: TokenUsage::default(),
            });
            aggregate.usage.prompt_tokens = aggregate
                .usage
                .prompt_tokens
                .saturating_add(event.usage.prompt_tokens);
            aggregate.usage.completion_tokens = aggregate
                .usage
                .completion_tokens
                .saturating_add(event.usage.completion_tokens);
            aggregate.usage.total_tokens = aggregate
                .usage
                .total_tokens
                .saturating_add(event.usage.total_tokens);
            aggregates.insert(id, aggregate);
        }
    }

    pub fn billing_events(&self) -> Vec<BillingEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.billing_events().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => {
                Vec::new()
            }
        }
    }

    pub fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .billing_events_page(offset, limit)
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => {
                StoragePage::empty(offset, limit)
            }
        }
    }

    pub fn request_logs(&self) -> Vec<StoredRequestLog> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.request_logs().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => self
                .request_logs
                .lock()
                .map(|logs| logs.list())
                .unwrap_or_default(),
        }
    }

    pub fn request_logs_page(&self, offset: usize, limit: usize) -> StoragePage<StoredRequestLog> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .request_logs_page(offset, limit)
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => self
                .request_logs
                .lock()
                .map(|logs| StoragePage {
                    data: logs.list_paginated(offset, limit),
                    total: logs.len(),
                    offset,
                    limit,
                })
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
        }
    }

    pub fn append_audit_event(&self, event: StoredAuditEvent) {
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            let _ = control_plane.append_audit_event(&event);
            return;
        }
        if let Ok(mut events) = self.audit_events.lock() {
            events.append(event);
        }
    }

    pub fn next_audit_event_id(&self) -> String {
        if matches!(&self.control_plane, RuntimeControlPlaneBackend::Postgres(_)) {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            return format!("audit-{nanos}-{}", std::process::id());
        }
        self.audit_events
            .lock()
            .map(|events| format!("audit-{}", events.len() + 1))
            .unwrap_or_else(|_| "audit-unknown".to_string())
    }

    pub fn audit_events(&self) -> Vec<StoredAuditEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.audit_events().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => self
                .audit_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
        }
    }

    pub fn audit_events_page(&self, offset: usize, limit: usize) -> StoragePage<StoredAuditEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .audit_events_page(offset, limit)
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => self
                .audit_events
                .lock()
                .map(|events| StoragePage {
                    data: events.list_paginated(offset, limit),
                    total: events.len(),
                    offset,
                    limit,
                })
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
        }
    }

    pub fn upsert_usage_aggregate(
        &self,
        id: impl Into<String>,
        build: impl FnOnce(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let id = id.into();
        let aggregate = if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let existing = aggregates.get(&id);
            let aggregate = build(existing);
            aggregates.insert(id, aggregate.clone());
            aggregate
        } else {
            return Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ));
        };
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            control_plane.upsert_usage_aggregate(&aggregate)?;
        }
        Ok(())
    }

    pub fn replace_usage_aggregate(
        &self,
        aggregate: StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let id = aggregate.id.clone();
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            aggregates.insert(id, aggregate.clone());
        } else {
            return Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ));
        }
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            control_plane.upsert_usage_aggregate(&aggregate)?;
        }
        Ok(())
    }

    pub fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.usage_aggregates().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) | RuntimeControlPlaneBackend::Mysql(_) => self
                .usage_aggregates
                .lock()
                .map(|aggregates| aggregates.list())
                .unwrap_or_default(),
        }
    }

    pub fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut runs) = self.agent_runs.lock() {
                    runs.insert(run.id.clone(), run);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_agent_run(&run)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.upsert("agent_run", run.id.clone(), serialize_storage_record(&run)?)
            }
        }
    }

    pub fn agent_run(&self, id: &str) -> Option<StoredAgentRun> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                self.agent_runs.lock().ok().and_then(|runs| runs.get(id))
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_run(id).unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .get_document("agent_run", id.to_string())
                .ok()
                .flatten()
                .and_then(|document| serde_json::from_str(&document).ok()),
        }
    }

    pub fn agent_runs(&self) -> Vec<StoredAgentRun> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_runs
                .lock()
                .map(|runs| runs.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_runs().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("agent_run")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn append_agent_run_event(&self, event: StoredAgentRunEvent) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.agent_run_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_agent_run_event(&event)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "agent_run_event",
                event.id.clone(),
                serialize_storage_record(&event)?,
            ),
        }
    }

    pub fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_run_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_run_events().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("agent_run_event")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut templates) = self.managed_worker_templates.lock() {
                    templates.insert(template.id.clone(), template);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_template(&template)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_template",
                template.id.clone(),
                serialize_storage_record(&template)?,
            ),
        }
    }

    pub fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_templates
                .lock()
                .map(|templates| templates.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.managed_worker_templates().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_template")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut instances) = self.agent_worker_instances.lock() {
                    instances.insert(instance.id.clone(), instance);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_agent_worker_instance(&instance)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "agent_worker_instance",
                instance.id.clone(),
                serialize_storage_record(&instance)?,
            ),
        }
    }

    pub fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_worker_instances
                .lock()
                .map(|instances| instances.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_worker_instances().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("agent_worker_instance")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut sessions) = self.managed_worker_sessions.lock() {
                    sessions.insert(session.id.clone(), session);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_session(&session)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_session",
                session.id.clone(),
                serialize_storage_record(&session)?,
            ),
        }
    }

    pub fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_sessions
                .lock()
                .map(|sessions| sessions.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.managed_worker_sessions().unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_session")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.managed_worker_lifecycle_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_managed_worker_lifecycle_event(&event)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_lifecycle_event",
                event.id.clone(),
                serialize_storage_record(&event)?,
            ),
        }
    }

    pub fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_lifecycle_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_lifecycle_events()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_lifecycle_event")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut selections) = self.managed_worker_isolation_selections.lock() {
                    selections.insert(selection.session_id.clone(), selection);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_isolation_selection(&selection)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_isolation_selection",
                selection.session_id.clone(),
                serialize_storage_record(&selection)?,
            ),
        }
    }

    pub fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_selections
                .lock()
                .map(|selections| selections.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_selections()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_isolation_selection")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut policies) = self.managed_worker_isolation_policies.lock() {
                    policies.insert(policy.session_id.clone(), policy);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_isolation_policy(&policy)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_isolation_policy",
                policy.session_id.clone(),
                serialize_storage_record(&policy)?,
            ),
        }
    }

    pub fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_policies
                .lock()
                .map(|policies| policies.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_policies()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_isolation_policy")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut records) = self.managed_worker_isolation_evidence.lock() {
                    records.insert(evidence.id.clone(), evidence);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_isolation_evidence(&evidence)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "managed_worker_isolation_evidence",
                evidence.id.clone(),
                serialize_storage_record(&evidence)?,
            ),
        }
    }

    pub fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_evidence
                .lock()
                .map(|records| records.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_evidence()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("managed_worker_isolation_evidence")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut registrations) = self.self_hosted_worker_registrations.lock() {
                    registrations.insert(registration.id.clone(), registration);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_self_hosted_worker_registration(&registration)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_worker_registration",
                registration.id.clone(),
                serialize_storage_record(&registration)?,
            ),
        }
    }

    pub fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_registrations
                .lock()
                .map(|registrations| registrations.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_registrations()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_worker_registration")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut heartbeats) = self.self_hosted_worker_heartbeats.lock() {
                    heartbeats.append(heartbeat);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_self_hosted_worker_heartbeat(&heartbeat)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_worker_heartbeat",
                heartbeat.id.clone(),
                serialize_storage_record(&heartbeat)?,
            ),
        }
    }

    pub fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_heartbeats
                .lock()
                .map(|heartbeats| heartbeats.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_heartbeats()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_worker_heartbeat")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.self_hosted_worker_telemetry_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_self_hosted_worker_telemetry_event(&event)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_worker_telemetry_event",
                event.id.clone(),
                serialize_storage_record(&event)?,
            ),
        }
    }

    pub fn self_hosted_worker_telemetry_events(&self) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_telemetry_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_telemetry_events()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_worker_telemetry_event")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut artifacts) = self.self_hosted_worker_artifacts.lock() {
                    artifacts.insert(artifact.id.clone(), artifact);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_self_hosted_worker_artifact(&artifact)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_worker_artifact",
                artifact.id.clone(),
                serialize_storage_record(&artifact)?,
            ),
        }
    }

    pub fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_artifacts
                .lock()
                .map(|artifacts| artifacts.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_artifacts()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_worker_artifact")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut checkpoints) = self.self_hosted_worker_checkpoints.lock() {
                    checkpoints.insert(checkpoint.id.clone(), checkpoint);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_self_hosted_worker_checkpoint(&checkpoint)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_worker_checkpoint",
                checkpoint.id.clone(),
                serialize_storage_record(&checkpoint)?,
            ),
        }
    }

    pub fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_checkpoints
                .lock()
                .map(|checkpoints| checkpoints.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_checkpoints()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_worker_checkpoint")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }

    pub fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut dispatches) = self.self_hosted_run_dispatches.lock() {
                    dispatches.insert(dispatch.dispatch_id.clone(), dispatch);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_self_hosted_run_dispatch(&dispatch)
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.upsert(
                "self_hosted_run_dispatch",
                dispatch.dispatch_id.clone(),
                serialize_storage_record(&dispatch)?,
            ),
        }
    }

    pub fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_run_dispatches
                .lock()
                .map(|dispatches| dispatches.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_run_dispatches()
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("self_hosted_run_dispatch")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
        }
    }
}

fn serialize_storage_record<T: Serialize>(record: &T) -> Result<String, StorageError> {
    serde_json::to_string(record).map_err(|error| {
        StorageError::Serialization(format!("failed to serialize storage record: {error}"))
    })
}

fn deserialize_storage_records<T: for<'de> Deserialize<'de>>(documents: Vec<String>) -> Vec<T> {
    documents
        .into_iter()
        .filter_map(|document| serde_json::from_str(&document).ok())
        .collect()
}

fn postgres_error(error: postgres::Error) -> StorageError {
    StorageError::Postgres(error.to_string())
}

fn postgres_connection_error(error: postgres::Error) -> StorageError {
    StorageError::Postgres(sanitize_storage_error(&error.to_string()))
}

fn sanitize_storage_error(error: &str) -> String {
    let mut sanitized = error.to_string();
    for marker in ["password=", "passfile=", "sslpassword="] {
        sanitized = redact_marker_value(&sanitized, marker);
    }
    redact_url_passwords(&sanitized)
}

fn redact_marker_value(input: &str, marker: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(marker) {
        output.push_str(&rest[..start + marker.len()]);
        output.push_str("[redacted]");
        let value_start = start + marker.len();
        let value_rest = &rest[value_start..];
        let value_end = value_rest
            .find(|ch: char| ch.is_whitespace() || ch == '\'' || ch == '"' || ch == ';')
            .unwrap_or(value_rest.len());
        rest = &value_rest[value_end..];
    }
    output.push_str(rest);
    output
}

fn redact_url_passwords(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_marker) = rest.find("://") {
        let authority_start = scheme_marker + 3;
        let Some(at_relative) = rest[authority_start..].find('@') else {
            output.push_str(rest);
            return output;
        };
        let at = authority_start + at_relative;
        let authority = &rest[authority_start..at];
        let Some(colon_relative) = authority.rfind(':') else {
            output.push_str(&rest[..=at]);
            rest = &rest[at + 1..];
            continue;
        };
        let colon = authority_start + colon_relative;
        output.push_str(&rest[..colon + 1]);
        output.push_str("[redacted]");
        output.push('@');
        rest = &rest[at + 1..];
    }
    output.push_str(rest);
    output
}

fn mysql_error(error: mysql::Error) -> StorageError {
    StorageError::Mysql(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePage<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

impl<T> StoragePage<T> {
    fn empty(offset: usize, limit: usize) -> Self {
        Self {
            data: Vec::new(),
            total: 0,
            offset,
            limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn postgres_empty(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        config: PostgresStorageConfig,
        initialize_schema: bool,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Result<RuntimeStorageRepositories, StorageError> {
        RuntimeStorageRepositories::postgres(
            config,
            runtime_options_empty(
                provider_order,
                required,
                initialize_schema,
                request_log_retention_records,
                audit_event_retention_records,
            ),
        )
    }

    fn runtime_options_empty(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        initialize_schema: bool,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> RuntimeStorageOptions {
        RuntimeStorageOptions {
            provider_order,
            required,
            initialize_schema,
            migration_mode: if initialize_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records,
            audit_event_retention_records,
        }
    }

    #[test]
    fn in_memory_api_key_repository_gets_and_lists_records() {
        let mut repository = InMemoryRepository::new();
        repository.insert(
            "key_dev",
            StoredApiKey {
                id: "key_dev".into(),
                workspace_id: "workspace_dev".into(),
                tenant_id: "org".into(),
                project_id: "project".into(),
                name: "Development key".into(),
                key_prefix: "fg_dev".into(),
                key_hash: "blake2b:test".into(),
                last4: "test".into(),
                enabled: true,
                scopes: vec!["chat.completions".into()],
                allowed_models: vec!["fast-chat".into()],
                allowed_providers: vec!["openai".into()],
                tenant: TenantContext {
                    workspace_id: Some("workspace_dev".into()),
                    organization_id: Some("org".into()),
                    team_id: None,
                    project_id: Some("project".into()),
                    user_id: None,
                    api_key_id: Some("key_dev".into()),
                },
                monthly_token_budget: Some(1_000),
                request_limit_per_minute: Some(60),
                created_at_unix: 100,
                updated_at_unix: 100,
                rotated_at_unix: None,
                expires_at_unix: None,
                revoked_at_unix: None,
            },
        );

        assert_eq!(repository.get("key_dev").unwrap().name, "Development key");
        assert_eq!(repository.list().len(), 1);
        assert!(repository.get("missing").is_none());
    }

    #[test]
    fn in_memory_policy_repository_uses_stable_policy_ids() {
        let mut repository = InMemoryRepository::new();
        repository.insert(
            "deny-fast-chat",
            StoredPolicyRule {
                id: "deny-fast-chat".into(),
                name: "Deny fast chat".into(),
                effect: "deny".into(),
                organization_ids: vec!["org".into()],
                project_ids: vec![],
                api_key_ids: vec![],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                code: "policy_denied".into(),
                message: "blocked".into(),
                enabled: true,
            },
        );

        let rule = repository.get("deny-fast-chat").unwrap();
        assert_eq!(rule.providers, vec!["openai"]);
    }

    #[test]
    fn in_memory_append_repository_keeps_request_logs_in_order() {
        let mut repository = InMemoryAppendRepository::new();
        repository.append(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: Some("trace-1".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(1),
            completed_at_unix: Some(2),
        });
        repository.append(StoredRequestLog {
            request_id: "fg-2".into(),
            trace_id: Some("trace-2".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some("gemini".into()),
            logical_model: Some("flash-chat".into()),
            provider_model: Some("gemini-2.5-flash".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 429,
            error_code: Some("rate_limit_exceeded".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(3),
            completed_at_unix: Some(4),
        });

        let logs = repository.list();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].request_id, "fg-1");
        assert_eq!(logs[1].error_code.as_deref(), Some("rate_limit_exceeded"));
    }

    #[test]
    fn in_memory_append_repository_enforces_retention_limit() {
        let mut repository = InMemoryAppendRepository::with_retention_limit(2);
        for id in ["fg-1", "fg-2", "fg-3"] {
            repository.append(StoredRequestLog {
                request_id: id.into(),
                trace_id: None,
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                cluster_id: None,
                node_id: None,
                tenant: TenantContext::default(),
                route: None,
                provider: None,
                logical_model: None,
                provider_model: None,
                gateway_config_id: None,
                gateway_config_revision: None,
                status_code: 200,
                error_code: None,
                prompt_recorded: false,
                response_recorded: false,
                prompt_body: None,
                response_body: None,
                cache_status: None,
                started_at_unix: None,
                completed_at_unix: None,
            });
        }

        let logs = repository.list();
        assert_eq!(repository.len(), 2);
        assert_eq!(repository.appended_total(), 3);
        assert_eq!(logs[0].request_id, "fg-2");
        assert_eq!(logs[1].request_id, "fg-3");
        assert_eq!(repository.list_paginated(1, 1)[0].request_id, "fg-3");
    }

    #[test]
    fn usage_aggregate_repository_stores_tenant_model_totals() {
        let mut repository = InMemoryRepository::new();
        repository.insert(
            "org:project:key:fast-chat:openai",
            StoredUsageAggregate {
                id: "org:project:key:fast-chat:openai".into(),
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key_dev".into()),
                logical_model: "fast-chat".into(),
                provider: "openai".into(),
                usage: TokenUsage::new(3, 5, 8),
            },
        );

        let aggregate = repository.get("org:project:key:fast-chat:openai").unwrap();
        assert_eq!(aggregate.usage.total_tokens, 8);
    }

    #[test]
    fn in_memory_append_repository_keeps_audit_events_in_order() {
        let mut repository = InMemoryAppendRepository::new();
        repository.append(StoredAuditEvent {
            id: "audit-1".into(),
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            actor_api_key_id: Some("admin".into()),
            tenant: TenantContext::default(),
            action: "config.validate".into(),
            target: "candidate_config".into(),
            outcome: "accepted".into(),
            message: "candidate config valid".into(),
            occurred_at_unix: Some(1),
        });
        repository.append(StoredAuditEvent {
            id: "audit-2".into(),
            request_id: "fg-2".into(),
            trace_id: Some("fg-2".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            actor_api_key_id: Some("admin".into()),
            tenant: TenantContext::default(),
            action: "config.validate".into(),
            target: "candidate_config".into(),
            outcome: "rejected".into(),
            message: "field listen: invalid listen address".into(),
            occurred_at_unix: Some(2),
        });

        let events = repository.list();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, "accepted");
        assert_eq!(events[1].outcome, "rejected");
    }

    #[test]
    fn runtime_repositories_keep_agent_run_timeline_events() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        repositories
            .upsert_agent_run(StoredAgentRun {
                id: "run-1".into(),
                request_id: "fg-1".into(),
                trace_id: Some("trace-1".into()),
                tenant: tenant.clone(),
                status: "running".into(),
                provider: "managed.native-harness".into(),
                turns_executed: 0,
                output_recorded: false,
                started_at_unix: Some(10),
                completed_at_unix: None,
            })
            .unwrap();
        repositories
            .append_agent_run_event(StoredAgentRunEvent {
                id: "event-1".into(),
                run_id: "run-1".into(),
                request_id: "fg-1".into(),
                trace_id: Some("trace-1".into()),
                tenant,
                turn: 0,
                kind: "capability.denied".into(),
                target: "cli:bash".into(),
                outcome: "denied".into(),
                tool_call_id: None,
                message: Some("cli is not allowed by capability policy".into()),
                occurred_at_unix: Some(11),
            })
            .unwrap();

        let run = repositories.agent_run("run-1").unwrap();
        assert_eq!(run.provider, "managed.native-harness");
        let events = repositories.agent_run_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "capability.denied");
        assert_eq!(events[0].target, "cli:bash");
        assert_eq!(events[0].outcome, "denied");
    }

    #[test]
    fn runtime_repositories_keep_managed_worker_lifecycle_records() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        repositories
            .upsert_managed_worker_template(StoredManagedWorkerTemplate {
                id: "template-firecracker-codex".into(),
                framework_adapter: "codex".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                enabled: true,
                max_tenant_sessions: Some(12),
                max_workspace_sessions: Some(4),
                created_at_unix: Some(10),
                updated_at_unix: Some(11),
            })
            .unwrap();
        repositories
            .upsert_agent_worker_instance(StoredAgentWorkerInstance {
                id: "agent-worker-1".into(),
                process_name: "agent-worker".into(),
                host_id: Some("host-a".into()),
                worker_version: Some("0.1.0".into()),
                status: "online".into(),
                started_at_unix: Some(12),
                last_seen_at_unix: Some(13),
                process_json: r#"{"pid":4242}"#.into(),
            })
            .unwrap();
        repositories
            .upsert_managed_worker_session(StoredManagedWorkerSession {
                id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_template_id: "template-firecracker-codex".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "running".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                microvm_id: Some("fc-vm-1".into()),
                capability_envelope_id: "capability-envelope-1".into(),
                requested_at_unix: Some(14),
                started_at_unix: Some(15),
                completed_at_unix: None,
                cleanup_completed_at_unix: None,
                capability_envelope_json: r#"{"id":"capability-envelope-1"}"#.into(),
                resource_limits_json: r#"{"vcpu":2,"memory_mib":1024}"#.into(),
            })
            .unwrap();
        repositories
            .append_managed_worker_lifecycle_event(StoredManagedWorkerLifecycleEvent {
                id: "lifecycle-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "running".into(),
                action: "start".into(),
                outcome: "succeeded".into(),
                occurred_at_unix: Some(16),
                evidence_json: r#"{"microvm_id":"fc-vm-1"}"#.into(),
            })
            .unwrap();
        repositories
            .upsert_managed_worker_isolation_selection(StoredManagedWorkerIsolationSelection {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                backend_name: "firecracker".into(),
                backend_version: "1.8.0".into(),
                backend_kind: "firecracker_micro_vm".into(),
                host_lifecycle_owner: "agent-worker".into(),
                gateway_controls_backend: false,
                capability_envelope_id: "capability-envelope-1".into(),
                selected_at_unix: Some(16),
            })
            .unwrap();
        repositories
            .upsert_managed_worker_isolation_policy(StoredManagedWorkerIsolationPolicy {
                session_id: "session-1".into(),
                cpu_count: 2,
                memory_mib: 1024,
                disk_mib: 4096,
                max_runtime_millis: Some(30_000),
                direct_public_egress: false,
                gateway_control_channel: true,
                governed_egress: true,
                read_only_rootfs: true,
                writable_workspace: true,
                host_path_mounts: false,
            })
            .unwrap();
        repositories
            .upsert_managed_worker_isolation_evidence(StoredManagedWorkerIsolationEvidence {
                id: "isolation-evidence-1".into(),
                session_id: "session-1".into(),
                lifecycle_event_id: "lifecycle-1".into(),
                run_id: "run-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                isolation_instance_id: Some("fc-vm-1".into()),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                failure_reason: None,
                occurred_at_unix: Some(16),
                evidence_json: r#"{"microvm_id":"fc-vm-1"}"#.into(),
            })
            .unwrap();

        assert_eq!(
            repositories.managed_worker_templates()[0].isolation_backend_kind,
            "firecracker_micro_vm"
        );
        assert_eq!(
            repositories.agent_worker_instances()[0].process_name,
            "agent-worker"
        );
        assert_eq!(
            repositories.managed_worker_sessions()[0]
                .microvm_id
                .as_deref(),
            Some("fc-vm-1")
        );
        assert_eq!(
            repositories.managed_worker_lifecycle_events()[0].action,
            "start"
        );
        assert_eq!(
            repositories.managed_worker_isolation_selections()[0].host_lifecycle_owner,
            "agent-worker"
        );
        assert!(!repositories.managed_worker_isolation_selections()[0].gateway_controls_backend);
        assert!(!repositories.managed_worker_isolation_policies()[0].direct_public_egress);
        assert_eq!(
            repositories.managed_worker_isolation_evidence()[0]
                .isolation_instance_id
                .as_deref(),
            Some("fc-vm-1")
        );
    }

    #[test]
    fn migration_snapshot_includes_managed_worker_lifecycle_records() {
        let source =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        source
            .upsert_managed_worker_template(StoredManagedWorkerTemplate {
                id: "template-1".into(),
                framework_adapter: "codex".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                enabled: true,
                max_tenant_sessions: Some(24),
                max_workspace_sessions: Some(6),
                created_at_unix: Some(1),
                updated_at_unix: Some(2),
            })
            .unwrap();
        source
            .upsert_agent_worker_instance(StoredAgentWorkerInstance {
                id: "agent-worker-1".into(),
                process_name: "agent-worker".into(),
                host_id: Some("host-a".into()),
                worker_version: Some("0.1.0".into()),
                status: "online".into(),
                started_at_unix: Some(3),
                last_seen_at_unix: Some(4),
                process_json: "{}".into(),
            })
            .unwrap();
        source
            .upsert_managed_worker_session(StoredManagedWorkerSession {
                id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_template_id: "template-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "cleaned_up".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                microvm_id: Some("fc-vm-1".into()),
                capability_envelope_id: "capability-envelope-1".into(),
                requested_at_unix: Some(5),
                started_at_unix: Some(6),
                completed_at_unix: Some(7),
                cleanup_completed_at_unix: Some(8),
                capability_envelope_json: "{}".into(),
                resource_limits_json: "{}".into(),
            })
            .unwrap();
        source
            .append_managed_worker_lifecycle_event(StoredManagedWorkerLifecycleEvent {
                id: "lifecycle-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "cleaned_up".into(),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                occurred_at_unix: Some(9),
                evidence_json: "{}".into(),
            })
            .unwrap();
        source
            .upsert_managed_worker_isolation_selection(StoredManagedWorkerIsolationSelection {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                backend_name: "firecracker".into(),
                backend_version: "1.8.0".into(),
                backend_kind: "firecracker_micro_vm".into(),
                host_lifecycle_owner: "agent-worker".into(),
                gateway_controls_backend: false,
                capability_envelope_id: "capability-envelope-1".into(),
                selected_at_unix: Some(5),
            })
            .unwrap();
        source
            .upsert_managed_worker_isolation_policy(StoredManagedWorkerIsolationPolicy {
                session_id: "session-1".into(),
                cpu_count: 1,
                memory_mib: 512,
                disk_mib: 1024,
                max_runtime_millis: Some(30_000),
                direct_public_egress: false,
                gateway_control_channel: true,
                governed_egress: true,
                read_only_rootfs: true,
                writable_workspace: true,
                host_path_mounts: false,
            })
            .unwrap();
        source
            .upsert_managed_worker_isolation_evidence(StoredManagedWorkerIsolationEvidence {
                id: "isolation-evidence-1".into(),
                session_id: "session-1".into(),
                lifecycle_event_id: "lifecycle-1".into(),
                run_id: "run-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                isolation_instance_id: Some("fc-vm-1".into()),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                failure_reason: None,
                occurred_at_unix: Some(9),
                evidence_json: "{}".into(),
            })
            .unwrap();

        let snapshot = source.export_migration_snapshot().unwrap();
        let counts = snapshot.counts();
        assert_eq!(counts.managed_worker_templates, 1);
        assert_eq!(counts.agent_worker_instances, 1);
        assert_eq!(counts.managed_worker_sessions, 1);
        assert_eq!(counts.managed_worker_lifecycle_events, 1);
        assert_eq!(counts.managed_worker_isolation_selections, 1);
        assert_eq!(counts.managed_worker_isolation_policies, 1);
        assert_eq!(counts.managed_worker_isolation_evidence, 1);

        let target =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        target.import_migration_snapshot(snapshot).unwrap();

        assert_eq!(target.managed_worker_templates().len(), 1);
        assert_eq!(target.agent_worker_instances().len(), 1);
        assert_eq!(target.managed_worker_sessions().len(), 1);
        assert_eq!(target.managed_worker_lifecycle_events().len(), 1);
        assert_eq!(target.managed_worker_isolation_selections().len(), 1);
        assert_eq!(target.managed_worker_isolation_policies().len(), 1);
        assert_eq!(target.managed_worker_isolation_evidence().len(), 1);
    }

    fn self_hosted_tenant() -> TenantContext {
        TenantContext {
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            workspace_id: None,
            user_id: None,
            api_key_id: Some("key".into()),
        }
    }

    fn insert_self_hosted_worker_records(repositories: &RuntimeStorageRepositories) {
        let tenant = self_hosted_tenant();
        repositories
            .upsert_self_hosted_worker_registration(StoredSelfHostedWorkerRegistration {
                id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_name: "customer-worker-a".into(),
                status: "online".into(),
                identity_fingerprint: "sha256:worker-identity".into(),
                identity_expires_at_unix: Some(2_000),
                orchestration_enabled: true,
                registered_at_unix: Some(20),
                last_seen_at_unix: Some(21),
                trust_level: "reported_by_self_hosted_worker".into(),
                capability_envelope_json: r#"{"frameworks":["codex"]}"#.into(),
            })
            .unwrap();
        repositories
            .append_self_hosted_worker_heartbeat(StoredSelfHostedWorkerHeartbeat {
                id: "heartbeat-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                status: "online".into(),
                reported_at_unix: Some(22),
                observed_at_unix: Some(23),
                heartbeat_json: r#"{"load":0.42}"#.into(),
            })
            .unwrap();
        repositories
            .append_self_hosted_worker_telemetry_event(StoredSelfHostedWorkerTelemetryEvent {
                id: "telemetry-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: Some("session-1".into()),
                run_id: Some("run-1".into()),
                kind: "tool_call".into(),
                trust_level: "reported_by_self_hosted_worker".into(),
                occurred_at_unix: Some(24),
                ingested_at_unix: Some(25),
                event_json: r#"{"tool":"bash"}"#.into(),
            })
            .unwrap();
        repositories
            .upsert_self_hosted_worker_artifact(StoredSelfHostedWorkerArtifact {
                id: "artifact-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: Some("text/plain".into()),
                size_bytes: 128,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(26),
                artifact_json: r#"{"path":"stdout.log"}"#.into(),
            })
            .unwrap();
        repositories
            .upsert_self_hosted_worker_checkpoint(StoredSelfHostedWorkerCheckpoint {
                id: "checkpoint-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: 256,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(27),
                checkpoint_json: r#"{"version":1}"#.into(),
            })
            .unwrap();
        repositories
            .upsert_self_hosted_run_dispatch(StoredSelfHostedRunDispatch {
                dispatch_id: "dispatch-1".into(),
                action: "start_run".into(),
                tenant_id: "org".into(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                framework_adapter: "codex".into(),
                required_capabilities: vec!["shell".into()],
                workload_ref: "self-hosted-workload://self-hosted-worker-1".into(),
                queued_at_unix: Some(28),
                assigned_worker_id: Some("self-hosted-worker-1".into()),
                lease_id: Some("dispatch-1:attempt-1".into()),
                lease_expires_at_unix: Some(58),
                attempt: 1,
                acknowledged_status: Some("accepted".into()),
                acknowledged_at_unix: Some(29),
            })
            .unwrap();
    }

    #[test]
    fn runtime_repositories_keep_self_hosted_worker_records() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        insert_self_hosted_worker_records(&repositories);

        let registrations = repositories.self_hosted_worker_registrations();
        assert_eq!(registrations.len(), 1);
        assert_eq!(
            registrations[0].trust_level,
            "reported_by_self_hosted_worker"
        );
        assert!(registrations[0].orchestration_enabled);
        assert_eq!(
            repositories.self_hosted_worker_heartbeats()[0].status,
            "online"
        );
        assert_eq!(
            repositories.self_hosted_worker_telemetry_events()[0].kind,
            "tool_call"
        );
        assert_eq!(
            repositories.self_hosted_worker_artifacts()[0].artifact_name,
            "stdout.log"
        );
        assert_eq!(
            repositories.self_hosted_worker_checkpoints()[0].checkpoint_name,
            "resume-state"
        );
        assert_eq!(
            repositories.self_hosted_run_dispatches()[0]
                .lease_id
                .as_deref(),
            Some("dispatch-1:attempt-1")
        );
    }

    #[test]
    fn migration_snapshot_includes_self_hosted_worker_records() {
        let source =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        insert_self_hosted_worker_records(&source);

        let snapshot = source.export_migration_snapshot().unwrap();
        let counts = snapshot.counts();
        assert_eq!(counts.self_hosted_worker_registrations, 1);
        assert_eq!(counts.self_hosted_worker_heartbeats, 1);
        assert_eq!(counts.self_hosted_worker_telemetry_events, 1);
        assert_eq!(counts.self_hosted_worker_artifacts, 1);
        assert_eq!(counts.self_hosted_worker_checkpoints, 1);
        assert_eq!(counts.self_hosted_run_dispatches, 1);

        let target =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        target.import_migration_snapshot(snapshot).unwrap();

        assert_eq!(target.self_hosted_worker_registrations().len(), 1);
        assert_eq!(target.self_hosted_worker_heartbeats().len(), 1);
        assert_eq!(target.self_hosted_worker_telemetry_events().len(), 1);
        assert_eq!(target.self_hosted_worker_artifacts().len(), 1);
        assert_eq!(target.self_hosted_worker_checkpoints().len(), 1);
        assert_eq!(target.self_hosted_run_dispatches().len(), 1);
        assert_eq!(
            target.self_hosted_run_dispatches()[0].required_capabilities,
            vec!["shell".to_string()]
        );
    }

    #[test]
    fn runtime_backend_reports_provider_contract_evidence() {
        let backend = RuntimeStorageBackend::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec());
        let evidence = backend.evidence();

        assert_eq!(evidence.provider, StorageProviderKind::Memory);
        assert!(!evidence.durable);
        assert!(evidence.implemented);
        assert_eq!(evidence.contract_version, 1);
        assert_eq!(
            evidence.provider_order,
            vec![
                StorageProviderKind::Supabase,
                StorageProviderKind::Postgres,
                StorageProviderKind::Mysql,
            ]
        );

        assert!(
            RuntimeStorageBackend::new(StorageProviderKind::TursoLibsql, true, Vec::new()).is_err()
        );

        let supabase_backend =
            RuntimeStorageBackend::new(StorageProviderKind::Supabase, true, Vec::new()).unwrap();
        assert!(supabase_backend.evidence().durable);
        assert!(supabase_backend.evidence().implemented);

        let postgres_backend =
            RuntimeStorageBackend::new(StorageProviderKind::Postgres, true, Vec::new()).unwrap();
        assert!(postgres_backend.evidence().durable);
        assert!(postgres_backend.evidence().implemented);

        let mysql_backend =
            RuntimeStorageBackend::new(StorageProviderKind::Mysql, true, Vec::new()).unwrap();
        assert!(mysql_backend.evidence().durable);
        assert!(mysql_backend.evidence().implemented);
    }

    #[test]
    fn postgres_tls_ca_path_errors_before_connecting() {
        let error = postgres_empty(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            PostgresStorageConfig {
                dsn: "host=127.0.0.1 port=1 user=postgres dbname=ferrogate".into(),
                pool_size: 1,
                tls_mode: PostgresTlsMode::VerifyFull,
                tls_ca_cert_path: Some("/tmp/ferrogate-missing-postgres-ca.pem".into()),
                connect_timeout_secs: 1,
                statement_timeout_millis: 1_000,
                schema: None,
                search_path: Vec::new(),
            },
            false,
            10,
            10,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("storage.postgres_tls_ca_cert_path"));
    }

    #[test]
    fn storage_error_sanitizer_redacts_postgres_credentials() {
        let keyword = sanitize_storage_error(
            "connection failed for host=db.example user=postgres password=super-secret dbname=postgres",
        );
        assert!(keyword.contains("password=[redacted]"));
        assert!(!keyword.contains("super-secret"));

        let url = sanitize_storage_error(
            "failed to connect to postgresql://postgres:service-role-token@db.example:5432/postgres",
        );
        assert!(url.contains("postgresql://postgres:[redacted]@db.example:5432/postgres"));
        assert!(!url.contains("service-role-token"));
    }

    #[test]
    fn runtime_repositories_isolate_control_plane_storage_operations() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 1, 1);

        repositories
            .upsert_control_plane_api_key("key_a", r#"{"id":"key_a","name":"A"}"#.to_string())
            .unwrap();
        repositories
            .upsert_control_plane_policy(
                "deny_a",
                r#"{"name":"deny_a","effect":"deny"}"#.to_string(),
            )
            .unwrap();
        repositories
            .replace_control_plane(ControlPlaneDocuments {
                api_keys: vec![("key_a".into(), r#"{"id":"key_a","name":"A"}"#.to_string())],
                policies: vec![(
                    "deny_a".into(),
                    r#"{"name":"deny_a","effect":"deny"}"#.to_string(),
                )],
                plugin_registrations: vec![(
                    "tool.echo".into(),
                    r#"{"id":"tool.echo","source":"builtin"}"#.to_string(),
                )],
                mcp_servers: vec![(
                    "github".into(),
                    r#"{"name":"github","transport":"streamable_http"}"#.to_string(),
                )],
                ..ControlPlaneDocuments::default()
            })
            .unwrap();
        let snapshot = repositories.control_plane_snapshot().unwrap();
        assert_eq!(snapshot.api_keys, [r#"{"id":"key_a","name":"A"}"#]);
        assert_eq!(snapshot.policies, [r#"{"name":"deny_a","effect":"deny"}"#]);
        assert_eq!(
            snapshot.mcp_servers,
            [r#"{"name":"github","transport":"streamable_http"}"#]
        );
        assert_eq!(
            snapshot.plugin_registrations,
            [r#"{"id":"tool.echo","source":"builtin"}"#]
        );

        assert!(repositories.delete_control_plane_api_key("key_a").unwrap());
        assert!(!repositories.delete_control_plane_api_key("key_a").unwrap());
        assert!(repositories
            .control_plane_snapshot()
            .unwrap()
            .api_keys
            .is_empty());

        repositories.append_request_log(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            route: None,
            provider: None,
            logical_model: Some("fast-chat".into()),
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: None,
            completed_at_unix: None,
        });
        repositories.append_request_log(StoredRequestLog {
            request_id: "fg-2".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            route: None,
            provider: None,
            logical_model: Some("slow-chat".into()),
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 500,
            error_code: Some("provider_error".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: None,
            completed_at_unix: None,
        });

        let page = repositories.request_logs_page(0, 10);
        assert_eq!(page.total, 1);
        assert_eq!(page.data[0].request_id, "fg-2");

        repositories
            .upsert_usage_aggregate("org:project:fast-chat:openai", |_| StoredUsageAggregate {
                id: "org:project:fast-chat:openai".into(),
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                logical_model: "fast-chat".into(),
                provider: "openai".into(),
                usage: TokenUsage::new(1, 2, 3),
            })
            .unwrap();
        assert_eq!(repositories.usage_aggregates()[0].usage.total_tokens, 3);
    }

    fn memory_repositories() -> RuntimeStorageRepositories {
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 0, 0)
    }

    fn sample_tenant(id: &str, slug: &str) -> StoredTenantAccount {
        StoredTenantAccount {
            id: id.into(),
            name: format!("Tenant {id}"),
            slug: slug.into(),
            status: "active".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_project(id: &str, tenant_id: &str, slug: &str) -> StoredProject {
        StoredProject {
            id: id.into(),
            tenant_id: tenant_id.into(),
            name: format!("Project {id}"),
            slug: slug.into(),
            status: "active".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_workspace(
        id: &str,
        project_id: &str,
        tenant_id: &str,
        slug: &str,
    ) -> StoredWorkspace {
        StoredWorkspace {
            id: id.into(),
            project_id: project_id.into(),
            tenant_id: tenant_id.into(),
            name: format!("Workspace {id}"),
            slug: slug.into(),
            environment: "dev".into(),
            status: "active".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_api_key(id: &str, prefix: &str) -> StoredApiKey {
        StoredApiKey {
            id: id.into(),
            workspace_id: "ws-dev".into(),
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            name: format!("API key {id}"),
            key_prefix: prefix.into(),
            key_hash: format!("sha256:{id}"),
            last4: "wxyz".into(),
            enabled: true,
            scopes: vec!["chat.completions".into()],
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            tenant: TenantContext {
                organization_id: Some("tenant-a".into()),
                team_id: None,
                project_id: Some("project-a".into()),
                workspace_id: Some("ws-dev".into()),
                user_id: None,
                api_key_id: Some(id.into()),
            },
            monthly_token_budget: None,
            request_limit_per_minute: None,
            created_at_unix: 100,
            updated_at_unix: 100,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        }
    }

    #[test]
    fn hierarchy_upsert_get_list_roundtrip() {
        let repositories = memory_repositories();

        repositories
            .upsert_tenant_account(sample_tenant("tenant-a", "tenant-a"))
            .unwrap();
        repositories
            .upsert_project(sample_project("project-a", "tenant-a", "core"))
            .unwrap();
        repositories
            .upsert_workspace(sample_workspace("ws-dev", "project-a", "tenant-a", "dev"))
            .unwrap();

        assert_eq!(
            repositories
                .get_tenant_account("tenant-a")
                .unwrap()
                .unwrap()
                .slug,
            "tenant-a"
        );
        assert_eq!(
            repositories
                .get_project("project-a")
                .unwrap()
                .unwrap()
                .tenant_id,
            "tenant-a"
        );
        let workspace = repositories.get_workspace("ws-dev").unwrap().unwrap();
        assert_eq!(workspace.project_id, "project-a");
        assert_eq!(workspace.tenant_id, "tenant-a");
        assert_eq!(workspace.environment, "dev");

        assert_eq!(repositories.list_tenant_accounts().unwrap().len(), 1);
        assert_eq!(repositories.list_projects().unwrap().len(), 1);
        assert_eq!(repositories.list_workspaces().unwrap().len(), 1);
    }

    #[test]
    fn hierarchy_upsert_overwrites_existing_record() {
        let repositories = memory_repositories();
        repositories
            .upsert_workspace(sample_workspace("ws-dev", "project-a", "tenant-a", "dev"))
            .unwrap();
        let mut updated = sample_workspace("ws-dev", "project-a", "tenant-a", "dev");
        updated.name = "Renamed workspace".into();
        updated.status = "disabled".into();
        repositories.upsert_workspace(updated).unwrap();

        let stored = repositories.get_workspace("ws-dev").unwrap().unwrap();
        assert_eq!(stored.name, "Renamed workspace");
        assert_eq!(stored.status, "disabled");
        assert_eq!(repositories.list_workspaces().unwrap().len(), 1);
    }

    #[test]
    fn resolve_workspace_scope_returns_full_attribution_chain() {
        let repositories = memory_repositories();
        repositories
            .upsert_tenant_account(sample_tenant("tenant-a", "tenant-a"))
            .unwrap();
        repositories
            .upsert_project(sample_project("project-a", "tenant-a", "core"))
            .unwrap();
        repositories
            .upsert_workspace(sample_workspace("ws-prod", "project-a", "tenant-a", "prod"))
            .unwrap();

        let scope = repositories
            .resolve_workspace_scope("ws-prod")
            .unwrap()
            .expect("workspace resolves");
        assert_eq!(scope.tenant_id, "tenant-a");
        assert_eq!(scope.project_id, "project-a");
        assert_eq!(scope.workspace_id, "ws-prod");

        // A resolved scope backfills a TenantContext with the full chain.
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);
        assert_eq!(tenant.organization_id.as_deref(), Some("tenant-a"));
        assert_eq!(tenant.project_id.as_deref(), Some("project-a"));
        assert_eq!(tenant.workspace_id.as_deref(), Some("ws-prod"));
    }

    #[test]
    fn resolve_workspace_scope_unknown_workspace_is_none() {
        let repositories = memory_repositories();
        assert!(repositories
            .resolve_workspace_scope("missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn stored_workspace_deserializes_with_default_fields() {
        // A minimal document (predating environment/status defaults) still loads.
        let json = r#"{
            "id": "ws-1",
            "project_id": "project-1",
            "tenant_id": "tenant-1",
            "name": "Workspace 1",
            "slug": "ws-1"
        }"#;
        let workspace: StoredWorkspace = serde_json::from_str(json).unwrap();
        assert_eq!(workspace.environment, "default");
        assert_eq!(workspace.status, "active");
        assert_eq!(workspace.created_at_unix, 0);
    }

    #[test]
    fn api_key_record_upsert_get_list_and_prefix_lookup_roundtrip() {
        let repositories = memory_repositories();
        repositories
            .upsert_api_key_record(sample_api_key("key-a", "fg_live"))
            .unwrap();
        repositories
            .upsert_api_key_record(sample_api_key("key-b", "fg_live"))
            .unwrap();
        repositories
            .upsert_api_key_record(sample_api_key("key-c", "fg_test"))
            .unwrap();

        let key = repositories
            .get_api_key_record("key-a")
            .unwrap()
            .expect("api key is stored");
        assert_eq!(key.workspace_id, "ws-dev");
        assert_eq!(key.tenant.organization_id.as_deref(), Some("tenant-a"));
        assert_eq!(key.tenant.project_id.as_deref(), Some("project-a"));
        assert_eq!(key.tenant.workspace_id.as_deref(), Some("ws-dev"));
        assert_eq!(key.tenant.api_key_id.as_deref(), Some("key-a"));

        assert_eq!(repositories.list_api_key_records().unwrap().len(), 3);
        let live_candidates = repositories
            .find_api_key_records_by_prefix("fg_live")
            .unwrap();
        assert_eq!(live_candidates.len(), 2);
        assert!(live_candidates
            .iter()
            .all(|candidate| candidate.key_hash != "fg_live"));
    }

    #[test]
    fn api_key_record_upsert_overwrites_lifecycle_state() {
        let repositories = memory_repositories();
        repositories
            .upsert_api_key_record(sample_api_key("key-a", "fg_live"))
            .unwrap();

        let mut updated = sample_api_key("key-a", "fg_live");
        updated.enabled = false;
        updated.revoked_at_unix = Some(200);
        updated.updated_at_unix = 200;
        repositories.upsert_api_key_record(updated).unwrap();

        let stored = repositories.get_api_key_record("key-a").unwrap().unwrap();
        assert!(!stored.enabled);
        assert_eq!(stored.revoked_at_unix, Some(200));
        assert_eq!(repositories.list_api_key_records().unwrap().len(), 1);
    }

    #[test]
    fn migration_snapshot_includes_api_key_records() {
        let source = memory_repositories();
        source
            .upsert_api_key_record(sample_api_key("key-a", "fg_live"))
            .unwrap();

        let snapshot = source.export_migration_snapshot().unwrap();
        assert_eq!(snapshot.counts().api_key_records, 1);

        let target = memory_repositories();
        target.import_migration_snapshot(snapshot).unwrap();
        let stored = target.get_api_key_record("key-a").unwrap().unwrap();
        assert_eq!(stored.key_prefix, "fg_live");
        assert_eq!(stored.workspace_id, "ws-dev");
    }

    #[test]
    fn stored_api_key_deserializes_legacy_payload_with_durable_defaults() {
        let json = r#"{
            "id": "key-dev",
            "name": "Development key",
            "key_hash": "sha256:stored",
            "enabled": true
        }"#;
        let api_key: StoredApiKey = serde_json::from_str(json).unwrap();
        assert_eq!(api_key.workspace_id, "");
        assert_eq!(api_key.tenant_id, "");
        assert_eq!(api_key.project_id, "");
        assert_eq!(api_key.key_prefix, "");
        assert_eq!(api_key.last4, "");
        assert!(api_key.scopes.is_empty());
        assert_eq!(api_key.created_at_unix, 0);
        assert_eq!(api_key.revoked_at_unix, None);
    }
}
