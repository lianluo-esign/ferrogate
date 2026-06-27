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
use ferrogate_core::TenantContext;
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMigrationCounts {
    pub api_keys: usize,
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
}

impl StorageMigrationSnapshot {
    pub fn counts(&self) -> StorageMigrationCounts {
        StorageMigrationCounts {
            api_keys: self.control_plane.api_keys.len(),
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
const POSTGRES_SCHEMA_VERSION: u64 = 4;
const POSTGRES_SCHEMA_NAME: &str = "004_supabase_managed_worker_lifecycle";

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

#[derive(Debug)]
pub struct RuntimeControlPlaneState {
    api_keys: InMemoryRepository<StoredControlPlaneResource>,
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
        "request_logs",
        "audit_events",
        "billing_metering_events",
        "usage_aggregates",
        "tenant_contexts",
        "metering_events",
        "metering_event_routes",
        "metering_event_usage",
        "usage_aggregate_rollups",
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
        ("request_logs", "request_json"),
        ("audit_events", "audit_json"),
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

    const INDEXES: &[&str] = &[
        "idx_control_plane_resources_document_gin",
        "idx_agent_runs_tenant_started",
        "idx_agent_run_events_run_time",
        "idx_managed_worker_templates_enabled_adapter",
        "idx_agent_worker_instances_status_seen",
        "idx_managed_worker_sessions_tenant_status",
        "idx_managed_worker_lifecycle_session_time",
        "idx_request_logs_model_provider_started",
        "idx_audit_events_actor_time",
        "idx_billing_metering_model_provider_time",
        "idx_usage_aggregates_tenant_model_provider",
        "idx_tenant_contexts_api_key",
        "idx_metering_events_tenant_time",
        "idx_metering_event_routes_model_provider",
        "idx_usage_rollups_tenant_model_provider",
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

fn nonnegative_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn serialize_storage_document<T: Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|error| StorageError::Serialization(error.to_string()))
}

fn deserialize_storage_document<T: for<'de> Deserialize<'de>>(
    value: &str,
) -> Result<T, StorageError> {
    serde_json::from_str(value).map_err(|error| StorageError::Serialization(error.to_string()))
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
        }
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
    pub name: String,
    pub key_hash: String,
    pub enabled: bool,
    pub scopes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub allowed_providers: Vec<String>,
    pub tenant: TenantContext,
    pub monthly_token_budget: Option<u64>,
    pub request_limit_per_minute: Option<u64>,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTenant {
    pub id: String,
    pub name: String,
    pub tenant: TenantContext,
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
}

impl RuntimeStorageRepositories {
    pub fn new(
        backend: RuntimeStorageBackend,
        control_plane: RuntimeControlPlaneState,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Memory(Box::new(Mutex::new(control_plane))),
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
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
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
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Mysql(Arc::new(control_plane)),
            request_logs: Mutex::new(InMemoryAppendRepository::new()),
            audit_events: Mutex::new(InMemoryAppendRepository::new()),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            agent_run_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_templates: Mutex::new(InMemoryRepository::new()),
            agent_worker_instances: Mutex::new(InMemoryRepository::new()),
            managed_worker_sessions: Mutex::new(InMemoryRepository::new()),
            managed_worker_lifecycle_events: Mutex::new(InMemoryAppendRepository::new()),
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
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
            request_logs: Mutex::new(InMemoryAppendRepository::new()),
            audit_events: Mutex::new(InMemoryAppendRepository::new()),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            agent_run_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_templates: Mutex::new(InMemoryRepository::new()),
            agent_worker_instances: Mutex::new(InMemoryRepository::new()),
            managed_worker_sessions: Mutex::new(InMemoryRepository::new()),
            managed_worker_lifecycle_events: Mutex::new(InMemoryAppendRepository::new()),
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
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Mysql(Arc::new(control_plane)),
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
        })
    }

    pub fn import_migration_snapshot(
        &self,
        snapshot: StorageMigrationSnapshot,
    ) -> Result<(), StorageError> {
        self.replace_control_plane(snapshot.control_plane)?;
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
                name: "Development key".into(),
                key_hash: "blake2b:test".into(),
                enabled: true,
                scopes: vec!["chat.completions".into()],
                allowed_models: vec!["fast-chat".into()],
                allowed_providers: vec!["openai".into()],
                tenant: TenantContext {
                    organization_id: Some("org".into()),
                    team_id: None,
                    project_id: Some("project".into()),
                    user_id: None,
                    api_key_id: Some("key_dev".into()),
                },
                monthly_token_budget: Some(1_000),
                request_limit_per_minute: Some(60),
                expires_at_unix: None,
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
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "running".into(),
                action: "start".into(),
                outcome: "succeeded".into(),
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
    }

    #[test]
    fn migration_snapshot_includes_managed_worker_lifecycle_records() {
        let source =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
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
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "cleaned_up".into(),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
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

        let target =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        target.import_migration_snapshot(snapshot).unwrap();

        assert_eq!(target.managed_worker_templates().len(), 1);
        assert_eq!(target.agent_worker_instances().len(), 1);
        assert_eq!(target.managed_worker_sessions().len(), 1);
        assert_eq!(target.managed_worker_lifecycle_events().len(), 1);
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
}
