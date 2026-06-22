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
    future::Future,
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::TenantContext;
use libsql::Builder as LibsqlBuilder;
use mysql::prelude::Queryable;
use mysql::{
    params, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, PooledConn, SslOpts, TxOpts,
};
use native_tls::{Certificate as NativeTlsCertificate, TlsConnector};
use postgres::config::SslMode as PostgresSslMode;
use postgres::{Client as PostgresClient, NoTls};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DURABLE_PROVIDER_ORDER: &[StorageProviderKind] = &[
    StorageProviderKind::TursoLibsql,
    StorageProviderKind::Postgres,
    StorageProviderKind::Mysql,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProviderKind {
    Memory,
    TursoLibsql,
    Postgres,
    Mysql,
}

impl Default for StorageProviderKind {
    fn default() -> Self {
        Self::Memory
    }
}

impl StorageProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageProviderKind::Memory => "memory",
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
                | StorageProviderKind::TursoLibsql
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
    pub provider_order: Vec<StorageProviderKind>,
    pub contract_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStorageBackend {
    provider: StorageProviderKind,
    required: bool,
    provider_order: Vec<StorageProviderKind>,
    contract_version: u32,
}

impl RuntimeStorageBackend {
    pub fn new(
        provider: StorageProviderKind,
        required: bool,
        provider_order: Vec<StorageProviderKind>,
    ) -> Result<Self, StorageError> {
        if !provider.implemented() {
            return Err(StorageError::UnsupportedProvider { provider, required });
        }
        Ok(Self {
            provider,
            required,
            provider_order,
            contract_version: 1,
        })
    }

    pub fn in_memory(provider_order: Vec<StorageProviderKind>) -> Self {
        Self {
            provider: StorageProviderKind::Memory,
            required: false,
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
            provider_order: self.provider_order.clone(),
            contract_version: self.contract_version,
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
    Libsql(String),
    Postgres(String),
    Mysql(String),
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
            StorageError::Libsql(error) => write!(formatter, "libsql storage error: {error}"),
            StorageError::Postgres(error) => write!(formatter, "postgres storage error: {error}"),
            StorageError::Mysql(error) => write!(formatter, "mysql storage error: {error}"),
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
    tool_approvals: InMemoryRepository<StoredControlPlaneResource>,
}

struct LibsqlControlPlaneStore {
    database: Arc<libsql::Database>,
}

struct PostgresControlPlaneStore {
    pool: Arc<PostgresClientPool>,
}

struct MySqlControlPlaneStore {
    pool: Pool,
}

struct PostgresClientPool {
    clients: Mutex<Vec<PostgresClient>>,
    available: Condvar,
}

impl std::fmt::Debug for LibsqlControlPlaneStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LibsqlControlPlaneStore")
            .field("database", &"<redacted>")
            .finish()
    }
}

impl LibsqlControlPlaneStore {
    async fn connect(
        url: String,
        auth_token: Option<String>,
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
        initialize_schema: bool,
    ) -> Result<Self, StorageError> {
        let database = build_libsql_database(url, auth_token).await?;
        let store = Self {
            database: Arc::new(database),
        };
        if initialize_schema {
            store.initialize_schema().await?;
        }
        store
            .seed_missing_resources("api_key", bootstrap_api_keys)
            .await?;
        store
            .seed_missing_resources("tenant", bootstrap_tenants)
            .await?;
        store
            .seed_missing_resources("policy", bootstrap_policies)
            .await?;
        store
            .seed_missing_resources("gateway_config", bootstrap_gateway_configs)
            .await?;
        store
            .seed_missing_resources("agent_workflow", bootstrap_agent_workflows)
            .await?;
        store
            .seed_missing_resources("skill_package", bootstrap_skill_packages)
            .await?;
        store
            .seed_missing_resources("prompt_template", bootstrap_prompt_templates)
            .await?;
        store
            .seed_missing_resources("plugin_registration", bootstrap_plugin_registrations)
            .await?;
        store
            .seed_missing_resources("mcp_server", bootstrap_mcp_servers)
            .await?;
        Ok(store)
    }

    async fn initialize_schema(&self) -> Result<(), StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        connection
            .execute_transactional_batch(include_str!("../../../sql/001_init_libsql.sql"))
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn seed_missing_resources(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        for (id, document_json) in records {
            connection
                .execute(
                    "INSERT OR IGNORE INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES (?1, ?2, ?3)",
                    libsql::params![kind, id, document_json],
                )
                .await
                .map_err(libsql_error)?;
        }
        Ok(())
    }

    async fn snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        Ok(ControlPlaneSnapshot {
            api_keys: self.list_documents("api_key").await?,
            tenants: self.list_documents("tenant").await?,
            policies: self.list_documents("policy").await?,
            gateway_configs: self.list_documents("gateway_config").await?,
            agent_workflows: self.list_documents("agent_workflow").await?,
            skill_packages: self.list_documents("skill_package").await?,
            prompt_templates: self.list_documents("prompt_template").await?,
            plugin_registrations: self.list_documents("plugin_registration").await?,
            mcp_servers: self.list_documents("mcp_server").await?,
        })
    }

    async fn list_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        let mut rows = connection
            .query(
                "SELECT document_json FROM control_plane_resources \
                 WHERE resource_kind = ?1 ORDER BY resource_id ASC",
                libsql::params![kind],
            )
            .await
            .map_err(libsql_error)?;
        let mut documents = Vec::new();
        while let Some(row) = rows.next().await.map_err(libsql_error)? {
            documents.push(row.get::<String>(0).map_err(libsql_error)?);
        }
        Ok(documents)
    }

    async fn get_document(
        &self,
        kind: &'static str,
        id: String,
    ) -> Result<Option<String>, StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        let mut rows = connection
            .query(
                "SELECT document_json FROM control_plane_resources \
                 WHERE resource_kind = ?1 AND resource_id = ?2",
                libsql::params![kind, id],
            )
            .await
            .map_err(libsql_error)?;
        rows.next()
            .await
            .map_err(libsql_error)?
            .map(|row| row.get::<String>(0).map_err(libsql_error))
            .transpose()
    }

    async fn upsert(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        connection
            .execute(
                "INSERT INTO control_plane_resources \
                 (resource_kind, resource_id, document_json, revision, updated_at_unix) \
                 VALUES (?1, ?2, ?3, 1, unixepoch()) \
                 ON CONFLICT(resource_kind, resource_id) DO UPDATE SET \
                 document_json = excluded.document_json, \
                 revision = control_plane_resources.revision + 1, \
                 updated_at_unix = unixepoch()",
                libsql::params![kind, id, document_json],
            )
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn replace_kind(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        let transaction = connection.transaction().await.map_err(libsql_error)?;
        transaction
            .execute(
                "DELETE FROM control_plane_resources WHERE resource_kind = ?1",
                libsql::params![kind],
            )
            .await
            .map_err(libsql_error)?;
        for (id, document_json) in records {
            transaction
                .execute(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES (?1, ?2, ?3)",
                    libsql::params![kind, id, document_json],
                )
                .await
                .map_err(libsql_error)?;
        }
        transaction.commit().await.map_err(libsql_error)?;
        Ok(())
    }

    async fn delete(&self, kind: &'static str, id: String) -> Result<bool, StorageError> {
        let connection = self.database.connect().map_err(libsql_error)?;
        let rows_changed = connection
            .execute(
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = ?1 AND resource_id = ?2",
                libsql::params![kind, id],
            )
            .await
            .map_err(libsql_error)?;
        Ok(rows_changed > 0)
    }
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
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
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
        };
        if initialize_schema {
            store.initialize_schema()?;
        }
        store.seed_missing_resources("api_key", bootstrap_api_keys)?;
        store.seed_missing_resources("tenant", bootstrap_tenants)?;
        store.seed_missing_resources("policy", bootstrap_policies)?;
        store.seed_missing_resources("gateway_config", bootstrap_gateway_configs)?;
        store.seed_missing_resources("agent_workflow", bootstrap_agent_workflows)?;
        store.seed_missing_resources("skill_package", bootstrap_skill_packages)?;
        store.seed_missing_resources("prompt_template", bootstrap_prompt_templates)?;
        store.seed_missing_resources("plugin_registration", bootstrap_plugin_registrations)?;
        store.seed_missing_resources("mcp_server", bootstrap_mcp_servers)?;
        Ok(store)
    }

    fn initialize_schema(&self) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.batch_execute(include_str!("../../../sql/001_init_postgres.sql"))
        })?;
        Ok(())
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
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3) \
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
        })
    }

    fn list_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        self.with_client(|client| {
            let rows = client.query(
                "SELECT document_json FROM control_plane_resources \
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
                "SELECT document_json FROM control_plane_resources \
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
                 VALUES ($1, $2, $3, 1, EXTRACT(EPOCH FROM NOW())::BIGINT) \
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
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3)",
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

    fn with_client<T: Send>(
        &self,
        action: impl FnOnce(&mut PostgresClient) -> Result<T, postgres::Error> + Send,
    ) -> Result<T, StorageError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut client = self.pool.acquire()?;
                    let result = action(&mut client).map_err(postgres_error);
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
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
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
        store.seed_missing_resources("api_key", bootstrap_api_keys)?;
        store.seed_missing_resources("tenant", bootstrap_tenants)?;
        store.seed_missing_resources("policy", bootstrap_policies)?;
        store.seed_missing_resources("gateway_config", bootstrap_gateway_configs)?;
        store.seed_missing_resources("agent_workflow", bootstrap_agent_workflows)?;
        store.seed_missing_resources("skill_package", bootstrap_skill_packages)?;
        store.seed_missing_resources("prompt_template", bootstrap_prompt_templates)?;
        store.seed_missing_resources("plugin_registration", bootstrap_plugin_registrations)?;
        store.seed_missing_resources("mcp_server", bootstrap_mcp_servers)?;
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
        PostgresTlsMode::Disable => pg_config.connect(NoTls).map_err(postgres_error)?,
        PostgresTlsMode::Prefer
        | PostgresTlsMode::Require
        | PostgresTlsMode::VerifyCa
        | PostgresTlsMode::VerifyFull => {
            let connector = build_postgres_tls_connector(config)?;
            pg_config.connect(connector).map_err(postgres_error)?
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

async fn build_libsql_database(
    url: String,
    auth_token: Option<String>,
) -> Result<libsql::Database, StorageError> {
    if let Some(path) = url.strip_prefix("file://") {
        if path.trim().is_empty() {
            return Err(StorageError::Libsql(
                "field storage.libsql_url: file:// path must not be empty".into(),
            ));
        }
        return LibsqlBuilder::new_local(path)
            .build()
            .await
            .map_err(libsql_error);
    }

    let auth_token = match auth_token.filter(|token| !token.trim().is_empty()) {
        Some(token) => token,
        None if is_local_libsql_server_url(&url) => String::new(),
        None => {
            return Err(StorageError::Libsql(
                "field storage.libsql_auth_token_env is required for remote libSQL URLs".into(),
            ));
        }
    };
    LibsqlBuilder::new_remote(url, auth_token)
        .build()
        .await
        .map_err(libsql_error)
}

fn is_local_libsql_server_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| authority.split(':').next().unwrap_or_default());
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

#[derive(Debug)]
enum RuntimeControlPlaneBackend {
    Memory(Mutex<RuntimeControlPlaneState>),
    Libsql(Arc<LibsqlControlPlaneStore>),
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
            tool_approvals: InMemoryRepository::new(),
        }
    }

    pub fn from_documents(
        api_keys: Vec<(String, String)>,
        tenants: Vec<(String, String)>,
        policies: Vec<(String, String)>,
        gateway_configs: Vec<(String, String)>,
        agent_workflows: Vec<(String, String)>,
        skill_packages: Vec<(String, String)>,
        prompt_templates: Vec<(String, String)>,
        plugin_registrations: Vec<(String, String)>,
        mcp_servers: Vec<(String, String)>,
    ) -> Self {
        let mut state = Self::new();
        for (id, document_json) in api_keys {
            state.upsert_api_key(id, document_json);
        }
        for (id, document_json) in tenants {
            state.upsert_tenant(id, document_json);
        }
        for (id, document_json) in policies {
            state.upsert_policy(id, document_json);
        }
        for (id, document_json) in gateway_configs {
            state.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in agent_workflows {
            state.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in skill_packages {
            state.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in prompt_templates {
            state.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in plugin_registrations {
            state.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in mcp_servers {
            state.upsert_mcp_server(id, document_json);
        }
        state
    }

    pub fn replace_config_documents(
        &mut self,
        api_keys: Vec<(String, String)>,
        tenants: Vec<(String, String)>,
        policies: Vec<(String, String)>,
        gateway_configs: Vec<(String, String)>,
        agent_workflows: Vec<(String, String)>,
        skill_packages: Vec<(String, String)>,
        prompt_templates: Vec<(String, String)>,
        plugin_registrations: Vec<(String, String)>,
        mcp_servers: Vec<(String, String)>,
    ) {
        self.api_keys = InMemoryRepository::new();
        self.tenants = InMemoryRepository::new();
        self.policies = InMemoryRepository::new();
        self.gateway_configs = InMemoryRepository::new();
        self.agent_workflows = InMemoryRepository::new();
        self.skill_packages = InMemoryRepository::new();
        self.prompt_templates = InMemoryRepository::new();
        self.plugin_registrations = InMemoryRepository::new();
        self.mcp_servers = InMemoryRepository::new();
        for (id, document_json) in api_keys {
            self.upsert_api_key(id, document_json);
        }
        for (id, document_json) in tenants {
            self.upsert_tenant(id, document_json);
        }
        for (id, document_json) in policies {
            self.upsert_policy(id, document_json);
        }
        for (id, document_json) in gateway_configs {
            self.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in agent_workflows {
            self.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in skill_packages {
            self.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in prompt_templates {
            self.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in plugin_registrations {
            self.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in mcp_servers {
            self.upsert_mcp_server(id, document_json);
        }
    }

    pub fn snapshot(&self) -> ControlPlaneSnapshot {
        let mut api_keys = self
            .api_keys
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        api_keys.sort_by(|left, right| left.0.cmp(&right.0));

        let mut tenants = self
            .tenants
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        tenants.sort_by(|left, right| left.0.cmp(&right.0));

        let mut policies = self
            .policies
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        policies.sort_by(|left, right| left.0.cmp(&right.0));

        let mut gateway_configs = self
            .gateway_configs
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        gateway_configs.sort_by(|left, right| left.0.cmp(&right.0));

        let mut agent_workflows = self
            .agent_workflows
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        agent_workflows.sort_by(|left, right| left.0.cmp(&right.0));

        let mut skill_packages = self
            .skill_packages
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        skill_packages.sort_by(|left, right| left.0.cmp(&right.0));

        let mut prompt_templates = self
            .prompt_templates
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        prompt_templates.sort_by(|left, right| left.0.cmp(&right.0));

        let mut plugin_registrations = self
            .plugin_registrations
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        plugin_registrations.sort_by(|left, right| left.0.cmp(&right.0));

        let mut mcp_servers = self
            .mcp_servers
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        mcp_servers.sort_by(|left, right| left.0.cmp(&right.0));

        ControlPlaneSnapshot {
            api_keys: api_keys
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            tenants: tenants
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            policies: policies
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            gateway_configs: gateway_configs
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            agent_workflows: agent_workflows
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            skill_packages: skill_packages
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            prompt_templates: prompt_templates
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            plugin_registrations: plugin_registrations
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
            mcp_servers: mcp_servers
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
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
        let mut approvals = self
            .tool_approvals
            .list()
            .into_iter()
            .map(|resource| (resource.id, resource.document_json))
            .collect::<Vec<_>>();
        approvals.sort_by(|left, right| left.0.cmp(&right.0));
        approvals
            .into_iter()
            .map(|(_, document_json)| document_json)
            .collect()
    }
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

#[derive(Debug)]
pub struct RuntimeStorageRepositories {
    backend: RuntimeStorageBackend,
    control_plane: RuntimeControlPlaneBackend,
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    agent_run_events: Mutex<InMemoryAppendRepository<StoredAgentRunEvent>>,
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
            control_plane: RuntimeControlPlaneBackend::Memory(Mutex::new(control_plane)),
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            agent_run_events: Mutex::new(InMemoryAppendRepository::new()),
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

    pub async fn turso_libsql(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        url: String,
        auth_token: Option<String>,
        initialize_schema: bool,
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Result<Self, StorageError> {
        let backend =
            RuntimeStorageBackend::new(StorageProviderKind::TursoLibsql, required, provider_order)?;
        let control_plane = LibsqlControlPlaneStore::connect(
            url,
            auth_token,
            bootstrap_api_keys,
            bootstrap_tenants,
            bootstrap_policies,
            bootstrap_gateway_configs,
            bootstrap_agent_workflows,
            bootstrap_skill_packages,
            bootstrap_prompt_templates,
            bootstrap_plugin_registrations,
            bootstrap_mcp_servers,
            initialize_schema,
        )
        .await?;
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Libsql(Arc::new(control_plane)),
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            agent_run_events: Mutex::new(InMemoryAppendRepository::new()),
        })
    }

    pub fn postgres(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        config: PostgresStorageConfig,
        initialize_schema: bool,
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Result<Self, StorageError> {
        let backend =
            RuntimeStorageBackend::new(StorageProviderKind::Postgres, required, provider_order)?;
        let control_plane = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    PostgresControlPlaneStore::connect(
                        config,
                        bootstrap_api_keys,
                        bootstrap_tenants,
                        bootstrap_policies,
                        bootstrap_gateway_configs,
                        bootstrap_agent_workflows,
                        bootstrap_skill_packages,
                        bootstrap_prompt_templates,
                        bootstrap_plugin_registrations,
                        bootstrap_mcp_servers,
                        initialize_schema,
                    )
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
        })
    }

    pub fn mysql(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        config: MySqlStorageConfig,
        initialize_schema: bool,
        bootstrap_api_keys: Vec<(String, String)>,
        bootstrap_tenants: Vec<(String, String)>,
        bootstrap_policies: Vec<(String, String)>,
        bootstrap_gateway_configs: Vec<(String, String)>,
        bootstrap_agent_workflows: Vec<(String, String)>,
        bootstrap_skill_packages: Vec<(String, String)>,
        bootstrap_prompt_templates: Vec<(String, String)>,
        bootstrap_plugin_registrations: Vec<(String, String)>,
        bootstrap_mcp_servers: Vec<(String, String)>,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Result<Self, StorageError> {
        let backend =
            RuntimeStorageBackend::new(StorageProviderKind::Mysql, required, provider_order)?;
        let control_plane = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    MySqlControlPlaneStore::connect(
                        config,
                        bootstrap_api_keys,
                        bootstrap_tenants,
                        bootstrap_policies,
                        bootstrap_gateway_configs,
                        bootstrap_agent_workflows,
                        bootstrap_skill_packages,
                        bootstrap_prompt_templates,
                        bootstrap_plugin_registrations,
                        bootstrap_mcp_servers,
                        initialize_schema,
                    )
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
        })
    }

    pub fn backend_evidence(&self) -> StorageBackendEvidence {
        self.backend.evidence()
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
                })),
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.snapshot())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.snapshot(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane.snapshot(),
        }
    }

    pub fn replace_control_plane(
        &self,
        api_keys: Vec<(String, String)>,
        tenants: Vec<(String, String)>,
        policies: Vec<(String, String)>,
        gateway_configs: Vec<(String, String)>,
        agent_workflows: Vec<(String, String)>,
        skill_packages: Vec<(String, String)>,
        prompt_templates: Vec<(String, String)>,
        plugin_registrations: Vec<(String, String)>,
        mcp_servers: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.replace_config_documents(
                        api_keys,
                        tenants,
                        policies,
                        gateway_configs,
                        agent_workflows,
                        skill_packages,
                        prompt_templates,
                        plugin_registrations,
                        mcp_servers,
                    );
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Libsql(control_plane) => block_on_storage(async {
                control_plane.replace_kind("api_key", api_keys).await?;
                control_plane.replace_kind("tenant", tenants).await?;
                control_plane.replace_kind("policy", policies).await?;
                control_plane
                    .replace_kind("gateway_config", gateway_configs)
                    .await?;
                control_plane
                    .replace_kind("agent_workflow", agent_workflows)
                    .await?;
                control_plane
                    .replace_kind("skill_package", skill_packages)
                    .await?;
                control_plane
                    .replace_kind("prompt_template", prompt_templates)
                    .await?;
                control_plane
                    .replace_kind("plugin_registration", plugin_registrations)
                    .await?;
                control_plane
                    .replace_kind("mcp_server", mcp_servers)
                    .await?;
                Ok(())
            }),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.replace_kind("api_key", api_keys)?;
                control_plane.replace_kind("tenant", tenants)?;
                control_plane.replace_kind("policy", policies)?;
                control_plane.replace_kind("gateway_config", gateway_configs)?;
                control_plane.replace_kind("agent_workflow", agent_workflows)?;
                control_plane.replace_kind("skill_package", skill_packages)?;
                control_plane.replace_kind("prompt_template", prompt_templates)?;
                control_plane.replace_kind("plugin_registration", plugin_registrations)?;
                control_plane.replace_kind("mcp_server", mcp_servers)?;
                Ok(())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.replace_kind("api_key", api_keys)?;
                control_plane.replace_kind("tenant", tenants)?;
                control_plane.replace_kind("policy", policies)?;
                control_plane.replace_kind("gateway_config", gateway_configs)?;
                control_plane.replace_kind("agent_workflow", agent_workflows)?;
                control_plane.replace_kind("skill_package", skill_packages)?;
                control_plane.replace_kind("prompt_template", prompt_templates)?;
                control_plane.replace_kind("plugin_registration", plugin_registrations)?;
                control_plane.replace_kind("mcp_server", mcp_servers)?;
                Ok(())
            }
        }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("api_key", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("api_key", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("policy", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("policy", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("gateway_config", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("gateway_config", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("agent_workflow", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("agent_workflow", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("skill_package", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("skill_package", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("prompt_template", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => block_on_storage(
                control_plane.upsert("plugin_registration", id.into(), document_json),
            ),
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("plugin_registration", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("mcp_server", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.delete("mcp_server", id.to_string()))
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete("mcp_server", id.to_string())
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.delete("mcp_server", id.to_string())
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert("tool_approval", id.into(), document_json))
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.get_document("tool_approval", id.to_string()))
            }
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.list_documents("tool_approval"))
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_documents("tool_approval")
            }
            RuntimeControlPlaneBackend::Mysql(control_plane) => {
                control_plane.list_documents("tool_approval")
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
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    pub fn request_logs(&self) -> Vec<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| logs.list())
            .unwrap_or_default()
    }

    pub fn request_logs_page(&self, offset: usize, limit: usize) -> StoragePage<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| StoragePage {
                data: logs.list_paginated(offset, limit),
                total: logs.len(),
                offset,
                limit,
            })
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    pub fn append_audit_event(&self, event: StoredAuditEvent) {
        if let Ok(mut events) = self.audit_events.lock() {
            events.append(event);
        }
    }

    pub fn next_audit_event_id(&self) -> String {
        self.audit_events
            .lock()
            .map(|events| format!("audit-{}", events.len() + 1))
            .unwrap_or_else(|_| "audit-unknown".to_string())
    }

    pub fn audit_events(&self) -> Vec<StoredAuditEvent> {
        self.audit_events
            .lock()
            .map(|events| events.list())
            .unwrap_or_default()
    }

    pub fn audit_events_page(&self, offset: usize, limit: usize) -> StoragePage<StoredAuditEvent> {
        self.audit_events
            .lock()
            .map(|events| StoragePage {
                data: events.list_paginated(offset, limit),
                total: events.len(),
                offset,
                limit,
            })
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    pub fn upsert_usage_aggregate(
        &self,
        id: impl Into<String>,
        build: impl FnOnce(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) {
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let id = id.into();
            let existing = aggregates.get(&id);
            aggregates.insert(id, build(existing));
        }
    }

    pub fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        self.usage_aggregates
            .lock()
            .map(|aggregates| aggregates.list())
            .unwrap_or_default()
    }

    pub fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut runs) = self.agent_runs.lock() {
                    runs.insert(run.id.clone(), run);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Libsql(control_plane) => block_on_storage(
                control_plane.upsert("agent_run", run.id.clone(), serialize_storage_record(&run)?),
            ),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert("agent_run", run.id.clone(), serialize_storage_record(&run)?)
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.get_document("agent_run", id.to_string()))
                    .ok()
                    .flatten()
                    .and_then(|document| serde_json::from_str(&document).ok())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .get_document("agent_run", id.to_string())
                .ok()
                .flatten()
                .and_then(|document| serde_json::from_str(&document).ok()),
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.list_documents("agent_run"))
                    .map(deserialize_storage_records)
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .list_documents("agent_run")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.upsert(
                    "agent_run_event",
                    event.id.clone(),
                    serialize_storage_record(&event)?,
                ))
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.upsert(
                "agent_run_event",
                event.id.clone(),
                serialize_storage_record(&event)?,
            ),
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
            RuntimeControlPlaneBackend::Libsql(control_plane) => {
                block_on_storage(control_plane.list_documents("agent_run_event"))
                    .map(deserialize_storage_records)
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .list_documents("agent_run_event")
                .map(deserialize_storage_records)
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Mysql(control_plane) => control_plane
                .list_documents("agent_run_event")
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

fn block_on_storage<T: Send>(
    future: impl Future<Output = Result<T, StorageError>> + Send,
) -> Result<T, StorageError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| StorageError::Libsql(error.to_string()))?
                    .block_on(future)
            })
            .join()
            .map_err(|_| StorageError::Libsql("storage runtime thread panicked".into()))?
    })
}

fn libsql_error(error: libsql::Error) -> StorageError {
    StorageError::Libsql(error.to_string())
}

fn postgres_error(error: postgres::Error) -> StorageError {
    StorageError::Postgres(error.to_string())
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
                StorageProviderKind::TursoLibsql,
                StorageProviderKind::Postgres,
                StorageProviderKind::Mysql,
            ]
        );

        let turso_backend =
            RuntimeStorageBackend::new(StorageProviderKind::TursoLibsql, true, Vec::new()).unwrap();
        assert!(turso_backend.evidence().durable);
        assert!(turso_backend.evidence().implemented);

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
        let error = RuntimeStorageRepositories::postgres(
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
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("storage.postgres_tls_ca_cert_path"));
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
            .replace_control_plane(
                vec![("key_a".into(), r#"{"id":"key_a","name":"A"}"#.to_string())],
                Vec::new(),
                vec![(
                    "deny_a".into(),
                    r#"{"name":"deny_a","effect":"deny"}"#.to_string(),
                )],
                Vec::new(),
                Vec::new(),
                vec![(
                    "tool.echo".into(),
                    r#"{"id":"tool.echo","source":"builtin"}"#.to_string(),
                )],
                vec![(
                    "github".into(),
                    r#"{"name":"github","transport":"streamable_http"}"#.to_string(),
                )],
            )
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

        repositories.upsert_usage_aggregate("org:project:fast-chat:openai", |_| {
            StoredUsageAggregate {
                id: "org:project:fast-chat:openai".into(),
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                logical_model: "fast-chat".into(),
                provider: "openai".into(),
                usage: TokenUsage::new(1, 2, 3),
            }
        });
        assert_eq!(repositories.usage_aggregates()[0].usage.total_tokens, 3);
    }

    #[test]
    fn libsql_file_store_persists_tool_approval_documents() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ferrogate-control-plane.db");
        let url = format!("file://{}", db_path.display());
        let approval_json = r#"{"id":"approval-1","tool_name":"github.search","status":"pending"}"#;

        let repositories = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url.clone(),
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();
        repositories
            .upsert_control_plane_tool_approval("approval-1", approval_json.to_string())
            .unwrap();

        let reopened = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url,
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();

        assert_eq!(
            reopened
                .control_plane_tool_approval("approval-1")
                .unwrap()
                .as_deref(),
            Some(approval_json)
        );
        assert!(reopened
            .control_plane_tool_approvals()
            .unwrap()
            .iter()
            .any(|document| document.contains("\"tool_name\":\"github.search\"")));
    }

    #[test]
    fn libsql_file_store_persists_agent_run_records() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ferrogate-agent-runs.db");
        let url = format!("file://{}", db_path.display());
        let tenant = TenantContext {
            organization_id: Some("org_demo".into()),
            project_id: Some("project_gateway".into()),
            api_key_id: Some("agent-client".into()),
            ..TenantContext::default()
        };

        let repositories = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url.clone(),
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();
        repositories
            .upsert_agent_run(StoredAgentRun {
                id: "agent-run-1".into(),
                request_id: "fg-1".into(),
                trace_id: Some("fg-1".into()),
                tenant: tenant.clone(),
                status: "completed".into(),
                provider: "ferrogate.default".into(),
                turns_executed: 1,
                output_recorded: true,
                started_at_unix: Some(10),
                completed_at_unix: Some(11),
            })
            .unwrap();
        repositories
            .append_agent_run_event(StoredAgentRunEvent {
                id: "agent-run-1:0001:run-completed".into(),
                run_id: "agent-run-1".into(),
                request_id: "fg-1".into(),
                trace_id: Some("fg-1".into()),
                tenant,
                turn: 1,
                kind: "run_completed".into(),
                target: "agent_run:agent-run-1".into(),
                outcome: "success".into(),
                tool_call_id: None,
                message: Some("agent run completed".into()),
                occurred_at_unix: Some(11),
            })
            .unwrap();

        let reopened = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url,
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();

        let run = reopened.agent_run("agent-run-1").unwrap();
        assert_eq!(run.status, "completed");
        assert_eq!(run.tenant.api_key_id.as_deref(), Some("agent-client"));
        let events = reopened.agent_run_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].run_id, "agent-run-1");
        assert_eq!(events[0].kind, "run_completed");
    }

    #[test]
    fn libsql_file_store_persists_plugin_registration_documents() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ferrogate-control-plane.db");
        let url = format!("file://{}", db_path.display());
        let plugin_json = r#"{"id":"tool.echo","kind":"tool_provider","enabled":true,"source":"builtin","order":10,"approval_policy":"never","permissions":{"tools":["tool.echo"],"network":[],"filesystem":false,"shell":false},"config":{"timeout_ms":30000}}"#;

        let repositories = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url.clone(),
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();
        repositories
            .upsert_control_plane_plugin_registration("tool.echo", plugin_json.to_string())
            .unwrap();

        let reopened = block_on_storage(RuntimeStorageRepositories::turso_libsql(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            url,
            None,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            10,
            10,
        ))
        .unwrap();

        assert!(reopened
            .control_plane_snapshot()
            .unwrap()
            .plugin_registrations
            .iter()
            .any(|document| document == plugin_json));
    }
}
