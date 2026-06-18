// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Repository boundaries for tenant, key, usage, and request-log storage.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::TenantContext;
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
        matches!(self, StorageProviderKind::Memory)
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

pub trait AppendRepository<T> {
    fn append(&mut self, record: T);
    fn list(&self) -> Vec<T>;
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

#[derive(Debug)]
pub struct RuntimeStorageRepositories {
    backend: RuntimeStorageBackend,
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
}

impl RuntimeStorageRepositories {
    pub fn new(
        backend: RuntimeStorageBackend,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        Self {
            backend,
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
        }
    }

    pub fn in_memory(
        provider_order: Vec<StorageProviderKind>,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        Self::new(
            RuntimeStorageBackend::in_memory(provider_order),
            request_log_retention_records,
            audit_event_retention_records,
        )
    }

    pub fn backend_evidence(&self) -> StorageBackendEvidence {
        self.backend.evidence()
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

        let error = RuntimeStorageBackend::new(StorageProviderKind::TursoLibsql, true, Vec::new())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "storage provider turso_libsql is not implemented yet (required=true)"
        );
    }

    #[test]
    fn runtime_repositories_isolate_control_plane_storage_operations() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 1, 1);

        repositories.append_request_log(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: None,
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
}
