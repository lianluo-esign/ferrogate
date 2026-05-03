//! Repository boundaries for tenant, key, usage, and request-log storage.

use std::collections::HashMap;

use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::TenantContext;

pub trait Repository<T> {
    fn get(&self, id: &str) -> Option<T>;
    fn list(&self) -> Vec<T>;
}

pub trait ApiKeyRepository: Repository<StoredApiKey> {}

pub trait TenantRepository: Repository<StoredTenant> {}

pub trait PolicyRepository: Repository<StoredPolicyRule> {}

pub trait RequestLogRepository: AppendRepository<StoredRequestLog> {}

pub trait BillingEventRepository: AppendRepository<BillingEvent> {}

pub trait UsageAggregateRepository: Repository<StoredUsageAggregate> {}

pub trait AppendRepository<T> {
    fn append(&mut self, record: T);
    fn list(&self) -> Vec<T>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTenant {
    pub id: String,
    pub name: String,
    pub tenant: TenantContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRequestLog {
    pub request_id: String,
    pub trace_id: Option<String>,
    pub tenant: TenantContext,
    pub route: Option<String>,
    pub provider: Option<String>,
    pub logical_model: Option<String>,
    pub provider_model: Option<String>,
    pub status_code: u16,
    pub error_code: Option<String>,
    pub prompt_recorded: bool,
    pub response_recorded: bool,
    pub prompt_body: Option<String>,
    pub response_body: Option<String>,
    pub started_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    records: Vec<T>,
}

impl<T> InMemoryAppendRepository<T> {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }
}

impl<T: Clone> AppendRepository<T> for InMemoryAppendRepository<T> {
    fn append(&mut self, record: T) {
        self.records.push(record);
    }

    fn list(&self) -> Vec<T> {
        self.records.clone()
    }
}

impl RequestLogRepository for InMemoryAppendRepository<StoredRequestLog> {}

impl BillingEventRepository for InMemoryAppendRepository<BillingEvent> {}

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
            tenant: TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            started_at_unix: Some(1),
            completed_at_unix: Some(2),
        });
        repository.append(StoredRequestLog {
            request_id: "fg-2".into(),
            trace_id: Some("trace-2".into()),
            tenant: TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some("gemini".into()),
            logical_model: Some("flash-chat".into()),
            provider_model: Some("gemini-2.5-flash".into()),
            status_code: 429,
            error_code: Some("rate_limit_exceeded".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            started_at_unix: Some(3),
            completed_at_unix: Some(4),
        });

        let logs = repository.list();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].request_id, "fg-1");
        assert_eq!(logs[1].error_code.as_deref(), Some("rate_limit_exceeded"));
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
}
