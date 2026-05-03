//! Repository boundaries for tenant, key, usage, and request-log storage.

use std::collections::HashMap;

use ferrogate_core::TenantContext;

pub trait Repository<T> {
    fn get(&self, id: &str) -> Option<T>;
    fn list(&self) -> Vec<T>;
}

pub trait ApiKeyRepository: Repository<StoredApiKey> {}

pub trait TenantRepository: Repository<StoredTenant> {}

pub trait PolicyRepository: Repository<StoredPolicyRule> {}

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
}
