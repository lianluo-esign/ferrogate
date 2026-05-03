use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::config::{Config, Model, PolicyRule as ConfigPolicyRule, Provider, Upstream};
use ferrogate_core::RequestContext;
use ferrogate_policy::{
    BasicPolicyEngine, PolicyDecision, PolicyEngine, PolicyRule, PolicySubject,
};
use ferrogate_providers::{
    AdapterError, ChatCompletionPlan, ModelRegistry, ModelRegistryEntry, ModelRegistryError,
    ProviderAdapterRegistry, ProviderConfig, ProviderErrorResponse, ProviderHttpRequest,
    ProviderUsage, ResolvedModelRoute,
};

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) providers: Arc<HashMap<String, Provider>>,
    pub(crate) upstreams: Arc<HashMap<String, Upstream>>,
    model_registry: Arc<ModelRegistry>,
    provider_adapters: Arc<ProviderAdapterRegistry>,
    policy_engine: Arc<BasicPolicyEngine>,
    upstream_counters: Arc<HashMap<String, AtomicU64>>,
    request_ids: Arc<AtomicU64>,
}

impl AppState {
    pub(crate) fn new(config: Config) -> Self {
        let providers = config
            .providers
            .iter()
            .cloned()
            .map(|provider| (provider.name.clone(), provider))
            .collect();
        let upstreams = config
            .upstreams
            .iter()
            .cloned()
            .map(|upstream| (upstream.name.clone(), upstream))
            .collect();
        let upstream_counters = config
            .upstreams
            .iter()
            .map(|upstream| (upstream.name.clone(), AtomicU64::new(0)))
            .collect();
        let model_registry = ModelRegistry::new(config.models.iter().map(model_registry_entry))
            .expect("config validation must reject invalid model registry entries");

        let policy_engine = build_policy_engine(&config.policies);

        Self {
            config: Arc::new(config),
            providers: Arc::new(providers),
            upstreams: Arc::new(upstreams),
            model_registry: Arc::new(model_registry),
            provider_adapters: Arc::new(ProviderAdapterRegistry::default()),
            policy_engine: Arc::new(policy_engine),
            upstream_counters: Arc::new(upstream_counters),
            request_ids: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) fn next_request_id(&self) -> String {
        let next = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fg-{next:016x}")
    }

    pub(crate) fn auth_required(&self) -> bool {
        !self.config.api_keys.is_empty()
    }

    pub(crate) fn prepare_chat_completions(
        &self,
        provider: &Provider,
        model: &ResolvedModelRoute,
        logical_model: String,
        stream: bool,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.provider_adapters.prepare_chat_completions(
            ProviderConfig {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                api_key: provider.api_key_value(),
            },
            ChatCompletionPlan {
                logical_model,
                provider_model: model.primary.provider_model.clone(),
                stream,
                body,
            },
        )
    }

    pub(crate) fn resolve_model(
        &self,
        logical_model: &str,
    ) -> Result<ResolvedModelRoute, ModelRegistryError> {
        self.model_registry.resolve(logical_model)
    }

    pub(crate) fn normalize_provider_error(
        &self,
        provider_kind: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<ProviderErrorResponse, AdapterError> {
        self.provider_adapters.normalize_error_response(
            provider_kind,
            status,
            content_type,
            body,
            request_id,
        )
    }

    pub(crate) fn extract_provider_usage(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Option<ProviderUsage>, AdapterError> {
        self.provider_adapters.extract_usage(provider_kind, body)
    }

    pub(crate) fn evaluate_policy(
        &self,
        request: &RequestContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> PolicyDecision {
        self.policy_engine.evaluate(request, model, provider)
    }

    pub(crate) fn select_upstream_url(&self, upstream: &Upstream) -> Option<String> {
        let endpoints = upstream.endpoint_urls();
        if endpoints.is_empty() {
            return None;
        }
        let next = self
            .upstream_counters
            .get(&upstream.name)
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(0);
        endpoints
            .get(next as usize % endpoints.len())
            .map(|url| (*url).to_string())
    }
}

fn model_registry_entry(model: &Model) -> ModelRegistryEntry {
    let mut entry = ModelRegistryEntry::new(
        model.name.clone(),
        model.provider.clone(),
        model.provider_model.clone(),
    );
    entry.capabilities = model.capabilities.clone();
    entry.context_window = model.context_window;
    entry.input_price_per_1m = model.input_price_per_1m;
    entry.output_price_per_1m = model.output_price_per_1m;
    entry.enabled = model.enabled;
    entry
}

fn build_policy_engine(config_rules: &[ConfigPolicyRule]) -> BasicPolicyEngine {
    let mut rules = Vec::new();
    for rule in config_rules
        .iter()
        .filter(|rule| rule.enabled && rule.effect.eq_ignore_ascii_case("deny"))
    {
        for organization_id in expand_optional_subjects(&rule.organization_ids) {
            for project_id in expand_optional_subjects(&rule.project_ids) {
                for api_key_id in expand_optional_subjects(&rule.api_key_ids) {
                    rules.push(PolicyRule::deny(
                        PolicySubject {
                            organization_id: organization_id.clone(),
                            project_id: project_id.clone(),
                            api_key_id,
                        },
                        rule.models.clone(),
                        rule.providers.clone(),
                        rule.code.clone(),
                        rule.message.clone(),
                    ));
                }
            }
        }
    }
    BasicPolicyEngine::new(rules)
}

fn expand_optional_subjects(values: &[String]) -> Vec<Option<String>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.iter().cloned().map(Some).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_upstream_endpoints_round_robin() {
        let upstream = Upstream {
            name: "pool".to_string(),
            url: Some("http://127.0.0.1:10001".to_string()),
            urls: vec!["http://127.0.0.1:10002".to_string()],
            enabled: true,
        };
        let config = Config {
            upstreams: vec![upstream.clone()],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10001")
        );
        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10002")
        );
        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10001")
        );
    }
}
