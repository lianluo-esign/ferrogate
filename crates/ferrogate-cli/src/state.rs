use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::config::{Config, Model, Provider, Upstream};
use ferrogate_providers::{
    AdapterError, ChatCompletionPlan, ProviderAdapterRegistry, ProviderConfig,
    ProviderErrorResponse, ProviderHttpRequest, ProviderUsage,
};

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) providers: Arc<HashMap<String, Provider>>,
    pub(crate) models: Arc<HashMap<String, Model>>,
    pub(crate) upstreams: Arc<HashMap<String, Upstream>>,
    provider_adapters: Arc<ProviderAdapterRegistry>,
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
        let models = config
            .models
            .iter()
            .cloned()
            .map(|model| (model.name.clone(), model))
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

        Self {
            config: Arc::new(config),
            providers: Arc::new(providers),
            models: Arc::new(models),
            upstreams: Arc::new(upstreams),
            provider_adapters: Arc::new(ProviderAdapterRegistry::default()),
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
        model: &Model,
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
                provider_model: model.provider_model.clone(),
                stream,
                body,
            },
        )
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
