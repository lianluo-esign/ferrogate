use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::config::{Config, Model, PolicyRule as ConfigPolicyRule, Provider, Upstream};
use ferrogate_billing::{
    BillingEvent, BillingEventSink, InMemoryBillingEventSink, ModelPrice,
    TokenUsage as BillingTokenUsage,
};
use ferrogate_core::RequestContext;
use ferrogate_observability::{
    CostMetricTotal, GatewayMetricsSnapshot, ModelProviderMetricTotal, RequestStatusMetric,
    TokenMetricTotals,
};
use ferrogate_policy::{
    BasicPolicyEngine, PolicyDecision, PolicyEngine, PolicyRule, PolicySubject,
};
use ferrogate_providers::{
    AdapterError, ChatCompletionPlan, ModelRegistry, ModelRegistryEntry, ModelRegistryError,
    ModelRoute, ProviderAdapterRegistry, ProviderConfig, ProviderErrorResponse,
    ProviderHttpRequest, ProviderUsage, ResolvedModelRoute,
};
use ferrogate_storage::{AppendRepository, InMemoryAppendRepository, StoredRequestLog};

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) providers: Arc<HashMap<String, Provider>>,
    pub(crate) upstreams: Arc<HashMap<String, Upstream>>,
    model_visibility: Arc<HashMap<String, ModelVisibility>>,
    model_prices: Arc<HashMap<String, ModelPrice>>,
    model_registry: Arc<ModelRegistry>,
    provider_adapters: Arc<ProviderAdapterRegistry>,
    billing_events: Arc<InMemoryBillingEventSink>,
    request_logs: Arc<Mutex<InMemoryAppendRepository<StoredRequestLog>>>,
    policy_engine: Arc<BasicPolicyEngine>,
    upstream_counters: Arc<HashMap<String, AtomicU64>>,
    model_route_counter: Arc<AtomicU64>,
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
        let model_visibility = config
            .models
            .iter()
            .map(|model| (model.name.clone(), ModelVisibility::from(model)))
            .collect();
        let model_prices = config
            .models
            .iter()
            .filter_map(|model| model_price(model).map(|price| (model.name.clone(), price)))
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
            model_visibility: Arc::new(model_visibility),
            model_prices: Arc::new(model_prices),
            model_registry: Arc::new(model_registry),
            provider_adapters: Arc::new(ProviderAdapterRegistry::default()),
            billing_events: Arc::new(InMemoryBillingEventSink::default()),
            request_logs: Arc::new(Mutex::new(InMemoryAppendRepository::new())),
            policy_engine: Arc::new(policy_engine),
            upstream_counters: Arc::new(upstream_counters),
            model_route_counter: Arc::new(AtomicU64::new(0)),
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
        model_route: &ModelRoute,
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
                provider_model: model_route.provider_model.clone(),
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

    pub(crate) fn candidate_model_routes(&self, model: &ResolvedModelRoute) -> Vec<ModelRoute> {
        let mut routes = vec![model.primary.clone()];
        let mut cursor = self.model_route_counter.fetch_add(1, Ordering::Relaxed);
        let mut fallbacks = model.fallbacks.as_slice();

        while let Some((priority, group_end)) = fallback_priority_group(fallbacks) {
            let group = &fallbacks[..group_end];
            let start = weighted_start_index(group, cursor);
            routes.extend(group[start..].iter().cloned());
            routes.extend(group[..start].iter().cloned());
            cursor /= total_weight(group);
            fallbacks = &fallbacks[group_end..];
            debug_assert!(group.iter().all(|route| route.priority == priority));
        }

        routes
    }

    pub(crate) fn can_tenant_use_model(
        &self,
        logical_model: &str,
        organization_id: Option<&str>,
        project_id: Option<&str>,
    ) -> bool {
        self.model_visibility
            .get(logical_model)
            .is_none_or(|visibility| visibility.allows(organization_id, project_id))
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

    pub(crate) fn is_provider_status_retryable(
        &self,
        provider_kind: &str,
        status: u16,
    ) -> Result<bool, AdapterError> {
        self.provider_adapters
            .is_retryable_status(provider_kind, status)
    }

    pub(crate) fn evaluate_policy(
        &self,
        request: &RequestContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> PolicyDecision {
        self.policy_engine.evaluate(request, model, provider)
    }

    pub(crate) fn record_billing_event(
        &self,
        request: &RequestContext,
        logical_model: &str,
        provider: &str,
        provider_model: &str,
        usage: &ProviderUsage,
        status_code: u16,
    ) -> Result<(), ferrogate_billing::BillingError> {
        let usage = BillingTokenUsage::new(
            usage.prompt_tokens.unwrap_or_default(),
            usage.completion_tokens.unwrap_or_default(),
            usage.total_tokens.unwrap_or_default(),
        )
        .estimate_missing_total();
        let cost = self
            .model_prices
            .get(logical_model)
            .map(|price| price.estimate(&usage));
        self.billing_events.record(BillingEvent {
            request_id: request.request_id.clone(),
            trace_id: request.trace_id.clone(),
            tenant: request.tenant.clone(),
            logical_model: logical_model.into(),
            provider: provider.into(),
            provider_model: provider_model.into(),
            usage,
            cost,
            status_code,
            occurred_at_unix: None,
        })
    }

    #[cfg(test)]
    fn billing_events(&self) -> Vec<BillingEvent> {
        self.billing_events.list()
    }

    pub(crate) fn record_request_log(&self, log: StoredRequestLog) {
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    pub(crate) fn prometheus_metrics_snapshot(&self) -> GatewayMetricsSnapshot {
        let request_logs = self
            .request_logs
            .lock()
            .map(|logs| logs.list())
            .unwrap_or_default();
        let billing_events = self.billing_events.list();

        let mut status_totals = BTreeMap::<u16, u64>::new();
        let mut token_totals = TokenMetricTotals::default();
        let mut cost_totals = BTreeMap::<String, f64>::new();
        let mut model_provider_totals =
            BTreeMap::<(String, String), ModelProviderMetricTotal>::new();

        for log in &request_logs {
            *status_totals.entry(log.status_code).or_default() += 1;
        }

        for event in &billing_events {
            token_totals.prompt_tokens += event.usage.prompt_tokens;
            token_totals.completion_tokens += event.usage.completion_tokens;
            token_totals.total_tokens += event.usage.total_tokens;

            if let Some(cost) = &event.cost {
                *cost_totals.entry(cost.currency.clone()).or_default() += cost.total_cost;
            }

            let key = (event.logical_model.clone(), event.provider.clone());
            let total =
                model_provider_totals
                    .entry(key)
                    .or_insert_with(|| ModelProviderMetricTotal {
                        logical_model: event.logical_model.clone(),
                        provider: event.provider.clone(),
                        requests: 0,
                        total_tokens: 0,
                    });
            total.requests += 1;
            total.total_tokens += event.usage.total_tokens;
        }

        GatewayMetricsSnapshot {
            service_name: self.state_service_name(),
            request_log_total: request_logs.len() as u64,
            request_error_total: request_logs
                .iter()
                .filter(|log| log.status_code >= 400 || log.error_code.is_some())
                .count() as u64,
            request_status_totals: status_totals
                .into_iter()
                .map(|(status_code, count)| RequestStatusMetric { status_code, count })
                .collect(),
            billing_event_total: billing_events.len() as u64,
            token_totals,
            cost_estimates: cost_totals
                .into_iter()
                .map(|(currency, amount)| CostMetricTotal { currency, amount })
                .collect(),
            model_provider_totals: model_provider_totals.into_values().collect(),
        }
    }

    fn state_service_name(&self) -> String {
        self.config.telemetry.service_name.clone()
    }

    #[cfg(test)]
    fn request_logs(&self) -> Vec<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| logs.list())
            .unwrap_or_default()
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

#[derive(Debug, Clone, Default)]
struct ModelVisibility {
    organization_ids: Vec<String>,
    project_ids: Vec<String>,
}

impl ModelVisibility {
    fn allows(&self, organization_id: Option<&str>, project_id: Option<&str>) -> bool {
        allows_optional_scope(&self.organization_ids, organization_id)
            && allows_optional_scope(&self.project_ids, project_id)
    }
}

impl From<&Model> for ModelVisibility {
    fn from(model: &Model) -> Self {
        Self {
            organization_ids: model.visible_organization_ids.clone(),
            project_ids: model.visible_project_ids.clone(),
        }
    }
}

fn allows_optional_scope(allowed_values: &[String], actual: Option<&str>) -> bool {
    allowed_values.is_empty()
        || actual.is_some_and(|actual| allowed_values.iter().any(|allowed| allowed == actual))
}

fn fallback_priority_group(routes: &[ModelRoute]) -> Option<(u32, usize)> {
    let priority = routes.first()?.priority;
    let end = routes
        .iter()
        .position(|route| route.priority != priority)
        .unwrap_or(routes.len());
    Some((priority, end))
}

fn weighted_start_index(routes: &[ModelRoute], cursor: u64) -> usize {
    let total = total_weight(routes);
    let mut remaining = cursor % total;
    for (index, route) in routes.iter().enumerate() {
        let weight = u64::from(route.weight.max(1));
        if remaining < weight {
            return index;
        }
        remaining -= weight;
    }
    0
}

fn total_weight(routes: &[ModelRoute]) -> u64 {
    routes
        .iter()
        .map(|route| u64::from(route.weight.max(1)))
        .sum::<u64>()
        .max(1)
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
    entry.fallbacks = model
        .fallbacks
        .iter()
        .filter(|fallback| fallback.enabled)
        .map(|fallback| {
            ModelRoute::with_routing(
                fallback.provider.clone(),
                fallback.provider_model.clone(),
                fallback.priority.unwrap_or(100),
                fallback.weight.unwrap_or(1),
            )
        })
        .collect();
    entry
}

fn model_price(model: &Model) -> Option<ModelPrice> {
    match (model.input_price_per_1m, model.output_price_per_1m) {
        (None, None) => None,
        (input, output) => Some(ModelPrice::usd(
            input.unwrap_or_default(),
            output.unwrap_or_default(),
        )),
    }
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

    #[test]
    fn orders_model_fallbacks_with_weighted_rotation_within_priority() {
        let config = Config {
            providers: vec![
                Provider {
                    name: "primary".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10001/v1".into(),
                    api_key_env: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-a".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-b".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let first = state
            .candidate_model_routes(&resolved)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let second = state
            .candidate_model_routes(&resolved)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let third = state
            .candidate_model_routes(&resolved)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(first, ["primary", "backup-b", "backup-a"]);
        assert_eq!(second, ["primary", "backup-b", "backup-a"]);
        assert_eq!(third, ["primary", "backup-a", "backup-b"]);
    }

    #[test]
    fn records_billing_event_with_model_price() {
        let config = Config {
            providers: vec![Provider {
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let request = RequestContext {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("org".into()),
                team_id: None,
                project_id: Some("project".into()),
                user_id: None,
                api_key_id: Some("key_dev".into()),
            },
        };

        state
            .record_billing_event(
                &request,
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ProviderUsage {
                    prompt_tokens: Some(3),
                    completion_tokens: Some(5),
                    total_tokens: Some(8),
                },
                200,
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant.organization_id.as_deref(), Some("org"));
        assert_eq!(events[0].usage.total_tokens, 8);
        assert_eq!(events[0].cost.as_ref().unwrap().currency, "USD");
    }

    #[test]
    fn records_structured_request_logs_without_body_flags_by_default() {
        let state = AppState::new(Config::default());
        state.record_request_log(StoredRequestLog {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            tenant: ferrogate_core::TenantContext::default(),
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
            started_at_unix: None,
            completed_at_unix: None,
        });

        let logs = state.request_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_id, "fg-test");
        assert!(!logs[0].prompt_recorded);
        assert!(!logs[0].response_recorded);
        assert!(logs[0].prompt_body.is_none());
        assert!(logs[0].response_body.is_none());
    }

    #[test]
    fn prometheus_metrics_snapshot_aggregates_request_logs_and_billing() {
        let config = Config {
            telemetry: crate::config::TelemetryConfig {
                service_name: "ferrogate-test".into(),
                log_bodies: false,
            },
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let request = RequestContext {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext::default(),
        };

        state.record_request_log(StoredRequestLog {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            tenant: ferrogate_core::TenantContext::default(),
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
            started_at_unix: None,
            completed_at_unix: None,
        });
        state
            .record_billing_event(
                &request,
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ProviderUsage {
                    prompt_tokens: Some(3),
                    completion_tokens: Some(5),
                    total_tokens: Some(8),
                },
                200,
            )
            .unwrap();

        let snapshot = state.prometheus_metrics_snapshot();

        assert_eq!(snapshot.service_name, "ferrogate-test");
        assert_eq!(snapshot.request_log_total, 1);
        assert_eq!(snapshot.request_status_totals[0].status_code, 200);
        assert_eq!(snapshot.billing_event_total, 1);
        assert_eq!(snapshot.token_totals.total_tokens, 8);
        assert_eq!(snapshot.model_provider_totals[0].logical_model, "fast-chat");
    }
}
