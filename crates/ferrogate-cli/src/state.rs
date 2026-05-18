use std::{
    collections::{BTreeMap, HashMap},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::config::{
    config_snapshot_id, resolve_env_placeholders, AccessLogMode, ApiKey, Config, HeaderMutation,
    Model, PolicyRule as ConfigPolicyRule, Provider, RouteRule, StorageConfig, Upstream,
};
use crate::routing::parse_upstream_endpoint;
use ferrogate_billing::{
    BillingEvent, BillingEventSink, BillingUsageSource, InMemoryBillingEventSink, ModelPrice,
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
    ProviderHttpRequest, ProviderUsage, ResolvedModelRoute, ResponsesPlan,
};
use ferrogate_storage::{
    AppendRepository, InMemoryAppendRepository, InMemoryRepository, Repository, StoredAuditEvent,
    StoredRequestLog, StoredUsageAggregate,
};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use serde::Serialize;
use tracing::warn;

pub(crate) const RELOAD_MODE_PROCESS_LOCAL: &str = "process-local";
pub(crate) const RELOAD_MODE_LISTENER_LEVEL_REQUIRED: &str = "listener-level-required";

#[derive(Debug, Clone)]
pub(crate) struct SharedAppState {
    inner: Arc<RwLock<AppState>>,
    reload_coordinator: Arc<Mutex<ferrogate_runtime::ReloadCoordinator>>,
    source_path: Option<Arc<PathBuf>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimeReloadResult {
    pub(crate) active_snapshot: String,
    pub(crate) candidate_snapshot: String,
    pub(crate) committed: bool,
    pub(crate) mode: &'static str,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimeReloadPlan {
    pub(crate) mode: &'static str,
    pub(crate) listener_reload_required: bool,
    pub(crate) reason: Option<String>,
}

impl SharedAppState {
    pub(crate) fn with_source_path(config: Config, source_path: Option<PathBuf>) -> Self {
        let snapshot = config_snapshot_id(&config);
        Self {
            inner: Arc::new(RwLock::new(AppState::new(config))),
            reload_coordinator: Arc::new(Mutex::new(ferrogate_runtime::ReloadCoordinator::new(
                snapshot,
            ))),
            source_path: source_path.map(Arc::new),
        }
    }

    pub(crate) fn current(&self) -> AppState {
        match self.inner.read() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub(crate) fn next_request_id(&self) -> String {
        self.current().next_request_id()
    }

    pub(crate) fn record_request_log(&self, log: StoredRequestLog) {
        self.current().record_request_log(log);
    }

    pub(crate) fn source_path(&self) -> Option<&PathBuf> {
        self.source_path.as_deref()
    }

    pub(crate) fn reload_from_source_path(&self) -> anyhow::Result<RuntimeReloadResult> {
        let path = self
            .source_path()
            .ok_or_else(|| anyhow::anyhow!("runtime was not started from a config file"))?;
        let candidate = Config::load(path)?;
        Ok(self.reload_process_local(candidate))
    }

    pub(crate) fn reload_plan_for_candidate(&self, candidate: &Config) -> RuntimeReloadPlan {
        let active = self.current();
        reload_plan_for_configs(&active.config, candidate)
    }

    pub(crate) fn reload_process_local(&self, candidate: Config) -> RuntimeReloadResult {
        let active = self.current();
        let candidate_snapshot = config_snapshot_id(&candidate);
        let mut coordinator = match self.reload_coordinator.lock() {
            Ok(coordinator) => coordinator,
            Err(poisoned) => poisoned.into_inner(),
        };
        let reload_candidate = coordinator.prepare(candidate_snapshot);

        if let Some(reason) = process_local_reload_rejection(&active.config, &candidate) {
            let outcome = coordinator.reject(reload_candidate, reason);
            return RuntimeReloadResult {
                active_snapshot: outcome.active.id,
                candidate_snapshot: outcome.candidate.id,
                committed: false,
                mode: RELOAD_MODE_LISTENER_LEVEL_REQUIRED,
                reason: outcome.reason,
            };
        }

        let next = active.with_reloaded_config(candidate);
        match self.inner.write() {
            Ok(mut state) => *state = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
        let outcome = coordinator.commit(reload_candidate);

        RuntimeReloadResult {
            active_snapshot: outcome.active.id,
            candidate_snapshot: outcome.candidate.id,
            committed: true,
            mode: RELOAD_MODE_PROCESS_LOCAL,
            reason: None,
        }
    }

    pub(crate) fn upsert_api_key(&self, key: ApiKey) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let mut candidate = (*active.config).clone();
        if let Some(existing) = candidate
            .api_keys
            .iter_mut()
            .find(|existing| existing.id == key.id)
        {
            *existing = key;
        } else {
            candidate.api_keys.push(key);
        }
        candidate.validate()?;
        Ok(self.reload_process_local(candidate))
    }

    pub(crate) fn delete_api_key(&self, id: &str) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        let mut candidate = (*active.config).clone();
        let before = candidate.api_keys.len();
        candidate.api_keys.retain(|key| key.id != id);
        if candidate.api_keys.len() == before {
            return Ok(None);
        }
        candidate.validate()?;
        Ok(Some(self.reload_process_local(candidate)))
    }

    pub(crate) fn upsert_policy(
        &self,
        policy: ConfigPolicyRule,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let mut candidate = (*active.config).clone();
        if let Some(existing) = candidate
            .policies
            .iter_mut()
            .find(|existing| existing.name == policy.name)
        {
            *existing = policy;
        } else {
            candidate.policies.push(policy);
        }
        candidate.validate()?;
        Ok(self.reload_process_local(candidate))
    }

    pub(crate) fn delete_policy(&self, name: &str) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        let mut candidate = (*active.config).clone();
        let before = candidate.policies.len();
        candidate.policies.retain(|policy| policy.name != name);
        if candidate.policies.len() == before {
            return Ok(None);
        }
        candidate.validate()?;
        Ok(Some(self.reload_process_local(candidate)))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) providers: Arc<HashMap<String, Provider>>,
    pub(crate) upstreams: Arc<HashMap<String, Upstream>>,
    runtime_routes: Arc<Vec<RuntimeRoute>>,
    runtime_upstreams: Arc<HashMap<String, RuntimeUpstream>>,
    model_visibility: Arc<HashMap<String, ModelVisibility>>,
    model_prices: Arc<HashMap<String, ModelPrice>>,
    model_registry: Arc<ModelRegistry>,
    provider_adapters: Arc<ProviderAdapterRegistry>,
    provider_circuit_config: Option<ProviderCircuitConfig>,
    provider_circuits: Arc<HashMap<String, ProviderCircuitBreaker>>,
    api_key_request_windows: Arc<HashMap<String, ApiKeyRequestWindow>>,
    api_key_token_reservations: Arc<Mutex<HashMap<String, u64>>>,
    billing_events: Arc<InMemoryBillingEventSink>,
    request_logs: Arc<Mutex<InMemoryAppendRepository<StoredRequestLog>>>,
    audit_events: Arc<Mutex<InMemoryAppendRepository<StoredAuditEvent>>>,
    usage_aggregates: Arc<Mutex<InMemoryRepository<StoredUsageAggregate>>>,
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    access_log_error_limiter: Arc<AccessLogRateLimiter>,
    policy_engine: Arc<BasicPolicyEngine>,
    upstream_counters: Arc<HashMap<String, AtomicU64>>,
    model_route_counter: Arc<AtomicU64>,
    request_ids: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeRoute {
    pub(crate) config: RouteRule,
    match_headers: Vec<RuntimeHeaderMatcher>,
    pub(crate) request_headers: Vec<RuntimeHeaderMutation>,
    pub(crate) response_headers: Vec<RuntimeHeaderMutation>,
}

#[derive(Debug, Clone)]
struct RuntimeHeaderMatcher {
    name: HeaderName,
    value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeHeaderMutation {
    pub(crate) name: HeaderName,
    pub(crate) value: HeaderValue,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeUpstream {
    endpoints: Vec<RuntimeUpstreamEndpoint>,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeUpstreamEndpoint {
    pub(crate) endpoint: crate::routing::UpstreamEndpoint,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminAuditEventDraft {
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) outcome: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminPagination {
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminPage<T> {
    pub(crate) data: Vec<T>,
    pub(crate) total: usize,
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

#[derive(Debug, Default)]
struct GatewayMetricsAccumulator {
    request_log_total: u64,
    request_error_total: u64,
    request_status_totals: BTreeMap<u16, u64>,
    billing_event_total: u64,
    token_totals: TokenMetricTotals,
    cost_totals: BTreeMap<String, f64>,
    model_provider_totals: BTreeMap<(String, String), ModelProviderMetricTotal>,
}

#[derive(Debug)]
struct AccessLogRateLimiter {
    window_second: AtomicU64,
    count: AtomicU64,
}

impl Default for AccessLogRateLimiter {
    fn default() -> Self {
        Self {
            window_second: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl AccessLogRateLimiter {
    fn allow(&self, now_second: u64, limit: u64) -> bool {
        let current = self.window_second.load(Ordering::Relaxed);
        if current != now_second
            && self
                .window_second
                .compare_exchange(current, now_second, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.count.store(0, Ordering::Relaxed);
        }

        self.count.fetch_add(1, Ordering::Relaxed) < limit
    }
}

impl AdminPagination {
    fn from_query(query: Option<&str>, default_limit: usize, max_limit: usize) -> Self {
        let mut offset = 0;
        let mut limit = default_limit;

        if let Some(query) = query {
            for (name, value) in query.split('&').filter_map(|part| part.split_once('=')) {
                match name {
                    "offset" => {
                        offset = value.parse().unwrap_or(offset);
                    }
                    "limit" => {
                        limit = value.parse().unwrap_or(limit);
                    }
                    _ => {}
                }
            }
        }

        if limit == 0 {
            limit = default_limit;
        }
        limit = limit.min(max_limit);

        Self { offset, limit }
    }
}

impl GatewayMetricsAccumulator {
    fn record_request_log(&mut self, log: &StoredRequestLog) {
        self.request_log_total = self.request_log_total.saturating_add(1);
        if log.status_code >= 400 || log.error_code.is_some() {
            self.request_error_total = self.request_error_total.saturating_add(1);
        }
        *self
            .request_status_totals
            .entry(log.status_code)
            .or_default() += 1;
    }

    fn record_billing_event(&mut self, event: &BillingEvent) {
        self.billing_event_total = self.billing_event_total.saturating_add(1);
        self.token_totals.prompt_tokens += event.usage.prompt_tokens;
        self.token_totals.completion_tokens += event.usage.completion_tokens;
        self.token_totals.total_tokens += event.usage.total_tokens;

        if let Some(cost) = &event.cost {
            *self.cost_totals.entry(cost.currency.clone()).or_default() += cost.total_cost;
        }

        let key = (event.logical_model.clone(), event.provider.clone());
        let total =
            self.model_provider_totals
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

    fn snapshot(&self, service_name: String) -> GatewayMetricsSnapshot {
        GatewayMetricsSnapshot {
            service_name,
            request_log_total: self.request_log_total,
            request_error_total: self.request_error_total,
            request_status_totals: self
                .request_status_totals
                .iter()
                .map(|(status_code, count)| RequestStatusMetric {
                    status_code: *status_code,
                    count: *count,
                })
                .collect(),
            billing_event_total: self.billing_event_total,
            token_totals: self.token_totals.clone(),
            cost_estimates: self
                .cost_totals
                .iter()
                .map(|(currency, amount)| CostMetricTotal {
                    currency: currency.clone(),
                    amount: *amount,
                })
                .collect(),
            model_provider_totals: self.model_provider_totals.values().cloned().collect(),
        }
    }
}

impl RuntimeRoute {
    fn from_config(route: &RouteRule) -> Self {
        Self {
            config: route.clone(),
            match_headers: route
                .match_headers
                .iter()
                .map(|header| RuntimeHeaderMatcher {
                    name: HeaderName::from_bytes(header.name.as_bytes())
                        .expect("config validation must reject invalid header names"),
                    value: header.value.clone(),
                })
                .collect(),
            request_headers: compile_header_mutations(&route.request_headers),
            response_headers: compile_header_mutations(&route.response_headers),
        }
    }

    fn matches_request(&self, host: Option<&str>, path: &str, headers: &HeaderMap) -> bool {
        if !self.config.hosts.is_empty() {
            let Some(host) = host else {
                return false;
            };
            if !self
                .config
                .hosts
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(host))
            {
                return false;
            }
        }

        let path_matches = self.config.path_prefixes.is_empty()
            || self.config.path_prefixes.iter().any(|prefix| {
                path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
            });
        if !path_matches {
            return false;
        }

        self.match_headers.iter().all(|matcher| {
            headers
                .get(&matcher.name)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == matcher.value)
        })
    }

    pub(crate) fn rewrite_path(&self, original_path: &str) -> String {
        self.config.rewrite_path(original_path)
    }
}

impl RuntimeUpstream {
    fn from_config(upstream: &Upstream) -> Self {
        Self {
            endpoints: upstream
                .endpoint_urls()
                .into_iter()
                .map(|raw_url| RuntimeUpstreamEndpoint {
                    endpoint: parse_upstream_endpoint(raw_url)
                        .expect("config validation must reject invalid upstream endpoints"),
                })
                .collect(),
        }
    }
}

fn compile_header_mutations(headers: &[HeaderMutation]) -> Vec<RuntimeHeaderMutation> {
    headers
        .iter()
        .filter_map(|header| {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .expect("config validation must reject invalid header names");
            let Ok(value) = resolve_env_placeholders(&header.value) else {
                warn!(header = %header.name, "skipping precompiled header with unresolved environment placeholder");
                return None;
            };
            let value = HeaderValue::from_str(&value)
                .expect("config validation must reject invalid literal header values");
            Some(RuntimeHeaderMutation { name, value })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderHealthCheck {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) enabled: bool,
    pub(crate) status: &'static str,
    pub(crate) reachable: bool,
    pub(crate) circuit_open: bool,
    pub(crate) consecutive_failures: u32,
    pub(crate) checked_at_unix: Option<u64>,
    pub(crate) error: Option<String>,
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
        let runtime_routes = config
            .routes
            .iter()
            .map(RuntimeRoute::from_config)
            .collect();
        let runtime_upstreams = config
            .upstreams
            .iter()
            .map(|upstream| {
                (
                    upstream.name.clone(),
                    RuntimeUpstream::from_config(upstream),
                )
            })
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
        let provider_circuit_config = provider_circuit_config(&config);
        let provider_circuits = if provider_circuit_config.is_some() {
            config
                .providers
                .iter()
                .map(|provider| (provider.name.clone(), ProviderCircuitBreaker::new()))
                .collect()
        } else {
            HashMap::new()
        };
        let api_key_request_windows = config
            .api_keys
            .iter()
            .filter(|key| key.request_limit_per_minute.is_some())
            .map(|key| (key.id.clone(), ApiKeyRequestWindow::default()))
            .collect();
        let storage = config.storage.clone();

        Self {
            config: Arc::new(config),
            providers: Arc::new(providers),
            upstreams: Arc::new(upstreams),
            runtime_routes: Arc::new(runtime_routes),
            runtime_upstreams: Arc::new(runtime_upstreams),
            model_visibility: Arc::new(model_visibility),
            model_prices: Arc::new(model_prices),
            model_registry: Arc::new(model_registry),
            provider_adapters: Arc::new(ProviderAdapterRegistry::default()),
            provider_circuit_config,
            provider_circuits: Arc::new(provider_circuits),
            api_key_request_windows: Arc::new(api_key_request_windows),
            api_key_token_reservations: Arc::new(Mutex::new(HashMap::new())),
            billing_events: Arc::new(InMemoryBillingEventSink::with_retention_limit(
                storage.billing_event_retention_records,
            )),
            request_logs: Arc::new(Mutex::new(InMemoryAppendRepository::with_retention_limit(
                storage.request_log_retention_records,
            ))),
            audit_events: Arc::new(Mutex::new(InMemoryAppendRepository::with_retention_limit(
                storage.audit_event_retention_records,
            ))),
            usage_aggregates: Arc::new(Mutex::new(InMemoryRepository::new())),
            metrics: Arc::new(Mutex::new(GatewayMetricsAccumulator::default())),
            access_log_error_limiter: Arc::new(AccessLogRateLimiter::default()),
            policy_engine: Arc::new(policy_engine),
            upstream_counters: Arc::new(upstream_counters),
            model_route_counter: Arc::new(AtomicU64::new(0)),
            request_ids: Arc::new(AtomicU64::new(1)),
        }
    }

    fn with_reloaded_config(&self, config: Config) -> Self {
        let mut next = AppState::new(config);
        next.api_key_token_reservations = Arc::clone(&self.api_key_token_reservations);
        next.billing_events = Arc::clone(&self.billing_events);
        next.request_logs = Arc::clone(&self.request_logs);
        next.audit_events = Arc::clone(&self.audit_events);
        next.usage_aggregates = Arc::clone(&self.usage_aggregates);
        next.metrics = Arc::clone(&self.metrics);
        next.request_ids = Arc::clone(&self.request_ids);
        self.apply_storage_config(&next.config.storage);
        next
    }

    fn apply_storage_config(&self, storage: &StorageConfig) {
        let _ = self
            .billing_events
            .set_retention_limit(storage.billing_event_retention_records);
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.set_retention_limit(storage.request_log_retention_records);
        }
        if let Ok(mut events) = self.audit_events.lock() {
            events.set_retention_limit(storage.audit_event_retention_records);
        }
    }

    pub(crate) fn next_request_id(&self) -> String {
        let next = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fg-{next:016x}")
    }

    pub(crate) fn auth_required(&self) -> bool {
        !self.config.api_keys.is_empty()
    }

    pub(crate) fn should_log_access(
        &self,
        request_id: &str,
        response_code: u16,
        request_failed: bool,
    ) -> bool {
        self.should_log_access_at(
            request_id,
            response_code,
            request_failed,
            now_unix_seconds().unwrap_or_default(),
        )
    }

    fn should_log_access_at(
        &self,
        request_id: &str,
        response_code: u16,
        request_failed: bool,
        now_second: u64,
    ) -> bool {
        let is_error = request_failed || response_code == 0 || response_code >= 400;
        match self.config.telemetry.access_log {
            AccessLogMode::Off => false,
            AccessLogMode::Error => self.should_log_error_access(is_error, now_second),
            AccessLogMode::Sampled if is_error => self.should_log_error_access(true, now_second),
            AccessLogMode::Sampled => {
                sampled_request_id(request_id, self.config.telemetry.access_log_sample_rate)
            }
            AccessLogMode::All => !is_error || self.should_log_error_access(is_error, now_second),
        }
    }

    fn should_log_error_access(&self, is_error: bool, now_second: u64) -> bool {
        is_error
            && self.access_log_error_limiter.allow(
                now_second,
                self.config.telemetry.access_log_error_rate_limit_per_sec,
            )
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

    pub(crate) fn prepare_responses(
        &self,
        provider: &Provider,
        model_route: &ModelRoute,
        logical_model: String,
        stream: bool,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.provider_adapters.prepare_responses(
            ProviderConfig {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                api_key: provider.api_key_value(),
            },
            ResponsesPlan {
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

    pub(crate) fn provider_dispatch_timeout(&self) -> Duration {
        Duration::from_secs(
            self.config
                .reliability
                .provider_dispatch_timeout_secs
                .unwrap_or(10),
        )
    }

    pub(crate) fn provider_dispatch_max_retries(&self) -> u32 {
        self.config
            .reliability
            .provider_dispatch_max_retries
            .unwrap_or_default()
    }

    pub(crate) fn provider_response_body_max_bytes(&self) -> usize {
        self.config
            .reliability
            .provider_response_body_max_bytes
            .unwrap_or(16 * 1024 * 1024)
    }

    pub(crate) fn provider_health_checks(&self) -> Vec<ProviderHealthCheck> {
        self.config
            .providers
            .iter()
            .map(|provider| self.provider_health_check(provider))
            .collect()
    }

    pub(crate) fn provider_circuit_allows(&self, provider_name: &str) -> bool {
        let Some(config) = self.provider_circuit_config else {
            return true;
        };
        self.provider_circuits
            .get(provider_name)
            .is_none_or(|circuit| circuit.allows_request(config.cooldown, SystemTime::now()))
    }

    pub(crate) fn record_provider_success(&self, provider_name: &str) {
        if self.provider_circuit_config.is_none() {
            return;
        }
        if let Some(circuit) = self.provider_circuits.get(provider_name) {
            circuit.record_success();
        }
    }

    pub(crate) fn record_provider_failure(&self, provider_name: &str) {
        let Some(config) = self.provider_circuit_config else {
            return;
        };
        if let Some(circuit) = self.provider_circuits.get(provider_name) {
            circuit.record_failure(config.failure_threshold, SystemTime::now());
        }
    }

    fn provider_circuit_snapshot(&self, provider_name: &str) -> ProviderCircuitSnapshot {
        self.provider_circuits
            .get(provider_name)
            .map(|circuit| circuit.snapshot())
            .unwrap_or_default()
    }

    fn provider_health_check(&self, provider: &Provider) -> ProviderHealthCheck {
        let checked_at_unix = now_unix_seconds();
        let circuit = self.provider_circuit_snapshot(&provider.name);
        if !provider.enabled {
            return ProviderHealthCheck {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                enabled: false,
                status: "disabled",
                reachable: false,
                circuit_open: circuit.open,
                consecutive_failures: circuit.consecutive_failures,
                checked_at_unix,
                error: None,
            };
        }

        let probe = probe_provider_endpoint(&provider.base_url, Duration::from_millis(500));
        let reachable = probe.is_ok();
        let status = if circuit.open {
            "circuit_open"
        } else if reachable {
            "healthy"
        } else {
            "unreachable"
        };

        ProviderHealthCheck {
            name: provider.name.clone(),
            kind: provider.kind.clone(),
            base_url: provider.base_url.clone(),
            enabled: true,
            status,
            reachable,
            circuit_open: circuit.open,
            consecutive_failures: circuit.consecutive_failures,
            checked_at_unix,
            error: probe.err(),
        }
    }

    pub(crate) fn try_consume_api_key_request(&self, api_key_id: &str, limit: u64) -> bool {
        self.api_key_request_windows
            .get(api_key_id)
            .is_none_or(|window| window.try_consume(limit, now_unix_seconds().unwrap_or_default()))
    }

    pub(crate) fn api_key_total_tokens_used(&self, api_key_id: &str) -> u64 {
        self.usage_aggregates
            .lock()
            .map(|aggregates| {
                aggregates
                    .list()
                    .into_iter()
                    .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
                    .map(|aggregate| aggregate.usage.total_tokens)
                    .sum()
            })
            .unwrap_or_default()
    }

    pub(crate) fn api_key_tokens_committed_or_reserved(&self, api_key_id: &str) -> u64 {
        self.api_key_total_tokens_used(api_key_id)
            + self
                .api_key_token_reservations
                .lock()
                .ok()
                .and_then(|reservations| reservations.get(api_key_id).copied())
                .unwrap_or_default()
    }

    pub(crate) fn try_reserve_api_key_tokens(
        &self,
        api_key_id: &str,
        budget: u64,
        estimated_tokens: u64,
    ) -> Option<ApiKeyTokenReservation> {
        let committed = self.api_key_total_tokens_used(api_key_id);
        let Ok(mut reservations) = self.api_key_token_reservations.lock() else {
            return None;
        };
        let reserved = reservations.get(api_key_id).copied().unwrap_or_default();
        if committed
            .saturating_add(reserved)
            .saturating_add(estimated_tokens)
            > budget
        {
            return None;
        }

        *reservations.entry(api_key_id.to_string()).or_default() += estimated_tokens;
        Some(ApiKeyTokenReservation {
            api_key_id: api_key_id.to_string(),
            tokens: estimated_tokens,
            reservations: Arc::clone(&self.api_key_token_reservations),
            released: false,
        })
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
        self.record_billing_token_usage(BillingTokenUsageDraft {
            request,
            logical_model,
            provider,
            provider_model,
            usage: &usage,
            usage_source: BillingUsageSource::ProviderUsage,
            status_code,
        })
    }

    pub(crate) fn record_estimated_billing_event(
        &self,
        request: &RequestContext,
        logical_model: &str,
        provider: &str,
        provider_model: &str,
        usage: &BillingTokenUsage,
        status_code: u16,
    ) -> Result<(), ferrogate_billing::BillingError> {
        self.record_billing_token_usage(BillingTokenUsageDraft {
            request,
            logical_model,
            provider,
            provider_model,
            usage,
            usage_source: BillingUsageSource::GatewayEstimate,
            status_code,
        })
    }

    fn record_billing_token_usage(
        &self,
        draft: BillingTokenUsageDraft<'_>,
    ) -> Result<(), ferrogate_billing::BillingError> {
        let usage = draft.usage.clone().estimate_missing_total();
        let cost = self
            .model_prices
            .get(draft.logical_model)
            .map(|price| price.estimate(&usage));
        let event = BillingEvent {
            request_id: draft.request.request_id.clone(),
            trace_id: draft.request.trace_id.clone(),
            tenant: draft.request.tenant.clone(),
            logical_model: draft.logical_model.into(),
            provider: draft.provider.into(),
            provider_model: draft.provider_model.into(),
            usage: usage.clone(),
            usage_source: draft.usage_source,
            cost,
            status_code: draft.status_code,
            occurred_at_unix: None,
        };
        self.billing_events.record(event.clone())?;
        self.record_billing_metrics(&event);
        self.record_usage_aggregate(
            &draft.request.tenant,
            draft.logical_model,
            draft.provider,
            &usage,
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn billing_events(&self) -> Vec<BillingEvent> {
        self.billing_events.list()
    }

    pub(crate) fn billing_events_page(
        &self,
        pagination: AdminPagination,
    ) -> AdminPage<BillingEvent> {
        AdminPage {
            data: self
                .billing_events
                .list_paginated(pagination.offset, pagination.limit),
            total: self.billing_events.len(),
            offset: pagination.offset,
            limit: pagination.limit,
        }
    }

    pub(crate) fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        self.usage_aggregates
            .lock()
            .map(|aggregates| aggregates.list())
            .unwrap_or_default()
    }

    fn record_usage_aggregate(
        &self,
        tenant: &ferrogate_core::TenantContext,
        logical_model: &str,
        provider: &str,
        usage: &BillingTokenUsage,
    ) {
        let id = usage_aggregate_id(tenant, logical_model, provider);
        let Ok(mut aggregates) = self.usage_aggregates.lock() else {
            return;
        };

        let mut aggregate = aggregates.get(&id).unwrap_or_else(|| StoredUsageAggregate {
            id: id.clone(),
            organization_id: tenant.organization_id.clone(),
            project_id: tenant.project_id.clone(),
            api_key_id: tenant.api_key_id.clone(),
            logical_model: logical_model.to_string(),
            provider: provider.to_string(),
            usage: BillingTokenUsage::default(),
        });
        aggregate.usage.prompt_tokens += usage.prompt_tokens;
        aggregate.usage.completion_tokens += usage.completion_tokens;
        aggregate.usage.total_tokens += usage.total_tokens;
        aggregates.insert(id, aggregate);
    }

    pub(crate) fn record_request_log(&self, log: StoredRequestLog) {
        self.record_request_metrics(&log);
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    fn record_request_metrics(&self, log: &StoredRequestLog) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_request_log(log);
        }
    }

    fn record_billing_metrics(&self, event: &BillingEvent) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_billing_event(event);
        }
    }

    pub(crate) fn record_admin_audit_event(&self, event: AdminAuditEventDraft) {
        if let Ok(mut events) = self.audit_events.lock() {
            let id = format!("audit-{}", events.list().len() + 1);
            events.append(StoredAuditEvent {
                id,
                request_id: event.request_id,
                trace_id: event.trace_id,
                actor_api_key_id: event.actor_api_key_id,
                action: event.action,
                target: event.target,
                outcome: event.outcome,
                message: event.message,
                occurred_at_unix: now_unix_seconds(),
            });
        }
    }

    pub(crate) fn prometheus_metrics_snapshot(&self) -> GatewayMetricsSnapshot {
        self.metrics
            .lock()
            .map(|metrics| metrics.snapshot(self.state_service_name()))
            .unwrap_or_else(|_| GatewayMetricsSnapshot {
                service_name: self.state_service_name(),
                request_log_total: 0,
                request_error_total: 0,
                request_status_totals: Vec::new(),
                billing_event_total: 0,
                token_totals: TokenMetricTotals::default(),
                cost_estimates: Vec::new(),
                model_provider_totals: Vec::new(),
            })
    }

    fn state_service_name(&self) -> String {
        self.config.telemetry.service_name.clone()
    }

    pub(crate) fn otlp_endpoint(&self) -> Option<String> {
        self.config
            .telemetry
            .otlp_endpoint
            .as_ref()
            .map(|endpoint| endpoint.trim().to_string())
            .filter(|endpoint| !endpoint.is_empty())
    }

    pub(crate) fn request_logs(&self) -> Vec<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| logs.list())
            .unwrap_or_default()
    }

    pub(crate) fn request_logs_page(
        &self,
        pagination: AdminPagination,
    ) -> AdminPage<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| AdminPage {
                data: logs.list_paginated(pagination.offset, pagination.limit),
                total: logs.len(),
                offset: pagination.offset,
                limit: pagination.limit,
            })
            .unwrap_or_else(|_| AdminPage {
                data: Vec::new(),
                total: 0,
                offset: pagination.offset,
                limit: pagination.limit,
            })
    }

    pub(crate) fn audit_events_page(
        &self,
        pagination: AdminPagination,
    ) -> AdminPage<StoredAuditEvent> {
        self.audit_events
            .lock()
            .map(|events| AdminPage {
                data: events.list_paginated(pagination.offset, pagination.limit),
                total: events.len(),
                offset: pagination.offset,
                limit: pagination.limit,
            })
            .unwrap_or_else(|_| AdminPage {
                data: Vec::new(),
                total: 0,
                offset: pagination.offset,
                limit: pagination.limit,
            })
    }

    pub(crate) fn admin_pagination(&self, query: Option<&str>) -> AdminPagination {
        AdminPagination::from_query(
            query,
            self.config.storage.admin_list_default_limit,
            self.config.storage.admin_list_max_limit,
        )
    }

    pub(crate) fn match_runtime_route(
        &self,
        host: Option<&str>,
        path: &str,
        headers: &HeaderMap,
    ) -> Option<RuntimeRoute> {
        self.runtime_routes
            .iter()
            .filter(|route| route.config.enabled)
            .find(|route| route.matches_request(host, path, headers))
            .cloned()
    }

    pub(crate) fn select_runtime_upstream_endpoint(
        &self,
        upstream_name: &str,
    ) -> Option<RuntimeUpstreamEndpoint> {
        let upstream = self.runtime_upstreams.get(upstream_name)?;
        if upstream.endpoints.is_empty() {
            return None;
        }
        let next = self
            .upstream_counters
            .get(upstream_name)
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(0);
        upstream
            .endpoints
            .get(next as usize % upstream.endpoints.len())
            .cloned()
    }

    #[cfg(test)]
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

#[derive(Debug)]
struct BillingTokenUsageDraft<'a> {
    request: &'a RequestContext,
    logical_model: &'a str,
    provider: &'a str,
    provider_model: &'a str,
    usage: &'a BillingTokenUsage,
    usage_source: BillingUsageSource,
    status_code: u16,
}

#[derive(Debug)]
pub(crate) struct ApiKeyTokenReservation {
    api_key_id: String,
    tokens: u64,
    reservations: Arc<Mutex<HashMap<String, u64>>>,
    released: bool,
}

impl ApiKeyTokenReservation {
    pub(crate) fn tokens(&self) -> u64 {
        self.tokens
    }

    pub(crate) fn settle(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut reservations) = self.reservations.lock() {
            if let Some(reserved) = reservations.get_mut(&self.api_key_id) {
                *reserved = reserved.saturating_sub(self.tokens);
                if *reserved == 0 {
                    reservations.remove(&self.api_key_id);
                }
            }
        }
        self.released = true;
    }
}

impl Drop for ApiKeyTokenReservation {
    fn drop(&mut self) {
        self.release_inner();
    }
}

fn process_local_reload_rejection(active: &Config, candidate: &Config) -> Option<String> {
    ListenerRuntimeConfig::from(active)
        .process_local_reload_rejection(&ListenerRuntimeConfig::from(candidate))
}

fn reload_plan_for_configs(active: &Config, candidate: &Config) -> RuntimeReloadPlan {
    match process_local_reload_rejection(active, candidate) {
        Some(reason) => RuntimeReloadPlan {
            mode: RELOAD_MODE_LISTENER_LEVEL_REQUIRED,
            listener_reload_required: true,
            reason: Some(reason),
        },
        None => RuntimeReloadPlan {
            mode: RELOAD_MODE_PROCESS_LOCAL,
            listener_reload_required: false,
            reason: None,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenerRuntimeConfig {
    listen: String,
    tls_enabled: bool,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    tls_http2: bool,
    tls_acme: crate::config::TlsAcmeConfig,
}

impl ListenerRuntimeConfig {
    fn process_local_reload_rejection(&self, candidate: &Self) -> Option<String> {
        if self.listen != candidate.listen {
            return Some(format!(
                "listen address changes require listener-level reload: active={} candidate={}",
                self.listen, candidate.listen
            ));
        }

        if self.tls_enabled != candidate.tls_enabled
            || self.tls_cert_path != candidate.tls_cert_path
            || self.tls_key_path != candidate.tls_key_path
            || self.tls_http2 != candidate.tls_http2
            || self.tls_acme != candidate.tls_acme
        {
            return Some("TLS listener changes require listener-level reload".to_string());
        }

        None
    }
}

impl From<&Config> for ListenerRuntimeConfig {
    fn from(config: &Config) -> Self {
        Self {
            listen: config.listen.clone(),
            tls_enabled: config.tls.is_enabled(),
            tls_cert_path: config.tls.cert_path.clone(),
            tls_key_path: config.tls.key_path.clone(),
            tls_http2: config.tls.http2,
            tls_acme: config.tls.acme.clone(),
        }
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

#[derive(Debug, Clone, Copy)]
struct ProviderCircuitConfig {
    failure_threshold: u32,
    cooldown: Duration,
}

#[derive(Debug)]
struct ProviderCircuitBreaker {
    state: Mutex<ProviderCircuitState>,
}

impl ProviderCircuitBreaker {
    fn new() -> Self {
        Self {
            state: Mutex::new(ProviderCircuitState::default()),
        }
    }

    fn allows_request(&self, cooldown: Duration, now: SystemTime) -> bool {
        let Ok(state) = self.state.lock() else {
            return true;
        };
        state.opened_at.is_none_or(|opened_at| {
            now.duration_since(opened_at)
                .map(|elapsed| elapsed >= cooldown)
                .unwrap_or(false)
        })
    }

    fn record_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.consecutive_failures = 0;
            state.opened_at = None;
        }
    }

    fn record_failure(&self, failure_threshold: u32, now: SystemTime) {
        if let Ok(mut state) = self.state.lock() {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            if state.consecutive_failures >= failure_threshold {
                state.opened_at = Some(now);
            }
        }
    }

    fn snapshot(&self) -> ProviderCircuitSnapshot {
        self.state
            .lock()
            .map(|state| ProviderCircuitSnapshot {
                consecutive_failures: state.consecutive_failures,
                open: state.opened_at.is_some(),
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Default)]
struct ProviderCircuitState {
    consecutive_failures: u32,
    opened_at: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct ProviderCircuitSnapshot {
    consecutive_failures: u32,
    open: bool,
}

#[derive(Debug, Default)]
struct ApiKeyRequestWindow {
    state: Mutex<ApiKeyRequestWindowState>,
}

impl ApiKeyRequestWindow {
    fn try_consume(&self, limit: u64, now_unix_seconds: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return true;
        };

        if now_unix_seconds.saturating_sub(state.window_started_at) >= 60 {
            state.window_started_at = now_unix_seconds;
            state.count = 0;
        }

        if state.count >= limit {
            return false;
        }

        state.count += 1;
        true
    }
}

#[derive(Debug, Default)]
struct ApiKeyRequestWindowState {
    window_started_at: u64,
    count: u64,
}

fn provider_circuit_config(config: &Config) -> Option<ProviderCircuitConfig> {
    Some(ProviderCircuitConfig {
        failure_threshold: config
            .reliability
            .provider_circuit_breaker_failure_threshold?,
        cooldown: Duration::from_secs(config.reliability.provider_circuit_breaker_cooldown_secs?),
    })
}

fn probe_provider_endpoint(base_url: &str, timeout: Duration) -> Result<(), String> {
    let uri = base_url
        .parse::<Uri>()
        .map_err(|error| format!("invalid provider base_url: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "provider base_url is missing scheme".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "provider base_url is missing authority".to_string())?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => return Err(format!("unsupported provider base_url scheme {other}")),
    };
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(default_port);
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve provider endpoint: {error}"))?
        .next()
        .ok_or_else(|| "provider endpoint resolved no addresses".to_string())?;
    TcpStream::connect_timeout(&address, timeout)
        .map(|_| ())
        .map_err(|error| format!("failed to connect provider endpoint: {error}"))
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

fn usage_aggregate_id(
    tenant: &ferrogate_core::TenantContext,
    logical_model: &str,
    provider: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        tenant.organization_id.as_deref().unwrap_or("_"),
        tenant.project_id.as_deref().unwrap_or("_"),
        tenant.api_key_id.as_deref().unwrap_or("_"),
        logical_model,
        provider
    )
}

fn now_unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn sampled_request_id(request_id: &str, sample_rate: u64) -> bool {
    let Some(raw) = request_id.strip_prefix("fg-") else {
        return false;
    };
    u64::from_str_radix(raw, 16).is_ok_and(|value| value % sample_rate == 0)
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
    fn listener_runtime_config_allows_process_local_app_state_changes() {
        let active = Config::default();
        let candidate = Config {
            providers: vec![Provider {
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                enabled: true,
            }],
            ..Config::default()
        };

        assert_eq!(process_local_reload_rejection(&active, &candidate), None);
        assert_eq!(
            reload_plan_for_configs(&active, &candidate),
            RuntimeReloadPlan {
                mode: RELOAD_MODE_PROCESS_LOCAL,
                listener_reload_required: false,
                reason: None,
            }
        );
    }

    #[test]
    fn listener_runtime_config_rejects_listen_socket_changes() {
        let active = Config::default();
        let candidate = Config {
            listen: "127.0.0.1:18080".into(),
            ..Config::default()
        };

        let rejection = process_local_reload_rejection(&active, &candidate)
            .expect("listen changes must require listener-level reload");

        assert!(rejection.contains("listen address changes require listener-level reload"));
        assert!(rejection.contains("active=127.0.0.1:8080"));
        assert!(rejection.contains("candidate=127.0.0.1:18080"));

        let plan = reload_plan_for_configs(&active, &candidate);
        assert_eq!(plan.mode, RELOAD_MODE_LISTENER_LEVEL_REQUIRED);
        assert!(plan.listener_reload_required);
        assert_eq!(plan.reason.as_deref(), Some(rejection.as_str()));
    }

    #[test]
    fn listener_runtime_config_rejects_tls_listener_changes() {
        let active = Config::default();
        let candidate = Config {
            tls: crate::config::TlsConfig {
                enabled: true,
                cert_path: Some("cert.pem".into()),
                key_path: Some("key.pem".into()),
                http2: true,
                acme: crate::config::TlsAcmeConfig::default(),
            },
            ..Config::default()
        };

        let rejection = process_local_reload_rejection(&active, &candidate)
            .expect("TLS changes must require listener-level reload");

        assert_eq!(
            rejection,
            "TLS listener changes require listener-level reload"
        );

        let plan = reload_plan_for_configs(&active, &candidate);
        assert_eq!(plan.mode, RELOAD_MODE_LISTENER_LEVEL_REQUIRED);
        assert!(plan.listener_reload_required);
        assert_eq!(plan.reason.as_deref(), Some(rejection.as_str()));
    }

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
    fn selects_runtime_upstream_endpoints_round_robin() {
        let upstream = Upstream {
            name: "pool".to_string(),
            url: Some("http://127.0.0.1:10001/base".to_string()),
            urls: vec!["https://example.com:9443/api".to_string()],
            enabled: true,
        };
        let config = Config {
            upstreams: vec![upstream],
            ..Config::default()
        };
        let state = AppState::new(config);

        let first = state
            .select_runtime_upstream_endpoint("pool")
            .expect("first endpoint");
        assert_eq!(first.endpoint.scheme, "http");
        assert_eq!(first.endpoint.authority, "127.0.0.1:10001");
        assert_eq!(first.endpoint.base_path, "/base");

        let second = state
            .select_runtime_upstream_endpoint("pool")
            .expect("second endpoint");
        assert_eq!(second.endpoint.scheme, "https");
        assert_eq!(second.endpoint.authority, "example.com:9443");
        assert_eq!(second.endpoint.base_path, "/api");
    }

    #[test]
    fn matches_runtime_route_with_precompiled_headers() {
        let config = Config {
            routes: vec![RouteRule {
                name: "api".into(),
                upstream: "pool".into(),
                hosts: vec!["api.example.com".into()],
                path_prefixes: vec!["/v1".into()],
                match_headers: vec![crate::config::HeaderMatcher {
                    name: "x-tier".into(),
                    value: "gold".into(),
                }],
                strip_prefix: Some("/v1".into()),
                add_prefix: Some("/proxy".into()),
                request_headers: vec![HeaderMutation {
                    name: "x-added".into(),
                    value: "enabled".into(),
                }],
                response_headers: vec![HeaderMutation {
                    name: "x-response-added".into(),
                    value: "done".into(),
                }],
                enabled: true,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let mut headers = HeaderMap::new();
        headers.insert("x-tier", HeaderValue::from_static("gold"));

        let route = state
            .match_runtime_route(Some("api.example.com"), "/v1/chat", &headers)
            .expect("runtime route must match");

        assert_eq!(route.config.name, "api");
        assert_eq!(route.rewrite_path("/v1/chat"), "/proxy/chat");
        assert_eq!(route.request_headers[0].name.as_str(), "x-added");
        assert_eq!(
            route.request_headers[0].value,
            HeaderValue::from_static("enabled")
        );
        assert!(state
            .match_runtime_route(Some("api.example.com"), "/v1/chat", &HeaderMap::new())
            .is_none());
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
    fn provider_circuit_opens_after_configured_failures_and_resets_on_success() {
        let config = Config {
            reliability: crate::config::ReliabilityConfig {
                provider_circuit_breaker_failure_threshold: Some(2),
                provider_circuit_breaker_cooldown_secs: Some(60),
                ..crate::config::ReliabilityConfig::default()
            },
            providers: vec![Provider {
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                enabled: true,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert!(state.provider_circuit_allows("openai"));
        state.record_provider_failure("openai");
        assert!(state.provider_circuit_allows("openai"));
        state.record_provider_failure("openai");
        assert!(!state.provider_circuit_allows("openai"));
        state.record_provider_success("openai");
        assert!(state.provider_circuit_allows("openai"));
    }

    #[test]
    fn provider_circuit_is_disabled_without_reliability_config() {
        let state = AppState::new(Config {
            providers: vec![Provider {
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                enabled: true,
            }],
            ..Config::default()
        });

        state.record_provider_failure("openai");
        state.record_provider_failure("openai");

        assert!(state.provider_circuit_allows("openai"));
    }

    #[test]
    fn provider_health_reports_disabled_provider_without_probe() {
        let state = AppState::new(Config {
            providers: vec![Provider {
                name: "disabled".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key_env: None,
                enabled: false,
            }],
            ..Config::default()
        });

        let checks = state.provider_health_checks();

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "disabled");
        assert!(!checks[0].reachable);
    }

    #[test]
    fn api_key_request_window_rejects_after_configured_limit() {
        let state = AppState::new(Config {
            api_keys: vec![crate::config::ApiKey {
                id: "key_dev".into(),
                name: "Development key".into(),
                key_env: None,
                key: Some("client-secret".into()),
                key_hash: None,
                enabled: true,
                scopes: vec!["chat.completions".into()],
                allowed_models: vec![],
                denied_models: vec![],
                allowed_providers: vec![],
                denied_providers: vec![],
                organization_id: None,
                team_id: None,
                project_id: None,
                user_id: None,
                monthly_token_budget: None,
                request_limit_per_minute: Some(1),
                expires_at_unix: None,
                log_bodies: None,
            }],
            ..Config::default()
        });

        assert!(state.try_consume_api_key_request("key_dev", 1));
        assert!(!state.try_consume_api_key_request("key_dev", 1));
    }

    #[test]
    fn api_key_token_reservation_counts_against_budget_until_released() {
        let state = AppState::new(Config::default());

        let reservation = state
            .try_reserve_api_key_tokens("key_dev", 10, 7)
            .expect("first reservation should fit");

        assert_eq!(state.api_key_tokens_committed_or_reserved("key_dev"), 7);
        assert!(state.try_reserve_api_key_tokens("key_dev", 10, 4).is_none());

        drop(reservation);

        assert_eq!(state.api_key_tokens_committed_or_reserved("key_dev"), 0);
        assert!(state.try_reserve_api_key_tokens("key_dev", 10, 4).is_some());
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
        assert_eq!(events[0].usage_source, BillingUsageSource::ProviderUsage);
        assert_eq!(events[0].cost.as_ref().unwrap().currency, "USD");

        let aggregates = state.usage_aggregates();
        assert_eq!(aggregates.len(), 1);
        assert_eq!(aggregates[0].organization_id.as_deref(), Some("org"));
        assert_eq!(aggregates[0].project_id.as_deref(), Some("project"));
        assert_eq!(aggregates[0].api_key_id.as_deref(), Some("key_dev"));
        assert_eq!(aggregates[0].logical_model, "fast-chat");
        assert_eq!(aggregates[0].provider, "openai");
        assert_eq!(aggregates[0].usage.total_tokens, 8);
    }

    #[test]
    fn records_estimated_billing_event_when_provider_usage_is_missing() {
        let state = AppState::new(Config::default());
        let request = RequestContext {
            request_id: "fg-estimated".into(),
            trace_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                organization_id: None,
                team_id: None,
                project_id: None,
                user_id: None,
                api_key_id: Some("key_dev".into()),
            },
        };

        state
            .record_estimated_billing_event(
                &request,
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &BillingTokenUsage::new(2, 6, 8),
                200,
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].usage_source, BillingUsageSource::GatewayEstimate);
        assert_eq!(events[0].usage.total_tokens, 8);
        assert_eq!(state.api_key_total_tokens_used("key_dev"), 8);
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
    fn in_memory_runtime_storage_retains_configured_window_with_paginated_admin_views() {
        let state = AppState::new(Config {
            storage: crate::config::StorageConfig {
                request_log_retention_records: 2,
                audit_event_retention_records: 2,
                billing_event_retention_records: 2,
                admin_list_default_limit: 1,
                admin_list_max_limit: 2,
            },
            ..Config::default()
        });

        for (index, status_code) in [(1, 200), (2, 500), (3, 200)] {
            state.record_request_log(StoredRequestLog {
                request_id: format!("fg-{index}"),
                trace_id: None,
                tenant: ferrogate_core::TenantContext::default(),
                route: None,
                provider: None,
                logical_model: None,
                provider_model: None,
                status_code,
                error_code: None,
                prompt_recorded: false,
                response_recorded: false,
                prompt_body: None,
                response_body: None,
                started_at_unix: None,
                completed_at_unix: None,
            });
            state.record_admin_audit_event(AdminAuditEventDraft {
                request_id: format!("fg-{index}"),
                trace_id: None,
                actor_api_key_id: None,
                action: "config.validate".into(),
                target: "config".into(),
                outcome: "accepted".into(),
                message: format!("audit {index}"),
            });
            state
                .record_estimated_billing_event(
                    &RequestContext {
                        request_id: format!("fg-{index}"),
                        trace_id: None,
                        route: None,
                        upstream: None,
                        tenant: ferrogate_core::TenantContext::default(),
                    },
                    "fast-chat",
                    "openai",
                    "gpt-4o-mini",
                    &BillingTokenUsage::new(index, index, index * 2),
                    status_code,
                )
                .unwrap();
        }

        let first_page = state.request_logs_page(state.admin_pagination(None));
        assert_eq!(first_page.total, 2);
        assert_eq!(first_page.limit, 1);
        assert_eq!(first_page.data[0].request_id, "fg-2");

        let second_page = state.request_logs_page(state.admin_pagination(Some("offset=1&limit=9")));
        assert_eq!(second_page.limit, 2);
        assert_eq!(second_page.data.len(), 1);
        assert_eq!(second_page.data[0].request_id, "fg-3");

        let audit_page = state.audit_events_page(state.admin_pagination(None));
        assert_eq!(audit_page.total, 2);
        assert_eq!(audit_page.data[0].request_id, "fg-2");

        let billing_page = state.billing_events_page(state.admin_pagination(None));
        assert_eq!(billing_page.total, 2);
        assert_eq!(billing_page.data[0].request_id, "fg-2");

        let snapshot = state.prometheus_metrics_snapshot();
        assert_eq!(snapshot.request_log_total, 3);
        assert_eq!(snapshot.request_error_total, 1);
        assert_eq!(snapshot.billing_event_total, 3);
        assert_eq!(snapshot.token_totals.total_tokens, 12);
    }

    #[test]
    fn access_log_modes_filter_success_and_error_requests() {
        let mut config = Config::default();
        config.telemetry.access_log = AccessLogMode::Error;
        let state = AppState::new(config.clone());
        assert!(!state.should_log_access("fg-0000000000000001", 200, false));
        assert!(state.should_log_access("fg-0000000000000001", 500, false));
        assert!(state.should_log_access("fg-0000000000000001", 200, true));

        config.telemetry.access_log = AccessLogMode::Sampled;
        config.telemetry.access_log_sample_rate = 10;
        let state = AppState::new(config.clone());
        assert!(state.should_log_access("fg-000000000000000a", 200, false));
        assert!(!state.should_log_access("fg-000000000000000b", 200, false));
        assert!(state.should_log_access("fg-000000000000000b", 404, false));

        config.telemetry.access_log = AccessLogMode::All;
        let state = AppState::new(config.clone());
        assert!(state.should_log_access("fg-0000000000000001", 200, false));

        config.telemetry.access_log = AccessLogMode::Off;
        let state = AppState::new(config);
        assert!(!state.should_log_access("fg-0000000000000001", 500, true));
    }

    #[test]
    fn access_log_rate_limits_error_storms_per_second() {
        let mut config = Config::default();
        config.telemetry.access_log = AccessLogMode::Error;
        config.telemetry.access_log_error_rate_limit_per_sec = 2;
        let state = AppState::new(config.clone());

        assert!(state.should_log_access_at("fg-0000000000000001", 500, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000002", 502, false, 1_000));
        assert!(!state.should_log_access_at("fg-0000000000000003", 503, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000004", 500, false, 1_001));

        config.telemetry.access_log = AccessLogMode::All;
        let state = AppState::new(config);
        assert!(state.should_log_access_at("fg-0000000000000001", 200, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000002", 500, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000003", 500, false, 1_000));
        assert!(!state.should_log_access_at("fg-0000000000000004", 500, false, 1_000));
    }

    #[test]
    fn prometheus_metrics_snapshot_aggregates_request_logs_and_billing() {
        let config = Config {
            telemetry: crate::config::TelemetryConfig {
                service_name: "ferrogate-test".into(),
                log_bodies: false,
                otlp_endpoint: None,
                ..crate::config::TelemetryConfig::default()
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
        state
            .record_billing_event(
                &request,
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ProviderUsage {
                    prompt_tokens: Some(7),
                    completion_tokens: Some(11),
                    total_tokens: Some(18),
                },
                200,
            )
            .unwrap();

        let snapshot = state.prometheus_metrics_snapshot();

        assert_eq!(snapshot.service_name, "ferrogate-test");
        assert_eq!(snapshot.request_log_total, 1);
        assert_eq!(snapshot.request_status_totals[0].status_code, 200);
        assert_eq!(snapshot.billing_event_total, 2);
        assert_eq!(snapshot.token_totals.total_tokens, 26);
        assert_eq!(snapshot.model_provider_totals[0].logical_model, "fast-chat");

        let aggregates = state.usage_aggregates();
        assert_eq!(aggregates.len(), 1);
        assert_eq!(aggregates[0].usage.prompt_tokens, 10);
        assert_eq!(aggregates[0].usage.completion_tokens, 16);
        assert_eq!(aggregates[0].usage.total_tokens, 26);
    }
}
