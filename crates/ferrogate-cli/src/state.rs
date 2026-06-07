use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    env, fs,
    io::ErrorKind,
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::acme::{AcmeRenewalStatus, SharedAcmeRenewalState};
use crate::config::{
    config_snapshot_id, resolve_env_placeholders, AccessLogMode, ApiKey, Config, HeaderMutation,
    Model, PolicyRule as ConfigPolicyRule, Provider, RouteRule, StorageConfig, Upstream,
};
use crate::extensions::{
    ExtensionRegistry, ExtensionStatus, RegisteredTool, ToolExecutionError, ToolExecutionRequest,
    ToolExecutionResponse,
};
use crate::metering::MeteringExporter;
use crate::routing::parse_upstream_endpoint;
use ferrogate_billing::{
    BillingEvent, BillingEventSink, BillingUsageSource, InMemoryBillingEventSink, ModelPrice,
    TokenUsage as BillingTokenUsage,
};
use ferrogate_core::RequestContext;
use ferrogate_mcp::{
    McpExecutionError, McpManager, McpServerStatus, McpToolExecutionRequest, McpToolExecutionResult,
};
use ferrogate_observability::{
    GatewayMetricsSnapshot, ModelProviderMetricTotal, RequestStatusMetric, TokenMetricTotals,
};
use ferrogate_policy::{
    BasicPolicyEngine, PolicyDecision, PolicyEngine, PolicyRule, PolicySubject,
};
use ferrogate_providers::{
    AdapterError, ChatCompletionPlan, ModelRegistry, ModelRegistryEntry, ModelRegistryError,
    ModelRoute, ProviderAdapterRegistry, ProviderConfig, ProviderErrorResponse,
    ProviderHttpRequest, ProviderUsage, ResolvedModelRoute, ResponsesPlan, RoutingStrategy,
};
use ferrogate_storage::{
    AppendRepository, InMemoryAppendRepository, InMemoryRepository, Repository, StoredAuditEvent,
    StoredRequestLog, StoredUsageAggregate,
};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
#[cfg(test)]
use redis::Commands;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub(crate) const RELOAD_MODE_PROCESS_LOCAL: &str = "process-local";
pub(crate) const RELOAD_MODE_LISTENER_LEVEL_REQUIRED: &str = "listener-level-required";

#[derive(Debug)]
struct SharedFileControlPlane {
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SharedFileSnapshot {
    version: u32,
    revision: String,
    api_keys: Vec<ApiKey>,
    policies: Vec<ConfigPolicyRule>,
}

impl SharedFileControlPlane {
    fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        if !config.cluster.enabled || config.cluster.state_backend != "file" {
            return Ok(None);
        }
        let path = config
            .cluster
            .file_state_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("cluster.file_state_path is required"))?;
        Ok(Some(Self {
            path: PathBuf::from(path),
        }))
    }

    fn load(&self) -> anyhow::Result<Option<SharedFileSnapshot>> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).map_err(|error| {
                    anyhow::anyhow!("failed to read file cluster state: {error}")
                });
            }
        };
        let snapshot: SharedFileSnapshot = serde_json::from_str(&raw)
            .map_err(|error| anyhow::anyhow!("invalid file cluster state JSON: {error}"))?;
        if snapshot.version != 1 {
            anyhow::bail!(
                "unsupported file cluster state version {}; expected 1",
                snapshot.version
            );
        }
        Ok(Some(snapshot))
    }

    fn publish_from_config(&self, config: &Config) -> anyhow::Result<String> {
        let revision = shared_control_plane_revision(&config.api_keys, &config.policies);
        let snapshot = SharedFileSnapshot {
            version: 1,
            revision: revision.clone(),
            api_keys: config.api_keys.clone(),
            policies: config.policies.clone(),
        };
        let raw = serde_json::to_vec_pretty(&snapshot)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                anyhow::anyhow!("failed to publish file cluster state: {error}")
            })?;
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, raw)
            .map_err(|error| anyhow::anyhow!("failed to publish file cluster state: {error}"))?;
        fs::rename(&tmp, &self.path)
            .map_err(|error| anyhow::anyhow!("failed to publish file cluster state: {error}"))?;
        Ok(revision)
    }
}

fn shared_control_plane_revision(api_keys: &[ApiKey], policies: &[ConfigPolicyRule]) -> String {
    #[derive(Serialize)]
    struct RevisionInput<'a> {
        api_keys: &'a [ApiKey],
        policies: &'a [ConfigPolicyRule],
    }

    let bytes = serde_json::to_vec(&RevisionInput { api_keys, policies })
        .expect("shared control plane serialization should not fail");
    format!("{:016x}", fnv1a64(&bytes))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug, Clone)]
pub(crate) struct SharedAppState {
    inner: Arc<RwLock<AppState>>,
    reload_coordinator: Arc<Mutex<ferrogate_runtime::ReloadCoordinator>>,
    source_path: Option<Arc<PathBuf>>,
    shared_file_control_plane: Option<Arc<SharedFileControlPlane>>,
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
        let shared_file_control_plane = SharedFileControlPlane::from_config(&config)
            .inspect_err(|error| warn!("failed to initialize file cluster state: {error}"))
            .ok()
            .flatten()
            .map(Arc::new);
        Self {
            inner: Arc::new(RwLock::new(AppState::new(config))),
            reload_coordinator: Arc::new(Mutex::new(ferrogate_runtime::ReloadCoordinator::new(
                snapshot,
            ))),
            source_path: source_path.map(Arc::new),
            shared_file_control_plane,
        }
    }

    pub(crate) fn current(&self) -> AppState {
        match self.inner.read() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub(crate) fn with_acme_renewal_state(
        self,
        acme_renewal: Option<Arc<SharedAcmeRenewalState>>,
    ) -> Self {
        if let Some(acme_renewal) = acme_renewal {
            match self.inner.write() {
                Ok(mut state) => state.acme_renewal = Some(acme_renewal),
                Err(poisoned) => poisoned.into_inner().acme_renewal = Some(acme_renewal),
            }
        }
        self
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

    pub(crate) fn sync_shared_control_plane(&self) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let Some(control_plane) = &self.shared_file_control_plane else {
            return Ok(None);
        };
        let active = self.current();
        let snapshot = match control_plane.load() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let message = error.to_string();
                self.mark_cluster_sync_error(message);
                return Err(error);
            }
        };
        let Some(snapshot) = snapshot else {
            let revision = match control_plane.publish_from_config(&active.config) {
                Ok(revision) => revision,
                Err(error) => {
                    let message = error.to_string();
                    self.mark_cluster_sync_error(message);
                    return Err(error);
                }
            };
            self.update_cluster_sync_revision(revision);
            return Ok(None);
        };
        if snapshot.revision == active.cluster_sync.active_revision {
            self.update_cluster_sync_revision(snapshot.revision);
            return Ok(None);
        }
        let mut candidate = (*active.config).clone();
        candidate.api_keys = snapshot.api_keys;
        candidate.policies = snapshot.policies;
        if let Err(error) = candidate.validate() {
            let message = error.to_string();
            self.mark_cluster_sync_error(message);
            return Err(error);
        }
        Ok(Some(self.reload_process_local_with_revision(
            candidate,
            Some(snapshot.revision),
        )))
    }

    fn publish_shared_control_plane(&self, config: &Config) -> anyhow::Result<String> {
        if let Some(control_plane) = &self.shared_file_control_plane {
            let revision = control_plane.publish_from_config(config)?;
            self.update_cluster_sync_revision(revision.clone());
            return Ok(revision);
        }
        Ok(config_snapshot_id(config))
    }

    fn reload_process_local_with_revision(
        &self,
        candidate: Config,
        active_revision: Option<String>,
    ) -> RuntimeReloadResult {
        let result = self.reload_process_local(candidate);
        if result.committed {
            if let Some(active_revision) = active_revision {
                self.update_cluster_sync_revision(active_revision);
            }
        }
        result
    }

    fn update_cluster_sync_revision(&self, active_revision: String) {
        match self.inner.write() {
            Ok(mut state) => {
                state.cluster_sync = Arc::new(ClusterSyncStatus {
                    active_revision,
                    last_sync_at_unix: now_unix_seconds(),
                    last_sync_error: None,
                    stale: false,
                });
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.cluster_sync = Arc::new(ClusterSyncStatus {
                    active_revision,
                    last_sync_at_unix: now_unix_seconds(),
                    last_sync_error: None,
                    stale: false,
                });
            }
        }
    }

    pub(crate) fn mark_cluster_sync_error(&self, error: impl Into<String>) {
        let error = error.into();
        match self.inner.write() {
            Ok(mut state) => {
                let current = state.cluster_sync.as_ref();
                let has_revision = !current.active_revision.trim().is_empty();
                state.cluster_sync = Arc::new(ClusterSyncStatus {
                    active_revision: current.active_revision.clone(),
                    last_sync_at_unix: current.last_sync_at_unix,
                    last_sync_error: Some(error.clone()),
                    stale: has_revision,
                });
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                let current = state.cluster_sync.as_ref();
                let has_revision = !current.active_revision.trim().is_empty();
                state.cluster_sync = Arc::new(ClusterSyncStatus {
                    active_revision: current.active_revision.clone(),
                    last_sync_at_unix: current.last_sync_at_unix,
                    last_sync_error: Some(error),
                    stale: has_revision,
                });
            }
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
        let result = self.reload_process_local(candidate);
        if result.committed {
            let _ = self.publish_shared_control_plane(&self.current().config)?;
        }
        Ok(result)
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
        let result = self.reload_process_local(candidate);
        if result.committed {
            let _ = self.publish_shared_control_plane(&self.current().config)?;
        }
        Ok(Some(result))
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
        let result = self.reload_process_local(candidate);
        if result.committed {
            let _ = self.publish_shared_control_plane(&self.current().config)?;
        }
        Ok(result)
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
        let result = self.reload_process_local(candidate);
        if result.committed {
            let _ = self.publish_shared_control_plane(&self.current().config)?;
        }
        Ok(Some(result))
    }

    pub(crate) fn set_drain(&self, drain: bool) -> DrainStatus {
        let state = self.current();
        state.drain.store(drain, Ordering::Relaxed);
        state.drain_status()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    cluster_identity: Arc<ClusterIdentity>,
    cluster_sync: Arc<ClusterSyncStatus>,
    pub(crate) providers: Arc<HashMap<String, Provider>>,
    pub(crate) upstreams: Arc<HashMap<String, Upstream>>,
    runtime_routes: Arc<Vec<RuntimeRoute>>,
    runtime_upstreams: Arc<HashMap<String, RuntimeUpstream>>,
    extension_registry: Arc<ExtensionRegistry>,
    model_visibility: Arc<HashMap<String, ModelVisibility>>,
    model_registry: Arc<ModelRegistry>,
    provider_adapters: Arc<ProviderAdapterRegistry>,
    provider_circuit_config: Option<ProviderCircuitConfig>,
    provider_circuits: Arc<HashMap<String, ProviderCircuitBreaker>>,
    provider_routing_metrics: Arc<Mutex<ProviderRoutingMetrics>>,
    cluster_counters: Arc<ClusterCounterBackend>,
    metering_events: Arc<InMemoryBillingEventSink>,
    metering_exporter: Option<Arc<MeteringExporter>>,
    request_logs: Arc<Mutex<InMemoryAppendRepository<StoredRequestLog>>>,
    audit_events: Arc<Mutex<InMemoryAppendRepository<StoredAuditEvent>>>,
    usage_aggregates: Arc<Mutex<InMemoryRepository<StoredUsageAggregate>>>,
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    response_cache: Arc<Mutex<AiResponseCache>>,
    mcp_manager: Arc<McpManager>,
    access_log_error_limiter: Arc<AccessLogRateLimiter>,
    policy_engine: Arc<BasicPolicyEngine>,
    upstream_counters: Arc<HashMap<String, AtomicU64>>,
    model_route_counter: Arc<AtomicU64>,
    request_ids: Arc<AtomicU64>,
    drain: Arc<AtomicBool>,
    acme_renewal: Option<Arc<SharedAcmeRenewalState>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DrainStatus {
    pub(crate) draining: bool,
    pub(crate) accepting_new_requests: bool,
    pub(crate) drain_reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClusterIdentity {
    pub(crate) enabled: bool,
    pub(crate) cluster_id: String,
    pub(crate) node_id: String,
    pub(crate) node_region: Option<String>,
    pub(crate) node_zone: Option<String>,
    pub(crate) state_backend: String,
    pub(crate) counter_backend: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClusterSyncStatus {
    pub(crate) active_revision: String,
    pub(crate) last_sync_at_unix: Option<u64>,
    pub(crate) last_sync_error: Option<String>,
    pub(crate) stale: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClusterStatus {
    pub(crate) enabled: bool,
    pub(crate) cluster_id: String,
    pub(crate) node_id: String,
    pub(crate) node_region: Option<String>,
    pub(crate) node_zone: Option<String>,
    pub(crate) state_backend: String,
    pub(crate) counter_backend: String,
    pub(crate) active_revision: String,
    pub(crate) last_sync_at_unix: Option<u64>,
    pub(crate) last_sync_error: Option<String>,
    pub(crate) stale: bool,
    pub(crate) ready: bool,
    pub(crate) readiness_reason: &'static str,
    pub(crate) draining: bool,
    pub(crate) accepting_new_requests: bool,
}

impl ClusterIdentity {
    fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.cluster.enabled,
            cluster_id: config.cluster.cluster_id.clone(),
            node_id: resolve_cluster_node_id(&config.cluster.node_id),
            node_region: config.cluster.node_region.clone(),
            node_zone: config.cluster.node_zone.clone(),
            state_backend: config.cluster.state_backend.clone(),
            counter_backend: config.cluster.counter_backend.clone(),
        }
    }
}

impl ClusterStatus {
    fn new(identity: &ClusterIdentity, sync: &ClusterSyncStatus, drain: &DrainStatus) -> Self {
        let has_revision = !sync.active_revision.trim().is_empty();
        let state_ready = has_revision;
        let ready = state_ready && drain.accepting_new_requests;
        let readiness_reason = if drain.draining {
            "operator_drain"
        } else if sync.stale && has_revision {
            "stale_state"
        } else if state_ready {
            "state_loaded"
        } else if sync.last_sync_error.is_some() {
            "sync_error"
        } else {
            "revision_missing"
        };
        Self {
            enabled: identity.enabled,
            cluster_id: identity.cluster_id.clone(),
            node_id: identity.node_id.clone(),
            node_region: identity.node_region.clone(),
            node_zone: identity.node_zone.clone(),
            state_backend: identity.state_backend.clone(),
            counter_backend: identity.counter_backend.clone(),
            active_revision: sync.active_revision.clone(),
            last_sync_at_unix: sync.last_sync_at_unix,
            last_sync_error: sync.last_sync_error.clone(),
            stale: sync.stale,
            ready,
            readiness_reason,
            draining: drain.draining,
            accepting_new_requests: drain.accepting_new_requests,
        }
    }
}

fn initial_cluster_sync_status(config: &Config) -> ClusterSyncStatus {
    let uses_required_shared_state =
        config.cluster.enabled && config.cluster.state_backend == "file";
    ClusterSyncStatus {
        active_revision: if uses_required_shared_state {
            String::new()
        } else {
            config_snapshot_id(config)
        },
        last_sync_at_unix: if uses_required_shared_state {
            None
        } else {
            now_unix_seconds()
        },
        last_sync_error: None,
        stale: false,
    }
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

pub(crate) struct ToolInjectionContext<'a> {
    pub(crate) tenant: &'a ferrogate_core::TenantContext,
    pub(crate) api_key_id: Option<&'a str>,
    pub(crate) route: Option<&'a str>,
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
    cache_hits_total: u64,
    cache_misses_total: u64,
    billing_event_total: u64,
    token_totals: TokenMetricTotals,
    model_provider_totals: BTreeMap<(String, String), ModelProviderMetricTotal>,
    tool_call_total: u64,
    tool_latency_ms_total: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct AiResponseCacheKey {
    value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AiCachedResponse {
    pub(crate) status_code: u16,
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AiResponseCacheEntry {
    response: AiCachedResponse,
    expires_at_unix: u64,
}

#[derive(Debug, Default)]
struct AiResponseCache {
    entries: HashMap<String, AiResponseCacheEntry>,
    order: VecDeque<String>,
}

#[derive(Debug, Default)]
struct ProviderRoutingMetrics {
    providers: HashMap<String, ProviderRoutingMetric>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProviderRoutingMetric {
    successful_requests: u64,
    failed_requests: u64,
    total_latency_ms: u64,
}

impl ProviderRoutingMetrics {
    fn record_request_log(&mut self, log: &StoredRequestLog) {
        let Some(provider) = &log.provider else {
            return;
        };
        let metric = self.providers.entry(provider.clone()).or_default();
        if log.status_code >= 400 || log.error_code.is_some() {
            metric.failed_requests = metric.failed_requests.saturating_add(1);
        } else {
            metric.successful_requests = metric.successful_requests.saturating_add(1);
            if let (Some(started), Some(completed)) = (log.started_at_unix, log.completed_at_unix) {
                metric.total_latency_ms = metric
                    .total_latency_ms
                    .saturating_add(completed.saturating_sub(started).saturating_mul(1_000));
            }
        }
    }

    fn score(&self, provider: &str) -> ProviderRoutingScore {
        self.providers
            .get(provider)
            .map(ProviderRoutingMetric::score)
            .unwrap_or_default()
    }
}

impl ProviderRoutingMetric {
    fn score(&self) -> ProviderRoutingScore {
        let total_requests = self
            .successful_requests
            .saturating_add(self.failed_requests);
        let average_latency_ms = if self.successful_requests == 0 {
            None
        } else {
            Some(self.total_latency_ms / self.successful_requests)
        };
        ProviderRoutingScore {
            average_latency_ms,
            failure_rate: if total_requests == 0 {
                0.0
            } else {
                self.failed_requests as f64 / total_requests as f64
            },
            observed_requests: total_requests,
        }
    }

    fn health(&self, health_rank: u8, health_reason: &'static str) -> ProviderRoutingHealth {
        ProviderRoutingHealth::from_metric(*self, health_rank, health_reason)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProviderRoutingScore {
    average_latency_ms: Option<u64>,
    failure_rate: f64,
    observed_requests: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct ProviderRoutingHealth {
    pub(crate) observed_requests: u64,
    pub(crate) successful_requests: u64,
    pub(crate) failed_requests: u64,
    pub(crate) average_latency_ms: Option<u64>,
    pub(crate) failure_rate: f64,
    pub(crate) health_rank: u8,
    pub(crate) health_reason: &'static str,
}

impl ProviderRoutingHealth {
    fn from_metric(
        metric: ProviderRoutingMetric,
        health_rank: u8,
        health_reason: &'static str,
    ) -> Self {
        let score = metric.score();
        Self {
            observed_requests: score.observed_requests,
            successful_requests: metric.successful_requests,
            failed_requests: metric.failed_requests,
            average_latency_ms: score.average_latency_ms,
            failure_rate: score.failure_rate,
            health_rank,
            health_reason,
        }
    }
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

    fn record_cache_hit(&mut self) {
        self.cache_hits_total = self.cache_hits_total.saturating_add(1);
    }

    fn record_cache_miss(&mut self) {
        self.cache_misses_total = self.cache_misses_total.saturating_add(1);
    }

    fn record_tool_call(&mut self, _tool_name: &str, latency_ms: u64) {
        self.tool_call_total = self.tool_call_total.saturating_add(1);
        self.tool_latency_ms_total = self.tool_latency_ms_total.saturating_add(latency_ms);
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
            cache_hits_total: self.cache_hits_total,
            cache_misses_total: self.cache_misses_total,
            billing_event_total: self.billing_event_total,
            tool_call_total: self.tool_call_total,
            tool_latency_ms_total: self.tool_latency_ms_total,
            token_totals: self.token_totals.clone(),
            model_provider_totals: self.model_provider_totals.values().cloned().collect(),
        }
    }
}

impl AiResponseCacheKey {
    fn new(value: String) -> Self {
        Self { value }
    }

    fn as_str(&self) -> &str {
        &self.value
    }
}

impl AiResponseCache {
    fn get(&mut self, key: &AiResponseCacheKey, now_unix: u64) -> Option<AiCachedResponse> {
        let entry = self.entries.get(key.as_str())?;
        if entry.expires_at_unix <= now_unix {
            self.entries.remove(key.as_str());
            self.order.retain(|existing| existing != key.as_str());
            return None;
        }
        Some(entry.response.clone())
    }

    fn insert(
        &mut self,
        key: AiResponseCacheKey,
        response: AiCachedResponse,
        ttl_secs: u64,
        max_records: usize,
        now_unix: u64,
    ) {
        let key = key.value;
        if self.entries.contains_key(&key) {
            self.order.retain(|existing| existing != &key);
        }
        self.entries.insert(
            key.clone(),
            AiResponseCacheEntry {
                response,
                expires_at_unix: now_unix.saturating_add(ttl_secs),
            },
        );
        self.order.push_back(key);
        while self.entries.len() > max_records {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
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
    pub(crate) routing: ProviderRoutingHealth,
    pub(crate) local_observations: ProviderRoutingHealth,
    pub(crate) cluster_observations: Option<ProviderRoutingHealth>,
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
        let upstream_counters = config
            .upstreams
            .iter()
            .map(|upstream| (upstream.name.clone(), AtomicU64::new(0)))
            .collect();
        let extension_registry = ExtensionRegistry::from_config(&config.extensions);
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
        let storage = config.storage.clone();
        let mcp_servers = config.mcp_servers.clone();
        let cluster_sync = initial_cluster_sync_status(&config);
        let metering_exporter = MeteringExporter::from_config(&config.metering)
            .ok()
            .flatten()
            .map(Arc::new);
        let cluster_counters = ClusterCounterBackend::from_config(&config);

        Self {
            cluster_identity: Arc::new(ClusterIdentity::from_config(&config)),
            cluster_sync: Arc::new(cluster_sync),
            config: Arc::new(config),
            providers: Arc::new(providers),
            upstreams: Arc::new(upstreams),
            runtime_routes: Arc::new(runtime_routes),
            runtime_upstreams: Arc::new(runtime_upstreams),
            extension_registry: Arc::new(extension_registry),
            model_visibility: Arc::new(model_visibility),
            model_registry: Arc::new(model_registry),
            provider_adapters: Arc::new(ProviderAdapterRegistry::default()),
            provider_circuit_config,
            provider_circuits: Arc::new(provider_circuits),
            provider_routing_metrics: Arc::new(Mutex::new(ProviderRoutingMetrics::default())),
            cluster_counters: Arc::new(cluster_counters),
            metering_events: Arc::new(InMemoryBillingEventSink::with_retention_limit(
                storage.billing_event_retention_records,
            )),
            metering_exporter,
            request_logs: Arc::new(Mutex::new(InMemoryAppendRepository::with_retention_limit(
                storage.request_log_retention_records,
            ))),
            audit_events: Arc::new(Mutex::new(InMemoryAppendRepository::with_retention_limit(
                storage.audit_event_retention_records,
            ))),
            usage_aggregates: Arc::new(Mutex::new(InMemoryRepository::new())),
            metrics: Arc::new(Mutex::new(GatewayMetricsAccumulator::default())),
            response_cache: Arc::new(Mutex::new(AiResponseCache::default())),
            mcp_manager: Arc::new(McpManager::from_configs(&mcp_servers)),
            access_log_error_limiter: Arc::new(AccessLogRateLimiter::default()),
            policy_engine: Arc::new(policy_engine),
            upstream_counters: Arc::new(upstream_counters),
            model_route_counter: Arc::new(AtomicU64::new(0)),
            request_ids: Arc::new(AtomicU64::new(1)),
            drain: Arc::new(AtomicBool::new(false)),
            acme_renewal: None,
        }
    }

    pub(crate) fn extension_statuses(&self) -> Vec<ExtensionStatus> {
        self.extension_registry.statuses()
    }

    pub(crate) fn tools_for(
        &self,
        tenant: &ferrogate_core::TenantContext,
        api_key_id: Option<&str>,
        route: Option<&str>,
    ) -> Vec<RegisteredTool> {
        let mut tools = self.extension_registry.tools_for(tenant, api_key_id, route);
        tools.extend(self.mcp_registered_tools());
        tools
    }

    pub(crate) fn all_tools(&self) -> Vec<RegisteredTool> {
        let mut tools = self.extension_registry.all_tools();
        tools.extend(self.mcp_registered_tools());
        tools
    }

    pub(crate) fn mcp_statuses(&self) -> Vec<McpServerStatus> {
        self.mcp_manager.statuses()
    }

    pub(crate) fn mcp_health_check_and_reconnect(&self) {
        self.mcp_manager.health_check_and_reconnect();
    }

    fn mcp_registered_tools(&self) -> Vec<RegisteredTool> {
        self.mcp_manager
            .tools()
            .into_iter()
            .map(|tool| RegisteredTool {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
                extension_id: format!("mcp.{}", tool.server_name),
                tenant_allowlist: Vec::new(),
                api_key_allowlist: Vec::new(),
                route_allowlist: Vec::new(),
            })
            .collect()
    }

    pub(crate) async fn execute_tool(
        &self,
        request: ToolExecutionRequest,
        request_id: String,
        tenant: ferrogate_core::TenantContext,
        api_key_id: Option<&str>,
    ) -> Result<ToolExecutionResponse, ToolExecutionError> {
        self.extension_registry
            .execute_tool(request, request_id, tenant, api_key_id)
            .await
    }

    pub(crate) async fn execute_mcp_tool(
        &self,
        request: ToolExecutionRequest,
        request_id: String,
        tenant: ferrogate_core::TenantContext,
    ) -> Result<ToolExecutionResponse, ToolExecutionError> {
        let (server_name, _) = request.name.split_once('-').ok_or_else(|| {
            ToolExecutionError::NotFound(format!(
                "MCP tool {} must use serverName-toolName namespace",
                request.name
            ))
        })?;
        let policy_request = RequestContext {
            request_id: request_id.clone(),
            trace_id: None,
            route: Some("/v1/mcp/tool/execute".into()),
            upstream: Some(format!("mcp:{server_name}")),
            tenant: tenant.clone(),
        };
        let policy_model = format!("mcp_tool:{}", request.name);
        let policy_provider = format!("mcp:{server_name}");
        if let PolicyDecision::Deny { code: _, message } =
            self.evaluate_policy(&policy_request, Some(&policy_model), Some(&policy_provider))
        {
            self.record_tool_billing_event(&request_id, &tenant, &request.name, 0, 403);
            return Err(ToolExecutionError::Denied(message));
        }

        let started = std::time::Instant::now();
        let result = self
            .mcp_manager
            .execute_tool(McpToolExecutionRequest {
                name: request.name.clone(),
                arguments: request.arguments.clone(),
            })
            .map_err(tool_error_from_mcp)?;
        let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.record_tool_billing_event(
            &request_id,
            &tenant,
            &request.name,
            latency_ms,
            if result.is_error { 502 } else { 200 },
        );
        Ok(tool_response_from_mcp(
            request, request_id, result, latency_ms,
        ))
    }

    pub(crate) fn run_pre_request_hooks(
        &self,
        request_id: &str,
        path: &str,
    ) -> Result<(), ToolExecutionError> {
        self.extension_registry.pre_request(request_id, path)
    }

    pub(crate) fn run_post_response_hooks(&self, request_id: &str, status: u16) {
        self.extension_registry.post_response(request_id, status);
    }

    fn with_reloaded_config(&self, config: Config) -> Self {
        let mut next = AppState::new(config);
        next.cluster_identity = Arc::clone(&self.cluster_identity);
        next.cluster_counters = Arc::new(ClusterCounterBackend::from_reloaded_config(
            &next.config,
            &self.cluster_counters,
        ));
        next.provider_routing_metrics = Arc::clone(&self.provider_routing_metrics);
        next.metering_events = Arc::clone(&self.metering_events);
        next.request_logs = Arc::clone(&self.request_logs);
        next.audit_events = Arc::clone(&self.audit_events);
        next.usage_aggregates = Arc::clone(&self.usage_aggregates);
        next.metrics = Arc::clone(&self.metrics);
        next.response_cache = Arc::clone(&self.response_cache);
        next.mcp_manager = Arc::clone(&self.mcp_manager);
        next.mcp_manager.reconfigure(&next.config.mcp_servers);
        next.request_ids = Arc::clone(&self.request_ids);
        next.drain = Arc::clone(&self.drain);
        next.acme_renewal = self.acme_renewal.clone();
        self.apply_storage_config(&next.config.storage);
        next
    }

    fn apply_storage_config(&self, storage: &StorageConfig) {
        let _ = self
            .metering_events
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

    pub(crate) fn cluster_status(&self) -> ClusterStatus {
        ClusterStatus::new(
            &self.cluster_identity,
            &self.cluster_sync,
            &self.drain_status(),
        )
    }

    pub(crate) fn drain_status(&self) -> DrainStatus {
        let draining = self.drain.load(Ordering::Relaxed);
        DrainStatus {
            draining,
            accepting_new_requests: !draining,
            drain_reason: if draining {
                "operator_drain"
            } else {
                "not_draining"
            },
        }
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.drain.load(Ordering::Relaxed)
    }

    pub(crate) fn acme_renewal_status(&self) -> Option<AcmeRenewalStatus> {
        self.acme_renewal.as_ref().map(|state| state.snapshot())
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
        tool_context: ToolInjectionContext<'_>,
        logical_model: String,
        stream: bool,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        let tools = self
            .tools_for(
                tool_context.tenant,
                tool_context.api_key_id,
                tool_context.route,
            )
            .into_iter()
            .map(|tool| ferrogate_core::ToolDef {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect::<Vec<_>>();
        let body = self
            .provider_adapters
            .inject_tools(&provider.kind, body, &tools)?;
        self.provider_adapters.prepare_chat_completions(
            ProviderConfig {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                api_key: provider.api_key_value(),
                openrouter_http_referer: provider.openrouter_http_referer.clone(),
                openrouter_x_title: provider.openrouter_x_title.clone(),
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
                openrouter_http_referer: provider.openrouter_http_referer.clone(),
                openrouter_x_title: provider.openrouter_x_title.clone(),
            },
            ResponsesPlan {
                logical_model,
                provider_model: model_route.provider_model.clone(),
                stream,
                body,
            },
        )
    }

    pub(crate) fn ai_cache_enabled(
        &self,
        api_key_id: Option<&str>,
        logical_model: &str,
        provider_name: &str,
    ) -> bool {
        if !self.config.cache.enabled {
            return false;
        }
        let _ = provider_name;
        if self
            .config
            .models
            .iter()
            .find(|model| model.name == logical_model)
            .and_then(|model| model.cache_enabled)
            == Some(false)
        {
            return false;
        }
        if let Some(api_key_id) = api_key_id {
            if self
                .config
                .api_keys
                .iter()
                .find(|key| key.id == api_key_id)
                .and_then(|key| key.cache_enabled)
                == Some(false)
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn ai_response_cache_key(
        &self,
        route: &str,
        tenant: &ferrogate_core::TenantContext,
        logical_model: &str,
        provider: &str,
        provider_model: &str,
        body: &serde_json::Value,
    ) -> AiResponseCacheKey {
        #[derive(Serialize)]
        struct CacheKeyInput<'a> {
            route: &'a str,
            organization_id: &'a Option<String>,
            team_id: &'a Option<String>,
            project_id: &'a Option<String>,
            user_id: &'a Option<String>,
            api_key_id: &'a Option<String>,
            logical_model: &'a str,
            provider: &'a str,
            provider_model: &'a str,
            stream: bool,
            request_body: &'a serde_json::Value,
        }

        let bytes = serde_json::to_vec(&CacheKeyInput {
            route,
            organization_id: &tenant.organization_id,
            team_id: &tenant.team_id,
            project_id: &tenant.project_id,
            user_id: &tenant.user_id,
            api_key_id: &tenant.api_key_id,
            logical_model,
            provider,
            provider_model,
            stream: false,
            request_body: body,
        })
        .expect("AI cache key serialization should not fail");
        AiResponseCacheKey::new(format!("ai-cache:{:016x}", fnv1a64(&bytes)))
    }

    pub(crate) fn lookup_ai_response_cache(
        &self,
        key: &AiResponseCacheKey,
    ) -> Option<AiCachedResponse> {
        let now = now_unix_seconds().unwrap_or_default();
        self.response_cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(key, now))
    }

    pub(crate) fn store_ai_response_cache(
        &self,
        key: AiResponseCacheKey,
        response: AiCachedResponse,
    ) {
        let now = now_unix_seconds().unwrap_or_default();
        if let Ok(mut cache) = self.response_cache.lock() {
            cache.insert(
                key,
                response,
                self.config.cache.ttl_secs,
                self.config.cache.max_records,
                now,
            );
        }
    }

    pub(crate) fn record_ai_cache_hit(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_cache_hit();
        }
    }

    pub(crate) fn record_ai_cache_miss(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_cache_miss();
        }
    }

    pub(crate) fn resolve_model(
        &self,
        logical_model: &str,
    ) -> Result<ResolvedModelRoute, ModelRegistryError> {
        self.model_registry.resolve(logical_model)
    }

    pub(crate) fn candidate_model_routes(
        &self,
        model: &ResolvedModelRoute,
        estimated_usage: Option<&BillingTokenUsage>,
    ) -> Vec<ModelRoute> {
        match model.routing_strategy {
            RoutingStrategy::Priority => {
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
            RoutingStrategy::LowestCost => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                routes.sort_by(|left, right| {
                    route_estimated_cost(left, estimated_usage)
                        .partial_cmp(&route_estimated_cost(right, estimated_usage))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| left.priority.cmp(&right.priority))
                        .then_with(|| right.weight.cmp(&left.weight))
                        .then_with(|| left.provider.cmp(&right.provider))
                        .then_with(|| left.provider_model.cmp(&right.provider_model))
                });
                routes
            }
            RoutingStrategy::LowestLatency => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                self.sort_routes_by_latency(&mut routes);
                routes
            }
            RoutingStrategy::Balanced => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                self.sort_routes_by_balanced_score(&mut routes);
                routes
            }
        }
    }

    fn sort_routes_by_latency(&self, routes: &mut [ModelRoute]) {
        let metrics = self.provider_routing_metrics.lock().ok();
        routes.sort_by(|left, right| {
            let left_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&left.provider))
                .unwrap_or_default();
            let right_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&right.provider))
                .unwrap_or_default();
            provider_health_rank(self, left, left_score)
                .cmp(&provider_health_rank(self, right, right_score))
                .then_with(|| latency_rank(left_score).cmp(&latency_rank(right_score)))
                .then_with(|| left.priority.cmp(&right.priority))
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.provider.cmp(&right.provider))
                .then_with(|| left.provider_model.cmp(&right.provider_model))
        });
    }

    fn sort_routes_by_balanced_score(&self, routes: &mut [ModelRoute]) {
        let metrics = self.provider_routing_metrics.lock().ok();
        routes.sort_by(|left, right| {
            let left_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&left.provider))
                .unwrap_or_default();
            let right_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&right.provider))
                .unwrap_or_default();
            provider_health_rank(self, left, left_score)
                .cmp(&provider_health_rank(self, right, right_score))
                .then_with(|| {
                    balanced_route_score(left, left_score)
                        .partial_cmp(&balanced_route_score(right, right_score))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| left.priority.cmp(&right.priority))
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.provider.cmp(&right.provider))
                .then_with(|| left.provider_model.cmp(&right.provider_model))
        });
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
        let local_observations = self.provider_routing_health(provider, circuit.open);
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
                routing: local_observations,
                local_observations,
                cluster_observations: None,
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
            routing: local_observations,
            local_observations,
            cluster_observations: None,
        }
    }

    fn provider_routing_health(
        &self,
        provider: &Provider,
        circuit_open: bool,
    ) -> ProviderRoutingHealth {
        let metric = self
            .provider_routing_metrics
            .lock()
            .ok()
            .and_then(|metrics| metrics.providers.get(&provider.name).copied())
            .unwrap_or_default();
        if !provider.enabled {
            return metric.health(3, "disabled");
        }
        let score = metric.score();
        metric.health(
            provider_health_rank_from_signals(!circuit_open, score),
            provider_health_reason(circuit_open, score),
        )
    }

    pub(crate) fn try_consume_api_key_request(
        &self,
        api_key_id: &str,
        limit: u64,
    ) -> anyhow::Result<bool> {
        self.cluster_counters.try_consume_request(api_key_id, limit)
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

    #[cfg(test)]
    pub(crate) fn api_key_tokens_committed_or_reserved(
        &self,
        api_key_id: &str,
    ) -> anyhow::Result<u64> {
        self.cluster_counters
            .committed_or_reserved(api_key_id, self.api_key_total_tokens_used(api_key_id))
    }

    pub(crate) fn try_reserve_api_key_tokens(
        &self,
        api_key_id: &str,
        budget: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<Option<ApiKeyTokenReservation>> {
        let committed = self.api_key_total_tokens_used(api_key_id);
        self.cluster_counters
            .try_reserve_tokens(api_key_id, committed, budget, estimated_tokens)
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
        let event = BillingEvent {
            request_id: draft.request.request_id.clone(),
            trace_id: draft.request.trace_id.clone(),
            cluster_id: Some(self.cluster_identity.cluster_id.clone()),
            node_id: Some(self.cluster_identity.node_id.clone()),
            tenant: draft.request.tenant.clone(),
            logical_model: draft.logical_model.into(),
            provider: draft.provider.into(),
            provider_model: draft.provider_model.into(),
            usage: usage.clone(),
            usage_source: draft.usage_source,
            status_code: draft.status_code,
            occurred_at_unix: None,
        };
        self.metering_events.record(event.clone())?;
        self.record_billing_metrics(&event);
        if let Some(exporter) = &self.metering_exporter {
            exporter.export_event(event.clone());
        }
        self.record_usage_aggregate(
            &draft.request.tenant,
            draft.logical_model,
            draft.provider,
            &usage,
        );
        if let Some(api_key_id) = &draft.request.tenant.api_key_id {
            if let Err(error) = self
                .cluster_counters
                .record_used_tokens(api_key_id, usage.total_tokens)
            {
                warn!(
                    api_key_id = %api_key_id,
                    total_tokens = usage.total_tokens,
                    error = %error,
                    "failed to record shared token counter usage"
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn billing_events(&self) -> Vec<BillingEvent> {
        self.metering_events.list()
    }

    pub(crate) fn metering_events_page(
        &self,
        pagination: AdminPagination,
    ) -> AdminPage<BillingEvent> {
        AdminPage {
            data: self
                .metering_events
                .list_paginated(pagination.offset, pagination.limit),
            total: self.metering_events.len(),
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

    pub(crate) fn record_request_log(&self, mut log: StoredRequestLog) {
        log.cluster_id = Some(self.cluster_identity.cluster_id.clone());
        log.node_id = Some(self.cluster_identity.node_id.clone());
        self.record_request_metrics(&log);
        if let Ok(mut metrics) = self.provider_routing_metrics.lock() {
            metrics.record_request_log(&log);
        }
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
                cluster_id: Some(self.cluster_identity.cluster_id.clone()),
                node_id: Some(self.cluster_identity.node_id.clone()),
                actor_api_key_id: event.actor_api_key_id,
                action: event.action,
                target: event.target,
                outcome: event.outcome,
                message: event.message,
                occurred_at_unix: now_unix_seconds(),
            });
        }
    }

    fn record_tool_billing_event(
        &self,
        request_id: &str,
        tenant: &ferrogate_core::TenantContext,
        tool_name: &str,
        latency_ms: u64,
        status_code: u16,
    ) {
        let event = BillingEvent {
            request_id: request_id.into(),
            trace_id: None,
            cluster_id: Some(self.cluster_identity.cluster_id.clone()),
            node_id: Some(self.cluster_identity.node_id.clone()),
            tenant: tenant.clone(),
            logical_model: format!("mcp_tool:{tool_name}"),
            provider: "mcp".into(),
            provider_model: tool_name.into(),
            usage: BillingTokenUsage::new(0, 0, 0),
            usage_source: BillingUsageSource::GatewayEstimate,
            status_code,
            occurred_at_unix: now_unix_seconds(),
        };
        let _ = self.metering_events.record(event.clone());
        self.record_billing_metrics(&event);
        if let Some(exporter) = &self.metering_exporter {
            exporter.export_event(event);
        }
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_tool_call(tool_name, latency_ms);
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
                cache_hits_total: 0,
                cache_misses_total: 0,
                billing_event_total: 0,
                tool_call_total: 0,
                tool_latency_ms_total: 0,
                token_totals: TokenMetricTotals::default(),
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

    pub(crate) fn tool_session_events(&self, session_id: &str) -> Vec<StoredAuditEvent> {
        let target = format!("tool_session:{session_id}");
        self.audit_events
            .lock()
            .map(|events| {
                events
                    .list()
                    .into_iter()
                    .filter(|event| event.action == "tool.execute" && event.target == target)
                    .collect()
            })
            .unwrap_or_default()
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
    counters: Arc<ClusterCounterBackend>,
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
        self.counters.release_tokens(&self.api_key_id, self.tokens);
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

#[derive(Debug)]
enum ClusterCounterBackend {
    Local {
        request_windows: HashMap<String, ApiKeyRequestWindow>,
        token_reservations: Arc<Mutex<HashMap<String, u64>>>,
    },
    Redis(RedisCounterBackend),
}

#[derive(Debug)]
struct RedisCounterBackend {
    cluster_id: String,
    url: String,
    timeout: Duration,
}

impl ClusterCounterBackend {
    fn from_config(config: &Config) -> Self {
        if config.cluster.enabled && config.cluster.counter_backend == "redis" {
            if let Some(url) = &config.cluster.redis_url {
                return Self::Redis(RedisCounterBackend {
                    cluster_id: config.cluster.cluster_id.clone(),
                    url: url.clone(),
                    timeout: Duration::from_millis(config.cluster.counter_timeout_millis),
                });
            }
        }

        Self::Local {
            request_windows: config
                .api_keys
                .iter()
                .filter(|key| key.request_limit_per_minute.is_some())
                .map(|key| (key.id.clone(), ApiKeyRequestWindow::default()))
                .collect(),
            token_reservations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn from_reloaded_config(config: &Config, previous: &Arc<Self>) -> Self {
        match (Self::from_config(config), previous.as_ref()) {
            (
                Self::Local {
                    request_windows, ..
                },
                Self::Local {
                    token_reservations, ..
                },
            ) => Self::Local {
                request_windows,
                token_reservations: Arc::clone(token_reservations),
            },
            (next, _) => next,
        }
    }

    fn try_consume_request(&self, api_key_id: &str, limit: u64) -> anyhow::Result<bool> {
        match self {
            Self::Local {
                request_windows, ..
            } => Ok(request_windows.get(api_key_id).is_none_or(|window| {
                window.try_consume(limit, now_unix_seconds().unwrap_or_default())
            })),
            Self::Redis(redis) => redis.try_consume_request(api_key_id, limit),
        }
    }

    #[cfg(test)]
    fn reserved_tokens(&self, api_key_id: &str) -> anyhow::Result<u64> {
        match self {
            Self::Local {
                token_reservations, ..
            } => Ok(token_reservations
                .lock()
                .ok()
                .and_then(|reservations| reservations.get(api_key_id).copied())
                .unwrap_or_default()),
            Self::Redis(redis) => redis.reserved_tokens(api_key_id),
        }
    }

    #[cfg(test)]
    fn committed_or_reserved(&self, api_key_id: &str, local_committed: u64) -> anyhow::Result<u64> {
        match self {
            Self::Local { .. } => {
                Ok(local_committed.saturating_add(self.reserved_tokens(api_key_id)?))
            }
            Self::Redis(redis) => redis.committed_or_reserved(api_key_id),
        }
    }

    fn try_reserve_tokens(
        self: &Arc<Self>,
        api_key_id: &str,
        committed: u64,
        budget: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<Option<ApiKeyTokenReservation>> {
        match self.as_ref() {
            Self::Local {
                token_reservations, ..
            } => {
                let Ok(mut reservations) = token_reservations.lock() else {
                    return Ok(None);
                };
                let reserved = reservations.get(api_key_id).copied().unwrap_or_default();
                if committed
                    .saturating_add(reserved)
                    .saturating_add(estimated_tokens)
                    > budget
                {
                    return Ok(None);
                }

                *reservations.entry(api_key_id.to_string()).or_default() += estimated_tokens;
                Ok(Some(ApiKeyTokenReservation {
                    api_key_id: api_key_id.to_string(),
                    tokens: estimated_tokens,
                    counters: Arc::clone(self),
                    released: false,
                }))
            }
            Self::Redis(redis) => {
                if redis.try_reserve_tokens(api_key_id, budget, estimated_tokens)? {
                    Ok(Some(ApiKeyTokenReservation {
                        api_key_id: api_key_id.to_string(),
                        tokens: estimated_tokens,
                        counters: Arc::clone(self),
                        released: false,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn record_used_tokens(&self, api_key_id: &str, tokens: u64) -> anyhow::Result<()> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Redis(redis) => redis.record_used_tokens(api_key_id, tokens),
        }
    }

    fn release_tokens(&self, api_key_id: &str, tokens: u64) {
        match self {
            Self::Local {
                token_reservations, ..
            } => {
                if let Ok(mut reservations) = token_reservations.lock() {
                    if let Some(reserved) = reservations.get_mut(api_key_id) {
                        *reserved = reserved.saturating_sub(tokens);
                        if *reserved == 0 {
                            reservations.remove(api_key_id);
                        }
                    }
                }
            }
            Self::Redis(redis) => {
                let _ = redis.release_tokens(api_key_id, tokens);
            }
        }
    }
}

impl RedisCounterBackend {
    fn connection(&self) -> anyhow::Result<redis::Connection> {
        let client = redis::Client::open(self.url.as_str())?;
        let connection = client.get_connection_with_timeout(self.timeout)?;
        connection.set_read_timeout(Some(self.timeout))?;
        connection.set_write_timeout(Some(self.timeout))?;
        Ok(connection)
    }

    fn key(&self, suffix: &str) -> String {
        format!("ferrogate:{}:{suffix}", self.cluster_id)
    }

    fn api_key_prefix(&self, api_key_id: &str) -> String {
        let sanitized = sanitize_redis_key_part(api_key_id);
        self.key(&format!("api-key:{sanitized}"))
    }

    fn try_consume_request(&self, api_key_id: &str, limit: u64) -> anyhow::Result<bool> {
        let now = now_unix_seconds().unwrap_or_default();
        let window = now / 60;
        let key = format!("{}:rate:{window}", self.api_key_prefix(api_key_id));
        let mut connection = self.connection()?;
        let count: u64 = redis::cmd("INCR").arg(&key).query(&mut connection)?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(120)
                .query(&mut connection)?;
        }
        Ok(count <= limit)
    }

    #[cfg(test)]
    fn reserved_tokens(&self, api_key_id: &str) -> anyhow::Result<u64> {
        let key = format!("{}:tokens:reserved", self.api_key_prefix(api_key_id));
        let mut connection = self.connection()?;
        Ok(connection.get(key).unwrap_or_default())
    }

    #[cfg(test)]
    fn committed_or_reserved(&self, api_key_id: &str) -> anyhow::Result<u64> {
        let prefix = self.api_key_prefix(api_key_id);
        let used_key = format!("{prefix}:tokens:used");
        let reserved_key = format!("{prefix}:tokens:reserved");
        let mut connection = self.connection()?;
        let used: u64 = connection.get(used_key).unwrap_or_default();
        let reserved: u64 = connection.get(reserved_key).unwrap_or_default();
        Ok(used.saturating_add(reserved))
    }

    fn try_reserve_tokens(
        &self,
        api_key_id: &str,
        budget: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<bool> {
        let prefix = self.api_key_prefix(api_key_id);
        let used_key = format!("{prefix}:tokens:used");
        let reserved_key = format!("{prefix}:tokens:reserved");
        let script = redis::Script::new(
            r#"
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
local reserved = tonumber(redis.call('GET', KEYS[2]) or '0')
local budget = tonumber(ARGV[1])
local estimate = tonumber(ARGV[2])
if used + reserved + estimate > budget then
  return 0
end
redis.call('INCRBY', KEYS[2], estimate)
return 1
"#,
        );
        let mut connection = self.connection()?;
        let reserved: u8 = script
            .key(used_key)
            .key(reserved_key)
            .arg(budget)
            .arg(estimated_tokens)
            .invoke(&mut connection)?;
        Ok(reserved == 1)
    }

    fn record_used_tokens(&self, api_key_id: &str, tokens: u64) -> anyhow::Result<()> {
        if tokens == 0 {
            return Ok(());
        }
        let key = format!("{}:tokens:used", self.api_key_prefix(api_key_id));
        let mut connection = self.connection()?;
        let _: u64 = redis::cmd("INCRBY")
            .arg(key)
            .arg(tokens)
            .query(&mut connection)?;
        Ok(())
    }

    fn release_tokens(&self, api_key_id: &str, tokens: u64) -> anyhow::Result<()> {
        let key = format!("{}:tokens:reserved", self.api_key_prefix(api_key_id));
        let script = redis::Script::new(
            r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local next = current - tonumber(ARGV[1])
if next <= 0 then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], next)
end
return 1
"#,
        );
        let mut connection = self.connection()?;
        let _: u8 = script.key(key).arg(tokens).invoke(&mut connection)?;
        Ok(())
    }
}

fn sanitize_redis_key_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
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
    entry.routing_strategy = model.routing_strategy;
    entry.enabled = model.enabled;
    entry.primary.input_price_per_1m = model.input_price_per_1m;
    entry.primary.output_price_per_1m = model.output_price_per_1m;
    entry.fallbacks = model
        .fallbacks
        .iter()
        .filter(|fallback| fallback.enabled)
        .map(|fallback| {
            ModelRoute::with_routing(
                fallback.provider.clone(),
                fallback.provider_model.clone(),
                fallback.input_price_per_1m,
                fallback.output_price_per_1m,
                fallback.priority.unwrap_or(100),
                fallback.weight.unwrap_or(1),
            )
        })
        .collect();
    entry
}

fn route_estimated_cost(route: &ModelRoute, usage: Option<&BillingTokenUsage>) -> f64 {
    let Some(usage) = usage else {
        return route_estimated_unit_cost(route);
    };
    match (route.input_price_per_1m, route.output_price_per_1m) {
        (Some(input), Some(output)) => {
            let price = ModelPrice::usd(input, output);
            price.estimate(usage).total_cost
        }
        _ => route_estimated_unit_cost(route),
    }
}

fn tool_error_from_mcp(error: McpExecutionError) -> ToolExecutionError {
    match error {
        McpExecutionError::Denied(message) => ToolExecutionError::Denied(message),
        McpExecutionError::NotFound(message) => ToolExecutionError::NotFound(message),
        McpExecutionError::Unavailable(message) | McpExecutionError::Failed(message) => {
            ToolExecutionError::Failed(message)
        }
    }
}

fn tool_response_from_mcp(
    request: ToolExecutionRequest,
    request_id: String,
    result: McpToolExecutionResult,
    latency_ms: u64,
) -> ToolExecutionResponse {
    ToolExecutionResponse {
        object: "tool_execution",
        name: request.name,
        content: result.content,
        is_error: result.is_error,
        request_id,
        session_id: request.session_id,
        latency_ms,
    }
}

fn provider_health_rank(state: &AppState, route: &ModelRoute, score: ProviderRoutingScore) -> u8 {
    provider_health_rank_from_signals(state.provider_circuit_allows(&route.provider), score)
}

fn provider_health_rank_from_signals(circuit_allows: bool, score: ProviderRoutingScore) -> u8 {
    if !circuit_allows {
        return 2;
    }
    if score.observed_requests >= 3 && score.failure_rate >= 0.5 {
        return 1;
    }
    0
}

fn provider_health_reason(circuit_open: bool, score: ProviderRoutingScore) -> &'static str {
    if circuit_open {
        return "circuit_open";
    }
    if score.observed_requests >= 3 && score.failure_rate >= 0.5 {
        return "observed_failure_rate";
    }
    if score.observed_requests == 0 {
        return "no_observations";
    }
    "healthy_observations"
}

fn latency_rank(score: ProviderRoutingScore) -> u64 {
    score.average_latency_ms.unwrap_or(u64::MAX)
}

fn balanced_route_score(route: &ModelRoute, score: ProviderRoutingScore) -> f64 {
    let cost = route
        .input_price_per_1m
        .zip(route.output_price_per_1m)
        .map(|(input, output)| input + output)
        .unwrap_or(1_000.0);
    let latency = score.average_latency_ms.unwrap_or(1_000) as f64 / 1_000.0;
    let failure_penalty = score.failure_rate * 10.0;
    cost + latency + failure_penalty
}

fn route_estimated_unit_cost(route: &ModelRoute) -> f64 {
    match (route.input_price_per_1m, route.output_price_per_1m) {
        (Some(input), Some(output)) => input + output,
        (Some(input), None) => input,
        (None, Some(output)) => output,
        (None, None) => f64::INFINITY,
    }
}

fn resolve_cluster_node_id(configured: &str) -> String {
    let configured = configured.trim();
    if configured != "auto" {
        return configured.to_string();
    }
    env::var("FERROGATE_NODE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| format!("ferrogate-{}", std::process::id()))
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
                openrouter_http_referer: None,
                openrouter_x_title: None,
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
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-a".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-b".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
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
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let first = state
            .candidate_model_routes(&resolved, None)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let second = state
            .candidate_model_routes(&resolved, None)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let third = state
            .candidate_model_routes(&resolved, None)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(first, ["primary", "backup-b", "backup-a"]);
        assert_eq!(second, ["primary", "backup-b", "backup-a"]);
        assert_eq!(third, ["primary", "backup-a", "backup-b"]);
    }

    #[test]
    fn orders_lowest_cost_routes_by_estimated_price() {
        let config = Config {
            providers: vec![
                Provider {
                    name: "primary".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10001/v1".into(),
                    api_key_env: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-a".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    name: "backup-b".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::LowestCost,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(5.0),
                output_price_per_1m: Some(5.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();
        let usage = BillingTokenUsage::new(1_000, 2_000, 3_000);

        let providers = state
            .candidate_model_routes(&resolved, Some(&usage))
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-b", "backup-a", "primary"]);
    }

    #[test]
    fn orders_lowest_latency_routes_by_observed_provider_latency() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 3);
        record_provider_latency(&state, "backup-b", 200, 0, 2);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let providers = state
            .candidate_model_routes(&resolved, None)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["primary", "backup-b", "backup-a"]);
    }

    #[test]
    fn latency_routing_avoids_unhealthy_observed_provider() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 5);
        record_provider_latency(&state, "backup-b", 200, 0, 10);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let providers = state
            .candidate_model_routes(&resolved, None)
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-a", "backup-b", "primary"]);
    }

    #[test]
    fn provider_health_exposes_routing_observations_and_rank_reason() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 200, 0, 1);

        let primary = state
            .provider_health_checks()
            .into_iter()
            .find(|check| check.name == "primary")
            .unwrap();

        assert_eq!(primary.routing.observed_requests, 3);
        assert_eq!(primary.routing.successful_requests, 1);
        assert_eq!(primary.routing.failed_requests, 2);
        assert_eq!(primary.routing.average_latency_ms, Some(1_000));
        assert!((primary.routing.failure_rate - 0.666).abs() < 0.001);
        assert_eq!(primary.routing.health_rank, 1);
        assert_eq!(primary.routing.health_reason, "observed_failure_rate");
    }

    #[test]
    fn balanced_routing_combines_cost_latency_and_failures() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::Balanced,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 4);
        record_provider_latency(&state, "backup-b", 500, 0, 1);
        record_provider_latency(&state, "backup-b", 500, 0, 1);
        record_provider_latency(&state, "backup-b", 200, 0, 1);
        let resolved = state.resolve_model("fast-chat").unwrap();
        let usage = BillingTokenUsage::new(1_000, 1_000, 2_000);

        let providers = state
            .candidate_model_routes(&resolved, Some(&usage))
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-a", "primary", "backup-b"]);
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
                openrouter_http_referer: None,
                openrouter_x_title: None,
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
                openrouter_http_referer: None,
                openrouter_x_title: None,
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
                openrouter_http_referer: None,
                openrouter_x_title: None,
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
                cache_enabled: None,
            }],
            ..Config::default()
        });

        assert!(state.try_consume_api_key_request("key_dev", 1).unwrap());
        assert!(!state.try_consume_api_key_request("key_dev", 1).unwrap());
    }

    #[test]
    fn api_key_token_reservation_counts_against_budget_until_released() {
        let state = AppState::new(Config::default());

        let reservation = state
            .try_reserve_api_key_tokens("key_dev", 10, 7)
            .unwrap()
            .expect("first reservation should fit");

        assert_eq!(
            state
                .api_key_tokens_committed_or_reserved("key_dev")
                .unwrap(),
            7
        );
        assert!(state
            .try_reserve_api_key_tokens("key_dev", 10, 4)
            .unwrap()
            .is_none());

        drop(reservation);

        assert_eq!(
            state
                .api_key_tokens_committed_or_reserved("key_dev")
                .unwrap(),
            0
        );
        assert!(state
            .try_reserve_api_key_tokens("key_dev", 10, 4)
            .unwrap()
            .is_some());
    }

    #[test]
    fn records_token_metering_event_without_gateway_cost() {
        let config = Config {
            providers: vec![Provider {
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
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
            cluster_id: None,
            node_id: None,
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
            cache_status: None,
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
                cluster_id: None,
                node_id: None,
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
                cache_status: None,
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

        let metering_page = state.metering_events_page(state.admin_pagination(None));
        assert_eq!(metering_page.total, 2);
        assert_eq!(metering_page.data[0].request_id, "fg-2");

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
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
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
            cluster_id: None,
            node_id: None,
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
            cache_status: None,
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
        assert_eq!(snapshot.cache_hits_total, 0);
        assert_eq!(snapshot.cache_misses_total, 0);
        assert_eq!(snapshot.billing_event_total, 2);
        assert_eq!(snapshot.token_totals.total_tokens, 26);
        assert_eq!(snapshot.model_provider_totals[0].logical_model, "fast-chat");

        let aggregates = state.usage_aggregates();
        assert_eq!(aggregates.len(), 1);
        assert_eq!(aggregates[0].usage.prompt_tokens, 10);
        assert_eq!(aggregates[0].usage.completion_tokens, 16);
        assert_eq!(aggregates[0].usage.total_tokens, 26);
    }

    fn routing_strategy_test_config(
        routing_strategy: RoutingStrategy,
        primary_input_price: Option<f64>,
        primary_output_price: Option<f64>,
    ) -> Config {
        let config = Config {
            providers: vec![
                provider_config("primary", "http://127.0.0.1:10001/v1"),
                provider_config("backup-a", "http://127.0.0.1:10002/v1"),
                provider_config("backup-b", "http://127.0.0.1:10003/v1"),
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: primary_input_price,
                output_price_per_1m: primary_output_price,
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        config
    }

    fn provider_config(name: &str, base_url: &str) -> Provider {
        Provider {
            name: name.into(),
            kind: "openai".into(),
            base_url: base_url.into(),
            api_key_env: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }
    }

    fn record_provider_latency(
        state: &AppState,
        provider: &str,
        status_code: u16,
        started_at_unix: u64,
        completed_at_unix: u64,
    ) {
        state.record_request_log(StoredRequestLog {
            request_id: format!("fg-{provider}-{status_code}-{completed_at_unix}"),
            trace_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some(provider.into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            status_code,
            error_code: (status_code >= 400).then(|| "provider_error".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(started_at_unix),
            completed_at_unix: Some(completed_at_unix),
        });
    }
}
