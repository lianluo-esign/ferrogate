// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env, fs,
    io::ErrorKind,
    net::{IpAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::acme::{AcmeRenewalStatus, SharedAcmeRenewalState};
use crate::approval::{
    ApprovalDecisionError, ApprovalRegistry, ApprovalStatus, ApprovalWaitError,
    ToolApprovalDecisionRequest, ToolApprovalDraft, ToolApprovalRecord,
};
use crate::billing_client::BillingReporter;
use crate::config::{
    config_snapshot_id, resolve_env_placeholders, AccessLogMode, AgentWorkflowPolicy,
    AnalyticsConfig, AnalyticsProvider, ApiKey, Config, GatewayConfigProfile, GuardrailEffect,
    GuardrailProviderErrorMode, GuardrailProviderKind, GuardrailRule, GuardrailStage,
    HeaderMutation, Model, PolicyRule as ConfigPolicyRule, PromptTemplate, PromptTemplateStatus,
    Provider, RouteRule, SkillPackage, StorageConfig, StorageMigrationMode, Upstream,
};
use crate::extensions::{
    ExtensionRegistry, ExtensionStatus, RegisteredTool, ToolExecutionError, ToolExecutionRequest,
    ToolExecutionResponse,
};
use crate::metering::{MeteringExportStatus, MeteringExporter};
use crate::network_access::{resolve_client_ip, IpCidr, UnauthenticatedIpRateLimiter};
use crate::routing::parse_upstream_endpoint;
use ferrogate_billing::{
    BillingEvent, BillingEventSink, BillingUsageSource, InMemoryBillingEventSink, ModelPrice,
    ProviderAttempt, TokenUsage as BillingTokenUsage,
};
use ferrogate_core::{RequestContext, WorkspaceScope};
use ferrogate_guardrails::{
    apply_content_patches_to_document, validate_content_patch_permissions,
    ActionKind as GuardrailActionKind, AggregateOutcome, CheckBinding, CheckOutcome, ContentPatch,
    ContentSource, CustomHttpDetector, CustomHttpDetectorConfig, DetectorDefinition, DetectorError,
    DetectorInput, DetectorResult, DetectorSecret, DetectorStage, DetectorTenant, DetectorVerdict,
    DeterministicDetector, DeterministicDetectorConfig, GuardrailDetector, GuardrailEnvelope,
    PolicyAction, PolicyAggregation, PolicyExecution, PolicyMode, PolicyRevision,
    PolicyRevisionStatus, PolicyRevisionView, PolicyScopeSelector, PolicySelectionContext,
    PolicyStreamingMode,
};
use ferrogate_mcp::{
    McpExecutionError, McpManager, McpServerStatus, McpToolExecutionRequest, McpToolExecutionResult,
};
use ferrogate_observability::{
    GatewayMetricsSnapshot, ModelProviderMetricTotal, RequestStatusMetric, TokenMetricTotals,
};
use ferrogate_policy::{
    resolve_effective_quota, BasicPolicyEngine, EffectiveQuota, PolicyDecision, PolicyEngine,
    PolicyRule, PolicySubject, QuotaScopeChain,
};
use ferrogate_providers::{
    AdapterError, AwsProviderCredentials, ChatCompletionPlan, EmbeddingsPlan,
    GcpProviderCredentials, ModelRegistry, ModelRegistryEntry, ModelRegistryError, ModelRoute,
    ProviderAdapterRegistry, ProviderConfig, ProviderErrorResponse, ProviderHttpRequest,
    ProviderUsage, ResolvedModelRoute, ResponsesPlan, RoutingStrategy, SecretValue,
};
use ferrogate_runtime::{
    InMemorySelfHostedRunQueue, SelfHostedRunAck, SelfHostedRunAckRequest, SelfHostedRunAckStatus,
    SelfHostedRunAction, SelfHostedRunDispatch, SelfHostedRunLease, SelfHostedRunPollRequest,
    SelfHostedRunQueueRecord, SelfHostedWorkerError, SelfHostedWorkerIdentity,
    SelfHostedWorkerRegistration, SelfHostedWorkerRegistry,
};
use ferrogate_storage::{
    budget_alert_notification_id, guardrail_policy_revision_id, ControlPlaneDocuments,
    GuardrailEvaluationQuery, GuardrailEvaluationRepository, GuardrailPolicyRepository,
    PostgresStorageConfig, QuotaScopeKind, RuntimeControlPlaneState, RuntimeStorageBackend,
    RuntimeStorageOptions, RuntimeStorageRepositories, StorageBackendEvidence, StorageError,
    StoredAgentRun, StoredAgentRunEvent, StoredAgentWorkerInstance, StoredApiKey, StoredAsset,
    StoredAuditEvent, StoredBillingReportOutboxEntry, StoredBudgetAlertNotification,
    StoredGuardrailCheckEvaluation, StoredGuardrailEvaluation, StoredGuardrailPolicyBinding,
    StoredGuardrailPolicyRevision, StoredManagedWorkerIsolationEvidence,
    StoredManagedWorkerIsolationPolicy, StoredManagedWorkerIsolationSelection,
    StoredManagedWorkerLifecycleEvent, StoredManagedWorkerSession, StoredPaymentMethod,
    StoredPermission, StoredPlan, StoredProject, StoredQuotaPolicy, StoredRequestLog, StoredRole,
    StoredSelfHostedRunDispatch, StoredSelfHostedWorkerArtifact, StoredSelfHostedWorkerCheckpoint,
    StoredSelfHostedWorkerHeartbeat, StoredSelfHostedWorkerRegistration,
    StoredSelfHostedWorkerTelemetryEvent, StoredTenantAccount, StoredTenantRoleBinding,
    StoredUsageAggregate, StoredUsageMonthlyRollup, StoredWallet, StoredWorkspace,
};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
#[cfg(test)]
use redis::Commands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::warn;

pub(crate) const RELOAD_MODE_PROCESS_LOCAL: &str = "process-local";
const GUARDRAIL_EVIDENCE_MAX_IN_FLIGHT: usize = 64;
pub(crate) const RELOAD_MODE_LISTENER_LEVEL_REQUIRED: &str = "listener-level-required";
const SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const SELF_HOSTED_WORKER_STALE_THRESHOLD_SECS: u64 = 300;

pub(crate) struct ToolApprovalCreateRequest<'a> {
    pub(crate) tool: &'a ToolExecutionRequest,
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) approval_policy: ferrogate_core::ApprovalPolicy,
    pub(crate) can_log_bodies: bool,
}

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
    #[cfg(test)]
    pub(crate) fn with_source_path(config: Config, source_path: Option<PathBuf>) -> Self {
        Self::try_with_source_path(config, source_path).expect("failed to initialize app state")
    }

    pub(crate) fn try_with_source_path(
        config: Config,
        source_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let snapshot = config_snapshot_id(&config);
        let shared_file_control_plane = SharedFileControlPlane::from_config(&config)
            .inspect_err(|error| warn!("failed to initialize file cluster state: {error}"))
            .ok()
            .flatten()
            .map(Arc::new);
        Ok(Self {
            inner: Arc::new(RwLock::new(AppState::try_new(config)?)),
            reload_coordinator: Arc::new(Mutex::new(ferrogate_runtime::ReloadCoordinator::new(
                snapshot,
            ))),
            source_path: source_path.map(Arc::new),
            shared_file_control_plane,
        })
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

    pub(crate) fn create_guardrail_policy_revision(
        &self,
        revision: PolicyRevision,
    ) -> anyhow::Result<PolicyRevisionView> {
        let active = self.current();
        if active.guardrail_policies.iter().any(|policy| {
            policy.revision.created_by == "static_config"
                && policy.revision.policy_id == revision.policy_id
        }) {
            anyhow::bail!(
                "guardrail policy id {} is owned by static configuration",
                revision.policy_id
            );
        }
        let secret_registry = ferrogate_secrets::SecretResolverRegistry::from_env();
        build_guardrail_policy_runtime(revision.clone(), &secret_registry)?;
        active
            .repositories
            .insert_guardrail_policy_revision(stored_guardrail_policy_revision(&revision)?)?;
        Ok(PolicyRevisionView {
            revision,
            status: PolicyRevisionStatus::Draft,
        })
    }

    pub(crate) fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        actor: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let stored = active
            .repositories
            .get_guardrail_policy_revision(policy_id, revision)?
            .ok_or_else(|| {
                anyhow::anyhow!("guardrail policy revision {policy_id}@{revision} was not found")
            })?;
        let policy = deserialize_guardrail_policy_revision(&stored)?;
        let secret_registry = ferrogate_secrets::SecretResolverRegistry::from_env();
        build_guardrail_policy_runtime(policy, &secret_registry)?;
        let transition = active.repositories.activate_guardrail_policy_revision(
            policy_id,
            revision,
            actor,
            updated_at_unix,
            rollback_only,
        )?;
        let result = self.reload_process_local((*active.config).clone());
        if !result.committed {
            active.repositories.restore_guardrail_policy_binding(
                policy_id,
                Some(transition.current.generation),
                transition.previous,
            )?;
            anyhow::bail!(
                "guardrail policy binding was restored after runtime reload failed: {}",
                result
                    .reason
                    .as_deref()
                    .unwrap_or("runtime rejected the policy revision")
            );
        }
        Ok(result)
    }

    pub(crate) fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        actor: &str,
        updated_at_unix: u64,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let transition = active.repositories.archive_guardrail_policy_revision(
            policy_id,
            revision,
            actor,
            updated_at_unix,
        )?;
        let result = self.reload_process_local((*active.config).clone());
        if !result.committed {
            active.repositories.restore_guardrail_policy_binding(
                policy_id,
                Some(transition.current.generation),
                transition.previous,
            )?;
            anyhow::bail!(
                "guardrail policy binding was restored after runtime reload failed: {}",
                result
                    .reason
                    .as_deref()
                    .unwrap_or("runtime rejected the archived revision")
            );
        }
        Ok(result)
    }

    pub(crate) fn upsert_plugin_registration(
        &self,
        plugin: crate::config::PluginConfig,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active
                .repositories
                .upsert_control_plane_plugin_registration(
                    plugin.id.clone(),
                    serde_json::to_string(&plugin)?,
                )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            upsert_or_replace_plugin_registration(&mut candidate.plugins, plugin);
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(result)
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_plugin_registration(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active
            .repositories
            .delete_control_plane_plugin_registration(id)?
        {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.plugins.retain(|plugin| plugin.id != id);
            candidate.extensions.retain(|plugin| plugin.id != id);
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_mcp_server(
        &self,
        server: crate::config::McpServerConfig,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_mcp_server(
                server.name.clone(),
                serde_json::to_string(&server)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            upsert_or_replace_mcp_server(&mut candidate.mcp_servers, server);
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(result)
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_mcp_server(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active.repositories.delete_control_plane_mcp_server(name)? {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.mcp_servers.retain(|server| server.name != name);
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_agent_upstream(
        &self,
        upstream: crate::config::AgentUpstreamConfig,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_agent_upstream(
                upstream.id.clone(),
                serde_json::to_string(&upstream)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            upsert_or_replace_agent_upstream(&mut candidate.agent_upstreams, upstream);
            candidate.validate()?;
            Ok(self.reload_process_local(candidate))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_agent_upstream(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active
            .repositories
            .delete_control_plane_agent_upstream(id)?
        {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate
                .agent_upstreams
                .retain(|upstream| upstream.id != id);
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
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

        let next = match active.with_reloaded_config(candidate) {
            Ok(next) => next,
            Err(error) => {
                let outcome = coordinator.reject(reload_candidate, error.to_string());
                return RuntimeReloadResult {
                    active_snapshot: outcome.active.id,
                    candidate_snapshot: outcome.candidate.id,
                    committed: false,
                    mode: RELOAD_MODE_PROCESS_LOCAL,
                    reason: outcome.reason,
                };
            }
        };
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
        let result = (|| {
            active
                .repositories
                .upsert_control_plane_api_key(key.id.clone(), serde_json::to_string(&key)?)?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(result)
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_api_key(&self, id: &str) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active.repositories.delete_control_plane_api_key(id)? {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(Some(result))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_policy(
        &self,
        policy: ConfigPolicyRule,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_policy(
                policy.name.clone(),
                serde_json::to_string(&policy)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(result)
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_policy(&self, name: &str) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active.repositories.delete_control_plane_policy(name)? {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            let result = self.reload_process_local(candidate);
            if result.committed {
                let _ = self.publish_shared_control_plane(&self.current().config)?;
            }
            Ok(Some(result))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_gateway_config(
        &self,
        profile: GatewayConfigProfile,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_gateway_config(
                profile.id.clone(),
                serde_json::to_string(&profile)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(self.reload_process_local(candidate))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_gateway_config(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active
            .repositories
            .delete_control_plane_gateway_config(id)?
        {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_agent_workflow(
        &self,
        workflow: crate::config::AgentWorkflowPolicy,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_agent_workflow(
                workflow_resource_id(&workflow),
                serde_json::to_string(&workflow)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(self.reload_process_local(candidate))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_skill_package(
        &self,
        package: SkillPackage,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_skill_package(
                package.id.clone(),
                serde_json::to_string(&package)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(self.reload_process_local(candidate))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_skill_package(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        if !active.repositories.delete_control_plane_skill_package(id)? {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn delete_agent_workflow(
        &self,
        id: &str,
        version: Option<u32>,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        let Some(workflow) = select_agent_workflow(&active.config.agent_workflows, id, version)
        else {
            return Ok(None);
        };
        let resource_id = workflow_resource_id(workflow);
        if !active
            .repositories
            .delete_control_plane_agent_workflow(&resource_id)?
        {
            return Ok(None);
        }
        let result = (|| {
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn upsert_prompt_template(
        &self,
        template: PromptTemplate,
    ) -> anyhow::Result<RuntimeReloadResult> {
        let active = self.current();
        let result = (|| {
            active.repositories.upsert_control_plane_prompt_template(
                template.id.clone(),
                serde_json::to_string(&template)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(self.reload_process_local(candidate))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn archive_prompt_template(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<RuntimeReloadResult>> {
        let active = self.current();
        let mut template = active
            .config
            .prompt_templates
            .iter()
            .find(|template| template.id == id)
            .cloned();
        let Some(mut template) = template.take() else {
            return Ok(None);
        };
        template.status = PromptTemplateStatus::Archived;
        let result = (|| {
            active.repositories.upsert_control_plane_prompt_template(
                template.id.clone(),
                serde_json::to_string(&template)?,
            )?;
            let mut candidate = (*active.config).clone();
            active.apply_control_plane_snapshot_to_config(&mut candidate)?;
            candidate.validate()?;
            Ok(Some(self.reload_process_local(candidate)))
        })();
        if result.is_err() {
            let _ = active.sync_control_plane_storage_from_config(&active.config);
        }
        result
    }

    pub(crate) fn set_drain(&self, drain: bool) -> DrainStatus {
        let state = self.current();
        state.drain.store(drain, Ordering::Relaxed);
        state.drain_status()
    }
}

const MCP_IDENTITY_ERROR_AUDIT_MAX_IN_FLIGHT: usize = 8;

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
    billing_reporter: Option<Arc<BillingReporter>>,
    repositories: Arc<RuntimeStorageRepositories>,
    durable_api_key_authenticator: Arc<ferrogate_auth::StorageApiKeyAuthenticator>,
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    observability_export: Arc<Mutex<ObservabilityExportRuntime>>,
    analytics_export: Arc<Mutex<ObservabilityExportRuntime>>,
    response_cache: Arc<Mutex<AiResponseCache>>,
    self_hosted_dispatch: Arc<Mutex<SelfHostedWorkerDispatchRuntime>>,
    mcp_manager: Arc<McpManager>,
    mcp_dispatch_permits: Arc<Semaphore>,
    mcp_identity_error_audit_permits: Arc<Semaphore>,
    approvals: ApprovalRegistry,
    access_log_error_limiter: Arc<AccessLogRateLimiter>,
    policy_engine: Arc<BasicPolicyEngine>,
    guardrail_policies: Arc<Vec<GuardrailPolicyRuntime>>,
    guardrail_evidence_permits: Arc<Semaphore>,
    guardrail_evidence_hmac_key: Option<Arc<[u8]>>,
    upstream_counters: Arc<HashMap<String, AtomicU64>>,
    model_route_counter: Arc<AtomicU64>,
    request_ids: Arc<AtomicU64>,
    drain: Arc<AtomicBool>,
    acme_renewal: Option<Arc<SharedAcmeRenewalState>>,
    ip_allowlist: Arc<Vec<IpCidr>>,
    trust_forwarded_for: bool,
    unauthenticated_rate_limit_per_minute: Option<u64>,
    unauth_rate_limiter: Arc<UnauthenticatedIpRateLimiter>,
    /// `Provider.secret_ref` values resolved once at config load/reload time
    /// (issue #163), keyed by provider name. Resolving here (rather than per
    /// request) avoids a live Vault round-trip on every AI request; rotation
    /// propagates on the next `/admin/v1/config/reload`, mirroring how every
    /// other config field already picks up changes.
    resolved_provider_secrets: Arc<HashMap<String, String>>,
}

/// Outcome of [`AppState::check_network_access`]: `Allowed` lets the request
/// proceed to `authenticate()`; the other variants carry enough context to
/// write a 403/429 response and increment the matching metric before any
/// virtual-key/storage lookup happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkAccessDecision {
    Allowed,
    IpDenied,
    RateLimited,
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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ObservabilityStatus {
    pub(crate) provider: String,
    pub(crate) enabled: bool,
    pub(crate) active: bool,
    pub(crate) endpoint: Option<String>,
    pub(crate) endpoint_source: &'static str,
    pub(crate) protocol: &'static str,
    pub(crate) signals: Vec<&'static str>,
    pub(crate) prometheus_metrics_path: String,
    pub(crate) export_timeout_secs: u64,
    pub(crate) health: &'static str,
    pub(crate) last_success_at_unix: Option<u64>,
    pub(crate) last_export_error: Option<String>,
    pub(crate) queue_backpressure_events: u64,
    pub(crate) dropped_events: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AnalyticsStatus {
    pub(crate) provider: String,
    pub(crate) enabled: bool,
    pub(crate) active: bool,
    pub(crate) required: bool,
    pub(crate) mode: &'static str,
    pub(crate) sink_configured: bool,
    pub(crate) signals: Vec<&'static str>,
    pub(crate) export_timeout_secs: u64,
    pub(crate) batch_max_events: usize,
    pub(crate) flush_interval_millis: u64,
    pub(crate) queue_capacity: usize,
    pub(crate) request_log_retention_records: usize,
    pub(crate) audit_event_retention_records: usize,
    pub(crate) billing_event_retention_records: usize,
    pub(crate) health: &'static str,
    pub(crate) last_success_at_unix: Option<u64>,
    pub(crate) last_export_error: Option<String>,
    pub(crate) contract_version: u32,
}

#[derive(Debug, Default, Clone)]
struct ObservabilityExportRuntime {
    last_success_at_unix: Option<u64>,
    last_export_error: Option<String>,
    queue_backpressure_events: u64,
    dropped_events: u64,
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

fn runtime_storage_repositories(config: &Config) -> anyhow::Result<RuntimeStorageRepositories> {
    let storage = &config.storage;
    let control_plane = control_plane_documents_from_config(config);
    let storage_options = |control_plane: ControlPlaneDocuments| RuntimeStorageOptions {
        provider_order: storage.provider_order.clone(),
        required: storage.required,
        initialize_schema: storage.migration_mode == StorageMigrationMode::Auto,
        migration_mode: storage.migration_mode.as_str().into(),
        control_plane,
        request_log_retention_records: config.analytics.request_log_retention_records,
        audit_event_retention_records: config.analytics.audit_event_retention_records,
    };
    if storage.provider == ferrogate_storage::StorageProviderKind::Supabase {
        let dsn = storage_supabase_dsn(storage)?;
        let repositories = RuntimeStorageRepositories::supabase(
            PostgresStorageConfig {
                dsn,
                pool_size: storage.postgres_pool_size,
                pool_acquire_timeout_millis: storage.postgres_pool_acquire_timeout_millis,
                tls_mode: storage.postgres_tls_mode,
                tls_ca_cert_path: storage
                    .postgres_tls_ca_cert_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .map(ToOwned::to_owned),
                connect_timeout_secs: storage.postgres_connect_timeout_secs,
                statement_timeout_millis: storage.postgres_statement_timeout_millis,
                schema: storage
                    .postgres_schema
                    .as_deref()
                    .map(str::trim)
                    .filter(|schema| !schema.is_empty())
                    .map(ToOwned::to_owned),
                search_path: storage
                    .postgres_search_path
                    .iter()
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
            },
            storage_options(control_plane),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        repositories.set_guardrail_evaluation_retention_records(
            config.analytics.guardrail_evaluation_retention_records,
        );
        return Ok(repositories);
    }
    if storage.provider == ferrogate_storage::StorageProviderKind::Postgres {
        let dsn = storage_postgres_dsn(storage)?;
        let repositories = RuntimeStorageRepositories::postgres(
            PostgresStorageConfig {
                dsn,
                pool_size: storage.postgres_pool_size,
                pool_acquire_timeout_millis: storage.postgres_pool_acquire_timeout_millis,
                tls_mode: storage.postgres_tls_mode,
                tls_ca_cert_path: storage
                    .postgres_tls_ca_cert_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .map(ToOwned::to_owned),
                connect_timeout_secs: storage.postgres_connect_timeout_secs,
                statement_timeout_millis: storage.postgres_statement_timeout_millis,
                schema: storage
                    .postgres_schema
                    .as_deref()
                    .map(str::trim)
                    .filter(|schema| !schema.is_empty())
                    .map(ToOwned::to_owned),
                search_path: storage
                    .postgres_search_path
                    .iter()
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
            },
            storage_options(control_plane),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        repositories.set_guardrail_evaluation_retention_records(
            config.analytics.guardrail_evaluation_retention_records,
        );
        return Ok(repositories);
    }
    let backend = RuntimeStorageBackend::new(
        storage.provider,
        storage.required,
        storage.provider_order.clone(),
    )?;
    let repositories = RuntimeStorageRepositories::new(
        backend,
        RuntimeControlPlaneState::from_documents(control_plane),
        config.analytics.request_log_retention_records,
        config.analytics.audit_event_retention_records,
    );
    repositories.set_guardrail_evaluation_retention_records(
        config.analytics.guardrail_evaluation_retention_records,
    );
    Ok(repositories)
}

fn control_plane_documents_from_config(config: &Config) -> ControlPlaneDocuments {
    ControlPlaneDocuments {
        api_keys: serialize_control_plane_documents(&config.api_keys, |key| key.id.clone()),
        tenants: serialize_control_plane_documents(
            &tenant_refs_from_api_keys(&config.api_keys),
            |tenant| tenant.api_key_id.clone(),
        ),
        policies: serialize_control_plane_documents(&config.policies, |policy| policy.name.clone()),
        gateway_configs: serialize_control_plane_documents(&config.gateway_configs, |profile| {
            profile.id.clone()
        }),
        agent_workflows: serialize_control_plane_documents(&config.agent_workflows, |workflow| {
            workflow_resource_id(workflow)
        }),
        skill_packages: serialize_control_plane_documents(&config.skill_packages, |package| {
            package.id.clone()
        }),
        prompt_templates: serialize_control_plane_documents(&config.prompt_templates, |template| {
            template.id.clone()
        }),
        plugin_registrations: serialize_control_plane_documents(
            &config.plugin_registrations(),
            |plugin| plugin.id.clone(),
        ),
        mcp_servers: serialize_control_plane_documents(&config.mcp_servers, |server| {
            server.name.clone()
        }),
        agent_upstreams: serialize_control_plane_documents(&config.agent_upstreams, |upstream| {
            upstream.id.clone()
        }),
    }
}

fn storage_postgres_dsn(storage: &StorageConfig) -> anyhow::Result<String> {
    if let Some(dsn) = storage
        .postgres_dsn
        .as_deref()
        .map(str::trim)
        .filter(|dsn| !dsn.is_empty())
    {
        return Ok(dsn.to_string());
    }
    let env_name = storage
        .postgres_dsn_env
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("field storage.postgres_dsn_env is required"))?;
    let dsn = env::var(env_name).map_err(|_| {
        anyhow::anyhow!(
            "field storage.postgres_dsn_env: environment variable {env_name} is not set"
        )
    })?;
    if dsn.trim().is_empty() {
        anyhow::bail!(
            "field storage.postgres_dsn_env: environment variable {env_name} must not be empty"
        );
    }
    Ok(dsn)
}

fn storage_supabase_dsn(storage: &StorageConfig) -> anyhow::Result<String> {
    let env_name = storage
        .supabase_dsn_env
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("field storage.supabase_dsn_env is required"))?;
    let dsn = env::var(env_name).map_err(|_| {
        anyhow::anyhow!(
            "field storage.supabase_dsn_env: environment variable {env_name} is not set"
        )
    })?;
    if dsn.trim().is_empty() {
        anyhow::bail!(
            "field storage.supabase_dsn_env: environment variable {env_name} must not be empty"
        );
    }
    Ok(dsn)
}

fn serialize_control_plane_documents<T: Serialize>(
    records: &[T],
    id: impl Fn(&T) -> String,
) -> Vec<(String, String)> {
    records
        .iter()
        .filter_map(|record| {
            serde_json::to_string(record)
                .ok()
                .map(|json| (id(record), json))
        })
        .collect()
}

fn deserialize_control_plane_documents<T: for<'de> Deserialize<'de>>(
    records: Vec<String>,
) -> anyhow::Result<Vec<T>> {
    records
        .into_iter()
        .map(|record| serde_json::from_str(&record))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            anyhow::anyhow!("failed to decode control-plane storage document: {error}")
        })
}

fn workflow_resource_id(workflow: &crate::config::AgentWorkflowPolicy) -> String {
    format!("{}@{}", workflow.id, workflow.version)
}

fn record_latest_workflow_node(
    latest: &mut Option<(u64, String)>,
    timestamp: u64,
    node_id: String,
) {
    if latest
        .as_ref()
        .is_none_or(|(latest_timestamp, _)| timestamp >= *latest_timestamp)
    {
        *latest = Some((timestamp, node_id));
    }
}

pub(crate) fn select_agent_workflow<'a>(
    workflows: &'a [crate::config::AgentWorkflowPolicy],
    id: &str,
    version: Option<u32>,
) -> Option<&'a crate::config::AgentWorkflowPolicy> {
    workflows
        .iter()
        .filter(|workflow| workflow.id == id)
        .filter(|workflow| version.is_none_or(|version| workflow.version == version))
        .max_by_key(|workflow| workflow.version)
}

fn tenant_refs_from_api_keys(api_keys: &[ApiKey]) -> Vec<crate::responses::AdminTenantRef> {
    api_keys
        .iter()
        .filter(|key| {
            key.organization_id.is_some()
                || key.team_id.is_some()
                || key.project_id.is_some()
                || key.user_id.is_some()
        })
        .map(|key| crate::responses::AdminTenantRef {
            organization_id: key.organization_id.clone(),
            team_id: key.team_id.clone(),
            project_id: key.project_id.clone(),
            user_id: key.user_id.clone(),
            api_key_id: key.id.clone(),
        })
        .collect()
}

fn apply_tenant_refs_to_api_keys(
    api_keys: &mut [ApiKey],
    tenant_refs: Vec<crate::responses::AdminTenantRef>,
) {
    for tenant in tenant_refs {
        if let Some(key) = api_keys.iter_mut().find(|key| key.id == tenant.api_key_id) {
            key.organization_id = tenant.organization_id;
            key.team_id = tenant.team_id;
            key.project_id = tenant.project_id;
            key.user_id = tenant.user_id;
        }
    }
}

fn upsert_or_replace_plugin_registration(
    plugins: &mut Vec<crate::config::PluginConfig>,
    plugin: crate::config::PluginConfig,
) {
    if let Some(existing) = plugins.iter_mut().find(|existing| existing.id == plugin.id) {
        *existing = plugin;
    } else {
        plugins.push(plugin);
    }
}

fn upsert_or_replace_mcp_server(
    servers: &mut Vec<crate::config::McpServerConfig>,
    server: crate::config::McpServerConfig,
) {
    if let Some(existing) = servers
        .iter_mut()
        .find(|existing| existing.name == server.name)
    {
        *existing = server;
    } else {
        servers.push(server);
    }
}

fn upsert_or_replace_agent_upstream(
    upstreams: &mut Vec<crate::config::AgentUpstreamConfig>,
    upstream: crate::config::AgentUpstreamConfig,
) {
    if let Some(existing) = upstreams
        .iter_mut()
        .find(|existing| existing.id == upstream.id)
    {
        *existing = upstream;
    } else {
        upstreams.push(upstream);
    }
}

fn apply_control_plane_snapshot_to_config_from_repositories(
    repositories: &RuntimeStorageRepositories,
    config: &mut Config,
) -> anyhow::Result<()> {
    let previous_skill_packages = config.skill_packages.clone();
    let snapshot = repositories.control_plane_snapshot()?;
    config.api_keys = deserialize_control_plane_documents(snapshot.api_keys)?;
    let tenant_refs: Vec<crate::responses::AdminTenantRef> =
        deserialize_control_plane_documents(snapshot.tenants)?;
    config.policies = deserialize_control_plane_documents(snapshot.policies)?;
    config.gateway_configs = deserialize_control_plane_documents(snapshot.gateway_configs)?;
    config.agent_workflows = deserialize_control_plane_documents(snapshot.agent_workflows)?;
    config.skill_packages = deserialize_control_plane_documents(snapshot.skill_packages)?;
    config.prompt_templates = deserialize_control_plane_documents(snapshot.prompt_templates)?;
    config.plugins = deserialize_control_plane_documents(snapshot.plugin_registrations)?;
    config.extensions.clear();
    config.mcp_servers = deserialize_control_plane_documents(snapshot.mcp_servers)?;
    config.agent_upstreams = deserialize_control_plane_documents(snapshot.agent_upstreams)?;
    if !tenant_refs.is_empty() {
        apply_tenant_refs_to_api_keys(&mut config.api_keys, tenant_refs);
    }
    config.materialize_skill_package_resources_with_previous(&previous_skill_packages);
    Ok(())
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
    pub(crate) agent_run_id: Option<String>,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) outcome: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
struct GuardrailPolicyRuntime {
    revision: PolicyRevision,
    checks: Vec<GuardrailCheckRuntime>,
}

#[derive(Debug, Clone)]
struct GuardrailCheckRuntime {
    id: String,
    enabled: bool,
    stage: DetectorStage,
    sources: Vec<ferrogate_guardrails::ContentSource>,
    detector_id: String,
    detector_config_digest: String,
    detector: Arc<dyn GuardrailDetector>,
    fallback_detector: Option<Arc<dyn GuardrailDetector>>,
}

#[derive(Debug, Clone)]
pub(crate) struct GuardrailMatch {
    pub(crate) rule_id: String,
    pub(crate) rule_name: String,
    pub(crate) policy_revision: u32,
    pub(crate) check_id: Option<String>,
    pub(crate) effect: GuardrailEffect,
    pub(crate) segment_id: Option<String>,
    pub(crate) byte_start: Option<usize>,
    pub(crate) byte_end: Option<usize>,
    content_patches: Vec<ContentPatch>,
    patch_envelope: Option<GuardrailEnvelope>,
    patch_sources: Vec<ContentSource>,
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamingGuardrailPlan {
    None,
    ShadowAfterComplete,
    BufferAndEnforce,
}

impl GuardrailMatch {
    pub(crate) fn evidence_target(&self) -> String {
        let revision = format!("{}@{}", self.rule_id, self.policy_revision);
        self.check_id
            .as_ref()
            .map(|check_id| format!("{revision}/{check_id}"))
            .unwrap_or(revision)
    }

    pub(crate) fn redact_text(&self, text: &str) -> String {
        if !self.content_patches.is_empty() {
            let result = serde_json::from_str(text).ok().and_then(|document| {
                apply_content_patches_to_document(
                    &document,
                    self.patch_envelope.as_ref()?,
                    &self.patch_sources,
                    &self.content_patches,
                )
                .ok()
            });
            result
                .and_then(|document| serde_json::to_string(&document).ok())
                .unwrap_or_else(|| "[REDACTED]".to_string())
        } else {
            "[REDACTED]".to_string()
        }
    }

    pub(crate) fn evidence_location(&self) -> String {
        match (self.segment_id.as_deref(), self.byte_start, self.byte_end) {
            (Some(segment_id), Some(start), Some(end)) => {
                format!("segment {segment_id} bytes {start}..{end}")
            }
            (Some(segment_id), _, _) => format!("segment {segment_id}"),
            _ => "unlocated content".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuardrailEvaluationContext<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: Option<&'a str>,
    pub(crate) agent_run_id: Option<&'a str>,
    pub(crate) workflow_id: Option<&'a str>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<&'a str>,
    pub(crate) actor_api_key_id: Option<&'a str>,
    pub(crate) tenant: &'a ferrogate_core::TenantContext,
    pub(crate) service_account_id: Option<&'a str>,
    pub(crate) gateway_config_id: Option<&'a str>,
    pub(crate) model: Option<&'a str>,
    pub(crate) provider: Option<&'a str>,
    pub(crate) streaming: bool,
    pub(crate) envelope: &'a GuardrailEnvelope,
    /// `Some` when evaluating a managed MCP/Tool/CLI/etc action (issue #200),
    /// selecting managed-action guardrail policies instead of model-content
    /// ones; `None` for model-content (chat/responses/embeddings) evaluation.
    pub(crate) managed_action: Option<ferrogate_guardrails::ManagedActionContext<'a>>,
}

impl RequestLogExportFilter {
    const DEFAULT_LIMIT: usize = 100;
    const MAX_LIMIT: usize = 1_000;

    pub(crate) fn from_query(query: Option<&str>) -> Self {
        let mut filter = Self {
            organization_id: None,
            project_id: None,
            logical_model: None,
            provider: None,
            status: None,
            since_unix: None,
            until_unix: None,
            limit: Self::DEFAULT_LIMIT,
        };
        let Some(query) = query else {
            return filter;
        };
        for (name, value) in query_pairs(query) {
            match name.as_str() {
                "organization_id" | "tenant" => filter.organization_id = non_empty(value),
                "project_id" | "project" => filter.project_id = non_empty(value),
                "model" | "logical_model" => filter.logical_model = non_empty(value),
                "provider" => filter.provider = non_empty(value),
                "status" | "status_code" => {
                    filter.status = value
                        .parse::<u16>()
                        .ok()
                        .filter(|status| (100..=599).contains(status))
                }
                "since" | "since_unix" => filter.since_unix = value.parse::<u64>().ok(),
                "until" | "until_unix" => filter.until_unix = value.parse::<u64>().ok(),
                "limit" => {
                    filter.limit = value
                        .parse::<usize>()
                        .ok()
                        .map(|limit| limit.clamp(1, Self::MAX_LIMIT))
                        .unwrap_or(filter.limit)
                }
                _ => {}
            }
        }
        filter
    }

    fn matches(&self, log: &StoredRequestLog) -> bool {
        if self
            .organization_id
            .as_ref()
            .is_some_and(|expected| log.tenant.organization_id.as_ref() != Some(expected))
        {
            return false;
        }
        if self
            .project_id
            .as_ref()
            .is_some_and(|expected| log.tenant.project_id.as_ref() != Some(expected))
        {
            return false;
        }
        if self
            .logical_model
            .as_ref()
            .is_some_and(|expected| log.logical_model.as_ref() != Some(expected))
        {
            return false;
        }
        if self
            .provider
            .as_ref()
            .is_some_and(|expected| log.provider.as_ref() != Some(expected))
        {
            return false;
        }
        if self
            .status
            .is_some_and(|expected| log.status_code != expected)
        {
            return false;
        }
        if self.since_unix.is_some_and(|since| {
            log.completed_at_unix
                .or(log.started_at_unix)
                .is_some_and(|timestamp| timestamp < since)
        }) {
            return false;
        }
        if self.until_unix.is_some_and(|until| {
            log.started_at_unix
                .or(log.completed_at_unix)
                .is_some_and(|timestamp| timestamp > until)
        }) {
            return false;
        }
        true
    }
}

impl RequestLogExportRecord {
    fn from_log(log: StoredRequestLog, usage: Option<BillingTokenUsage>) -> Self {
        let latency_ms = log
            .started_at_unix
            .zip(log.completed_at_unix)
            .and_then(|(started, completed)| completed.checked_sub(started))
            .map(|seconds| seconds.saturating_mul(1_000));
        Self {
            object: "request_log_export",
            request_id: log.request_id,
            trace_id: log.trace_id,
            agent_run_id: log.agent_run_id,
            workflow_id: log.workflow_id,
            workflow_version: log.workflow_version,
            workflow_node_id: log.workflow_node_id,
            tenant: log.tenant,
            route: log.route,
            logical_model: log.logical_model,
            provider: log.provider,
            provider_model: log.provider_model,
            status_code: log.status_code,
            error_code: log.error_code,
            usage,
            latency_ms,
            prompt_recorded: log.prompt_recorded,
            response_recorded: log.response_recorded,
            prompt_body: log.prompt_recorded.then_some(log.prompt_body).flatten(),
            response_body: log.response_recorded.then_some(log.response_body).flatten(),
            started_at_unix: log.started_at_unix,
            completed_at_unix: log.completed_at_unix,
        }
    }
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn summarize_agent_run(
    id: String,
    run: Option<&StoredAgentRun>,
    agent_events: &[StoredAgentRunEvent],
    requests: &[StoredRequestLog],
    billing_events: &[BillingEvent],
    audit_events: &[StoredAuditEvent],
) -> AgentRunSummary {
    let tenant = run
        .into_iter()
        .map(|run| run.tenant.clone())
        .chain(agent_events.iter().map(|event| event.tenant.clone()))
        .chain(requests.iter().map(|log| log.tenant.clone()))
        .chain(billing_events.iter().map(|event| event.tenant.clone()))
        .chain(audit_events.iter().map(|event| event.tenant.clone()))
        .next()
        .unwrap_or_default();
    let first_seen_unix = run
        .iter()
        .flat_map(|run| [run.started_at_unix, run.completed_at_unix])
        .chain(agent_events.iter().map(|event| event.occurred_at_unix))
        .chain(
            requests
                .iter()
                .flat_map(|log| [log.started_at_unix, log.completed_at_unix]),
        )
        .chain(billing_events.iter().map(|event| event.occurred_at_unix))
        .chain(audit_events.iter().map(|event| event.occurred_at_unix))
        .flatten()
        .min();
    let last_seen_unix = run
        .iter()
        .flat_map(|run| [run.started_at_unix, run.completed_at_unix])
        .chain(agent_events.iter().map(|event| event.occurred_at_unix))
        .chain(
            requests
                .iter()
                .flat_map(|log| [log.started_at_unix, log.completed_at_unix]),
        )
        .chain(billing_events.iter().map(|event| event.occurred_at_unix))
        .chain(audit_events.iter().map(|event| event.occurred_at_unix))
        .flatten()
        .max();
    let status = if let Some(run) = run {
        match run.status.as_str() {
            "completed" => "completed",
            "failed" | "timed_out" => "failed",
            _ => "blocked",
        }
    } else if requests
        .iter()
        .any(|log| log.status_code >= 500 || log.error_code.is_some())
    {
        "failed"
    } else if requests.iter().any(|log| log.status_code >= 400) {
        "blocked"
    } else {
        "completed"
    };
    AgentRunSummary {
        object: "agent_run",
        id,
        tenant,
        status,
        request_count: requests.len(),
        billing_event_count: billing_events.len(),
        audit_event_count: audit_events.len(),
        agent_event_count: agent_events.len(),
        first_seen_unix,
        last_seen_unix,
    }
}

fn query_pairs(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.split('&').filter_map(|part| {
        let (name, value) = part.split_once('=')?;
        Some((name.to_string(), value.to_string()))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminPagination {
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelfHostedWorkerEventStreamQuery {
    pub(crate) after_event_id: Option<String>,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminPage<T> {
    pub(crate) data: Vec<T>,
    pub(crate) total: usize,
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AgentRunFilter {
    pub(crate) organization_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) api_key_id: Option<String>,
    pub(crate) request_id: Option<String>,
}

impl AgentRunFilter {
    pub(crate) fn from_query(query: Option<&str>) -> Self {
        let mut filter = Self::default();
        let Some(query) = query else {
            return filter;
        };
        for (name, value) in query_pairs(query) {
            match name.as_str() {
                "organization_id" | "tenant" => filter.organization_id = non_empty(value),
                "project_id" | "project" => filter.project_id = non_empty(value),
                "api_key_id" | "api_key" => filter.api_key_id = non_empty(value),
                "request_id" => filter.request_id = non_empty(value),
                _ => {}
            }
        }
        filter
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsageReportGroupBy {
    /// Aggregate every period_month into one row per (scope_type, scope_id).
    Scope,
    /// Aggregate every scope into one row per period_month.
    PeriodMonth,
    /// Aggregate every period_month into one row per distinct value of the
    /// given metadata key (issue #171), e.g. `group_by=metadata.customer_id`
    /// returns one row per distinct `customer_id` value ever seen. Sourced
    /// from `usage_metadata_rollups`, not `usage_monthly_rollups` -- an
    /// entirely separate aggregation dimension from the built-in scope
    /// chain, not a further breakdown of it.
    Metadata(String),
}

/// Query filter for the P1-4 `/admin/v1/usage-reports` surface, built on top
/// of the `usage_monthly_rollups` table populated alongside every settled
/// billing event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UsageReportFilter {
    pub(crate) scope_type: Option<QuotaScopeKind>,
    pub(crate) scope_id: Option<String>,
    pub(crate) from_month: Option<String>,
    pub(crate) to_month: Option<String>,
    pub(crate) group_by: Option<UsageReportGroupBy>,
}

impl UsageReportFilter {
    pub(crate) fn from_query(query: Option<&str>) -> Self {
        let mut filter = Self::default();
        let Some(query) = query else {
            return filter;
        };
        for (name, value) in query_pairs(query) {
            match name.as_str() {
                "scope_type" => filter.scope_type = QuotaScopeKind::from_str_opt(&value),
                "scope_id" => filter.scope_id = non_empty(value),
                "period_month" => {
                    if let Some(month) = non_empty(value) {
                        filter.from_month = Some(month.clone());
                        filter.to_month = Some(month);
                    }
                }
                "from_month" => filter.from_month = non_empty(value),
                "to_month" => filter.to_month = non_empty(value),
                "group_by" => {
                    filter.group_by = match value.as_str() {
                        "scope" => Some(UsageReportGroupBy::Scope),
                        "period_month" | "month" => Some(UsageReportGroupBy::PeriodMonth),
                        other => other
                            .strip_prefix("metadata.")
                            .map(str::trim)
                            .filter(|key| !key.is_empty())
                            .map(|key| UsageReportGroupBy::Metadata(key.to_string())),
                    }
                }
                _ => {}
            }
        }
        filter
    }

    fn matches(&self, rollup: &StoredUsageMonthlyRollup) -> bool {
        if let Some(scope_type) = self.scope_type {
            if rollup.scope_type != scope_type {
                return false;
            }
        }
        if let Some(scope_id) = &self.scope_id {
            if &rollup.scope_id != scope_id {
                return false;
            }
        }
        if let Some(from_month) = &self.from_month {
            if rollup.period_month < *from_month {
                return false;
            }
        }
        if let Some(to_month) = &self.to_month {
            if rollup.period_month > *to_month {
                return false;
            }
        }
        true
    }
}

fn usage_report_row_raw(rollup: StoredUsageMonthlyRollup) -> crate::responses::AdminUsageReportRow {
    crate::responses::AdminUsageReportRow {
        period_month: Some(rollup.period_month),
        scope_type: Some(rollup.scope_type.as_str().to_string()),
        scope_id: Some(rollup.scope_id),
        metadata_key: None,
        metadata_value: None,
        prompt_tokens: rollup.prompt_tokens,
        completion_tokens: rollup.completion_tokens,
        total_tokens: rollup.total_tokens,
        cost_usd: rollup.cost_usd,
        request_count: rollup.request_count,
        error_count: rollup.error_count,
    }
}

fn usage_report_row_zero(
    scope_type: Option<QuotaScopeKind>,
    scope_id: Option<&str>,
    period_month: Option<&str>,
) -> crate::responses::AdminUsageReportRow {
    crate::responses::AdminUsageReportRow {
        period_month: period_month.map(ToOwned::to_owned),
        scope_type: scope_type.map(|scope_type| scope_type.as_str().to_string()),
        scope_id: scope_id.map(ToOwned::to_owned),
        metadata_key: None,
        metadata_value: None,
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
        cost_usd: 0.0,
        request_count: 0,
        error_count: 0,
    }
}

fn usage_metadata_report_row_zero(
    metadata_key: &str,
    metadata_value: &str,
) -> crate::responses::AdminUsageReportRow {
    crate::responses::AdminUsageReportRow {
        period_month: None,
        scope_type: None,
        scope_id: None,
        metadata_key: Some(metadata_key.to_string()),
        metadata_value: Some(metadata_value.to_string()),
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
        cost_usd: 0.0,
        request_count: 0,
        error_count: 0,
    }
}

fn accumulate_usage_report_row(
    row: &mut crate::responses::AdminUsageReportRow,
    rollup: &StoredUsageMonthlyRollup,
) {
    row.prompt_tokens += rollup.prompt_tokens;
    row.completion_tokens += rollup.completion_tokens;
    row.total_tokens += rollup.total_tokens;
    row.cost_usd += rollup.cost_usd;
    row.request_count += rollup.request_count;
    row.error_count += rollup.error_count;
}

fn agent_run_matches_filter(
    request_id: &str,
    tenant: &ferrogate_core::TenantContext,
    filter: &AgentRunFilter,
) -> bool {
    if filter
        .organization_id
        .as_ref()
        .is_some_and(|expected| tenant.organization_id.as_ref() != Some(expected))
    {
        return false;
    }
    if filter
        .project_id
        .as_ref()
        .is_some_and(|expected| tenant.project_id.as_ref() != Some(expected))
    {
        return false;
    }
    if filter
        .api_key_id
        .as_ref()
        .is_some_and(|expected| tenant.api_key_id.as_ref() != Some(expected))
    {
        return false;
    }
    if filter
        .request_id
        .as_ref()
        .is_some_and(|expected| request_id != expected)
    {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestLogExportFilter {
    pub(crate) organization_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) logical_model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) status: Option<u16>,
    pub(crate) since_unix: Option<u64>,
    pub(crate) until_unix: Option<u64>,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RequestLogExportRecord {
    pub(crate) object: &'static str,
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) agent_run_id: Option<String>,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) route: Option<String>,
    pub(crate) logical_model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) provider_model: Option<String>,
    pub(crate) status_code: u16,
    pub(crate) error_code: Option<String>,
    pub(crate) usage: Option<BillingTokenUsage>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) prompt_recorded: bool,
    pub(crate) response_recorded: bool,
    pub(crate) prompt_body: Option<String>,
    pub(crate) response_body: Option<String>,
    pub(crate) started_at_unix: Option<u64>,
    pub(crate) completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GuardrailEvidenceFilter {
    pub(crate) tenant_id: Option<String>,
    pub(crate) request_id: Option<String>,
    pub(crate) trace_id: Option<String>,
    pub(crate) agent_run_id: Option<String>,
    pub(crate) scope_type: Option<String>,
    pub(crate) scope_id: Option<String>,
    pub(crate) subject_id: Option<String>,
    pub(crate) policy_id: Option<String>,
    pub(crate) policy_revision: Option<u32>,
    pub(crate) detector_id: Option<String>,
    pub(crate) category: Option<String>,
    pub(crate) verdict: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) error_kind: Option<String>,
    pub(crate) since_unix: Option<u64>,
    pub(crate) until_unix: Option<u64>,
}

impl GuardrailEvidenceFilter {
    pub(crate) fn from_query(query: Option<&str>) -> Self {
        let mut filter = Self::default();
        let Some(query) = query else {
            return filter;
        };
        for (name, value) in query_pairs(query) {
            match name.as_str() {
                "tenant" | "tenant_id" | "organization_id" => filter.tenant_id = non_empty(value),
                "request_id" => filter.request_id = non_empty(value),
                "trace_id" => filter.trace_id = non_empty(value),
                "agent_run_id" => filter.agent_run_id = non_empty(value),
                "scope_type" => filter.scope_type = non_empty(value),
                "scope_id" => filter.scope_id = non_empty(value),
                "subject" | "subject_id" => filter.subject_id = non_empty(value),
                "policy" | "policy_id" => filter.policy_id = non_empty(value),
                "policy_revision" | "revision" => {
                    filter.policy_revision = value.parse::<u32>().ok().filter(|value| *value > 0)
                }
                "detector" | "detector_id" => filter.detector_id = non_empty(value),
                "category" => filter.category = non_empty(value),
                "verdict" => filter.verdict = non_empty(value),
                "action" => filter.action = non_empty(value),
                "error" | "error_kind" => filter.error_kind = non_empty(value),
                "since" | "since_unix" => filter.since_unix = value.parse::<u64>().ok(),
                "until" | "until_unix" => filter.until_unix = value.parse::<u64>().ok(),
                _ => {}
            }
        }
        filter
    }

    fn has_investigation_selector(&self) -> bool {
        self.request_id.is_some() || self.trace_id.is_some() || self.agent_run_id.is_some()
    }

    fn storage_query(&self, offset: usize, limit: usize) -> GuardrailEvaluationQuery {
        GuardrailEvaluationQuery {
            tenant_id: self.tenant_id.clone(),
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            agent_run_id: self.agent_run_id.clone(),
            scope_type: self.scope_type.clone(),
            scope_id: self.scope_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_id: self.policy_id.clone(),
            policy_revision: self.policy_revision,
            detector_id: self.detector_id.clone(),
            category: self.category.clone(),
            verdict: self.verdict.clone(),
            action: self.action.clone(),
            error_kind: self.error_kind.clone(),
            since_unix: self.since_unix,
            until_unix: self.until_unix,
            offset,
            limit,
        }
    }

    #[cfg(test)]
    fn matches(
        &self,
        evaluation: &StoredGuardrailEvaluation,
        checks: &[StoredGuardrailCheckEvaluation],
    ) -> bool {
        if self
            .tenant_id
            .as_ref()
            .is_some_and(|expected| evaluation.tenant.organization_id.as_ref() != Some(expected))
            || self
                .request_id
                .as_ref()
                .is_some_and(|expected| &evaluation.request_id != expected)
            || self
                .trace_id
                .as_ref()
                .is_some_and(|expected| evaluation.trace_id.as_ref() != Some(expected))
            || self
                .agent_run_id
                .as_ref()
                .is_some_and(|expected| evaluation.agent_run_id.as_ref() != Some(expected))
            || self
                .scope_type
                .as_ref()
                .is_some_and(|expected| &evaluation.scope_type != expected)
            || self
                .scope_id
                .as_ref()
                .is_some_and(|expected| &evaluation.scope_id != expected)
            || self
                .subject_id
                .as_ref()
                .is_some_and(|expected| evaluation.subject_id.as_ref() != Some(expected))
            || self
                .policy_id
                .as_ref()
                .is_some_and(|expected| &evaluation.policy_id != expected)
            || self
                .policy_revision
                .is_some_and(|expected| evaluation.policy_revision != expected)
            || self
                .verdict
                .as_ref()
                .is_some_and(|expected| &evaluation.verdict != expected)
            || self
                .action
                .as_ref()
                .is_some_and(|expected| &evaluation.action != expected)
            || self
                .since_unix
                .is_some_and(|since| evaluation.occurred_at_unix < since)
            || self
                .until_unix
                .is_some_and(|until| evaluation.occurred_at_unix > until)
        {
            return false;
        }
        if self.detector_id.is_none() && self.category.is_none() && self.error_kind.is_none() {
            return true;
        }
        checks.iter().any(|check| {
            self.detector_id
                .as_ref()
                .is_none_or(|expected| &check.detector_id == expected)
                && self
                    .category
                    .as_ref()
                    .is_none_or(|expected| check.finding_category_counts.contains_key(expected))
                && self
                    .error_kind
                    .as_ref()
                    .is_none_or(|expected| check.error_kind.as_ref() == Some(expected))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GuardrailEvaluationView {
    #[serde(flatten)]
    pub(crate) evaluation: StoredGuardrailEvaluation,
    pub(crate) checks: Vec<StoredGuardrailCheckEvaluation>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InvestigationRequestEvidence {
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) agent_run_id: Option<String>,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) route: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) logical_model: Option<String>,
    pub(crate) provider_model: Option<String>,
    pub(crate) status_code: u16,
    pub(crate) error_code: Option<String>,
    pub(crate) cache_status: Option<String>,
    pub(crate) started_at_unix: Option<u64>,
    pub(crate) completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InvestigationApprovalEvidence {
    pub(crate) id: String,
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) tool_name: String,
    pub(crate) server_name: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) status: ApprovalStatus,
    pub(crate) reviewer_api_key_id: Option<String>,
    pub(crate) reviewer_authority: Option<String>,
    pub(crate) terminal_reason: Option<String>,
    pub(crate) requested_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) decided_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InvestigationBillingEvidence {
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) agent_run_id: Option<String>,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) logical_model: String,
    pub(crate) provider: String,
    pub(crate) provider_model: String,
    pub(crate) usage: BillingTokenUsage,
    pub(crate) status_code: u16,
    pub(crate) occurred_at_unix: Option<u64>,
    pub(crate) cost_usd: Option<f64>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) wallet_delta_credits: Option<i64>,
    pub(crate) wallet_balance_after_credits: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GuardrailInvestigationTimeline {
    pub(crate) object: &'static str,
    pub(crate) selector: String,
    pub(crate) identity: Option<ferrogate_core::TenantContext>,
    pub(crate) agent_runs: Vec<StoredAgentRun>,
    pub(crate) agent_events: Vec<StoredAgentRunEvent>,
    pub(crate) requests: Vec<InvestigationRequestEvidence>,
    pub(crate) guardrail_evaluations: Vec<GuardrailEvaluationView>,
    pub(crate) audit_events: Vec<StoredAuditEvent>,
    pub(crate) approvals: Vec<InvestigationApprovalEvidence>,
    pub(crate) billing_events: Vec<InvestigationBillingEvidence>,
    pub(crate) total_cost_usd: f64,
    pub(crate) final_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AgentRunSummary {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) status: &'static str,
    pub(crate) request_count: usize,
    pub(crate) billing_event_count: usize,
    pub(crate) audit_event_count: usize,
    pub(crate) agent_event_count: usize,
    pub(crate) first_seen_unix: Option<u64>,
    pub(crate) last_seen_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct AgentRunTimeline {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) run: Option<StoredAgentRun>,
    pub(crate) summary: AgentRunSummary,
    pub(crate) agent_events: Vec<StoredAgentRunEvent>,
    pub(crate) requests: Vec<StoredRequestLog>,
    pub(crate) billing_events: Vec<BillingEvent>,
    pub(crate) audit_events: Vec<StoredAuditEvent>,
}

#[derive(Debug, Default)]
struct GatewayMetricsAccumulator {
    request_log_total: u64,
    request_error_total: u64,
    request_status_totals: BTreeMap<u16, u64>,
    cache_hits_total: u64,
    cache_misses_total: u64,
    guardrail_match_total: u64,
    guardrail_denial_total: u64,
    guardrail_redaction_total: u64,
    guardrail_detector_error_total: u64,
    guardrail_evaluation_total: u64,
    guardrail_evaluation_fail_total: u64,
    guardrail_evaluation_error_total: u64,
    guardrail_evaluation_shadow_total: u64,
    guardrail_evidence_persistence_failure_total: u64,
    guardrail_policy_cas_conflict_total: u64,
    billing_event_total: u64,
    /// Failures durably enqueueing a settled usage event for delivery to the
    /// billing service (issue #151).
    billing_report_enqueue_failure_total: u64,
    token_totals: TokenMetricTotals,
    model_provider_totals: BTreeMap<(String, String), ModelProviderMetricTotal>,
    tool_call_total: u64,
    tool_latency_ms_total: u64,
    mcp_identity_resolution_total: u64,
    mcp_identity_failure_total: u64,
    mcp_identity_refresh_total: u64,
    mcp_identity_revocation_total: u64,
    mcp_refresh_response_deadline_total: u64,
    mcp_refresh_storage_cancellation_total: u64,
    mcp_refresh_storage_outcome_unknown_total: u64,
    mcp_refresh_late_reconciliation_total: u64,
    mcp_identity_error_audit_deadline_total: u64,
    /// Requests rejected pre-authentication for not matching a configured
    /// `network_access.ip_allowlist` (issue #166).
    network_access_denied_total: u64,
    /// Requests rejected pre-authentication for exceeding
    /// `network_access.unauthenticated_rate_limit_per_minute` (issue #166).
    network_access_rate_limited_total: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayConfigUse {
    pub(crate) id: String,
    pub(crate) revision: u32,
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GatewayConfigResolveError {
    NotFound(String),
    Disabled { id: String, revision: u32 },
    NotAllowed { id: String, revision: u32 },
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

impl SelfHostedWorkerEventStreamQuery {
    fn from_query(query: Option<&str>, default_limit: usize, max_limit: usize) -> Self {
        let mut after_event_id = None;
        let mut limit = default_limit;
        if let Some(query) = query {
            for (name, value) in query.split('&').filter_map(|part| part.split_once('=')) {
                match name {
                    "after_event_id" if !value.trim().is_empty() => {
                        after_event_id = Some(value.trim().to_string());
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
        Self {
            after_event_id,
            limit,
        }
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

    fn record_billing_report_enqueue_failure(&mut self) {
        self.billing_report_enqueue_failure_total =
            self.billing_report_enqueue_failure_total.saturating_add(1);
    }

    fn record_cache_hit(&mut self) {
        self.cache_hits_total = self.cache_hits_total.saturating_add(1);
    }

    fn record_cache_miss(&mut self) {
        self.cache_misses_total = self.cache_misses_total.saturating_add(1);
    }

    fn record_guardrail_match(&mut self, effect: GuardrailEffect) {
        self.guardrail_match_total = self.guardrail_match_total.saturating_add(1);
        match effect {
            GuardrailEffect::Deny => {
                self.guardrail_denial_total = self.guardrail_denial_total.saturating_add(1);
            }
            GuardrailEffect::Redact => {
                self.guardrail_redaction_total = self.guardrail_redaction_total.saturating_add(1);
            }
        }
    }

    fn record_guardrail_detector_error(&mut self) {
        self.guardrail_detector_error_total = self.guardrail_detector_error_total.saturating_add(1);
    }

    fn record_guardrail_evaluation(&mut self, verdict: &str, enforcement_status: &str) {
        self.guardrail_evaluation_total = self.guardrail_evaluation_total.saturating_add(1);
        if verdict == "fail" {
            self.guardrail_evaluation_fail_total =
                self.guardrail_evaluation_fail_total.saturating_add(1);
        } else if verdict == "error" {
            self.guardrail_evaluation_error_total =
                self.guardrail_evaluation_error_total.saturating_add(1);
        }
        if matches!(enforcement_status, "shadow_only" | "not_enforced") {
            self.guardrail_evaluation_shadow_total =
                self.guardrail_evaluation_shadow_total.saturating_add(1);
        }
    }

    fn record_guardrail_evidence_persistence_failure(&mut self) {
        self.guardrail_evidence_persistence_failure_total = self
            .guardrail_evidence_persistence_failure_total
            .saturating_add(1);
    }

    fn record_guardrail_policy_cas_conflict(&mut self) {
        self.guardrail_policy_cas_conflict_total =
            self.guardrail_policy_cas_conflict_total.saturating_add(1);
    }

    fn record_tool_call(&mut self, _tool_name: &str, latency_ms: u64) {
        self.tool_call_total = self.tool_call_total.saturating_add(1);
        self.tool_latency_ms_total = self.tool_latency_ms_total.saturating_add(latency_ms);
    }

    fn record_mcp_identity_resolution(&mut self, allowed: bool) {
        self.mcp_identity_resolution_total = self.mcp_identity_resolution_total.saturating_add(1);
        if !allowed {
            self.mcp_identity_failure_total = self.mcp_identity_failure_total.saturating_add(1);
        }
    }

    fn record_mcp_identity_refresh(&mut self) {
        self.mcp_identity_refresh_total = self.mcp_identity_refresh_total.saturating_add(1);
    }

    fn record_mcp_identity_revocation(&mut self) {
        self.mcp_identity_revocation_total = self.mcp_identity_revocation_total.saturating_add(1);
    }

    fn record_mcp_refresh_response_deadline(&mut self) {
        self.mcp_refresh_response_deadline_total =
            self.mcp_refresh_response_deadline_total.saturating_add(1);
    }

    fn record_mcp_refresh_storage_cancellation(&mut self) {
        self.mcp_refresh_storage_cancellation_total = self
            .mcp_refresh_storage_cancellation_total
            .saturating_add(1);
    }

    fn record_mcp_refresh_storage_outcome_unknown(&mut self) {
        self.mcp_refresh_storage_outcome_unknown_total = self
            .mcp_refresh_storage_outcome_unknown_total
            .saturating_add(1);
    }

    fn record_mcp_refresh_late_reconciliation(&mut self) {
        self.mcp_refresh_late_reconciliation_total =
            self.mcp_refresh_late_reconciliation_total.saturating_add(1);
    }

    fn record_mcp_identity_error_audit_deadline(&mut self) {
        self.mcp_identity_error_audit_deadline_total = self
            .mcp_identity_error_audit_deadline_total
            .saturating_add(1);
    }

    fn record_network_access_decision(&mut self, decision: NetworkAccessDecision) {
        match decision {
            NetworkAccessDecision::Allowed => {}
            NetworkAccessDecision::IpDenied => {
                self.network_access_denied_total =
                    self.network_access_denied_total.saturating_add(1);
            }
            NetworkAccessDecision::RateLimited => {
                self.network_access_rate_limited_total =
                    self.network_access_rate_limited_total.saturating_add(1);
            }
        }
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
            guardrail_match_total: self.guardrail_match_total,
            guardrail_denial_total: self.guardrail_denial_total,
            guardrail_redaction_total: self.guardrail_redaction_total,
            guardrail_detector_error_total: self.guardrail_detector_error_total,
            guardrail_evaluation_total: self.guardrail_evaluation_total,
            guardrail_evaluation_fail_total: self.guardrail_evaluation_fail_total,
            guardrail_evaluation_error_total: self.guardrail_evaluation_error_total,
            guardrail_evaluation_shadow_total: self.guardrail_evaluation_shadow_total,
            guardrail_evidence_persistence_failure_total: self
                .guardrail_evidence_persistence_failure_total,
            guardrail_policy_cas_conflict_total: self.guardrail_policy_cas_conflict_total,
            billing_event_total: self.billing_event_total,
            billing_report_enqueue_failure_total: self.billing_report_enqueue_failure_total,
            tool_call_total: self.tool_call_total,
            tool_latency_ms_total: self.tool_latency_ms_total,
            mcp_identity_resolution_total: self.mcp_identity_resolution_total,
            mcp_identity_failure_total: self.mcp_identity_failure_total,
            mcp_identity_refresh_total: self.mcp_identity_refresh_total,
            mcp_identity_revocation_total: self.mcp_identity_revocation_total,
            mcp_refresh_response_deadline_total: self.mcp_refresh_response_deadline_total,
            mcp_refresh_storage_cancellation_total: self.mcp_refresh_storage_cancellation_total,
            mcp_refresh_storage_outcome_unknown_total: self
                .mcp_refresh_storage_outcome_unknown_total,
            mcp_refresh_late_reconciliation_total: self.mcp_refresh_late_reconciliation_total,
            mcp_identity_error_audit_deadline_total: self.mcp_identity_error_audit_deadline_total,
            postgres_pool_acquire_total: 0,
            postgres_pool_acquire_timeout_total: 0,
            postgres_pool_acquire_wait_micros_total: 0,
            token_totals: self.token_totals.clone(),
            model_provider_totals: self.model_provider_totals.values().cloned().collect(),
            network_access_denied_total: self.network_access_denied_total,
            network_access_rate_limited_total: self.network_access_rate_limited_total,
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

fn latest_self_hosted_heartbeat(
    heartbeats: &[StoredSelfHostedWorkerHeartbeat],
    worker_id: &str,
) -> Option<StoredSelfHostedWorkerHeartbeat> {
    heartbeats
        .iter()
        .filter(|heartbeat| heartbeat.worker_id == worker_id)
        .max_by(|left, right| {
            left.reported_at_unix
                .cmp(&right.reported_at_unix)
                .then_with(|| left.id.cmp(&right.id))
        })
        .cloned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelfHostedWorkerRecordError {
    InvalidRequest(String),
    NotFound(String),
    Storage(String),
}

impl std::fmt::Display for SelfHostedWorkerRecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelfHostedWorkerRecordError::InvalidRequest(message) => {
                write!(formatter, "{message}")
            }
            SelfHostedWorkerRecordError::NotFound(message) => write!(formatter, "{message}"),
            SelfHostedWorkerRecordError::Storage(message) => write!(formatter, "{message}"),
        }
    }
}

fn validate_self_hosted_registration_request(
    request: &crate::responses::AdminSelfHostedWorkerRegistrationRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("workspace_id", &request.workspace_id)?;
    require_self_hosted_field("worker_name", &request.worker_name)?;
    require_self_hosted_field("identity_fingerprint", &request.identity_fingerprint)?;
    if !request
        .capability_envelope_json
        .as_deref()
        .unwrap_or("{}")
        .trim()
        .is_empty()
        && serde_json::from_str::<serde_json::Value>(
            request.capability_envelope_json.as_deref().unwrap_or("{}"),
        )
        .is_err()
    {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(
            "capability_envelope_json must be valid JSON when provided".into(),
        ));
    }
    Ok(())
}

fn validate_self_hosted_rotate_request(
    request: &crate::responses::AdminSelfHostedWorkerRotateRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("identity_fingerprint", &request.identity_fingerprint)?;
    Ok(())
}

fn validate_self_hosted_heartbeat_request(
    request: &crate::responses::AdminSelfHostedWorkerHeartbeatRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("status", &request.status)?;
    if !request
        .heartbeat_json
        .as_deref()
        .unwrap_or("{}")
        .trim()
        .is_empty()
        && serde_json::from_str::<serde_json::Value>(
            request.heartbeat_json.as_deref().unwrap_or("{}"),
        )
        .is_err()
    {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(
            "heartbeat_json must be valid JSON when provided".into(),
        ));
    }
    Ok(())
}

fn validate_self_hosted_telemetry_event_request(
    request: &crate::responses::AdminSelfHostedWorkerTelemetryEventRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("session_id", &request.session_id)?;
    require_self_hosted_field("run_id", &request.run_id)?;
    require_self_hosted_field("kind", &request.kind)?;
    let kind = request.kind.trim();
    if !matches!(
        kind,
        "lifecycle"
            | "log"
            | "tool_call"
            | "mcp_call"
            | "cli_command"
            | "skill_invocation"
            | "artifact"
            | "checkpoint"
            | "usage"
    ) {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
            "kind must be one of lifecycle, log, tool_call, mcp_call, cli_command, skill_invocation, artifact, checkpoint, usage; got {kind}"
        )));
    }
    if !request
        .event_json
        .as_deref()
        .unwrap_or("{}")
        .trim()
        .is_empty()
        && serde_json::from_str::<serde_json::Value>(request.event_json.as_deref().unwrap_or("{}"))
            .is_err()
    {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(
            "event_json must be valid JSON when provided".into(),
        ));
    }
    Ok(())
}

fn self_hosted_lifecycle_state_from_json(event_json: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(event_json).ok()?;
    value
        .get("state")
        .or_else(|| value.get("status"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn validate_self_hosted_artifact_request(
    request: &crate::responses::AdminSelfHostedWorkerArtifactRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("artifact_id", &request.artifact_id)?;
    require_self_hosted_field("session_id", &request.session_id)?;
    require_self_hosted_field("run_id", &request.run_id)?;
    require_self_hosted_field("artifact_name", &request.artifact_name)?;
    if let Some(content_type) = request.content_type.as_deref() {
        if content_type.trim().is_empty() {
            return Err(SelfHostedWorkerRecordError::InvalidRequest(
                "content_type must not be empty when provided".into(),
            ));
        }
    }
    if request.size_bytes > SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
            "size_bytes must be less than or equal to {SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES}"
        )));
    }
    if !request
        .artifact_json
        .as_deref()
        .unwrap_or("{}")
        .trim()
        .is_empty()
        && serde_json::from_str::<serde_json::Value>(
            request.artifact_json.as_deref().unwrap_or("{}"),
        )
        .is_err()
    {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(
            "artifact_json must be valid JSON when provided".into(),
        ));
    }
    Ok(())
}

fn validate_self_hosted_checkpoint_request(
    request: &crate::responses::AdminSelfHostedWorkerCheckpointRequest,
) -> Result<(), SelfHostedWorkerRecordError> {
    require_self_hosted_field("checkpoint_id", &request.checkpoint_id)?;
    require_self_hosted_field("session_id", &request.session_id)?;
    require_self_hosted_field("run_id", &request.run_id)?;
    require_self_hosted_field("checkpoint_name", &request.checkpoint_name)?;
    if request.size_bytes > SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
            "size_bytes must be less than or equal to {SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES}"
        )));
    }
    if !request
        .checkpoint_json
        .as_deref()
        .unwrap_or("{}")
        .trim()
        .is_empty()
        && serde_json::from_str::<serde_json::Value>(
            request.checkpoint_json.as_deref().unwrap_or("{}"),
        )
        .is_err()
    {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(
            "checkpoint_json must be valid JSON when provided".into(),
        ));
    }
    Ok(())
}

fn require_self_hosted_field(field: &str, value: &str) -> Result<(), SelfHostedWorkerRecordError> {
    if value.trim().is_empty() {
        return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn next_self_hosted_worker_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("self-hosted-worker-{nanos}-{}", std::process::id())
}

fn next_self_hosted_heartbeat_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("self-hosted-heartbeat-{nanos}-{}", std::process::id())
}

fn next_self_hosted_telemetry_event_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("self-hosted-event-{nanos}-{}", std::process::id())
}

fn self_hosted_worker_stale_state(
    last_seen_at_unix: Option<u64>,
    now_unix: Option<u64>,
) -> (bool, Option<u64>) {
    let stale_after_unix =
        last_seen_at_unix.map(|seen| seen.saturating_add(SELF_HOSTED_WORKER_STALE_THRESHOLD_SECS));
    let stale = match (stale_after_unix, now_unix) {
        (Some(stale_after), Some(now)) => now > stale_after,
        _ => false,
    };
    (stale, stale_after_unix)
}

#[derive(Debug, Default)]
struct SelfHostedWorkerDispatchRuntime {
    registry: SelfHostedWorkerRegistry,
    queue: InMemorySelfHostedRunQueue,
}

impl SelfHostedWorkerDispatchRuntime {
    fn register_worker(
        &mut self,
        registration: &StoredSelfHostedWorkerRegistration,
    ) -> Result<(), SelfHostedWorkerError> {
        let capabilities =
            self_hosted_capabilities_from_envelope(&registration.capability_envelope_json);
        let identity = self_hosted_worker_runtime_identity(registration);
        match self.registry.register(SelfHostedWorkerRegistration {
            tenant_id: self_hosted_tenant_id(&registration.tenant),
            workspace_id: registration.workspace_id.clone(),
            worker_id: registration.id.clone(),
            framework_adapter: self_hosted_framework_adapter(
                &registration.capability_envelope_json,
            ),
            token_id: identity.token_id,
            token_secret: identity.token_secret,
            identity_expires_at_unix: registration.identity_expires_at_unix,
            capabilities: capabilities.clone(),
        }) {
            Ok(_) | Err(SelfHostedWorkerError::DuplicateWorker(_)) => {}
            Err(error) => return Err(error),
        }
        self.seed_run(registration, capabilities)
    }

    fn rebuild_registries(
        &mut self,
        registrations: Vec<StoredSelfHostedWorkerRegistration>,
        dispatches: Vec<StoredSelfHostedRunDispatch>,
    ) -> Result<(), SelfHostedWorkerError> {
        let mut next = Self::default();
        next.queue.restore_runs(
            dispatches
                .into_iter()
                .map(self_hosted_queue_record_from_storage)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        for registration in registrations {
            next.register_worker(&registration)?;
        }
        *self = next;
        Ok(())
    }

    fn storage_records(&self) -> Vec<StoredSelfHostedRunDispatch> {
        self.queue
            .run_records()
            .into_iter()
            .map(self_hosted_queue_record_to_storage)
            .collect()
    }

    fn poll_run(
        &mut self,
        request: SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError> {
        self.queue.poll_run(&self.registry, request)
    }

    fn ack_run(
        &mut self,
        request: SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError> {
        self.queue.ack_run(&self.registry, request)
    }

    fn validate_worker_identity(
        &self,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<(), SelfHostedWorkerError> {
        let mut observed_identity = identity.clone();
        // Security (#113): identity expiry must be judged against the server's
        // trusted clock. A client-supplied observed_at_unix (e.g. Some(0)) must
        // never satisfy the expiry check, so overwrite it unconditionally.
        observed_identity.observed_at_unix = now_unix_seconds();
        self.registry
            .validate_identity(&observed_identity)
            .map(|_| ())
    }

    fn seed_run(
        &mut self,
        registration: &StoredSelfHostedWorkerRegistration,
        capabilities: Vec<String>,
    ) -> Result<(), SelfHostedWorkerError> {
        if !registration.orchestration_enabled {
            return Ok(());
        }
        let dispatch_id = self_hosted_seed_dispatch_id(&registration.id);
        let required_capabilities = capabilities
            .iter()
            .find(|capability| capability.as_str() == "shell")
            .cloned()
            .or_else(|| capabilities.first().cloned())
            .into_iter()
            .collect::<Vec<_>>();
        match self.queue.enqueue_run(SelfHostedRunDispatch {
            dispatch_id,
            action: SelfHostedRunAction::StartRun,
            tenant_id: self_hosted_tenant_id(&registration.tenant),
            workspace_id: registration.workspace_id.clone(),
            session_id: format!("self-hosted-session-{}", registration.id),
            run_id: format!("self-hosted-run-{}", registration.id),
            framework_adapter: self_hosted_framework_adapter(
                &registration.capability_envelope_json,
            ),
            required_capabilities,
            workload_ref: format!("self-hosted-workload://{}", registration.id),
            queued_at_unix: registration.registered_at_unix.unwrap_or_default(),
        }) {
            Ok(()) => Ok(()),
            Err(SelfHostedWorkerError::InvalidTransport(message))
                if message.contains("already exists") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

fn self_hosted_worker_runtime_identity(
    registration: &StoredSelfHostedWorkerRegistration,
) -> SelfHostedWorkerIdentity {
    SelfHostedWorkerIdentity {
        tenant_id: self_hosted_tenant_id(&registration.tenant),
        workspace_id: registration.workspace_id.clone(),
        worker_id: registration.id.clone(),
        token_id: registration.identity_fingerprint.clone(),
        token_secret: registration.identity_fingerprint.clone(),
        observed_at_unix: None,
    }
}

fn self_hosted_seed_dispatch_id(worker_id: &str) -> String {
    format!("self-hosted-dispatch-{worker_id}")
}

pub(crate) fn self_hosted_tenant_id(tenant: &ferrogate_core::TenantContext) -> String {
    tenant
        .organization_id
        .as_deref()
        .or(tenant.project_id.as_deref())
        .or(tenant.team_id.as_deref())
        .or(tenant.user_id.as_deref())
        .or(tenant.api_key_id.as_deref())
        .unwrap_or("tenant")
        .to_string()
}

fn self_hosted_framework_adapter(envelope: &str) -> String {
    serde_json::from_str::<serde_json::Value>(envelope)
        .ok()
        .and_then(|value| {
            value
                .get("frameworks")
                .and_then(|frameworks| frameworks.as_array())
                .and_then(|frameworks| frameworks.first())
                .and_then(|framework| framework.as_str())
                .map(str::to_string)
        })
        .filter(|framework| !framework.trim().is_empty())
        .unwrap_or_else(|| "native-harness".to_string())
}

fn self_hosted_capabilities_from_envelope(envelope: &str) -> Vec<String> {
    let mut capabilities = serde_json::from_str::<serde_json::Value>(envelope)
        .ok()
        .and_then(|value| {
            value
                .get("capabilities")
                .and_then(|capabilities| capabilities.as_array())
                .map(|capabilities| {
                    capabilities
                        .iter()
                        .filter_map(|capability| capability.as_str())
                        .map(str::trim)
                        .filter(|capability| !capability.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_default();
    if capabilities.is_empty() {
        capabilities.push("shell".to_string());
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn self_hosted_queue_record_to_storage(
    record: SelfHostedRunQueueRecord,
) -> StoredSelfHostedRunDispatch {
    StoredSelfHostedRunDispatch {
        dispatch_id: record.dispatch.dispatch_id,
        action: self_hosted_run_action_as_str(record.dispatch.action).to_string(),
        tenant_id: record.dispatch.tenant_id,
        workspace_id: record.dispatch.workspace_id,
        session_id: record.dispatch.session_id,
        run_id: record.dispatch.run_id,
        framework_adapter: record.dispatch.framework_adapter,
        required_capabilities: record.dispatch.required_capabilities,
        workload_ref: record.dispatch.workload_ref,
        queued_at_unix: Some(record.dispatch.queued_at_unix),
        assigned_worker_id: record.assigned_worker_id,
        lease_id: record.lease_id,
        lease_expires_at_unix: record.lease_expires_at_unix,
        attempt: record.attempt,
        acknowledged_status: record
            .acknowledged_status
            .map(self_hosted_run_ack_status_as_str)
            .map(str::to_string),
        acknowledged_at_unix: record.acknowledged_at_unix,
    }
}

fn self_hosted_queue_record_from_storage(
    record: StoredSelfHostedRunDispatch,
) -> Result<SelfHostedRunQueueRecord, SelfHostedWorkerError> {
    Ok(SelfHostedRunQueueRecord {
        dispatch: SelfHostedRunDispatch {
            dispatch_id: record.dispatch_id,
            action: self_hosted_run_action_from_str(&record.action)?,
            tenant_id: record.tenant_id,
            workspace_id: record.workspace_id,
            session_id: record.session_id,
            run_id: record.run_id,
            framework_adapter: record.framework_adapter,
            required_capabilities: record.required_capabilities,
            workload_ref: record.workload_ref,
            queued_at_unix: record.queued_at_unix.unwrap_or_default(),
        },
        assigned_worker_id: record.assigned_worker_id,
        lease_id: record.lease_id,
        lease_expires_at_unix: record.lease_expires_at_unix,
        attempt: record.attempt,
        acknowledged_status: record
            .acknowledged_status
            .as_deref()
            .map(self_hosted_run_ack_status_from_str)
            .transpose()?,
        acknowledged_at_unix: record.acknowledged_at_unix,
    })
}

fn self_hosted_run_action_as_str(action: SelfHostedRunAction) -> &'static str {
    match action {
        SelfHostedRunAction::StartRun => "start_run",
        SelfHostedRunAction::CancelRun => "cancel_run",
        SelfHostedRunAction::ResumeRun => "resume_run",
        SelfHostedRunAction::CloseSession => "close_session",
    }
}

fn self_hosted_run_action_from_str(
    value: &str,
) -> Result<SelfHostedRunAction, SelfHostedWorkerError> {
    match value {
        "start_run" => Ok(SelfHostedRunAction::StartRun),
        "cancel_run" => Ok(SelfHostedRunAction::CancelRun),
        "resume_run" => Ok(SelfHostedRunAction::ResumeRun),
        "close_session" => Ok(SelfHostedRunAction::CloseSession),
        _ => Err(SelfHostedWorkerError::InvalidTransport(format!(
            "unknown self-hosted dispatch action {value}"
        ))),
    }
}

fn self_hosted_run_ack_status_as_str(status: SelfHostedRunAckStatus) -> &'static str {
    match status {
        SelfHostedRunAckStatus::Accepted => "accepted",
        SelfHostedRunAckStatus::Completed => "completed",
        SelfHostedRunAckStatus::Failed => "failed",
        SelfHostedRunAckStatus::Cancelled => "cancelled",
    }
}

fn self_hosted_run_ack_status_from_str(
    value: &str,
) -> Result<SelfHostedRunAckStatus, SelfHostedWorkerError> {
    match value {
        "accepted" => Ok(SelfHostedRunAckStatus::Accepted),
        "completed" => Ok(SelfHostedRunAckStatus::Completed),
        "failed" => Ok(SelfHostedRunAckStatus::Failed),
        "cancelled" => Ok(SelfHostedRunAckStatus::Cancelled),
        _ => Err(SelfHostedWorkerError::InvalidTransport(format!(
            "unknown self-hosted dispatch ack status {value}"
        ))),
    }
}

fn persist_self_hosted_dispatch_records(
    repositories: &RuntimeStorageRepositories,
    records: Vec<StoredSelfHostedRunDispatch>,
) -> Result<(), SelfHostedWorkerError> {
    for record in records {
        crate::gateway::block_on_sync_bridge(repositories.upsert_self_hosted_run_dispatch(record))
            .map_err(|error| SelfHostedWorkerError::InvalidTransport(error.to_string()))?;
    }
    Ok(())
}

impl AppState {
    #[cfg(test)]
    pub(crate) fn new(config: Config) -> Self {
        Self::try_new(config).expect("failed to initialize app state")
    }

    pub(crate) fn try_new(config: Config) -> anyhow::Result<Self> {
        let repositories = Arc::new(runtime_storage_repositories(&config)?);
        Self::try_new_with_repositories(config, repositories, true)
    }

    fn try_new_with_repositories(
        mut config: Config,
        repositories: Arc<RuntimeStorageRepositories>,
        apply_durable_snapshot: bool,
    ) -> anyhow::Result<Self> {
        let analytics = config.analytics.clone();
        config.materialize_skill_package_resources();
        let previous_skill_packages = config.skill_packages.clone();
        if apply_durable_snapshot {
            apply_control_plane_snapshot_to_config_from_repositories(&repositories, &mut config)?;
        }
        config.materialize_skill_package_resources_with_previous(&previous_skill_packages);
        state_mcp_identity::validate_mcp_identity_runtime(&config)?;
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
        let plugin_registrations = config.plugin_registrations();
        let extension_registry = ExtensionRegistry::from_config(&plugin_registrations);
        // Provider name -> declared region (issue #173), threaded into
        // each ModelRoute so candidate_model_routes can enforce a
        // tenant's region_allowlist at routing time.
        let provider_regions: HashMap<&str, Option<&str>> = config
            .providers
            .iter()
            .map(|provider| (provider.name.as_str(), provider.region.as_deref()))
            .collect();
        let model_registry = ModelRegistry::new(
            config
                .models
                .iter()
                .map(|model| model_registry_entry(model, &provider_regions)),
        )
        .expect("config validation must reject invalid model registry entries");

        let policy_engine = build_policy_engine(&config.policies);
        let guardrail_secret_registry = ferrogate_secrets::SecretResolverRegistry::from_env();
        let mut guardrail_policies = config
            .guardrails
            .iter()
            .filter(|rule| rule.enabled)
            .map(compile_static_guardrail_policy)
            .map(|revision| {
                revision.and_then(|revision| {
                    build_guardrail_policy_runtime(revision, &guardrail_secret_registry)
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let static_policy_ids = guardrail_policies
            .iter()
            .map(|policy| policy.revision.policy_id.clone())
            .collect::<HashSet<_>>();
        for binding in repositories.list_guardrail_policy_bindings()? {
            let Some(active_revision) = binding.active_revision else {
                continue;
            };
            if static_policy_ids.contains(binding.policy_id.as_str()) {
                anyhow::bail!(
                    "active durable guardrail policy {} conflicts with a static guardrail id",
                    binding.policy_id
                );
            }
            let stored = repositories
                .get_guardrail_policy_revision(&binding.policy_id, active_revision)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "active guardrail policy {}@{} is missing its immutable revision",
                        binding.policy_id,
                        active_revision
                    )
                })?;
            let revision = deserialize_guardrail_policy_revision(&stored)?;
            guardrail_policies.push(build_guardrail_policy_runtime(
                revision,
                &guardrail_secret_registry,
            )?);
        }
        guardrail_policies.sort_by(|left, right| {
            left.revision
                .scope
                .administrative_rank()
                .cmp(&right.revision.scope.administrative_rank())
                .then_with(|| left.revision.policy_id.cmp(&right.revision.policy_id))
                .then_with(|| left.revision.revision.cmp(&right.revision.revision))
        });
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
        let ip_allowlist: Vec<IpCidr> = config
            .network_access
            .ip_allowlist
            .iter()
            .map(|entry| {
                IpCidr::parse(entry).expect(
                    "config validation must reject invalid network_access.ip_allowlist entries",
                )
            })
            .collect();
        let resolved_provider_secrets = resolve_provider_secret_refs(&config.providers);
        let mcp_servers = config.mcp_servers.clone();
        let cluster_sync = initial_cluster_sync_status(&config);
        let metering_exporter = MeteringExporter::from_config(&config.metering)
            .ok()
            .flatten()
            .map(Arc::new);
        // Billing reporting is a non-blocking accounting side effect, so a
        // misconfiguration (e.g. a missing token env) must NOT take the gateway
        // offline — degrade to disabled with a warning, matching the metering
        // exporter's fail-open behavior (issue #139).
        let billing_reporter = match BillingReporter::from_config(&config.billing_service) {
            Ok(reporter) => reporter.map(Arc::new),
            Err(error) => {
                warn!(
                    error = %error,
                    "billing service client disabled: failed to initialize (accounting is non-blocking)"
                );
                None
            }
        };
        let cluster_counters = ClusterCounterBackend::from_config(&config);
        let self_hosted_dispatch = Arc::new(Mutex::new(SelfHostedWorkerDispatchRuntime::default()));
        {
            let registrations = crate::gateway::block_on_sync_bridge(
                repositories.self_hosted_worker_registrations(),
            );
            let dispatches =
                crate::gateway::block_on_sync_bridge(repositories.self_hosted_run_dispatches());
            let records = match self_hosted_dispatch.lock() {
                Ok(mut dispatch) => {
                    dispatch.rebuild_registries(registrations, dispatches)?;
                    dispatch.storage_records()
                }
                Err(poisoned) => {
                    let mut dispatch = poisoned.into_inner();
                    dispatch.rebuild_registries(registrations, dispatches)?;
                    dispatch.storage_records()
                }
            };
            persist_self_hosted_dispatch_records(&repositories, records).map_err(|error| {
                anyhow::anyhow!("failed to persist self-hosted worker dispatch state: {error}")
            })?;
        }

        Ok(Self {
            cluster_identity: Arc::new(ClusterIdentity::from_config(&config)),
            cluster_sync: Arc::new(cluster_sync),
            config: Arc::new(config.clone()),
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
                analytics.billing_event_retention_records,
            )),
            metering_exporter,
            billing_reporter,
            durable_api_key_authenticator: Arc::new(
                ferrogate_auth::StorageApiKeyAuthenticator::new(Arc::clone(&repositories)),
            ),
            repositories,
            metrics: Arc::new(Mutex::new(GatewayMetricsAccumulator::default())),
            observability_export: Arc::new(Mutex::new(ObservabilityExportRuntime::default())),
            analytics_export: Arc::new(Mutex::new(ObservabilityExportRuntime::default())),
            response_cache: Arc::new(Mutex::new(AiResponseCache::default())),
            self_hosted_dispatch,
            mcp_manager: Arc::new(McpManager::from_configs(&mcp_servers)),
            mcp_dispatch_permits: Arc::new(Semaphore::new(
                config.reliability.mcp_dispatch_max_concurrency,
            )),
            mcp_identity_error_audit_permits: Arc::new(Semaphore::new(
                MCP_IDENTITY_ERROR_AUDIT_MAX_IN_FLIGHT,
            )),
            approvals: ApprovalRegistry::new(),
            access_log_error_limiter: Arc::new(AccessLogRateLimiter::default()),
            policy_engine: Arc::new(policy_engine),
            guardrail_policies: Arc::new(guardrail_policies),
            guardrail_evidence_permits: Arc::new(Semaphore::new(GUARDRAIL_EVIDENCE_MAX_IN_FLIGHT)),
            guardrail_evidence_hmac_key: env::var("FERROGATE_GUARDRAIL_EVIDENCE_HMAC_KEY")
                .ok()
                .filter(|key| key.len() >= 32)
                .map(|key| Arc::from(key.into_bytes())),
            upstream_counters: Arc::new(upstream_counters),
            model_route_counter: Arc::new(AtomicU64::new(0)),
            request_ids: Arc::new(AtomicU64::new(request_id_seed())),
            drain: Arc::new(AtomicBool::new(false)),
            acme_renewal: None,
            ip_allowlist: Arc::new(ip_allowlist),
            trust_forwarded_for: config.network_access.trust_forwarded_for,
            unauthenticated_rate_limit_per_minute: config
                .network_access
                .unauthenticated_rate_limit_per_minute,
            unauth_rate_limiter: Arc::new(UnauthenticatedIpRateLimiter::default()),
            resolved_provider_secrets: Arc::new(resolved_provider_secrets),
        })
    }

    fn with_reloaded_config(&self, config: Config) -> anyhow::Result<Self> {
        let mut next =
            AppState::try_new_with_repositories(config, Arc::clone(&self.repositories), false)?;
        next.cluster_identity = Arc::clone(&self.cluster_identity);
        next.cluster_counters = Arc::new(ClusterCounterBackend::from_reloaded_config(
            &next.config,
            &self.cluster_counters,
        ));
        next.provider_routing_metrics = Arc::clone(&self.provider_routing_metrics);
        next.metering_events = Arc::clone(&self.metering_events);
        next.durable_api_key_authenticator = Arc::new(
            ferrogate_auth::StorageApiKeyAuthenticator::new(Arc::clone(&next.repositories)),
        );
        next.metrics = Arc::clone(&self.metrics);
        next.analytics_export = Arc::clone(&self.analytics_export);
        next.response_cache = Arc::clone(&self.response_cache);
        next.mcp_manager = Arc::clone(&self.mcp_manager);
        next.mcp_manager.reconfigure(&next.config.mcp_servers);
        next.approvals = self.approvals.clone();
        next.guardrail_evidence_permits = Arc::clone(&self.guardrail_evidence_permits);
        next.request_ids = Arc::clone(&self.request_ids);
        next.drain = Arc::clone(&self.drain);
        next.acme_renewal = self.acme_renewal.clone();
        next.unauth_rate_limiter = Arc::clone(&self.unauth_rate_limiter);
        self.apply_analytics_config(&next.config.analytics);
        let _ = self.sync_control_plane_storage_from_config(&next.config);
        Ok(next)
    }

    fn apply_analytics_config(&self, analytics: &AnalyticsConfig) {
        let _ = self
            .metering_events
            .set_retention_limit(analytics.billing_event_retention_records);
        self.repositories.set_retention_limits(
            analytics.request_log_retention_records,
            analytics.audit_event_retention_records,
        );
        self.repositories
            .set_guardrail_evaluation_retention_records(
                analytics.guardrail_evaluation_retention_records,
            );
    }

    fn sync_control_plane_storage_from_config(&self, config: &Config) -> anyhow::Result<()> {
        self.repositories
            .replace_control_plane(control_plane_documents_from_config(config))?;
        Ok(())
    }

    fn apply_control_plane_snapshot_to_config(&self, config: &mut Config) -> anyhow::Result<()> {
        let previous_skill_packages = config.skill_packages.clone();
        let snapshot = self.repositories.control_plane_snapshot()?;
        config.api_keys = deserialize_control_plane_documents(snapshot.api_keys)?;
        let tenant_refs: Vec<crate::responses::AdminTenantRef> =
            deserialize_control_plane_documents(snapshot.tenants)?;
        config.policies = deserialize_control_plane_documents(snapshot.policies)?;
        config.gateway_configs = deserialize_control_plane_documents(snapshot.gateway_configs)?;
        config.agent_workflows = deserialize_control_plane_documents(snapshot.agent_workflows)?;
        config.skill_packages = deserialize_control_plane_documents(snapshot.skill_packages)?;
        config.prompt_templates = deserialize_control_plane_documents(snapshot.prompt_templates)?;
        config.plugins = deserialize_control_plane_documents(snapshot.plugin_registrations)?;
        config.extensions.clear();
        config.mcp_servers = deserialize_control_plane_documents(snapshot.mcp_servers)?;
        config.agent_upstreams = deserialize_control_plane_documents(snapshot.agent_upstreams)?;
        if !tenant_refs.is_empty() {
            apply_tenant_refs_to_api_keys(&mut config.api_keys, tenant_refs);
        }
        config.materialize_skill_package_resources_with_previous(&previous_skill_packages);
        Ok(())
    }

    pub(crate) fn next_request_id(&self) -> String {
        let next = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fg-{next:016x}")
    }

    pub(crate) fn auth_required(&self) -> bool {
        self.config.auth_service.enabled || !self.config.api_keys.is_empty()
    }

    /// Pre-authentication network gate (issue #166): rejects requests whose
    /// client IP is outside a configured allowlist, or that exceed the
    /// unauthenticated per-source-IP rate limit — both checked before
    /// `authenticate()` runs, so a flood or credential-stuffing scan never
    /// pays the virtual-key/storage lookup cost. A missing/unparsable client
    /// IP is treated as denied whenever an allowlist is configured (fail
    /// closed), and is exempt from rate limiting (nothing to key it on).
    pub(crate) fn check_network_access(
        &self,
        headers: &HeaderMap,
        peer_addr: Option<IpAddr>,
    ) -> NetworkAccessDecision {
        let client_ip = resolve_client_ip(headers, peer_addr, self.trust_forwarded_for);

        if !self.ip_allowlist.is_empty() {
            let allowed =
                client_ip.is_some_and(|ip| self.ip_allowlist.iter().any(|cidr| cidr.contains(&ip)));
            if !allowed {
                self.record_network_access_decision(NetworkAccessDecision::IpDenied);
                return NetworkAccessDecision::IpDenied;
            }
        }

        if let Some(limit) = self.unauthenticated_rate_limit_per_minute {
            if let Some(ip) = client_ip {
                let now_minute = now_unix_seconds().unwrap_or(0) / 60;
                if !self.unauth_rate_limiter.allow(ip, now_minute, limit) {
                    self.record_network_access_decision(NetworkAccessDecision::RateLimited);
                    return NetworkAccessDecision::RateLimited;
                }
            }
        }

        NetworkAccessDecision::Allowed
    }

    fn record_network_access_decision(&self, decision: NetworkAccessDecision) {
        match self.metrics.lock() {
            Ok(mut metrics) => metrics.record_network_access_decision(decision),
            Err(poisoned) => poisoned
                .into_inner()
                .record_network_access_decision(decision),
        }
    }

    pub(crate) fn storage_status(&self) -> StorageBackendEvidence {
        self.repositories.backend_evidence()
    }

    pub(crate) fn managed_worker_session_lifecycle_storage_ready(&self) -> bool {
        self.storage_status().schema.as_ref().is_some_and(|schema| {
            schema.engine == "postgres"
                && schema.validated
                && schema.version >= 4
                && matches!(
                    schema.name.as_str(),
                    "004_supabase_managed_worker_lifecycle"
                        | "005_supabase_self_hosted_worker_lifecycle"
                )
        })
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

    // --- P1-4 usage/cost monthly rollups ---

    pub(crate) fn list_usage_monthly_rollups(
        &self,
    ) -> anyhow::Result<Vec<StoredUsageMonthlyRollup>> {
        Ok(crate::gateway::block_on_sync_bridge(
            self.repositories.list_usage_monthly_rollups(),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> anyhow::Result<Option<StoredUsageMonthlyRollup>> {
        Ok(crate::gateway::block_on_sync_bridge(
            self.repositories
                .get_usage_monthly_rollup(scope_type, scope_id, period_month),
        )?)
    }

    pub(crate) fn admin_pagination(&self, query: Option<&str>) -> AdminPagination {
        AdminPagination::from_query(
            query,
            self.config.storage.admin_list_default_limit,
            self.config.storage.admin_list_max_limit,
        )
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
    latency_ms: Option<u64>,
    metadata: Option<&'a std::collections::BTreeMap<String, String>>,
}

/// Everything about a settled request needed to record a billing event,
/// except the token usage itself -- callers hold either a provider-reported
/// [`ProviderUsage`] ([`AppState::record_billing_event`]) or a gateway
/// [`BillingTokenUsage`] estimate ([`AppState::record_estimated_billing_event`]),
/// so usage stays a separate parameter rather than living in this struct.
#[derive(Debug)]
pub(crate) struct BillingEventDraft<'a> {
    pub(crate) request: &'a RequestContext,
    pub(crate) logical_model: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) provider_model: &'a str,
    pub(crate) status_code: u16,
    pub(crate) latency_ms: Option<u64>,
    /// Caller-supplied request tags (issue #171) -- `None` for every
    /// non-AI-request settlement path (self-hosted worker billing, MCP tool
    /// billing, etc.), `Some` only where an ingress actually parses a
    /// `metadata` object (currently `ChatCompletionRequest`, shared by both
    /// the chat completions and Responses API endpoints).
    pub(crate) metadata: Option<&'a std::collections::BTreeMap<String, String>>,
}

/// Resolves AWS SigV4 credentials for a `bedrock`-kind provider (issue
/// #172) from `aws_access_key_id` (plain config) + `aws_secret_access_key_env`
/// (an environment variable name) + `region` (reused from #173's
/// data-residency field) + an optional `aws_session_token_env`. Returns
/// `None` when any required piece is absent -- the Bedrock adapter then
/// fails closed at request-preparation time (`AdapterError::InvalidRequest`)
/// rather than sending an unsigned request, same fail-closed shape as
/// every other required-config gap in this codebase. Env vars, not the
/// vault-backed `secret_ref` mechanism `api_key` has: see the field docs
/// on `Provider::aws_secret_access_key_env`.
fn aws_provider_credentials(provider: &Provider) -> Option<AwsProviderCredentials> {
    let access_key_id = provider.aws_access_key_id.clone()?;
    let secret_env = provider.aws_secret_access_key_env.as_deref()?;
    let secret_access_key = std::env::var(secret_env)
        .ok()
        .filter(|value| !value.is_empty())?;
    let region = provider.region.clone()?;
    let session_token = provider
        .aws_session_token_env
        .as_deref()
        .and_then(|env| std::env::var(env).ok())
        .filter(|value| !value.is_empty())
        .map(SecretValue::new);
    Some(AwsProviderCredentials {
        access_key_id,
        secret_access_key: SecretValue::new(secret_access_key),
        session_token,
        region,
    })
}

/// Resolves a static GCP OAuth2 access token for a `vertex`-kind provider
/// (issue #172) from `gcp_project_id` (plain config) + `region` (reused
/// from #173's data-residency field, doubling as the GCP location) +
/// `gcp_access_token_env` (an environment variable holding an
/// already-valid token). Returns `None` when any required piece is
/// absent -- same fail-closed shape as `aws_provider_credentials`. No
/// token-minting or refresh happens here; see `GcpProviderCredentials`'s
/// doc comment in `ferrogate-providers` for why.
fn gcp_provider_credentials(provider: &Provider) -> Option<GcpProviderCredentials> {
    let project_id = provider.gcp_project_id.clone()?;
    let location = provider.region.clone()?;
    let token_env = provider.gcp_access_token_env.as_deref()?;
    let access_token = std::env::var(token_env)
        .ok()
        .filter(|value| !value.is_empty())?;
    Some(GcpProviderCredentials {
        access_token: SecretValue::new(access_token),
        project_id,
        location,
    })
}

/// Settled cost in USD for one request, looked up from the model registry's
/// configured pricing for whichever route (primary or fallback) actually
/// served `provider`/`provider_model`. `None` when the model is unknown or
/// has no configured price on that route (P1-4: cost is only ever computed
/// from real configuration, never silently guessed).
fn settled_cost_usd(
    model_registry: &ModelRegistry,
    logical_model: &str,
    provider: &str,
    provider_model: &str,
    usage: &BillingTokenUsage,
) -> Option<f64> {
    let resolved = model_registry.resolve(logical_model).ok()?;
    let route = std::iter::once(&resolved.primary)
        .chain(resolved.fallbacks.iter())
        .find(|route| route.provider == provider && route.provider_model == provider_model)?;
    let input_price = route.input_price_per_1m?;
    let output_price = route.output_price_per_1m?;
    Some(
        ModelPrice::usd(input_price, output_price)
            .estimate(usage)
            .total_cost,
    )
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

/// Fixed 60s window tracking total estimated tokens consumed, for the P1-3
/// tokens-per-minute (TPM) quota. Structurally identical to
/// `ApiKeyRequestWindow` except it sums a caller-supplied token count instead
/// of incrementing by one per call.
#[derive(Debug, Default)]
struct ApiKeyTokenWindow {
    state: Mutex<ApiKeyTokenWindowState>,
}

impl ApiKeyTokenWindow {
    fn try_consume(&self, limit: u64, tokens: u64, now_unix_seconds: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return true;
        };

        if now_unix_seconds.saturating_sub(state.window_started_at) >= 60 {
            state.window_started_at = now_unix_seconds;
            state.tokens_used = 0;
        }

        if state.tokens_used.saturating_add(tokens) > limit {
            return false;
        }

        state.tokens_used = state.tokens_used.saturating_add(tokens);
        true
    }
}

#[derive(Debug, Default)]
struct ApiKeyTokenWindowState {
    window_started_at: u64,
    tokens_used: u64,
}

#[derive(Debug)]
enum ClusterCounterBackend {
    Local {
        request_windows: Arc<Mutex<HashMap<String, Arc<ApiKeyRequestWindow>>>>,
        token_rate_windows: Arc<Mutex<HashMap<String, Arc<ApiKeyTokenWindow>>>>,
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
            // Windows are created lazily on first use (see `try_consume_request`)
            // rather than pre-seeded from `config.api_keys`, so request-limit
            // enforcement also covers durable (Supabase-backed) virtual keys
            // that never appear in the static YAML key list.
            request_windows: Arc::new(Mutex::new(HashMap::new())),
            token_rate_windows: Arc::new(Mutex::new(HashMap::new())),
            token_reservations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn from_reloaded_config(config: &Config, previous: &Arc<Self>) -> Self {
        match (Self::from_config(config), previous.as_ref()) {
            (
                Self::Local { .. },
                Self::Local {
                    request_windows,
                    token_rate_windows,
                    token_reservations,
                },
            ) => Self::Local {
                request_windows: Arc::clone(request_windows),
                token_rate_windows: Arc::clone(token_rate_windows),
                token_reservations: Arc::clone(token_reservations),
            },
            (next, _) => next,
        }
    }

    fn try_consume_request(&self, api_key_id: &str, limit: u64) -> anyhow::Result<bool> {
        match self {
            Self::Local {
                request_windows, ..
            } => {
                let Ok(mut windows) = request_windows.lock() else {
                    return Ok(true);
                };
                let window = Arc::clone(
                    windows
                        .entry(api_key_id.to_string())
                        .or_insert_with(|| Arc::new(ApiKeyRequestWindow::default())),
                );
                drop(windows);
                Ok(window.try_consume(limit, now_unix_seconds().unwrap_or_default()))
            }
            Self::Redis(redis) => redis.try_consume_request(api_key_id, limit),
        }
    }

    fn try_consume_tokens_per_minute(
        &self,
        api_key_id: &str,
        limit: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Local {
                token_rate_windows, ..
            } => {
                let Ok(mut windows) = token_rate_windows.lock() else {
                    return Ok(true);
                };
                let window = Arc::clone(
                    windows
                        .entry(api_key_id.to_string())
                        .or_insert_with(|| Arc::new(ApiKeyTokenWindow::default())),
                );
                drop(windows);
                Ok(window.try_consume(
                    limit,
                    estimated_tokens,
                    now_unix_seconds().unwrap_or_default(),
                ))
            }
            Self::Redis(redis) => {
                redis.try_consume_tokens_per_minute(api_key_id, limit, estimated_tokens)
            }
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

    fn try_consume_tokens_per_minute(
        &self,
        api_key_id: &str,
        limit: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<bool> {
        let now = now_unix_seconds().unwrap_or_default();
        let window = now / 60;
        let key = format!("{}:tpm:{window}", self.api_key_prefix(api_key_id));
        let script = redis::Script::new(
            r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local estimate = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if current + estimate > limit then
  return 0
end
redis.call('INCRBY', KEYS[1], estimate)
redis.call('EXPIRE', KEYS[1], 120)
return 1
"#,
        );
        let mut connection = self.connection()?;
        let allowed: u8 = script
            .key(key)
            .arg(estimated_tokens)
            .arg(limit)
            .invoke(&mut connection)?;
        Ok(allowed == 1)
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

fn compile_static_guardrail_policy(rule: &GuardrailRule) -> anyhow::Result<PolicyRevision> {
    let local = DetectorDefinition::local(
        rule.keywords.clone(),
        rule.regex.clone(),
        rule.max_input_bytes,
    );
    let has_local =
        !rule.keywords.is_empty() || !rule.regex.is_empty() || rule.max_input_bytes.is_some();
    let detector = match rule.provider {
        GuardrailProviderKind::None => local.clone(),
        GuardrailProviderKind::CustomHttp => DetectorDefinition::CustomHttp {
            endpoint: rule.provider_endpoint.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "guardrail {} custom_http provider is missing provider_endpoint",
                    rule.id
                )
            })?,
            timeout_ms: rule.provider_timeout_ms,
            max_concurrency: rule.provider_runtime.provider_max_concurrency,
            circuit_failure_threshold: rule.provider_runtime.provider_circuit_failure_threshold,
            circuit_cooldown_ms: rule.provider_runtime.provider_circuit_cooldown_ms,
            max_retries: rule.provider_runtime.provider_max_retries,
            max_payload_bytes: rule.provider_runtime.provider_max_payload_bytes,
            max_response_bytes: rule.provider_runtime.provider_max_response_bytes,
            allow_private_network: rule.provider_runtime.provider_allow_private_network,
            secret_ref: rule.provider_runtime.provider_secret_ref.clone(),
        },
    };
    let fallback_detector = (rule.provider == GuardrailProviderKind::CustomHttp
        && rule.provider_runtime.provider_on_error == GuardrailProviderErrorMode::FallbackDetector
        && has_local)
        .then_some(local);
    let enforcement_action = match rule.effect {
        GuardrailEffect::Deny => PolicyAction::block(&rule.code, &rule.message),
        GuardrailEffect::Redact => PolicyAction::redact(&rule.code, &rule.message),
    };
    let on_error = match rule.provider_runtime.provider_on_error {
        GuardrailProviderErrorMode::Block => vec![PolicyAction::block(
            "guardrail_provider_unavailable",
            format!("guardrail detector for rule '{}' failed", rule.name),
        )],
        GuardrailProviderErrorMode::Record | GuardrailProviderErrorMode::FallbackDetector => {
            vec![PolicyAction::record()]
        }
    };
    let revision = PolicyRevision {
        policy_id: rule.id.clone(),
        revision: 1,
        name: rule.name.clone(),
        description: Some("compiled from static guardrails configuration".to_string()),
        enforced: true,
        scope: PolicyScopeSelector {
            organization_ids: rule.organization_ids.clone(),
            project_ids: rule.project_ids.clone(),
            api_key_ids: rule.api_key_ids.clone(),
            models: rule.models.clone(),
            providers: rule.providers.clone(),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "static-check".to_string(),
            enabled: true,
            stage: match rule.stage {
                GuardrailStage::Request => DetectorStage::Request,
                GuardrailStage::Response => DetectorStage::Response,
            },
            sources: rule.sources.clone(),
            detector,
            fallback_detector,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![enforcement_action],
        on_error,
        deadline_ms: rule.provider_timeout_ms,
        created_at_unix: 0,
        created_by: "static_config".to_string(),
    };
    revision.validate().map_err(|error| {
        anyhow::anyhow!(
            "failed to compile static guardrail {}: {}",
            rule.id,
            error.safe_message()
        )
    })?;
    Ok(revision)
}

fn deserialize_guardrail_policy_revision(
    stored: &StoredGuardrailPolicyRevision,
) -> anyhow::Result<PolicyRevision> {
    let revision: PolicyRevision = serde_json::from_str(&stored.policy_json).map_err(|error| {
        anyhow::anyhow!(
            "guardrail policy revision {} is invalid JSON: {error}",
            stored.id
        )
    })?;
    if revision.policy_id != stored.policy_id
        || revision.revision != stored.revision
        || revision.immutable_id() != stored.id
        || revision.created_at_unix != stored.created_at_unix
        || revision.created_by != stored.created_by
    {
        anyhow::bail!(
            "guardrail policy revision {} metadata does not match its immutable document",
            stored.id
        );
    }
    revision.validate().map_err(|error| {
        anyhow::anyhow!(
            "guardrail policy revision {} is invalid: {}",
            stored.id,
            error.safe_message()
        )
    })?;
    Ok(revision)
}

fn stored_guardrail_policy_revision(
    revision: &PolicyRevision,
) -> anyhow::Result<StoredGuardrailPolicyRevision> {
    Ok(StoredGuardrailPolicyRevision {
        id: guardrail_policy_revision_id(&revision.policy_id, revision.revision),
        policy_id: revision.policy_id.clone(),
        revision: revision.revision,
        policy_json: serde_json::to_string(revision)?,
        created_at_unix: revision.created_at_unix,
        created_by: revision.created_by.clone(),
    })
}

fn build_guardrail_policy_runtime(
    revision: PolicyRevision,
    secret_registry: &ferrogate_secrets::SecretResolverRegistry,
) -> anyhow::Result<GuardrailPolicyRuntime> {
    revision.validate().map_err(|error| {
        anyhow::anyhow!(
            "failed to initialize guardrail {}: {}",
            revision.immutable_id(),
            error.safe_message()
        )
    })?;
    let checks = revision
        .checks
        .iter()
        .map(|check| {
            let (detector_id, detector_config_digest) =
                guardrail_detector_evidence_metadata(&check.detector)?;
            Ok(GuardrailCheckRuntime {
                id: check.id.clone(),
                enabled: check.enabled,
                stage: check.stage,
                sources: check.sources.clone(),
                detector_id,
                detector_config_digest,
                detector: build_guardrail_detector(
                    &revision.immutable_id(),
                    &check.id,
                    &check.sources,
                    &check.detector,
                    secret_registry,
                )?,
                fallback_detector: check
                    .fallback_detector
                    .as_ref()
                    .map(|detector| {
                        build_guardrail_detector(
                            &revision.immutable_id(),
                            &check.id,
                            &check.sources,
                            detector,
                            secret_registry,
                        )
                    })
                    .transpose()?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(GuardrailPolicyRuntime { revision, checks })
}

fn guardrail_detector_evidence_metadata(
    definition: &DetectorDefinition,
) -> anyhow::Result<(String, String)> {
    let detector_id = match definition {
        DetectorDefinition::Local { .. } => "ferrogate.local".to_string(),
        DetectorDefinition::CustomHttp { .. } => "custom_http".to_string(),
    };
    let serialized = serde_json::to_vec(definition)?;
    let digest = Sha256::digest(serialized);
    Ok((detector_id, format!("sha256:{digest:x}")))
}
fn build_guardrail_detector(
    policy_id: &str,
    check_id: &str,
    sources: &[ferrogate_guardrails::ContentSource],
    definition: &DetectorDefinition,
    secret_registry: &ferrogate_secrets::SecretResolverRegistry,
) -> anyhow::Result<Arc<dyn GuardrailDetector>> {
    if let DetectorDefinition::Local {
        keywords,
        regex,
        max_input_bytes,
        json,
        request,
        secret_patterns,
        fingerprint_secret_ref,
    } = definition
    {
        let fingerprint_key = fingerprint_secret_ref
            .as_deref()
            .map(|secret_ref| {
                secret_registry
                    .resolve(secret_ref)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "failed to resolve fingerprint secret for guardrail {policy_id}/{check_id}: {error}"
                        )
                    })?
                    .map(DetectorSecret::new)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "fingerprint secret for guardrail {policy_id}/{check_id} resolved no value"
                        )
                    })
            })
            .transpose()?;
        let detector = DeterministicDetector::new(DeterministicDetectorConfig {
            id: format!("{policy_id}/{check_id}"),
            supported_sources: sources.to_vec(),
            keywords: keywords.clone(),
            regex: regex.clone(),
            max_input_bytes: *max_input_bytes,
            json: json.clone(),
            request: request.as_deref().cloned(),
            secret_patterns: secret_patterns.clone(),
            fingerprint_key,
        })
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to initialize guardrail {policy_id}/{check_id}: {}",
                error.safe_message()
            )
        })?;
        return Ok(Arc::new(detector));
    }
    let DetectorDefinition::CustomHttp {
        endpoint,
        timeout_ms,
        max_concurrency,
        circuit_failure_threshold,
        circuit_cooldown_ms,
        max_retries,
        max_payload_bytes,
        max_response_bytes,
        allow_private_network,
        secret_ref,
    } = definition
    else {
        unreachable!("local detector returned above")
    };
    let bearer_token = match secret_ref.as_deref() {
        Some(secret_ref) => Some(DetectorSecret::new(
            secret_registry
                .resolve(secret_ref)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to resolve secret for guardrail {policy_id}/{check_id}: {error}"
                    )
                })?
                .ok_or_else(|| {
                    anyhow::anyhow!("secret for guardrail {policy_id}/{check_id} resolved no value")
                })?,
        )),
        None => None,
    };
    let detector = CustomHttpDetector::new(CustomHttpDetectorConfig {
        id: format!("{policy_id}/{check_id}"),
        endpoint: endpoint.clone(),
        timeout: Duration::from_millis(*timeout_ms),
        max_concurrency: *max_concurrency,
        circuit_failure_threshold: *circuit_failure_threshold,
        circuit_cooldown: Duration::from_millis(*circuit_cooldown_ms),
        max_retries: *max_retries,
        max_payload_bytes: *max_payload_bytes,
        max_response_bytes: *max_response_bytes,
        allow_private_network: *allow_private_network,
        supported_sources: sources.to_vec(),
        bearer_token,
    })
    .map_err(|error| {
        anyhow::anyhow!(
            "failed to initialize guardrail {policy_id}/{check_id}: {}",
            error.safe_message()
        )
    })?;
    Ok(Arc::new(detector))
}

/// Resolves every configured `Provider.secret_ref` once (issue #163),
/// keyed by provider name. Failures (bad reference syntax, unreachable
/// Vault, missing field) are logged and skipped rather than failing
/// gateway startup/reload — a provider whose secret fails to resolve just
/// falls back to `api_key_env` in `AppState::provider_config`, matching the
/// existing fail-open behavior for optional-adjacent config.
fn resolve_provider_secret_refs(providers: &[Provider]) -> HashMap<String, String> {
    let mut resolved = HashMap::new();
    if !providers
        .iter()
        .any(|provider| provider.secret_ref.is_some())
    {
        return resolved;
    }
    let registry = ferrogate_secrets::SecretResolverRegistry::from_env();
    for provider in providers {
        let Some(secret_ref) = provider.secret_ref.as_deref() else {
            continue;
        };
        match registry.resolve(secret_ref) {
            Ok(Some(value)) => {
                resolved.insert(provider.name.clone(), value);
            }
            Ok(None) => {
                warn!(
                    provider = %provider.name,
                    secret_ref,
                    "provider secret_ref resolved to no value; falling back to api_key_env if set"
                );
            }
            Err(error) => {
                warn!(
                    provider = %provider.name,
                    secret_ref,
                    error = %error,
                    "failed to resolve provider secret_ref; falling back to api_key_env if set"
                );
            }
        }
    }
    resolved
}

fn provider_circuit_config(config: &Config) -> Option<ProviderCircuitConfig> {
    Some(ProviderCircuitConfig {
        failure_threshold: config
            .reliability
            .provider_circuit_breaker_failure_threshold?,
        cooldown: Duration::from_secs(config.reliability.provider_circuit_breaker_cooldown_secs?),
    })
}

fn gateway_config_use(
    profile: &GatewayConfigProfile,
    api_key_id: Option<&str>,
) -> Result<GatewayConfigUse, GatewayConfigResolveError> {
    if !profile.enabled {
        return Err(GatewayConfigResolveError::Disabled {
            id: profile.id.clone(),
            revision: profile.revision,
        });
    }
    if !profile.api_key_ids.is_empty()
        && !api_key_id.is_some_and(|api_key_id| {
            profile
                .api_key_ids
                .iter()
                .any(|allowed| allowed == api_key_id)
        })
    {
        return Err(GatewayConfigResolveError::NotAllowed {
            id: profile.id.clone(),
            revision: profile.revision,
        });
    }
    Ok(GatewayConfigUse {
        id: profile.id.clone(),
        revision: profile.revision,
        cache_enabled: profile.cache_enabled,
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

fn model_registry_entry(
    model: &Model,
    provider_regions: &HashMap<&str, Option<&str>>,
) -> ModelRegistryEntry {
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
    entry.primary.region = provider_region(provider_regions, &model.provider);
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
            .with_region(provider_region(provider_regions, &fallback.provider))
        })
        .collect();
    entry
}

fn provider_region(
    provider_regions: &HashMap<&str, Option<&str>>,
    provider_name: &str,
) -> Option<String> {
    provider_regions
        .get(provider_name)
        .copied()
        .flatten()
        .map(str::to_string)
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
        McpExecutionError::Unauthorized(message) => {
            ToolExecutionError::UpstreamUnauthorized(message)
        }
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

fn now_unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn request_id_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let hostname = env::var("HOSTNAME").unwrap_or_default();
    let material = format!("{hostname}:{}:{nanos}", std::process::id());
    fnv1a64(material.as_bytes()).max(1)
}

/// Max billing-report outbox rows delivered per sweep (issue #137).
const BILLING_OUTBOX_BATCH: usize = 100;

/// After this many failed delivery attempts, a report is dead-lettered
/// instead of rescheduled forever (issue #143). With the backoff sequence
/// below this is roughly 15 minutes of retries — long enough to ride out a
/// billing-service restart or a brief network blip, short enough that a
/// permanently-undeliverable event (e.g. a 422 from a rate-card mismatch)
/// doesn't retry indefinitely and starve the sweeper batch.
const MAX_BILLING_OUTBOX_ATTEMPTS: i64 = 20;

/// Capped exponential backoff (seconds) for a failed billing report, by prior
/// attempt count: 1, 2, 4, 8, 16, 32, 60, 60, ...
fn billing_outbox_backoff_secs(attempts: i64) -> i64 {
    let shift = attempts.clamp(0, 6) as u32;
    (1i64 << shift).min(60)
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

#[path = "state_tools.rs"]
mod state_tools;

#[path = "state_mcp_identity.rs"]
mod state_mcp_identity;

#[path = "state_assets.rs"]
mod state_assets;

#[path = "state_rbac.rs"]
mod state_rbac;

#[path = "state_tenancy.rs"]
mod state_tenancy;

#[path = "state_wallets.rs"]
mod state_wallets;

#[path = "state_quota_and_policy.rs"]
mod state_quota_and_policy;

#[path = "state_billing_metering.rs"]
mod state_billing_metering;

#[path = "state_observability.rs"]
mod state_observability;

#[path = "state_routing.rs"]
mod state_routing;

#[path = "state_agent_runtime.rs"]
mod state_agent_runtime;
#[path = "state_guardrail_evidence.rs"]
mod state_guardrail_evidence;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> Provider {
        Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:10001/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }
    }

    fn test_model() -> Model {
        Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-test".into(),
            routing_strategy: RoutingStrategy::default(),
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: Vec::new(),
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }
    }

    fn test_api_key(id: &str) -> ApiKey {
        ApiKey {
            region_allowlist: Vec::new(),
            id: id.into(),
            name: id.into(),
            key_env: None,
            key: Some(format!("{id}-secret")),
            key_hash: None,
            enabled: true,
            scopes: vec!["admin.read".into(), "chat.completions".into()],
            allowed_models: vec!["fast-chat".into()],
            denied_models: Vec::new(),
            allowed_providers: vec!["openai".into()],
            denied_providers: Vec::new(),
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            workspace_id: None,
            user_id: None,
            monthly_token_budget: None,
            request_limit_per_minute: None,
            expires_at_unix: None,
            log_bodies: None,
            cache_enabled: None,
        }
    }

    #[test]
    fn control_plane_crud_uses_storage_boundary() {
        let shared = SharedAppState::with_source_path(
            Config {
                providers: vec![test_provider()],
                models: vec![test_model()],
                api_keys: vec![test_api_key("key_initial")],
                mcp_servers: vec![ferrogate_mcp::McpServerConfig {
                    name: "github".into(),
                    transport: ferrogate_mcp::McpTransport::StreamableHttp,
                    url: Some("http://127.0.0.1:1/mcp".into()),
                    command: None,
                    args: Vec::new(),
                    auth_type: ferrogate_mcp::McpAuthType::None,
                    headers: Vec::new(),
                    oauth: None,
                    signed_jwt_audience: None,
                    tools_to_execute: vec!["search".into()],
                    tools_to_auto_execute: Vec::new(),
                    approval_policy: ferrogate_core::ApprovalPolicy::Never,
                    tool_include: vec!["search".into()],
                    tool_regex: Vec::new(),
                    tls: ferrogate_mcp::McpTlsConfig::default(),
                    timeout_ms: 100,
                    health_ping_interval_secs: 10,
                    max_reconnect_attempts: 1,
                    min_reconnect_backoff_secs: 1,
                    max_reconnect_backoff_secs: 1,
                }],
                ..Config::default()
            },
            None,
        );

        shared.upsert_api_key(test_api_key("key_added")).unwrap();
        let state = shared.current();
        assert!(state
            .config
            .api_keys
            .iter()
            .any(|key| key.id == "key_added"));
        let snapshot = state.repositories.control_plane_snapshot().unwrap();
        assert!(snapshot
            .api_keys
            .iter()
            .any(|document| document.contains("\"id\":\"key_added\"")));
        assert!(snapshot
            .mcp_servers
            .iter()
            .any(|document| document.contains("\"name\":\"github\"")));

        shared
            .upsert_policy(ConfigPolicyRule {
                name: "deny-added".into(),
                effect: "deny".into(),
                organization_ids: Vec::new(),
                project_ids: Vec::new(),
                api_key_ids: vec!["key_added".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                code: "blocked".into(),
                message: "blocked".into(),
                enabled: true,
            })
            .unwrap();
        let state = shared.current();
        assert!(state
            .config
            .policies
            .iter()
            .any(|policy| policy.name == "deny-added"));
        assert!(state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .policies
            .iter()
            .any(|document| document.contains("\"name\":\"deny-added\"")));

        shared
            .upsert_gateway_config(GatewayConfigProfile {
                id: "profile-added".into(),
                name: "Profile added".into(),
                revision: 3,
                enabled: true,
                api_key_ids: vec!["key_added".into()],
                cache_enabled: Some(false),
            })
            .unwrap();
        let state = shared.current();
        assert!(state
            .config
            .gateway_configs
            .iter()
            .any(|profile| profile.id == "profile-added"));
        assert!(state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .gateway_configs
            .iter()
            .any(|document| document.contains("\"id\":\"profile-added\"")));

        shared
            .upsert_prompt_template(PromptTemplate {
                id: "template-added".into(),
                name: "Template added".into(),
                status: PromptTemplateStatus::Active,
                target: crate::config::PromptTemplateTarget::ChatCompletions,
                model: "fast-chat".into(),
                variables: Vec::new(),
                versions: vec![crate::config::PromptTemplateVersion {
                    revision: 1,
                    status: crate::config::PromptTemplateVersionStatus::Active,
                    messages: vec![crate::config::PromptTemplateMessage {
                        role: "user".into(),
                        content: "hello".into(),
                    }],
                    temperature: None,
                    top_p: None,
                    max_tokens: None,
                }],
            })
            .unwrap();
        let state = shared.current();
        assert!(state
            .config
            .prompt_templates
            .iter()
            .any(|template| template.id == "template-added"));
        assert!(state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .prompt_templates
            .iter()
            .any(|document| document.contains("\"id\":\"template-added\"")));

        assert!(shared
            .delete_gateway_config("profile-added")
            .unwrap()
            .is_some());
        assert!(shared
            .archive_prompt_template("template-added")
            .unwrap()
            .is_some());
        let state = shared.current();
        assert!(!state
            .config
            .gateway_configs
            .iter()
            .any(|profile| profile.id == "profile-added"));
        assert!(state.config.prompt_templates.iter().any(|template| {
            template.id == "template-added" && template.status == PromptTemplateStatus::Archived
        }));

        assert!(shared.delete_policy("deny-added").unwrap().is_some());
        assert!(shared.delete_api_key("key_added").unwrap().is_some());
        let state = shared.current();
        assert!(!state
            .config
            .api_keys
            .iter()
            .any(|key| key.id == "key_added"));
        assert!(!state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .api_keys
            .iter()
            .any(|document| document.contains("\"id\":\"key_added\"")));
        assert!(!state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .gateway_configs
            .iter()
            .any(|document| document.contains("\"id\":\"profile-added\"")));
        assert!(state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .prompt_templates
            .iter()
            .any(|document| document.contains("\"status\":\"archived\"")));

        let approval = state
            .create_tool_approval(ToolApprovalCreateRequest {
                tool: &ToolExecutionRequest {
                    name: "github.search".into(),
                    arguments: serde_json::json!({"query":"ferrogate"}),
                    route: None,
                    session_id: None,
                },
                request_id: "request-test",
                trace_id: Some("trace-test".into()),
                tenant: ferrogate_core::TenantContext::default(),
                actor_api_key_id: Some("key_initial".into()),
                server_name: Some("mcp.github".into()),
                approval_policy: ferrogate_core::ApprovalPolicy::Always,
                can_log_bodies: false,
            })
            .unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
        let stored_approval = state.tool_approval(&approval.id).unwrap();
        assert_eq!(stored_approval.id, approval.id);
        assert_eq!(stored_approval.status, ApprovalStatus::Pending);
        assert!(state
            .repositories
            .control_plane_tool_approvals()
            .unwrap()
            .iter()
            .any(|document| document.contains("\"tool_name\":\"github.search\"")));
    }

    #[test]
    fn failed_control_plane_storage_mutation_rolls_back_to_active_config() {
        let shared = SharedAppState::with_source_path(
            Config {
                providers: vec![test_provider()],
                models: vec![test_model()],
                api_keys: vec![test_api_key("key_initial")],
                ..Config::default()
            },
            None,
        );

        let result = shared.upsert_policy(ConfigPolicyRule {
            name: "deny-invalid".into(),
            effect: "deny".into(),
            organization_ids: Vec::new(),
            project_ids: Vec::new(),
            api_key_ids: vec!["missing-key".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            code: "blocked".into(),
            message: "blocked".into(),
            enabled: true,
        });

        assert!(result.is_err());
        let state = shared.current();
        assert!(!state
            .config
            .policies
            .iter()
            .any(|policy| policy.name == "deny-invalid"));
        assert!(!state
            .repositories
            .control_plane_snapshot()
            .unwrap()
            .policies
            .iter()
            .any(|document| document.contains("\"name\":\"deny-invalid\"")));
    }

    #[test]
    fn listener_runtime_config_allows_process_local_app_state_changes() {
        let active = Config::default();
        let candidate = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
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
}

#[cfg(test)]
#[path = "state_self_hosted_security_test.rs"]
mod state_self_hosted_security_test;

#[cfg(test)]
#[path = "state_billing_outbox_test.rs"]
mod state_billing_outbox_test;

#[cfg(test)]
#[path = "state_reload_test.rs"]
mod state_reload_test;
