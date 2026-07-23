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
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::{TenantContext, WorkspaceScope};
use native_tls::{Certificate as NativeTlsCertificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row as PostgresRow;

mod async_postgres;
pub use async_postgres::PostgresPoolMetricsSnapshot;

mod rbac;
pub use rbac::{tenant_role_binding_id, StoredPermission, StoredRole, StoredTenantRoleBinding};

mod mcp_identity;
pub use mcp_identity::{
    McpCredentialRepository, McpIdentityAccessOutcome, McpIdentityAccessRequest,
    McpIdentityRevocationOutcome, McpOauthCallbackCommitOutcome, McpRefreshClaimOutcome,
    McpRefreshClaimRequest, McpRefreshRenewOutcome, McpRefreshRenewRequest,
    StoredMcpOauthCredential, StoredMcpOauthFlow,
};

const STORAGE_OPERATION_ACTIVE: u8 = 0;
const STORAGE_OPERATION_CANCELLED: u8 = 1;
const STORAGE_OPERATION_COMMITTING: u8 = 2;
const STORAGE_OPERATION_FINISHED: u8 = 3;

#[derive(Debug)]
struct StorageOperationInner {
    name: &'static str,
    deadline: Instant,
    commit_deadline_policy: StorageCommitDeadlinePolicy,
    state: AtomicU8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageCommitDeadlinePolicy {
    Cancel,
    Reconcile { commit_timeout: Duration },
}

/// A deadline and commit fence shared by an async caller and its storage task.
///
/// Cancellation wins directly while the operation is active. Once the storage
/// task acquires the commit fence, callers preserve the operation token and
/// report only the authoritative result or explicit pending reconciliation.
/// Completion operations opt into late-result reconciliation.
#[derive(Debug, Clone)]
pub struct StorageOperation {
    inner: Arc<StorageOperationInner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOperationCancelOutcome {
    Cancelled,
    AlreadyCancelled,
    CommitStarted,
    Finished,
}

impl StorageOperation {
    pub fn new(name: &'static str, timeout: Duration) -> Self {
        Self::with_commit_deadline_policy(name, timeout, StorageCommitDeadlinePolicy::Cancel)
    }

    pub fn new_reconcilable_commit(
        name: &'static str,
        timeout: Duration,
        commit_timeout: Duration,
    ) -> Self {
        Self::with_commit_deadline_policy(
            name,
            timeout,
            StorageCommitDeadlinePolicy::Reconcile { commit_timeout },
        )
    }

    fn with_commit_deadline_policy(
        name: &'static str,
        timeout: Duration,
        commit_deadline_policy: StorageCommitDeadlinePolicy,
    ) -> Self {
        Self {
            inner: Arc::new(StorageOperationInner {
                name,
                deadline: Instant::now()
                    .checked_add(timeout)
                    .unwrap_or_else(Instant::now),
                commit_deadline_policy,
                state: AtomicU8::new(STORAGE_OPERATION_ACTIVE),
            }),
        }
    }

    pub fn name(&self) -> &'static str {
        self.inner.name
    }

    pub fn reconciles_commit_after_deadline(&self) -> bool {
        matches!(
            self.inner.commit_deadline_policy,
            StorageCommitDeadlinePolicy::Reconcile { .. }
        )
    }

    pub fn reconciliation_commit_timeout(&self) -> Option<Duration> {
        match self.inner.commit_deadline_policy {
            StorageCommitDeadlinePolicy::Cancel => None,
            StorageCommitDeadlinePolicy::Reconcile { commit_timeout } => Some(commit_timeout),
        }
    }

    pub fn cancel(&self) -> StorageOperationCancelOutcome {
        match self.inner.state.compare_exchange(
            STORAGE_OPERATION_ACTIVE,
            STORAGE_OPERATION_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => StorageOperationCancelOutcome::Cancelled,
            Err(STORAGE_OPERATION_CANCELLED) => StorageOperationCancelOutcome::AlreadyCancelled,
            Err(STORAGE_OPERATION_COMMITTING) => StorageOperationCancelOutcome::CommitStarted,
            Err(STORAGE_OPERATION_FINISHED) => StorageOperationCancelOutcome::Finished,
            Err(_) => StorageOperationCancelOutcome::AlreadyCancelled,
        }
    }

    pub fn remaining(&self, stage: &'static str) -> Result<Duration, StorageError> {
        match self.inner.state.load(Ordering::Acquire) {
            STORAGE_OPERATION_ACTIVE => {}
            STORAGE_OPERATION_CANCELLED => {
                return Err(StorageError::OperationCancelled {
                    operation: self.name(),
                    stage,
                });
            }
            STORAGE_OPERATION_COMMITTING | STORAGE_OPERATION_FINISHED => {
                return Err(StorageError::Runtime(format!(
                    "storage operation {} was reused after its commit fence",
                    self.name()
                )));
            }
            _ => unreachable!("invalid storage operation state"),
        }
        let Some(remaining) = self.inner.deadline.checked_duration_since(Instant::now()) else {
            let _ = self.cancel();
            return Err(StorageError::OperationDeadlineExceeded {
                operation: self.name(),
                stage,
                commit_started: false,
            });
        };
        if remaining.is_zero() {
            let _ = self.cancel();
            return Err(StorageError::OperationDeadlineExceeded {
                operation: self.name(),
                stage,
                commit_started: false,
            });
        }
        Ok(remaining)
    }

    pub fn check_active(&self, stage: &'static str) -> Result<(), StorageError> {
        self.remaining(stage).map(|_| ())
    }

    pub fn begin_commit(&self, stage: &'static str) -> Result<(), StorageError> {
        self.check_active(stage)?;
        match self.inner.state.compare_exchange(
            STORAGE_OPERATION_ACTIVE,
            STORAGE_OPERATION_COMMITTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(STORAGE_OPERATION_CANCELLED) => Err(StorageError::OperationCancelled {
                operation: self.name(),
                stage,
            }),
            Err(_) => Err(StorageError::Runtime(format!(
                "storage operation {} attempted to acquire its commit fence twice",
                self.name()
            ))),
        }
    }

    pub fn finish_commit(&self) {
        let _ = self.inner.state.compare_exchange(
            STORAGE_OPERATION_COMMITTING,
            STORAGE_OPERATION_FINISHED,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

mod budget_alerts;
pub use budget_alerts::{budget_alert_notification_id, StoredBudgetAlertNotification};

mod agent_schedule;
pub use agent_schedule::{
    agent_schedule_fire_id, compute_next_cron_fire_at, CatchupPolicy, OverlapPolicy, ScheduleError,
    ScheduleFireOutcome, ScheduleSpecKind, ScheduleTargetKind, StoredAgentSchedule,
    StoredAgentScheduleFire,
};

mod site_domain;
pub use site_domain::StoredSiteDomain;

// #357: durable, coalesced observed-agent presence backing the observed-agent
// -activity surface's "recent activity" (running) signal.
mod observed_agent_presence;
pub use observed_agent_presence::{
    observed_agent_presence_key, ObservedAgentPresenceTouch, StoredObservedAgentPresence,
};

mod metadata_rollups;
use metadata_rollups::increment_usage_metadata_rollups;
pub use metadata_rollups::{usage_metadata_rollup_id, StoredUsageMetadataRollup};

mod wallet;
pub use wallet::{
    payment_method_id, StoredPaymentMethod, StoredWallet, StoredWalletReservation,
    StoredWalletSettlement, WalletReservationResult, WalletReservationSettlement,
    WalletSettlementOutcome, WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_RELEASED,
    WALLET_RESERVATION_SETTLED,
};

mod payment_attempt;
pub use payment_attempt::{
    payment_attempt_state_is_terminal, PaymentAttemptCreation, PaymentAttemptEvidenceArgs,
    PaymentAttemptLinks, PaymentAttemptTransition, StoredPaymentAttempt,
    PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED, PAYMENT_ATTEMPT_DENIED,
    PAYMENT_ATTEMPT_EXPIRABLE_STATES, PAYMENT_ATTEMPT_FAILED, PAYMENT_ATTEMPT_INITIAL_STATES,
    PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_RECONCILABLE_STATES, PAYMENT_ATTEMPT_RELEASED,
    PAYMENT_ATTEMPT_SETTLED, PAYMENT_ATTEMPT_SUBMITTED,
};

mod workflow_budget;
pub use workflow_budget::{
    workflow_run_budget_id, StoredWorkflowRunBudget, WorkflowBudgetDebit, WorkflowBudgetDimension,
    WorkflowRunBudgetCaps, WORKFLOW_BUDGET_EXCEEDED_CODE, WORKFLOW_RUN_BUDGET_ACTIVE,
    WORKFLOW_RUN_BUDGET_EXHAUSTED,
};

// #263: asset lifecycle engine (version retention + unreferenced-blob GC).
mod asset_lifecycle;
pub use asset_lifecycle::{
    pinned_versions, plan_blob_gc, plan_log_retention, plan_version_retention, retention_policy_id,
    BucketObject, LogRetentionCandidate, RetentionPlan, RetentionPolicy, RetentionPruneTarget,
    StoredRetentionPolicy, RETENTION_RESOURCE_ASSET, RETENTION_RESOURCE_AUDIT_EVENT,
    RETENTION_RESOURCE_REQUEST_LOG, RETENTION_SCOPE_DEFAULT, RETENTION_SCOPE_RESPONSE_BODY,
};

mod guardrail_evidence;
use guardrail_evidence::StoredGuardrailEvidence;
pub use guardrail_evidence::{
    GuardrailEvaluationQuery, GuardrailEvaluationQueryPage, GuardrailEvaluationRepository,
    StoredGuardrailCheckEvaluation, StoredGuardrailEvaluation,
};

pub const DEFAULT_DURABLE_PROVIDER_ORDER: &[StorageProviderKind] =
    &[StorageProviderKind::Supabase, StorageProviderKind::Postgres];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProviderKind {
    #[default]
    Memory,
    Supabase,
    TursoLibsql,
    Postgres,
    Mysql,
}

impl StorageProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageProviderKind::Memory => "memory",
            StorageProviderKind::Supabase => "supabase",
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
                | StorageProviderKind::Supabase
                | StorageProviderKind::Postgres
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
    pub pool_acquire_timeout_millis: u64,
    pub tls_mode: PostgresTlsMode,
    pub tls_ca_cert_path: Option<String>,
    pub connect_timeout_secs: u64,
    pub statement_timeout_millis: u64,
    pub schema: Option<String>,
    pub search_path: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneDocuments {
    pub api_keys: Vec<(String, String)>,
    pub tenants: Vec<(String, String)>,
    pub policies: Vec<(String, String)>,
    pub gateway_configs: Vec<(String, String)>,
    pub agent_workflows: Vec<(String, String)>,
    pub skill_packages: Vec<(String, String)>,
    pub prompt_templates: Vec<(String, String)>,
    pub plugin_registrations: Vec<(String, String)>,
    pub mcp_servers: Vec<(String, String)>,
    pub agent_upstreams: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageMigrationSnapshot {
    pub control_plane: ControlPlaneDocuments,
    #[serde(default)]
    pub guardrail_policy_revisions: Vec<StoredGuardrailPolicyRevision>,
    #[serde(default)]
    pub guardrail_policy_bindings: Vec<StoredGuardrailPolicyBinding>,
    pub api_key_records: Vec<StoredApiKey>,
    pub tool_approvals: Vec<(String, String)>,
    pub billing_events: Vec<BillingEvent>,
    pub usage_aggregates: Vec<StoredUsageAggregate>,
    pub request_logs: Vec<StoredRequestLog>,
    pub audit_events: Vec<StoredAuditEvent>,
    pub agent_runs: Vec<StoredAgentRun>,
    pub agent_run_events: Vec<StoredAgentRunEvent>,
    pub managed_worker_templates: Vec<StoredManagedWorkerTemplate>,
    pub agent_worker_instances: Vec<StoredAgentWorkerInstance>,
    pub managed_worker_sessions: Vec<StoredManagedWorkerSession>,
    pub managed_worker_lifecycle_events: Vec<StoredManagedWorkerLifecycleEvent>,
    pub managed_worker_isolation_selections: Vec<StoredManagedWorkerIsolationSelection>,
    pub managed_worker_isolation_policies: Vec<StoredManagedWorkerIsolationPolicy>,
    pub managed_worker_isolation_evidence: Vec<StoredManagedWorkerIsolationEvidence>,
    pub self_hosted_worker_registrations: Vec<StoredSelfHostedWorkerRegistration>,
    pub self_hosted_worker_heartbeats: Vec<StoredSelfHostedWorkerHeartbeat>,
    pub self_hosted_worker_telemetry_events: Vec<StoredSelfHostedWorkerTelemetryEvent>,
    pub self_hosted_worker_artifacts: Vec<StoredSelfHostedWorkerArtifact>,
    pub self_hosted_worker_checkpoints: Vec<StoredSelfHostedWorkerCheckpoint>,
    pub self_hosted_run_dispatches: Vec<StoredSelfHostedRunDispatch>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMigrationCounts {
    pub api_keys: usize,
    pub api_key_records: usize,
    pub tenants: usize,
    pub policies: usize,
    pub gateway_configs: usize,
    pub agent_workflows: usize,
    pub skill_packages: usize,
    pub prompt_templates: usize,
    pub plugin_registrations: usize,
    pub mcp_servers: usize,
    pub agent_upstreams: usize,
    #[serde(default)]
    pub guardrail_policy_revisions: usize,
    #[serde(default)]
    pub guardrail_policy_bindings: usize,
    pub tool_approvals: usize,
    pub billing_events: usize,
    pub usage_aggregates: usize,
    pub request_logs: usize,
    pub audit_events: usize,
    pub agent_runs: usize,
    pub agent_run_events: usize,
    pub managed_worker_templates: usize,
    pub agent_worker_instances: usize,
    pub managed_worker_sessions: usize,
    pub managed_worker_lifecycle_events: usize,
    pub managed_worker_isolation_selections: usize,
    pub managed_worker_isolation_policies: usize,
    pub managed_worker_isolation_evidence: usize,
    pub self_hosted_worker_registrations: usize,
    pub self_hosted_worker_heartbeats: usize,
    pub self_hosted_worker_telemetry_events: usize,
    pub self_hosted_worker_artifacts: usize,
    pub self_hosted_worker_checkpoints: usize,
    pub self_hosted_run_dispatches: usize,
}

impl StorageMigrationSnapshot {
    pub fn counts(&self) -> StorageMigrationCounts {
        StorageMigrationCounts {
            api_keys: self.control_plane.api_keys.len(),
            api_key_records: self.api_key_records.len(),
            tenants: self.control_plane.tenants.len(),
            policies: self.control_plane.policies.len(),
            gateway_configs: self.control_plane.gateway_configs.len(),
            agent_workflows: self.control_plane.agent_workflows.len(),
            skill_packages: self.control_plane.skill_packages.len(),
            prompt_templates: self.control_plane.prompt_templates.len(),
            plugin_registrations: self.control_plane.plugin_registrations.len(),
            mcp_servers: self.control_plane.mcp_servers.len(),
            agent_upstreams: self.control_plane.agent_upstreams.len(),
            guardrail_policy_revisions: self.guardrail_policy_revisions.len(),
            guardrail_policy_bindings: self.guardrail_policy_bindings.len(),
            tool_approvals: self.tool_approvals.len(),
            billing_events: self.billing_events.len(),
            usage_aggregates: self.usage_aggregates.len(),
            request_logs: self.request_logs.len(),
            audit_events: self.audit_events.len(),
            agent_runs: self.agent_runs.len(),
            agent_run_events: self.agent_run_events.len(),
            managed_worker_templates: self.managed_worker_templates.len(),
            agent_worker_instances: self.agent_worker_instances.len(),
            managed_worker_sessions: self.managed_worker_sessions.len(),
            managed_worker_lifecycle_events: self.managed_worker_lifecycle_events.len(),
            managed_worker_isolation_selections: self.managed_worker_isolation_selections.len(),
            managed_worker_isolation_policies: self.managed_worker_isolation_policies.len(),
            managed_worker_isolation_evidence: self.managed_worker_isolation_evidence.len(),
            self_hosted_worker_registrations: self.self_hosted_worker_registrations.len(),
            self_hosted_worker_heartbeats: self.self_hosted_worker_heartbeats.len(),
            self_hosted_worker_telemetry_events: self.self_hosted_worker_telemetry_events.len(),
            self_hosted_worker_artifacts: self.self_hosted_worker_artifacts.len(),
            self_hosted_worker_checkpoints: self.self_hosted_worker_checkpoints.len(),
            self_hosted_run_dispatches: self.self_hosted_run_dispatches.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStorageOptions {
    pub provider_order: Vec<StorageProviderKind>,
    pub required: bool,
    pub initialize_schema: bool,
    pub migration_mode: String,
    pub control_plane: ControlPlaneDocuments,
    pub request_log_retention_records: usize,
    pub audit_event_retention_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackendEvidence {
    pub provider: StorageProviderKind,
    pub durable: bool,
    pub implemented: bool,
    pub required: bool,
    pub migration_mode: String,
    pub health: String,
    pub provider_order: Vec<StorageProviderKind>,
    pub contract_version: u32,
    pub schema: Option<StorageSchemaEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSchemaEvidence {
    pub engine: String,
    pub version: u64,
    pub name: String,
    pub checksum: String,
    pub validated: bool,
}

impl StorageSchemaEvidence {
    fn postgres_expected() -> Self {
        Self {
            engine: "postgres".into(),
            version: POSTGRES_SCHEMA_VERSION,
            name: POSTGRES_SCHEMA_NAME.into(),
            checksum: fnv1a64_hex(POSTGRES_SCHEMA_SQL),
            validated: true,
        }
    }
}

const POSTGRES_SCHEMA_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");

/// Global in-memory cap for `agent_run_events`, as a multiple of the per-run
/// cap (issue #231). Generous so eviction pressure on runs other than the
/// one being appended to only builds up across MANY distinct runs.
const AGENT_RUN_EVENT_GLOBAL_RETENTION_MULTIPLIER: usize = 8;

/// Durable (Postgres) retention pruning runs opportunistically on write,
/// every Nth write per table (issue #231). Between prunes a scope can
/// overshoot its retention bound by at most this many rows, which keeps the
/// hot ingest path from paying an indexed OFFSET scan on every single write.
const DURABLE_PRUNE_WRITE_INTERVAL: u64 = 32;
/// Current schema migration version; exported so the E2E harness asserts
/// against the runtime authority instead of a hardcoded copy.
pub const POSTGRES_SCHEMA_VERSION: u64 = 50;
pub const POSTGRES_SCHEMA_NAME: &str = "050_bucket_backed_asset_size_constraint";
const POSTGRES_SCHEMA_INITIALIZATION_TIMEOUT_MILLIS: u64 = 120_000;
const GUARDRAIL_POLICY_BINDING_INSERT_CAS_SQL: &str =
    "INSERT INTO guardrail_policy_bindings \
     (policy_id, active_revision, archived_revisions_json, updated_at_unix, updated_by, generation) \
     VALUES ($1, $2, $3::text::jsonb, $4, $5, $6) \
     ON CONFLICT (policy_id) DO NOTHING";
const GUARDRAIL_POLICY_BINDING_UPDATE_CAS_SQL: &str = "UPDATE guardrail_policy_bindings SET \
     active_revision = $2, archived_revisions_json = $3::text::jsonb, \
     updated_at_unix = $4, updated_by = $5, generation = $6 \
     WHERE policy_id = $1 AND generation = $7";
const GUARDRAIL_POLICY_BINDING_DELETE_CAS_SQL: &str =
    "DELETE FROM guardrail_policy_bindings WHERE policy_id = $1 AND generation = $2";
const GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE: &str =
    "guardrail policy binding changed concurrently";
const PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY: &str =
    "SELECT source_attribute.attname, target_namespace.nspname = current_schema(), \
            target_relation.relname, \
            target_attribute.attname, con.confdeltype::text \
     FROM pg_constraint AS con \
     JOIN pg_class AS source_relation ON source_relation.oid = con.conrelid \
     JOIN pg_namespace AS namespace ON namespace.oid = source_relation.relnamespace \
     JOIN pg_class AS target_relation ON target_relation.oid = con.confrelid \
     JOIN pg_namespace AS target_namespace ON target_namespace.oid = target_relation.relnamespace \
     JOIN unnest(con.conkey, con.confkey) \
          AS key(source_attnum, target_attnum) ON TRUE \
     JOIN pg_attribute AS source_attribute \
       ON source_attribute.attrelid = source_relation.oid \
      AND source_attribute.attnum = key.source_attnum \
     JOIN pg_attribute AS target_attribute \
       ON target_attribute.attrelid = target_relation.oid \
      AND target_attribute.attnum = key.target_attnum \
     WHERE namespace.nspname = current_schema() \
       AND source_relation.relname = $1 \
       AND con.conname = $2 AND con.contype = 'f'";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStorageBackend {
    provider: StorageProviderKind,
    required: bool,
    migration_mode: String,
    health: String,
    provider_order: Vec<StorageProviderKind>,
    contract_version: u32,
}

impl RuntimeStorageBackend {
    pub fn new(
        provider: StorageProviderKind,
        required: bool,
        provider_order: Vec<StorageProviderKind>,
    ) -> Result<Self, StorageError> {
        Self::new_with_migration_mode(provider, required, provider_order, "disabled".into())
    }

    pub fn new_with_migration_mode(
        provider: StorageProviderKind,
        required: bool,
        provider_order: Vec<StorageProviderKind>,
        migration_mode: String,
    ) -> Result<Self, StorageError> {
        if !provider.implemented() {
            return Err(StorageError::UnsupportedProvider { provider, required });
        }
        Ok(Self {
            provider,
            required,
            migration_mode,
            health: "ok".into(),
            provider_order,
            contract_version: 1,
        })
    }

    pub fn in_memory(provider_order: Vec<StorageProviderKind>) -> Self {
        Self {
            provider: StorageProviderKind::Memory,
            required: false,
            migration_mode: "disabled".into(),
            health: "ok".into(),
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
            migration_mode: self.migration_mode.clone(),
            health: self.health.clone(),
            provider_order: self.provider_order.clone(),
            contract_version: self.contract_version,
            schema: None,
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
    Postgres(String),
    Runtime(String),
    Serialization(String),
    Conflict(String),
    NotFound(String),
    OperationDeadlineExceeded {
        operation: &'static str,
        stage: &'static str,
        commit_started: bool,
    },
    OperationCancelled {
        operation: &'static str,
        stage: &'static str,
    },
    OperationCommitOutcomeUnknown {
        operation: &'static str,
        stage: &'static str,
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
            StorageError::Postgres(error) => write!(formatter, "postgres storage error: {error}"),
            StorageError::Runtime(error) => write!(formatter, "storage runtime error: {error}"),
            StorageError::Serialization(error) => {
                write!(formatter, "storage serialization error: {error}")
            }
            StorageError::Conflict(error) => write!(formatter, "storage conflict: {error}"),
            StorageError::NotFound(error) => write!(formatter, "storage record not found: {error}"),
            StorageError::OperationDeadlineExceeded {
                operation, stage, ..
            } => write!(
                formatter,
                "storage operation {operation} exceeded its deadline during {stage}"
            ),
            StorageError::OperationCancelled { operation, stage } => write!(
                formatter,
                "storage operation {operation} was cancelled during {stage}"
            ),
            StorageError::OperationCommitOutcomeUnknown { operation, stage } => write!(
                formatter,
                "storage operation {operation} has an unknown commit outcome after {stage}"
            ),
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

pub trait ManagedWorkerTemplateRepository: Repository<StoredManagedWorkerTemplate> {}

pub trait AgentWorkerInstanceRepository: Repository<StoredAgentWorkerInstance> {}

pub trait ManagedWorkerSessionRepository: Repository<StoredManagedWorkerSession> {}

pub trait ManagedWorkerLifecycleEventRepository:
    AppendRepository<StoredManagedWorkerLifecycleEvent>
{
}

pub trait SelfHostedWorkerRegistrationRepository:
    Repository<StoredSelfHostedWorkerRegistration>
{
}

pub trait SelfHostedWorkerHeartbeatRepository:
    AppendRepository<StoredSelfHostedWorkerHeartbeat>
{
}

pub trait SelfHostedWorkerTelemetryEventRepository:
    AppendRepository<StoredSelfHostedWorkerTelemetryEvent>
{
}

pub trait SelfHostedWorkerArtifactRepository: Repository<StoredSelfHostedWorkerArtifact> {}

pub trait SelfHostedWorkerCheckpointRepository:
    Repository<StoredSelfHostedWorkerCheckpoint>
{
}

pub trait SelfHostedRunDispatchRepository: Repository<StoredSelfHostedRunDispatch> {}

pub trait GuardrailPolicyRepository {
    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError>;

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError>;

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError>;

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError>;

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError>;

    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError>;

    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError>;

    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError>;
}

/// Durable replay floor for signed control-plane snapshots (#206): the highest
/// snapshot revision a node has accepted (verified+activated or self-published)
/// per `(tenant_id, deployment_id)` identity. Persisting it means a process
/// restart does NOT reset the floor to zero, so an attacker with shared-file
/// write access cannot replay an authentically-signed OLDER snapshot in the
/// post-restart window (the previously documented bounded-rollback gap).
pub trait SnapshotReplayFloorRepository {
    /// The persisted floor for an identity, or `None` if never recorded.
    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError>;

    /// Monotonically raise the persisted floor to at least `revision` and
    /// return the resulting floor. Never moves the floor backward: a
    /// lower-than-stored `revision` leaves the stored value untouched (also
    /// race-safe across concurrent writers via a `GREATEST` upsert on the
    /// Postgres backend).
    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError>;
}

/// Composite in-memory key for a snapshot replay floor. Length-prefixed so two
/// distinct `(tenant_id, deployment_id)` pairs can never collide regardless of
/// which characters the ids contain (a bare delimiter would alias
/// `("a", "b<sep>c")` with `("a<sep>b", "c")`).
fn snapshot_replay_floor_key(tenant_id: &str, deployment_id: &str) -> String {
    format!(
        "{}:{tenant_id}|{}:{deployment_id}",
        tenant_id.len(),
        deployment_id.len()
    )
}

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
pub struct StoredGuardrailPolicyRevision {
    pub id: String,
    pub policy_id: String,
    pub revision: u32,
    pub policy_json: String,
    pub created_at_unix: u64,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGuardrailPolicyBinding {
    pub policy_id: String,
    pub active_revision: Option<u32>,
    pub archived_revisions: Vec<u32>,
    pub updated_at_unix: u64,
    pub updated_by: String,
    #[serde(default)]
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailPolicyBindingTransition {
    pub previous: Option<StoredGuardrailPolicyBinding>,
    pub current: StoredGuardrailPolicyBinding,
}

pub fn guardrail_policy_revision_id(policy_id: &str, revision: u32) -> String {
    format!("{policy_id}@{revision}")
}

pub fn is_guardrail_policy_binding_cas_conflict(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::Conflict(message)
            if message == GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE
    )
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
    pub agent_upstreams: Vec<String>,
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
    /// #304 action-identity columns (all optional; NULL on rows recorded
    /// before migration 045 or by paths without capability evidence):
    /// target-level fingerprint under the `canonical_target_sha256` contract
    /// (`"sha256:<hex>"`, `ferrogate_runtime::ACTION_FINGERPRINT_CONTRACT`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_fingerprint: Option<String>,
    /// Canonical decision class: `"allow"` / `"deny"` / `"ask"` / `"degrade"`
    /// (`ferrogate_runtime::ActionDecision::class_label`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Stable decision reason code (`ferrogate_runtime::ActionDecision::code`),
    /// e.g. `"capability_allowed"` or `"guardrail:fail:block:enforced"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    /// Structured output disposition: `"returned"` / `"redacted"` /
    /// `"withheld"` / `"errored"` (`ferrogate_runtime::OutputDisposition`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_disposition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerTemplate {
    pub id: String,
    pub framework_adapter: String,
    pub isolation_backend_kind: String,
    pub enabled: bool,
    pub max_tenant_sessions: Option<u32>,
    pub max_workspace_sessions: Option<u32>,
    pub created_at_unix: Option<u64>,
    pub updated_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentWorkerInstance {
    pub id: String,
    pub process_name: String,
    pub host_id: Option<String>,
    pub worker_version: Option<String>,
    pub status: String,
    pub started_at_unix: Option<u64>,
    pub last_seen_at_unix: Option<u64>,
    pub process_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerSession {
    pub id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub worker_template_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub status: String,
    pub isolation_backend_kind: String,
    pub microvm_id: Option<String>,
    pub capability_envelope_id: String,
    pub requested_at_unix: Option<u64>,
    pub started_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
    pub cleanup_completed_at_unix: Option<u64>,
    pub capability_envelope_json: String,
    pub resource_limits_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerLifecycleEvent {
    pub id: String,
    pub session_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub status: String,
    pub action: String,
    pub outcome: String,
    pub occurred_at_unix: Option<u64>,
    pub evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationSelection {
    pub session_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub backend_name: String,
    pub backend_version: String,
    pub backend_kind: String,
    pub host_lifecycle_owner: String,
    pub gateway_controls_backend: bool,
    pub capability_envelope_id: String,
    pub selected_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationPolicy {
    pub session_id: String,
    pub cpu_count: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub max_runtime_millis: Option<u64>,
    pub direct_public_egress: bool,
    pub gateway_control_channel: bool,
    pub governed_egress: bool,
    pub read_only_rootfs: bool,
    pub writable_workspace: bool,
    pub host_path_mounts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManagedWorkerIsolationEvidence {
    pub id: String,
    pub session_id: String,
    pub lifecycle_event_id: String,
    pub run_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub agent_worker_instance_id: Option<String>,
    pub isolation_instance_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub occurred_at_unix: Option<u64>,
    pub evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerRegistration {
    pub id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub worker_name: String,
    pub status: String,
    pub identity_fingerprint: String,
    pub identity_expires_at_unix: Option<u64>,
    pub orchestration_enabled: bool,
    pub registered_at_unix: Option<u64>,
    pub last_seen_at_unix: Option<u64>,
    pub trust_level: String,
    pub capability_envelope_json: String,
    /// High-entropy secret keying the symmetric-AEAD transport (and bearer
    /// check), provisioned server-side at registration/rotation. Distinct from
    /// the public `identity_fingerprint`. `#[serde(default)]` keeps rows written
    /// before this field existed loadable; an empty secret fails closed (the
    /// transport rejects a secret shorter than the required minimum).
    #[serde(default)]
    pub token_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerHeartbeat {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub status: String,
    pub reported_at_unix: Option<u64>,
    pub observed_at_unix: Option<u64>,
    pub heartbeat_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerTelemetryEvent {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub kind: String,
    pub trust_level: String,
    pub occurred_at_unix: Option<u64>,
    pub ingested_at_unix: Option<u64>,
    pub event_json: String,
    /// #329: the dispatch lease's correlation identity, stamped by the
    /// self-hosted worker onto the evidence it reports for the run. These are
    /// the SAME {request_id, trace_id, agent_run_id} triple (#305) and
    /// `parent_action_fingerprint` (#307) the control plane persisted on the
    /// dispatch (`self_hosted_run_dispatches`), so worker-reported evidence
    /// joins the investigation view + `action_correlations` by the same keys
    /// instead of relying on gateway-side back-fill. All `None` for a keyless
    /// dispatch (report-only / background tick) — never fabricated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_action_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerArtifact {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub artifact_name: String,
    pub content_type: Option<String>,
    pub size_bytes: u64,
    pub trust_level: String,
    pub created_at_unix: Option<u64>,
    pub artifact_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedWorkerCheckpoint {
    pub id: String,
    pub worker_id: String,
    pub tenant: TenantContext,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub checkpoint_name: String,
    pub size_bytes: u64,
    pub trust_level: String,
    pub created_at_unix: Option<u64>,
    pub checkpoint_json: String,
}

/// Per-worker activity aggregates for the admin worker record (issue #231):
/// computed with worker-filtered queries instead of loading the telemetry /
/// artifact / checkpoint tables wholesale.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredSelfHostedWorkerActivityStats {
    pub telemetry_event_count: usize,
    pub artifact_count: usize,
    pub checkpoint_count: usize,
    pub latest_event_at_unix: Option<u64>,
    pub latest_artifact_at_unix: Option<u64>,
    pub latest_checkpoint_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSelfHostedRunDispatch {
    pub dispatch_id: String,
    pub action: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub run_id: String,
    pub framework_adapter: String,
    pub required_capabilities: Vec<String>,
    pub workload_ref: String,
    pub queued_at_unix: Option<u64>,
    pub assigned_worker_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_expires_at_unix: Option<u64>,
    pub attempt: u32,
    pub acknowledged_status: Option<String>,
    pub acknowledged_at_unix: Option<u64>,
    /// #305 correlation keys (migration 046, all optional; NULL on rows
    /// persisted before the migration and on dispatches created outside any
    /// inbound request): `request_id`/`trace_id` of the dispatching request
    /// (e.g. the admin run-now trigger), `agent_run_id` of the agent run this
    /// dispatch starts/controls — so dispatch leases join timeline/audit/
    /// approval evidence on the same {request_id, trace_id, agent_run_id}
    /// triple. `serde(default)` keeps legacy snapshots readable;
    /// `skip_serializing_if` keeps legacy JSON byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_run_id: Option<String>,
    /// #307 handoff parent identity (migration 048, optional): the
    /// `canonical_target_sha256` fingerprint (`"sha256:<hex>"`) of the
    /// UPSTREAM governed action this dispatch is a downstream effect of — the
    /// same value the parent's timeline/audit/guardrail/approval rows carry,
    /// NOT this dispatch's own identity. NULL on rows persisted before the
    /// migration and on dispatches created outside any governed-action
    /// context (registry seed, scheduler tick, admin run-now) — never
    /// fabricated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_action_fingerprint: Option<String>,
}

#[derive(Debug)]
pub struct RuntimeControlPlaneState {
    api_keys: InMemoryRepository<StoredControlPlaneResource>,
    api_key_records: InMemoryRepository<StoredApiKey>,
    tenants: InMemoryRepository<StoredControlPlaneResource>,
    policies: InMemoryRepository<StoredControlPlaneResource>,
    gateway_configs: InMemoryRepository<StoredControlPlaneResource>,
    agent_workflows: InMemoryRepository<StoredControlPlaneResource>,
    skill_packages: InMemoryRepository<StoredControlPlaneResource>,
    prompt_templates: InMemoryRepository<StoredControlPlaneResource>,
    plugin_registrations: InMemoryRepository<StoredControlPlaneResource>,
    mcp_servers: InMemoryRepository<StoredControlPlaneResource>,
    agent_upstreams: InMemoryRepository<StoredControlPlaneResource>,
    tool_approvals: InMemoryRepository<StoredControlPlaneResource>,
    tenant_accounts: InMemoryRepository<StoredTenantAccount>,
    projects: InMemoryRepository<StoredProject>,
    workspaces: InMemoryRepository<StoredWorkspace>,
    admin_users: InMemoryRepository<StoredAdminUser>,
    admin_user_memberships: InMemoryRepository<StoredAdminUserMembership>,
    admin_user_refresh_tokens: InMemoryRepository<StoredAdminUserRefreshToken>,
    /// Per-tenant SSO configuration keyed by `tenant_id` (#283).
    sso_provider_configs: InMemoryRepository<StoredSsoProviderConfig>,
    /// In-flight SSO authorize->callback state keyed by the `state` token (#283).
    sso_pending_flows: InMemoryRepository<StoredSsoPendingFlow>,
    quota_policies: InMemoryRepository<StoredQuotaPolicy>,
    plans: InMemoryRepository<StoredPlan>,
    assets: InMemoryRepository<StoredAsset>,
    /// Mutable channel pointers keyed by `asset_channel_id` (#260).
    asset_channels: InMemoryRepository<StoredAssetChannel>,
    permissions: InMemoryRepository<StoredPermission>,
    roles: InMemoryRepository<StoredRole>,
    tenant_role_bindings: InMemoryRepository<StoredTenantRoleBinding>,
    usage_monthly_rollups: InMemoryRepository<StoredUsageMonthlyRollup>,
    billing_report_outbox: InMemoryRepository<StoredBillingReportOutboxEntry>,
    budget_alert_notifications: InMemoryRepository<StoredBudgetAlertNotification>,
    usage_metadata_rollups: InMemoryRepository<StoredUsageMetadataRollup>,
    billing_event_ids: InMemoryRepository<BillingEvent>,
    wallets: InMemoryRepository<StoredWallet>,
    wallet_settlements: InMemoryRepository<StoredWalletSettlement>,
    // #281: durable reserve/hold rows keyed by reservation id.
    wallet_reservations: InMemoryRepository<StoredWalletReservation>,
    // #352: durable x402 payment attempts keyed by attempt/idempotency id.
    payment_attempts: InMemoryRepository<StoredPaymentAttempt>,
    payment_methods: InMemoryRepository<StoredPaymentMethod>,
    guardrail_policy_revisions: InMemoryRepository<StoredGuardrailPolicyRevision>,
    guardrail_policy_bindings: InMemoryRepository<StoredGuardrailPolicyBinding>,
    mcp_oauth_authorization_generations: InMemoryRepository<u64>,
    mcp_oauth_flows: InMemoryRepository<StoredMcpOauthFlow>,
    mcp_oauth_credentials: InMemoryRepository<StoredMcpOauthCredential>,
    /// Signed-snapshot replay floors keyed by
    /// `snapshot_replay_floor_key(tenant_id, deployment_id)` (#206).
    snapshot_replay_floors: InMemoryRepository<u64>,
    /// Time-based agent schedule definitions keyed by `schedule_id` (#246).
    agent_schedules: InMemoryRepository<StoredAgentSchedule>,
    /// Idempotent fire-history ledger keyed by `fire_id` (#246).
    agent_schedule_fires: InMemoryRepository<StoredAgentScheduleFire>,
    /// Durable per-workflow-run execution budgets keyed by
    /// `workflow_run_budget_id(workflow_id, version, run_id)` (#279).
    workflow_run_budgets: InMemoryRepository<StoredWorkflowRunBudget>,
    /// Generalizable retention rules keyed by
    /// `retention_policy_id(tenant_id, resource_type, scope)` (#263).
    retention_policies: InMemoryRepository<StoredRetentionPolicy>,
    /// Custom-domain -> static-site bindings keyed by hostname (#265).
    site_domains: InMemoryRepository<StoredSiteDomain>,
    /// Durable coalesced virtual-key presence keyed by
    /// `observed_agent_presence_key(tenant_id, api_key_id)` (#357).
    observed_agent_presence: InMemoryRepository<StoredObservedAgentPresence>,
}

struct PostgresControlPlaneStore {
    async_pool: Arc<async_postgres::AsyncPostgresPool>,
    schema: StorageSchemaEvidence,
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
        bootstrap: ControlPlaneDocuments,
        initialize_schema: bool,
    ) -> Result<Self, StorageError> {
        let schema_timeout_millis = config
            .statement_timeout_millis
            .max(POSTGRES_SCHEMA_INITIALIZATION_TIMEOUT_MILLIS);
        let async_pool = Arc::new(async_postgres::AsyncPostgresPool::new(&config)?);
        let store = Self {
            async_pool,
            schema: StorageSchemaEvidence::postgres_expected(),
        };
        if initialize_schema {
            block_on_sync_bridge(store.initialize_schema(schema_timeout_millis))?;
        }
        block_on_sync_bridge(store.validate_schema())?;
        block_on_sync_bridge(store.seed_missing_resources("api_key", bootstrap.api_keys))?;
        block_on_sync_bridge(store.seed_missing_resources("tenant", bootstrap.tenants))?;
        block_on_sync_bridge(store.seed_missing_resources("policy", bootstrap.policies))?;
        block_on_sync_bridge(
            store.seed_missing_resources("gateway_config", bootstrap.gateway_configs),
        )?;
        block_on_sync_bridge(
            store.seed_missing_resources("agent_workflow", bootstrap.agent_workflows),
        )?;
        block_on_sync_bridge(
            store.seed_missing_resources("skill_package", bootstrap.skill_packages),
        )?;
        block_on_sync_bridge(
            store.seed_missing_resources("prompt_template", bootstrap.prompt_templates),
        )?;
        block_on_sync_bridge(
            store.seed_missing_resources("plugin_registration", bootstrap.plugin_registrations),
        )?;
        block_on_sync_bridge(store.seed_missing_resources("mcp_server", bootstrap.mcp_servers))?;
        block_on_sync_bridge(
            store.seed_missing_resources("agent_upstream", bootstrap.agent_upstreams),
        )?;
        Ok(store)
    }

    fn connect_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        let schema_timeout_millis = config
            .statement_timeout_millis
            .max(POSTGRES_SCHEMA_INITIALIZATION_TIMEOUT_MILLIS);
        let async_pool = Arc::new(async_postgres::AsyncPostgresPool::new(&config)?);
        let store = Self {
            async_pool,
            schema: StorageSchemaEvidence::postgres_expected(),
        };
        if initialize_schema {
            block_on_sync_bridge(store.initialize_schema(schema_timeout_millis))?;
        }
        if validate_schema {
            block_on_sync_bridge(store.validate_schema())?;
        }
        Ok(store)
    }

    fn document_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn initialize_schema(&self, statement_timeout_millis: u64) -> Result<(), StorageError> {
        let statement_timeout = format!("{statement_timeout_millis}ms");
        // Schema DDL runs under an advisory-locked transaction and can take a
        // while on a cold database, so the pool-acquire/commit deadline uses the
        // (longer) schema-initialization timeout rather than the default
        // statement timeout.
        let operation = StorageOperation::new(
            "initialize schema",
            Duration::from_millis(statement_timeout_millis),
        );
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        transaction
            .query_one(
                "SELECT set_config('statement_timeout', $1, true)",
                &[&statement_timeout],
            )
            .await
            .map_err(postgres_error)?;
        transaction
            .query_one(
                "SELECT set_config('lock_timeout', $1, true)",
                &[&statement_timeout],
            )
            .await
            .map_err(postgres_error)?;
        // Key the advisory lock on the CONFIGURED schema (not the connection's
        // default `current_schema()`), so two gateways initializing different
        // schemas on one database do not serialize on each other while two
        // initializing the same schema do.
        let configured_schema = self.async_pool.configured_schema().map(str::to_string);
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(\
                    hashtextextended(\
                        current_database() || ':' || COALESCE($1, current_schema()), 0\
                    )\
                 )",
                &[&configured_schema],
            )
            .await
            .map_err(postgres_error)?;
        // Route the schema DDL into the configured `postgres_schema`. The sync
        // driver used to do this per-session (`CREATE SCHEMA IF NOT EXISTS ...;
        // SET search_path ...`); the async pool (#221) intentionally pins
        // `search_path` per-transaction instead, so the DDL transaction must
        // pin it too -- otherwise every unqualified `CREATE TABLE` in
        // `POSTGRES_SCHEMA_SQL` lands in the connection-default schema
        // (`public`) and the configured schema is silently left empty.
        if let Some(schema) = configured_schema.as_deref() {
            transaction
                .batch_execute(&format!(
                    "CREATE SCHEMA IF NOT EXISTS {}",
                    quote_postgres_identifier(schema)
                ))
                .await
                .map_err(postgres_error)?;
        }
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .batch_execute(POSTGRES_SCHEMA_SQL)
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn validate_schema(&self) -> Result<(), StorageError> {
        let operation = self.document_operation("validate schema");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Validate against the same search path every data query pins
        // (`"<postgres_schema>", <search_path...>`): `to_regclass` /
        // `current_schema()` then resolve exactly the tables the gateway will
        // read and write at runtime. Without the pin, validation resolved the
        // connection-default schema (`public`) and could pass while the
        // configured schema was empty (or vice versa).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        // `&*transaction` derefs the deadpool wrapper to the underlying
        // `tokio_postgres::Transaction`, which implements `GenericClient`.
        validate_postgres_schema(&*transaction).await?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    fn schema_evidence(&self) -> StorageSchemaEvidence {
        self.schema.clone()
    }

    async fn seed_missing_resources(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let operation = self.document_operation("seed missing resources");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` before touching
        // `control_plane_resources`, exactly like the #237/mcp-identity path. A
        // bare pooled-client query resolves the table against the connection's
        // default schema (`public` on stock Supabase roles), splitting control
        // plane state across schemas when `postgres_schema` is non-default (#238).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        for (id, document_json) in records {
            transaction
                .execute(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3::text::jsonb) \
                     ON CONFLICT (resource_kind, resource_id) DO NOTHING",
                    &[&kind, &id, &document_json],
                )
                .await
                .map_err(postgres_error)?;
        }
        transaction.commit().await.map_err(postgres_error)?;
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
            agent_upstreams: self.list_documents("agent_upstream").await?,
        })
    }

    async fn documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(ControlPlaneDocuments {
            api_keys: self.list_resource_documents("api_key").await?,
            tenants: self.list_resource_documents("tenant").await?,
            policies: self.list_resource_documents("policy").await?,
            gateway_configs: self.list_resource_documents("gateway_config").await?,
            agent_workflows: self.list_resource_documents("agent_workflow").await?,
            skill_packages: self.list_resource_documents("skill_package").await?,
            prompt_templates: self.list_resource_documents("prompt_template").await?,
            plugin_registrations: self.list_resource_documents("plugin_registration").await?,
            mcp_servers: self.list_resource_documents("mcp_server").await?,
            agent_upstreams: self.list_resource_documents("agent_upstream").await?,
        })
    }

    async fn list_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let operation = self.document_operation("list resource documents");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `control_plane_resources` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT resource_id, document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 ORDER BY resource_id ASC",
                &[&kind],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect())
    }

    async fn list_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        let operation = self.document_operation("list documents");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `control_plane_resources` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 ORDER BY resource_id ASC",
                &[&kind],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect())
    }

    async fn get_document(
        &self,
        kind: &'static str,
        id: String,
    ) -> Result<Option<String>, StorageError> {
        let operation = self.document_operation("get document");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `control_plane_resources` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT document_json::text FROM control_plane_resources \
                 WHERE resource_kind = $1 AND resource_id = $2",
                &[&kind, &id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    async fn upsert(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        let operation = self.document_operation("upsert control plane document");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `control_plane_resources` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO control_plane_resources \
                 (resource_kind, resource_id, document_json, revision, updated_at_unix) \
                 VALUES ($1, $2, $3::text::jsonb, 1, EXTRACT(EPOCH FROM NOW())::BIGINT) \
                 ON CONFLICT (resource_kind, resource_id) DO UPDATE SET \
                 document_json = EXCLUDED.document_json, \
                 revision = control_plane_resources.revision + 1, \
                 updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
                &[&kind, &id, &document_json],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn replace_kind(
        &self,
        kind: &'static str,
        records: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let operation = self.document_operation("replace control plane kind");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        // Pin `search_path` to the configured `postgres_schema` (#238) before the
        // delete/insert so `control_plane_resources` resolves in the same schema
        // as the rest of the control plane, not the connection default.
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "DELETE FROM control_plane_resources WHERE resource_kind = $1",
                &[&kind],
            )
            .await
            .map_err(postgres_error)?;
        for (id, document_json) in records {
            transaction
                .execute(
                    "INSERT INTO control_plane_resources \
                     (resource_kind, resource_id, document_json) VALUES ($1, $2, $3::text::jsonb)",
                    &[&kind, &id, &document_json],
                )
                .await
                .map_err(postgres_error)?;
        }
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn delete(&self, kind: &'static str, id: String) -> Result<bool, StorageError> {
        let operation = self.document_operation("delete control plane document");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `control_plane_resources` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows_changed = transaction
            .execute(
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = $1 AND resource_id = $2",
                &[&kind, &id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows_changed > 0)
    }

    fn guardrail_policy_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    /// #206: the persisted signed-snapshot replay floor for an identity.
    async fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        let operation = self.guardrail_policy_operation("get snapshot replay floor");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Run inside a transaction that pins `search_path` to the configured
        // `postgres_schema`, exactly like the mcp-identity control-plane path.
        // A bare query would resolve `control_plane_replay_floors` against the
        // connection's default schema (`public` on stock Supabase roles), so the
        // durable #206 replay floor could silently split from the rest of the
        // control plane when `postgres_schema` is non-default (#237).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT last_accepted_revision FROM control_plane_replay_floors \
                 WHERE tenant_id = $1 AND deployment_id = $2",
                &[&tenant_id, &deployment_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(|row| {
            let value: i64 = row.get(0);
            u64::try_from(value).unwrap_or(0)
        }))
    }

    /// #206: monotonically raise the persisted replay floor. The `GREATEST`
    /// upsert makes concurrent writers race-safe and guarantees the stored
    /// floor never moves backward; returns the resulting floor.
    async fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        let revision = i64::try_from(revision).map_err(|_| {
            StorageError::Runtime(format!(
                "snapshot replay floor revision {revision} exceeds the storable range"
            ))
        })?;
        let operation = self.guardrail_policy_operation("advance snapshot replay floor");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` for the upsert so
        // the persisted replay floor lands in the same schema as the rest of the
        // control plane, not the connection default (#237).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_one(
                "INSERT INTO control_plane_replay_floors \
                 (tenant_id, deployment_id, last_accepted_revision, updated_at_unix) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (tenant_id, deployment_id) DO UPDATE SET \
                     last_accepted_revision = GREATEST( \
                         control_plane_replay_floors.last_accepted_revision, \
                         EXCLUDED.last_accepted_revision), \
                     updated_at_unix = CASE \
                         WHEN EXCLUDED.last_accepted_revision > \
                              control_plane_replay_floors.last_accepted_revision \
                         THEN EXCLUDED.updated_at_unix \
                         ELSE control_plane_replay_floors.updated_at_unix END \
                 RETURNING last_accepted_revision",
                &[&tenant_id, &deployment_id, &revision, &updated_at_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let value: i64 = row.get(0);
        Ok(u64::try_from(value).unwrap_or(0))
    }

    async fn insert_guardrail_policy_revision(
        &self,
        revision: &StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        let revision_number = i64::from(revision.revision);
        let created_at_unix = saturating_i64(revision.created_at_unix);
        let operation = self.guardrail_policy_operation("insert guardrail policy revision");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let changed = transaction
            .execute(
                "INSERT INTO guardrail_policy_revisions \
                 (policy_id, revision, immutable_id, created_at_unix, created_by, policy_json) \
                 VALUES ($1, $2, $3, $4, $5, $6::text::jsonb) \
                 ON CONFLICT (policy_id, revision) DO NOTHING",
                &[
                    &revision.policy_id,
                    &revision_number,
                    &revision.id,
                    &created_at_unix,
                    &revision.created_by,
                    &revision.policy_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        if changed == 0 {
            return Err(StorageError::Conflict(format!(
                "guardrail policy revision {} already exists",
                revision.id
            )));
        }
        Ok(())
    }

    async fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        let revision = i64::from(revision);
        let operation = self.guardrail_policy_operation("get guardrail policy revision");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT immutable_id, policy_id, revision, policy_json::text, \
                        created_at_unix, created_by \
                 FROM guardrail_policy_revisions \
                 WHERE policy_id = $1 AND revision = $2",
                &[&policy_id, &revision],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.map(guardrail_policy_revision_from_row).transpose()
    }

    async fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        let operation = self.guardrail_policy_operation("list guardrail policy revisions");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = match policy_id {
            Some(policy_id) => {
                transaction
                    .query(
                        "SELECT immutable_id, policy_id, revision, policy_json::text, \
                                created_at_unix, created_by \
                         FROM guardrail_policy_revisions WHERE policy_id = $1 \
                         ORDER BY policy_id ASC, revision ASC",
                        &[&policy_id],
                    )
                    .await
            }
            None => {
                transaction
                    .query(
                        "SELECT immutable_id, policy_id, revision, policy_json::text, \
                                created_at_unix, created_by \
                         FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC",
                        &[],
                    )
                    .await
            }
        }
        .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.into_iter()
            .map(guardrail_policy_revision_from_row)
            .collect()
    }

    async fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        let operation = self.guardrail_policy_operation("get guardrail policy binding");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT policy_id, active_revision, archived_revisions_json::text, \
                        updated_at_unix, updated_by, generation \
                 FROM guardrail_policy_bindings WHERE policy_id = $1",
                &[&policy_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.map(guardrail_policy_binding_from_row).transpose()
    }

    async fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        let operation = self.guardrail_policy_operation("list guardrail policy bindings");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT policy_id, active_revision, archived_revisions_json::text, \
                        updated_at_unix, updated_by, generation \
                 FROM guardrail_policy_bindings ORDER BY policy_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.into_iter()
            .map(guardrail_policy_binding_from_row)
            .collect()
    }

    async fn compare_and_swap_guardrail_policy_binding(
        &self,
        expected_generation: Option<u64>,
        current: &StoredGuardrailPolicyBinding,
    ) -> Result<(), StorageError> {
        let active_revision = current.active_revision.map(i64::from);
        let archived_json = serialize_storage_document(&current.archived_revisions)?;
        let updated_at_unix = saturating_i64(current.updated_at_unix);
        let current_generation = guardrail_binding_generation_i64(current.generation)?;
        let operation =
            self.guardrail_policy_operation("compare and swap guardrail policy binding");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let changed = match expected_generation {
            Some(expected_generation) => {
                let expected_generation = guardrail_binding_generation_i64(expected_generation)?;
                transaction
                    .execute(
                        GUARDRAIL_POLICY_BINDING_UPDATE_CAS_SQL,
                        &[
                            &current.policy_id,
                            &active_revision,
                            &archived_json,
                            &updated_at_unix,
                            &current.updated_by,
                            &current_generation,
                            &expected_generation,
                        ],
                    )
                    .await
                    .map_err(postgres_error)?
            }
            None => transaction
                .execute(
                    GUARDRAIL_POLICY_BINDING_INSERT_CAS_SQL,
                    &[
                        &current.policy_id,
                        &active_revision,
                        &archived_json,
                        &updated_at_unix,
                        &current.updated_by,
                        &current_generation,
                    ],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        if changed != 1 {
            return Err(StorageError::Conflict(
                GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.into(),
            ));
        }
        Ok(())
    }

    async fn delete_guardrail_policy_binding_cas(
        &self,
        policy_id: &str,
        expected_generation: u64,
    ) -> Result<(), StorageError> {
        let expected_generation = guardrail_binding_generation_i64(expected_generation)?;
        let operation = self.guardrail_policy_operation("delete guardrail policy binding cas");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let changed = transaction
            .execute(
                GUARDRAIL_POLICY_BINDING_DELETE_CAS_SQL,
                &[&policy_id, &expected_generation],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        if changed != 1 {
            return Err(StorageError::Conflict(
                GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.into(),
            ));
        }
        Ok(())
    }

    async fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        let revision_number = i64::from(revision);
        let operation =
            self.guardrail_policy_operation("check guardrail policy revision exists (activate)");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let revision_exists = transaction
            .query_opt(
                "SELECT 1 FROM guardrail_policy_revisions \
                 WHERE policy_id = $1 AND revision = $2",
                &[&policy_id, &revision_number],
            )
            .await
            .map_err(postgres_error)?
            .is_some();
        transaction.commit().await.map_err(postgres_error)?;
        if !revision_exists {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                guardrail_policy_revision_id(policy_id, revision)
            )));
        }

        let previous = self.get_guardrail_policy_binding(policy_id).await?;
        let current = next_guardrail_activation_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
            rollback_only,
        )?;
        self.compare_and_swap_guardrail_policy_binding(
            previous.as_ref().map(|binding| binding.generation),
            &current,
        )
        .await?;
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    async fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        let revision_number = i64::from(revision);
        let operation =
            self.guardrail_policy_operation("check guardrail policy revision exists (archive)");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let revision_exists = transaction
            .query_opt(
                "SELECT 1 FROM guardrail_policy_revisions \
                 WHERE policy_id = $1 AND revision = $2",
                &[&policy_id, &revision_number],
            )
            .await
            .map_err(postgres_error)?
            .is_some();
        transaction.commit().await.map_err(postgres_error)?;
        if !revision_exists {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                guardrail_policy_revision_id(policy_id, revision)
            )));
        }

        let previous = self.get_guardrail_policy_binding(policy_id).await?;
        let current = next_guardrail_archive_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
        )?;
        self.compare_and_swap_guardrail_policy_binding(
            previous.as_ref().map(|binding| binding.generation),
            &current,
        )
        .await?;
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    async fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<&StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        match binding {
            Some(binding) => {
                let mut restored = binding.clone();
                restored.generation =
                    next_guardrail_binding_generation(expected_generation.unwrap_or_default())?;
                self.compare_and_swap_guardrail_policy_binding(expected_generation, &restored)
                    .await
            }
            None => {
                self.delete_guardrail_policy_binding_cas(
                    policy_id,
                    expected_generation.ok_or_else(|| {
                        StorageError::Conflict(GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.into())
                    })?,
                )
                .await
            }
        }
    }

    fn tenancy_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn upsert_api_key_record(&self, api_key: &StoredApiKey) -> Result<(), StorageError> {
        let scopes_json = serialize_storage_document(&api_key.scopes)?;
        let allowed_models_json = serialize_storage_document(&api_key.allowed_models)?;
        let allowed_providers_json = serialize_storage_document(&api_key.allowed_providers)?;
        let monthly_token_budget = api_key.monthly_token_budget.map(saturating_i64);
        let request_limit_per_minute = api_key.request_limit_per_minute.map(saturating_i64);
        let created_at_unix = saturating_i64(api_key.created_at_unix);
        let updated_at_unix = saturating_i64(api_key.updated_at_unix);
        let rotated_at_unix = api_key.rotated_at_unix.map(saturating_i64);
        let expires_at_unix = api_key.expires_at_unix.map(saturating_i64);
        let revoked_at_unix = api_key.revoked_at_unix.map(saturating_i64);
        let operation = self.tenancy_operation("upsert api key record");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO api_keys \
                 (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
                  enabled, scopes_json, allowed_models_json, allowed_providers_json, \
                  monthly_token_budget, request_limit_per_minute, created_at_unix, \
                  updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb, $11::text::jsonb, \
                 $12::text::jsonb, $13, $14, $15, $16, $17, $18, $19) \
                 ON CONFLICT (id) DO UPDATE SET \
                 workspace_id = EXCLUDED.workspace_id, tenant_id = EXCLUDED.tenant_id, \
                 project_id = EXCLUDED.project_id, name = EXCLUDED.name, \
                 key_prefix = EXCLUDED.key_prefix, key_hash = EXCLUDED.key_hash, \
                 last4 = EXCLUDED.last4, enabled = EXCLUDED.enabled, \
                 scopes_json = EXCLUDED.scopes_json, \
                 allowed_models_json = EXCLUDED.allowed_models_json, \
                 allowed_providers_json = EXCLUDED.allowed_providers_json, \
                 monthly_token_budget = EXCLUDED.monthly_token_budget, \
                 request_limit_per_minute = EXCLUDED.request_limit_per_minute, \
                 updated_at_unix = EXCLUDED.updated_at_unix, \
                 rotated_at_unix = EXCLUDED.rotated_at_unix, \
                 expires_at_unix = EXCLUDED.expires_at_unix, revoked_at_unix = EXCLUDED.revoked_at_unix",
                &[
                    &api_key.id,
                    &api_key.workspace_id,
                    &api_key.tenant_id,
                    &api_key.project_id,
                    &api_key.name,
                    &api_key.key_prefix,
                    &api_key.key_hash,
                    &api_key.last4,
                    &api_key.enabled,
                    &scopes_json,
                    &allowed_models_json,
                    &allowed_providers_json,
                    &monthly_token_budget,
                    &request_limit_per_minute,
                    &created_at_unix,
                    &updated_at_unix,
                    &rotated_at_unix,
                    &expires_at_unix,
                    &revoked_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        let operation = self.tenancy_operation("get api key record");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix, allowed_models_json::text, \
                 allowed_providers_json::text, monthly_token_budget, request_limit_per_minute \
                 FROM api_keys WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(api_key_from_row).transpose()
    }

    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        let operation = self.tenancy_operation("list api key records");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix, allowed_models_json::text, \
                 allowed_providers_json::text, monthly_token_budget, request_limit_per_minute \
                 FROM api_keys ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(api_key_from_row).collect()
    }

    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        let operation = self.tenancy_operation("find api key records by prefix");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, \
                 last4, enabled, scopes_json::text, created_at_unix, updated_at_unix, \
                 rotated_at_unix, expires_at_unix, revoked_at_unix, allowed_models_json::text, \
                 allowed_providers_json::text, monthly_token_budget, request_limit_per_minute \
                 FROM api_keys WHERE key_prefix = $1 ORDER BY id ASC",
                &[&key_prefix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(api_key_from_row).collect()
    }

    fn admin_user_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn upsert_admin_user(&self, user: &StoredAdminUser) -> Result<(), StorageError> {
        let operation = self.admin_user_operation("upsert admin user");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO admin_users \
                 (id, email, password_hash, display_name, superadmin, created_at_unix, \
                  updated_at_unix, last_login_at_unix, disabled_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO UPDATE SET \
                 email = EXCLUDED.email, password_hash = EXCLUDED.password_hash, \
                 display_name = EXCLUDED.display_name, superadmin = EXCLUDED.superadmin, \
                 updated_at_unix = EXCLUDED.updated_at_unix, \
                 last_login_at_unix = EXCLUDED.last_login_at_unix, \
                 disabled_at_unix = EXCLUDED.disabled_at_unix",
                &[
                    &user.id,
                    &user.email,
                    &user.password_hash,
                    &user.display_name,
                    &user.superadmin,
                    &user.created_at_unix,
                    &user.updated_at_unix,
                    &user.last_login_at_unix,
                    &user.disabled_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        let operation = self.admin_user_operation("get admin user by id");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, email, password_hash, display_name, superadmin, created_at_unix, \
                 updated_at_unix, last_login_at_unix, disabled_at_unix \
                 FROM admin_users WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(admin_user_from_row))
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        let operation = self.admin_user_operation("get admin user by email");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, email, password_hash, display_name, superadmin, created_at_unix, \
                 updated_at_unix, last_login_at_unix, disabled_at_unix \
                 FROM admin_users WHERE email = $1",
                &[&email],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(admin_user_from_row))
    }

    async fn upsert_admin_user_membership(
        &self,
        membership: &StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        let operation = self.admin_user_operation("upsert admin user membership");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO admin_user_tenant_memberships \
                 (id, user_id, tenant_id, role, created_at_unix) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = EXCLUDED.role",
                &[
                    &membership.id,
                    &membership.user_id,
                    &membership.tenant_id,
                    &membership.role,
                    &membership.created_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        let operation = self.admin_user_operation("list admin user memberships by user");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, user_id, tenant_id, role, created_at_unix \
                 FROM admin_user_tenant_memberships WHERE user_id = $1 ORDER BY id ASC",
                &[&user_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(admin_user_membership_from_row).collect())
    }

    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        let operation = self.admin_user_operation("list admin user memberships by tenant");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, user_id, tenant_id, role, created_at_unix \
                 FROM admin_user_tenant_memberships WHERE tenant_id = $1 ORDER BY id ASC",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(admin_user_membership_from_row).collect())
    }

    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.admin_user_operation("delete admin user membership");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "DELETE FROM admin_user_tenant_memberships WHERE user_id = $1 AND tenant_id = $2",
                &[&user_id, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    async fn upsert_sso_provider_config(
        &self,
        config: &StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        let operation = self.admin_user_operation("upsert sso provider config");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let group_role_mapping_json = serde_json::to_string(&config.group_role_mapping)
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO sso_provider_configs \
                 (tenant_id, provider_kind, default_role, group_role_mapping_json, \
                  oidc_issuer, oidc_client_id, oidc_client_secret_ref, oidc_redirect_uri, \
                  oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, saml_idp_certificate, \
                  saml_sp_entity_id, saml_acs_url, saml_email_attribute, saml_name_attribute, \
                  saml_groups_attribute, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4::text::jsonb, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                         $15, $16, $17, $18, $19) \
                 ON CONFLICT (tenant_id) DO UPDATE SET \
                 provider_kind = EXCLUDED.provider_kind, default_role = EXCLUDED.default_role, \
                 group_role_mapping_json = EXCLUDED.group_role_mapping_json, \
                 oidc_issuer = EXCLUDED.oidc_issuer, oidc_client_id = EXCLUDED.oidc_client_id, \
                 oidc_client_secret_ref = EXCLUDED.oidc_client_secret_ref, \
                 oidc_redirect_uri = EXCLUDED.oidc_redirect_uri, \
                 oidc_group_claim = EXCLUDED.oidc_group_claim, \
                 saml_idp_entity_id = EXCLUDED.saml_idp_entity_id, \
                 saml_idp_sso_url = EXCLUDED.saml_idp_sso_url, \
                 saml_idp_certificate = EXCLUDED.saml_idp_certificate, \
                 saml_sp_entity_id = EXCLUDED.saml_sp_entity_id, \
                 saml_acs_url = EXCLUDED.saml_acs_url, \
                 saml_email_attribute = EXCLUDED.saml_email_attribute, \
                 saml_name_attribute = EXCLUDED.saml_name_attribute, \
                 saml_groups_attribute = EXCLUDED.saml_groups_attribute, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &config.tenant_id,
                    &config.provider_kind,
                    &config.default_role,
                    &group_role_mapping_json,
                    &config.oidc_issuer,
                    &config.oidc_client_id,
                    &config.oidc_client_secret_ref,
                    &config.oidc_redirect_uri,
                    &config.oidc_group_claim,
                    &config.saml_idp_entity_id,
                    &config.saml_idp_sso_url,
                    &config.saml_idp_certificate,
                    &config.saml_sp_entity_id,
                    &config.saml_acs_url,
                    &config.saml_email_attribute,
                    &config.saml_name_attribute,
                    &config.saml_groups_attribute,
                    &config.created_at_unix,
                    &config.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        let operation = self.admin_user_operation("get sso provider config");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT tenant_id, provider_kind, default_role, group_role_mapping_json::text, \
                 oidc_issuer, oidc_client_id, oidc_client_secret_ref, oidc_redirect_uri, \
                 oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, saml_idp_certificate, \
                 saml_sp_entity_id, saml_acs_url, saml_email_attribute, saml_name_attribute, \
                 saml_groups_attribute, created_at_unix, updated_at_unix \
                 FROM sso_provider_configs WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(sso_provider_config_from_row).transpose()
    }

    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        let operation = self.admin_user_operation("delete sso provider config");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "DELETE FROM sso_provider_configs WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    async fn insert_sso_pending_flow(
        &self,
        flow: &StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        let operation = self.admin_user_operation("insert sso pending flow");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO sso_pending_flows \
                 (state, tenant_id, provider_kind, code_verifier, request_id, created_at_unix, \
                  expires_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (state) DO NOTHING",
                &[
                    &flow.state,
                    &flow.tenant_id,
                    &flow.provider_kind,
                    &flow.code_verifier,
                    &flow.request_id,
                    &flow.created_at_unix,
                    &flow.expires_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    /// Deletes the pending flow row and returns it iff it existed AND had not
    /// yet expired, so a callback can consume its state exactly once. Also
    /// prunes any other expired rows opportunistically.
    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        let operation = self.admin_user_operation("take sso pending flow");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        // Consume the flow (delete-returning) so it can be used at most once,
        // even under concurrent callbacks.
        let row = transaction
            .query_opt(
                "DELETE FROM sso_pending_flows WHERE state = $1 \
                 RETURNING state, tenant_id, provider_kind, code_verifier, request_id, \
                 created_at_unix, expires_at_unix",
                &[&state],
            )
            .await
            .map_err(postgres_error)?;
        // Opportunistic expiry prune, independent of the consumed row.
        transaction
            .execute(
                "DELETE FROM sso_pending_flows WHERE expires_at_unix <= $1",
                &[&now_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let flow = row.as_ref().map(sso_pending_flow_from_row);
        Ok(flow.filter(|flow| flow.expires_at_unix > now_unix))
    }

    async fn upsert_admin_user_refresh_token(
        &self,
        token: &StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        let operation = self.admin_user_operation("upsert admin user refresh token");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO admin_user_refresh_tokens \
                 (id, user_id, token_hash, tenant_id, role, created_at_unix, expires_at_unix, \
                 revoked_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO UPDATE SET revoked_at_unix = EXCLUDED.revoked_at_unix",
                &[
                    &token.id,
                    &token.user_id,
                    &token.token_hash,
                    &token.tenant_id,
                    &token.role,
                    &token.created_at_unix,
                    &token.expires_at_unix,
                    &token.revoked_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        let operation = self.admin_user_operation("get admin user refresh token by hash");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, user_id, token_hash, tenant_id, role, created_at_unix, \
                 expires_at_unix, revoked_at_unix \
                 FROM admin_user_refresh_tokens WHERE token_hash = $1",
                &[&token_hash],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(admin_user_refresh_token_from_row))
    }

    /// Revokes every not-yet-revoked refresh token for a user (issue #161),
    /// used when a SCIM/admin deactivation must terminate live sessions
    /// immediately rather than waiting for access-token expiry.
    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        let operation = self.admin_user_operation("revoke all admin user refresh tokens");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "UPDATE admin_user_refresh_tokens SET revoked_at_unix = $1 \
                 WHERE user_id = $2 AND revoked_at_unix IS NULL",
                &[&revoked_at_unix, &user_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected)
    }

    /// Revokes every not-yet-revoked refresh token a user holds for ONE
    /// tenant (issue #232), so a tenant-scoped SCIM deprovision terminates
    /// only that tenant's sessions and can never log the user out of the
    /// other tenants they belong to.
    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        let operation = self.admin_user_operation("revoke admin user refresh tokens for tenant");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "UPDATE admin_user_refresh_tokens SET revoked_at_unix = $1 \
                 WHERE user_id = $2 AND tenant_id = $3 AND revoked_at_unix IS NULL",
                &[&revoked_at_unix, &user_id, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected)
    }

    async fn upsert_tenant_account(
        &self,
        account: &StoredTenantAccount,
    ) -> Result<(), StorageError> {
        let operation = self.tenancy_operation("upsert tenant account");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO tenants \
                 (id, name, slug, status, plan_id, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, status = EXCLUDED.status, \
                 plan_id = EXCLUDED.plan_id, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &account.id,
                    &account.name,
                    &account.slug,
                    &account.status,
                    &account.plan_id,
                    &account.created_at_unix,
                    &account.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        let operation = self.tenancy_operation("get tenant account");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, name, slug, status, plan_id, created_at_unix, updated_at_unix \
                 FROM tenants WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(tenant_account_from_row))
    }

    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        let operation = self.tenancy_operation("list tenant accounts");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, name, slug, status, plan_id, created_at_unix, updated_at_unix \
                 FROM tenants ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(tenant_account_from_row).collect())
    }

    async fn upsert_project(&self, project: &StoredProject) -> Result<(), StorageError> {
        let operation = self.tenancy_operation("upsert project");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO projects \
                 (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 tenant_id = EXCLUDED.tenant_id, name = EXCLUDED.name, slug = EXCLUDED.slug, \
                 status = EXCLUDED.status, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &project.id,
                    &project.tenant_id,
                    &project.name,
                    &project.slug,
                    &project.status,
                    &project.created_at_unix,
                    &project.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        let operation = self.tenancy_operation("get project");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(project_from_row))
    }

    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        let operation = self.tenancy_operation("list projects");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix \
                 FROM projects ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(project_from_row).collect())
    }

    async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        let operation = self.tenancy_operation("delete project");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM projects WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    /// Atomic reject-if-referenced project delete (issue #328, finding 4).
    /// Locks the parent row `FOR UPDATE` -- which conflicts with the
    /// `FOR KEY SHARE` lock a concurrent child insert takes on its FK
    /// parent -- then counts children and deletes inside the same
    /// transaction, closing the TOCTOU window where a workspace/key created
    /// between a separate count and delete would be silently
    /// `ON DELETE CASCADE`d.
    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        let operation = self.tenancy_operation("delete project if unreferenced");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so
        // these control-plane queries resolve their tables in the
        // configured schema, not the connection default.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        // Lock the parent row first; a missing row means nothing to delete.
        let locked = transaction
            .query_opt("SELECT id FROM projects WHERE id = $1 FOR UPDATE", &[&id])
            .await
            .map_err(postgres_error)?;
        if locked.is_none() {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(DeleteProjectOutcome::NotFound);
        }
        let workspaces: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM workspaces WHERE project_id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?
            .get(0);
        let virtual_keys: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM api_keys WHERE project_id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?
            .get(0);
        if workspaces > 0 || virtual_keys > 0 {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(DeleteProjectOutcome::Referenced {
                workspaces: workspaces.max(0) as usize,
                virtual_keys: virtual_keys.max(0) as usize,
            });
        }
        let affected = transaction
            .execute("DELETE FROM projects WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(if affected > 0 {
            DeleteProjectOutcome::Deleted
        } else {
            DeleteProjectOutcome::NotFound
        })
    }

    async fn upsert_workspace(&self, workspace: &StoredWorkspace) -> Result<(), StorageError> {
        let operation = self.tenancy_operation("upsert workspace");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO workspaces \
                 (id, project_id, tenant_id, name, slug, environment, status, \
                  created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO UPDATE SET \
                 project_id = EXCLUDED.project_id, tenant_id = EXCLUDED.tenant_id, \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, environment = EXCLUDED.environment, \
                 status = EXCLUDED.status, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &workspace.id,
                    &workspace.project_id,
                    &workspace.tenant_id,
                    &workspace.name,
                    &workspace.slug,
                    &workspace.environment,
                    &workspace.status,
                    &workspace.created_at_unix,
                    &workspace.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        let operation = self.tenancy_operation("get workspace");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(workspace_from_row))
    }

    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        let operation = self.tenancy_operation("list workspaces");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, project_id, tenant_id, name, slug, environment, status, \
                 created_at_unix, updated_at_unix FROM workspaces ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(workspace_from_row).collect())
    }

    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        let operation = self.tenancy_operation("delete workspace");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM workspaces WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    /// Atomic reject-if-referenced workspace delete (issue #328, finding 4).
    /// See [`PostgresControlPlaneStore::delete_project_if_unreferenced`] for
    /// the `FOR UPDATE` locking rationale that closes the TOCTOU window.
    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        let operation = self.tenancy_operation("delete workspace if unreferenced");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let locked = transaction
            .query_opt("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", &[&id])
            .await
            .map_err(postgres_error)?;
        if locked.is_none() {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(DeleteWorkspaceOutcome::NotFound);
        }
        let virtual_keys: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM api_keys WHERE workspace_id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?
            .get(0);
        if virtual_keys > 0 {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(DeleteWorkspaceOutcome::Referenced {
                virtual_keys: virtual_keys.max(0) as usize,
            });
        }
        let affected = transaction
            .execute("DELETE FROM workspaces WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(if affected > 0 {
            DeleteWorkspaceOutcome::Deleted
        } else {
            DeleteWorkspaceOutcome::NotFound
        })
    }

    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        let operation = self.tenancy_operation("resolve workspace scope");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT tenant_id, project_id, id FROM workspaces WHERE id = $1",
                &[&workspace_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(|row| {
            WorkspaceScope::new(
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
            )
        }))
    }

    async fn upsert_quota_policy(&self, policy: &StoredQuotaPolicy) -> Result<(), StorageError> {
        let model_allowlist_json = serialize_storage_document(&policy.model_allowlist)?;
        let alert_threshold_pcts_json = serialize_storage_document(&policy.alert_threshold_pcts)?;
        let rpm_limit = policy.rpm_limit.map(saturating_i64);
        let tpm_limit = policy.tpm_limit.map(saturating_i64);
        let asset_storage_quota_bytes = policy.asset_storage_quota_bytes.map(saturating_i64);
        let monthly_egress_bytes_budget = policy.monthly_egress_bytes_budget.map(saturating_i64);
        let download_rpm_limit = policy.download_rpm_limit.map(saturating_i64);
        let created_at_unix = policy.created_at_unix;
        let updated_at_unix = policy.updated_at_unix;
        let operation = self.tenancy_operation("upsert quota policy");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO quota_policies \
                 (id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, \
                  monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
                  alert_threshold_pcts_json, asset_storage_quota_bytes, \
                  monthly_egress_bytes_budget, download_rpm_limit) \
                 VALUES ($1, $2, $3, $4::text::jsonb, $5, $6, $7, $8, $9, $10, $11::text::jsonb, \
                  $12, $13, $14) \
                 ON CONFLICT (scope_type, scope_id) DO UPDATE SET \
                 model_allowlist_json = EXCLUDED.model_allowlist_json, \
                 rpm_limit = EXCLUDED.rpm_limit, tpm_limit = EXCLUDED.tpm_limit, \
                 monthly_budget_usd = EXCLUDED.monthly_budget_usd, \
                 enabled = EXCLUDED.enabled, updated_at_unix = EXCLUDED.updated_at_unix, \
                 alert_threshold_pcts_json = EXCLUDED.alert_threshold_pcts_json, \
                 asset_storage_quota_bytes = EXCLUDED.asset_storage_quota_bytes, \
                 monthly_egress_bytes_budget = EXCLUDED.monthly_egress_bytes_budget, \
                 download_rpm_limit = EXCLUDED.download_rpm_limit",
                &[
                    &policy.id,
                    &policy.scope_type.as_str(),
                    &policy.scope_id,
                    &model_allowlist_json,
                    &rpm_limit,
                    &tpm_limit,
                    &policy.monthly_budget_usd,
                    &policy.enabled,
                    &created_at_unix,
                    &updated_at_unix,
                    &alert_threshold_pcts_json,
                    &asset_storage_quota_bytes,
                    &monthly_egress_bytes_budget,
                    &download_rpm_limit,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        let operation = self.tenancy_operation("get quota policy");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, scope_type, scope_id, model_allowlist_json::text, rpm_limit, \
                 tpm_limit, monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
                 alert_threshold_pcts_json::text, asset_storage_quota_bytes, \
                 monthly_egress_bytes_budget, download_rpm_limit \
                 FROM quota_policies WHERE scope_type = $1 AND scope_id = $2",
                &[&scope_type.as_str(), &scope_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(quota_policy_from_row).transpose()
    }

    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        let operation = self.tenancy_operation("list quota policies");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, scope_type, scope_id, model_allowlist_json::text, rpm_limit, \
                 tpm_limit, monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
                 alert_threshold_pcts_json::text, asset_storage_quota_bytes, \
                 monthly_egress_bytes_budget, download_rpm_limit \
                 FROM quota_policies ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(quota_policy_from_row).collect()
    }

    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.tenancy_operation("delete quota policy");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "DELETE FROM quota_policies WHERE scope_type = $1 AND scope_id = $2",
                &[&scope_type.as_str(), &scope_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    async fn upsert_plan(&self, plan: &StoredPlan) -> Result<(), StorageError> {
        let default_model_allowlist_json =
            serialize_storage_document(&plan.default_model_allowlist)?;
        let default_rpm_limit = plan.default_rpm_limit.map(saturating_i64);
        let default_tpm_limit = plan.default_tpm_limit.map(saturating_i64);
        let admin_console_seats = plan.admin_console_seats.map(i64::from);
        let default_asset_storage_quota_bytes =
            plan.default_asset_storage_quota_bytes.map(saturating_i64);
        let default_monthly_egress_bytes_budget =
            plan.default_monthly_egress_bytes_budget.map(saturating_i64);
        let default_download_rpm_limit = plan.default_download_rpm_limit.map(saturating_i64);
        let operation = self.tenancy_operation("upsert plan");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO plans \
                 (id, name, slug, mcp_enabled, self_hosted_workers_enabled, \
                  admin_console_seats, default_model_allowlist_json, default_rpm_limit, \
                  default_tpm_limit, default_monthly_budget_usd, created_at_unix, \
                  updated_at_unix, asset_hosting_enabled, default_asset_storage_quota_bytes, \
                  extension_tools_enabled, default_monthly_egress_bytes_budget, \
                  default_download_rpm_limit) \
                 VALUES \
                 ($1, $2, $3, $4, $5, $6, $7::text::jsonb, $8, $9, $10, $11, $12, $13, $14, $15, \
                  $16, $17) \
                 ON CONFLICT (id) DO UPDATE SET \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, \
                 mcp_enabled = EXCLUDED.mcp_enabled, \
                 self_hosted_workers_enabled = EXCLUDED.self_hosted_workers_enabled, \
                 admin_console_seats = EXCLUDED.admin_console_seats, \
                 default_model_allowlist_json = EXCLUDED.default_model_allowlist_json, \
                 default_rpm_limit = EXCLUDED.default_rpm_limit, \
                 default_tpm_limit = EXCLUDED.default_tpm_limit, \
                 default_monthly_budget_usd = EXCLUDED.default_monthly_budget_usd, \
                 updated_at_unix = EXCLUDED.updated_at_unix, \
                 asset_hosting_enabled = EXCLUDED.asset_hosting_enabled, \
                 default_asset_storage_quota_bytes = EXCLUDED.default_asset_storage_quota_bytes, \
                 extension_tools_enabled = EXCLUDED.extension_tools_enabled, \
                 default_monthly_egress_bytes_budget = EXCLUDED.default_monthly_egress_bytes_budget, \
                 default_download_rpm_limit = EXCLUDED.default_download_rpm_limit",
                &[
                    &plan.id,
                    &plan.name,
                    &plan.slug,
                    &plan.mcp_enabled,
                    &plan.self_hosted_workers_enabled,
                    &admin_console_seats,
                    &default_model_allowlist_json,
                    &default_rpm_limit,
                    &default_tpm_limit,
                    &plan.default_monthly_budget_usd,
                    &plan.created_at_unix,
                    &plan.updated_at_unix,
                    &plan.asset_hosting_enabled,
                    &default_asset_storage_quota_bytes,
                    &plan.extension_tools_enabled,
                    &default_monthly_egress_bytes_budget,
                    &default_download_rpm_limit,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        let operation = self.tenancy_operation("get plan");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, name, slug, mcp_enabled, self_hosted_workers_enabled, \
                 admin_console_seats, default_model_allowlist_json::text, default_rpm_limit, \
                 default_tpm_limit, default_monthly_budget_usd, created_at_unix, \
                 updated_at_unix, asset_hosting_enabled, default_asset_storage_quota_bytes, \
                 extension_tools_enabled, default_monthly_egress_bytes_budget, \
                 default_download_rpm_limit \
                 FROM plans WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(plan_from_row).transpose()
    }

    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        let operation = self.tenancy_operation("list plans");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, name, slug, mcp_enabled, self_hosted_workers_enabled, \
                 admin_console_seats, default_model_allowlist_json::text, default_rpm_limit, \
                 default_tpm_limit, default_monthly_budget_usd, created_at_unix, \
                 updated_at_unix, asset_hosting_enabled, default_asset_storage_quota_bytes, \
                 extension_tools_enabled, default_monthly_egress_bytes_budget, \
                 default_download_rpm_limit \
                 FROM plans ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(plan_from_row).collect()
    }

    fn asset_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn upsert_asset(&self, asset: &StoredAsset) -> Result<(), StorageError> {
        let size_bytes = saturating_i64(asset.size_bytes);
        let visibility = asset.visibility.as_str();
        let operation = self.asset_operation("upsert asset");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO stored_assets \
                 (id, tenant_id, project_id, asset_type, name, version, content_type, \
                  content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                  storage_uri, variant, yanked, visibility) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
                 ON CONFLICT (id) DO UPDATE SET \
                 content_type = EXCLUDED.content_type, content_hash = EXCLUDED.content_hash, \
                 size_bytes = EXCLUDED.size_bytes, content = EXCLUDED.content, \
                 updated_at_unix = EXCLUDED.updated_at_unix, \
                 storage_uri = EXCLUDED.storage_uri, yanked = EXCLUDED.yanked, \
                 visibility = EXCLUDED.visibility",
                &[
                    &asset.id,
                    &asset.tenant_id,
                    &asset.project_id,
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    &asset.content_type,
                    &asset.content_hash,
                    &size_bytes,
                    &asset.content,
                    &asset.created_at_unix,
                    &asset.updated_at_unix,
                    &asset.storage_uri,
                    &asset.variant,
                    &asset.yanked,
                    &visibility,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    const CREATE_ASSET_IF_ABSENT_QUERY: &'static str = "INSERT INTO stored_assets \
         (id, tenant_id, project_id, asset_type, name, version, content_type, \
          content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
          storage_uri, variant, yanked, visibility) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
         ON CONFLICT (id) DO NOTHING";

    async fn create_asset_if_absent(&self, asset: &StoredAsset) -> Result<bool, StorageError> {
        let size_bytes = saturating_i64(asset.size_bytes);
        let visibility = asset.visibility.as_str();
        let operation = self.asset_operation("create asset if absent");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                Self::CREATE_ASSET_IF_ABSENT_QUERY,
                &[
                    &asset.id,
                    &asset.tenant_id,
                    &asset.project_id,
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    &asset.content_type,
                    &asset.content_hash,
                    &size_bytes,
                    &asset.content,
                    &asset.created_at_unix,
                    &asset.updated_at_unix,
                    &asset.storage_uri,
                    &asset.variant,
                    &asset.yanked,
                    &visibility,
                ],
            )
            .await
            .map_err(postgres_error)?;
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the immutable asset create commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(inserted == 1)
    }

    /// One conditional statement that atomically admits a push against the tenant
    /// asset-storage quota AND publishes it (issue #371). The former two-step
    /// admission (read `tenant_asset_storage_bytes_used`, then a separate
    /// `create_asset_if_absent`) let two commits for two DIFFERENT asset ids both
    /// read the same remaining capacity, both pass, and jointly overshoot the
    /// quota. Here the usage sum, the quota guard, the immutability guard, and the
    /// insert share ONE statement's snapshot, so there is no read-then-write gap:
    /// the `INSERT ... SELECT ... WHERE` materializes the row only when the tenant
    /// still has room, and the wrapping `WITH`/`SELECT` reports the definitive
    /// classification even when nothing is inserted.
    ///
    /// `$17` is the quota bound (NULL = unlimited: the quota guard is a no-op and
    /// only the create-if-absent immutability guard remains). The returned row
    /// yields (`id_exists`, `used_bytes`, `quota_ok`, `inserted`) so the caller
    /// distinguishes Admitted / AlreadyExists / OverQuota without a second read.
    const CREATE_ASSET_WITHIN_QUOTA_QUERY: &'static str = "\
        WITH guard AS ( \
            SELECT \
                EXISTS (SELECT 1 FROM stored_assets WHERE id = $1) AS id_exists, \
                COALESCE((SELECT SUM(size_bytes) FROM stored_assets WHERE tenant_id = $2), 0) \
                    AS used_bytes \
        ), \
        inserted AS ( \
            INSERT INTO stored_assets \
                (id, tenant_id, project_id, asset_type, name, version, content_type, \
                 content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                 storage_uri, variant, yanked, visibility) \
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16 \
            FROM guard \
            WHERE NOT guard.id_exists \
              AND ($17::bigint IS NULL OR guard.used_bytes + $9::bigint <= $17::bigint) \
            ON CONFLICT (id) DO NOTHING \
            RETURNING 1 \
        ) \
        SELECT \
            guard.id_exists, \
            guard.used_bytes::bigint AS used_bytes, \
            ($17::bigint IS NULL OR guard.used_bytes + $9::bigint <= $17::bigint) AS quota_ok, \
            (SELECT COUNT(*) FROM inserted)::bigint AS inserted_count \
        FROM guard";

    async fn create_asset_within_quota(
        &self,
        asset: &StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        let size_bytes = saturating_i64(asset.size_bytes);
        let quota = quota_bytes.map(saturating_i64);
        let visibility = asset.visibility.as_str();
        let operation = self.asset_operation("create asset within quota");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_one(
                Self::CREATE_ASSET_WITHIN_QUOTA_QUERY,
                &[
                    &asset.id,
                    &asset.tenant_id,
                    &asset.project_id,
                    &asset.asset_type,
                    &asset.name,
                    &asset.version,
                    &asset.content_type,
                    &asset.content_hash,
                    &size_bytes,
                    &asset.content,
                    &asset.created_at_unix,
                    &asset.updated_at_unix,
                    &asset.storage_uri,
                    &asset.variant,
                    &asset.yanked,
                    &visibility,
                    &quota,
                ],
            )
            .await
            .map_err(postgres_error)?;
        let id_exists: bool = row.get("id_exists");
        let used_bytes = nonnegative_u64(row.get::<_, i64>("used_bytes"));
        let quota_ok: bool = row.get("quota_ok");
        let inserted_count: i64 = row.get("inserted_count");
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the asset quota-admission commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(classify_asset_quota_admission(
            inserted_count == 1,
            id_exists,
            quota_ok,
            used_bytes,
            asset.size_bytes,
            quota_bytes,
        ))
    }

    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        let operation = self.asset_operation("get asset");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                 content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                 storage_uri, variant, yanked, visibility \
                 FROM stored_assets WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(asset_from_row))
    }

    async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        let operation = self.asset_operation("list assets");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = match asset_type {
            Some(asset_type) => transaction
                .query(
                    "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                         content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                         storage_uri, variant, yanked, visibility \
                         FROM stored_assets WHERE tenant_id = $1 AND asset_type = $2 \
                         ORDER BY name ASC, version ASC",
                    &[&tenant_id, &asset_type],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                         content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                         storage_uri, variant, yanked, visibility \
                         FROM stored_assets WHERE tenant_id = $1 \
                         ORDER BY asset_type ASC, name ASC, version ASC",
                    &[&tenant_id],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(asset_from_row).collect())
    }

    /// The withheld-asset inverse of [`Self::list_assets`] (issue #379). Filters
    /// server-side to the non-`visible` (`pending_scan`/`quarantined`) rows so
    /// the still-unproven bytes an operator needs to inspect are the only thing
    /// shipped over the wire, and orders identically to the ordinary listing so
    /// the caller's offset/limit pagination is stable across both surfaces.
    async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        let operation = self.asset_operation("list withheld assets");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = match asset_type {
            Some(asset_type) => transaction
                .query(
                    "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                         content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                         storage_uri, variant, yanked, visibility \
                         FROM stored_assets \
                         WHERE tenant_id = $1 AND asset_type = $2 AND visibility <> 'visible' \
                         ORDER BY name ASC, version ASC, variant ASC",
                    &[&tenant_id, &asset_type],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                         content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                         storage_uri, variant, yanked, visibility \
                         FROM stored_assets \
                         WHERE tenant_id = $1 AND visibility <> 'visible' \
                         ORDER BY asset_type ASC, name ASC, version ASC, variant ASC",
                    &[&tenant_id],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(asset_from_row).collect())
    }

    /// Keep tenant storage accounting on a metadata-only projection. Loading
    /// `content` here would deserialize every inline BYTEA merely to add its
    /// already-recorded size, turning quota checks and operator summaries into
    /// bulk blob reads.
    const TENANT_ASSET_STORAGE_SIZE_QUERY: &'static str =
        "SELECT size_bytes FROM stored_assets WHERE tenant_id = $1";

    async fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> Result<u64, StorageError> {
        let operation = self.asset_operation("read tenant asset storage usage");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // The transaction exists only to pin the configured schema in
        // `search_path`; the indexed SELECT is the sole data operation.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(Self::TENANT_ASSET_STORAGE_SIZE_QUERY, &[&tenant_id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().fold(0_u64, |total, row| {
            total.saturating_add(nonnegative_u64(row.get::<_, i64>(0)))
        }))
    }

    async fn delete_asset(&self, id: &str) -> Result<bool, StorageError> {
        let operation = self.asset_operation("delete asset");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM stored_assets WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    async fn upsert_asset_channel(&self, channel: &StoredAssetChannel) -> Result<(), StorageError> {
        let operation = self.asset_operation("upsert asset channel");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO asset_channels \
                 (id, tenant_id, asset_type, name, channel, version, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 version = EXCLUDED.version, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &channel.id,
                    &channel.tenant_id,
                    &channel.asset_type,
                    &channel.name,
                    &channel.channel,
                    &channel.version,
                    &channel.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        let operation = self.asset_operation("list asset channels");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, asset_type, name, channel, version, updated_at_unix \
                 FROM asset_channels \
                 WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 \
                 ORDER BY channel ASC",
                &[&tenant_id, &asset_type, &name],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(asset_channel_from_row).collect())
    }

    async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError> {
        let operation = self.asset_operation("delete asset channel");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM asset_channels WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    // #367: atomic channel/version lifecycle coordination.
    //
    // The invariant is: every `asset_channels` row points at a resolvable
    // version (present, no yanked variant). Move (writes `asset_channels`, guards
    // on `stored_assets`) and yank/delete (writes `stored_assets`, guards on
    // `asset_channels`) touch two tables in opposite directions, which under
    // READ COMMITTED is a classic write-skew hazard: two single statements could
    // both pass their guard against a stale snapshot and both commit, leaving a
    // channel on a yanked/absent version. To close it deterministically -- with
    // no retry loop, no `pg_sleep`, no unbounded wait -- every coordination
    // mutation first takes a `SELECT ... FOR UPDATE` row lock on the version's
    // `stored_assets` rows (a single, shared lock ordering), then reads/writes
    // the channel row inside the same short transaction. Whichever operation
    // wins the row lock commits first and the other observes its committed
    // effect, so the two can never both pass their guard. This is the "smallest
    // irreducible transaction" AGENTS.md permits; `lock_timeout` /
    // `statement_timeout` are pinned per transaction so no lock wait is
    // unbounded.

    /// Prefix SQL that pins `search_path` (when configured) plus a bounded
    /// `lock_timeout`/`statement_timeout` for a coordination transaction, so a
    /// `FOR UPDATE` wait can never block past the operation's own deadline.
    fn coordination_session_sql(&self) -> String {
        let timeout_ms = u64::try_from(self.async_pool.statement_timeout().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let mut sql = String::new();
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            sql.push_str(search_path_sql);
            sql.push(';');
        }
        sql.push_str(&format!("SET LOCAL lock_timeout = '{timeout_ms}ms';"));
        sql.push_str(&format!("SET LOCAL statement_timeout = '{timeout_ms}ms';"));
        sql
    }

    async fn move_asset_channel_if_resolvable(
        &self,
        channel: &StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        let operation = self.asset_operation("move asset channel");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        transaction
            .batch_execute(&self.coordination_session_sql())
            .await
            .map_err(postgres_error)?;
        // Lock every variant row of the target version FIRST -- the shared lock
        // ordering yank/delete also use -- so the resolvability check below and
        // the channel upsert cannot be interleaved by a concurrent yank/delete.
        let variant_rows = transaction
            .query(
                "SELECT yanked FROM stored_assets \
                 WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4 \
                 FOR UPDATE",
                &[
                    &channel.tenant_id,
                    &channel.asset_type,
                    &channel.name,
                    &channel.version,
                ],
            )
            .await
            .map_err(postgres_error)?;
        let resolvable =
            !variant_rows.is_empty() && !variant_rows.iter().any(|row| row.get::<_, bool>(0));
        if !resolvable {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(ChannelMoveOutcome::TargetNotResolvable);
        }
        // Prior target (the version this channel pointed at) for audit evidence.
        let prior_version = transaction
            .query_opt(
                "SELECT version FROM asset_channels WHERE id = $1",
                &[&channel.id],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        transaction
            .execute(
                "INSERT INTO asset_channels \
                 (id, tenant_id, asset_type, name, channel, version, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 version = EXCLUDED.version, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &channel.id,
                    &channel.tenant_id,
                    &channel.asset_type,
                    &channel.name,
                    &channel.channel,
                    &channel.version,
                    &channel.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the channel move commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(ChannelMoveOutcome::Moved { prior_version })
    }

    async fn set_asset_version_yank(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError> {
        let operation = self.asset_operation(if yanked {
            "yank asset version"
        } else {
            "unyank asset version"
        });
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        transaction
            .batch_execute(&self.coordination_session_sql())
            .await
            .map_err(postgres_error)?;
        // Lock the version's variant rows FIRST (shared ordering with move).
        let target_rows = transaction
            .query(
                "SELECT id FROM stored_assets \
                 WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4 \
                 FOR UPDATE",
                &[&tenant_id, &asset_type, &name, &version],
            )
            .await
            .map_err(postgres_error)?;
        if target_rows.is_empty() {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(VersionYankOutcome::NotFound);
        }
        // Yank is fail-closed while referenced; unyank restores resolvability and
        // can never strand a channel, so it skips the reference guard.
        if yanked {
            let referenced = transaction
                .query_opt(
                    "SELECT 1 FROM asset_channels \
                     WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4 \
                     LIMIT 1",
                    &[&tenant_id, &asset_type, &name, &version],
                )
                .await
                .map_err(postgres_error)?
                .is_some();
            if referenced {
                transaction.commit().await.map_err(postgres_error)?;
                return Ok(VersionYankOutcome::ReferencedByChannel);
            }
        }
        let affected = transaction
            .execute(
                "UPDATE stored_assets SET yanked = $5, updated_at_unix = $6 \
                 WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4",
                &[&tenant_id, &asset_type, &name, &version, &yanked, &now_unix],
            )
            .await
            .map_err(postgres_error)?;
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the version yank commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(VersionYankOutcome::Applied {
            variants: affected as usize,
        })
    }

    async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        let operation = self.asset_operation("delete asset variant");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        transaction
            .batch_execute(&self.coordination_session_sql())
            .await
            .map_err(postgres_error)?;
        // Lock the whole version's rows FIRST (shared ordering with move/yank),
        // returning each row's id + yank state so the reject decision is made
        // against the locked, committed state.
        let version_rows = transaction
            .query(
                "SELECT id, yanked FROM stored_assets \
                 WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4 \
                 FOR UPDATE",
                &[&tenant_id, &asset_type, &name, &version],
            )
            .await
            .map_err(postgres_error)?;
        if !version_rows.iter().any(|row| row.get::<_, String>(0) == id) {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(VariantDeleteOutcome::NotFound);
        }
        // Would this delete leave the version with no resolvable (non-yanked)
        // variant? If so and a channel still references the version, reject.
        let remaining_resolvable = version_rows
            .iter()
            .any(|row| row.get::<_, String>(0) != id && !row.get::<_, bool>(1));
        if !remaining_resolvable {
            let referenced = transaction
                .query_opt(
                    "SELECT 1 FROM asset_channels \
                     WHERE tenant_id = $1 AND asset_type = $2 AND name = $3 AND version = $4 \
                     LIMIT 1",
                    &[&tenant_id, &asset_type, &name, &version],
                )
                .await
                .map_err(postgres_error)?
                .is_some();
            if referenced {
                transaction.commit().await.map_err(postgres_error)?;
                return Ok(VariantDeleteOutcome::BlockedByChannel);
            }
        }
        let affected = transaction
            .execute("DELETE FROM stored_assets WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the variant delete commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(if affected > 0 {
            VariantDeleteOutcome::Deleted
        } else {
            VariantDeleteOutcome::NotFound
        })
    }

    async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        let operation = self.asset_operation("promote asset visibility");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // One short conditional CAS (#378): the UPDATE fires only from the
        // `pending_scan` state, and the two scalar sub-selects classify the
        // zero-row case (absent row vs. already-terminal row) inside the SAME
        // statement snapshot -- no read-then-write gap, no coordination lock,
        // no long transaction. The transaction wrapper exists only to pin
        // `search_path` to the configured schema (#238/#239) so the CTE
        // resolves `stored_assets` in the same schema the push path wrote to.
        // Note: a data-modifying CTE's write is invisible to the sibling
        // sub-select, so when the UPDATE fires `current_visibility` still reads
        // the pre-update `pending_scan`; that is fine because the caller only
        // consults `current_visibility` when `promoted_visibility` is NULL.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let target_token = target.visibility().as_str();
        let row = transaction
            .query_one(
                "WITH promoted AS ( \
                     UPDATE stored_assets \
                        SET visibility = $2, updated_at_unix = $3 \
                      WHERE id = $1 AND visibility = 'pending_scan' \
                     RETURNING visibility \
                 ) \
                 SELECT (SELECT visibility FROM promoted) AS promoted_visibility, \
                        (SELECT visibility FROM stored_assets WHERE id = $1) \
                            AS current_visibility",
                &[&id, &target_token, &now_unix],
            )
            .await
            .map_err(postgres_error)?;
        // Extract the classification BEFORE the commit fence so the row's
        // borrow does not outlive the transaction.
        let promoted_visibility: Option<String> = row.get("promoted_visibility");
        let current_visibility: Option<String> = row.get("current_visibility");
        operation.begin_commit("before transaction commit")?;
        let commit_result = transaction.commit().await.map_err(|error| {
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "transaction commit",
                sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
                outcome = "commit_outcome_unknown",
                "PostgreSQL returned an error after the visibility promotion commit fence"
            );
            asset_transaction_commit_outcome_unknown(&operation)
        });
        operation.finish_commit();
        commit_result?;
        Ok(match (promoted_visibility, current_visibility) {
            // The CAS fired: RETURNING carries the exact new terminal state.
            (Some(promoted), _) => AssetVisibilityPromotionOutcome::Promoted {
                to: AssetVisibility::from_stored(&promoted),
            },
            // The CAS did not fire but the row exists -> already terminal.
            (None, Some(current)) => AssetVisibilityPromotionOutcome::NotPending {
                current: AssetVisibility::from_stored(&current),
            },
            // Neither: no such row.
            (None, None) => AssetVisibilityPromotionOutcome::NotFound,
        })
    }

    // #263: asset lifecycle -- retention policies + whole-table reconcile scans
    // for the lifecycle sweeper.

    async fn upsert_retention_policy(
        &self,
        policy: &StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        let keep_last_n = policy.keep_last_n.map(saturating_i64);
        let operation = self.asset_operation("upsert retention policy");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO retention_policies \
                 (id, tenant_id, resource_type, scope, keep_last_n, max_age_secs, \
                  min_age_secs, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO UPDATE SET \
                 keep_last_n = EXCLUDED.keep_last_n, max_age_secs = EXCLUDED.max_age_secs, \
                 min_age_secs = EXCLUDED.min_age_secs, updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &policy.id,
                    &policy.tenant_id,
                    &policy.resource_type,
                    &policy.scope,
                    &keep_last_n,
                    &policy.max_age_secs,
                    &policy.min_age_secs,
                    &policy.created_at_unix,
                    &policy.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        let operation = self.asset_operation("list retention policies");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, resource_type, scope, keep_last_n, max_age_secs, \
                 min_age_secs, created_at_unix, updated_at_unix \
                 FROM retention_policies WHERE tenant_id = $1 AND resource_type = $2 \
                 ORDER BY scope ASC",
                &[&tenant_id, &resource_type],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(retention_policy_from_row).collect())
    }

    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        let operation = self.asset_operation("list all assets");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, project_id, asset_type, name, version, content_type, \
                 content_hash, size_bytes, content, created_at_unix, updated_at_unix, \
                 storage_uri, variant, yanked, visibility \
                 FROM stored_assets ORDER BY tenant_id ASC, asset_type ASC, name ASC, version ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(asset_from_row).collect())
    }

    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        let operation = self.asset_operation("list all asset channels");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, asset_type, name, channel, version, updated_at_unix \
                 FROM asset_channels ORDER BY tenant_id ASC, asset_type ASC, name ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(asset_channel_from_row).collect())
    }

    fn usage_rollup_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    fn billing_ledger_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        let operation = self.usage_rollup_operation("get usage monthly rollup");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `usage_monthly_rollups` in the same schema the settlement
        // transaction writes to, not the connection default (`public`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, period_month, scope_type, scope_id, prompt_tokens, \
                 completion_tokens, total_tokens, cost_usd, request_count, error_count, \
                 updated_at_unix \
                 FROM usage_monthly_rollups \
                 WHERE scope_type = $1 AND scope_id = $2 AND period_month = $3",
                &[&scope_type.as_str(), &scope_id, &period_month],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(usage_monthly_rollup_from_row).transpose()
    }

    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        let operation = self.usage_rollup_operation("list usage monthly rollups");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `usage_monthly_rollups` in the same schema the settlement
        // transaction writes to, not the connection default (`public`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, period_month, scope_type, scope_id, prompt_tokens, \
                 completion_tokens, total_tokens, cost_usd, request_count, error_count, \
                 updated_at_unix \
                 FROM usage_monthly_rollups \
                 ORDER BY period_month DESC, scope_type ASC, scope_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(usage_monthly_rollup_from_row).collect()
    }

    async fn append_billing_ledger_entry(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        let entry_json = serialize_storage_document(entry)?;
        let prompt_tokens = saturating_i64(entry.usage.prompt_tokens);
        let completion_tokens = saturating_i64(entry.usage.completion_tokens);
        let total_tokens = saturating_i64(entry.usage.total_tokens);
        let status_code = i32::from(entry.status_code);
        let usage_source = entry.usage_source.as_str();
        let occurred_at_unix = entry.occurred_at_unix.map(saturating_i64);
        let created_at_unix = saturating_i64(now_unix_seconds());
        let operation = self.billing_ledger_operation("append billing ledger entry");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_ledger` against the connection default
        // schema (`public` on stock Supabase roles), splitting the ledger.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO billing_ledger \
                 (id, request_id, trace_id, provider_attempt_id, provider_attempt_index, \
                  organization_id, project_id, workspace_id, api_key_id, logical_model, provider, \
                  provider_model, prompt_tokens, completion_tokens, total_tokens, usage_source, \
                  status_code, input_cost, output_cost, total_cost, currency, credits, entry_json, \
                  occurred_at_unix, created_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                  $16, $17, $18, $19, $20, $21, $22, $23::text::jsonb, $24, $25) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &entry.id,
                    &entry.request_id,
                    &entry.trace_id,
                    &entry.provider_attempt.provider_attempt_id,
                    &(entry.provider_attempt.provider_attempt_index as i32),
                    &entry.tenant.organization_id,
                    &entry.tenant.project_id,
                    &entry.tenant.workspace_id,
                    &entry.tenant.api_key_id,
                    &entry.logical_model,
                    &entry.provider,
                    &entry.provider_model,
                    &prompt_tokens,
                    &completion_tokens,
                    &total_tokens,
                    &usage_source,
                    &status_code,
                    &entry.cost.input_cost,
                    &entry.cost.output_cost,
                    &entry.cost.total_cost,
                    &entry.cost.currency,
                    &entry.credits,
                    &entry_json,
                    &occurred_at_unix,
                    &created_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        // Release the pooled connection BEFORE the idempotent-conflict reload
        // below. `get_billing_ledger_entry` acquires its own connection from the
        // same pool; holding this one across that nested acquire self-deadlocks a
        // single-connection pool (`pool_size = 1`) until the acquire deadline
        // trips (`OperationDeadlineExceeded`), which is exactly what the live
        // idempotent-retry round-trip hit (#248).
        drop(client);
        if inserted > 0 {
            return Ok(true);
        }
        let existing = self
            .get_billing_ledger_entry(&entry.id)
            .await?
            .ok_or_else(|| {
                StorageError::Runtime(format!(
                    "billing ledger id {} conflicted but could not be reloaded",
                    entry.id
                ))
            })?;
        if ferrogate_billing::same_provider_attempt_settlement(&existing, entry) {
            Ok(false)
        } else {
            Err(StorageError::Conflict(format!(
                "billing ledger id {} was replayed with different provider-attempt settlement data",
                entry.id
            )))
        }
    }

    /// Issue #149: the tenant filter is pushed into the WHERE clause itself
    /// (via the `$n::text IS NULL OR column = $n` idiom, so a single fixed
    /// query serves both the unfiltered and per-tenant cases) rather than
    /// fetching an unfiltered page and discarding rows in application code —
    /// otherwise a scoped page could silently come back empty/incomplete in a
    /// busy, multi-tenant ledger, and the tenant-time index would go unused.
    async fn list_billing_ledger_entries(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        let operation = self.billing_ledger_operation("list billing ledger entries");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_ledger` against the connection default
        // schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT entry_json::text FROM billing_ledger \
                 WHERE ($1::text IS NULL OR organization_id = $1) \
                   AND ($2::text IS NULL OR project_id = $2) \
                   AND ($3::text IS NULL OR api_key_id = $3) \
                 ORDER BY created_at_unix ASC, id ASC OFFSET $4 LIMIT $5",
                &[
                    &filter.organization_id,
                    &filter.project_id,
                    &filter.api_key_id,
                    &offset,
                    &limit,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(ledger_entry_from_row).collect()
    }

    async fn get_billing_ledger_entry(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        let operation = self.billing_ledger_operation("get billing ledger entry");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_ledger` against the connection default
        // schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT entry_json::text FROM billing_ledger WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(ledger_entry_from_row).transpose()
    }

    async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        let created_at_unix = saturating_i64(now_unix_seconds());
        let operation = self.billing_outbox_operation("enqueue billing report");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO billing_report_outbox \
                 (id, event_json, attempts, next_attempt_unix, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2::text::jsonb, 0, $3, $4, $4) \
                 ON CONFLICT (id) DO NOTHING",
                &[&id, &event_json, &next_attempt_unix, &created_at_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    fn billing_outbox_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        let operation = self.billing_outbox_operation("list due billing reports");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, event_json::text, attempts, next_attempt_unix, dead_lettered_at_unix \
                 FROM billing_report_outbox \
                 WHERE next_attempt_unix <= $1 AND dead_lettered_at_unix IS NULL \
                 ORDER BY next_attempt_unix ASC LIMIT $2",
                &[&now_unix, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(billing_report_outbox_from_row).collect()
    }

    async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        let updated_at_unix = saturating_i64(now_unix_seconds());
        let operation = self.billing_outbox_operation("reschedule billing report");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "UPDATE billing_report_outbox \
                 SET attempts = attempts + 1, next_attempt_unix = $2, updated_at_unix = $3 \
                 WHERE id = $1",
                &[&id, &next_attempt_unix, &updated_at_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    /// Mark a permanently-failing report dead-lettered (issue #143) instead of
    /// rescheduling it forever. The row is kept for operator inspection and
    /// excluded from `list_due_billing_reports`.
    async fn dead_letter_billing_report(&self, id: &str) -> Result<(), StorageError> {
        let now = saturating_i64(now_unix_seconds());
        let operation = self.billing_outbox_operation("dead letter billing report");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "UPDATE billing_report_outbox \
                 SET dead_lettered_at_unix = $2, updated_at_unix = $2 \
                 WHERE id = $1",
                &[&id, &now],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn list_dead_lettered_billing_reports(
        &self,
        limit: i64,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        let operation = self.billing_outbox_operation("list dead lettered billing reports");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, event_json::text, attempts, next_attempt_unix, dead_lettered_at_unix \
                 FROM billing_report_outbox WHERE dead_lettered_at_unix IS NOT NULL \
                 ORDER BY dead_lettered_at_unix DESC LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(billing_report_outbox_from_row).collect()
    }

    /// Conditionally re-enqueue a dead-lettered report for redelivery (issue
    /// #388). One short conditional `UPDATE ... WHERE dead_lettered_at_unix
    /// IS NOT NULL` performs the CAS: it clears the dead-letter mark, resets
    /// the attempt counter, and schedules the row for immediate delivery,
    /// returning the updated row so the memory and Postgres backends agree on
    /// the re-enqueued state. When zero rows match, a single follow-up SELECT
    /// distinguishes a missing id (`NotFound`) from a live/already-replayed
    /// row (`NotDeadLettered`) -- fail closed either way, no mutation.
    async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        let now = saturating_i64(now_unix_seconds());
        let operation = self.billing_outbox_operation("replay dead lettered billing report");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let replayed = transaction
            .query_opt(
                "UPDATE billing_report_outbox \
                 SET dead_lettered_at_unix = NULL, attempts = 0, \
                     next_attempt_unix = $2, updated_at_unix = $3 \
                 WHERE id = $1 AND dead_lettered_at_unix IS NOT NULL \
                 RETURNING id, event_json::text, attempts, next_attempt_unix, \
                     dead_lettered_at_unix",
                &[&id, &next_attempt_unix, &now],
            )
            .await
            .map_err(postgres_error)?;
        let outcome = match replayed {
            Some(row) => ReplayDeadLetterOutcome::Replayed(billing_report_outbox_from_row(&row)?),
            None => {
                let existing = transaction
                    .query_opt(
                        "SELECT id, event_json::text, attempts, next_attempt_unix, \
                             dead_lettered_at_unix \
                         FROM billing_report_outbox WHERE id = $1",
                        &[&id],
                    )
                    .await
                    .map_err(postgres_error)?;
                match existing {
                    Some(row) => ReplayDeadLetterOutcome::NotDeadLettered(
                        billing_report_outbox_from_row(&row)?,
                    ),
                    None => ReplayDeadLetterOutcome::NotFound,
                }
            }
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(outcome)
    }

    /// Fetch a single billing-report outbox row by id (issue #388), used to
    /// tenant-authorize a dead-letter replay before the mutation runs.
    async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        let operation = self.billing_outbox_operation("get billing report outbox entry");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, event_json::text, attempts, next_attempt_unix, \
                     dead_lettered_at_unix \
                 FROM billing_report_outbox WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(billing_report_outbox_from_row).transpose()
    }

    async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError> {
        let operation = self.billing_outbox_operation("delete billing report");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238); a bare
        // query would resolve `billing_report_outbox` against the connection
        // default schema (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute("DELETE FROM billing_report_outbox WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn append_billing_event(&self, event: &BillingEvent) -> Result<bool, StorageError> {
        self.append_billing_event_impl(event, None).await
    }

    /// Combines the metering write with the durable billing-report outbox
    /// enqueue (issue #150) into a single transaction/round-trip, instead of
    /// two sequential synchronous writes on the request-response hot path.
    ///
    /// Tradeoff, documented deliberately: because both inserts share one
    /// transaction, a failure of the (normally trivial) outbox insert now
    /// fails the whole call, same as a metering-write failure already did —
    /// there is no partial-success case to reconcile. This is judged
    /// acceptable because both writes target the same database, so a real
    /// outage fails both anyway; the common (all-success) case is what
    /// benefits from dropping the second round-trip.
    async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: &BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<bool, StorageError> {
        self.append_billing_event_impl(event, Some((outbox_id, outbox_next_attempt_unix)))
            .await
    }

    async fn append_billing_event_impl(
        &self,
        event: &BillingEvent,
        outbox_enqueue: Option<(&str, i64)>,
    ) -> Result<bool, StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix = event.occurred_at_unix.unwrap_or_else(now_unix_seconds);
        let workflow_version = event.workflow_version.map(|value| value as i32);
        let prompt_tokens = saturating_i64(event.usage.prompt_tokens);
        let completion_tokens = saturating_i64(event.usage.completion_tokens);
        let total_tokens = saturating_i64(event.usage.total_tokens);
        let status_code = i32::from(event.status_code);
        let usage_source = event.usage_source.as_str();
        let latency_ms = event.latency_ms.map(saturating_i64);
        let is_error = event.status_code >= 400;
        let period_month = period_month_from_unix(saturating_i64(occurred_at_unix));
        let outbox_event_json = outbox_enqueue
            .is_some()
            .then(|| serialize_storage_document(event))
            .transpose()?;
        let event_json = serialize_storage_document(event)?;
        let metadata_json = serialize_storage_document(&event.metadata)?;
        let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(event);
        let operation = self.billing_outbox_operation("append billing event");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        // Pin `search_path` to the configured `postgres_schema` as the FIRST
        // statement inside the EXISTING settlement transaction (#238) so every
        // metering/usage/outbox write below lands in the configured schema, not
        // the connection default (`public` on stock Supabase roles). Applied
        // in-place — not as a nested transaction — to preserve the outbox-enqueue
        // + billing-insert atomicity guarantee (#150).
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        upsert_tenant_context_async(&transaction, &tenant_context_id, &event.tenant).await?;
        let inserted = transaction
            .execute(
                "INSERT INTO metering_events \
                 (billing_event_id, request_id, provider_attempt_id, provider_attempt_index, \
                  tenant_context_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                  workflow_node_id, cluster_id, node_id, status_code, occurred_at_unix, cost_usd, \
                  latency_ms, metadata_json, event_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16, $17::text::jsonb, $18::text::jsonb) \
                 ON CONFLICT (billing_event_id) DO NOTHING",
                &[
                    &billing_event_id,
                    &event.request_id,
                    &event.provider_attempt.provider_attempt_id,
                    &(event.provider_attempt.provider_attempt_index as i32),
                    &tenant_context_id,
                    &event.trace_id,
                    &event.agent_run_id,
                    &event.workflow_id,
                    &workflow_version,
                    &event.workflow_node_id,
                    &event.cluster_id,
                    &event.node_id,
                    &status_code,
                    &saturating_i64(occurred_at_unix),
                    &event.cost_usd,
                    &latency_ms,
                    &metadata_json,
                    &event_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        if inserted == 1 {
            transaction
                .execute(
                    "INSERT INTO metering_event_routes \
                     (billing_event_id, request_id, logical_model, provider, provider_model) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[
                        &billing_event_id,
                        &event.request_id,
                        &event.logical_model,
                        &event.provider,
                        &event.provider_model,
                    ],
                )
                .await
                .map_err(postgres_error)?;
            transaction
                .execute(
                    "INSERT INTO metering_event_usage \
                     (billing_event_id, request_id, prompt_tokens, completion_tokens, total_tokens, \
                      usage_source) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &billing_event_id,
                        &event.request_id,
                        &prompt_tokens,
                        &completion_tokens,
                        &total_tokens,
                        &usage_source,
                    ],
                )
                .await
                .map_err(postgres_error)?;
            let rollup = UsageRollupUpsert {
                id: &usage_aggregate_id(&event.tenant, &event.logical_model, &event.provider),
                tenant_context_id: &tenant_context_id,
                logical_model: &event.logical_model,
                provider: &event.provider,
                prompt_tokens,
                completion_tokens,
                total_tokens,
            };
            upsert_usage_rollup_delta(&transaction, &rollup).await?;
            let usage_delta = UsageMonthlyDelta {
                prompt_tokens: event.usage.prompt_tokens,
                completion_tokens: event.usage.completion_tokens,
                total_tokens: event.usage.total_tokens,
                cost_usd: event.cost_usd.unwrap_or(0.0),
                is_error,
            };
            increment_usage_monthly_rollups(
                &transaction,
                &event.tenant,
                &period_month,
                &usage_delta,
            )
            .await?;
            increment_usage_metadata_rollups(
                &transaction,
                &event.tenant,
                &event.metadata,
                &period_month,
                &usage_delta,
            )
            .await?;
            if let (Some((outbox_id, next_attempt_unix)), Some(event_json)) =
                (outbox_enqueue, outbox_event_json.as_ref())
            {
                let created_at_unix = saturating_i64(now_unix_seconds());
                transaction
                    .execute(
                        "INSERT INTO billing_report_outbox \
                         (id, event_json, attempts, next_attempt_unix, created_at_unix, updated_at_unix) \
                         VALUES ($1, $2::text::jsonb, 0, $3, $4, $4) \
                         ON CONFLICT (id) DO NOTHING",
                        &[&outbox_id, event_json, &next_attempt_unix, &created_at_unix],
                    )
                    .await
                    .map_err(postgres_error)?;
            }
        }
        if inserted == 1 {
            transaction.commit().await.map_err(postgres_error)?;
        } else {
            // A conflicting attempt may carry a different tenant payload. Do not
            // commit its tenant-context upsert before exact replay is established.
            transaction.rollback().await.map_err(postgres_error)?;
        }
        // Release the pooled connection BEFORE the conflict-reload below.
        // `billing_event_settlement_matches` acquires its own connection from the
        // same pool; holding this one across that nested acquire self-deadlocks a
        // single-connection pool (`pool_size = 1`) until the acquire deadline
        // trips (`OperationDeadlineExceeded`), which is exactly what the live
        // idempotent-retry round-trip hit (#248).
        drop(client);
        if inserted == 1 {
            return Ok(true);
        }
        if self
            .billing_event_settlement_matches(&billing_event_id, event)
            .await?
        {
            Ok(false)
        } else {
            Err(StorageError::Conflict(format!(
                "billing event id {billing_event_id} was replayed with different provider-attempt settlement data"
            )))
        }
    }

    async fn billing_event_settlement_matches(
        &self,
        billing_event_id: &str,
        event: &BillingEvent,
    ) -> Result<bool, StorageError> {
        let operation = self.billing_outbox_operation("billing event settlement matches");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // conflict-reload read resolves `metering_events` in the same schema the
        // settlement transaction writes to, not the connection default.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT event_json::text FROM metering_events WHERE billing_event_id = $1",
                &[&billing_event_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let Some(row) = row else {
            return Err(StorageError::Runtime(format!(
                "billing event id {billing_event_id} conflicted but could not be reloaded"
            )));
        };
        let existing: BillingEvent = deserialize_storage_document(&row.get::<_, String>(0))?;
        Ok(same_billing_event_settlement(&existing, event))
    }

    fn observability_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn append_request_log(&self, log: &StoredRequestLog) -> Result<(), StorageError> {
        let request_json = serialize_storage_document(log)?;
        let tenant_context_id = tenant_storage_key(&log.tenant);
        let workflow_version = log.workflow_version.map(|value| value.to_string());
        let gateway_config_revision = log.gateway_config_revision.map(|value| value as i64);
        let status_code = i32::from(log.status_code);
        let started_at_unix = saturating_i64(log.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = log.completed_at_unix.map(saturating_i64);
        let operation = self.observability_operation("append request log");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO request_logs \
                 (request_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                  workflow_node_id, cluster_id, node_id, tenant, route, provider, logical_model, \
                  provider_model, gateway_config_id, gateway_config_revision, status_code, \
                  error_code, cache_status, started_at_unix, completed_at_unix, request_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16, $17, $18, $19, $20, $21::text::jsonb) \
                 ON CONFLICT (request_id) DO UPDATE SET \
                 trace_id = EXCLUDED.trace_id, \
                 agent_run_id = EXCLUDED.agent_run_id, \
                 workflow_id = EXCLUDED.workflow_id, \
                 workflow_version = EXCLUDED.workflow_version, \
                 workflow_node_id = EXCLUDED.workflow_node_id, \
                 cluster_id = EXCLUDED.cluster_id, \
                 node_id = EXCLUDED.node_id, \
                 tenant = EXCLUDED.tenant, \
                 route = EXCLUDED.route, \
                 provider = EXCLUDED.provider, \
                 logical_model = EXCLUDED.logical_model, \
                 provider_model = EXCLUDED.provider_model, \
                 gateway_config_id = EXCLUDED.gateway_config_id, \
                 gateway_config_revision = EXCLUDED.gateway_config_revision, \
                 status_code = EXCLUDED.status_code, \
                 error_code = EXCLUDED.error_code, \
                 cache_status = EXCLUDED.cache_status, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 request_json = EXCLUDED.request_json",
                &[
                    &log.request_id,
                    &log.trace_id,
                    &log.agent_run_id,
                    &log.workflow_id,
                    &workflow_version,
                    &log.workflow_node_id,
                    &log.cluster_id,
                    &log.node_id,
                    &tenant_context_id,
                    &log.route,
                    &log.provider,
                    &log.logical_model,
                    &log.provider_model,
                    &log.gateway_config_id,
                    &gateway_config_revision,
                    &status_code,
                    &log.error_code,
                    &log.cache_status,
                    &started_at_unix,
                    &completed_at_unix,
                    &request_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredRequestLog>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        let operation = self.observability_operation("request logs page");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT request_json::text, count(*) OVER() \
                 FROM request_logs \
                 ORDER BY started_at_unix ASC, request_id ASC \
                 OFFSET $1 LIMIT $2",
                &[&offset, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let total = rows
            .first()
            .map(|row| row.get::<_, i64>(1))
            .unwrap_or_default();
        let mut data = Vec::with_capacity(rows.len());
        for row in rows {
            data.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(StoragePage {
            data,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            offset: usize::try_from(offset).unwrap_or(usize::MAX),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        })
    }

    async fn request_logs(&self) -> Result<Vec<StoredRequestLog>, StorageError> {
        let operation = self.observability_operation("request logs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT request_json::text \
                 FROM request_logs \
                 ORDER BY started_at_unix ASC, request_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut logs = Vec::with_capacity(rows.len());
        for row in rows {
            logs.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(logs)
    }

    async fn append_audit_event(&self, event: &StoredAuditEvent) -> Result<(), StorageError> {
        let audit_json = serialize_storage_document(event)?;
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let workflow_version = event.workflow_version.map(|value| value.to_string());
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.observability_operation("append audit event");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO audit_events \
                 (id, request_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                  workflow_node_id, cluster_id, node_id, actor_api_key_id, tenant, action, target, \
                  outcome, occurred_at_unix, action_fingerprint, decision, decision_reason, \
                  output_disposition, audit_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16, $17, $18, $19, $20::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.request_id,
                    &event.trace_id,
                    &event.agent_run_id,
                    &event.workflow_id,
                    &workflow_version,
                    &event.workflow_node_id,
                    &event.cluster_id,
                    &event.node_id,
                    &event.actor_api_key_id,
                    &tenant_context_id,
                    &event.action,
                    &event.target,
                    &event.outcome,
                    &occurred_at_unix,
                    &event.action_fingerprint,
                    &event.decision,
                    &event.decision_reason,
                    &event.output_disposition,
                    &audit_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredAuditEvent>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        let operation = self.observability_operation("audit events page");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT audit_json::text, count(*) OVER() \
                 FROM audit_events \
                 ORDER BY occurred_at_unix ASC, id ASC \
                 OFFSET $1 LIMIT $2",
                &[&offset, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let total = rows
            .first()
            .map(|row| row.get::<_, i64>(1))
            .unwrap_or_default();
        let mut data = Vec::with_capacity(rows.len());
        for row in rows {
            data.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(StoragePage {
            data,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            offset: usize::try_from(offset).unwrap_or(usize::MAX),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        })
    }

    async fn audit_events(&self) -> Result<Vec<StoredAuditEvent>, StorageError> {
        let operation = self.observability_operation("audit events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT audit_json::text \
                 FROM audit_events \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(events)
    }

    /// #284: batched delete of `request_logs` rows by primary key, for the
    /// compliance retention sweeper. Idempotent (deleting an already-gone row
    /// is a no-op) so it is safe to run concurrently on every gateway instance.
    /// Returns the number of rows actually deleted.
    async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError> {
        if request_ids.is_empty() {
            return Ok(0);
        }
        let operation = self.observability_operation("prune request logs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute(
                "DELETE FROM request_logs WHERE request_id = ANY($1)",
                &[&request_ids],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected)
    }

    /// #284: batched delete of `audit_events` rows by primary key, for the
    /// compliance retention sweeper. Idempotent and multi-instance-safe.
    async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let operation = self.observability_operation("prune audit events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM audit_events WHERE id = ANY($1)", &[&ids])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected)
    }

    fn agent_run_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn upsert_agent_run(&self, run: &StoredAgentRun) -> Result<(), StorageError> {
        let run_json = serialize_storage_document(run)?;
        let tenant_context_id = tenant_storage_key(&run.tenant);
        let started_at_unix = saturating_i64(run.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = run.completed_at_unix.map(saturating_i64);
        let operation = self.agent_run_operation("upsert agent run");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO agent_runs \
                 (id, request_id, trace_id, tenant, status, provider, started_at_unix, \
                  completed_at_unix, run_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 request_id = EXCLUDED.request_id, \
                 trace_id = EXCLUDED.trace_id, \
                 tenant = EXCLUDED.tenant, \
                 status = EXCLUDED.status, \
                 provider = EXCLUDED.provider, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 run_json = EXCLUDED.run_json",
                &[
                    &run.id,
                    &run.request_id,
                    &run.trace_id,
                    &tenant_context_id,
                    &run.status,
                    &run.provider,
                    &started_at_unix,
                    &completed_at_unix,
                    &run_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn agent_run(&self, id: &str) -> Result<Option<StoredAgentRun>, StorageError> {
        let operation = self.agent_run_operation("get agent run");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT run_json::text FROM agent_runs WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.map(|row| deserialize_storage_document(row.get::<_, String>(0).as_str()))
            .transpose()
    }

    async fn agent_runs(&self) -> Result<Vec<StoredAgentRun>, StorageError> {
        let operation = self.agent_run_operation("list agent runs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT run_json::text \
                 FROM agent_runs \
                 ORDER BY started_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut runs = Vec::with_capacity(rows.len());
        for row in rows {
            runs.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(runs)
    }

    async fn append_agent_run_event(
        &self,
        event: &StoredAgentRunEvent,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let turn = saturating_i64(u64::from(event.turn));
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.agent_run_operation("append agent run event");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO agent_run_events \
                 (id, run_id, request_id, trace_id, tenant, turn, kind, target, outcome, \
                  occurred_at_unix, action_fingerprint, decision, decision_reason, \
                  output_disposition, event_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                         $15::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.run_id,
                    &event.request_id,
                    &event.trace_id,
                    &tenant_context_id,
                    &turn,
                    &event.kind,
                    &event.target,
                    &event.outcome,
                    &occurred_at_unix,
                    &event.action_fingerprint,
                    &event.decision,
                    &event.decision_reason,
                    &event.output_disposition,
                    &event_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn agent_run_events(&self) -> Result<Vec<StoredAgentRunEvent>, StorageError> {
        let operation = self.agent_run_operation("list agent run events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT event_json::text \
                 FROM agent_run_events \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(events)
    }

    /// Agent runs restricted to `run_ids` (issue #231): pushes the id filter
    /// into SQL instead of loading the whole table and filtering in memory.
    async fn agent_runs_by_ids(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAgentRun>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let operation = self.agent_run_operation("list agent runs by ids");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT run_json::text \
                 FROM agent_runs \
                 WHERE id = ANY($1) \
                 ORDER BY started_at_unix ASC, id ASC",
                &[&run_ids],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut runs = Vec::with_capacity(rows.len());
        for row in rows {
            runs.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(runs)
    }

    /// Agent-run events restricted to `run_ids` (issue #231).
    async fn agent_run_events_for_runs(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAgentRunEvent>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let operation = self.agent_run_operation("list agent run events for runs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT event_json::text \
                 FROM agent_run_events \
                 WHERE run_id = ANY($1) \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[&run_ids],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(events)
    }

    /// Request logs attributed to any of the given agent runs (issue #231).
    async fn request_logs_for_agent_runs(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredRequestLog>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let operation = self.observability_operation("request logs for agent runs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT request_json::text \
                 FROM request_logs \
                 WHERE agent_run_id = ANY($1) \
                 ORDER BY started_at_unix ASC, request_id ASC",
                &[&run_ids],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut logs = Vec::with_capacity(rows.len());
        for row in rows {
            logs.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(logs)
    }

    /// Audit events attributed to any of the given agent runs (issue #231).
    async fn audit_events_for_agent_runs(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAuditEvent>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let operation = self.observability_operation("audit events for agent runs");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT audit_json::text \
                 FROM audit_events \
                 WHERE agent_run_id = ANY($1) \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[&run_ids],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(deserialize_storage_document(
                row.get::<_, String>(0).as_str(),
            )?);
        }
        Ok(events)
    }

    /// Distinct agent-run ids known to the durable store, most recently seen
    /// first, LIMITed in SQL (issue #231). Replaces loading four whole
    /// tables into memory just to enumerate run ids for the admin summary
    /// list. `request_id` narrows the candidate set where the column exists;
    /// exact per-record filter semantics stay with the caller.
    async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        let limit = saturating_i64(limit as u64);
        let operation = self.agent_run_operation("agent run summary seed ids");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT run_id FROM ( \
                     SELECT id AS run_id, \
                            coalesce(completed_at_unix, started_at_unix, 0) AS seen_at \
                     FROM agent_runs \
                     WHERE ($1::text IS NULL OR request_id = $1) \
                   UNION ALL \
                     SELECT run_id, occurred_at_unix FROM agent_run_events \
                     WHERE ($1::text IS NULL OR request_id = $1) \
                   UNION ALL \
                     SELECT agent_run_id, coalesce(completed_at_unix, started_at_unix, 0) \
                     FROM request_logs \
                     WHERE agent_run_id IS NOT NULL \
                       AND ($1::text IS NULL OR request_id = $1) \
                   UNION ALL \
                     SELECT agent_run_id, occurred_at_unix FROM audit_events \
                     WHERE agent_run_id IS NOT NULL \
                       AND ($1::text IS NULL OR request_id = $1) \
                 ) seeds \
                 GROUP BY run_id \
                 ORDER BY max(seen_at) DESC, run_id ASC \
                 LIMIT $2",
                &[&request_id, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect())
    }

    /// Durable retention for `agent_run_events` (issue #231): keeps the
    /// newest `retain` events PER RUN, so one run's flood can only ever
    /// truncate that same run's own timeline on the durable path too.
    /// `retain == 0` disables pruning.
    async fn prune_agent_run_events(
        &self,
        run_id: &str,
        retain: usize,
    ) -> Result<u64, StorageError> {
        if retain == 0 {
            return Ok(0);
        }
        let offset = saturating_i64(retain as u64);
        let operation = self.agent_run_operation("prune agent run events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM agent_run_events WHERE id IN ( \
                     SELECT id FROM agent_run_events \
                     WHERE run_id = $1 \
                     ORDER BY occurred_at_unix DESC, id DESC \
                     OFFSET $2)",
                &[&run_id, &offset],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(deleted)
    }

    fn worker_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn upsert_managed_worker_template(
        &self,
        template: &StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        let max_tenant_sessions = template.max_tenant_sessions.map(i64::from);
        let max_workspace_sessions = template.max_workspace_sessions.map(i64::from);
        let created_at_unix =
            saturating_i64(template.created_at_unix.unwrap_or_else(now_unix_seconds));
        let updated_at_unix =
            saturating_i64(template.updated_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("upsert managed worker template");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_templates \
                 (id, framework_adapter, isolation_backend_kind, enabled, max_tenant_sessions, \
                  max_workspace_sessions, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO UPDATE SET \
                 framework_adapter = EXCLUDED.framework_adapter, \
                 isolation_backend_kind = EXCLUDED.isolation_backend_kind, \
                 enabled = EXCLUDED.enabled, \
                 max_tenant_sessions = EXCLUDED.max_tenant_sessions, \
                 max_workspace_sessions = EXCLUDED.max_workspace_sessions, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &template.id,
                    &template.framework_adapter,
                    &template.isolation_backend_kind,
                    &template.enabled,
                    &max_tenant_sessions,
                    &max_workspace_sessions,
                    &created_at_unix,
                    &updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_templates(
        &self,
    ) -> Result<Vec<StoredManagedWorkerTemplate>, StorageError> {
        let operation = self.worker_operation("list managed worker templates");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, framework_adapter, isolation_backend_kind, enabled, \
                    max_tenant_sessions, max_workspace_sessions, created_at_unix, \
                    updated_at_unix \
                 FROM managed_worker_templates \
                 ORDER BY id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_template_from_row)
            .collect())
    }

    async fn upsert_agent_worker_instance(
        &self,
        instance: &StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        let started_at_unix =
            saturating_i64(instance.started_at_unix.unwrap_or_else(now_unix_seconds));
        let last_seen_at_unix = instance.last_seen_at_unix.map(saturating_i64);
        let operation = self.worker_operation("upsert agent worker instance");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO agent_worker_instances \
                 (id, process_name, host_id, worker_version, status, started_at_unix, \
                  last_seen_at_unix, process_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 process_name = EXCLUDED.process_name, \
                 host_id = EXCLUDED.host_id, \
                 worker_version = EXCLUDED.worker_version, \
                 status = EXCLUDED.status, \
                 last_seen_at_unix = EXCLUDED.last_seen_at_unix, \
                 process_json = EXCLUDED.process_json",
                &[
                    &instance.id,
                    &instance.process_name,
                    &instance.host_id,
                    &instance.worker_version,
                    &instance.status,
                    &started_at_unix,
                    &last_seen_at_unix,
                    &instance.process_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn agent_worker_instances(&self) -> Result<Vec<StoredAgentWorkerInstance>, StorageError> {
        let operation = self.worker_operation("list agent worker instances");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, process_name, host_id, worker_version, status, started_at_unix, \
                    last_seen_at_unix, process_json::text \
                 FROM agent_worker_instances \
                 ORDER BY started_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(agent_worker_instance_from_row)
            .collect())
    }

    async fn upsert_managed_worker_session(
        &self,
        session: &StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&session.tenant);
        let requested_at_unix =
            saturating_i64(session.requested_at_unix.unwrap_or_else(now_unix_seconds));
        let started_at_unix = session.started_at_unix.map(saturating_i64);
        let completed_at_unix = session.completed_at_unix.map(saturating_i64);
        let cleanup_completed_at_unix = session.cleanup_completed_at_unix.map(saturating_i64);
        let operation = self.worker_operation("upsert managed worker session");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_sessions \
                 (id, run_id, tenant, workspace_id, worker_template_id, \
                  agent_worker_instance_id, status, isolation_backend_kind, microvm_id, \
                  capability_envelope_id, requested_at_unix, started_at_unix, completed_at_unix, \
                  cleanup_completed_at_unix, capability_envelope_json, resource_limits_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                         $15::text::jsonb, $16::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 worker_template_id = EXCLUDED.worker_template_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 status = EXCLUDED.status, \
                 isolation_backend_kind = EXCLUDED.isolation_backend_kind, \
                 microvm_id = EXCLUDED.microvm_id, \
                 capability_envelope_id = EXCLUDED.capability_envelope_id, \
                 started_at_unix = EXCLUDED.started_at_unix, \
                 completed_at_unix = EXCLUDED.completed_at_unix, \
                 cleanup_completed_at_unix = EXCLUDED.cleanup_completed_at_unix, \
                 capability_envelope_json = EXCLUDED.capability_envelope_json, \
                 resource_limits_json = EXCLUDED.resource_limits_json",
                &[
                    &session.id,
                    &session.run_id,
                    &tenant_context_id,
                    &session.workspace_id,
                    &session.worker_template_id,
                    &session.agent_worker_instance_id,
                    &session.status,
                    &session.isolation_backend_kind,
                    &session.microvm_id,
                    &session.capability_envelope_id,
                    &requested_at_unix,
                    &started_at_unix,
                    &completed_at_unix,
                    &cleanup_completed_at_unix,
                    &session.capability_envelope_json,
                    &session.resource_limits_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_sessions(
        &self,
    ) -> Result<Vec<StoredManagedWorkerSession>, StorageError> {
        let operation = self.worker_operation("list managed worker sessions");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, run_id, tenant, workspace_id, worker_template_id, \
                    agent_worker_instance_id, status, isolation_backend_kind, microvm_id, \
                    capability_envelope_id, requested_at_unix, started_at_unix, \
                    completed_at_unix, cleanup_completed_at_unix, \
                    capability_envelope_json::text, resource_limits_json::text \
                 FROM managed_worker_sessions \
                 ORDER BY requested_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_session_from_row)
            .collect())
    }

    async fn append_managed_worker_lifecycle_event(
        &self,
        event: &StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("append managed worker lifecycle event");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_lifecycle_events \
                 (id, session_id, run_id, tenant, workspace_id, agent_worker_instance_id, status, \
                  action, outcome, occurred_at_unix, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.session_id,
                    &event.run_id,
                    &tenant_context_id,
                    &event.workspace_id,
                    &event.agent_worker_instance_id,
                    &event.status,
                    &event.action,
                    &event.outcome,
                    &occurred_at_unix,
                    &event.evidence_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_lifecycle_events(
        &self,
    ) -> Result<Vec<StoredManagedWorkerLifecycleEvent>, StorageError> {
        let operation = self.worker_operation("list managed worker lifecycle events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, session_id, run_id, tenant, workspace_id, \
                    agent_worker_instance_id, status, action, outcome, occurred_at_unix, \
                    evidence_json::text \
                 FROM managed_worker_lifecycle_events \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_lifecycle_event_from_row)
            .collect())
    }

    async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: &StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&selection.tenant);
        let selected_at_unix =
            saturating_i64(selection.selected_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("upsert managed worker isolation selection");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_isolation_selections \
                 (session_id, run_id, tenant, workspace_id, agent_worker_instance_id, \
                  backend_name, backend_version, backend_kind, host_lifecycle_owner, \
                  gateway_controls_backend, capability_envelope_id, selected_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (session_id) DO UPDATE SET \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 backend_name = EXCLUDED.backend_name, \
                 backend_version = EXCLUDED.backend_version, \
                 backend_kind = EXCLUDED.backend_kind, \
                 host_lifecycle_owner = EXCLUDED.host_lifecycle_owner, \
                 gateway_controls_backend = EXCLUDED.gateway_controls_backend, \
                 capability_envelope_id = EXCLUDED.capability_envelope_id, \
                 selected_at_unix = EXCLUDED.selected_at_unix",
                &[
                    &selection.session_id,
                    &selection.run_id,
                    &tenant_context_id,
                    &selection.workspace_id,
                    &selection.agent_worker_instance_id,
                    &selection.backend_name,
                    &selection.backend_version,
                    &selection.backend_kind,
                    &selection.host_lifecycle_owner,
                    &selection.gateway_controls_backend,
                    &selection.capability_envelope_id,
                    &selected_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_isolation_selections(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationSelection>, StorageError> {
        let operation = self.worker_operation("list managed worker isolation selections");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT session_id, run_id, tenant, workspace_id, agent_worker_instance_id, \
                    backend_name, backend_version, backend_kind, host_lifecycle_owner, \
                    gateway_controls_backend, capability_envelope_id, selected_at_unix \
                 FROM managed_worker_isolation_selections \
                 ORDER BY selected_at_unix ASC, session_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_isolation_selection_from_row)
            .collect())
    }

    async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: &StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        let cpu_count = i32::from(policy.cpu_count);
        let memory_mib = saturating_i32(u64::from(policy.memory_mib));
        let disk_mib = saturating_i32(u64::from(policy.disk_mib));
        let max_runtime_millis = policy.max_runtime_millis.map(saturating_i64);
        let operation = self.worker_operation("upsert managed worker isolation policy");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_isolation_policies \
                 (session_id, cpu_count, memory_mib, disk_mib, max_runtime_millis, \
                  direct_public_egress, gateway_control_channel, governed_egress, \
                  read_only_rootfs, writable_workspace, host_path_mounts) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (session_id) DO UPDATE SET \
                 cpu_count = EXCLUDED.cpu_count, \
                 memory_mib = EXCLUDED.memory_mib, \
                 disk_mib = EXCLUDED.disk_mib, \
                 max_runtime_millis = EXCLUDED.max_runtime_millis, \
                 direct_public_egress = EXCLUDED.direct_public_egress, \
                 gateway_control_channel = EXCLUDED.gateway_control_channel, \
                 governed_egress = EXCLUDED.governed_egress, \
                 read_only_rootfs = EXCLUDED.read_only_rootfs, \
                 writable_workspace = EXCLUDED.writable_workspace, \
                 host_path_mounts = EXCLUDED.host_path_mounts",
                &[
                    &policy.session_id,
                    &cpu_count,
                    &memory_mib,
                    &disk_mib,
                    &max_runtime_millis,
                    &policy.direct_public_egress,
                    &policy.gateway_control_channel,
                    &policy.governed_egress,
                    &policy.read_only_rootfs,
                    &policy.writable_workspace,
                    &policy.host_path_mounts,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_isolation_policies(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationPolicy>, StorageError> {
        let operation = self.worker_operation("list managed worker isolation policies");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT session_id, cpu_count, memory_mib, disk_mib, max_runtime_millis, \
                    direct_public_egress, gateway_control_channel, governed_egress, \
                    read_only_rootfs, writable_workspace, host_path_mounts \
                 FROM managed_worker_isolation_policies \
                 ORDER BY session_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_isolation_policy_from_row)
            .collect())
    }

    async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: &StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&evidence.tenant);
        let occurred_at_unix =
            saturating_i64(evidence.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("upsert managed worker isolation evidence");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO managed_worker_isolation_evidence \
                 (id, session_id, lifecycle_event_id, run_id, tenant, workspace_id, \
                  agent_worker_instance_id, isolation_instance_id, action, outcome, \
                  failure_reason, occurred_at_unix, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 session_id = EXCLUDED.session_id, \
                 lifecycle_event_id = EXCLUDED.lifecycle_event_id, \
                 run_id = EXCLUDED.run_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 agent_worker_instance_id = EXCLUDED.agent_worker_instance_id, \
                 isolation_instance_id = EXCLUDED.isolation_instance_id, \
                 action = EXCLUDED.action, \
                 outcome = EXCLUDED.outcome, \
                 failure_reason = EXCLUDED.failure_reason, \
                 occurred_at_unix = EXCLUDED.occurred_at_unix, \
                 evidence_json = EXCLUDED.evidence_json",
                &[
                    &evidence.id,
                    &evidence.session_id,
                    &evidence.lifecycle_event_id,
                    &evidence.run_id,
                    &tenant_context_id,
                    &evidence.workspace_id,
                    &evidence.agent_worker_instance_id,
                    &evidence.isolation_instance_id,
                    &evidence.action,
                    &evidence.outcome,
                    &evidence.failure_reason,
                    &occurred_at_unix,
                    &evidence.evidence_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn managed_worker_isolation_evidence(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationEvidence>, StorageError> {
        let operation = self.worker_operation("list managed worker isolation evidence");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, session_id, lifecycle_event_id, run_id, tenant, workspace_id, \
                    agent_worker_instance_id, isolation_instance_id, action, outcome, \
                    failure_reason, occurred_at_unix, evidence_json::text \
                 FROM managed_worker_isolation_evidence \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(managed_worker_isolation_evidence_from_row)
            .collect())
    }

    async fn upsert_self_hosted_worker_registration(
        &self,
        registration: &StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&registration.tenant);
        let registered_at_unix = saturating_i64(
            registration
                .registered_at_unix
                .unwrap_or_else(now_unix_seconds),
        );
        let last_seen_at_unix = registration.last_seen_at_unix.map(saturating_i64);
        let identity_expires_at_unix = registration.identity_expires_at_unix.map(saturating_i64);
        let operation = self.worker_operation("upsert self hosted worker registration");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_worker_registrations \
                 (id, tenant, workspace_id, worker_name, status, identity_fingerprint, \
                  identity_expires_at_unix, orchestration_enabled, registered_at_unix, \
                  last_seen_at_unix, trust_level, capability_envelope_json, token_secret) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::jsonb, $13) \
                 ON CONFLICT (id) DO UPDATE SET \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 worker_name = EXCLUDED.worker_name, \
                 status = EXCLUDED.status, \
                 identity_fingerprint = EXCLUDED.identity_fingerprint, \
                 identity_expires_at_unix = EXCLUDED.identity_expires_at_unix, \
                 orchestration_enabled = EXCLUDED.orchestration_enabled, \
                 last_seen_at_unix = EXCLUDED.last_seen_at_unix, \
                 trust_level = EXCLUDED.trust_level, \
                 capability_envelope_json = EXCLUDED.capability_envelope_json, \
                 token_secret = EXCLUDED.token_secret",
                &[
                    &registration.id,
                    &tenant_context_id,
                    &registration.workspace_id,
                    &registration.worker_name,
                    &registration.status,
                    &registration.identity_fingerprint,
                    &identity_expires_at_unix,
                    &registration.orchestration_enabled,
                    &registered_at_unix,
                    &last_seen_at_unix,
                    &registration.trust_level,
                    &registration.capability_envelope_json,
                    &registration.token_secret,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_worker_registrations(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerRegistration>, StorageError> {
        let operation = self.worker_operation("list self hosted worker registrations");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant, workspace_id, worker_name, status, identity_fingerprint, \
                    identity_expires_at_unix, orchestration_enabled, registered_at_unix, \
                    last_seen_at_unix, trust_level, capability_envelope_json::text, token_secret \
                 FROM self_hosted_worker_registrations \
                 ORDER BY registered_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_registration_from_row)
            .collect())
    }

    async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: &StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&heartbeat.tenant);
        let reported_at_unix =
            saturating_i64(heartbeat.reported_at_unix.unwrap_or_else(now_unix_seconds));
        let observed_at_unix =
            saturating_i64(heartbeat.observed_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("append self hosted worker heartbeat");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_worker_heartbeats \
                 (id, worker_id, tenant, workspace_id, status, reported_at_unix, \
                  observed_at_unix, heartbeat_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &heartbeat.id,
                    &heartbeat.worker_id,
                    &tenant_context_id,
                    &heartbeat.workspace_id,
                    &heartbeat.status,
                    &reported_at_unix,
                    &observed_at_unix,
                    &heartbeat.heartbeat_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_worker_heartbeats(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerHeartbeat>, StorageError> {
        let operation = self.worker_operation("list self hosted worker heartbeats");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, status, reported_at_unix, \
                    observed_at_unix, heartbeat_json::text \
                 FROM self_hosted_worker_heartbeats \
                 ORDER BY reported_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_heartbeat_from_row)
            .collect())
    }

    async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: &StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&event.tenant);
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let ingested_at_unix =
            saturating_i64(event.ingested_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("append self hosted worker telemetry event");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_worker_telemetry_events \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, kind, trust_level, \
                  occurred_at_unix, ingested_at_unix, event_json, request_id, trace_id, \
                  agent_run_id, parent_action_fingerprint) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb, $12, $13, \
                  $14, $15) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &event.id,
                    &event.worker_id,
                    &tenant_context_id,
                    &event.workspace_id,
                    &event.session_id,
                    &event.run_id,
                    &event.kind,
                    &event.trust_level,
                    &occurred_at_unix,
                    &ingested_at_unix,
                    &event.event_json,
                    &event.request_id,
                    &event.trace_id,
                    &event.agent_run_id,
                    &event.parent_action_fingerprint,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        let operation = self.worker_operation("list self hosted worker telemetry events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, kind, \
                    trust_level, occurred_at_unix, ingested_at_unix, event_json::text, \
                    request_id, trace_id, agent_run_id, parent_action_fingerprint \
                 FROM self_hosted_worker_telemetry_events \
                 ORDER BY occurred_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_telemetry_event_from_row)
            .collect())
    }

    async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: &StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&artifact.tenant);
        let size_bytes = saturating_i64(artifact.size_bytes);
        let created_at_unix =
            saturating_i64(artifact.created_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("upsert self hosted worker artifact");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_worker_artifacts \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, artifact_name, \
                  content_type, size_bytes, trust_level, created_at_unix, artifact_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 worker_id = EXCLUDED.worker_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 session_id = EXCLUDED.session_id, \
                 run_id = EXCLUDED.run_id, \
                 artifact_name = EXCLUDED.artifact_name, \
                 content_type = EXCLUDED.content_type, \
                 size_bytes = EXCLUDED.size_bytes, \
                 trust_level = EXCLUDED.trust_level, \
                 artifact_json = EXCLUDED.artifact_json",
                &[
                    &artifact.id,
                    &artifact.worker_id,
                    &tenant_context_id,
                    &artifact.workspace_id,
                    &artifact.session_id,
                    &artifact.run_id,
                    &artifact.artifact_name,
                    &artifact.content_type,
                    &size_bytes,
                    &artifact.trust_level,
                    &created_at_unix,
                    &artifact.artifact_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_worker_artifacts(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerArtifact>, StorageError> {
        let operation = self.worker_operation("list self hosted worker artifacts");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                    artifact_name, content_type, size_bytes, trust_level, created_at_unix, \
                    artifact_json::text \
                 FROM self_hosted_worker_artifacts \
                 ORDER BY created_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_artifact_from_row)
            .collect())
    }

    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: &StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_storage_key(&checkpoint.tenant);
        let size_bytes = saturating_i64(checkpoint.size_bytes);
        let created_at_unix =
            saturating_i64(checkpoint.created_at_unix.unwrap_or_else(now_unix_seconds));
        let operation = self.worker_operation("upsert self hosted worker checkpoint");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_worker_checkpoints \
                 (id, worker_id, tenant, workspace_id, session_id, run_id, checkpoint_name, \
                  size_bytes, trust_level, created_at_unix, checkpoint_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb) \
                 ON CONFLICT (id) DO UPDATE SET \
                 worker_id = EXCLUDED.worker_id, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 session_id = EXCLUDED.session_id, \
                 run_id = EXCLUDED.run_id, \
                 checkpoint_name = EXCLUDED.checkpoint_name, \
                 size_bytes = EXCLUDED.size_bytes, \
                 trust_level = EXCLUDED.trust_level, \
                 checkpoint_json = EXCLUDED.checkpoint_json",
                &[
                    &checkpoint.id,
                    &checkpoint.worker_id,
                    &tenant_context_id,
                    &checkpoint.workspace_id,
                    &checkpoint.session_id,
                    &checkpoint.run_id,
                    &checkpoint.checkpoint_name,
                    &size_bytes,
                    &checkpoint.trust_level,
                    &created_at_unix,
                    &checkpoint.checkpoint_json,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_worker_checkpoints(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerCheckpoint>, StorageError> {
        let operation = self.worker_operation("list self hosted worker checkpoints");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                    checkpoint_name, size_bytes, trust_level, created_at_unix, \
                    checkpoint_json::text \
                 FROM self_hosted_worker_checkpoints \
                 ORDER BY created_at_unix ASC, id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_checkpoint_from_row)
            .collect())
    }

    /// Single-registration lookup (issue #231): the worker write hot path
    /// used to list ALL registrations and filter in memory.
    async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerRegistration>, StorageError> {
        let operation = self.worker_operation("get self hosted worker registration");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, tenant, workspace_id, worker_name, status, identity_fingerprint, \
                    identity_expires_at_unix, orchestration_enabled, registered_at_unix, \
                    last_seen_at_unix, trust_level, capability_envelope_json::text, token_secret \
                 FROM self_hosted_worker_registrations \
                 WHERE id = $1",
                &[&worker_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(self_hosted_worker_registration_from_row))
    }

    /// Latest heartbeat for one worker, filtered + LIMITed in SQL (#231).
    async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerHeartbeat>, StorageError> {
        let operation = self.worker_operation("latest self hosted worker heartbeat");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, worker_id, tenant, workspace_id, status, reported_at_unix, \
                    observed_at_unix, heartbeat_json::text \
                 FROM self_hosted_worker_heartbeats \
                 WHERE worker_id = $1 \
                 ORDER BY reported_at_unix DESC, id DESC \
                 LIMIT 1",
                &[&worker_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(self_hosted_worker_heartbeat_from_row))
    }

    /// Durable per-worker heartbeat retention (issue #231): keeps the newest
    /// `retain` heartbeats for `worker_id`. `retain == 0` disables pruning.
    async fn prune_self_hosted_worker_heartbeats(
        &self,
        worker_id: &str,
        retain: usize,
    ) -> Result<u64, StorageError> {
        if retain == 0 {
            return Ok(0);
        }
        let offset = saturating_i64(retain as u64);
        let operation = self.worker_operation("prune self hosted worker heartbeats");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM self_hosted_worker_heartbeats WHERE id IN ( \
                     SELECT id FROM self_hosted_worker_heartbeats \
                     WHERE worker_id = $1 \
                     ORDER BY reported_at_unix DESC, id DESC \
                     OFFSET $2)",
                &[&worker_id, &offset],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(deleted)
    }

    /// Telemetry events for one run, newest-`limit` selected in SQL and
    /// returned in ascending timeline order (issue #231). Keeping the NEWEST
    /// window (instead of the oldest) preserves the run's latest lifecycle
    /// state when a run exceeds the limit.
    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        let limit = if limit == 0 {
            i64::MAX
        } else {
            saturating_i64(limit as u64)
        };
        let operation = self.worker_operation("list self hosted telemetry events for run");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, kind, \
                    trust_level, occurred_at_unix, ingested_at_unix, event_json::text, \
                    request_id, trace_id, agent_run_id, parent_action_fingerprint \
                 FROM self_hosted_worker_telemetry_events \
                 WHERE run_id = $1 \
                 ORDER BY occurred_at_unix DESC, ingested_at_unix DESC, id DESC \
                 LIMIT $2",
                &[&run_id, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut events: Vec<_> = rows
            .into_iter()
            .map(self_hosted_worker_telemetry_event_from_row)
            .collect();
        events.reverse();
        Ok(events)
    }

    /// Telemetry events for one worker, filtered in SQL (issue #231). The
    /// result is bounded by the per-worker durable retention prune.
    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        let operation = self.worker_operation("list self hosted telemetry events for worker");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, kind, \
                    trust_level, occurred_at_unix, ingested_at_unix, event_json::text, \
                    request_id, trace_id, agent_run_id, parent_action_fingerprint \
                 FROM self_hosted_worker_telemetry_events \
                 WHERE worker_id = $1 \
                 ORDER BY occurred_at_unix ASC, ingested_at_unix ASC, id ASC",
                &[&worker_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows
            .into_iter()
            .map(self_hosted_worker_telemetry_event_from_row)
            .collect())
    }

    /// Durable per-worker telemetry retention (issue #231). `retain == 0`
    /// disables pruning.
    async fn prune_self_hosted_worker_telemetry_events(
        &self,
        worker_id: &str,
        retain: usize,
    ) -> Result<u64, StorageError> {
        if retain == 0 {
            return Ok(0);
        }
        let offset = saturating_i64(retain as u64);
        let operation = self.worker_operation("prune self hosted worker telemetry events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM self_hosted_worker_telemetry_events WHERE id IN ( \
                     SELECT id FROM self_hosted_worker_telemetry_events \
                     WHERE worker_id = $1 \
                     ORDER BY occurred_at_unix DESC, id DESC \
                     OFFSET $2)",
                &[&worker_id, &offset],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(deleted)
    }

    /// Single-artifact lookup by id (issue #231): the cross-worker overwrite
    /// guard (#228) used to list the whole table to find one id.
    async fn self_hosted_worker_artifact(
        &self,
        id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerArtifact>, StorageError> {
        let operation = self.worker_operation("get self hosted worker artifact");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                    artifact_name, content_type, size_bytes, trust_level, created_at_unix, \
                    artifact_json::text \
                 FROM self_hosted_worker_artifacts \
                 WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(self_hosted_worker_artifact_from_row))
    }

    /// Durable per-worker distinct-artifact retention (issue #231). Keeps
    /// the newest `retain` artifacts owned by `worker_id`; `retain == 0`
    /// disables pruning.
    async fn prune_self_hosted_worker_artifacts(
        &self,
        worker_id: &str,
        retain: usize,
    ) -> Result<u64, StorageError> {
        if retain == 0 {
            return Ok(0);
        }
        let offset = saturating_i64(retain as u64);
        let operation = self.worker_operation("prune self hosted worker artifacts");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM self_hosted_worker_artifacts WHERE id IN ( \
                     SELECT id FROM self_hosted_worker_artifacts \
                     WHERE worker_id = $1 \
                     ORDER BY created_at_unix DESC, id DESC \
                     OFFSET $2)",
                &[&worker_id, &offset],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(deleted)
    }

    /// Single-checkpoint lookup by id (issue #231); see the artifact twin.
    async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerCheckpoint>, StorageError> {
        let operation = self.worker_operation("get self hosted worker checkpoint");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, worker_id, tenant, workspace_id, session_id, run_id, \
                    checkpoint_name, size_bytes, trust_level, created_at_unix, \
                    checkpoint_json::text \
                 FROM self_hosted_worker_checkpoints \
                 WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.map(self_hosted_worker_checkpoint_from_row))
    }

    /// Durable per-worker distinct-checkpoint retention (issue #231).
    /// `retain == 0` disables pruning.
    async fn prune_self_hosted_worker_checkpoints(
        &self,
        worker_id: &str,
        retain: usize,
    ) -> Result<u64, StorageError> {
        if retain == 0 {
            return Ok(0);
        }
        let offset = saturating_i64(retain as u64);
        let operation = self.worker_operation("prune self hosted worker checkpoints");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM self_hosted_worker_checkpoints WHERE id IN ( \
                     SELECT id FROM self_hosted_worker_checkpoints \
                     WHERE worker_id = $1 \
                     ORDER BY created_at_unix DESC, id DESC \
                     OFFSET $2)",
                &[&worker_id, &offset],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(deleted)
    }

    /// Per-worker activity aggregates computed in SQL (issue #231): the
    /// worker record used to be assembled by loading FOUR whole tables just
    /// to count and take maxima for a single worker.
    async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> Result<StoredSelfHostedWorkerActivityStats, StorageError> {
        let operation = self.worker_operation("self hosted worker activity stats");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_one(
                "SELECT \
                    (SELECT count(*) FROM self_hosted_worker_telemetry_events \
                     WHERE worker_id = $1), \
                    (SELECT max(occurred_at_unix) FROM self_hosted_worker_telemetry_events \
                     WHERE worker_id = $1), \
                    (SELECT count(*) FROM self_hosted_worker_artifacts \
                     WHERE worker_id = $1), \
                    (SELECT max(created_at_unix) FROM self_hosted_worker_artifacts \
                     WHERE worker_id = $1), \
                    (SELECT count(*) FROM self_hosted_worker_checkpoints \
                     WHERE worker_id = $1), \
                    (SELECT max(created_at_unix) FROM self_hosted_worker_checkpoints \
                     WHERE worker_id = $1)",
                &[&worker_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let as_count = |value: i64| usize::try_from(value).unwrap_or_default();
        let as_unix = |value: Option<i64>| value.and_then(|value| u64::try_from(value).ok());
        Ok(StoredSelfHostedWorkerActivityStats {
            telemetry_event_count: as_count(row.get(0)),
            latest_event_at_unix: as_unix(row.get(1)),
            artifact_count: as_count(row.get(2)),
            latest_artifact_at_unix: as_unix(row.get(3)),
            checkpoint_count: as_count(row.get(4)),
            latest_checkpoint_at_unix: as_unix(row.get(5)),
        })
    }

    async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: &StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        let tenant_context_id = dispatch.tenant_id.clone();
        let queued_at_unix =
            saturating_i64(dispatch.queued_at_unix.unwrap_or_else(now_unix_seconds));
        let lease_expires_at_unix = dispatch.lease_expires_at_unix.map(saturating_i64);
        let acknowledged_at_unix = dispatch.acknowledged_at_unix.map(saturating_i64);
        let attempt = saturating_i64(u64::from(dispatch.attempt));
        let operation = self.worker_operation("upsert self hosted run dispatch");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239 follow-up)
        // as the FIRST statement inside this multi-statement transaction so
        // `self_hosted_run_dispatches` and `self_hosted_run_dispatch_capabilities`
        // resolve in the same schema the reader (`self_hosted_run_dispatches`)
        // uses, not the connection default (`public` on stock Supabase roles). A
        // bare transaction here wrote dispatches to a schema the reader never saw.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO self_hosted_run_dispatches \
                 (dispatch_id, action, tenant, workspace_id, session_id, run_id, \
                  framework_adapter, workload_ref, queued_at_unix, assigned_worker_id, \
                  lease_id, lease_expires_at_unix, attempt, acknowledged_status, \
                  acknowledged_at_unix, request_id, trace_id, agent_run_id, \
                  parent_action_fingerprint) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                         $16, $17, $18, $19) \
                 ON CONFLICT (dispatch_id) DO UPDATE SET \
                 action = EXCLUDED.action, \
                 tenant = EXCLUDED.tenant, \
                 workspace_id = EXCLUDED.workspace_id, \
                 session_id = EXCLUDED.session_id, \
                 run_id = EXCLUDED.run_id, \
                 framework_adapter = EXCLUDED.framework_adapter, \
                 workload_ref = EXCLUDED.workload_ref, \
                 queued_at_unix = EXCLUDED.queued_at_unix, \
                 assigned_worker_id = EXCLUDED.assigned_worker_id, \
                 lease_id = EXCLUDED.lease_id, \
                 lease_expires_at_unix = EXCLUDED.lease_expires_at_unix, \
                 attempt = EXCLUDED.attempt, \
                 acknowledged_status = EXCLUDED.acknowledged_status, \
                 acknowledged_at_unix = EXCLUDED.acknowledged_at_unix, \
                 request_id = EXCLUDED.request_id, \
                 trace_id = EXCLUDED.trace_id, \
                 agent_run_id = EXCLUDED.agent_run_id, \
                 parent_action_fingerprint = EXCLUDED.parent_action_fingerprint",
                &[
                    &dispatch.dispatch_id,
                    &dispatch.action,
                    &tenant_context_id,
                    &dispatch.workspace_id,
                    &dispatch.session_id,
                    &dispatch.run_id,
                    &dispatch.framework_adapter,
                    &dispatch.workload_ref,
                    &queued_at_unix,
                    &dispatch.assigned_worker_id,
                    &dispatch.lease_id,
                    &lease_expires_at_unix,
                    &attempt,
                    &dispatch.acknowledged_status,
                    &acknowledged_at_unix,
                    &dispatch.request_id,
                    &dispatch.trace_id,
                    &dispatch.agent_run_id,
                    &dispatch.parent_action_fingerprint,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction
            .execute(
                "DELETE FROM self_hosted_run_dispatch_capabilities WHERE dispatch_id = $1",
                &[&dispatch.dispatch_id],
            )
            .await
            .map_err(postgres_error)?;
        for capability in &dispatch.required_capabilities {
            transaction
                .execute(
                    "INSERT INTO self_hosted_run_dispatch_capabilities \
                     (dispatch_id, capability) VALUES ($1, $2) \
                     ON CONFLICT (dispatch_id, capability) DO NOTHING",
                    &[&dispatch.dispatch_id, capability],
                )
                .await
                .map_err(postgres_error)?;
        }
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn self_hosted_run_dispatches(
        &self,
    ) -> Result<Vec<StoredSelfHostedRunDispatch>, StorageError> {
        let operation = self.worker_operation("list self hosted run dispatches");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT dispatch_id, action, tenant, workspace_id, session_id, run_id, \
                    framework_adapter, workload_ref, queued_at_unix, assigned_worker_id, \
                    lease_id, lease_expires_at_unix, attempt, acknowledged_status, \
                    acknowledged_at_unix, request_id, trace_id, agent_run_id, \
                    parent_action_fingerprint \
                 FROM self_hosted_run_dispatches \
                 ORDER BY queued_at_unix ASC, dispatch_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        let capability_rows = transaction
            .query(
                "SELECT dispatch_id, capability \
                 FROM self_hosted_run_dispatch_capabilities \
                 ORDER BY dispatch_id ASC, capability ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let mut capabilities = HashMap::<String, Vec<String>>::new();
        for row in capability_rows {
            capabilities
                .entry(row.get::<_, String>(0))
                .or_default()
                .push(row.get(1));
        }
        Ok(rows
            .into_iter()
            .map(|row| self_hosted_run_dispatch_from_row(row, &capabilities))
            .collect())
    }

    async fn billing_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<BillingEvent>, StorageError> {
        let offset = saturating_i64(offset as u64);
        let limit = saturating_i64(limit as u64);
        let operation = self.billing_ledger_operation("billing events page");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `metering_events` in the same schema the settlement
        // transaction writes to, not the connection default (`public`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT e.event_json::text, count(*) OVER() \
                 FROM metering_events e \
                 ORDER BY e.occurred_at_unix ASC, e.request_id ASC, e.provider_attempt_index ASC \
                 OFFSET $1 LIMIT $2",
                &[&offset, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let total = rows
            .first()
            .map(|row| row.get::<_, i64>(1))
            .unwrap_or_default();
        let data = rows
            .into_iter()
            .map(|row| deserialize_billing_event_document(&row.get::<_, String>(0)))
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok(StoragePage {
            data,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            offset: usize::try_from(offset).unwrap_or(usize::MAX),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        })
    }

    async fn billing_events(&self) -> Result<Vec<BillingEvent>, StorageError> {
        let operation = self.billing_ledger_operation("list billing events");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `metering_events` in the same schema the settlement
        // transaction writes to, not the connection default (`public`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT e.event_json::text \
                 FROM metering_events e \
                 ORDER BY e.occurred_at_unix ASC, e.request_id ASC, e.provider_attempt_index ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.into_iter()
            .map(|row| deserialize_billing_event_document(&row.get::<_, String>(0)))
            .collect()
    }

    async fn upsert_usage_aggregate(
        &self,
        aggregate: &StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let tenant_context_id = tenant_parts_storage_key(
            aggregate.organization_id.as_deref(),
            None,
            aggregate.project_id.as_deref(),
            None,
            None,
            aggregate.api_key_id.as_deref(),
        );
        let prompt_tokens = saturating_i64(aggregate.usage.prompt_tokens);
        let completion_tokens = saturating_i64(aggregate.usage.completion_tokens);
        let total_tokens = saturating_i64(aggregate.usage.total_tokens);
        let operation = self.observability_operation("upsert usage aggregate");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so the
        // tenant-context + usage-aggregate upserts land in the same schema as the
        // settlement transaction, not the connection default (`public`).
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        upsert_tenant_context_parts(
            &transaction,
            &tenant_context_id,
            &TenantContextParts {
                organization_id: aggregate.organization_id.as_deref(),
                team_id: None,
                project_id: aggregate.project_id.as_deref(),
                workspace_id: None,
                user_id: None,
                api_key_id: aggregate.api_key_id.as_deref(),
            },
        )
        .await?;
        let rollup = UsageRollupUpsert {
            id: &aggregate.id,
            tenant_context_id: &tenant_context_id,
            logical_model: &aggregate.logical_model,
            provider: &aggregate.provider,
            prompt_tokens,
            completion_tokens,
            total_tokens,
        };
        replace_usage_rollup(&transaction, &rollup).await?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    async fn usage_aggregates(&self) -> Result<Vec<StoredUsageAggregate>, StorageError> {
        let operation = self.observability_operation("usage aggregates");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#238) so this
        // read resolves `usage_aggregate_rollups`/`tenant_contexts` in the same
        // schema the settlement transaction writes to, not the connection default.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT a.id, t.organization_id, t.project_id, t.api_key_id, \
                        a.logical_model, a.provider, \
                        a.prompt_tokens, a.completion_tokens, a.total_tokens \
                 FROM usage_aggregate_rollups a \
                 JOIN tenant_contexts t ON t.id = a.tenant_context_id \
                 ORDER BY a.id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.into_iter().map(usage_aggregate_from_row).collect())
    }

    /// Sum of `total_tokens` across every usage-aggregate rollup attributed to
    /// a single `api_key_id`, pushed down to SQL (`WHERE t.api_key_id = $1`)
    /// so the per-request token-budget gate no longer streams the whole
    /// `usage_aggregate_rollups` table into process memory just to filter it
    /// (issue #330; the read counterpart of the #231 full-scan class). The
    /// `SUM(...)::bigint` cast keeps the result an `i64` rather than the
    /// `numeric` Postgres returns for a `SUM` over `bigint`, and `COALESCE`
    /// makes the "no rows for this key" case a definite `0` instead of `NULL`.
    async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> Result<u64, StorageError> {
        let operation = self.observability_operation("sum api key committed tokens");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_one(
                "SELECT COALESCE(SUM(a.total_tokens), 0)::bigint \
                 FROM usage_aggregate_rollups a \
                 JOIN tenant_contexts t ON t.id = a.tenant_context_id \
                 WHERE t.api_key_id = $1",
                &[&api_key_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }
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

async fn validate_postgres_schema<C>(client: &C) -> Result<(), StorageError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    const TABLES: &[&str] = &[
        "control_plane_resources",
        "agent_runs",
        "agent_run_events",
        "managed_worker_templates",
        "agent_worker_instances",
        "managed_worker_sessions",
        "managed_worker_lifecycle_events",
        "managed_worker_isolation_selections",
        "managed_worker_isolation_policies",
        "managed_worker_isolation_evidence",
        "self_hosted_worker_registrations",
        "self_hosted_worker_heartbeats",
        "self_hosted_worker_telemetry_events",
        "self_hosted_worker_artifacts",
        "self_hosted_worker_checkpoints",
        "self_hosted_run_dispatches",
        "self_hosted_run_dispatch_capabilities",
        "request_logs",
        "guardrail_policy_revisions",
        "guardrail_policy_bindings",
        "guardrail_evaluations",
        "guardrail_check_evaluations",
        "mcp_oauth_authorization_states",
        "mcp_oauth_flows",
        "mcp_oauth_credentials",
        "audit_events",
        "billing_metering_events",
        "usage_aggregates",
        "tenant_contexts",
        "metering_events",
        "metering_event_routes",
        "metering_event_usage",
        "usage_aggregate_rollups",
        "tenants",
        "projects",
        "workspaces",
        "api_keys",
        "usage_monthly_rollups",
        "billing_ledger",
        "billing_report_outbox",
        "admin_users",
        "admin_user_tenant_memberships",
        "admin_user_refresh_tokens",
        "storage_schema_migrations",
        "quota_policies",
        "plans",
        "stored_assets",
        "permissions",
        "roles",
        "tenant_role_bindings",
        "budget_alert_notifications",
        "usage_metadata_rollups",
        "wallets",
        "wallet_settlements",
        "wallet_reservations",
        "payment_attempts",
        "payment_methods",
        "agent_schedules",
        "agent_schedule_fires",
        "workflow_run_budgets",
        "retention_policies",
        "site_domains",
        "observed_agent_presence",
    ];
    for table in TABLES {
        let exists = client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[table])
            .await
            .map_err(postgres_error)?
            .get::<_, bool>(0);
        if !exists {
            return Err(StorageError::Postgres(format!(
                "required schema table {table} is missing"
            )));
        }
    }

    const JSONB_COLUMNS: &[(&str, &str)] = &[
        ("control_plane_resources", "document_json"),
        ("agent_runs", "run_json"),
        ("agent_run_events", "event_json"),
        ("agent_worker_instances", "process_json"),
        ("managed_worker_sessions", "capability_envelope_json"),
        ("managed_worker_sessions", "resource_limits_json"),
        ("managed_worker_lifecycle_events", "evidence_json"),
        ("managed_worker_isolation_evidence", "evidence_json"),
        (
            "self_hosted_worker_registrations",
            "capability_envelope_json",
        ),
        ("self_hosted_worker_heartbeats", "heartbeat_json"),
        ("self_hosted_worker_telemetry_events", "event_json"),
        ("self_hosted_worker_artifacts", "artifact_json"),
        ("self_hosted_worker_checkpoints", "checkpoint_json"),
        ("request_logs", "request_json"),
        ("guardrail_policy_revisions", "policy_json"),
        ("guardrail_policy_bindings", "archived_revisions_json"),
        ("guardrail_evaluations", "evaluation_json"),
        ("guardrail_check_evaluations", "check_json"),
        ("mcp_oauth_credentials", "scopes_json"),
        ("audit_events", "audit_json"),
        ("api_keys", "scopes_json"),
        ("agent_schedules", "target_json"),
    ];
    for (table, column) in JSONB_COLUMNS {
        let data_type = client
            .query_opt(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 \
                   AND column_name = $2",
                &[table, column],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        if data_type.as_deref() != Some("jsonb") {
            return Err(StorageError::Postgres(format!(
                "required schema column {table}.{column} must be jsonb"
            )));
        }
    }

    let guardrail_generation = client
        .query_opt(
            "SELECT data_type, is_nullable FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'guardrail_policy_bindings' \
               AND column_name = 'generation'",
            &[],
        )
        .await
        .map_err(postgres_error)?
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)));
    if guardrail_generation != Some(("bigint".into(), "NO".into())) {
        return Err(StorageError::Postgres(
            "required schema column guardrail_policy_bindings.generation must be bigint NOT NULL"
                .into(),
        ));
    }

    const PROVIDER_ATTEMPT_COLUMNS: &[(&str, &str, &str, &str)] = &[
        ("metering_events", "billing_event_id", "text", "NO"),
        ("metering_events", "provider_attempt_id", "text", "NO"),
        ("metering_events", "provider_attempt_index", "integer", "NO"),
        ("metering_events", "event_json", "jsonb", "NO"),
        ("metering_event_routes", "billing_event_id", "text", "NO"),
        ("metering_event_usage", "billing_event_id", "text", "NO"),
        ("billing_ledger", "provider_attempt_id", "text", "NO"),
        ("billing_ledger", "provider_attempt_index", "integer", "NO"),
    ];
    for (table, column, expected_type, expected_nullable) in PROVIDER_ATTEMPT_COLUMNS {
        let definition = client
            .query_opt(
                "SELECT data_type, is_nullable FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 AND column_name = $2",
                &[table, column],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)));
        if definition.as_ref().map(|(value, _)| value.as_str()) != Some(*expected_type)
            || definition.as_ref().map(|(_, value)| value.as_str()) != Some(*expected_nullable)
        {
            return Err(StorageError::Postgres(format!(
                "required provider-attempt column {table}.{column} must be {expected_type} NOT NULL"
            )));
        }
    }

    // #256: other migration-added columns that a hand-built or partially-migrated
    // schema can silently lack (validate_schema must fail-fast on all of them, not
    // just the provider-attempt set above). organization_id (#226, migration 33) is
    // the exact column whose absence aborted the live migration in #254.
    const REQUIRED_MIGRATION_COLUMNS: &[(&str, &str, &str, &str)] = &[
        ("usage_metadata_rollups", "organization_id", "text", "NO"),
        (
            "self_hosted_worker_registrations",
            "token_secret",
            "text",
            "NO",
        ),
        // #366 (migration 51): the trust-screening visibility state must exist
        // and be NOT NULL, so a partially-migrated schema can never leave the
        // read path unable to tell a withheld row from a clean one.
        ("stored_assets", "visibility", "text", "NO"),
    ];
    for (table, column, expected_type, expected_nullable) in REQUIRED_MIGRATION_COLUMNS {
        let definition = client
            .query_opt(
                "SELECT data_type, is_nullable FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 AND column_name = $2",
                &[table, column],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)));
        if definition.as_ref().map(|(value, _)| value.as_str()) != Some(*expected_type)
            || definition.as_ref().map(|(_, value)| value.as_str()) != Some(*expected_nullable)
        {
            return Err(StorageError::Postgres(format!(
                "required schema column {table}.{column} must be {expected_type} NOT NULL"
            )));
        }
    }

    // #304 (migration 45): nullable action-identity projection columns on the
    // timeline/audit evidence tables. Nullable by design (pre-migration rows
    // and non-governed paths carry NULL), so only presence + type are pinned.
    const ACTION_IDENTITY_COLUMNS: &[(&str, &str)] = &[
        ("agent_run_events", "action_fingerprint"),
        ("agent_run_events", "decision"),
        ("agent_run_events", "decision_reason"),
        ("agent_run_events", "output_disposition"),
        ("audit_events", "action_fingerprint"),
        ("audit_events", "decision"),
        ("audit_events", "decision_reason"),
        ("audit_events", "output_disposition"),
    ];
    // #305 (migration 46): nullable correlation-key columns on the self-hosted
    // dispatch queue table, validated with the same presence + type pin as the
    // #304 action-identity set (nullable by design: pre-migration rows and
    // dispatches created outside any inbound request carry NULL).
    const DISPATCH_CORRELATION_COLUMNS: &[(&str, &str)] = &[
        ("self_hosted_run_dispatches", "request_id"),
        ("self_hosted_run_dispatches", "trace_id"),
        ("self_hosted_run_dispatches", "agent_run_id"),
        // #307 (migration 48): the parent governed action's fingerprint on the
        // dispatch queue table (nullable by design: dispatches created outside
        // any governed-action context carry NULL).
        ("self_hosted_run_dispatches", "parent_action_fingerprint"),
    ];
    // #306 (migration 47): the shared action identity + stored canonical
    // decision on guardrail evidence rows, same presence + type pin (nullable
    // by design: pre-migration rows and evaluations without a resolvable
    // canonical capability target carry NULL).
    const GUARDRAIL_ACTION_IDENTITY_COLUMNS: &[(&str, &str)] = &[
        ("guardrail_evaluations", "action_fingerprint"),
        ("guardrail_evaluations", "decision"),
        ("guardrail_evaluations", "decision_reason"),
    ];
    for (table, column) in ACTION_IDENTITY_COLUMNS
        .iter()
        .chain(DISPATCH_CORRELATION_COLUMNS)
        .chain(GUARDRAIL_ACTION_IDENTITY_COLUMNS)
    {
        let data_type = client
            .query_opt(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 AND column_name = $2",
                &[table, column],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        if data_type.as_deref() != Some("text") {
            return Err(StorageError::Postgres(format!(
                "required action-identity/correlation column {table}.{column} must be text (#304/#305/#306/#307)"
            )));
        }
    }

    for (table, expected_column) in [
        ("metering_events", "billing_event_id"),
        ("metering_event_routes", "billing_event_id"),
        ("metering_event_usage", "billing_event_id"),
    ] {
        let columns = client
            .query(
                "SELECT attribute.attname \
                 FROM pg_constraint AS con \
                 JOIN pg_class AS relation ON relation.oid = con.conrelid \
                 JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                 JOIN unnest(con.conkey) WITH ORDINALITY AS key(attnum, position) ON TRUE \
                 JOIN pg_attribute AS attribute \
                   ON attribute.attrelid = relation.oid AND attribute.attnum = key.attnum \
                 WHERE namespace.nspname = current_schema() AND relation.relname = $1 \
                   AND con.contype = 'p' \
                 ORDER BY key.position",
                &[&table],
            )
            .await
            .map_err(postgres_error)?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        if columns != [expected_column] {
            return Err(StorageError::Postgres(format!(
                "required provider-attempt primary key on {table} must be exactly ({expected_column}), got {columns:?}"
            )));
        }
    }

    for (table, constraint_name) in [
        (
            "metering_event_routes",
            "metering_event_routes_billing_event_id_fkey",
        ),
        (
            "metering_event_usage",
            "metering_event_usage_billing_event_id_fkey",
        ),
    ] {
        let foreign_key = client
            .query_opt(
                PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY,
                &[&table, &constraint_name],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| {
                (
                    row.get::<_, String>(0),
                    row.get::<_, bool>(1),
                    row.get::<_, String>(2),
                    row.get::<_, String>(3),
                    row.get::<_, String>(4),
                )
            });
        if foreign_key
            != Some((
                "billing_event_id".into(),
                true,
                "metering_events".into(),
                "billing_event_id".into(),
                "c".into(),
            ))
        {
            return Err(StorageError::Postgres(format!(
                "required provider-attempt foreign key {constraint_name} on {table} must map billing_event_id to metering_events.billing_event_id ON DELETE CASCADE, got {foreign_key:?}"
            )));
        }
    }

    for table in [
        "guardrail_evaluations",
        "guardrail_check_evaluations",
        "mcp_oauth_authorization_states",
        "mcp_oauth_flows",
        "mcp_oauth_credentials",
    ] {
        let row_level_security = client
            .query_opt(
                "SELECT class.relrowsecurity FROM pg_class AS class \
                 JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace \
                 WHERE namespace.nspname = current_schema() AND class.relname = $1",
                &[&table],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, bool>(0));
        if row_level_security != Some(true) {
            return Err(StorageError::Postgres(format!(
                "required schema table {table} must enable row level security"
            )));
        }
    }

    for (table, policy) in [
        (
            "guardrail_evaluations",
            "guardrail_evaluations_tenant_scope",
        ),
        (
            "guardrail_check_evaluations",
            "guardrail_checks_tenant_scope",
        ),
        (
            "mcp_oauth_authorization_states",
            "mcp_oauth_authorization_states_tenant_scope",
        ),
        ("mcp_oauth_flows", "mcp_oauth_flows_tenant_scope"),
        (
            "mcp_oauth_credentials",
            "mcp_oauth_credentials_tenant_scope",
        ),
    ] {
        let policy_is_complete = client
            .query_opt(
                "SELECT qual IS NOT NULL AND btrim(qual) <> '' \
                        AND with_check IS NOT NULL AND btrim(with_check) <> '' \
                 FROM pg_policies \
                 WHERE schemaname = current_schema() \
                   AND tablename = $1 \
                   AND policyname = $2",
                &[&table, &policy],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, bool>(0));
        if policy_is_complete != Some(true) {
            return Err(StorageError::Postgres(format!(
                "required tenant RLS policy {policy} on {table} must define USING and WITH CHECK"
            )));
        }
    }

    const BIGINT_COLUMNS: &[(&str, &str)] = &[(
        "self_hosted_worker_registrations",
        "identity_expires_at_unix",
    )];
    for (table, column) in BIGINT_COLUMNS {
        let data_type = client
            .query_opt(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() \
                   AND table_name = $1 \
                   AND column_name = $2",
                &[table, column],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get::<_, String>(0));
        if data_type.as_deref() != Some("bigint") {
            return Err(StorageError::Postgres(format!(
                "required schema column {table}.{column} must be bigint"
            )));
        }
    }

    const INDEXES: &[&str] = &[
        "idx_control_plane_resources_document_gin",
        "idx_agent_runs_tenant_started",
        "idx_agent_run_events_run_time",
        "idx_managed_worker_templates_enabled_adapter",
        "idx_agent_worker_instances_status_seen",
        "idx_managed_worker_sessions_tenant_status",
        "idx_managed_worker_lifecycle_session_time",
        "idx_managed_worker_isolation_selection_backend",
        "idx_managed_worker_isolation_policy_egress",
        "idx_managed_worker_isolation_evidence_session_time",
        "idx_self_hosted_worker_registrations_tenant_status",
        "idx_self_hosted_worker_registrations_identity_expiry",
        "idx_self_hosted_worker_heartbeats_worker_time",
        "idx_self_hosted_worker_telemetry_worker_time",
        "idx_self_hosted_worker_artifacts_run",
        "idx_self_hosted_worker_checkpoints_run",
        "idx_self_hosted_run_dispatches_tenant_queue",
        "idx_self_hosted_run_dispatches_worker_lease",
        "idx_self_hosted_run_dispatch_capabilities_capability",
        "idx_request_logs_model_provider_started",
        "idx_guardrail_policy_revisions_created",
        "idx_guardrail_policy_bindings_active",
        "idx_guardrail_evaluations_request",
        "idx_guardrail_evaluations_trace",
        "idx_guardrail_evaluations_agent_run",
        "idx_guardrail_evaluations_tenant_time",
        "idx_guardrail_evaluations_policy_time",
        "idx_guardrail_evaluations_verdict_action",
        "idx_guardrail_checks_evaluation",
        "idx_guardrail_checks_detector_verdict",
        "idx_guardrail_checks_error",
        "idx_mcp_oauth_flows_expiry",
        "idx_mcp_oauth_flows_pending_subject",
        "idx_mcp_oauth_credentials_subject",
        "idx_mcp_oauth_credentials_expiry",
        "idx_mcp_oauth_credentials_refresh_lease",
        "idx_audit_events_actor_time",
        "idx_audit_events_agent_run",
        "idx_billing_metering_model_provider_time",
        "idx_usage_aggregates_tenant_model_provider",
        "idx_tenant_contexts_api_key",
        "idx_metering_events_tenant_time",
        "idx_metering_events_request",
        "idx_metering_event_routes_model_provider",
        "idx_usage_rollups_tenant_model_provider",
        "idx_api_keys_workspace",
        "idx_api_keys_tenant_project",
        "idx_api_keys_prefix",
        "idx_usage_monthly_rollups_scope",
        "idx_usage_monthly_rollups_period",
        "idx_billing_ledger_tenant_time",
        "idx_billing_ledger_model_provider",
        "idx_billing_ledger_request_attempt",
        "idx_billing_report_outbox_due",
        "idx_billing_report_outbox_dead_lettered",
        "idx_admin_user_tenant_memberships_user",
        "idx_admin_user_tenant_memberships_tenant",
        "idx_admin_user_refresh_tokens_user",
        "idx_admin_user_refresh_tokens_hash",
        "idx_site_domains_tenant",
    ];
    for index in INDEXES {
        let count = client
            .query_one(
                "SELECT count(*) FROM pg_indexes \
                 WHERE schemaname = current_schema() AND indexname = $1",
                &[index],
            )
            .await
            .map_err(postgres_error)?
            .get::<_, i64>(0);
        if count != 1 {
            return Err(StorageError::Postgres(format!(
                "required schema index {index} is missing"
            )));
        }
    }

    let pending_flow_index = client
        .query_opt(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = current_schema() \
               AND tablename = 'mcp_oauth_flows' \
               AND indexname = 'idx_mcp_oauth_flows_pending_subject'",
            &[],
        )
        .await
        .map_err(postgres_error)?
        .map(|row| row.get::<_, String>(0));
    if pending_flow_index.as_deref().is_none_or(|definition| {
        !definition.contains("(tenant_id, workspace_id, user_id, server_name)")
            || !definition.contains("WHERE (consumed_at_unix IS NULL)")
    }) {
        return Err(StorageError::Postgres(
            "required partial index idx_mcp_oauth_flows_pending_subject must cover \
             (tenant_id, workspace_id, user_id, server_name) WHERE consumed_at_unix IS NULL"
                .into(),
        ));
    }

    let row = client
        .query_opt(
            "SELECT name FROM storage_schema_migrations WHERE version = $1",
            &[&(POSTGRES_SCHEMA_VERSION as i64)],
        )
        .await
        .map_err(postgres_error)?;
    let name = row.map(|row| row.get::<_, String>(0));
    if name.as_deref() != Some(POSTGRES_SCHEMA_NAME) {
        return Err(StorageError::Postgres(format!(
            "required schema migration {POSTGRES_SCHEMA_VERSION}:{POSTGRES_SCHEMA_NAME} is missing"
        )));
    }
    Ok(())
}

fn fnv1a64_hex(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn saturating_i32(value: u64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn same_billing_event_settlement(left: &BillingEvent, right: &BillingEvent) -> bool {
    left == right
}

fn nonnegative_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn nonnegative_u32(value: i64) -> u32 {
    u32::try_from(value).unwrap_or_default()
}

fn serialize_storage_document<T: Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|error| StorageError::Serialization(error.to_string()))
}

fn deserialize_storage_document<T: for<'de> Deserialize<'de>>(
    value: &str,
) -> Result<T, StorageError> {
    serde_json::from_str(value).map_err(|error| StorageError::Serialization(error.to_string()))
}

fn deserialize_billing_event_document(value: &str) -> Result<BillingEvent, StorageError> {
    deserialize_storage_document(value)
}

fn tenant_account_from_row(row: &PostgresRow) -> StoredTenantAccount {
    StoredTenantAccount {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        status: row.get::<_, String>(3),
        plan_id: row.get::<_, String>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

fn admin_user_from_row(row: &PostgresRow) -> StoredAdminUser {
    StoredAdminUser {
        id: row.get::<_, String>(0),
        email: row.get::<_, String>(1),
        password_hash: row.get::<_, String>(2),
        display_name: row.get::<_, String>(3),
        superadmin: row.get::<_, bool>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
        last_login_at_unix: row.get::<_, Option<i64>>(7),
        disabled_at_unix: row.get::<_, Option<i64>>(8),
    }
}

fn admin_user_membership_from_row(row: &PostgresRow) -> StoredAdminUserMembership {
    StoredAdminUserMembership {
        id: row.get::<_, String>(0),
        user_id: row.get::<_, String>(1),
        tenant_id: row.get::<_, String>(2),
        role: row.get::<_, String>(3),
        created_at_unix: row.get::<_, i64>(4),
    }
}

fn admin_user_refresh_token_from_row(row: &PostgresRow) -> StoredAdminUserRefreshToken {
    StoredAdminUserRefreshToken {
        id: row.get::<_, String>(0),
        user_id: row.get::<_, String>(1),
        token_hash: row.get::<_, String>(2),
        tenant_id: row.get::<_, Option<String>>(3),
        role: row.get::<_, Option<String>>(4),
        created_at_unix: row.get::<_, i64>(5),
        expires_at_unix: row.get::<_, i64>(6),
        revoked_at_unix: row.get::<_, Option<i64>>(7),
    }
}

fn sso_provider_config_from_row(
    row: &PostgresRow,
) -> Result<StoredSsoProviderConfig, StorageError> {
    let group_role_mapping_json = row.get::<_, String>(3);
    let group_role_mapping = serde_json::from_str(&group_role_mapping_json)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    Ok(StoredSsoProviderConfig {
        tenant_id: row.get::<_, String>(0),
        provider_kind: row.get::<_, String>(1),
        default_role: row.get::<_, String>(2),
        group_role_mapping,
        oidc_issuer: row.get::<_, Option<String>>(4),
        oidc_client_id: row.get::<_, Option<String>>(5),
        oidc_client_secret_ref: row.get::<_, Option<String>>(6),
        oidc_redirect_uri: row.get::<_, Option<String>>(7),
        oidc_group_claim: row.get::<_, Option<String>>(8),
        saml_idp_entity_id: row.get::<_, Option<String>>(9),
        saml_idp_sso_url: row.get::<_, Option<String>>(10),
        saml_idp_certificate: row.get::<_, Option<String>>(11),
        saml_sp_entity_id: row.get::<_, Option<String>>(12),
        saml_acs_url: row.get::<_, Option<String>>(13),
        saml_email_attribute: row.get::<_, Option<String>>(14),
        saml_name_attribute: row.get::<_, Option<String>>(15),
        saml_groups_attribute: row.get::<_, Option<String>>(16),
        created_at_unix: row.get::<_, i64>(17),
        updated_at_unix: row.get::<_, i64>(18),
    })
}

fn sso_pending_flow_from_row(row: &PostgresRow) -> StoredSsoPendingFlow {
    StoredSsoPendingFlow {
        state: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        provider_kind: row.get::<_, String>(2),
        code_verifier: row.get::<_, Option<String>>(3),
        request_id: row.get::<_, Option<String>>(4),
        created_at_unix: row.get::<_, i64>(5),
        expires_at_unix: row.get::<_, i64>(6),
    }
}

fn api_key_from_row(row: &PostgresRow) -> Result<StoredApiKey, StorageError> {
    let id = row.get::<_, String>(0);
    let workspace_id = row.get::<_, String>(1);
    let tenant_id = row.get::<_, String>(2);
    let project_id = row.get::<_, String>(3);
    let scopes = deserialize_storage_document(&row.get::<_, String>(9))?;
    let allowed_models = deserialize_storage_document(&row.get::<_, String>(15))?;
    let allowed_providers = deserialize_storage_document(&row.get::<_, String>(16))?;
    Ok(StoredApiKey {
        id: id.clone(),
        workspace_id: workspace_id.clone(),
        tenant_id: tenant_id.clone(),
        project_id: project_id.clone(),
        name: row.get::<_, String>(4),
        key_prefix: row.get::<_, String>(5),
        key_hash: row.get::<_, String>(6),
        last4: row.get::<_, String>(7),
        enabled: row.get::<_, bool>(8),
        scopes,
        allowed_models,
        allowed_providers,
        tenant: api_key_tenant_context(&id, &tenant_id, &project_id, &workspace_id),
        monthly_token_budget: row.get::<_, Option<i64>>(17).map(nonnegative_u64),
        request_limit_per_minute: row.get::<_, Option<i64>>(18).map(nonnegative_u64),
        created_at_unix: nonnegative_u64(row.get::<_, i64>(10)),
        updated_at_unix: nonnegative_u64(row.get::<_, i64>(11)),
        rotated_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        expires_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        revoked_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
    })
}

fn project_from_row(row: &PostgresRow) -> StoredProject {
    StoredProject {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        name: row.get::<_, String>(2),
        slug: row.get::<_, String>(3),
        status: row.get::<_, String>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

fn workspace_from_row(row: &PostgresRow) -> StoredWorkspace {
    StoredWorkspace {
        id: row.get::<_, String>(0),
        project_id: row.get::<_, String>(1),
        tenant_id: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        slug: row.get::<_, String>(4),
        environment: row.get::<_, String>(5),
        status: row.get::<_, String>(6),
        created_at_unix: row.get::<_, i64>(7),
        updated_at_unix: row.get::<_, i64>(8),
    }
}

fn quota_policy_from_row(row: &PostgresRow) -> Result<StoredQuotaPolicy, StorageError> {
    let scope_type_raw = row.get::<_, String>(1);
    let scope_type = QuotaScopeKind::from_str_opt(&scope_type_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown quota_policies.scope_type {scope_type_raw}"
        ))
    })?;
    let model_allowlist = deserialize_storage_document(&row.get::<_, String>(3))?;
    let alert_threshold_pcts = deserialize_storage_document(&row.get::<_, String>(10))?;
    Ok(StoredQuotaPolicy {
        id: row.get::<_, String>(0),
        scope_type,
        scope_id: row.get::<_, String>(2),
        model_allowlist,
        rpm_limit: row.get::<_, Option<i64>>(4).map(nonnegative_u64),
        tpm_limit: row.get::<_, Option<i64>>(5).map(nonnegative_u64),
        monthly_budget_usd: row.get::<_, Option<f64>>(6),
        enabled: row.get::<_, bool>(7),
        created_at_unix: row.get::<_, i64>(8),
        updated_at_unix: row.get::<_, i64>(9),
        alert_threshold_pcts,
        asset_storage_quota_bytes: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        monthly_egress_bytes_budget: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        download_rpm_limit: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
    })
}

fn plan_from_row(row: &PostgresRow) -> Result<StoredPlan, StorageError> {
    let default_model_allowlist = deserialize_storage_document(&row.get::<_, String>(6))?;
    Ok(StoredPlan {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        mcp_enabled: row.get::<_, bool>(3),
        self_hosted_workers_enabled: row.get::<_, bool>(4),
        admin_console_seats: row.get::<_, Option<i64>>(5).map(nonnegative_u32),
        default_model_allowlist,
        default_rpm_limit: row.get::<_, Option<i64>>(7).map(nonnegative_u64),
        default_tpm_limit: row.get::<_, Option<i64>>(8).map(nonnegative_u64),
        default_monthly_budget_usd: row.get::<_, Option<f64>>(9),
        created_at_unix: row.get::<_, i64>(10),
        updated_at_unix: row.get::<_, i64>(11),
        asset_hosting_enabled: row.get::<_, bool>(12),
        default_asset_storage_quota_bytes: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        extension_tools_enabled: row.get::<_, bool>(14),
        default_monthly_egress_bytes_budget: row.get::<_, Option<i64>>(15).map(nonnegative_u64),
        default_download_rpm_limit: row.get::<_, Option<i64>>(16).map(nonnegative_u64),
    })
}

fn asset_from_row(row: &PostgresRow) -> StoredAsset {
    StoredAsset {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        project_id: row.get::<_, Option<String>>(2),
        asset_type: row.get::<_, String>(3),
        name: row.get::<_, String>(4),
        version: row.get::<_, String>(5),
        content_type: row.get::<_, String>(6),
        content_hash: row.get::<_, String>(7),
        size_bytes: nonnegative_u64(row.get::<_, i64>(8)),
        content: row.get::<_, Vec<u8>>(9),
        created_at_unix: row.get::<_, i64>(10),
        updated_at_unix: row.get::<_, i64>(11),
        storage_uri: row.get::<_, Option<String>>(12),
        variant: row.get::<_, String>(13),
        yanked: row.get::<_, bool>(14),
        visibility: AssetVisibility::from_stored(&row.get::<_, String>(15)),
    }
}

fn asset_channel_from_row(row: &PostgresRow) -> StoredAssetChannel {
    StoredAssetChannel {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        asset_type: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        channel: row.get::<_, String>(4),
        version: row.get::<_, String>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

fn retention_policy_from_row(row: &PostgresRow) -> StoredRetentionPolicy {
    StoredRetentionPolicy {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        resource_type: row.get::<_, String>(2),
        scope: row.get::<_, String>(3),
        // #263: keep_last_n is stored as a nullable BIGINT; a negative value
        // would be nonsensical, so clamp to a non-negative count.
        keep_last_n: row
            .get::<_, Option<i64>>(4)
            .map(|value| value.max(0) as u64),
        max_age_secs: row.get::<_, Option<i64>>(5),
        min_age_secs: row.get::<_, i64>(6),
        created_at_unix: row.get::<_, i64>(7),
        updated_at_unix: row.get::<_, i64>(8),
    }
}

fn ledger_entry_from_row(
    row: &PostgresRow,
) -> Result<ferrogate_billing::LedgerEntry, StorageError> {
    deserialize_storage_document(&row.get::<_, String>(0))
}

fn billing_ledger_supabase_only_error() -> StorageError {
    StorageError::Runtime(
        "billing ledger entries are Supabase/Postgres-only; start `ferrogate billing serve` with a Supabase DSN".into(),
    )
}

/// A pending gateway→billing usage report awaiting durable delivery (issue #137).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredBillingReportOutboxEntry {
    /// Ledger entry id (idempotency key) of the usage report.
    pub id: String,
    pub event: ferrogate_billing::BillingEvent,
    pub attempts: i64,
    pub next_attempt_unix: i64,
    /// When this entry was given up on and dead-lettered (issue #143).
    /// `None` while the entry is still eligible for delivery attempts.
    pub dead_lettered_at_unix: Option<i64>,
}

/// Outcome of the conditional (CAS) dead-letter replay mutation
/// [`RuntimeStorageRepositories::replay_dead_lettered_billing_report`]
/// (issue #388). The transition only fires for a row that is *actually*
/// dead-lettered, so an operator (or the #364 CLI) driving a replay always
/// learns which of the three terminal states it hit instead of a bare
/// success/failure. The re-enqueued entry is returned on success so the
/// caller can surface its idempotency key (the ledger-entry `id`, on which
/// the billing service dedups delivery, so a replay never double-bills) and
/// its reset attempt schedule as audit evidence.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplayDeadLetterOutcome {
    /// The row was dead-lettered and has been cleared + re-scheduled for
    /// immediate redelivery. Carries the updated entry.
    Replayed(StoredBillingReportOutboxEntry),
    /// A row with this id exists but is NOT dead-lettered (still pending
    /// delivery, or already replayed) -- fail closed, nothing changed. The
    /// current entry is returned so the caller can report a precise conflict.
    NotDeadLettered(StoredBillingReportOutboxEntry),
    /// No outbox row with this id exists.
    NotFound,
}

/// Outcome of [`RuntimeStorageRepositories::append_billing_event_with_outbox_enqueue`]
/// (issue #150).
#[derive(Debug)]
pub struct BillingEventAppendOutcome {
    /// Same semantics as the plain `append_billing_event` bool: `false` when
    /// the event was already recorded (idempotent no-op on `request_id`).
    pub recorded: bool,
    /// Set only on backends where the metering write and outbox enqueue are
    /// NOT committed atomically (Memory) and the enqueue step
    /// specifically failed after a successful metering write — non-fatal,
    /// mirroring how a standalone `enqueue_billing_report` failure was always
    /// treated as a warning rather than an aborting error. Always `None` on
    /// Postgres, where both writes commit in one transaction: a failure there
    /// fails the whole call instead of surfacing here.
    pub enqueue_error: Option<StorageError>,
}

fn billing_report_outbox_from_row(
    row: &PostgresRow,
) -> Result<StoredBillingReportOutboxEntry, StorageError> {
    Ok(StoredBillingReportOutboxEntry {
        id: row.get::<_, String>(0),
        event: deserialize_storage_document(&row.get::<_, String>(1))?,
        // `attempts` is SQL INTEGER (i32); widen to i64 for the domain type.
        attempts: i64::from(row.get::<_, i32>(2)),
        next_attempt_unix: row.get::<_, i64>(3),
        dead_lettered_at_unix: row.get::<_, Option<i64>>(4),
    })
}

/// A durable [`ferrogate_billing::LedgerSink`] backed by Supabase/Postgres.
///
/// This is the storage-side half of the billing service's persistence seam:
/// `ferrogate-billing` defines the `LedgerSink` trait and stays storage-free,
/// while this crate (which already depends on it) supplies the concrete
/// Supabase-backed sink. The `ferrogate billing serve` subcommand injects one
/// of these when started with a Supabase DSN.
pub struct StorageLedgerSink {
    repositories: Arc<RuntimeStorageRepositories>,
}

impl StorageLedgerSink {
    pub fn new(repositories: Arc<RuntimeStorageRepositories>) -> Self {
        Self { repositories }
    }
}

impl std::fmt::Debug for StorageLedgerSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageLedgerSink")
            .finish_non_exhaustive()
    }
}

fn ledger_storage_error(error: StorageError) -> ferrogate_billing::BillingError {
    match error {
        StorageError::Conflict(message) => ferrogate_billing::BillingError::new(
            "billing_idempotency_conflict",
            format!("storage conflict: {message}"),
        ),
        other => {
            ferrogate_billing::BillingError::new("billing_ledger_storage_error", other.to_string())
        }
    }
}

/// Bridge async storage calls out of the synchronous [`ferrogate_billing::
/// LedgerSink`] trait seam. `LedgerSink` is a `Send + Sync` dyn trait defined in
/// `ferrogate-billing` (which cannot depend on this crate), consumed by the
/// synchronous `ferrogate billing serve` HTTP service (`ferrogate_billing::serve`
/// is a sync fn with no tokio runtime). Rather than making the whole trait +
/// service async, the three impl methods below bridge internally. Mirrors
/// `ferrogate-cli`'s `gateway::block_on_sync_bridge` and `ferrogate-auth`'s
/// copy: reuse a surrounding multi-thread runtime via `block_in_place`, else
/// spin a scoped `current_thread` runtime.
/// Process-wide runtime that drives every synchronous storage bridge call.
///
/// It MUST be long-lived: `tokio-postgres` spawns each pooled connection's
/// driver task onto whatever runtime was current when the connection was
/// created. Building a throwaway current-thread runtime per bridge call (the
/// previous design) abandoned those driver tasks the instant the per-call
/// runtime was dropped, leaving dead connections in the shared `deadpool` pool.
/// A later acquire on a fresh runtime would then pick a dead connection whose
/// recycle probe never resolves (its driver is gone), stalling until the
/// pool-acquire deadline (`OperationDeadlineExceeded`). That is exactly what
/// broke the multi-call export path -- `export_migration_snapshot` bridges ~30
/// reads across runtime boundaries -- against a real Postgres/Supabase (#248).
/// A single shared multi-thread runtime keeps every connection driver alive for
/// the whole process, so pooled connections stay usable across bridge calls.
fn sync_bridge_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("storage sync-bridge runtime should build")
    })
}

fn block_on_sync_bridge<T>(future: impl std::future::Future<Output = T> + Send) -> T
where
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
    }
    // No ambient multi-thread runtime: drive the future on the process-wide
    // shared runtime. Run it from a dedicated scoped thread so that (a) an
    // ambient current-thread runtime does not panic with "cannot start a runtime
    // from within a runtime", and (b) pooled connection drivers persist on the
    // shared runtime's worker threads instead of being abandoned when a per-call
    // runtime is dropped (#248).
    std::thread::scope(|scope| {
        scope
            .spawn(|| sync_bridge_runtime().block_on(future))
            .join()
            .expect("sync-bridge runtime thread should not panic")
    })
}

impl ferrogate_billing::LedgerSink for StorageLedgerSink {
    fn record(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, ferrogate_billing::BillingError> {
        block_on_sync_bridge(self.repositories.append_billing_ledger_entry(entry))
            .map_err(ledger_storage_error)
    }

    fn list(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, ferrogate_billing::BillingError> {
        block_on_sync_bridge(
            self.repositories
                .list_billing_ledger_entries(filter, offset, limit),
        )
        .map_err(ledger_storage_error)
    }

    fn get(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, ferrogate_billing::BillingError> {
        block_on_sync_bridge(self.repositories.billing_ledger_entry(id))
            .map_err(ledger_storage_error)
    }
}

fn resolve_scope_from_workspace(workspace: &StoredWorkspace) -> WorkspaceScope {
    WorkspaceScope::new(
        workspace.tenant_id.clone(),
        workspace.project_id.clone(),
        workspace.id.clone(),
    )
}

fn api_key_tenant_context(
    id: &str,
    tenant_id: &str,
    project_id: &str,
    workspace_id: &str,
) -> TenantContext {
    TenantContext {
        organization_id: Some(tenant_id.to_string()),
        team_id: None,
        project_id: Some(project_id.to_string()),
        workspace_id: Some(workspace_id.to_string()),
        user_id: None,
        api_key_id: Some(id.to_string()),
    }
}

fn tenant_storage_key(tenant: &TenantContext) -> String {
    tenant_parts_storage_key(
        tenant.organization_id.as_deref(),
        tenant.team_id.as_deref(),
        tenant.project_id.as_deref(),
        tenant.workspace_id.as_deref(),
        tenant.user_id.as_deref(),
        tenant.api_key_id.as_deref(),
    )
}

fn tenant_parts_storage_key(
    organization_id: Option<&str>,
    team_id: Option<&str>,
    project_id: Option<&str>,
    workspace_id: Option<&str>,
    user_id: Option<&str>,
    api_key_id: Option<&str>,
) -> String {
    [
        ("org", organization_id),
        ("team", team_id),
        ("project", project_id),
        ("workspace", workspace_id),
        ("user", user_id),
        ("api_key", api_key_id),
    ]
    .into_iter()
    .map(|(name, value)| format!("{name}:{}", value.unwrap_or("")))
    .collect::<Vec<_>>()
    .join("|")
}

fn usage_aggregate_id(tenant: &TenantContext, logical_model: &str, provider: &str) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        tenant.organization_id.as_deref().unwrap_or("_"),
        tenant.project_id.as_deref().unwrap_or("_"),
        tenant.api_key_id.as_deref().unwrap_or("_"),
        logical_model,
        provider
    )
}

/// Async-local twin of the sync tenant-context upsert used by
/// `upsert_usage_aggregate`'s (CLI-unreachable) sync path, used only by
/// `append_billing_event_impl`'s async transaction. Kept separate rather than
/// converting the shared sync helper, so the untouched sync callers of
/// `upsert_tenant_context_parts` are never put at risk by this migration.
async fn upsert_tenant_context_async(
    transaction: &deadpool_postgres::Transaction<'_>,
    id: &str,
    tenant: &TenantContext,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO tenant_contexts \
             (id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
            &[
                &id,
                &tenant.organization_id.as_deref(),
                &tenant.team_id.as_deref(),
                &tenant.project_id.as_deref(),
                &tenant.workspace_id.as_deref(),
                &tenant.user_id.as_deref(),
                &tenant.api_key_id.as_deref(),
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

struct TenantContextParts<'a> {
    organization_id: Option<&'a str>,
    team_id: Option<&'a str>,
    project_id: Option<&'a str>,
    workspace_id: Option<&'a str>,
    user_id: Option<&'a str>,
    api_key_id: Option<&'a str>,
}

async fn upsert_tenant_context_parts(
    transaction: &deadpool_postgres::Transaction<'_>,
    id: &str,
    parts: &TenantContextParts<'_>,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO tenant_contexts \
         (id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (id) DO NOTHING",
            &[
                &id,
                &parts.organization_id,
                &parts.team_id,
                &parts.project_id,
                &parts.workspace_id,
                &parts.user_id,
                &parts.api_key_id,
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

async fn upsert_usage_rollup_delta(
    transaction: &deadpool_postgres::Transaction<'_>,
    rollup: &UsageRollupUpsert<'_>,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO usage_aggregate_rollups \
         (id, tenant_context_id, logical_model, provider, prompt_tokens, completion_tokens, \
          total_tokens, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (id) DO UPDATE SET \
         prompt_tokens = usage_aggregate_rollups.prompt_tokens + EXCLUDED.prompt_tokens, \
         completion_tokens = usage_aggregate_rollups.completion_tokens + EXCLUDED.completion_tokens, \
         total_tokens = usage_aggregate_rollups.total_tokens + EXCLUDED.total_tokens, \
         updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
            &[
                &rollup.id,
                &rollup.tenant_context_id,
                &rollup.logical_model,
                &rollup.provider,
                &rollup.prompt_tokens,
                &rollup.completion_tokens,
                &rollup.total_tokens,
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

async fn replace_usage_rollup(
    transaction: &deadpool_postgres::Transaction<'_>,
    rollup: &UsageRollupUpsert<'_>,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO usage_aggregate_rollups \
         (id, tenant_context_id, logical_model, provider, prompt_tokens, completion_tokens, \
          total_tokens, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (id) DO UPDATE SET \
         tenant_context_id = EXCLUDED.tenant_context_id, \
         logical_model = EXCLUDED.logical_model, \
         provider = EXCLUDED.provider, \
         prompt_tokens = EXCLUDED.prompt_tokens, \
         completion_tokens = EXCLUDED.completion_tokens, \
         total_tokens = EXCLUDED.total_tokens, \
         updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
            &[
                &rollup.id,
                &rollup.tenant_context_id,
                &rollup.logical_model,
                &rollup.provider,
                &rollup.prompt_tokens,
                &rollup.completion_tokens,
                &rollup.total_tokens,
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

struct UsageRollupUpsert<'a> {
    id: &'a str,
    tenant_context_id: &'a str,
    logical_model: &'a str,
    provider: &'a str,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
}

/// Fans a settled request out into up to four [`usage_monthly_rollups`]
/// increments -- one per non-empty scope level (tenant/project/workspace/
/// key) in `tenant`. Called from within `append_billing_event`'s
/// transaction so a request's usage/cost lands in the raw event table and
/// every applicable rollup atomically or not at all.
/// A settled request's usage/cost delta to fan out across scope levels.
/// Bundled into one struct so the transaction-scoped helpers below stay
/// under clippy's argument-count lint.
#[derive(Clone, Copy)]
struct UsageMonthlyDelta {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    cost_usd: f64,
    is_error: bool,
}

async fn increment_usage_monthly_rollups(
    transaction: &deadpool_postgres::Transaction<'_>,
    tenant: &TenantContext,
    period_month: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), StorageError> {
    let scopes: [(QuotaScopeKind, Option<&str>); 4] = [
        (QuotaScopeKind::Tenant, tenant.organization_id.as_deref()),
        (QuotaScopeKind::Project, tenant.project_id.as_deref()),
        (QuotaScopeKind::Workspace, tenant.workspace_id.as_deref()),
        (QuotaScopeKind::Key, tenant.api_key_id.as_deref()),
    ];
    for (scope_type, scope_id) in scopes {
        let Some(scope_id) = scope_id else {
            continue;
        };
        upsert_usage_monthly_rollup_delta(transaction, period_month, scope_type, scope_id, delta)
            .await?;
    }
    Ok(())
}

async fn upsert_usage_monthly_rollup_delta(
    transaction: &deadpool_postgres::Transaction<'_>,
    period_month: &str,
    scope_type: QuotaScopeKind,
    scope_id: &str,
    delta: &UsageMonthlyDelta,
) -> Result<(), StorageError> {
    let id = usage_monthly_rollup_id(period_month, scope_type, scope_id);
    let scope_type_str = scope_type.as_str();
    let prompt_tokens = saturating_i64(delta.prompt_tokens);
    let completion_tokens = saturating_i64(delta.completion_tokens);
    let total_tokens = saturating_i64(delta.total_tokens);
    let cost_usd = delta.cost_usd;
    let error_increment: i64 = i64::from(delta.is_error);
    transaction
        .execute(
            "INSERT INTO usage_monthly_rollups \
         (id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens, \
          total_tokens, cost_usd, request_count, error_count, updated_at_unix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, EXTRACT(EPOCH FROM NOW())::BIGINT) \
         ON CONFLICT (period_month, scope_type, scope_id) DO UPDATE SET \
         prompt_tokens = usage_monthly_rollups.prompt_tokens + EXCLUDED.prompt_tokens, \
         completion_tokens = \
             usage_monthly_rollups.completion_tokens + EXCLUDED.completion_tokens, \
         total_tokens = usage_monthly_rollups.total_tokens + EXCLUDED.total_tokens, \
         cost_usd = usage_monthly_rollups.cost_usd + EXCLUDED.cost_usd, \
         request_count = usage_monthly_rollups.request_count + 1, \
         error_count = usage_monthly_rollups.error_count + EXCLUDED.error_count, \
         updated_at_unix = EXTRACT(EPOCH FROM NOW())::BIGINT",
            &[
                &id,
                &period_month,
                &scope_type_str,
                &scope_id,
                &prompt_tokens,
                &completion_tokens,
                &total_tokens,
                &cost_usd,
                &error_increment,
            ],
        )
        .await
        .map_err(postgres_error)?;
    Ok(())
}

fn usage_monthly_rollup_from_row(
    row: &PostgresRow,
) -> Result<StoredUsageMonthlyRollup, StorageError> {
    let scope_type_raw: String = row.get(2);
    let scope_type = QuotaScopeKind::from_str_opt(&scope_type_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown usage_monthly_rollups.scope_type {scope_type_raw}"
        ))
    })?;
    Ok(StoredUsageMonthlyRollup {
        id: row.get(0),
        period_month: row.get(1),
        scope_type,
        scope_id: row.get(3),
        prompt_tokens: nonnegative_u64(row.get(4)),
        completion_tokens: nonnegative_u64(row.get(5)),
        total_tokens: nonnegative_u64(row.get(6)),
        cost_usd: row.get(7),
        request_count: nonnegative_u64(row.get(8)),
        error_count: nonnegative_u64(row.get(9)),
        updated_at_unix: row.get(10),
    })
}

fn usage_aggregate_from_row(row: PostgresRow) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: row.get(0),
        organization_id: row.get(1),
        project_id: row.get(2),
        api_key_id: row.get(3),
        logical_model: row.get(4),
        provider: row.get(5),
        usage: TokenUsage {
            prompt_tokens: nonnegative_u64(row.get(6)),
            completion_tokens: nonnegative_u64(row.get(7)),
            total_tokens: nonnegative_u64(row.get(8)),
        },
    }
}

fn managed_worker_template_from_row(row: PostgresRow) -> StoredManagedWorkerTemplate {
    StoredManagedWorkerTemplate {
        id: row.get(0),
        framework_adapter: row.get(1),
        isolation_backend_kind: row.get(2),
        enabled: row.get(3),
        max_tenant_sessions: row
            .get::<_, Option<i64>>(4)
            .and_then(|value| u32::try_from(value).ok()),
        max_workspace_sessions: row
            .get::<_, Option<i64>>(5)
            .and_then(|value| u32::try_from(value).ok()),
        created_at_unix: Some(nonnegative_u64(row.get(6))),
        updated_at_unix: Some(nonnegative_u64(row.get(7))),
    }
}

fn agent_worker_instance_from_row(row: PostgresRow) -> StoredAgentWorkerInstance {
    StoredAgentWorkerInstance {
        id: row.get(0),
        process_name: row.get(1),
        host_id: row.get(2),
        worker_version: row.get(3),
        status: row.get(4),
        started_at_unix: Some(nonnegative_u64(row.get(5))),
        last_seen_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        process_json: row.get(7),
    }
}

fn managed_worker_session_from_row(row: PostgresRow) -> StoredManagedWorkerSession {
    StoredManagedWorkerSession {
        id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        worker_template_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        isolation_backend_kind: row.get(7),
        microvm_id: row.get(8),
        capability_envelope_id: row.get(9),
        requested_at_unix: Some(nonnegative_u64(row.get(10))),
        started_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        completed_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        cleanup_completed_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        capability_envelope_json: row.get(14),
        resource_limits_json: row.get(15),
    }
}

fn managed_worker_lifecycle_event_from_row(row: PostgresRow) -> StoredManagedWorkerLifecycleEvent {
    StoredManagedWorkerLifecycleEvent {
        id: row.get(0),
        session_id: row.get(1),
        run_id: row.get(2),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(3).as_deref()),
        workspace_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        action: row.get(7),
        outcome: row.get(8),
        occurred_at_unix: Some(nonnegative_u64(row.get(9))),
        evidence_json: row.get(10),
    }
}

fn managed_worker_isolation_selection_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationSelection {
    StoredManagedWorkerIsolationSelection {
        session_id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        agent_worker_instance_id: row.get(4),
        backend_name: row.get(5),
        backend_version: row.get(6),
        backend_kind: row.get(7),
        host_lifecycle_owner: row.get(8),
        gateway_controls_backend: row.get(9),
        capability_envelope_id: row.get(10),
        selected_at_unix: Some(nonnegative_u64(row.get(11))),
    }
}

fn managed_worker_isolation_policy_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationPolicy {
    StoredManagedWorkerIsolationPolicy {
        session_id: row.get(0),
        cpu_count: u16::try_from(row.get::<_, i32>(1)).unwrap_or_default(),
        memory_mib: u32::try_from(row.get::<_, i32>(2)).unwrap_or_default(),
        disk_mib: u32::try_from(row.get::<_, i32>(3)).unwrap_or_default(),
        max_runtime_millis: row.get::<_, Option<i64>>(4).map(nonnegative_u64),
        direct_public_egress: row.get(5),
        gateway_control_channel: row.get(6),
        governed_egress: row.get(7),
        read_only_rootfs: row.get(8),
        writable_workspace: row.get(9),
        host_path_mounts: row.get(10),
    }
}

fn managed_worker_isolation_evidence_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationEvidence {
    StoredManagedWorkerIsolationEvidence {
        id: row.get(0),
        session_id: row.get(1),
        lifecycle_event_id: row.get(2),
        run_id: row.get(3),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(4).as_deref()),
        workspace_id: row.get(5),
        agent_worker_instance_id: row.get(6),
        isolation_instance_id: row.get(7),
        action: row.get(8),
        outcome: row.get(9),
        failure_reason: row.get(10),
        occurred_at_unix: Some(nonnegative_u64(row.get(11))),
        evidence_json: row.get(12),
    }
}

fn self_hosted_worker_registration_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerRegistration {
    StoredSelfHostedWorkerRegistration {
        id: row.get(0),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(1).as_deref()),
        workspace_id: row.get(2),
        worker_name: row.get(3),
        status: row.get(4),
        identity_fingerprint: row.get(5),
        identity_expires_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        orchestration_enabled: row.get(7),
        registered_at_unix: Some(nonnegative_u64(row.get(8))),
        last_seen_at_unix: row.get::<_, Option<i64>>(9).map(nonnegative_u64),
        trust_level: row.get(10),
        capability_envelope_json: row.get(11),
        token_secret: row.get(12),
    }
}

fn self_hosted_worker_heartbeat_from_row(row: PostgresRow) -> StoredSelfHostedWorkerHeartbeat {
    StoredSelfHostedWorkerHeartbeat {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        status: row.get(4),
        reported_at_unix: Some(nonnegative_u64(row.get(5))),
        observed_at_unix: Some(nonnegative_u64(row.get(6))),
        heartbeat_json: row.get(7),
    }
}

fn self_hosted_worker_telemetry_event_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerTelemetryEvent {
    StoredSelfHostedWorkerTelemetryEvent {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        kind: row.get(6),
        trust_level: row.get(7),
        occurred_at_unix: Some(nonnegative_u64(row.get(8))),
        ingested_at_unix: Some(nonnegative_u64(row.get(9))),
        event_json: row.get(10),
        request_id: row.get(11),
        trace_id: row.get(12),
        agent_run_id: row.get(13),
        parent_action_fingerprint: row.get(14),
    }
}

fn self_hosted_worker_artifact_from_row(row: PostgresRow) -> StoredSelfHostedWorkerArtifact {
    StoredSelfHostedWorkerArtifact {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        artifact_name: row.get(6),
        content_type: row.get(7),
        size_bytes: nonnegative_u64(row.get(8)),
        trust_level: row.get(9),
        created_at_unix: Some(nonnegative_u64(row.get(10))),
        artifact_json: row.get(11),
    }
}

fn self_hosted_worker_checkpoint_from_row(row: PostgresRow) -> StoredSelfHostedWorkerCheckpoint {
    StoredSelfHostedWorkerCheckpoint {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        checkpoint_name: row.get(6),
        size_bytes: nonnegative_u64(row.get(7)),
        trust_level: row.get(8),
        created_at_unix: Some(nonnegative_u64(row.get(9))),
        checkpoint_json: row.get(10),
    }
}

fn self_hosted_run_dispatch_from_row(
    row: PostgresRow,
    capabilities: &HashMap<String, Vec<String>>,
) -> StoredSelfHostedRunDispatch {
    let dispatch_id = row.get::<_, String>(0);
    StoredSelfHostedRunDispatch {
        required_capabilities: capabilities.get(&dispatch_id).cloned().unwrap_or_default(),
        dispatch_id,
        action: row.get(1),
        tenant_id: row.get::<_, Option<String>>(2).unwrap_or_default(),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        framework_adapter: row.get(6),
        workload_ref: row.get(7),
        queued_at_unix: Some(nonnegative_u64(row.get(8))),
        assigned_worker_id: row.get(9),
        lease_id: row.get(10),
        lease_expires_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        attempt: nonnegative_u32(row.get(12)),
        acknowledged_status: row.get(13),
        acknowledged_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
        request_id: row.get(15),
        trace_id: row.get(16),
        agent_run_id: row.get(17),
        parent_action_fingerprint: row.get(18),
    }
}

fn guardrail_policy_revision_from_row(
    row: PostgresRow,
) -> Result<StoredGuardrailPolicyRevision, StorageError> {
    let revision = row.get::<_, i64>(2);
    Ok(StoredGuardrailPolicyRevision {
        id: row.get(0),
        policy_id: row.get(1),
        revision: u32::try_from(revision).map_err(|_| {
            StorageError::Serialization("guardrail policy revision is out of range".into())
        })?,
        policy_json: row.get(3),
        created_at_unix: nonnegative_u64(row.get(4)),
        created_by: row.get(5),
    })
}

fn guardrail_policy_binding_from_row(
    row: PostgresRow,
) -> Result<StoredGuardrailPolicyBinding, StorageError> {
    let active_revision = row
        .get::<_, Option<i64>>(1)
        .map(|revision| {
            u32::try_from(revision).map_err(|_| {
                StorageError::Serialization(
                    "active guardrail policy revision is out of range".into(),
                )
            })
        })
        .transpose()?;
    let archived_revisions = deserialize_storage_document::<Vec<u32>>(&row.get::<_, String>(2))?;
    Ok(StoredGuardrailPolicyBinding {
        policy_id: row.get(0),
        active_revision,
        archived_revisions,
        updated_at_unix: nonnegative_u64(row.get(3)),
        updated_by: row.get(4),
        generation: nonnegative_u64(row.get(5)),
    })
}

fn guardrail_binding_generation_i64(generation: u64) -> Result<i64, StorageError> {
    i64::try_from(generation).map_err(|_| {
        StorageError::Serialization("guardrail policy binding generation is out of range".into())
    })
}

fn next_guardrail_binding_generation(generation: u64) -> Result<u64, StorageError> {
    generation.checked_add(1).ok_or_else(|| {
        StorageError::Serialization("guardrail policy binding generation is exhausted".into())
    })
}

fn next_guardrail_activation_binding(
    previous: Option<&StoredGuardrailPolicyBinding>,
    policy_id: &str,
    revision: u32,
    updated_by: &str,
    updated_at_unix: u64,
    rollback_only: bool,
) -> Result<StoredGuardrailPolicyBinding, StorageError> {
    if rollback_only
        && !previous.is_some_and(|binding| binding.archived_revisions.contains(&revision))
    {
        return Err(StorageError::Conflict(format!(
            "guardrail policy revision {} is not archived and cannot be rolled back",
            guardrail_policy_revision_id(policy_id, revision)
        )));
    }

    let mut archived_revisions = previous
        .map(|binding| binding.archived_revisions.clone())
        .unwrap_or_default();
    if let Some(active_revision) = previous.and_then(|binding| binding.active_revision) {
        if active_revision != revision && !archived_revisions.contains(&active_revision) {
            archived_revisions.push(active_revision);
        }
    }
    archived_revisions.retain(|archived| *archived != revision);
    archived_revisions.sort_unstable();
    archived_revisions.dedup();

    Ok(StoredGuardrailPolicyBinding {
        policy_id: policy_id.to_string(),
        active_revision: Some(revision),
        archived_revisions,
        updated_at_unix,
        updated_by: updated_by.to_string(),
        generation: next_guardrail_binding_generation(
            previous
                .map(|binding| binding.generation)
                .unwrap_or_default(),
        )?,
    })
}

fn next_guardrail_archive_binding(
    previous: Option<&StoredGuardrailPolicyBinding>,
    policy_id: &str,
    revision: u32,
    updated_by: &str,
    updated_at_unix: u64,
) -> Result<StoredGuardrailPolicyBinding, StorageError> {
    if previous.is_some_and(|binding| binding.active_revision == Some(revision)) {
        return Err(StorageError::Conflict(format!(
            "active guardrail policy revision {} cannot be archived",
            guardrail_policy_revision_id(policy_id, revision)
        )));
    }

    let mut archived_revisions = previous
        .map(|binding| binding.archived_revisions.clone())
        .unwrap_or_default();
    if !archived_revisions.contains(&revision) {
        archived_revisions.push(revision);
    }
    archived_revisions.sort_unstable();
    archived_revisions.dedup();

    Ok(StoredGuardrailPolicyBinding {
        policy_id: policy_id.to_string(),
        active_revision: previous.and_then(|binding| binding.active_revision),
        archived_revisions,
        updated_at_unix,
        updated_by: updated_by.to_string(),
        generation: next_guardrail_binding_generation(
            previous
                .map(|binding| binding.generation)
                .unwrap_or_default(),
        )?,
    })
}

fn tenant_from_storage_key(value: Option<&str>) -> TenantContext {
    let mut tenant = TenantContext::default();
    let Some(value) = value else {
        return tenant;
    };
    for part in value.split('|') {
        let Some((name, raw_value)) = part.split_once(':') else {
            continue;
        };
        let parsed = if raw_value.is_empty() {
            None
        } else {
            Some(raw_value.to_string())
        };
        match name {
            "org" => tenant.organization_id = parsed,
            "team" => tenant.team_id = parsed,
            "project" => tenant.project_id = parsed,
            "user" => tenant.user_id = parsed,
            "api_key" => tenant.api_key_id = parsed,
            _ => {}
        }
    }
    tenant
}

#[derive(Debug)]
enum RuntimeControlPlaneBackend {
    Memory(Box<Mutex<RuntimeControlPlaneState>>),
    Postgres(Arc<PostgresControlPlaneStore>),
}

fn poisoned_asset_repository_lock() -> StorageError {
    StorageError::Runtime("in-memory asset repository lock is poisoned".to_string())
}

impl RuntimeControlPlaneState {
    pub fn new() -> Self {
        let mut plans = InMemoryRepository::new();
        let free_plan = default_free_plan();
        plans.insert(free_plan.id.clone(), free_plan);
        Self {
            api_keys: InMemoryRepository::new(),
            api_key_records: InMemoryRepository::new(),
            tenants: InMemoryRepository::new(),
            policies: InMemoryRepository::new(),
            gateway_configs: InMemoryRepository::new(),
            agent_workflows: InMemoryRepository::new(),
            skill_packages: InMemoryRepository::new(),
            prompt_templates: InMemoryRepository::new(),
            plugin_registrations: InMemoryRepository::new(),
            mcp_servers: InMemoryRepository::new(),
            agent_upstreams: InMemoryRepository::new(),
            tool_approvals: InMemoryRepository::new(),
            tenant_accounts: InMemoryRepository::new(),
            projects: InMemoryRepository::new(),
            workspaces: InMemoryRepository::new(),
            admin_users: InMemoryRepository::new(),
            admin_user_memberships: InMemoryRepository::new(),
            admin_user_refresh_tokens: InMemoryRepository::new(),
            sso_provider_configs: InMemoryRepository::new(),
            sso_pending_flows: InMemoryRepository::new(),
            quota_policies: InMemoryRepository::new(),
            plans,
            assets: InMemoryRepository::new(),
            asset_channels: InMemoryRepository::new(),
            permissions: InMemoryRepository::new(),
            roles: InMemoryRepository::new(),
            tenant_role_bindings: InMemoryRepository::new(),
            usage_monthly_rollups: InMemoryRepository::new(),
            billing_report_outbox: InMemoryRepository::new(),
            budget_alert_notifications: InMemoryRepository::new(),
            usage_metadata_rollups: InMemoryRepository::new(),
            billing_event_ids: InMemoryRepository::new(),
            wallets: InMemoryRepository::new(),
            wallet_settlements: InMemoryRepository::new(),
            wallet_reservations: InMemoryRepository::new(),
            payment_attempts: InMemoryRepository::new(),
            payment_methods: InMemoryRepository::new(),
            guardrail_policy_revisions: InMemoryRepository::new(),
            guardrail_policy_bindings: InMemoryRepository::new(),
            mcp_oauth_authorization_generations: InMemoryRepository::new(),
            mcp_oauth_flows: InMemoryRepository::new(),
            mcp_oauth_credentials: InMemoryRepository::new(),
            snapshot_replay_floors: InMemoryRepository::new(),
            agent_schedules: InMemoryRepository::new(),
            agent_schedule_fires: InMemoryRepository::new(),
            workflow_run_budgets: InMemoryRepository::new(),
            retention_policies: InMemoryRepository::new(),
            site_domains: InMemoryRepository::new(),
            observed_agent_presence: InMemoryRepository::new(),
        }
    }

    fn get_snapshot_replay_floor(&self, tenant_id: &str, deployment_id: &str) -> Option<u64> {
        self.snapshot_replay_floors
            .get(&snapshot_replay_floor_key(tenant_id, deployment_id))
    }

    /// Monotonic in-memory floor advance; returns the resulting floor.
    fn advance_snapshot_replay_floor(
        &mut self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
    ) -> u64 {
        let key = snapshot_replay_floor_key(tenant_id, deployment_id);
        let floor = self.snapshot_replay_floors.get(&key).unwrap_or(0);
        let next = floor.max(revision);
        self.snapshot_replay_floors.insert(key, next);
        next
    }

    fn insert_guardrail_policy_revision(
        &mut self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        if self.guardrail_policy_revisions.get(&revision.id).is_some() {
            return Err(StorageError::Conflict(format!(
                "guardrail policy revision {} already exists",
                revision.id
            )));
        }
        self.guardrail_policy_revisions
            .insert(revision.id.clone(), revision);
        Ok(())
    }

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Option<StoredGuardrailPolicyRevision> {
        self.guardrail_policy_revisions
            .get(&guardrail_policy_revision_id(policy_id, revision))
    }

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Vec<StoredGuardrailPolicyRevision> {
        let mut revisions = self
            .guardrail_policy_revisions
            .list()
            .into_iter()
            .filter(|revision| policy_id.is_none_or(|policy_id| revision.policy_id == policy_id))
            .collect::<Vec<_>>();
        revisions.sort_by(|left, right| {
            left.policy_id
                .cmp(&right.policy_id)
                .then_with(|| left.revision.cmp(&right.revision))
        });
        revisions
    }

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Option<StoredGuardrailPolicyBinding> {
        self.guardrail_policy_bindings.get(policy_id)
    }

    fn list_guardrail_policy_bindings(&self) -> Vec<StoredGuardrailPolicyBinding> {
        let mut bindings = self.guardrail_policy_bindings.list();
        bindings.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        bindings
    }

    fn activate_guardrail_policy_revision(
        &mut self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        if self
            .get_guardrail_policy_revision(policy_id, revision)
            .is_none()
        {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                guardrail_policy_revision_id(policy_id, revision)
            )));
        }
        let previous = self.get_guardrail_policy_binding(policy_id);
        let current = next_guardrail_activation_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
            rollback_only,
        )?;
        self.guardrail_policy_bindings
            .insert(policy_id.to_string(), current.clone());
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    fn archive_guardrail_policy_revision(
        &mut self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        if self
            .get_guardrail_policy_revision(policy_id, revision)
            .is_none()
        {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                guardrail_policy_revision_id(policy_id, revision)
            )));
        }
        let previous = self.get_guardrail_policy_binding(policy_id);
        let current = next_guardrail_archive_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
        )?;
        self.guardrail_policy_bindings
            .insert(policy_id.to_string(), current.clone());
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    fn restore_guardrail_policy_binding(
        &mut self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        let current_generation = self
            .get_guardrail_policy_binding(policy_id)
            .map(|binding| binding.generation);
        if current_generation != expected_generation {
            return Err(StorageError::Conflict(
                GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.into(),
            ));
        }
        match binding {
            Some(mut binding) => {
                binding.generation =
                    next_guardrail_binding_generation(expected_generation.unwrap_or_default())?;
                self.guardrail_policy_bindings
                    .insert(policy_id.to_string(), binding);
            }
            None => {
                self.guardrail_policy_bindings.remove(policy_id);
            }
        }
        Ok(())
    }

    pub fn upsert_tenant_account(&mut self, account: StoredTenantAccount) {
        self.tenant_accounts.insert(account.id.clone(), account);
    }

    pub fn upsert_admin_user(&mut self, user: StoredAdminUser) {
        self.admin_users.insert(user.id.clone(), user);
    }

    pub fn get_admin_user_by_id(&self, id: &str) -> Option<StoredAdminUser> {
        self.admin_users.get(id)
    }

    pub fn get_admin_user_by_email(&self, email: &str) -> Option<StoredAdminUser> {
        self.admin_users
            .list()
            .into_iter()
            .find(|user| user.email == email)
    }

    pub fn upsert_admin_user_membership(&mut self, membership: StoredAdminUserMembership) {
        self.admin_user_memberships
            .insert(membership.id.clone(), membership);
    }

    pub fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Vec<StoredAdminUserMembership> {
        self.admin_user_memberships
            .list()
            .into_iter()
            .filter(|membership| membership.user_id == user_id)
            .collect()
    }

    pub fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<StoredAdminUserMembership> {
        self.admin_user_memberships
            .list()
            .into_iter()
            .filter(|membership| membership.tenant_id == tenant_id)
            .collect()
    }

    pub fn delete_admin_user_membership(&mut self, user_id: &str, tenant_id: &str) -> bool {
        let Some(id) = self
            .admin_user_memberships
            .list()
            .into_iter()
            .find(|membership| membership.user_id == user_id && membership.tenant_id == tenant_id)
            .map(|membership| membership.id)
        else {
            return false;
        };
        self.admin_user_memberships.remove(&id).is_some()
    }

    pub fn upsert_admin_user_refresh_token(&mut self, token: StoredAdminUserRefreshToken) {
        self.admin_user_refresh_tokens
            .insert(token.id.clone(), token);
    }

    pub fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Option<StoredAdminUserRefreshToken> {
        self.admin_user_refresh_tokens
            .list()
            .into_iter()
            .find(|token| token.token_hash == token_hash)
    }

    pub fn revoke_all_admin_user_refresh_tokens(
        &mut self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> u64 {
        let mut affected = 0u64;
        for mut token in self
            .admin_user_refresh_tokens
            .list()
            .into_iter()
            .filter(|token| token.user_id == user_id && token.revoked_at_unix.is_none())
        {
            token.revoked_at_unix = Some(revoked_at_unix);
            self.admin_user_refresh_tokens
                .insert(token.id.clone(), token);
            affected += 1;
        }
        affected
    }

    /// Tenant-scoped counterpart of [`Self::revoke_all_admin_user_refresh_tokens`]
    /// (issue #232): only revokes tokens stamped with `tenant_id`, leaving the
    /// user's sessions in other tenants untouched.
    pub fn revoke_admin_user_refresh_tokens_for_tenant(
        &mut self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> u64 {
        let mut affected = 0u64;
        for mut token in self
            .admin_user_refresh_tokens
            .list()
            .into_iter()
            .filter(|token| {
                token.user_id == user_id
                    && token.tenant_id.as_deref() == Some(tenant_id)
                    && token.revoked_at_unix.is_none()
            })
        {
            token.revoked_at_unix = Some(revoked_at_unix);
            self.admin_user_refresh_tokens
                .insert(token.id.clone(), token);
            affected += 1;
        }
        affected
    }

    pub fn get_tenant_account(&self, id: &str) -> Option<StoredTenantAccount> {
        self.tenant_accounts.get(id)
    }

    pub fn list_tenant_accounts(&self) -> Vec<StoredTenantAccount> {
        self.tenant_accounts.list()
    }

    pub fn delete_tenant_account(&mut self, id: &str) -> bool {
        self.tenant_accounts.remove(id).is_some()
    }

    pub fn upsert_project(&mut self, project: StoredProject) {
        self.projects.insert(project.id.clone(), project);
    }

    pub fn get_project(&self, id: &str) -> Option<StoredProject> {
        self.projects.get(id)
    }

    pub fn list_projects(&self) -> Vec<StoredProject> {
        self.projects.list()
    }

    pub fn delete_project(&mut self, id: &str) -> bool {
        self.projects.remove(id).is_some()
    }

    /// Atomic reject-if-referenced project delete (issue #328, finding 4).
    /// The in-memory backend runs the whole check-then-delete inside the
    /// caller's `Mutex` critical section, so counting and deleting are
    /// already indivisible; this mirrors the Postgres transaction so both
    /// backends expose the same contract.
    pub fn delete_project_if_unreferenced(&mut self, id: &str) -> DeleteProjectOutcome {
        if self.projects.get(id).is_none() {
            return DeleteProjectOutcome::NotFound;
        }
        let workspaces = self
            .workspaces
            .list()
            .into_iter()
            .filter(|workspace| workspace.project_id == id)
            .count();
        let virtual_keys = self
            .api_key_records
            .list()
            .into_iter()
            .filter(|key| key.project_id == id)
            .count();
        if workspaces > 0 || virtual_keys > 0 {
            return DeleteProjectOutcome::Referenced {
                workspaces,
                virtual_keys,
            };
        }
        if self.projects.remove(id).is_some() {
            DeleteProjectOutcome::Deleted
        } else {
            DeleteProjectOutcome::NotFound
        }
    }

    pub fn upsert_workspace(&mut self, workspace: StoredWorkspace) {
        self.workspaces.insert(workspace.id.clone(), workspace);
    }

    pub fn get_workspace(&self, id: &str) -> Option<StoredWorkspace> {
        self.workspaces.get(id)
    }

    pub fn list_workspaces(&self) -> Vec<StoredWorkspace> {
        self.workspaces.list()
    }

    pub fn delete_workspace(&mut self, id: &str) -> bool {
        self.workspaces.remove(id).is_some()
    }

    /// Atomic reject-if-referenced workspace delete (issue #328, finding 4).
    /// See [`RuntimeControlPlaneState::delete_project_if_unreferenced`].
    pub fn delete_workspace_if_unreferenced(&mut self, id: &str) -> DeleteWorkspaceOutcome {
        if self.workspaces.get(id).is_none() {
            return DeleteWorkspaceOutcome::NotFound;
        }
        let virtual_keys = self
            .api_key_records
            .list()
            .into_iter()
            .filter(|key| key.workspace_id == id)
            .count();
        if virtual_keys > 0 {
            return DeleteWorkspaceOutcome::Referenced { virtual_keys };
        }
        if self.workspaces.remove(id).is_some() {
            DeleteWorkspaceOutcome::Deleted
        } else {
            DeleteWorkspaceOutcome::NotFound
        }
    }

    pub fn upsert_sso_provider_config(&mut self, config: StoredSsoProviderConfig) {
        self.sso_provider_configs
            .insert(config.tenant_id.clone(), config);
    }

    pub fn get_sso_provider_config(&self, tenant_id: &str) -> Option<StoredSsoProviderConfig> {
        self.sso_provider_configs.get(tenant_id)
    }

    pub fn delete_sso_provider_config(&mut self, tenant_id: &str) -> bool {
        self.sso_provider_configs.remove(tenant_id).is_some()
    }

    pub fn insert_sso_pending_flow(&mut self, flow: StoredSsoPendingFlow) {
        self.sso_pending_flows.insert(flow.state.clone(), flow);
    }

    /// Atomically consumes (removes and returns) a pending SSO flow by its
    /// `state` token, opportunistically pruning any expired flows first so the
    /// in-memory store cannot grow without bound.
    pub fn take_sso_pending_flow(
        &mut self,
        state: &str,
        now_unix: i64,
    ) -> Option<StoredSsoPendingFlow> {
        let expired: Vec<String> = self
            .sso_pending_flows
            .list()
            .into_iter()
            .filter(|flow| flow.expires_at_unix <= now_unix)
            .map(|flow| flow.state)
            .collect();
        for stale in expired {
            self.sso_pending_flows.remove(&stale);
        }
        self.sso_pending_flows.remove(state)
    }

    pub fn upsert_quota_policy(&mut self, policy: StoredQuotaPolicy) {
        self.quota_policies.insert(policy.id.clone(), policy);
    }

    pub fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Option<StoredQuotaPolicy> {
        self.quota_policies
            .get(&quota_policy_id(scope_type, scope_id))
    }

    pub fn list_quota_policies(&self) -> Vec<StoredQuotaPolicy> {
        self.quota_policies.list()
    }

    pub fn delete_quota_policy(&mut self, scope_type: QuotaScopeKind, scope_id: &str) -> bool {
        self.quota_policies
            .remove(&quota_policy_id(scope_type, scope_id))
            .is_some()
    }

    pub fn upsert_plan(&mut self, plan: StoredPlan) {
        self.plans.insert(plan.id.clone(), plan);
    }

    pub fn get_plan(&self, id: &str) -> Option<StoredPlan> {
        self.plans.get(id)
    }

    pub fn list_plans(&self) -> Vec<StoredPlan> {
        self.plans.list()
    }

    pub fn upsert_asset(&mut self, asset: StoredAsset) {
        self.assets.insert(asset.id.clone(), asset);
    }

    pub fn create_asset_if_absent(&mut self, asset: StoredAsset) -> bool {
        if self.assets.records.contains_key(&asset.id) {
            return false;
        }
        self.assets.insert(asset.id.clone(), asset);
        true
    }

    /// Memory equivalent of the atomic quota admission (issue #371). The whole
    /// read-guard-insert happens while the caller holds the single control-plane
    /// lock, so it is the exact analogue of the one Postgres conditional
    /// statement: the tenant usage read, the quota guard, the immutability guard,
    /// and the insert cannot interleave with another admission. Both backends run
    /// the same [`classify_asset_quota_admission`] so their truth tables match.
    pub fn create_asset_within_quota(
        &mut self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> AssetQuotaAdmission {
        let id_exists = self.assets.records.contains_key(&asset.id);
        // Usage is read BEFORE the insert and excludes this attempt's row, exactly
        // as the Postgres `SUM(size_bytes)` guard subquery does.
        let used_bytes = self.tenant_asset_storage_bytes_used(&asset.tenant_id);
        let attempted_bytes = asset.size_bytes;
        let quota_ok =
            quota_bytes.is_none_or(|quota| used_bytes.saturating_add(attempted_bytes) <= quota);
        let inserted = !id_exists && quota_ok;
        if inserted {
            self.assets.insert(asset.id.clone(), asset);
        }
        classify_asset_quota_admission(
            inserted,
            id_exists,
            quota_ok,
            used_bytes,
            attempted_bytes,
            quota_bytes,
        )
    }

    pub fn get_asset(&self, id: &str) -> Option<StoredAsset> {
        self.assets.get(id)
    }

    pub fn list_assets(&self, tenant_id: &str, asset_type: Option<&str>) -> Vec<StoredAsset> {
        self.assets
            .list()
            .into_iter()
            .filter(|asset| asset.tenant_id == tenant_id)
            .filter(|asset| match asset_type {
                Some(wanted) => asset.asset_type == wanted,
                None => true,
            })
            .collect()
    }

    /// The operator-only inverse of [`Self::list_assets`] (issue #379, follow-up
    /// to #366): return exactly the rows the ordinary list/manifest/resolution
    /// path WITHHOLDS -- every non-`Visible` (`pending_scan`/`quarantined`) asset
    /// for the tenant -- so an operator can inspect and act on assets that
    /// consumers can never see. Ordering is deterministic (asset_type, name,
    /// version) so the caller's offset/limit pagination is stable, mirroring the
    /// Postgres `ORDER BY` on the same columns.
    pub fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Vec<StoredAsset> {
        let mut rows: Vec<StoredAsset> = self
            .assets
            .list()
            .into_iter()
            .filter(|asset| asset.tenant_id == tenant_id)
            .filter(|asset| match asset_type {
                Some(wanted) => asset.asset_type == wanted,
                None => true,
            })
            // #366/#379: only the withheld states. `is_downloadable()` is the
            // exact predicate the read path uses to hide these, so this inverse
            // view can never disagree with what consumers are denied.
            .filter(|asset| !asset.is_downloadable())
            .collect();
        rows.sort_by(|left, right| {
            left.asset_type
                .cmp(&right.asset_type)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.version.cmp(&right.version))
                .then_with(|| left.variant.cmp(&right.variant))
        });
        rows
    }

    pub fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> u64 {
        self.assets
            .records
            .values()
            .filter(|asset| asset.tenant_id == tenant_id)
            .fold(0_u64, |total, asset| total.saturating_add(asset.size_bytes))
    }

    pub fn delete_asset(&mut self, id: &str) -> bool {
        self.assets.remove(id).is_some()
    }

    pub fn upsert_asset_channel(&mut self, channel: StoredAssetChannel) {
        self.asset_channels.insert(channel.id.clone(), channel);
    }

    pub fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Vec<StoredAssetChannel> {
        self.asset_channels
            .list()
            .into_iter()
            .filter(|channel| {
                channel.tenant_id == tenant_id
                    && channel.asset_type == asset_type
                    && channel.name == name
            })
            .collect()
    }

    pub fn delete_asset_channel(&mut self, id: &str) -> bool {
        self.asset_channels.remove(id).is_some()
    }

    // #367: atomic channel/version lifecycle coordination. Each of these runs
    // the whole check-and-mutate under the single control-plane lock the facade
    // already holds, which is the memory-backend equivalent of the Postgres
    // `FOR UPDATE` serialization point on the version's `stored_assets` rows.

    /// Whether `version` of one `{tenant, asset_type, name}` line is resolvable:
    /// at least one variant row exists and none of its variant rows is yanked
    /// (resolution treats a version as yanked when any variant is yanked). This
    /// is the memory counterpart of the Postgres resolvability guard and mirrors
    /// the gateway's `channel_target_is_resolvable`.
    fn asset_version_is_resolvable(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> bool {
        let mut found = false;
        for asset in self.assets.records.values().filter(|asset| {
            asset.tenant_id == tenant_id
                && asset.asset_type == asset_type
                && asset.name == name
                && asset.version == version
        }) {
            found = true;
            if asset.yanked {
                return false;
            }
        }
        found
    }

    fn asset_version_is_channel_referenced(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> bool {
        self.asset_channels.records.values().any(|channel| {
            channel.tenant_id == tenant_id
                && channel.asset_type == asset_type
                && channel.name == name
                && channel.version == version
        })
    }

    /// Move a channel pointer only when its target version is durably
    /// resolvable (issue #367). The resolvability check and the channel upsert
    /// run under one lock, so a concurrent yank/delete cannot land between them.
    pub fn move_asset_channel_if_resolvable(
        &mut self,
        channel: StoredAssetChannel,
    ) -> ChannelMoveOutcome {
        if !self.asset_version_is_resolvable(
            &channel.tenant_id,
            &channel.asset_type,
            &channel.name,
            &channel.version,
        ) {
            return ChannelMoveOutcome::TargetNotResolvable;
        }
        let prior_version = self
            .asset_channels
            .records
            .get(&channel.id)
            .map(|existing| existing.version.clone());
        self.asset_channels.insert(channel.id.clone(), channel);
        ChannelMoveOutcome::Moved { prior_version }
    }

    /// Set (or clear) the yank flag on every variant row of a version (issue
    /// #367). Yank is rejected while a channel references the version; unyank
    /// never coordinates because restoring resolvability cannot strand a
    /// channel. Runs under one lock.
    pub fn set_asset_version_yank(
        &mut self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> VersionYankOutcome {
        let target_ids: Vec<String> = self
            .assets
            .records
            .values()
            .filter(|asset| {
                asset.tenant_id == tenant_id
                    && asset.asset_type == asset_type
                    && asset.name == name
                    && asset.version == version
            })
            .map(|asset| asset.id.clone())
            .collect();
        if target_ids.is_empty() {
            return VersionYankOutcome::NotFound;
        }
        if yanked && self.asset_version_is_channel_referenced(tenant_id, asset_type, name, version)
        {
            return VersionYankOutcome::ReferencedByChannel;
        }
        for id in &target_ids {
            if let Some(asset) = self.assets.records.get_mut(id) {
                asset.yanked = yanked;
                asset.updated_at_unix = now_unix;
            }
        }
        VersionYankOutcome::Applied {
            variants: target_ids.len(),
        }
    }

    /// Delete one variant row unless doing so would strand a channel (issue
    /// #367): a delete that removes the last resolvable variant of a
    /// channel-referenced version is rejected. Runs under one lock.
    pub fn delete_asset_variant_if_unreferenced(
        &mut self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> VariantDeleteOutcome {
        if !self.assets.records.contains_key(id) {
            return VariantDeleteOutcome::NotFound;
        }
        let remaining_resolvable = self.assets.records.values().any(|asset| {
            asset.id != id
                && asset.tenant_id == tenant_id
                && asset.asset_type == asset_type
                && asset.name == name
                && asset.version == version
                && !asset.yanked
        });
        if !remaining_resolvable
            && self.asset_version_is_channel_referenced(tenant_id, asset_type, name, version)
        {
            return VariantDeleteOutcome::BlockedByChannel;
        }
        self.assets.remove(id);
        VariantDeleteOutcome::Deleted
    }

    /// Promote a single `pending_scan` asset row to a terminal visibility
    /// (issue #378) under one lock. The flip is applied only when the row is
    /// currently `pending_scan`; a missing or already-terminal row is rejected
    /// fail-closed so a completed out-of-band scan can never silently
    /// re-promote (or re-quarantine) a terminal asset. The single control-plane
    /// lock the caller holds around this method is the serialization point, so
    /// two concurrent promotions of the same row cannot both observe
    /// `pending_scan` -- the second sees the terminal state the first wrote.
    pub fn promote_pending_asset_visibility(
        &mut self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> AssetVisibilityPromotionOutcome {
        let Some(asset) = self.assets.records.get_mut(id) else {
            return AssetVisibilityPromotionOutcome::NotFound;
        };
        if asset.visibility != AssetVisibility::PendingScan {
            return AssetVisibilityPromotionOutcome::NotPending {
                current: asset.visibility,
            };
        }
        let to = target.visibility();
        asset.visibility = to;
        asset.updated_at_unix = now_unix;
        AssetVisibilityPromotionOutcome::Promoted { to }
    }

    // #263: asset lifecycle -- retention policies + reconcile scans.

    pub fn upsert_retention_policy(&mut self, policy: StoredRetentionPolicy) {
        self.retention_policies.insert(policy.id.clone(), policy);
    }

    pub fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Vec<StoredRetentionPolicy> {
        self.retention_policies
            .list()
            .into_iter()
            .filter(|policy| policy.tenant_id == tenant_id && policy.resource_type == resource_type)
            .collect()
    }

    pub fn delete_retention_policy(&mut self, id: &str) -> bool {
        self.retention_policies.remove(id).is_some()
    }

    /// Every asset row across every tenant. The lifecycle sweeper (#263) groups
    /// these by `{tenant, asset_type, name}` for retention and derives the GC
    /// referenced-key set from their `storage_uri`s.
    pub fn list_all_assets(&self) -> Vec<StoredAsset> {
        self.assets.list()
    }

    /// Every channel pointer across every tenant, so the sweeper (#263) can
    /// determine which versions are channel-pinned (never pruned).
    pub fn list_all_asset_channels(&self) -> Vec<StoredAssetChannel> {
        self.asset_channels.list()
    }

    /// In-memory counterpart of `increment_usage_monthly_rollups` (Postgres):
    /// fans a settled request out into up to four rollup rows, one per
    /// non-empty scope level in `tenant`. Crate-internal only: `UsageMonthlyDelta`
    /// is a private plumbing type shared with the Postgres path, not part of
    /// this crate's public API.
    pub(crate) fn increment_usage_monthly_rollups(
        &mut self,
        tenant: &TenantContext,
        period_month: &str,
        delta: &UsageMonthlyDelta,
    ) {
        let scopes: [(QuotaScopeKind, Option<&str>); 4] = [
            (QuotaScopeKind::Tenant, tenant.organization_id.as_deref()),
            (QuotaScopeKind::Project, tenant.project_id.as_deref()),
            (QuotaScopeKind::Workspace, tenant.workspace_id.as_deref()),
            (QuotaScopeKind::Key, tenant.api_key_id.as_deref()),
        ];
        for (scope_type, scope_id) in scopes {
            let Some(scope_id) = scope_id else {
                continue;
            };
            let id = usage_monthly_rollup_id(period_month, scope_type, scope_id);
            let mut rollup =
                self.usage_monthly_rollups
                    .get(&id)
                    .unwrap_or_else(|| StoredUsageMonthlyRollup {
                        id: id.clone(),
                        period_month: period_month.to_string(),
                        scope_type,
                        scope_id: scope_id.to_string(),
                        prompt_tokens: 0,
                        completion_tokens: 0,
                        total_tokens: 0,
                        cost_usd: 0.0,
                        request_count: 0,
                        error_count: 0,
                        updated_at_unix: 0,
                    });
            rollup.prompt_tokens = rollup.prompt_tokens.saturating_add(delta.prompt_tokens);
            rollup.completion_tokens = rollup
                .completion_tokens
                .saturating_add(delta.completion_tokens);
            rollup.total_tokens = rollup.total_tokens.saturating_add(delta.total_tokens);
            rollup.cost_usd += delta.cost_usd;
            rollup.request_count = rollup.request_count.saturating_add(1);
            if delta.is_error {
                rollup.error_count = rollup.error_count.saturating_add(1);
            }
            self.usage_monthly_rollups.insert(id, rollup);
        }
    }

    pub fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Option<StoredUsageMonthlyRollup> {
        self.usage_monthly_rollups
            .get(&usage_monthly_rollup_id(period_month, scope_type, scope_id))
    }

    pub fn list_usage_monthly_rollups(&self) -> Vec<StoredUsageMonthlyRollup> {
        self.usage_monthly_rollups.list()
    }

    pub fn enqueue_billing_report(
        &mut self,
        id: &str,
        event: &BillingEvent,
        next_attempt_unix: i64,
    ) {
        // Idempotent: keep the earliest enqueue for an id (matching the
        // Postgres `ON CONFLICT DO NOTHING`).
        if self.billing_report_outbox.get(id).is_none() {
            self.billing_report_outbox.insert(
                id,
                StoredBillingReportOutboxEntry {
                    id: id.to_string(),
                    event: event.clone(),
                    attempts: 0,
                    next_attempt_unix,
                    dead_lettered_at_unix: None,
                },
            );
        }
    }

    pub fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Vec<StoredBillingReportOutboxEntry> {
        let mut due: Vec<StoredBillingReportOutboxEntry> = self
            .billing_report_outbox
            .list()
            .into_iter()
            .filter(|entry| {
                entry.next_attempt_unix <= now_unix && entry.dead_lettered_at_unix.is_none()
            })
            .collect();
        due.sort_by(|a, b| {
            a.next_attempt_unix
                .cmp(&b.next_attempt_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        due.truncate(limit);
        due
    }

    pub fn reschedule_billing_report(&mut self, id: &str, next_attempt_unix: i64) {
        if let Some(mut entry) = self.billing_report_outbox.get(id) {
            entry.attempts += 1;
            entry.next_attempt_unix = next_attempt_unix;
            self.billing_report_outbox.insert(id, entry);
        }
    }

    /// Mark a permanently-failing report dead-lettered (issue #143) instead of
    /// rescheduling it forever.
    pub fn dead_letter_billing_report(&mut self, id: &str, dead_lettered_at_unix: i64) {
        if let Some(mut entry) = self.billing_report_outbox.get(id) {
            entry.dead_lettered_at_unix = Some(dead_lettered_at_unix);
            self.billing_report_outbox.insert(id, entry);
        }
    }

    pub fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Vec<StoredBillingReportOutboxEntry> {
        let mut dead: Vec<StoredBillingReportOutboxEntry> = self
            .billing_report_outbox
            .list()
            .into_iter()
            .filter(|entry| entry.dead_lettered_at_unix.is_some())
            .collect();
        dead.sort_by_key(|entry| std::cmp::Reverse(entry.dead_lettered_at_unix));
        dead.truncate(limit);
        dead
    }

    /// In-memory twin of the Postgres CAS replay (issue #388): only a row
    /// that is actually dead-lettered transitions. The whole read-modify-write
    /// runs under the caller's control-plane lock, so the check-then-write is
    /// atomic against a concurrent replay of the same id -- the second caller
    /// observes a cleared `dead_lettered_at_unix` and gets `NotDeadLettered`.
    pub fn replay_dead_lettered_billing_report(
        &mut self,
        id: &str,
        next_attempt_unix: i64,
    ) -> ReplayDeadLetterOutcome {
        match self.billing_report_outbox.get(id) {
            None => ReplayDeadLetterOutcome::NotFound,
            Some(entry) if entry.dead_lettered_at_unix.is_none() => {
                ReplayDeadLetterOutcome::NotDeadLettered(entry)
            }
            Some(mut entry) => {
                entry.dead_lettered_at_unix = None;
                entry.attempts = 0;
                entry.next_attempt_unix = next_attempt_unix;
                self.billing_report_outbox.insert(id, entry.clone());
                ReplayDeadLetterOutcome::Replayed(entry)
            }
        }
    }

    pub fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Option<StoredBillingReportOutboxEntry> {
        self.billing_report_outbox.get(id)
    }

    pub fn delete_billing_report(&mut self, id: &str) {
        self.billing_report_outbox.remove(id);
    }

    /// Resolve a workspace id to its full attribution chain using the workspace's
    /// stored `tenant_id`/`project_id`. Returns `None` when the workspace is unknown.
    pub fn resolve_workspace_scope(&self, workspace_id: &str) -> Option<WorkspaceScope> {
        self.workspaces
            .get(workspace_id)
            .map(|workspace| resolve_scope_from_workspace(&workspace))
    }

    pub fn from_documents(documents: ControlPlaneDocuments) -> Self {
        let mut state = Self::new();
        for (id, document_json) in documents.api_keys {
            state.upsert_api_key(id, document_json);
        }
        for (id, document_json) in documents.tenants {
            state.upsert_tenant(id, document_json);
        }
        for (id, document_json) in documents.policies {
            state.upsert_policy(id, document_json);
        }
        for (id, document_json) in documents.gateway_configs {
            state.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in documents.agent_workflows {
            state.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in documents.skill_packages {
            state.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in documents.prompt_templates {
            state.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in documents.plugin_registrations {
            state.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in documents.mcp_servers {
            state.upsert_mcp_server(id, document_json);
        }
        for (id, document_json) in documents.agent_upstreams {
            state.upsert_agent_upstream(id, document_json);
        }
        state
    }

    pub fn replace_config_documents(&mut self, documents: ControlPlaneDocuments) {
        self.api_keys = InMemoryRepository::new();
        self.tenants = InMemoryRepository::new();
        self.policies = InMemoryRepository::new();
        self.gateway_configs = InMemoryRepository::new();
        self.agent_workflows = InMemoryRepository::new();
        self.skill_packages = InMemoryRepository::new();
        self.prompt_templates = InMemoryRepository::new();
        self.plugin_registrations = InMemoryRepository::new();
        self.mcp_servers = InMemoryRepository::new();
        self.agent_upstreams = InMemoryRepository::new();
        for (id, document_json) in documents.api_keys {
            self.upsert_api_key(id, document_json);
        }
        for (id, document_json) in documents.tenants {
            self.upsert_tenant(id, document_json);
        }
        for (id, document_json) in documents.policies {
            self.upsert_policy(id, document_json);
        }
        for (id, document_json) in documents.gateway_configs {
            self.upsert_gateway_config(id, document_json);
        }
        for (id, document_json) in documents.agent_workflows {
            self.upsert_agent_workflow(id, document_json);
        }
        for (id, document_json) in documents.skill_packages {
            self.upsert_skill_package(id, document_json);
        }
        for (id, document_json) in documents.prompt_templates {
            self.upsert_prompt_template(id, document_json);
        }
        for (id, document_json) in documents.plugin_registrations {
            self.upsert_plugin_registration(id, document_json);
        }
        for (id, document_json) in documents.mcp_servers {
            self.upsert_mcp_server(id, document_json);
        }
        for (id, document_json) in documents.agent_upstreams {
            self.upsert_agent_upstream(id, document_json);
        }
    }

    pub fn snapshot(&self) -> ControlPlaneSnapshot {
        let documents = self.documents();
        ControlPlaneSnapshot {
            api_keys: into_document_json(documents.api_keys),
            tenants: into_document_json(documents.tenants),
            policies: into_document_json(documents.policies),
            gateway_configs: into_document_json(documents.gateway_configs),
            agent_workflows: into_document_json(documents.agent_workflows),
            skill_packages: into_document_json(documents.skill_packages),
            prompt_templates: into_document_json(documents.prompt_templates),
            plugin_registrations: into_document_json(documents.plugin_registrations),
            mcp_servers: into_document_json(documents.mcp_servers),
            agent_upstreams: into_document_json(documents.agent_upstreams),
        }
    }

    pub fn documents(&self) -> ControlPlaneDocuments {
        ControlPlaneDocuments {
            api_keys: sorted_control_plane_documents(&self.api_keys),
            tenants: sorted_control_plane_documents(&self.tenants),
            policies: sorted_control_plane_documents(&self.policies),
            gateway_configs: sorted_control_plane_documents(&self.gateway_configs),
            agent_workflows: sorted_control_plane_documents(&self.agent_workflows),
            skill_packages: sorted_control_plane_documents(&self.skill_packages),
            prompt_templates: sorted_control_plane_documents(&self.prompt_templates),
            plugin_registrations: sorted_control_plane_documents(&self.plugin_registrations),
            mcp_servers: sorted_control_plane_documents(&self.mcp_servers),
            agent_upstreams: sorted_control_plane_documents(&self.agent_upstreams),
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

    pub fn upsert_api_key_record(&mut self, api_key: StoredApiKey) {
        self.api_key_records.insert(api_key.id.clone(), api_key);
    }

    pub fn get_api_key_record(&self, id: &str) -> Option<StoredApiKey> {
        self.api_key_records.get(id)
    }

    pub fn list_api_key_records(&self) -> Vec<StoredApiKey> {
        self.api_key_records.list()
    }

    pub fn find_api_key_records_by_prefix(&self, key_prefix: &str) -> Vec<StoredApiKey> {
        self.api_key_records
            .list()
            .into_iter()
            .filter(|api_key| api_key.key_prefix == key_prefix)
            .collect()
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

    pub fn upsert_agent_upstream(&mut self, id: impl Into<String>, document_json: String) {
        let id = id.into();
        self.agent_upstreams.insert(
            id.clone(),
            StoredControlPlaneResource {
                kind: "agent_upstream".into(),
                id,
                document_json,
            },
        );
    }

    pub fn delete_agent_upstream(&mut self, id: &str) -> bool {
        self.agent_upstreams.remove(id).is_some()
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
        into_document_json(self.tool_approval_documents())
    }

    pub fn tool_approval_documents(&self) -> Vec<(String, String)> {
        sorted_control_plane_documents(&self.tool_approvals)
    }
}

impl Default for RuntimeControlPlaneState {
    fn default() -> Self {
        Self::new()
    }
}

fn sorted_control_plane_documents(
    repository: &InMemoryRepository<StoredControlPlaneResource>,
) -> Vec<(String, String)> {
    let mut documents = repository
        .list()
        .into_iter()
        .map(|resource| (resource.id, resource.document_json))
        .collect::<Vec<_>>();
    documents.sort_by(|left, right| left.0.cmp(&right.0));
    documents
}

fn into_document_json(documents: Vec<(String, String)>) -> Vec<String> {
    documents
        .into_iter()
        .map(|(_, document_json)| document_json)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredApiKey {
    pub id: String,
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub key_prefix: String,
    pub key_hash: String,
    #[serde(default)]
    pub last4: String,
    pub enabled: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub tenant: TenantContext,
    #[serde(default)]
    pub monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
    #[serde(default)]
    pub rotated_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTenant {
    pub id: String,
    pub name: String,
    pub tenant: TenantContext,
}

/// Top-level tenant account (billing / isolation boundary) in the
/// Tenant -> Project -> Workspace hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTenantAccount {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    /// Subscription/entitlement tier (issue #168), resolved through
    /// [`StoredPlan`] to supply the default quota bundle and feature flags a
    /// tenant gets before any explicit [`StoredQuotaPolicy`] override.
    /// Defaults to the `free` plan seeded by the schema migration, so
    /// existing rows and callers that don't set it keep prior behavior.
    #[serde(default = "default_plan_id")]
    pub plan_id: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

fn default_plan_id() -> String {
    "free".to_string()
}

/// The plan every tenant lands on unless explicitly assigned another one --
/// seeded into both the in-memory backend (here) and the Postgres schema
/// migration (`sql/001_init_postgres.sql`), so `plan_id = "free"` always
/// resolves to a real row regardless of storage backend.
fn default_free_plan() -> StoredPlan {
    StoredPlan {
        id: "free".to_string(),
        name: "Free".to_string(),
        slug: "free".to_string(),
        mcp_enabled: false,
        self_hosted_workers_enabled: false,
        admin_console_seats: Some(1),
        default_model_allowlist: Vec::new(),
        default_rpm_limit: None,
        default_tpm_limit: None,
        default_monthly_budget_usd: None,
        created_at_unix: 0,
        updated_at_unix: 0,
        // Unlike mcp_enabled/self_hosted_workers_enabled (compute-adjacent,
        // gated off by default), a small free asset-hosting quota is a
        // deliberate self-serve growth lever (issue #176/#177) rather than a
        // premium-only feature -- 10 MiB matches the per-asset row cap in
        // the `stored_assets` schema.
        asset_hosting_enabled: true,
        default_asset_storage_quota_bytes: Some(10 * 1024 * 1024),
        // Compute-adjacent like mcp_enabled/self_hosted_workers_enabled --
        // gated off by default (issue #183).
        extension_tools_enabled: false,
        // #262: a small free monthly egress budget (100 MiB) mirrors the free
        // storage quota above -- a self-serve growth lever, not a hard sell.
        default_monthly_egress_bytes_budget: Some(100 * 1024 * 1024),
        default_download_rpm_limit: None,
    }
}

/// A sellable subscription tier (issue #168): a named bundle of feature
/// flags plus default quota values that seed [`EffectiveQuota`] before any
/// scope-specific [`StoredQuotaPolicy`] override is applied. Plans are
/// shared across tenants (like [`crate::StoredQuotaPolicy`]'s sibling
/// concept, a named permission bundle) rather than owned by one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredPlan {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub mcp_enabled: bool,
    #[serde(default)]
    pub self_hosted_workers_enabled: bool,
    #[serde(default)]
    pub admin_console_seats: Option<u32>,
    #[serde(default)]
    pub default_model_allowlist: Vec<String>,
    #[serde(default)]
    pub default_rpm_limit: Option<u64>,
    #[serde(default)]
    pub default_tpm_limit: Option<u64>,
    #[serde(default)]
    pub default_monthly_budget_usd: Option<f64>,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
    /// Gates `/v1/assets/*` (issue #176/#177) the same way `mcp_enabled`
    /// gates MCP tool governance -- fail closed when absent or `false`.
    #[serde(default)]
    pub asset_hosting_enabled: bool,
    #[serde(default)]
    pub default_asset_storage_quota_bytes: Option<u64>,
    /// #262 (egress governance): tenant-wide default monthly egress/download
    /// byte budget, the floor `resolve_effective_quota` applies when no
    /// explicit `quota_policies.monthly_egress_bytes_budget` is set anywhere
    /// in the chain (mirrors `default_monthly_budget_usd`).
    #[serde(default)]
    pub default_monthly_egress_bytes_budget: Option<u64>,
    /// #262 (egress governance): tenant-wide default per-minute asset-download
    /// request cap, the floor applied when no explicit
    /// `quota_policies.download_rpm_limit` is set in the chain.
    #[serde(default)]
    pub default_download_rpm_limit: Option<u64>,
    /// Gates Extension-backend `/v1/tools/execute` (issue #183) the same
    /// way `mcp_enabled` gates the Mcp backend at the same endpoint --
    /// before this field existed, a tenant whose plan disabled
    /// `mcp_enabled` had no equivalent protection against routing
    /// identical tool-execution traffic through the Extension backend
    /// instead, since only the Mcp branch was ever checked. Fail closed
    /// when absent or `false`, same as every other plan flag.
    #[serde(default)]
    pub extension_tools_enabled: bool,
}

/// Durable trust-screening state of a stored asset version (issue #366). Push
/// screening (`asset_security::screen_asset_push`) resolves every asset -- from
/// both the inline and the presigned commit path -- to one of these states over
/// the *final verified bytes*. Only [`AssetVisibility::Visible`] is downloadable;
/// `PendingScan`/`Quarantined` rows are persisted but withheld from every
/// resolution and download surface until an out-of-band scan promotes them
/// clean. This is the write-path == read-path guard (#188): the state the push
/// path persists is exactly the state the read path enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssetVisibility {
    /// Screened clean (or a pre-#366 row, via `Default`): resolvable and
    /// downloadable through every asset surface.
    #[default]
    Visible,
    /// Admitted to storage but not yet proven clean (deferred/async scan). The
    /// bytes exist durably but are withheld from consumers until promoted.
    PendingScan,
    /// The scanner (or a fail-closed-unavailable policy) flagged the bytes.
    /// Stored for operator inspection but never served.
    Quarantined,
}

impl AssetVisibility {
    /// Stable wire/DB token. Kept in lockstep with `serde(rename_all)` so the
    /// TEXT column, the JSON snapshot, and audit evidence all agree.
    pub fn as_str(self) -> &'static str {
        match self {
            AssetVisibility::Visible => "visible",
            AssetVisibility::PendingScan => "pending_scan",
            AssetVisibility::Quarantined => "quarantined",
        }
    }

    /// Parse the TEXT column back into a typed state. An unrecognized token
    /// fails closed to `Quarantined` rather than silently becoming visible --
    /// an unknown state must never be served (#188 lesson: never let a poisoned
    /// or partially-migrated row default to downloadable).
    pub fn from_stored(raw: &str) -> Self {
        match raw {
            "visible" => AssetVisibility::Visible,
            "pending_scan" => AssetVisibility::PendingScan,
            _ => AssetVisibility::Quarantined,
        }
    }

    /// Whether a consumer may resolve/download this asset right now.
    pub fn is_downloadable(self) -> bool {
        matches!(self, AssetVisibility::Visible)
    }
}

/// A tenant-scoped static asset (issue #176): the storage primitive behind
/// the unified agent-asset hosting epic (#175) -- CLI tool packages, MCP
/// connection manifests, Skill bundles, static sites, and config files all
/// share this one table rather than being special-cased per type.
///
/// Content is stored inline (`content`) by default: it keeps every asset
/// operation to a single Postgres/Supabase round trip with no external
/// bucket credentials required, at the cost of Postgres row size for large
/// assets. When `storage_uri` is `Some`, the real bytes live in an
/// S3-compatible object-storage bucket instead (see
/// `ferrogate-cli/src/gateway/asset_bucket.rs`, issue #176) and `content`
/// is empty -- callers must check `storage_uri` before trusting `content`
/// to hold the actual asset bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredAsset {
    pub id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    pub asset_type: String,
    pub name: String,
    pub version: String,
    pub content_type: String,
    pub content_hash: String,
    pub size_bytes: u64,
    pub content: Vec<u8>,
    /// Bucket object key when this asset's bytes live in an S3-compatible
    /// bucket rather than the `content` column (issue #176). `None` means
    /// `content` holds the real bytes (the original, still-supported
    /// inline path).
    #[serde(default)]
    pub storage_uri: Option<String>,
    /// Platform/arch variant key for this artifact (issue #260), e.g.
    /// `linux-x86_64` / `darwin-arm64`. Empty string is the default
    /// "no-variant" artifact -- one logical `{name}/{version}` can carry
    /// multiple rows, one per variant, each with its own hash/size. Part of
    /// the row identity (`stored_asset_variant_id`), so it is never mutated
    /// on an upsert.
    #[serde(default)]
    pub variant: String,
    /// Yank flag (issue #260, cargo semantics): a yanked version is skipped
    /// by channel and semver-range resolution but still resolvable by exact
    /// `{name}/{version}` pull (with a deprecation warning). The bytes are
    /// retained -- yank is not delete.
    #[serde(default)]
    pub yanked: bool,
    /// Trust-screening visibility state (issue #366). A `Visible` asset is
    /// resolvable and downloadable; `PendingScan`/`Quarantined` rows are
    /// persisted but withheld from every list/manifest/resolution/download
    /// surface. Defaults to `Visible` so pre-#366 rows (and any snapshot
    /// exported before the column existed) deserialize as already-clean, which
    /// is safe because those rows were only ever admitted after passing the
    /// screening that existed at push time.
    #[serde(default)]
    pub visibility: AssetVisibility,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

impl StoredAsset {
    /// Whether this asset may be resolved/served right now (#366). The read
    /// path calls this at every download and resolution surface so a
    /// `PendingScan`/`Quarantined` row is never served.
    pub fn is_downloadable(&self) -> bool {
        self.visibility.is_downloadable()
    }
}

/// The durable, definitive outcome of an atomic asset-storage quota admission
/// (issue #371). The former admission was a read (`tenant_asset_storage_bytes_used`)
/// then a separate create, so two commits for two DIFFERENT asset ids could both
/// read the same remaining capacity, both pass, and jointly overshoot the tenant
/// quota. [`RuntimeControlPlane::create_asset_within_quota`] folds the usage read,
/// the quota guard, the immutability (create-if-absent) guard, and the row insert
/// into ONE conditional statement so exactly the fitting set is admitted.
///
/// This enum carries only the DEFINITIVE, pre-commit-fence classifications; a lost
/// commit outcome (the statement crossed the async-timeout fence after the commit
/// began) is reported as `Err(StorageError::OperationCommitOutcomeUnknown)` by the
/// method, never squashed into one of these arms, so a caller never treats an
/// unresolved reservation as a definitive rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetQuotaAdmission {
    /// The row was created; its `size_bytes` are now reserved against the tenant
    /// quota. This attempt is the immutable version.
    Admitted,
    /// This asset id already exists, so nothing was inserted and NO bytes were
    /// reserved (idempotent / immutable). A same-upload retry lands here and is
    /// therefore never charged twice. The caller reconciles the durable winner
    /// exactly as it would a create-if-absent conflict.
    AlreadyExists,
    /// Admission was definitively refused before any write: reserving
    /// `attempted_bytes` on top of the `used_bytes` observed in the same
    /// statement would exceed `quota_bytes`. Nothing was inserted, so no bytes
    /// were reserved and no candidate can be referenced by this attempt.
    OverQuota {
        used_bytes: u64,
        attempted_bytes: u64,
        quota_bytes: u64,
    },
}

/// The single classification the Postgres and memory backends share so their
/// admission truth tables can never drift (issue #371). Inputs mirror the four
/// values the one Postgres statement returns; the memory backend computes the
/// identical four under its lock.
///
/// Precedence is deliberate: an `Admitted` insert wins first; then an existing id
/// is an idempotent `AlreadyExists` (never charged, even if it would notionally
/// exceed quota); only a non-existing id whose quota guard FAILED is a definitive
/// `OverQuota`. A non-existing id that did not insert yet whose quota guard PASSED
/// can only be the rare same-id concurrent-commit race (Postgres `ON CONFLICT DO
/// NOTHING` after the snapshot); it is an `AlreadyExists` conflict, not a false
/// over-quota rejection.
fn classify_asset_quota_admission(
    inserted: bool,
    id_exists: bool,
    quota_ok: bool,
    used_bytes: u64,
    attempted_bytes: u64,
    quota_bytes: Option<u64>,
) -> AssetQuotaAdmission {
    if inserted {
        AssetQuotaAdmission::Admitted
    } else if id_exists || quota_ok {
        AssetQuotaAdmission::AlreadyExists
    } else {
        AssetQuotaAdmission::OverQuota {
            used_bytes,
            attempted_bytes,
            quota_bytes: quota_bytes.unwrap_or(u64::MAX),
        }
    }
}

/// Deterministic id for an asset so `upsert` is naturally idempotent per
/// `(tenant_id, asset_type, name, version)`, mirroring [`quota_policy_id`].
pub fn stored_asset_id(tenant_id: &str, asset_type: &str, name: &str, version: &str) -> String {
    format!("{tenant_id}:{asset_type}:{name}:{version}")
}

/// Variant-aware asset id (issue #260). Falls back to the historical
/// [`stored_asset_id`] shape for the default (empty) variant so pre-#260 rows
/// keep their ids, and appends `:v:{variant}` for platform/arch variants so
/// several variants of one `{name}/{version}` coexist under distinct ids.
pub fn stored_asset_variant_id(
    tenant_id: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    variant: &str,
) -> String {
    if variant.is_empty() {
        stored_asset_id(tenant_id, asset_type, name, version)
    } else {
        format!("{tenant_id}:{asset_type}:{name}:{version}:v:{variant}")
    }
}

/// A mutable channel pointer (issue #260): `latest` / `stable` / `canary` or
/// a free-form tag per `{tenant}/{asset_type}/{name}`, resolved to a concrete
/// version at pull time. Moving a tag is an upsert; the move is audited by the
/// gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAssetChannel {
    pub id: String,
    pub tenant_id: String,
    pub asset_type: String,
    pub name: String,
    pub channel: String,
    pub version: String,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Deterministic id for a channel pointer, idempotent per
/// `(tenant_id, asset_type, name, channel)`.
pub fn asset_channel_id(tenant_id: &str, asset_type: &str, name: &str, channel: &str) -> String {
    format!("{tenant_id}:{asset_type}:{name}:{channel}")
}

/// Outcome of the atomic channel move coordination mutation (issue #367). The
/// move is durable only when its target version is resolvable (present and with
/// no yanked variant) at the instant the channel row is written -- the check and
/// the write happen under one serialization point (the version's `stored_assets`
/// rows locked `FOR UPDATE` on Postgres, the single control-plane lock on
/// memory), so a concurrent yank/delete can never interleave between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelMoveOutcome {
    /// The channel now durably points at the requested version. `prior_version`
    /// is the version the channel pointed at before this move (`None` when the
    /// channel is newly created), recorded for audit evidence.
    Moved { prior_version: Option<String> },
    /// The requested version was absent or yanked at commit time, so no channel
    /// row was written. The caller must report the move as rejected.
    TargetNotResolvable,
}

/// Outcome of the atomic yank/unyank coordination mutation (issue #367). Yank
/// (`yanked = true`) is fail-closed: it is rejected while a channel still
/// references the version, preserving the invariant that no channel points at a
/// yanked version. Unyank (`yanked = false`) only restores resolvability and can
/// never strand a channel, so it never returns [`Self::ReferencedByChannel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionYankOutcome {
    /// The yank/unyank flag was applied to every variant row of the version.
    Applied { variants: usize },
    /// No variant row exists for the version (404).
    NotFound,
    /// A yank was rejected because a channel still references the version. The
    /// operator must move the channel off the version first (409).
    ReferencedByChannel,
}

/// Outcome of the atomic variant-delete coordination mutation (issue #367). A
/// delete is rejected when it would remove the last resolvable variant of a
/// version a channel still references, so a live channel can never be stranded
/// on an absent version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantDeleteOutcome {
    /// The variant row was deleted.
    Deleted,
    /// No variant row matched the id (404).
    NotFound,
    /// The delete would have removed the last resolvable variant of a
    /// channel-referenced version, so nothing was deleted (409).
    BlockedByChannel,
}

/// The legal terminal targets of an out-of-band scan promotion (issue #378). A
/// completed async scan can only ever move a `pending_scan` asset to one of
/// these two states -- clean bytes to `visible`, flagged bytes to
/// `quarantined` -- and never back to `pending_scan`. Modeling the target as
/// this two-variant enum makes an invalid/unknown promotion target
/// unrepresentable at the type level, so the CAS is fail-closed by
/// construction: the storage layer can never be handed a target that would
/// silently keep an asset withheld while reporting success, or promote to an
/// undefined state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetPromotionTarget {
    /// The out-of-band scan proved the bytes clean: publish the asset so every
    /// download/resolution surface will serve it.
    Visible,
    /// The out-of-band scan flagged the bytes: withhold them permanently for
    /// operator inspection (never served), the terminal fail-closed state.
    Quarantined,
}

impl AssetPromotionTarget {
    /// The durable [`AssetVisibility`] this target resolves to.
    pub fn visibility(self) -> AssetVisibility {
        match self {
            AssetPromotionTarget::Visible => AssetVisibility::Visible,
            AssetPromotionTarget::Quarantined => AssetVisibility::Quarantined,
        }
    }

    /// Stable wire token, kept in lockstep with [`AssetVisibility::as_str`] so
    /// the request contract, the persisted column, and the audit evidence all
    /// agree on one spelling.
    pub fn as_str(self) -> &'static str {
        self.visibility().as_str()
    }
}

/// Outcome of the atomic `pending_scan -> visible|quarantined` promotion CAS
/// (issue #378, follow-up to #366). The state flip is durable only when the row
/// is in `pending_scan` at the instant the conditional UPDATE fires; the
/// zero-row case is classified within the same statement snapshot (Postgres) /
/// under the same lock (memory) so a terminal (already-promoted) row is never
/// silently re-promoted and a missing row is never conflated with a rejected
/// one. Every non-`Promoted` variant means nothing was written -- fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetVisibilityPromotionOutcome {
    /// The row transitioned out of `pending_scan` to `to` (the requested
    /// terminal state). `to` is recorded so the caller's audit evidence links
    /// the scan outcome to the exact resulting visibility.
    Promoted { to: AssetVisibility },
    /// No `stored_assets` row with the given id exists (404). A scan result
    /// arriving for an absent asset is rejected, never treated as a success.
    NotFound,
    /// The row exists but is not `pending_scan`: it is already in a terminal
    /// state, so the promotion is a no-op and is rejected rather than silently
    /// succeeding (409 conflict). `current` is the state the row is actually
    /// in, so the caller can tell an already-`visible` from a `quarantined`
    /// asset in its evidence.
    NotPending { current: AssetVisibility },
}

/// SHA-256 content hash, hex-encoded. Computed by the caller when an asset
/// is pushed and re-verified on every read so storage-layer corruption or
/// tampering is detected rather than silently served (#176/#179).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Project (business line) nested under a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProject {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Workspace (environment such as dev/staging/prod) nested under a project.
/// `tenant_id` is stored redundantly so top-level isolation and aggregation can
/// filter workspaces without a join back through `projects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkspace {
    pub id: String,
    pub project_id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

fn default_active_status() -> String {
    "active".to_string()
}

fn default_environment() -> String {
    "default".to_string()
}

/// Outcome of an atomic reject-if-referenced project delete (issue #328,
/// finding 4). The child-count check and the `DELETE` run inside one
/// transaction (locking the parent row `FOR UPDATE` on Postgres so a
/// concurrent child insert cannot slip through the window and then be
/// silently `ON DELETE CASCADE`d), so the caller never observes a
/// time-of-check/time-of-use gap between counting and deleting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteProjectOutcome {
    /// The project existed, had no children, and was deleted.
    Deleted,
    /// No project with the given id exists.
    NotFound,
    /// The project still owns children and was left untouched. Both counts
    /// are reported so the caller can pick the exact 409 code/message
    /// (workspaces are surfaced before virtual keys, matching the prior
    /// two-step handler behavior).
    Referenced {
        workspaces: usize,
        virtual_keys: usize,
    },
}

/// Outcome of an atomic reject-if-referenced workspace delete (issue #328,
/// finding 4). See [`DeleteProjectOutcome`] for the atomicity guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteWorkspaceOutcome {
    /// The workspace existed, had no virtual keys, and was deleted.
    Deleted,
    /// No workspace with the given id exists.
    NotFound,
    /// The workspace still owns virtual keys and was left untouched.
    Referenced { virtual_keys: usize },
}

/// A human identity for the admin console (issue #157) -- distinct from
/// [`StoredApiKey`], which models machine/tenant-level gateway access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAdminUser {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    #[serde(default)]
    pub superadmin: bool,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
    #[serde(default)]
    pub last_login_at_unix: Option<i64>,
    #[serde(default)]
    pub disabled_at_unix: Option<i64>,
}

/// One admin user's membership in one tenant account, with a per-tenant role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAdminUserMembership {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub role: String,
    #[serde(default)]
    pub created_at_unix: i64,
}

/// A durable, hashed refresh token backing an admin console session. Stored
/// hashed (never plaintext) so reading this table back can never itself mint
/// a valid session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAdminUserRefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    /// Tenant the session backing this token was issued for (issue #232).
    /// `None` only on legacy rows minted before tenant stamping existed;
    /// consumers must treat such rows as unusable for session re-issue
    /// (reject and force a fresh login) rather than guessing a tenant.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Role the session backing this token was issued with (issue #232),
    /// recorded for audit; re-issue resolves the CURRENT membership role so
    /// demotions take effect on refresh. `None` on legacy rows.
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    #[serde(default)]
    pub revoked_at_unix: Option<i64>,
}

/// Durable per-tenant single-sign-on configuration for the admin console
/// (issue #283). Exactly one config per tenant, for EITHER an OIDC or a SAML
/// identity provider (`provider_kind`). Before this existed the auth service
/// kept OIDC config in process memory only (lost on restart, unmanageable per
/// tenant at runtime) and had no SAML.
///
/// Security note: an OIDC client secret is NEVER stored here in plaintext.
/// `oidc_client_secret_ref` holds a ferrogate-secrets reference URI
/// (`env://...` / `vault://...`) resolved at flow time, so a durable-storage
/// read can never itself leak the confidential client credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSsoProviderConfig {
    pub tenant_id: String,
    /// `"oidc"` or `"saml"`.
    pub provider_kind: String,
    pub default_role: String,
    /// IdP group/role name -> tenant role. Persisted as JSONB.
    #[serde(default)]
    pub group_role_mapping: std::collections::BTreeMap<String, String>,
    // --- OIDC ---
    #[serde(default)]
    pub oidc_issuer: Option<String>,
    #[serde(default)]
    pub oidc_client_id: Option<String>,
    /// ferrogate-secrets reference URI for the client secret; never plaintext.
    #[serde(default)]
    pub oidc_client_secret_ref: Option<String>,
    #[serde(default)]
    pub oidc_redirect_uri: Option<String>,
    #[serde(default)]
    pub oidc_group_claim: Option<String>,
    // --- SAML ---
    #[serde(default)]
    pub saml_idp_entity_id: Option<String>,
    #[serde(default)]
    pub saml_idp_sso_url: Option<String>,
    /// The IdP signing certificate, PEM or bare-base64 DER, used to verify the
    /// SAML response signature. Fail-closed if absent/unparseable.
    #[serde(default)]
    pub saml_idp_certificate: Option<String>,
    #[serde(default)]
    pub saml_sp_entity_id: Option<String>,
    #[serde(default)]
    pub saml_acs_url: Option<String>,
    #[serde(default)]
    pub saml_email_attribute: Option<String>,
    #[serde(default)]
    pub saml_name_attribute: Option<String>,
    #[serde(default)]
    pub saml_groups_attribute: Option<String>,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Restart-safe state for an in-flight SSO authorize->callback round trip
/// (issue #283), keyed by the opaque `state`/RelayState token. Consumed
/// (deleted) on first use; pruned once expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSsoPendingFlow {
    pub state: String,
    pub tenant_id: String,
    pub provider_kind: String,
    /// OIDC PKCE code_verifier (`None` for SAML).
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// SAML AuthnRequest ID echoed back as `InResponseTo` (`None` for OIDC).
    #[serde(default)]
    pub request_id: Option<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

/// A scope in the tenant -> project -> workspace -> key quota hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScopeKind {
    Tenant,
    Project,
    Workspace,
    Key,
}

impl QuotaScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            QuotaScopeKind::Tenant => "tenant",
            QuotaScopeKind::Project => "project",
            QuotaScopeKind::Workspace => "workspace",
            QuotaScopeKind::Key => "key",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "tenant" => Some(QuotaScopeKind::Tenant),
            "project" => Some(QuotaScopeKind::Project),
            "workspace" => Some(QuotaScopeKind::Workspace),
            "key" => Some(QuotaScopeKind::Key),
            _ => None,
        }
    }
}

/// Quota/rate-limit policy attached to one scope (tenant/project/workspace/
/// key). Resolution merges key -> workspace -> project -> tenant: the
/// nearest defined numeric value overrides, clamped to never exceed an
/// ancestor's cap; `model_allowlist` is the intersection of every scope in
/// the chain that defines a non-empty list. A missing policy at a scope
/// means that scope does not restrict; `enabled = false` at any scope in the
/// chain is a hard deny.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredQuotaPolicy {
    pub id: String,
    pub scope_type: QuotaScopeKind,
    pub scope_id: String,
    #[serde(default)]
    pub model_allowlist: Vec<String>,
    #[serde(default)]
    pub rpm_limit: Option<u64>,
    #[serde(default)]
    pub tpm_limit: Option<u64>,
    #[serde(default)]
    pub monthly_budget_usd: Option<f64>,
    /// Tenant-only override of `StoredPlan.default_asset_storage_quota_bytes`.
    /// Assets and their cumulative usage are tenant-owned; narrower scopes do
    /// not have independent asset ownership or usage counters. `None` means
    /// "no override, fall back to the plan default".
    #[serde(default)]
    pub asset_storage_quota_bytes: Option<u64>,
    /// Percent-of-`monthly_budget_usd` tiers (e.g. `[75, 90, 95]`) that fire
    /// a one-time webhook notification each, strictly before the 100% hard
    /// deny in `AppState::monthly_budget_exceeded` (issue #170). Empty
    /// means no proactive alerting -- unaffected existing policies keep
    /// today's "allowed, then a hard 429 at 100%" behavior.
    #[serde(default)]
    pub alert_threshold_pcts: Vec<u8>,
    #[serde(default = "default_true_bool")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
    /// #262 (egress governance): monthly egress/download-bandwidth byte budget
    /// for this scope. Merged `min`-across-the-chain exactly like `rpm_limit`
    /// / `monthly_budget_usd` by `resolve_effective_quota`; `None` means no
    /// egress cap defined at this scope.
    #[serde(default)]
    pub monthly_egress_bytes_budget: Option<u64>,
    /// #262 (egress governance): per-minute asset-download request cap for this
    /// scope, the download-side analogue of `rpm_limit`. `None` means no
    /// download-RPM cap defined at this scope.
    #[serde(default)]
    pub download_rpm_limit: Option<u64>,
}

fn default_true_bool() -> bool {
    true
}

/// Deterministic id for a quota policy so `upsert` is naturally idempotent
/// per `(scope_type, scope_id)` without a separate lookup-then-insert step.
pub fn quota_policy_id(scope_type: QuotaScopeKind, scope_id: &str) -> String {
    format!("{}:{}", scope_type.as_str(), scope_id)
}

pub fn validate_quota_policy(policy: &StoredQuotaPolicy) -> Result<(), StorageError> {
    if policy.scope_type != QuotaScopeKind::Tenant && policy.asset_storage_quota_bytes.is_some() {
        return Err(StorageError::Runtime(
            "asset_storage_quota_bytes is tenant-only because stored assets and usage are tenant-owned"
                .into(),
        ));
    }
    Ok(())
}

/// Per-scope, per-calendar-month usage/cost rollup (P1-4). `scope_type`
/// reuses the same tenant/project/workspace/key hierarchy `quota_policies`
/// (P1-3) uses, so a single resolved `TenantContext` fans out into up to
/// four of these rows (one per non-empty scope level) on every settled
/// request. This is the read side of "current month cumulative cost for
/// scope X" for monthly budget enforcement, and the source for the
/// usage/cost report API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredUsageMonthlyRollup {
    pub id: String,
    /// Calendar month in `YYYY-MM` form, UTC.
    pub period_month: String,
    pub scope_type: QuotaScopeKind,
    pub scope_id: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub request_count: u64,
    pub error_count: u64,
    pub updated_at_unix: i64,
}

/// Deterministic id for a monthly rollup row, mirroring [`quota_policy_id`].
pub fn usage_monthly_rollup_id(
    period_month: &str,
    scope_type: QuotaScopeKind,
    scope_id: &str,
) -> String {
    format!("{period_month}:{}:{scope_id}", scope_type.as_str())
}

/// Converts a unix timestamp (seconds) to a `YYYY-MM` calendar month string,
/// UTC. Dependency-free implementation of Howard Hinnant's `civil_from_days`
/// (<http://howardhinnant.github.io/date_algorithms.html>), since no
/// date/calendar crate is a direct dependency of this workspace.
pub fn period_month_from_unix(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let (year, month, _day) = civil_from_days(days);
    format!("{year:04}-{month:02}")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
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
    /// #307 handoff parent identity: the `canonical_target_sha256` fingerprint
    /// (`"sha256:<hex>"`) of the UPSTREAM governed action this request is a
    /// downstream effect of (e.g. an A2A exchange declaring
    /// `x-ferrogate-parent-action-fingerprint`). Persisted inside the
    /// `request_logs.request_json` document the read paths deserialize — no
    /// projection column needed. `None` when no parent was declared — never
    /// fabricated; `skip_serializing_if` keeps legacy documents byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_action_fingerprint: Option<String>,
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
    /// #304 action-identity columns (all optional; NULL on rows recorded
    /// before migration 045 or by paths without capability evidence). See
    /// [`StoredAgentRunEvent`] for the value contracts. The free-text
    /// `outcome`/`message` stay unchanged for humans; these are additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_disposition: Option<String>,
    /// #307 handoff parent identity: the fingerprint of the UPSTREAM governed
    /// action this audited event is a downstream effect of (declared-parent
    /// A2A exchanges stamp it on their guardrail/policy audit rows). NOT
    /// `action_fingerprint` (this event's own identity). Persisted inside the
    /// `audit_events.audit_json` document; `None` when no parent was declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_action_fingerprint: Option<String>,
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

impl ManagedWorkerTemplateRepository for InMemoryRepository<StoredManagedWorkerTemplate> {}

impl AgentWorkerInstanceRepository for InMemoryRepository<StoredAgentWorkerInstance> {}

impl ManagedWorkerSessionRepository for InMemoryRepository<StoredManagedWorkerSession> {}

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

    /// Retain only the records for which `keep` returns `true`, dropping the
    /// rest. Returns the number of records removed. Used by the compliance
    /// retention sweeper (#284) to prune request_logs / audit_events on the
    /// in-memory backend, mirroring the Postgres batched delete.
    pub fn retain<F>(&mut self, keep: F) -> usize
    where
        F: FnMut(&T) -> bool,
    {
        let before = self.records.len();
        self.records.retain(keep);
        before.saturating_sub(self.records.len())
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

/// Bounded in-memory store for `agent_run_events` (issue #231).
///
/// Chosen bound semantics: `agent_run_events` feed admin run timelines, so a
/// plain FIFO retention cap (the heartbeat/telemetry pattern) would let one
/// flooding run silently truncate every other -- possibly still ACTIVE --
/// run's timeline. Instead:
///
/// - **Per-run cap** (`per_run_limit`): each run keeps at most its own most
///   recent `per_run_limit` events; a run can only ever truncate itself.
/// - **Global cap** (`global_limit`, a generous multiple of the per-run cap):
///   when the whole store overflows, events are evicted oldest-first from the
///   LEAST-recently-appended-to run, and never from the run whose event is
///   currently being appended. An active run's retained window can therefore
///   only shrink under global pressure from many distinct idle runs -- a
///   single other run's flood is itself per-run capped and cannot evict it.
///
/// A limit of `0` disables the corresponding cap (the migration tooling
/// constructs repositories with retention `0`, meaning "unbounded").
#[derive(Debug, Default)]
pub struct InMemoryAgentRunEventRepository {
    records: VecDeque<StoredAgentRunEvent>,
    /// Count of retained events per run id.
    run_counts: HashMap<String, usize>,
    /// Run ids ordered by last append (front = least recently appended-to).
    run_recency: VecDeque<String>,
    per_run_limit: usize,
    global_limit: usize,
}

impl InMemoryAgentRunEventRepository {
    pub fn new() -> Self {
        Self::with_limits(0, 0)
    }

    pub fn with_limits(per_run_limit: usize, global_limit: usize) -> Self {
        Self {
            records: VecDeque::new(),
            run_counts: HashMap::new(),
            run_recency: VecDeque::new(),
            per_run_limit,
            global_limit,
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn remove_oldest_event_of_run(&mut self, run_id: &str) {
        let Some(position) = self.records.iter().position(|event| event.run_id == run_id) else {
            return;
        };
        self.records.remove(position);
        match self.run_counts.get_mut(run_id) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                self.run_counts.remove(run_id);
                self.run_recency.retain(|id| id != run_id);
            }
        }
    }

    fn touch_run_recency(&mut self, run_id: &str) {
        self.run_recency.retain(|id| id != run_id);
        self.run_recency.push_back(run_id.to_string());
    }
}

impl AppendRepository<StoredAgentRunEvent> for InMemoryAgentRunEventRepository {
    fn append(&mut self, record: StoredAgentRunEvent) {
        let run_id = record.run_id.clone();
        self.records.push_back(record);
        *self.run_counts.entry(run_id.clone()).or_insert(0) += 1;
        self.touch_run_recency(&run_id);
        if self.per_run_limit > 0 {
            while self.run_counts.get(&run_id).copied().unwrap_or_default() > self.per_run_limit {
                self.remove_oldest_event_of_run(&run_id.clone());
            }
        }
        if self.global_limit > 0 {
            while self.records.len() > self.global_limit {
                // Evict from the least-recently-appended-to run that is not
                // the run currently being appended (see type-level doc).
                let Some(victim_run) = self
                    .run_recency
                    .iter()
                    .find(|id| id.as_str() != run_id)
                    .cloned()
                else {
                    // Only the appending run remains; the per-run cap (<=
                    // global cap in practice) is the sole remaining bound.
                    break;
                };
                self.remove_oldest_event_of_run(&victim_run);
            }
        }
    }

    fn list(&self) -> Vec<StoredAgentRunEvent> {
        self.records.iter().cloned().collect()
    }
}

impl AgentRunEventRepository for InMemoryAgentRunEventRepository {}

/// A record that is durably owned by exactly one self-hosted worker.
pub trait WorkerOwnedRecord {
    fn owning_worker_id(&self) -> &str;
}

impl WorkerOwnedRecord for StoredSelfHostedWorkerArtifact {
    fn owning_worker_id(&self) -> &str {
        &self.worker_id
    }
}

impl WorkerOwnedRecord for StoredSelfHostedWorkerCheckpoint {
    fn owning_worker_id(&self) -> &str {
        &self.worker_id
    }
}

/// Keyed in-memory store with a per-worker DISTINCT-id cap (issue #231).
///
/// The artifact/checkpoint endpoints let an authenticated but customer-hosted
/// worker create unbounded distinct ids for its own rows, so an uncapped
/// keyed store is a worker-driven memory-DoS vector. This mirrors the
/// heartbeat/telemetry `with_retention_limit` pattern but scoped PER WORKER:
/// when a worker exceeds `per_worker_limit` distinct ids, that worker's
/// oldest-inserted id is evicted. One worker's flood can never evict another
/// worker's records. Updating an existing id does not count as a new distinct
/// id and does not evict. A limit of `0` disables the cap (migration tooling
/// constructs repositories with retention `0`).
#[derive(Debug, Default)]
pub struct InMemoryWorkerScopedRepository<T> {
    records: HashMap<String, T>,
    /// Per worker: distinct record ids in insertion order (front = oldest).
    per_worker_ids: HashMap<String, VecDeque<String>>,
    per_worker_limit: usize,
}

impl<T: WorkerOwnedRecord> InMemoryWorkerScopedRepository<T> {
    pub fn new() -> Self {
        Self::with_per_worker_limit(0)
    }

    pub fn with_per_worker_limit(per_worker_limit: usize) -> Self {
        Self {
            records: HashMap::new(),
            per_worker_ids: HashMap::new(),
            per_worker_limit,
        }
    }

    pub fn insert(&mut self, id: impl Into<String>, record: T) {
        let id = id.into();
        let worker_id = record.owning_worker_id().to_string();
        if let Some(existing) = self.records.get(&id) {
            let previous_worker = existing.owning_worker_id().to_string();
            if previous_worker != worker_id {
                // Ownership moves are rejected upstream (#228); handle them
                // anyway so the per-worker index never dangles.
                if let Some(ids) = self.per_worker_ids.get_mut(&previous_worker) {
                    ids.retain(|existing_id| existing_id != &id);
                    if ids.is_empty() {
                        self.per_worker_ids.remove(&previous_worker);
                    }
                }
                self.track_new_id_for_worker(&worker_id, &id);
            }
            self.records.insert(id, record);
            return;
        }
        self.records.insert(id.clone(), record);
        self.track_new_id_for_worker(&worker_id, &id);
    }

    fn track_new_id_for_worker(&mut self, worker_id: &str, id: &str) {
        let ids = self
            .per_worker_ids
            .entry(worker_id.to_string())
            .or_default();
        ids.push_back(id.to_string());
        if self.per_worker_limit > 0 {
            while ids.len() > self.per_worker_limit {
                if let Some(evicted) = ids.pop_front() {
                    self.records.remove(&evicted);
                }
            }
        }
    }

    pub fn remove(&mut self, id: &str) -> Option<T> {
        let removed = self.records.remove(id)?;
        let worker_id = removed.owning_worker_id().to_string();
        if let Some(ids) = self.per_worker_ids.get_mut(&worker_id) {
            ids.retain(|existing_id| existing_id != id);
            if ids.is_empty() {
                self.per_worker_ids.remove(&worker_id);
            }
        }
        Some(removed)
    }
}

impl<T: Clone + WorkerOwnedRecord> Repository<T> for InMemoryWorkerScopedRepository<T> {
    fn get(&self, id: &str) -> Option<T> {
        self.records.get(id).cloned()
    }

    fn list(&self) -> Vec<T> {
        self.records.values().cloned().collect()
    }
}

impl SelfHostedWorkerArtifactRepository
    for InMemoryWorkerScopedRepository<StoredSelfHostedWorkerArtifact>
{
}

impl SelfHostedWorkerCheckpointRepository
    for InMemoryWorkerScopedRepository<StoredSelfHostedWorkerCheckpoint>
{
}

impl RequestLogRepository for InMemoryAppendRepository<StoredRequestLog> {}

impl AuditLogRepository for InMemoryAppendRepository<StoredAuditEvent> {}

impl BillingEventRepository for InMemoryAppendRepository<BillingEvent> {}

impl AgentRunEventRepository for InMemoryAppendRepository<StoredAgentRunEvent> {}

impl ManagedWorkerLifecycleEventRepository
    for InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>
{
}

impl SelfHostedWorkerRegistrationRepository
    for InMemoryRepository<StoredSelfHostedWorkerRegistration>
{
}

impl SelfHostedWorkerHeartbeatRepository
    for InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>
{
}

impl SelfHostedWorkerTelemetryEventRepository
    for InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>
{
}

impl SelfHostedWorkerArtifactRepository for InMemoryRepository<StoredSelfHostedWorkerArtifact> {}

impl SelfHostedWorkerCheckpointRepository for InMemoryRepository<StoredSelfHostedWorkerCheckpoint> {}

impl SelfHostedRunDispatchRepository for InMemoryRepository<StoredSelfHostedRunDispatch> {}

#[derive(Debug)]
pub struct RuntimeStorageRepositories {
    backend: RuntimeStorageBackend,
    control_plane: RuntimeControlPlaneBackend,
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    guardrail_evidence: Mutex<InMemoryAppendRepository<StoredGuardrailEvidence>>,
    guardrail_evaluation_retention_records: Mutex<usize>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    agent_run_events: Mutex<InMemoryAgentRunEventRepository>,
    managed_worker_templates: Mutex<InMemoryRepository<StoredManagedWorkerTemplate>>,
    agent_worker_instances: Mutex<InMemoryRepository<StoredAgentWorkerInstance>>,
    managed_worker_sessions: Mutex<InMemoryRepository<StoredManagedWorkerSession>>,
    managed_worker_lifecycle_events:
        Mutex<InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>>,
    managed_worker_isolation_selections:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationSelection>>,
    managed_worker_isolation_policies:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationPolicy>>,
    managed_worker_isolation_evidence:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationEvidence>>,
    self_hosted_worker_registrations: Mutex<InMemoryRepository<StoredSelfHostedWorkerRegistration>>,
    self_hosted_worker_heartbeats: Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>>,
    self_hosted_worker_telemetry_events:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>>,
    self_hosted_worker_artifacts:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerArtifact>>,
    self_hosted_worker_checkpoints:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerCheckpoint>>,
    self_hosted_run_dispatches: Mutex<InMemoryRepository<StoredSelfHostedRunDispatch>>,
    /// Per-scope retention applied to the DURABLE (Postgres) worker/agent-run
    /// stores by opportunistic prune-on-write (issue #231). `0` disables
    /// durable pruning (the migration tooling constructs repositories with
    /// retention `0` and must never prune imported rows).
    durable_worker_retention_records: usize,
    heartbeat_prune_ticks: AtomicU64,
    telemetry_prune_ticks: AtomicU64,
    artifact_prune_ticks: AtomicU64,
    checkpoint_prune_ticks: AtomicU64,
    agent_run_event_prune_ticks: AtomicU64,
}

struct RuntimeStorageRepositorySets {
    request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    guardrail_evidence: Mutex<InMemoryAppendRepository<StoredGuardrailEvidence>>,
    usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    agent_run_events: Mutex<InMemoryAgentRunEventRepository>,
    managed_worker_templates: Mutex<InMemoryRepository<StoredManagedWorkerTemplate>>,
    agent_worker_instances: Mutex<InMemoryRepository<StoredAgentWorkerInstance>>,
    managed_worker_sessions: Mutex<InMemoryRepository<StoredManagedWorkerSession>>,
    managed_worker_lifecycle_events:
        Mutex<InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>>,
    managed_worker_isolation_selections:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationSelection>>,
    managed_worker_isolation_policies:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationPolicy>>,
    managed_worker_isolation_evidence:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationEvidence>>,
    self_hosted_worker_registrations: Mutex<InMemoryRepository<StoredSelfHostedWorkerRegistration>>,
    self_hosted_worker_heartbeats: Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>>,
    self_hosted_worker_telemetry_events:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>>,
    self_hosted_worker_artifacts:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerArtifact>>,
    self_hosted_worker_checkpoints:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerCheckpoint>>,
    self_hosted_run_dispatches: Mutex<InMemoryRepository<StoredSelfHostedRunDispatch>>,
}

impl RuntimeStorageRepositorySets {
    fn new(request_log_retention_records: usize, audit_event_retention_records: usize) -> Self {
        Self {
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            guardrail_evidence: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            // Bounded (issue #231): agent-run events previously grew without
            // limit. Per-run cap = the audit retention bound; global cap = a
            // generous multiple, evicting idle runs' events first so an
            // ACTIVE run's timeline is never truncated by another run's
            // flood. See `InMemoryAgentRunEventRepository` for the exact
            // semantics.
            agent_run_events: Mutex::new(InMemoryAgentRunEventRepository::with_limits(
                audit_event_retention_records,
                audit_event_retention_records
                    .saturating_mul(AGENT_RUN_EVENT_GLOBAL_RETENTION_MULTIPLIER),
            )),
            managed_worker_templates: Mutex::new(InMemoryRepository::new()),
            agent_worker_instances: Mutex::new(InMemoryRepository::new()),
            managed_worker_sessions: Mutex::new(InMemoryRepository::new()),
            managed_worker_lifecycle_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_isolation_selections: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_policies: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_evidence: Mutex::new(InMemoryRepository::new()),
            self_hosted_worker_registrations: Mutex::new(InMemoryRepository::new()),
            // Bounded like the other append-only analytics stores: heartbeats
            // and telemetry are ingested from UNTRUSTED, customer-hosted
            // self-hosted workers over an endpoint that performs no per-worker
            // count/rate cap, so an uncapped store is a memory/DoS vector (and
            // every write clones the whole store). Reuse the audit retention
            // bound so the oldest records are evicted instead of growing without
            // limit.
            self_hosted_worker_heartbeats: Mutex::new(
                InMemoryAppendRepository::with_retention_limit(audit_event_retention_records),
            ),
            self_hosted_worker_telemetry_events: Mutex::new(
                InMemoryAppendRepository::with_retention_limit(audit_event_retention_records),
            ),
            // Bounded (issue #231): a worker can create unbounded DISTINCT
            // artifact/checkpoint ids for its own rows, so the keyed stores
            // get a per-worker distinct-id cap with oldest-eviction. See
            // `InMemoryWorkerScopedRepository` for the exact semantics.
            self_hosted_worker_artifacts: Mutex::new(
                InMemoryWorkerScopedRepository::with_per_worker_limit(
                    audit_event_retention_records,
                ),
            ),
            self_hosted_worker_checkpoints: Mutex::new(
                InMemoryWorkerScopedRepository::with_per_worker_limit(
                    audit_event_retention_records,
                ),
            ),
            self_hosted_run_dispatches: Mutex::new(InMemoryRepository::new()),
        }
    }
}

impl RuntimeStorageRepositories {
    pub fn new(
        backend: RuntimeStorageBackend,
        control_plane: RuntimeControlPlaneState,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        let repositories = RuntimeStorageRepositorySets::new(
            request_log_retention_records,
            audit_event_retention_records,
        );
        Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Memory(Box::new(Mutex::new(control_plane))),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            guardrail_evidence: repositories.guardrail_evidence,
            guardrail_evaluation_retention_records: Mutex::new(audit_event_retention_records),
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
            durable_worker_retention_records: audit_event_retention_records,
            heartbeat_prune_ticks: AtomicU64::new(0),
            telemetry_prune_ticks: AtomicU64::new(0),
            artifact_prune_ticks: AtomicU64::new(0),
            checkpoint_prune_ticks: AtomicU64::new(0),
            agent_run_event_prune_ticks: AtomicU64::new(0),
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

    pub fn postgres(
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        Self::postgres_with_provider(StorageProviderKind::Postgres, config, options)
    }

    pub fn supabase(
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        Self::postgres_with_provider(StorageProviderKind::Supabase, config, options)
    }

    fn postgres_with_provider(
        provider: StorageProviderKind,
        config: PostgresStorageConfig,
        options: RuntimeStorageOptions,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            provider,
            options.required,
            options.provider_order,
            options.migration_mode,
        )?;
        let request_log_retention_records = options.request_log_retention_records;
        let audit_event_retention_records = options.audit_event_retention_records;
        let bootstrap = options.control_plane;
        let initialize_schema = options.initialize_schema;
        let control_plane = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    PostgresControlPlaneStore::connect(config, bootstrap, initialize_schema)
                })
                .join()
                .map_err(|_| {
                    StorageError::Postgres("postgres storage connect thread panicked".into())
                })?
        })?;
        let repositories = RuntimeStorageRepositorySets::new(
            request_log_retention_records,
            audit_event_retention_records,
        );
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            guardrail_evidence: repositories.guardrail_evidence,
            guardrail_evaluation_retention_records: Mutex::new(audit_event_retention_records),
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
            durable_worker_retention_records: audit_event_retention_records,
            heartbeat_prune_ticks: AtomicU64::new(0),
            telemetry_prune_ticks: AtomicU64::new(0),
            artifact_prune_ticks: AtomicU64::new(0),
            checkpoint_prune_ticks: AtomicU64::new(0),
            agent_run_event_prune_ticks: AtomicU64::new(0),
        })
    }

    pub fn supabase_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        Self::postgres_wire_for_migration(
            StorageProviderKind::Supabase,
            config,
            initialize_schema,
            validate_schema,
        )
    }

    pub fn postgres_for_migration(
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        Self::postgres_wire_for_migration(
            StorageProviderKind::Postgres,
            config,
            initialize_schema,
            validate_schema,
        )
    }

    fn postgres_wire_for_migration(
        provider: StorageProviderKind,
        config: PostgresStorageConfig,
        initialize_schema: bool,
        validate_schema: bool,
    ) -> Result<Self, StorageError> {
        let backend = RuntimeStorageBackend::new_with_migration_mode(
            provider,
            true,
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            if initialize_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
        )?;
        let control_plane = PostgresControlPlaneStore::connect_for_migration(
            config,
            initialize_schema,
            validate_schema,
        )?;
        let repositories = RuntimeStorageRepositorySets::new(0, 0);
        Ok(Self {
            backend,
            control_plane: RuntimeControlPlaneBackend::Postgres(Arc::new(control_plane)),
            request_logs: repositories.request_logs,
            audit_events: repositories.audit_events,
            guardrail_evidence: repositories.guardrail_evidence,
            guardrail_evaluation_retention_records: Mutex::new(0),
            usage_aggregates: repositories.usage_aggregates,
            agent_runs: repositories.agent_runs,
            agent_run_events: repositories.agent_run_events,
            managed_worker_templates: repositories.managed_worker_templates,
            agent_worker_instances: repositories.agent_worker_instances,
            managed_worker_sessions: repositories.managed_worker_sessions,
            managed_worker_lifecycle_events: repositories.managed_worker_lifecycle_events,
            managed_worker_isolation_selections: repositories.managed_worker_isolation_selections,
            managed_worker_isolation_policies: repositories.managed_worker_isolation_policies,
            managed_worker_isolation_evidence: repositories.managed_worker_isolation_evidence,
            self_hosted_worker_registrations: repositories.self_hosted_worker_registrations,
            self_hosted_worker_heartbeats: repositories.self_hosted_worker_heartbeats,
            self_hosted_worker_telemetry_events: repositories.self_hosted_worker_telemetry_events,
            self_hosted_worker_artifacts: repositories.self_hosted_worker_artifacts,
            self_hosted_worker_checkpoints: repositories.self_hosted_worker_checkpoints,
            self_hosted_run_dispatches: repositories.self_hosted_run_dispatches,
            // Migration tooling: retention 0 = durable pruning disabled, so a
            // batch import can never prune rows it just wrote.
            durable_worker_retention_records: 0,
            heartbeat_prune_ticks: AtomicU64::new(0),
            telemetry_prune_ticks: AtomicU64::new(0),
            artifact_prune_ticks: AtomicU64::new(0),
            checkpoint_prune_ticks: AtomicU64::new(0),
            agent_run_event_prune_ticks: AtomicU64::new(0),
        })
    }

    pub fn backend_evidence(&self) -> StorageBackendEvidence {
        let mut evidence = self.backend.evidence();
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            evidence.schema = Some(control_plane.schema_evidence());
        }
        evidence
    }

    pub fn postgres_pool_metrics_snapshot(&self) -> PostgresPoolMetricsSnapshot {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => PostgresPoolMetricsSnapshot::default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.async_pool.metrics_snapshot()
            }
        }
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
                    agent_upstreams: Vec::new(),
                })),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.snapshot())
            }
        }
    }

    pub fn replace_control_plane(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.replace_config_documents(documents);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.replace_kind("api_key", documents.api_keys))?;
                block_on_sync_bridge(control_plane.replace_kind("tenant", documents.tenants))?;
                block_on_sync_bridge(control_plane.replace_kind("policy", documents.policies))?;
                block_on_sync_bridge(
                    control_plane.replace_kind("gateway_config", documents.gateway_configs),
                )?;
                block_on_sync_bridge(
                    control_plane.replace_kind("agent_workflow", documents.agent_workflows),
                )?;
                block_on_sync_bridge(
                    control_plane.replace_kind("skill_package", documents.skill_packages),
                )?;
                block_on_sync_bridge(
                    control_plane.replace_kind("prompt_template", documents.prompt_templates),
                )?;
                block_on_sync_bridge(
                    control_plane
                        .replace_kind("plugin_registration", documents.plugin_registrations),
                )?;
                block_on_sync_bridge(
                    control_plane.replace_kind("mcp_server", documents.mcp_servers),
                )?;
                block_on_sync_bridge(
                    control_plane.replace_kind("agent_upstream", documents.agent_upstreams),
                )?;
                Ok(())
            }
        }
    }

    pub fn export_migration_snapshot(&self) -> Result<StorageMigrationSnapshot, StorageError> {
        let control_plane = match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.documents())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.documents())?
            }
        };
        // Sync CLI migration tool with no tokio runtime in its call chain. Every
        // async read is bridged through `block_on_sync_bridge`, which drives them
        // all on ONE process-wide shared runtime -- so the pooled Postgres
        // connection stays alive across all ~30 reads instead of being abandoned
        // at a per-call runtime boundary (the export-path stall fixed in #248).
        Ok(StorageMigrationSnapshot {
            control_plane,
            guardrail_policy_revisions: self.list_guardrail_policy_revisions(None)?,
            guardrail_policy_bindings: self.list_guardrail_policy_bindings()?,
            api_key_records: block_on_sync_bridge(self.list_api_key_records())?,
            tool_approvals: self.control_plane_tool_approval_documents()?,
            billing_events: block_on_sync_bridge(self.billing_events()),
            usage_aggregates: block_on_sync_bridge(self.usage_aggregates()),
            request_logs: block_on_sync_bridge(self.request_logs()),
            audit_events: block_on_sync_bridge(self.audit_events()),
            agent_runs: block_on_sync_bridge(self.agent_runs()),
            agent_run_events: block_on_sync_bridge(self.agent_run_events()),
            managed_worker_templates: block_on_sync_bridge(self.managed_worker_templates()),
            agent_worker_instances: block_on_sync_bridge(self.agent_worker_instances()),
            managed_worker_sessions: block_on_sync_bridge(self.managed_worker_sessions()),
            managed_worker_lifecycle_events: block_on_sync_bridge(
                self.managed_worker_lifecycle_events(),
            ),
            managed_worker_isolation_selections: block_on_sync_bridge(
                self.managed_worker_isolation_selections(),
            ),
            managed_worker_isolation_policies: block_on_sync_bridge(
                self.managed_worker_isolation_policies(),
            ),
            managed_worker_isolation_evidence: block_on_sync_bridge(
                self.managed_worker_isolation_evidence(),
            ),
            self_hosted_worker_registrations: block_on_sync_bridge(
                self.self_hosted_worker_registrations(),
            ),
            self_hosted_worker_heartbeats: block_on_sync_bridge(
                self.self_hosted_worker_heartbeats(),
            ),
            self_hosted_worker_telemetry_events: block_on_sync_bridge(
                self.self_hosted_worker_telemetry_events(),
            ),
            self_hosted_worker_artifacts: block_on_sync_bridge(self.self_hosted_worker_artifacts()),
            self_hosted_worker_checkpoints: block_on_sync_bridge(
                self.self_hosted_worker_checkpoints(),
            ),
            self_hosted_run_dispatches: block_on_sync_bridge(self.self_hosted_run_dispatches()),
        })
    }

    pub fn import_migration_snapshot(
        &self,
        snapshot: StorageMigrationSnapshot,
    ) -> Result<(), StorageError> {
        // One-shot CLI migration tool (`ferrogate storage migrate-to-supabase`),
        // called from a plain sync `main()` with no tokio runtime in its call
        // chain. Every async write is bridged through `block_on_sync_bridge`,
        // which drives them all on ONE process-wide shared runtime -- keeping the
        // pooled Postgres connection alive across the whole import instead of
        // abandoning it at a per-call runtime boundary (matching the export path,
        // and mixing cleanly with the `block_on_sync_bridge` control-plane and
        // guardrail writes below rather than straddling two runtimes) (#248).
        self.replace_control_plane(snapshot.control_plane)?;
        for revision in snapshot.guardrail_policy_revisions {
            match self.insert_guardrail_policy_revision(revision) {
                Ok(()) | Err(StorageError::Conflict(_)) => {}
                Err(error) => return Err(error),
            }
        }
        for binding in snapshot.guardrail_policy_bindings {
            let policy_id = binding.policy_id.clone();
            let expected_generation = self
                .get_guardrail_policy_binding(&policy_id)?
                .map(|binding| binding.generation);
            self.restore_guardrail_policy_binding(&policy_id, expected_generation, Some(binding))?;
        }
        for api_key in snapshot.api_key_records {
            block_on_sync_bridge(self.upsert_api_key_record(api_key))?;
        }
        for (id, document_json) in snapshot.tool_approvals {
            self.upsert_control_plane_tool_approval(id, document_json)?;
        }
        for event in snapshot.billing_events {
            block_on_sync_bridge(self.append_billing_event(event))?;
        }
        for aggregate in snapshot.usage_aggregates {
            block_on_sync_bridge(self.replace_usage_aggregate(aggregate))?;
        }
        for log in snapshot.request_logs {
            block_on_sync_bridge(self.append_request_log(log));
        }
        for event in snapshot.audit_events {
            block_on_sync_bridge(self.append_audit_event(event));
        }
        for run in snapshot.agent_runs {
            block_on_sync_bridge(self.upsert_agent_run(run))?;
        }
        for event in snapshot.agent_run_events {
            block_on_sync_bridge(self.append_agent_run_event(event))?;
        }
        for template in snapshot.managed_worker_templates {
            block_on_sync_bridge(self.upsert_managed_worker_template(template))?;
        }
        for instance in snapshot.agent_worker_instances {
            block_on_sync_bridge(self.upsert_agent_worker_instance(instance))?;
        }
        for session in snapshot.managed_worker_sessions {
            block_on_sync_bridge(self.upsert_managed_worker_session(session))?;
        }
        for event in snapshot.managed_worker_lifecycle_events {
            block_on_sync_bridge(self.append_managed_worker_lifecycle_event(event))?;
        }
        for selection in snapshot.managed_worker_isolation_selections {
            block_on_sync_bridge(self.upsert_managed_worker_isolation_selection(selection))?;
        }
        for policy in snapshot.managed_worker_isolation_policies {
            block_on_sync_bridge(self.upsert_managed_worker_isolation_policy(policy))?;
        }
        for evidence in snapshot.managed_worker_isolation_evidence {
            block_on_sync_bridge(self.upsert_managed_worker_isolation_evidence(evidence))?;
        }
        for registration in snapshot.self_hosted_worker_registrations {
            block_on_sync_bridge(self.upsert_self_hosted_worker_registration(registration))?;
        }
        for heartbeat in snapshot.self_hosted_worker_heartbeats {
            block_on_sync_bridge(self.append_self_hosted_worker_heartbeat(heartbeat))?;
        }
        for event in snapshot.self_hosted_worker_telemetry_events {
            block_on_sync_bridge(self.append_self_hosted_worker_telemetry_event(event))?;
        }
        for artifact in snapshot.self_hosted_worker_artifacts {
            block_on_sync_bridge(self.upsert_self_hosted_worker_artifact(artifact))?;
        }
        for checkpoint in snapshot.self_hosted_worker_checkpoints {
            block_on_sync_bridge(self.upsert_self_hosted_worker_checkpoint(checkpoint))?;
        }
        for dispatch in snapshot.self_hosted_run_dispatches {
            block_on_sync_bridge(self.upsert_self_hosted_run_dispatch(dispatch))?;
        }
        Ok(())
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.upsert("api_key", id.into(), document_json))
            }
        }
    }

    pub fn delete_control_plane_api_key(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_api_key(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("api_key", id.to_string()))
            }
        }
    }

    // --- Durable virtual API keys bound to workspaces ---

    pub async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_api_key_record(api_key);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_api_key_record(&api_key).await
            }
        }
    }

    pub async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_api_key_record(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_api_key_record(id).await
            }
        }
    }

    pub async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_api_key_records())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_api_key_records().await
            }
        }
    }

    pub async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.find_api_key_records_by_prefix(key_prefix))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .find_api_key_records_by_prefix(key_prefix)
                    .await
            }
        }
    }

    // --- Multi-tenant hierarchy: Tenant -> Project -> Workspace ---

    pub async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_admin_user(user);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_admin_user(&user).await
            }
        }
    }

    pub async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_admin_user_by_id(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_admin_user_by_id(id).await
            }
        }
    }

    pub async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_admin_user_by_email(email))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_admin_user_by_email(email).await
            }
        }
    }

    pub async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_admin_user_membership(membership);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_admin_user_membership(&membership)
                    .await
            }
        }
    }

    pub async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_admin_user_memberships_by_user(user_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_admin_user_memberships_by_user(user_id)
                    .await
            }
        }
    }

    /// Lists every teammate membership for a tenant (issue #162), used by the
    /// admin console's team-management view.
    pub async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_admin_user_memberships_by_tenant(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_admin_user_memberships_by_tenant(tenant_id)
                    .await
            }
        }
    }

    /// Revokes a teammate's membership in a tenant (issue #162). Returns
    /// `true` if a membership existed and was removed.
    pub async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.delete_admin_user_membership(user_id, tenant_id)
                })
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .delete_admin_user_membership(user_id, tenant_id)
                    .await
            }
        }
    }

    /// Persists (creates or replaces) the per-tenant SSO configuration (#283).
    pub async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_sso_provider_config(config);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_sso_provider_config(&config).await
            }
        }
    }

    /// Reads the per-tenant SSO configuration, if any (#283).
    pub async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_sso_provider_config(tenant_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_sso_provider_config(tenant_id).await
            }
        }
    }

    /// Removes the per-tenant SSO configuration (#283). Returns `true` if one
    /// existed.
    pub async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_sso_provider_config(tenant_id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_sso_provider_config(tenant_id).await
            }
        }
    }

    /// Records an in-flight SSO authorize->callback flow (#283).
    pub async fn insert_sso_pending_flow(
        &self,
        flow: StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.insert_sso_pending_flow(flow);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.insert_sso_pending_flow(&flow).await
            }
        }
    }

    /// Consumes (removes and returns) a pending SSO flow by its `state` token,
    /// returning `None` if it is unknown or already expired (#283).
    pub async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.take_sso_pending_flow(state, now_unix))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.take_sso_pending_flow(state, now_unix).await
            }
        }
    }

    pub async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_admin_user_refresh_token(token);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_admin_user_refresh_token(&token).await
            }
        }
    }

    pub async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_admin_user_refresh_token_by_hash(token_hash))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .get_admin_user_refresh_token_by_hash(token_hash)
                    .await
            }
        }
    }

    /// Revokes every live refresh token for a user (issue #161), so a SCIM
    /// or admin-console deactivation terminates existing browser sessions
    /// immediately rather than merely blocking future logins.
    pub async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.revoke_all_admin_user_refresh_tokens(user_id, revoked_at_unix)
                })
                .unwrap_or(0)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .revoke_all_admin_user_refresh_tokens(user_id, revoked_at_unix)
                    .await
            }
        }
    }

    /// Revokes only the refresh tokens a user holds for one tenant (issue
    /// #232), backing tenant-scoped SCIM deprovisioning: the user's live
    /// sessions in every other tenant keep working.
    pub async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.revoke_admin_user_refresh_tokens_for_tenant(
                        user_id,
                        tenant_id,
                        revoked_at_unix,
                    )
                })
                .unwrap_or(0)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .revoke_admin_user_refresh_tokens_for_tenant(
                        user_id,
                        tenant_id,
                        revoked_at_unix,
                    )
                    .await
            }
        }
    }

    pub async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_tenant_account(account);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_tenant_account(&account).await
            }
        }
    }

    pub async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_tenant_account(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_tenant_account(id).await
            }
        }
    }

    pub async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_tenant_accounts())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_tenant_accounts().await
            }
        }
    }

    pub async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_project(project);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_project(&project).await
            }
        }
    }

    pub async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_project(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_project(id).await
            }
        }
    }

    pub async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_projects())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_projects().await
            }
        }
    }

    pub async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_project(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_project(id).await
            }
        }
    }

    /// Atomic reject-if-referenced project delete (issue #328, finding 4):
    /// the child-count check and the delete run indivisibly (one Postgres
    /// transaction with the parent row locked `FOR UPDATE`, or the whole
    /// in-memory critical section), so a child created between a separate
    /// count and delete can no longer be silently `ON DELETE CASCADE`d.
    pub async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_project_if_unreferenced(id))
                .map_err(|_| {
                    StorageError::Runtime(
                        "in-memory control-plane mutex poisoned during project delete".to_string(),
                    )
                }),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_project_if_unreferenced(id).await
            }
        }
    }

    pub async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_workspace(workspace);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_workspace(&workspace).await
            }
        }
    }

    pub async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_workspace(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_workspace(id).await
            }
        }
    }

    pub async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_workspaces())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_workspaces().await
            }
        }
    }

    pub async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_workspace(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_workspace(id).await
            }
        }
    }

    /// Atomic reject-if-referenced workspace delete (issue #328, finding 4).
    /// See [`RuntimeStorageRepositories::delete_project_if_unreferenced`].
    pub async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_workspace_if_unreferenced(id))
                .map_err(|_| {
                    StorageError::Runtime(
                        "in-memory control-plane mutex poisoned during workspace delete"
                            .to_string(),
                    )
                }),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_workspace_if_unreferenced(id).await
            }
        }
    }

    /// Resolve a workspace id to its full `tenant -> project -> workspace`
    /// attribution chain. Returns `None` when the workspace does not exist.
    pub async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.resolve_workspace_scope(workspace_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.resolve_workspace_scope(workspace_id).await
            }
        }
    }

    // --- Multi-level quota/rate-limit policies (tenant/project/workspace/key) ---

    pub async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError> {
        validate_quota_policy(&policy)?;
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_quota_policy(policy);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_quota_policy(&policy).await
            }
        }
    }

    pub async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_quota_policy(scope_type, scope_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_quota_policy(scope_type, scope_id).await
            }
        }
    }

    pub async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_quota_policies())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_quota_policies().await
            }
        }
    }

    pub async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_quota_policy(scope_type, scope_id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .delete_quota_policy(scope_type, scope_id)
                    .await
            }
        }
    }

    /// Creates or replaces a plan (issue #168). Plans are shared across
    /// tenants, so any authenticated admin-write caller may define one --
    /// same trust model as [`Self::upsert_quota_policy`].
    pub async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_plan(plan);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_plan(&plan).await
            }
        }
    }

    pub async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_plan(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.get_plan(id).await,
        }
    }

    pub async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_plans())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_plans().await,
        }
    }

    /// Creates or replaces an asset (issue #176). Unlike plans/quota
    /// policies (shared/scope-keyed), assets are tenant-owned -- same trust
    /// model as tenant account CRUD.
    pub async fn upsert_asset(&self, asset: StoredAsset) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.upsert_asset(asset))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_asset(&asset).await
            }
        }
    }

    /// Publishes an immutable asset version exactly once. The Postgres backend
    /// uses one `INSERT ... ON CONFLICT DO NOTHING` statement; the memory
    /// backend performs the equivalent check and insert under one lock.
    pub async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.create_asset_if_absent(asset))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.create_asset_if_absent(&asset).await
            }
        }
    }

    /// Atomically admit a push against the tenant asset-storage quota and publish
    /// it (issue #371). Replaces the read-then-write admission (a
    /// `tenant_asset_storage_bytes_used` read followed by a separate
    /// `create_asset_if_absent`) that let two commits for two DIFFERENT asset ids
    /// both observe the same remaining capacity and jointly overshoot the quota.
    ///
    /// The Postgres backend folds the usage read, the quota guard, the
    /// create-if-absent immutability guard, and the row insert into ONE
    /// conditional statement; the memory backend performs the identical
    /// read-guard-insert under one lock. Both return the same typed outcome:
    /// `Admitted` (bytes reserved), `AlreadyExists` (idempotent, never charged
    /// twice), or `OverQuota` (definitively rejected pre-commit, nothing written).
    /// A lost commit outcome surfaces as `Err(OperationCommitOutcomeUnknown)` and
    /// is never collapsed into a definitive arm, so a caller never double-reserves
    /// nor falsely rejects on an unresolved reservation.
    pub async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.create_asset_within_quota(asset, quota_bytes)
                })
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .create_asset_within_quota(&asset, quota_bytes)
                    .await
            }
        }
    }

    pub async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.get_asset(id))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_asset(id).await
            }
        }
    }

    pub async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.list_assets(tenant_id, asset_type))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_assets(tenant_id, asset_type).await
            }
        }
    }

    /// Operator-only listing of WITHHELD assets (issue #379): every non-`visible`
    /// (`pending_scan`/`quarantined`) row for the tenant, ordered deterministically
    /// so offset/limit pagination is stable. This is the inverse of the consumer
    /// [`Self::list_assets`], which hides exactly these rows (#366). Both backends
    /// filter on the same `is_downloadable()`/`visibility <> 'visible'` predicate
    /// so the operator view can never disagree with what the read path withholds.
    pub async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.list_withheld_assets(tenant_id, asset_type))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_withheld_assets(tenant_id, asset_type)
                    .await
            }
        }
    }

    /// Authoritative tenant storage usage without loading stored object bytes.
    pub async fn tenant_asset_storage_bytes_used(
        &self,
        tenant_id: &str,
    ) -> Result<u64, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.tenant_asset_storage_bytes_used(tenant_id))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .tenant_asset_storage_bytes_used(tenant_id)
                    .await
            }
        }
    }

    pub async fn delete_asset(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_asset(id))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_asset(id).await
            }
        }
    }

    /// Creates or moves a channel pointer (issue #260). Idempotent per
    /// `(tenant, asset_type, name, channel)`; the caller audits the move.
    pub async fn upsert_asset_channel(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.upsert_asset_channel(channel))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_asset_channel(&channel).await
            }
        }
    }

    pub async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|control_plane| control_plane.list_asset_channels(tenant_id, asset_type, name))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_asset_channels(tenant_id, asset_type, name)
                    .await
            }
        }
    }

    pub async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_asset_channel(id))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_asset_channel(id).await
            }
        }
    }

    /// Atomically move a channel pointer only when its target version is durably
    /// resolvable (issue #367). The Postgres backend takes a `FOR UPDATE` row
    /// lock on the version's `stored_assets` rows before the guarded upsert; the
    /// memory backend performs the equivalent check-and-write under one lock. A
    /// concurrent yank/delete can therefore never leave the channel on a
    /// non-resolvable version.
    pub async fn move_asset_channel_if_resolvable(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| control_plane.move_asset_channel_if_resolvable(channel))
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .move_asset_channel_if_resolvable(&channel)
                    .await
            }
        }
    }

    /// Atomically set/clear the yank flag on every variant of a version (issue
    /// #367). Yank is rejected while a channel references the version so the
    /// lifecycle invariant holds as one atomic step; unyank never coordinates.
    /// Postgres locks the version's rows `FOR UPDATE`; memory runs under one lock.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_asset_version_yank(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.set_asset_version_yank(
                        tenant_id, asset_type, name, version, yanked, now_unix,
                    )
                })
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .set_asset_version_yank(tenant_id, asset_type, name, version, yanked, now_unix)
                    .await
            }
        }
    }

    /// Atomically delete one variant row unless it would strand a channel on an
    /// absent version (issue #367). Postgres locks the version's rows
    /// `FOR UPDATE`; memory runs under one lock.
    pub async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.delete_asset_variant_if_unreferenced(
                        id, tenant_id, asset_type, name, version,
                    )
                })
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .delete_asset_variant_if_unreferenced(id, tenant_id, asset_type, name, version)
                    .await
            }
        }
    }

    /// Atomically promote a `pending_scan` asset row to `visible`/`quarantined`
    /// after an out-of-band scan completes (issue #378, follow-up to #366). The
    /// flip fires only from the `pending_scan` state -- Postgres via one short
    /// conditional data-modifying CTE, memory under one lock -- so a missing or
    /// already-terminal row is rejected fail-closed and two concurrent
    /// promotions can never both succeed. This is the only path that moves an
    /// asset out of `pending_scan`; the push path only ever admits INTO it.
    pub async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.promote_pending_asset_visibility(id, target, now_unix)
                })
                .map_err(|_| poisoned_asset_repository_lock()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .promote_pending_asset_visibility(id, target, now_unix)
                    .await
            }
        }
    }

    // #263: asset lifecycle -- retention policies + whole-registry reconcile
    // scans the lifecycle sweeper drives.

    pub async fn upsert_retention_policy(
        &self,
        policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_retention_policy(policy);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_retention_policy(&policy).await
            }
        }
    }

    pub async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| {
                    control_plane.list_retention_policies(tenant_id, resource_type)
                })
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_retention_policies(tenant_id, resource_type)
                    .await
            }
        }
    }

    /// Every asset row across every tenant, for the lifecycle sweeper's
    /// retention grouping + GC referenced-key derivation (#263).
    pub async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_all_assets())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_all_assets().await
            }
        }
    }

    /// Every channel pointer across every tenant, so the sweeper knows which
    /// versions are channel-pinned (never pruned) (#263).
    pub async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_all_asset_channels())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_all_asset_channels().await
            }
        }
    }

    // --- P1-4 usage/cost monthly rollups ---

    pub async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| {
                    control_plane.get_usage_monthly_rollup(scope_type, scope_id, period_month)
                })
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .get_usage_monthly_rollup(scope_type, scope_id, period_month)
                    .await
            }
        }
    }

    pub async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_usage_monthly_rollups())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_usage_monthly_rollups().await
            }
        }
    }

    /// Persist a settled billing ledger entry (issue #129). Idempotent on the
    /// entry id; returns `true` when newly inserted. Supabase/Postgres-only.
    pub async fn append_billing_ledger_entry(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_billing_ledger_entry(entry).await
            }
            RuntimeControlPlaneBackend::Memory(_) => Err(billing_ledger_supabase_only_error()),
        }
    }

    /// List settled ledger entries matching `filter`, oldest first, paginated.
    /// Supabase-only. The filter is pushed into the SQL query (issue #149).
    pub async fn list_billing_ledger_entries(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_billing_ledger_entries(
                        filter,
                        saturating_i64(offset as u64),
                        saturating_i64(limit as u64),
                    )
                    .await
            }
            RuntimeControlPlaneBackend::Memory(_) => Err(billing_ledger_supabase_only_error()),
        }
    }

    /// Fetch a single settled ledger entry by id. Supabase-only.
    pub async fn billing_ledger_entry(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_billing_ledger_entry(id).await
            }
            RuntimeControlPlaneBackend::Memory(_) => Err(billing_ledger_supabase_only_error()),
        }
    }

    /// Enqueue a gateway→billing usage report for durable delivery (issue #137).
    /// Idempotent on `id` (the ledger entry id). Supported on Postgres and the
    /// in-memory backend so the sweeper works in both production and tests.
    pub async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.enqueue_billing_report(id, event, next_attempt_unix);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .enqueue_billing_report(id, event, next_attempt_unix)
                    .await
            }
        }
    }

    /// List billing report outbox entries whose `next_attempt_unix <= now`.
    pub async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_due_billing_reports(now_unix, limit))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_due_billing_reports(now_unix, saturating_i64(limit as u64))
                    .await
            }
        }
    }

    /// Bump the attempt count and next-attempt time of a pending report.
    pub async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.reschedule_billing_report(id, next_attempt_unix);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .reschedule_billing_report(id, next_attempt_unix)
                    .await
            }
        }
    }

    /// Mark a permanently-failing report dead-lettered (issue #143) instead of
    /// rescheduling it forever. The row is kept for operator inspection via
    /// [`list_dead_lettered_billing_reports`](Self::list_dead_lettered_billing_reports)
    /// and excluded from [`list_due_billing_reports`](Self::list_due_billing_reports).
    pub async fn dead_letter_billing_report(
        &self,
        id: &str,
        dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.dead_letter_billing_report(id, dead_lettered_at_unix);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.dead_letter_billing_report(id).await
            }
        }
    }

    /// List dead-lettered billing reports, most recently given-up-on first.
    pub async fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_dead_lettered_billing_reports(limit))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_dead_lettered_billing_reports(saturating_i64(limit as u64))
                    .await
            }
        }
    }

    /// Conditionally replay (re-enqueue) a dead-lettered billing report for
    /// redelivery (issue #388). Returns a typed [`ReplayDeadLetterOutcome`] so
    /// the admin handler can map missing / not-dead-lettered / replayed to
    /// distinct HTTP results. `next_attempt_unix` schedules the redelivery
    /// (pass "now" for the sweeper to pick it up on its next batch). Fails
    /// closed on a poisoned in-memory lock rather than silently reporting a
    /// no-op success.
    pub async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.replay_dead_lettered_billing_report(id, next_attempt_unix)
                })
                .map_err(|_| {
                    StorageError::Runtime(
                        "in-memory control-plane mutex poisoned during dead-letter replay"
                            .to_string(),
                    )
                }),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .replay_dead_lettered_billing_report(id, next_attempt_unix)
                    .await
            }
        }
    }

    /// Fetch a single billing-report outbox row by id (issue #388). Used to
    /// tenant-authorize a dead-letter replay before the CAS mutation runs, so
    /// a tenant-scoped admin key can never re-enqueue another tenant's report.
    pub async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_billing_report_outbox_entry(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_billing_report_outbox_entry(id).await
            }
        }
    }

    /// Delete a delivered report from the outbox.
    pub async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.delete_billing_report(id);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_billing_report(id).await
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.upsert("policy", id.into(), document_json))
            }
        }
    }

    pub fn delete_control_plane_policy(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_policy(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("policy", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("gateway_config", id.into(), document_json),
            ),
        }
    }

    pub fn delete_control_plane_gateway_config(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_gateway_config(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("gateway_config", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("agent_workflow", id.into(), document_json),
            ),
        }
    }

    pub fn delete_control_plane_agent_workflow(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_agent_workflow(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("agent_workflow", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("skill_package", id.into(), document_json),
            ),
        }
    }

    pub fn delete_control_plane_skill_package(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_skill_package(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("skill_package", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("prompt_template", id.into(), document_json),
            ),
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("plugin_registration", id.into(), document_json),
            ),
        }
    }

    pub fn delete_control_plane_plugin_registration(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_plugin_registration(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("plugin_registration", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.upsert("mcp_server", id.into(), document_json))
            }
        }
    }

    pub fn delete_control_plane_mcp_server(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_mcp_server(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("mcp_server", id.to_string()))
            }
        }
    }

    pub fn upsert_control_plane_agent_upstream(
        &self,
        id: impl Into<String>,
        document_json: String,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_agent_upstream(id, document_json);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("agent_upstream", id.into(), document_json),
            ),
        }
    }

    pub fn delete_control_plane_agent_upstream(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_agent_upstream(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.delete("agent_upstream", id.to_string()))
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
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.upsert("tool_approval", id.into(), document_json),
            ),
        }
    }

    pub fn control_plane_tool_approval(&self, id: &str) -> Result<Option<String>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .ok()
                .and_then(|control_plane| control_plane.tool_approval(id))),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.get_document("tool_approval", id.to_string()))
            }
        }
    }

    pub fn control_plane_tool_approvals(&self) -> Result<Vec<String>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.tool_approvals())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.list_documents("tool_approval"))
            }
        }
    }

    pub fn control_plane_tool_approval_documents(
        &self,
    ) -> Result<Vec<(String, String)>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.tool_approval_documents())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.list_resource_documents("tool_approval"))
            }
        }
    }

    /// Opportunistic durable-prune scheduling (issue #231): due on the first
    /// write and every `DURABLE_PRUNE_WRITE_INTERVAL`th write per table, and
    /// only when durable retention is enabled (`> 0`).
    fn durable_prune_due(&self, ticks: &AtomicU64) -> bool {
        self.durable_worker_retention_records > 0
            && ticks
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(DURABLE_PRUNE_WRITE_INTERVAL)
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

    pub async fn append_request_log(&self, log: StoredRequestLog) {
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            let _ = control_plane.append_request_log(&log).await;
            return;
        }
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    pub async fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_billing_event(&event).await
            }
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(&event);
                let mut control_plane = control_plane.lock().map_err(|_| {
                    StorageError::Runtime("memory control-plane lock poisoned".into())
                })?;
                if let Some(existing) = control_plane.billing_event_ids.get(&billing_event_id) {
                    if same_billing_event_settlement(&existing, &event) {
                        return Ok(false);
                    }
                    return Err(StorageError::Conflict(format!(
                        "billing event id {billing_event_id} was replayed with different provider-attempt settlement data"
                    )));
                }
                control_plane
                    .billing_event_ids
                    .insert(billing_event_id, event.clone());
                let period_month = period_month_from_unix(saturating_i64(
                    event.occurred_at_unix.unwrap_or_else(now_unix_seconds),
                ));
                let usage_delta = UsageMonthlyDelta {
                    prompt_tokens: event.usage.prompt_tokens,
                    completion_tokens: event.usage.completion_tokens,
                    total_tokens: event.usage.total_tokens,
                    cost_usd: event.cost_usd.unwrap_or(0.0),
                    is_error: event.status_code >= 400,
                };
                control_plane.increment_usage_monthly_rollups(
                    &event.tenant,
                    &period_month,
                    &usage_delta,
                );
                control_plane.increment_usage_metadata_rollups(
                    &event.tenant,
                    &event.metadata,
                    &period_month,
                    &usage_delta,
                );
                drop(control_plane);
                self.upsert_in_memory_usage_aggregate(&event);
                Ok(true)
            }
        }
    }

    /// Append a billing event and durably enqueue it for delivery to the
    /// billing service in as few round-trips as the backend allows (issue
    /// #150). On Postgres both writes commit in a single transaction. On
    /// Memory (no real round-trip to save) this simply calls
    /// [`append_billing_event`](Self::append_billing_event) followed by
    /// [`enqueue_billing_report`](Self::enqueue_billing_report), preserving
    /// their prior non-fatal enqueue-failure semantics via
    /// [`BillingEventAppendOutcome::enqueue_error`].
    pub async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                let recorded = control_plane
                    .append_billing_event_with_outbox_enqueue(
                        &event,
                        outbox_id,
                        outbox_next_attempt_unix,
                    )
                    .await?;
                Ok(BillingEventAppendOutcome {
                    recorded,
                    enqueue_error: None,
                })
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                let recorded = self.append_billing_event(event.clone()).await?;
                let enqueue_error = if recorded {
                    self.enqueue_billing_report(outbox_id, &event, outbox_next_attempt_unix)
                        .await
                        .err()
                } else {
                    None
                };
                Ok(BillingEventAppendOutcome {
                    recorded,
                    enqueue_error,
                })
            }
        }
    }

    fn upsert_in_memory_usage_aggregate(&self, event: &BillingEvent) {
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let id = usage_aggregate_id(&event.tenant, &event.logical_model, &event.provider);
            let existing = aggregates.get(&id);
            let mut aggregate = existing.unwrap_or_else(|| StoredUsageAggregate {
                id: id.clone(),
                organization_id: event.tenant.organization_id.clone(),
                project_id: event.tenant.project_id.clone(),
                api_key_id: event.tenant.api_key_id.clone(),
                logical_model: event.logical_model.clone(),
                provider: event.provider.clone(),
                usage: TokenUsage::default(),
            });
            aggregate.usage.prompt_tokens = aggregate
                .usage
                .prompt_tokens
                .saturating_add(event.usage.prompt_tokens);
            aggregate.usage.completion_tokens = aggregate
                .usage
                .completion_tokens
                .saturating_add(event.usage.completion_tokens);
            aggregate.usage.total_tokens = aggregate
                .usage
                .total_tokens
                .saturating_add(event.usage.total_tokens);
            aggregates.insert(id, aggregate);
        }
    }

    pub async fn billing_events(&self) -> Vec<BillingEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.billing_events().await.unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) => Vec::new(),
        }
    }

    pub async fn billing_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<BillingEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .billing_events_page(offset, limit)
                .await
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) => StoragePage::empty(offset, limit),
        }
    }

    pub async fn request_logs(&self) -> Vec<StoredRequestLog> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.request_logs().await.unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) => self
                .request_logs
                .lock()
                .map(|logs| logs.list())
                .unwrap_or_default(),
        }
    }

    pub async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredRequestLog> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .request_logs_page(offset, limit)
                .await
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) => self
                .request_logs
                .lock()
                .map(|logs| StoragePage {
                    data: logs.list_paginated(offset, limit),
                    total: logs.len(),
                    offset,
                    limit,
                })
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
        }
    }

    pub async fn append_audit_event(&self, event: StoredAuditEvent) {
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            let _ = control_plane.append_audit_event(&event).await;
            return;
        }
        if let Ok(mut events) = self.audit_events.lock() {
            events.append(event);
        }
    }

    pub fn next_audit_event_id(&self) -> String {
        if matches!(&self.control_plane, RuntimeControlPlaneBackend::Postgres(_)) {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            return format!("audit-{nanos}-{}", std::process::id());
        }
        self.audit_events
            .lock()
            .map(|events| format!("audit-{}", events.len() + 1))
            .unwrap_or_else(|_| "audit-unknown".to_string())
    }

    pub async fn audit_events(&self) -> Vec<StoredAuditEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.audit_events().await.unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) => self
                .audit_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
        }
    }

    pub async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredAuditEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .audit_events_page(offset, limit)
                .await
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
            RuntimeControlPlaneBackend::Memory(_) => self
                .audit_events
                .lock()
                .map(|events| StoragePage {
                    data: events.list_paginated(offset, limit),
                    total: events.len(),
                    offset,
                    limit,
                })
                .unwrap_or_else(|_| StoragePage::empty(offset, limit)),
        }
    }

    /// #284: batched, idempotent delete of `request_logs` rows by
    /// `request_id`, for the compliance retention sweeper. On Postgres this is
    /// a single `DELETE ... WHERE request_id = ANY($1)`; on the in-memory
    /// backend it retains only the rows whose id is not in `request_ids`.
    /// Returns the number of rows removed.
    pub async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError> {
        if request_ids.is_empty() {
            return Ok(0);
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_request_logs(request_ids).await
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                let drop: std::collections::HashSet<&str> =
                    request_ids.iter().map(String::as_str).collect();
                let removed = self
                    .request_logs
                    .lock()
                    .map(|mut logs| logs.retain(|log| !drop.contains(log.request_id.as_str())))
                    .unwrap_or(0);
                Ok(removed as u64)
            }
        }
    }

    /// #284: batched, idempotent delete of `audit_events` rows by `id`, for the
    /// compliance retention sweeper. Postgres uses `DELETE ... WHERE id =
    /// ANY($1)`; the in-memory backend retains only the rows not listed.
    pub async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError> {
        if ids.is_empty() {
            return Ok(0);
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_audit_events(ids).await
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                let drop: std::collections::HashSet<&str> =
                    ids.iter().map(String::as_str).collect();
                let removed = self
                    .audit_events
                    .lock()
                    .map(|mut events| events.retain(|event| !drop.contains(event.id.as_str())))
                    .unwrap_or(0);
                Ok(removed as u64)
            }
        }
    }

    pub async fn upsert_usage_aggregate(
        &self,
        id: impl Into<String>,
        build: impl FnOnce(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let id = id.into();
        let aggregate = if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let existing = aggregates.get(&id);
            let aggregate = build(existing);
            aggregates.insert(id, aggregate.clone());
            aggregate
        } else {
            return Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ));
        };
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            control_plane.upsert_usage_aggregate(&aggregate).await?;
        }
        Ok(())
    }

    pub async fn replace_usage_aggregate(
        &self,
        aggregate: StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        let id = aggregate.id.clone();
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            aggregates.insert(id, aggregate.clone());
        } else {
            return Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ));
        }
        if let RuntimeControlPlaneBackend::Postgres(control_plane) = &self.control_plane {
            control_plane.upsert_usage_aggregate(&aggregate).await?;
        }
        Ok(())
    }

    pub async fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.usage_aggregates().await.unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Memory(_) => self
                .usage_aggregates
                .lock()
                .map(|aggregates| aggregates.list())
                .unwrap_or_default(),
        }
    }

    /// Total committed `total_tokens` for one `api_key_id` (issue #330). On
    /// the durable path the filter + sum run in SQL so the per-request token
    /// budget gate never materializes the whole `usage_aggregate_rollups`
    /// table; the in-memory backend keeps the equivalent filter-and-sum over
    /// its aggregate map. Errors collapse to `0` to preserve the exact
    /// pre-existing gate semantics (`usage_aggregates().unwrap_or_default()`
    /// already treated a storage error as "no committed usage").
    pub async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> u64 {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .sum_api_key_committed_tokens(api_key_id)
                .await
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Memory(_) => self
                .usage_aggregates
                .lock()
                .map(|aggregates| {
                    aggregates
                        .list()
                        .into_iter()
                        .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
                        .fold(0_u64, |total, aggregate| {
                            total.saturating_add(aggregate.usage.total_tokens)
                        })
                })
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut runs) = self.agent_runs.lock() {
                    runs.insert(run.id.clone(), run);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_agent_run(&run).await
            }
        }
    }

    pub async fn agent_run(&self, id: &str) -> Option<StoredAgentRun> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                self.agent_runs.lock().ok().and_then(|runs| runs.get(id))
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_run(id).await.unwrap_or_default()
            }
        }
    }

    pub async fn agent_runs(&self) -> Vec<StoredAgentRun> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_runs
                .lock()
                .map(|runs| runs.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_runs().await.unwrap_or_default()
            }
        }
    }

    pub async fn append_agent_run_event(
        &self,
        event: StoredAgentRunEvent,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.agent_run_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.append_agent_run_event(&event).await?;
                if self.durable_prune_due(&self.agent_run_event_prune_ticks) {
                    // Best-effort retention (issue #231): a prune failure
                    // must not fail ingestion of the already-written event.
                    if let Err(error) = control_plane
                        .prune_agent_run_events(
                            &event.run_id,
                            self.durable_worker_retention_records,
                        )
                        .await
                    {
                        tracing::warn!("agent run event retention prune failed: {error}");
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_run_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.agent_run_events().await.unwrap_or_default()
            }
        }
    }

    /// Agent runs restricted to `run_ids` (issue #231): the filter is pushed
    /// into SQL on the durable path; the in-memory backend implements the
    /// same filtered semantics.
    pub async fn agent_runs_by_ids(&self, run_ids: &[String]) -> Vec<StoredAgentRun> {
        if run_ids.is_empty() {
            return Vec::new();
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
                self.agent_runs
                    .lock()
                    .map(|runs| {
                        runs.list()
                            .into_iter()
                            .filter(|run| wanted.contains(run.id.as_str()))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .agent_runs_by_ids(run_ids)
                .await
                .unwrap_or_default(),
        }
    }

    /// Agent-run events restricted to `run_ids` (issue #231).
    pub async fn agent_run_events_for_runs(&self, run_ids: &[String]) -> Vec<StoredAgentRunEvent> {
        if run_ids.is_empty() {
            return Vec::new();
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
                self.agent_run_events
                    .lock()
                    .map(|events| {
                        events
                            .list()
                            .into_iter()
                            .filter(|event| wanted.contains(event.run_id.as_str()))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .agent_run_events_for_runs(run_ids)
                .await
                .unwrap_or_default(),
        }
    }

    /// Request logs attributed to any of the given agent runs (issue #231).
    pub async fn request_logs_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredRequestLog> {
        if run_ids.is_empty() {
            return Vec::new();
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
                self.request_logs
                    .lock()
                    .map(|logs| {
                        logs.list()
                            .into_iter()
                            .filter(|log| {
                                log.agent_run_id
                                    .as_deref()
                                    .is_some_and(|run_id| wanted.contains(run_id))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .request_logs_for_agent_runs(run_ids)
                .await
                .unwrap_or_default(),
        }
    }

    /// Audit events attributed to any of the given agent runs (issue #231).
    pub async fn audit_events_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredAuditEvent> {
        if run_ids.is_empty() {
            return Vec::new();
        }
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
                self.audit_events
                    .lock()
                    .map(|events| {
                        events
                            .list()
                            .into_iter()
                            .filter(|event| {
                                event
                                    .agent_run_id
                                    .as_deref()
                                    .is_some_and(|run_id| wanted.contains(run_id))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .audit_events_for_agent_runs(run_ids)
                .await
                .unwrap_or_default(),
        }
    }

    /// Distinct agent-run ids, most recently seen first, bounded by `limit`
    /// (issue #231). `request_id` narrows candidates; exact per-record
    /// filtering remains with the caller. Both backends implement the same
    /// semantics; the durable path evaluates the whole thing in SQL.
    pub async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Vec<String> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let mut last_seen: HashMap<String, u64> = HashMap::new();
                let mut observe = |run_id: &str, seen_at: Option<u64>| {
                    let seen_at = seen_at.unwrap_or_default();
                    let entry = last_seen.entry(run_id.to_string()).or_insert(seen_at);
                    *entry = (*entry).max(seen_at);
                };
                if let Ok(runs) = self.agent_runs.lock() {
                    for run in runs.list() {
                        if request_id.is_none_or(|expected| run.request_id == expected) {
                            observe(&run.id, run.completed_at_unix.or(run.started_at_unix));
                        }
                    }
                }
                if let Ok(events) = self.agent_run_events.lock() {
                    for event in events.list() {
                        if request_id.is_none_or(|expected| event.request_id == expected) {
                            observe(&event.run_id, event.occurred_at_unix);
                        }
                    }
                }
                if let Ok(logs) = self.request_logs.lock() {
                    for log in logs.list() {
                        if let Some(run_id) = log.agent_run_id.as_deref() {
                            if request_id.is_none_or(|expected| log.request_id == expected) {
                                observe(run_id, log.completed_at_unix.or(log.started_at_unix));
                            }
                        }
                    }
                }
                if let Ok(events) = self.audit_events.lock() {
                    for event in events.list() {
                        if let Some(run_id) = event.agent_run_id.as_deref() {
                            if request_id.is_none_or(|expected| event.request_id == expected) {
                                observe(run_id, event.occurred_at_unix);
                            }
                        }
                    }
                }
                let mut seeds: Vec<(String, u64)> = last_seen.into_iter().collect();
                seeds
                    .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
                seeds.truncate(limit);
                seeds.into_iter().map(|(run_id, _)| run_id).collect()
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .agent_run_summary_seed_ids(request_id, limit)
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut templates) = self.managed_worker_templates.lock() {
                    templates.insert(template.id.clone(), template);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_managed_worker_template(&template)
                    .await
            }
        }
    }

    pub async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_templates
                .lock()
                .map(|templates| templates.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_templates()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut instances) = self.agent_worker_instances.lock() {
                    instances.insert(instance.id.clone(), instance);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_agent_worker_instance(&instance).await
            }
        }
    }

    pub async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .agent_worker_instances
                .lock()
                .map(|instances| instances.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .agent_worker_instances()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut sessions) = self.managed_worker_sessions.lock() {
                    sessions.insert(session.id.clone(), session);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_managed_worker_session(&session).await
            }
        }
    }

    pub async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_sessions
                .lock()
                .map(|sessions| sessions.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_sessions()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.managed_worker_lifecycle_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .append_managed_worker_lifecycle_event(&event)
                    .await
            }
        }
    }

    pub async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_lifecycle_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_lifecycle_events()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut selections) = self.managed_worker_isolation_selections.lock() {
                    selections.insert(selection.session_id.clone(), selection);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_managed_worker_isolation_selection(&selection)
                    .await
            }
        }
    }

    pub async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_selections
                .lock()
                .map(|selections| selections.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_selections()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut policies) = self.managed_worker_isolation_policies.lock() {
                    policies.insert(policy.session_id.clone(), policy);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_managed_worker_isolation_policy(&policy)
                    .await
            }
        }
    }

    pub async fn managed_worker_isolation_policies(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationPolicy> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_policies
                .lock()
                .map(|policies| policies.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_policies()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut records) = self.managed_worker_isolation_evidence.lock() {
                    records.insert(evidence.id.clone(), evidence);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_managed_worker_isolation_evidence(&evidence)
                    .await
            }
        }
    }

    pub async fn managed_worker_isolation_evidence(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationEvidence> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .managed_worker_isolation_evidence
                .lock()
                .map(|records| records.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .managed_worker_isolation_evidence()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut registrations) = self.self_hosted_worker_registrations.lock() {
                    registrations.insert(registration.id.clone(), registration);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_self_hosted_worker_registration(&registration)
                    .await
            }
        }
    }

    pub async fn self_hosted_worker_registrations(
        &self,
    ) -> Vec<StoredSelfHostedWorkerRegistration> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_registrations
                .lock()
                .map(|registrations| registrations.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_registrations()
                .await
                .unwrap_or_default(),
        }
    }

    /// Single-registration lookup (issue #231): worker-id filter pushed into
    /// SQL on the durable path instead of listing every registration.
    pub async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_registrations
                .lock()
                .ok()
                .and_then(|registrations| registrations.get(worker_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_registration(worker_id)
                .await
                .unwrap_or_default(),
        }
    }

    /// Latest heartbeat for one worker (issue #231): `worker_id` filter and
    /// `LIMIT 1` pushed into SQL on the durable path.
    pub async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_heartbeats
                .lock()
                .ok()
                .and_then(|heartbeats| {
                    heartbeats
                        .list()
                        .into_iter()
                        .filter(|heartbeat| heartbeat.worker_id == worker_id)
                        .max_by(|left, right| {
                            left.reported_at_unix
                                .cmp(&right.reported_at_unix)
                                .then_with(|| left.id.cmp(&right.id))
                        })
                }),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .latest_self_hosted_worker_heartbeat(worker_id)
                .await
                .unwrap_or_default(),
        }
    }

    /// Per-worker activity aggregates (issue #231): computed with
    /// worker-filtered queries on the durable path; the in-memory backend
    /// computes the same aggregates over its (bounded) stores.
    pub async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let mut stats = StoredSelfHostedWorkerActivityStats::default();
                if let Ok(events) = self.self_hosted_worker_telemetry_events.lock() {
                    for event in events.list() {
                        if event.worker_id == worker_id {
                            stats.telemetry_event_count += 1;
                            stats.latest_event_at_unix =
                                stats.latest_event_at_unix.max(event.occurred_at_unix);
                        }
                    }
                }
                if let Ok(artifacts) = self.self_hosted_worker_artifacts.lock() {
                    for artifact in artifacts.list() {
                        if artifact.worker_id == worker_id {
                            stats.artifact_count += 1;
                            stats.latest_artifact_at_unix =
                                stats.latest_artifact_at_unix.max(artifact.created_at_unix);
                        }
                    }
                }
                if let Ok(checkpoints) = self.self_hosted_worker_checkpoints.lock() {
                    for checkpoint in checkpoints.list() {
                        if checkpoint.worker_id == worker_id {
                            stats.checkpoint_count += 1;
                            stats.latest_checkpoint_at_unix = stats
                                .latest_checkpoint_at_unix
                                .max(checkpoint.created_at_unix);
                        }
                    }
                }
                stats
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_activity_stats(worker_id)
                .await
                .unwrap_or_default(),
        }
    }

    /// Telemetry events for one run in ascending timeline order, keeping the
    /// NEWEST `limit` events (issue #231) so a flooded run still reports its
    /// latest lifecycle state. `limit == 0` means unbounded.
    pub async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                let mut events = self
                    .self_hosted_worker_telemetry_events
                    .lock()
                    .map(|events| {
                        events
                            .list()
                            .into_iter()
                            .filter(|event| event.run_id.as_deref() == Some(run_id))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                events.sort_by(|left, right| {
                    left.occurred_at_unix
                        .cmp(&right.occurred_at_unix)
                        .then_with(|| left.ingested_at_unix.cmp(&right.ingested_at_unix))
                        .then_with(|| left.id.cmp(&right.id))
                });
                if limit > 0 && events.len() > limit {
                    events.drain(..events.len() - limit);
                }
                events
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_telemetry_events_for_run(run_id, limit)
                .await
                .unwrap_or_default(),
        }
    }

    /// Telemetry events for one worker (issue #231): worker-id filter pushed
    /// into SQL on the durable path; both backends are retention-bounded.
    pub async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_telemetry_events
                .lock()
                .map(|events| {
                    events
                        .list()
                        .into_iter()
                        .filter(|event| event.worker_id == worker_id)
                        .collect()
                })
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_telemetry_events_for_worker(worker_id)
                .await
                .unwrap_or_default(),
        }
    }

    /// Single-artifact lookup by id (issue #231): backs the cross-worker
    /// overwrite guard (#228) without listing the whole table.
    pub async fn self_hosted_worker_artifact(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerArtifact> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_artifacts
                .lock()
                .ok()
                .and_then(|artifacts| artifacts.get(id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_artifact(id)
                .await
                .unwrap_or_default(),
        }
    }

    /// Single-checkpoint lookup by id (issue #231); see the artifact twin.
    pub async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_checkpoints
                .lock()
                .ok()
                .and_then(|checkpoints| checkpoints.get(id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_checkpoint(id)
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut heartbeats) = self.self_hosted_worker_heartbeats.lock() {
                    heartbeats.append(heartbeat);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .append_self_hosted_worker_heartbeat(&heartbeat)
                    .await?;
                if self.durable_prune_due(&self.heartbeat_prune_ticks) {
                    // Best-effort retention (issue #231): a prune failure
                    // must not fail ingestion of the already-written record.
                    if let Err(error) = control_plane
                        .prune_self_hosted_worker_heartbeats(
                            &heartbeat.worker_id,
                            self.durable_worker_retention_records,
                        )
                        .await
                    {
                        tracing::warn!("self-hosted heartbeat retention prune failed: {error}");
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_heartbeats
                .lock()
                .map(|heartbeats| heartbeats.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_heartbeats()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut events) = self.self_hosted_worker_telemetry_events.lock() {
                    events.append(event);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .append_self_hosted_worker_telemetry_event(&event)
                    .await?;
                if self.durable_prune_due(&self.telemetry_prune_ticks) {
                    // Best-effort retention (issue #231); see heartbeat twin.
                    if let Err(error) = control_plane
                        .prune_self_hosted_worker_telemetry_events(
                            &event.worker_id,
                            self.durable_worker_retention_records,
                        )
                        .await
                    {
                        tracing::warn!("self-hosted telemetry retention prune failed: {error}");
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_telemetry_events
                .lock()
                .map(|events| events.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_telemetry_events()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut artifacts) = self.self_hosted_worker_artifacts.lock() {
                    artifacts.insert(artifact.id.clone(), artifact);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_self_hosted_worker_artifact(&artifact)
                    .await?;
                if self.durable_prune_due(&self.artifact_prune_ticks) {
                    // Best-effort retention (issue #231); see heartbeat twin.
                    if let Err(error) = control_plane
                        .prune_self_hosted_worker_artifacts(
                            &artifact.worker_id,
                            self.durable_worker_retention_records,
                        )
                        .await
                    {
                        tracing::warn!("self-hosted artifact retention prune failed: {error}");
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_artifacts
                .lock()
                .map(|artifacts| artifacts.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_artifacts()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut checkpoints) = self.self_hosted_worker_checkpoints.lock() {
                    checkpoints.insert(checkpoint.id.clone(), checkpoint);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_self_hosted_worker_checkpoint(&checkpoint)
                    .await?;
                if self.durable_prune_due(&self.checkpoint_prune_ticks) {
                    // Best-effort retention (issue #231); see heartbeat twin.
                    if let Err(error) = control_plane
                        .prune_self_hosted_worker_checkpoints(
                            &checkpoint.worker_id,
                            self.durable_worker_retention_records,
                        )
                        .await
                    {
                        tracing::warn!("self-hosted checkpoint retention prune failed: {error}");
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_worker_checkpoints
                .lock()
                .map(|checkpoints| checkpoints.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_worker_checkpoints()
                .await
                .unwrap_or_default(),
        }
    }

    pub async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => {
                if let Ok(mut dispatches) = self.self_hosted_run_dispatches.lock() {
                    dispatches.insert(dispatch.dispatch_id.clone(), dispatch);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .upsert_self_hosted_run_dispatch(&dispatch)
                    .await
            }
        }
    }

    pub async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(_) => self
                .self_hosted_run_dispatches
                .lock()
                .map(|dispatches| dispatches.list())
                .unwrap_or_default(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane
                .self_hosted_run_dispatches()
                .await
                .unwrap_or_default(),
        }
    }
}

impl GuardrailPolicyRepository for RuntimeStorageRepositories {
    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .insert_guardrail_policy_revision(revision),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.insert_guardrail_policy_revision(&revision))
            }
        }
    }

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .get_guardrail_policy_revision(policy_id, revision)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.get_guardrail_policy_revision(policy_id, revision),
            ),
        }
    }

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .list_guardrail_policy_revisions(policy_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.list_guardrail_policy_revisions(policy_id))
            }
        }
    }

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .get_guardrail_policy_binding(policy_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.get_guardrail_policy_binding(policy_id))
            }
        }
    }

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .list_guardrail_policy_bindings()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.list_guardrail_policy_bindings())
            }
        }
    }

    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .activate_guardrail_policy_revision(
                    policy_id,
                    revision,
                    updated_by,
                    updated_at_unix,
                    rollback_only,
                ),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.activate_guardrail_policy_revision(
                    policy_id,
                    revision,
                    updated_by,
                    updated_at_unix,
                    rollback_only,
                ))
            }
        }
    }

    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .archive_guardrail_policy_revision(
                    policy_id,
                    revision,
                    updated_by,
                    updated_at_unix,
                ),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.archive_guardrail_policy_revision(
                    policy_id,
                    revision,
                    updated_by,
                    updated_at_unix,
                ))
            }
        }
    }

    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail policy repository lock poisoned".into())
                })?
                .restore_guardrail_policy_binding(policy_id, expected_generation, binding),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.restore_guardrail_policy_binding(
                    policy_id,
                    expected_generation,
                    binding.as_ref(),
                ))
            }
        }
    }
}

fn postgres_error(error: tokio_postgres::Error) -> StorageError {
    StorageError::Postgres(sanitize_storage_error(&postgres_error_message(&error)))
}

fn asset_transaction_commit_outcome_unknown(operation: &StorageOperation) -> StorageError {
    StorageError::OperationCommitOutcomeUnknown {
        operation: operation.name(),
        stage: "transaction commit",
    }
}

fn postgres_error_message(error: &tokio_postgres::Error) -> String {
    error.as_db_error().map_or_else(
        || error.to_string(),
        |database_error| {
            postgres_database_error_message(
                database_error.message(),
                database_error.code().code(),
                database_error.detail(),
            )
        },
    )
}

impl SnapshotReplayFloorRepository for RuntimeStorageRepositories {
    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("snapshot replay floor repository lock poisoned".into())
                })?
                .get_snapshot_replay_floor(tenant_id, deployment_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => block_on_sync_bridge(
                control_plane.get_snapshot_replay_floor(tenant_id, deployment_id),
            ),
        }
    }

    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("snapshot replay floor repository lock poisoned".into())
                })?
                .advance_snapshot_replay_floor(tenant_id, deployment_id, revision)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                block_on_sync_bridge(control_plane.advance_snapshot_replay_floor(
                    tenant_id,
                    deployment_id,
                    revision,
                    updated_at_unix,
                ))
            }
        }
    }
}

fn postgres_database_error_message(message: &str, sqlstate: &str, _detail: Option<&str>) -> String {
    format!("{message} (SQLSTATE {sqlstate})")
}

fn sanitize_storage_error(error: &str) -> String {
    let mut sanitized = error.to_string();
    for marker in ["password=", "passfile=", "sslpassword="] {
        sanitized = redact_marker_value(&sanitized, marker);
    }
    redact_url_passwords(&sanitized)
}

fn redact_marker_value(input: &str, marker: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(marker) {
        output.push_str(&rest[..start + marker.len()]);
        output.push_str("[redacted]");
        let value_start = start + marker.len();
        let value_rest = &rest[value_start..];
        let value_end = value_rest
            .find(|ch: char| ch.is_whitespace() || ch == '\'' || ch == '"' || ch == ';')
            .unwrap_or(value_rest.len());
        rest = &value_rest[value_end..];
    }
    output.push_str(rest);
    output
}

fn redact_url_passwords(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_marker) = rest.find("://") {
        let authority_start = scheme_marker + 3;
        let Some(at_relative) = rest[authority_start..].find('@') else {
            output.push_str(rest);
            return output;
        };
        let at = authority_start + at_relative;
        let authority = &rest[authority_start..at];
        let Some(colon_relative) = authority.rfind(':') else {
            output.push_str(&rest[..=at]);
            rest = &rest[at + 1..];
            continue;
        };
        let colon = authority_start + colon_relative;
        output.push_str(&rest[..colon + 1]);
        output.push_str("[redacted]");
        output.push('@');
        rest = &rest[at + 1..];
    }
    output.push_str(rest);
    output
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
#[path = "usage_aggregate_sum_test.rs"]
mod usage_aggregate_sum_test;

#[cfg(test)]
#[path = "schema_validation_test.rs"]
mod schema_validation_test;

#[cfg(test)]
#[path = "async_postgres_test.rs"]
mod async_postgres_test;

#[cfg(test)]
#[path = "storage_ledger_sink_test.rs"]
mod storage_ledger_sink_test;

#[cfg(test)]
#[path = "postgres_error_test.rs"]
mod postgres_error_test;

#[cfg(test)]
#[path = "guardrail_policy_test.rs"]
mod guardrail_policy_test;

#[cfg(test)]
#[path = "schema_routing_test_support.rs"]
mod schema_routing_test_support;

#[cfg(test)]
#[path = "replay_floor_test.rs"]
mod replay_floor_test;

#[cfg(test)]
#[path = "agent_schedule_test.rs"]
mod agent_schedule_test;

#[cfg(test)]
#[path = "site_domain_test.rs"]
mod site_domain_test;

#[cfg(test)]
#[path = "action_identity_persistence_test.rs"]
mod action_identity_persistence_test;

#[cfg(test)]
#[path = "usage_metadata_schema_test.rs"]
mod usage_metadata_schema_test;

#[cfg(test)]
#[path = "control_plane_schema_test.rs"]
mod control_plane_schema_test;

#[cfg(test)]
#[path = "asset_storage_usage_test.rs"]
mod asset_storage_usage_test;

#[cfg(test)]
#[path = "asset_quota_admission_test.rs"]
mod asset_quota_admission_test;

#[cfg(test)]
#[path = "asset_channel_lifecycle_test.rs"]
mod asset_channel_lifecycle_test;

#[cfg(test)]
#[path = "asset_visibility_test.rs"]
mod asset_visibility_test;

#[cfg(test)]
#[path = "asset_visibility_promotion_test.rs"]
mod asset_visibility_promotion_test;

#[cfg(test)]
#[path = "asset_withheld_listing_test.rs"]
mod asset_withheld_listing_test;

#[cfg(test)]
#[path = "payment_attempt_test.rs"]
mod payment_attempt_test;

#[cfg(test)]
#[path = "billing_outbox_replay_test.rs"]
mod billing_outbox_replay_test;

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn postgres_empty(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        config: PostgresStorageConfig,
        initialize_schema: bool,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Result<RuntimeStorageRepositories, StorageError> {
        RuntimeStorageRepositories::postgres(
            config,
            runtime_options_empty(
                provider_order,
                required,
                initialize_schema,
                request_log_retention_records,
                audit_event_retention_records,
            ),
        )
    }

    fn runtime_options_empty(
        provider_order: Vec<StorageProviderKind>,
        required: bool,
        initialize_schema: bool,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> RuntimeStorageOptions {
        RuntimeStorageOptions {
            provider_order,
            required,
            initialize_schema,
            migration_mode: if initialize_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records,
            audit_event_retention_records,
        }
    }

    #[test]
    fn in_memory_api_key_repository_gets_and_lists_records() {
        let mut repository = InMemoryRepository::new();
        repository.insert(
            "key_dev",
            StoredApiKey {
                id: "key_dev".into(),
                workspace_id: "workspace_dev".into(),
                tenant_id: "org".into(),
                project_id: "project".into(),
                name: "Development key".into(),
                key_prefix: "fg_dev".into(),
                key_hash: "blake2b:test".into(),
                last4: "test".into(),
                enabled: true,
                scopes: vec!["chat.completions".into()],
                allowed_models: vec!["fast-chat".into()],
                allowed_providers: vec!["openai".into()],
                tenant: TenantContext {
                    workspace_id: Some("workspace_dev".into()),
                    organization_id: Some("org".into()),
                    team_id: None,
                    project_id: Some("project".into()),
                    user_id: None,
                    api_key_id: Some("key_dev".into()),
                },
                monthly_token_budget: Some(1_000),
                request_limit_per_minute: Some(60),
                created_at_unix: 100,
                updated_at_unix: 100,
                rotated_at_unix: None,
                expires_at_unix: None,
                revoked_at_unix: None,
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
            parent_action_fingerprint: None,
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
            parent_action_fingerprint: None,
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
                parent_action_fingerprint: None,
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
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
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
            parent_action_fingerprint: None,
        });
        repository.append(StoredAuditEvent {
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
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
            parent_action_fingerprint: None,
        });

        let events = repository.list();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, "accepted");
        assert_eq!(events[1].outcome, "rejected");
    }

    #[test]
    fn runtime_repositories_keep_agent_run_timeline_events() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        block_on(repositories.upsert_agent_run(StoredAgentRun {
            id: "run-1".into(),
            request_id: "fg-1".into(),
            trace_id: Some("trace-1".into()),
            tenant: tenant.clone(),
            status: "running".into(),
            provider: "managed.native-harness".into(),
            turns_executed: 0,
            output_recorded: false,
            started_at_unix: Some(10),
            completed_at_unix: None,
        }))
        .unwrap();
        block_on(repositories.append_agent_run_event(StoredAgentRunEvent {
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
            id: "event-1".into(),
            run_id: "run-1".into(),
            request_id: "fg-1".into(),
            trace_id: Some("trace-1".into()),
            tenant,
            turn: 0,
            kind: "capability.denied".into(),
            target: "cli:bash".into(),
            outcome: "denied".into(),
            tool_call_id: None,
            message: Some("cli is not allowed by capability policy".into()),
            occurred_at_unix: Some(11),
        }))
        .unwrap();

        let run = block_on(repositories.agent_run("run-1")).unwrap();
        assert_eq!(run.provider, "managed.native-harness");
        let events = block_on(repositories.agent_run_events());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "capability.denied");
        assert_eq!(events[0].target, "cli:bash");
        assert_eq!(events[0].outcome, "denied");
    }

    #[test]
    fn self_hosted_worker_telemetry_and_heartbeats_are_retention_bounded() {
        // Untrusted customer-hosted workers ingest heartbeats/telemetry over an
        // endpoint with no per-worker count cap; the stores must evict rather
        // than grow without bound. Retention is wired to the audit bound (10).
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            organization_id: Some("org".into()),
            ..Default::default()
        };

        for index in 0..50 {
            block_on(repositories.append_self_hosted_worker_telemetry_event(
                StoredSelfHostedWorkerTelemetryEvent {
                    id: format!("event-{index}"),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    session_id: None,
                    run_id: None,
                    kind: "log".into(),
                    trust_level: "reported_by_self_hosted_worker".into(),
                    occurred_at_unix: Some(index),
                    ingested_at_unix: Some(index),
                    event_json: "{}".into(),
                    request_id: None,
                    trace_id: None,
                    agent_run_id: None,
                    parent_action_fingerprint: None,
                },
            ))
            .unwrap();
            block_on(repositories.append_self_hosted_worker_heartbeat(
                StoredSelfHostedWorkerHeartbeat {
                    id: format!("heartbeat-{index}"),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    status: "online".into(),
                    reported_at_unix: Some(index),
                    observed_at_unix: Some(index),
                    heartbeat_json: "{}".into(),
                },
            ))
            .unwrap();
        }

        let events = block_on(repositories.self_hosted_worker_telemetry_events());
        assert_eq!(
            events.len(),
            10,
            "telemetry store must be retention-bounded"
        );
        // The most-recent events are retained, oldest evicted.
        assert_eq!(events.last().unwrap().id, "event-49");
        assert_eq!(events.first().unwrap().id, "event-40");

        let heartbeats = block_on(repositories.self_hosted_worker_heartbeats());
        assert_eq!(
            heartbeats.len(),
            10,
            "heartbeat store must be retention-bounded"
        );
        assert_eq!(heartbeats.last().unwrap().id, "heartbeat-49");
    }

    fn sample_agent_run_event(id: &str, run_id: &str, occurred_at: u64) -> StoredAgentRunEvent {
        StoredAgentRunEvent {
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
            id: id.into(),
            run_id: run_id.into(),
            request_id: format!("req-{run_id}"),
            trace_id: None,
            tenant: TenantContext {
                organization_id: Some("org".into()),
                ..Default::default()
            },
            turn: 0,
            kind: "tool.execute".into(),
            target: "cli:bash".into(),
            outcome: "allowed".into(),
            tool_call_id: None,
            message: None,
            occurred_at_unix: Some(occurred_at),
        }
    }

    #[test]
    fn agent_run_event_repository_per_run_cap_evicts_only_that_runs_oldest() {
        let mut repository = InMemoryAgentRunEventRepository::with_limits(3, 100);
        for index in 0..5 {
            repository.append(sample_agent_run_event(
                &format!("a-{index}"),
                "run-a",
                index,
            ));
        }
        repository.append(sample_agent_run_event("b-0", "run-b", 100));
        let events = repository.list();
        let run_a_ids: Vec<&str> = events
            .iter()
            .filter(|event| event.run_id == "run-a")
            .map(|event| event.id.as_str())
            .collect();
        assert_eq!(
            run_a_ids,
            vec!["a-2", "a-3", "a-4"],
            "per-run cap keeps the newest events of the flooding run"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.run_id == "run-b")
                .count(),
            1,
            "other runs are untouched by run-a's flood"
        );
    }

    #[test]
    fn agent_run_event_repository_global_cap_never_evicts_the_active_run() {
        // per-run cap 4, global cap 6: an active run holding its full 4-event
        // window plus enough idle-run events to overflow the global cap must
        // see ONLY the idle runs' events evicted (oldest / least recently
        // appended-to run first).
        let mut repository = InMemoryAgentRunEventRepository::with_limits(4, 6);
        for index in 0..3 {
            repository.append(sample_agent_run_event(
                &format!("idle1-{index}"),
                "run-idle-1",
                index,
            ));
        }
        for index in 0..3 {
            repository.append(sample_agent_run_event(
                &format!("idle2-{index}"),
                "run-idle-2",
                10 + index,
            ));
        }
        // The active run floods; its own window must stay intact.
        for index in 0..4 {
            repository.append(sample_agent_run_event(
                &format!("active-{index}"),
                "run-active",
                20 + index,
            ));
        }
        let events = repository.list();
        assert!(events.len() <= 6, "global cap enforced: {}", events.len());
        let active: Vec<&str> = events
            .iter()
            .filter(|event| event.run_id == "run-active")
            .map(|event| event.id.as_str())
            .collect();
        assert_eq!(
            active,
            vec!["active-0", "active-1", "active-2", "active-3"],
            "the appending (active) run's timeline is never truncated by the global cap"
        );
        // run-idle-1 was the least recently appended-to run, so it is
        // evicted before run-idle-2.
        assert_eq!(
            events
                .iter()
                .filter(|event| event.run_id == "run-idle-1")
                .count(),
            0,
            "least-recently-active run's events are evicted first"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.run_id == "run-idle-2")
                .count(),
            2,
            "the more recently active idle run keeps its newest events"
        );
        // Eviction within the victim run is oldest-first.
        assert!(events.iter().all(|event| event.id != "idle2-0"));
    }

    #[test]
    fn agent_run_event_repository_zero_limits_disable_caps() {
        let mut repository = InMemoryAgentRunEventRepository::with_limits(0, 0);
        for index in 0..100 {
            repository.append(sample_agent_run_event(
                &format!("event-{index}"),
                "run-1",
                index,
            ));
        }
        assert_eq!(repository.list().len(), 100);
    }

    fn sample_artifact(
        id: &str,
        worker_id: &str,
        created_at: u64,
    ) -> StoredSelfHostedWorkerArtifact {
        StoredSelfHostedWorkerArtifact {
            id: id.into(),
            worker_id: worker_id.into(),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                ..Default::default()
            },
            workspace_id: "workspace-1".into(),
            session_id: "session-1".into(),
            run_id: "run-1".into(),
            artifact_name: format!("{id}.tar"),
            content_type: None,
            size_bytes: 1,
            trust_level: "reported_by_self_hosted_worker".into(),
            created_at_unix: Some(created_at),
            artifact_json: "{}".into(),
        }
    }

    #[test]
    fn worker_scoped_repository_caps_distinct_ids_per_worker_with_oldest_eviction() {
        let mut repository = InMemoryWorkerScopedRepository::with_per_worker_limit(2);
        repository.insert("art-1", sample_artifact("art-1", "worker-1", 1));
        repository.insert("art-2", sample_artifact("art-2", "worker-1", 2));
        repository.insert("other-1", sample_artifact("other-1", "worker-2", 3));
        // Updating an EXISTING id is not a new distinct id: no eviction.
        repository.insert("art-2", sample_artifact("art-2", "worker-1", 20));
        assert!(repository.get("art-1").is_some());
        assert_eq!(repository.get("art-2").unwrap().created_at_unix, Some(20));
        // A third distinct id for worker-1 evicts its oldest distinct id.
        repository.insert("art-3", sample_artifact("art-3", "worker-1", 4));
        assert!(
            repository.get("art-1").is_none(),
            "oldest distinct id of the flooding worker is evicted"
        );
        assert!(repository.get("art-2").is_some());
        assert!(repository.get("art-3").is_some());
        assert!(
            repository.get("other-1").is_some(),
            "another worker's records are never evicted by worker-1's flood"
        );
        assert_eq!(repository.list().len(), 3);
    }

    #[test]
    fn worker_scoped_repository_zero_limit_is_unbounded() {
        let mut repository = InMemoryWorkerScopedRepository::with_per_worker_limit(0);
        for index in 0..50 {
            let id = format!("art-{index}");
            repository.insert(id.clone(), sample_artifact(&id, "worker-1", index));
        }
        assert_eq!(repository.list().len(), 50);
    }

    #[test]
    fn in_memory_worker_filtered_reads_match_full_load_semantics() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            organization_id: Some("org".into()),
            ..Default::default()
        };
        block_on(repositories.upsert_self_hosted_worker_registration(
            StoredSelfHostedWorkerRegistration {
                id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_name: "edge".into(),
                status: "registered".into(),
                identity_fingerprint: "fp-1".into(),
                identity_expires_at_unix: None,
                orchestration_enabled: true,
                registered_at_unix: Some(1),
                last_seen_at_unix: None,
                trust_level: "reported_by_self_hosted_worker".into(),
                capability_envelope_json: "{}".into(),
                token_secret: "secret-1".into(),
            },
        ))
        .unwrap();
        for index in 0..3u64 {
            block_on(repositories.append_self_hosted_worker_heartbeat(
                StoredSelfHostedWorkerHeartbeat {
                    id: format!("heartbeat-{index}"),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    status: "online".into(),
                    reported_at_unix: Some(index),
                    observed_at_unix: Some(index),
                    heartbeat_json: "{}".into(),
                },
            ))
            .unwrap();
        }
        for (index, run_id) in [(0u64, "run-1"), (1, "run-1"), (2, "run-2")] {
            block_on(repositories.append_self_hosted_worker_telemetry_event(
                StoredSelfHostedWorkerTelemetryEvent {
                    id: format!("event-{index}"),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    session_id: Some("session-1".into()),
                    run_id: Some(run_id.into()),
                    kind: "lifecycle".into(),
                    trust_level: "reported_by_self_hosted_worker".into(),
                    occurred_at_unix: Some(index),
                    ingested_at_unix: Some(index),
                    event_json: "{}".into(),
                    request_id: None,
                    trace_id: None,
                    agent_run_id: None,
                    parent_action_fingerprint: None,
                },
            ))
            .unwrap();
        }
        block_on(
            repositories
                .upsert_self_hosted_worker_artifact(sample_artifact("art-1", "worker-1", 7)),
        )
        .unwrap();
        block_on(repositories.upsert_self_hosted_worker_checkpoint(
            StoredSelfHostedWorkerCheckpoint {
                id: "ckpt-1".into(),
                worker_id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume".into(),
                size_bytes: 1,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(9),
                checkpoint_json: "{}".into(),
            },
        ))
        .unwrap();

        // Registration lookup.
        assert_eq!(
            block_on(repositories.self_hosted_worker_registration("worker-1"))
                .unwrap()
                .worker_name,
            "edge"
        );
        assert!(block_on(repositories.self_hosted_worker_registration("missing")).is_none());
        // Latest heartbeat.
        assert_eq!(
            block_on(repositories.latest_self_hosted_worker_heartbeat("worker-1"))
                .unwrap()
                .id,
            "heartbeat-2"
        );
        assert!(block_on(repositories.latest_self_hosted_worker_heartbeat("missing")).is_none());
        // Activity stats.
        let stats = block_on(repositories.self_hosted_worker_activity_stats("worker-1"));
        assert_eq!(stats.telemetry_event_count, 3);
        assert_eq!(stats.artifact_count, 1);
        assert_eq!(stats.checkpoint_count, 1);
        assert_eq!(stats.latest_event_at_unix, Some(2));
        assert_eq!(stats.latest_artifact_at_unix, Some(7));
        assert_eq!(stats.latest_checkpoint_at_unix, Some(9));
        assert_eq!(
            block_on(repositories.self_hosted_worker_activity_stats("missing")),
            StoredSelfHostedWorkerActivityStats::default()
        );
        // Run-filtered telemetry keeps ascending order.
        let run_events =
            block_on(repositories.self_hosted_worker_telemetry_events_for_run("run-1", 10));
        assert_eq!(
            run_events
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            vec!["event-0", "event-1"]
        );
        // ... and a smaller limit keeps the NEWEST window.
        let run_events =
            block_on(repositories.self_hosted_worker_telemetry_events_for_run("run-1", 1));
        assert_eq!(
            run_events
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            vec!["event-1"],
            "the newest events win when a run exceeds the timeline limit"
        );
        // Worker-filtered telemetry.
        assert_eq!(
            block_on(repositories.self_hosted_worker_telemetry_events_for_worker("worker-1")).len(),
            3
        );
        assert!(
            block_on(repositories.self_hosted_worker_telemetry_events_for_worker("missing"))
                .is_empty()
        );
        // Keyed lookups.
        assert!(block_on(repositories.self_hosted_worker_artifact("art-1")).is_some());
        assert!(block_on(repositories.self_hosted_worker_artifact("missing")).is_none());
        assert!(block_on(repositories.self_hosted_worker_checkpoint("ckpt-1")).is_some());
        assert!(block_on(repositories.self_hosted_worker_checkpoint("missing")).is_none());
    }

    #[test]
    fn in_memory_agent_run_filtered_reads_and_seed_ids() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            organization_id: Some("org".into()),
            ..Default::default()
        };
        for (run_id, started_at) in [("run-1", 10u64), ("run-2", 20), ("run-3", 30)] {
            block_on(repositories.upsert_agent_run(StoredAgentRun {
                id: run_id.into(),
                request_id: format!("req-{run_id}"),
                trace_id: None,
                tenant: tenant.clone(),
                status: "completed".into(),
                provider: "managed.native-harness".into(),
                turns_executed: 1,
                output_recorded: true,
                started_at_unix: Some(started_at),
                completed_at_unix: Some(started_at + 1),
            }))
            .unwrap();
        }
        block_on(
            repositories.append_agent_run_event(sample_agent_run_event("event-1", "run-1", 12)),
        )
        .unwrap();
        block_on(
            repositories.append_agent_run_event(sample_agent_run_event("event-2", "run-2", 22)),
        )
        .unwrap();

        let run_ids = vec!["run-1".to_string(), "run-3".to_string()];
        let runs = block_on(repositories.agent_runs_by_ids(&run_ids));
        let mut fetched: Vec<&str> = runs.iter().map(|run| run.id.as_str()).collect();
        fetched.sort();
        assert_eq!(fetched, vec!["run-1", "run-3"]);
        assert!(block_on(repositories.agent_runs_by_ids(&[])).is_empty());

        let events = block_on(repositories.agent_run_events_for_runs(&run_ids));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "event-1");

        // Seed ids: most recently seen first, LIMITed.
        let seeds = block_on(repositories.agent_run_summary_seed_ids(None, 10));
        assert_eq!(seeds, vec!["run-3", "run-2", "run-1"]);
        let seeds = block_on(repositories.agent_run_summary_seed_ids(None, 2));
        assert_eq!(
            seeds,
            vec!["run-3", "run-2"],
            "seed scan keeps the most recently seen runs when limited"
        );
        let seeds = block_on(repositories.agent_run_summary_seed_ids(Some("req-run-1"), 10));
        assert_eq!(seeds, vec!["run-1"]);
    }

    #[test]
    fn runtime_repositories_keep_managed_worker_lifecycle_records() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        block_on(
            repositories.upsert_managed_worker_template(StoredManagedWorkerTemplate {
                id: "template-firecracker-codex".into(),
                framework_adapter: "codex".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                enabled: true,
                max_tenant_sessions: Some(12),
                max_workspace_sessions: Some(4),
                created_at_unix: Some(10),
                updated_at_unix: Some(11),
            }),
        )
        .unwrap();
        block_on(
            repositories.upsert_agent_worker_instance(StoredAgentWorkerInstance {
                id: "agent-worker-1".into(),
                process_name: "agent-worker".into(),
                host_id: Some("host-a".into()),
                worker_version: Some("0.1.0".into()),
                status: "online".into(),
                started_at_unix: Some(12),
                last_seen_at_unix: Some(13),
                process_json: r#"{"pid":4242}"#.into(),
            }),
        )
        .unwrap();
        block_on(
            repositories.upsert_managed_worker_session(StoredManagedWorkerSession {
                id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_template_id: "template-firecracker-codex".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "running".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                microvm_id: Some("fc-vm-1".into()),
                capability_envelope_id: "capability-envelope-1".into(),
                requested_at_unix: Some(14),
                started_at_unix: Some(15),
                completed_at_unix: None,
                cleanup_completed_at_unix: None,
                capability_envelope_json: r#"{"id":"capability-envelope-1"}"#.into(),
                resource_limits_json: r#"{"vcpu":2,"memory_mib":1024}"#.into(),
            }),
        )
        .unwrap();
        block_on(repositories.append_managed_worker_lifecycle_event(
            StoredManagedWorkerLifecycleEvent {
                id: "lifecycle-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "running".into(),
                action: "start".into(),
                outcome: "succeeded".into(),
                occurred_at_unix: Some(16),
                evidence_json: r#"{"microvm_id":"fc-vm-1"}"#.into(),
            },
        ))
        .unwrap();
        block_on(repositories.upsert_managed_worker_isolation_selection(
            StoredManagedWorkerIsolationSelection {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                backend_name: "firecracker".into(),
                backend_version: "1.8.0".into(),
                backend_kind: "firecracker_micro_vm".into(),
                host_lifecycle_owner: "agent-worker".into(),
                gateway_controls_backend: false,
                capability_envelope_id: "capability-envelope-1".into(),
                selected_at_unix: Some(16),
            },
        ))
        .unwrap();
        block_on(repositories.upsert_managed_worker_isolation_policy(
            StoredManagedWorkerIsolationPolicy {
                session_id: "session-1".into(),
                cpu_count: 2,
                memory_mib: 1024,
                disk_mib: 4096,
                max_runtime_millis: Some(30_000),
                direct_public_egress: false,
                gateway_control_channel: true,
                governed_egress: true,
                read_only_rootfs: true,
                writable_workspace: true,
                host_path_mounts: false,
            },
        ))
        .unwrap();
        block_on(repositories.upsert_managed_worker_isolation_evidence(
            StoredManagedWorkerIsolationEvidence {
                id: "isolation-evidence-1".into(),
                session_id: "session-1".into(),
                lifecycle_event_id: "lifecycle-1".into(),
                run_id: "run-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                isolation_instance_id: Some("fc-vm-1".into()),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                failure_reason: None,
                occurred_at_unix: Some(16),
                evidence_json: r#"{"microvm_id":"fc-vm-1"}"#.into(),
            },
        ))
        .unwrap();

        assert_eq!(
            block_on(repositories.managed_worker_templates())[0].isolation_backend_kind,
            "firecracker_micro_vm"
        );
        assert_eq!(
            block_on(repositories.agent_worker_instances())[0].process_name,
            "agent-worker"
        );
        assert_eq!(
            block_on(repositories.managed_worker_sessions())[0]
                .microvm_id
                .as_deref(),
            Some("fc-vm-1")
        );
        assert_eq!(
            block_on(repositories.managed_worker_lifecycle_events())[0].action,
            "start"
        );
        assert_eq!(
            block_on(repositories.managed_worker_isolation_selections())[0].host_lifecycle_owner,
            "agent-worker"
        );
        assert!(
            !block_on(repositories.managed_worker_isolation_selections())[0]
                .gateway_controls_backend
        );
        assert!(
            !block_on(repositories.managed_worker_isolation_policies())[0].direct_public_egress
        );
        assert_eq!(
            block_on(repositories.managed_worker_isolation_evidence())[0]
                .isolation_instance_id
                .as_deref(),
            Some("fc-vm-1")
        );
    }

    #[test]
    fn migration_snapshot_includes_managed_worker_lifecycle_records() {
        let source =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let tenant = TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        block_on(
            source.upsert_managed_worker_template(StoredManagedWorkerTemplate {
                id: "template-1".into(),
                framework_adapter: "codex".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                enabled: true,
                max_tenant_sessions: Some(24),
                max_workspace_sessions: Some(6),
                created_at_unix: Some(1),
                updated_at_unix: Some(2),
            }),
        )
        .unwrap();
        block_on(
            source.upsert_agent_worker_instance(StoredAgentWorkerInstance {
                id: "agent-worker-1".into(),
                process_name: "agent-worker".into(),
                host_id: Some("host-a".into()),
                worker_version: Some("0.1.0".into()),
                status: "online".into(),
                started_at_unix: Some(3),
                last_seen_at_unix: Some(4),
                process_json: "{}".into(),
            }),
        )
        .unwrap();
        block_on(
            source.upsert_managed_worker_session(StoredManagedWorkerSession {
                id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_template_id: "template-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "cleaned_up".into(),
                isolation_backend_kind: "firecracker_micro_vm".into(),
                microvm_id: Some("fc-vm-1".into()),
                capability_envelope_id: "capability-envelope-1".into(),
                requested_at_unix: Some(5),
                started_at_unix: Some(6),
                completed_at_unix: Some(7),
                cleanup_completed_at_unix: Some(8),
                capability_envelope_json: "{}".into(),
                resource_limits_json: "{}".into(),
            }),
        )
        .unwrap();
        block_on(
            source.append_managed_worker_lifecycle_event(StoredManagedWorkerLifecycleEvent {
                id: "lifecycle-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                status: "cleaned_up".into(),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                occurred_at_unix: Some(9),
                evidence_json: "{}".into(),
            }),
        )
        .unwrap();
        block_on(source.upsert_managed_worker_isolation_selection(
            StoredManagedWorkerIsolationSelection {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                backend_name: "firecracker".into(),
                backend_version: "1.8.0".into(),
                backend_kind: "firecracker_micro_vm".into(),
                host_lifecycle_owner: "agent-worker".into(),
                gateway_controls_backend: false,
                capability_envelope_id: "capability-envelope-1".into(),
                selected_at_unix: Some(5),
            },
        ))
        .unwrap();
        block_on(source.upsert_managed_worker_isolation_policy(
            StoredManagedWorkerIsolationPolicy {
                session_id: "session-1".into(),
                cpu_count: 1,
                memory_mib: 512,
                disk_mib: 1024,
                max_runtime_millis: Some(30_000),
                direct_public_egress: false,
                gateway_control_channel: true,
                governed_egress: true,
                read_only_rootfs: true,
                writable_workspace: true,
                host_path_mounts: false,
            },
        ))
        .unwrap();
        block_on(source.upsert_managed_worker_isolation_evidence(
            StoredManagedWorkerIsolationEvidence {
                id: "isolation-evidence-1".into(),
                session_id: "session-1".into(),
                lifecycle_event_id: "lifecycle-1".into(),
                run_id: "run-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                agent_worker_instance_id: Some("agent-worker-1".into()),
                isolation_instance_id: Some("fc-vm-1".into()),
                action: "cleanup".into(),
                outcome: "succeeded".into(),
                failure_reason: None,
                occurred_at_unix: Some(9),
                evidence_json: "{}".into(),
            },
        ))
        .unwrap();

        let snapshot = source.export_migration_snapshot().unwrap();
        let counts = snapshot.counts();
        assert_eq!(counts.managed_worker_templates, 1);
        assert_eq!(counts.agent_worker_instances, 1);
        assert_eq!(counts.managed_worker_sessions, 1);
        assert_eq!(counts.managed_worker_lifecycle_events, 1);
        assert_eq!(counts.managed_worker_isolation_selections, 1);
        assert_eq!(counts.managed_worker_isolation_policies, 1);
        assert_eq!(counts.managed_worker_isolation_evidence, 1);

        let target =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        target.import_migration_snapshot(snapshot).unwrap();

        assert_eq!(block_on(target.managed_worker_templates()).len(), 1);
        assert_eq!(block_on(target.agent_worker_instances()).len(), 1);
        assert_eq!(block_on(target.managed_worker_sessions()).len(), 1);
        assert_eq!(block_on(target.managed_worker_lifecycle_events()).len(), 1);
        assert_eq!(
            block_on(target.managed_worker_isolation_selections()).len(),
            1
        );
        assert_eq!(
            block_on(target.managed_worker_isolation_policies()).len(),
            1
        );
        assert_eq!(
            block_on(target.managed_worker_isolation_evidence()).len(),
            1
        );
    }

    fn self_hosted_tenant() -> TenantContext {
        TenantContext {
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            workspace_id: None,
            user_id: None,
            api_key_id: Some("key".into()),
        }
    }

    fn insert_self_hosted_worker_records(repositories: &RuntimeStorageRepositories) {
        let tenant = self_hosted_tenant();
        block_on(repositories.upsert_self_hosted_worker_registration(
            StoredSelfHostedWorkerRegistration {
                id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_name: "customer-worker-a".into(),
                status: "online".into(),
                identity_fingerprint: "sha256:worker-identity".into(),
                identity_expires_at_unix: Some(2_000),
                orchestration_enabled: true,
                registered_at_unix: Some(20),
                last_seen_at_unix: Some(21),
                trust_level: "reported_by_self_hosted_worker".into(),
                capability_envelope_json: r#"{"frameworks":["codex"]}"#.into(),
                token_secret: "transport-secret-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            },
        ))
        .unwrap();
        block_on(repositories.append_self_hosted_worker_heartbeat(
            StoredSelfHostedWorkerHeartbeat {
                id: "heartbeat-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                status: "online".into(),
                reported_at_unix: Some(22),
                observed_at_unix: Some(23),
                heartbeat_json: r#"{"load":0.42}"#.into(),
            },
        ))
        .unwrap();
        block_on(repositories.append_self_hosted_worker_telemetry_event(
            StoredSelfHostedWorkerTelemetryEvent {
                id: "telemetry-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: Some("session-1".into()),
                run_id: Some("run-1".into()),
                kind: "tool_call".into(),
                trust_level: "reported_by_self_hosted_worker".into(),
                occurred_at_unix: Some(24),
                ingested_at_unix: Some(25),
                event_json: r#"{"tool":"bash"}"#.into(),
                request_id: None,
                trace_id: None,
                agent_run_id: None,
                parent_action_fingerprint: None,
            },
        ))
        .unwrap();
        block_on(
            repositories.upsert_self_hosted_worker_artifact(StoredSelfHostedWorkerArtifact {
                id: "artifact-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: Some("text/plain".into()),
                size_bytes: 128,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(26),
                artifact_json: r#"{"path":"stdout.log"}"#.into(),
            }),
        )
        .unwrap();
        block_on(repositories.upsert_self_hosted_worker_checkpoint(
            StoredSelfHostedWorkerCheckpoint {
                id: "checkpoint-1".into(),
                worker_id: "self-hosted-worker-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: 256,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(27),
                checkpoint_json: r#"{"version":1}"#.into(),
            },
        ))
        .unwrap();
        block_on(
            repositories.upsert_self_hosted_run_dispatch(StoredSelfHostedRunDispatch {
                dispatch_id: "dispatch-1".into(),
                action: "start_run".into(),
                tenant_id: "org".into(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                framework_adapter: "codex".into(),
                required_capabilities: vec!["shell".into()],
                workload_ref: "self-hosted-workload://self-hosted-worker-1".into(),
                queued_at_unix: Some(28),
                assigned_worker_id: Some("self-hosted-worker-1".into()),
                lease_id: Some("dispatch-1:attempt-1".into()),
                lease_expires_at_unix: Some(58),
                attempt: 1,
                acknowledged_status: Some("accepted".into()),
                acknowledged_at_unix: Some(29),
                request_id: Some("fg-dispatch-1".into()),
                trace_id: Some("trace-dispatch-1".into()),
                agent_run_id: Some("self-hosted-run-1".into()),
                // #307: the parent governed action's fingerprint survives the
                // in-memory round-trip / migration snapshot like the #305
                // correlation keys.
                parent_action_fingerprint: Some(format!("sha256:{}", "ab".repeat(32))),
            }),
        )
        .unwrap();
    }

    #[test]
    fn runtime_repositories_keep_self_hosted_worker_records() {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        insert_self_hosted_worker_records(&repositories);

        let registrations = block_on(repositories.self_hosted_worker_registrations());
        assert_eq!(registrations.len(), 1);
        assert_eq!(
            registrations[0].trust_level,
            "reported_by_self_hosted_worker"
        );
        assert!(registrations[0].orchestration_enabled);
        assert_eq!(
            block_on(repositories.self_hosted_worker_heartbeats())[0].status,
            "online"
        );
        assert_eq!(
            block_on(repositories.self_hosted_worker_telemetry_events())[0].kind,
            "tool_call"
        );
        assert_eq!(
            block_on(repositories.self_hosted_worker_artifacts())[0].artifact_name,
            "stdout.log"
        );
        assert_eq!(
            block_on(repositories.self_hosted_worker_checkpoints())[0].checkpoint_name,
            "resume-state"
        );
        assert_eq!(
            block_on(repositories.self_hosted_run_dispatches())[0]
                .lease_id
                .as_deref(),
            Some("dispatch-1:attempt-1")
        );
        // #307: the parent-action identity round-trips with the dispatch.
        assert_eq!(
            block_on(repositories.self_hosted_run_dispatches())[0].parent_action_fingerprint,
            Some(format!("sha256:{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn migration_snapshot_includes_self_hosted_worker_records() {
        let source =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        insert_self_hosted_worker_records(&source);

        let snapshot = source.export_migration_snapshot().unwrap();
        let counts = snapshot.counts();
        assert_eq!(counts.self_hosted_worker_registrations, 1);
        assert_eq!(counts.self_hosted_worker_heartbeats, 1);
        assert_eq!(counts.self_hosted_worker_telemetry_events, 1);
        assert_eq!(counts.self_hosted_worker_artifacts, 1);
        assert_eq!(counts.self_hosted_worker_checkpoints, 1);
        assert_eq!(counts.self_hosted_run_dispatches, 1);

        let target =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        target.import_migration_snapshot(snapshot).unwrap();

        assert_eq!(block_on(target.self_hosted_worker_registrations()).len(), 1);
        assert_eq!(block_on(target.self_hosted_worker_heartbeats()).len(), 1);
        assert_eq!(
            block_on(target.self_hosted_worker_telemetry_events()).len(),
            1
        );
        assert_eq!(block_on(target.self_hosted_worker_artifacts()).len(), 1);
        assert_eq!(block_on(target.self_hosted_worker_checkpoints()).len(), 1);
        assert_eq!(block_on(target.self_hosted_run_dispatches()).len(), 1);
        assert_eq!(
            block_on(target.self_hosted_run_dispatches())[0].required_capabilities,
            vec!["shell".to_string()]
        );
        // #307: the parent-action identity survives the migration snapshot.
        assert_eq!(
            block_on(target.self_hosted_run_dispatches())[0].parent_action_fingerprint,
            Some(format!("sha256:{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn asset_variants_and_channels_roundtrip_in_memory() {
        // #260: two platform variants of one logical version coexist as
        // distinct rows, and channel pointers create/move/delete idempotently.
        let repos =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        let linux = StoredAsset {
            id: stored_asset_variant_id("t", "cli_tool", "rg", "1.0.0", "linux-x86_64"),
            tenant_id: "t".into(),
            project_id: None,
            asset_type: "cli_tool".into(),
            name: "rg".into(),
            version: "1.0.0".into(),
            content_type: "application/octet-stream".into(),
            content_hash: "a".into(),
            size_bytes: 1,
            content: vec![1],
            storage_uri: None,
            variant: "linux-x86_64".into(),
            yanked: false,
            visibility: AssetVisibility::Visible,
            created_at_unix: 0,
            updated_at_unix: 0,
        };
        let darwin = StoredAsset {
            id: stored_asset_variant_id("t", "cli_tool", "rg", "1.0.0", "darwin-arm64"),
            variant: "darwin-arm64".into(),
            content_hash: "b".into(),
            ..linux.clone()
        };
        block_on(repos.upsert_asset(linux.clone())).unwrap();
        block_on(repos.upsert_asset(darwin)).unwrap();
        assert_eq!(
            block_on(repos.list_assets("t", Some("cli_tool")))
                .unwrap()
                .len(),
            2,
            "both platform variants must persist as distinct rows"
        );

        let channel = StoredAssetChannel {
            id: asset_channel_id("t", "cli_tool", "rg", "latest"),
            tenant_id: "t".into(),
            asset_type: "cli_tool".into(),
            name: "rg".into(),
            channel: "latest".into(),
            version: "1.0.0".into(),
            updated_at_unix: 5,
        };
        block_on(repos.upsert_asset_channel(channel.clone())).unwrap();
        // Moving the pointer updates in place, not appends.
        let moved = StoredAssetChannel {
            version: "1.1.0".into(),
            updated_at_unix: 6,
            ..channel
        };
        block_on(repos.upsert_asset_channel(moved)).unwrap();
        let channels = block_on(repos.list_asset_channels("t", "cli_tool", "rg")).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].version, "1.1.0");

        assert!(block_on(
            repos.delete_asset_channel(&asset_channel_id("t", "cli_tool", "rg", "latest"))
        )
        .unwrap());
        assert!(block_on(repos.list_asset_channels("t", "cli_tool", "rg"))
            .unwrap()
            .is_empty());
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
            vec![StorageProviderKind::Supabase, StorageProviderKind::Postgres,]
        );

        assert!(
            RuntimeStorageBackend::new(StorageProviderKind::TursoLibsql, true, Vec::new()).is_err()
        );
        assert!(RuntimeStorageBackend::new(StorageProviderKind::Mysql, true, Vec::new()).is_err());

        let supabase_backend =
            RuntimeStorageBackend::new(StorageProviderKind::Supabase, true, Vec::new()).unwrap();
        assert!(supabase_backend.evidence().durable);
        assert!(supabase_backend.evidence().implemented);

        let postgres_backend =
            RuntimeStorageBackend::new(StorageProviderKind::Postgres, true, Vec::new()).unwrap();
        assert!(postgres_backend.evidence().durable);
        assert!(postgres_backend.evidence().implemented);
    }

    #[test]
    fn postgres_tls_ca_path_errors_before_connecting() {
        let error = postgres_empty(
            DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(),
            true,
            PostgresStorageConfig {
                dsn: "host=127.0.0.1 port=1 user=postgres dbname=ferrogate".into(),
                pool_size: 1,
                pool_acquire_timeout_millis: 1_000,
                tls_mode: PostgresTlsMode::VerifyFull,
                tls_ca_cert_path: Some("/tmp/ferrogate-missing-postgres-ca.pem".into()),
                connect_timeout_secs: 1,
                statement_timeout_millis: 1_000,
                schema: None,
                search_path: Vec::new(),
            },
            false,
            10,
            10,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("storage.postgres_tls_ca_cert_path"));
    }

    #[test]
    fn storage_error_sanitizer_redacts_postgres_credentials() {
        let keyword = sanitize_storage_error(
            "connection failed for host=db.example user=postgres password=super-secret dbname=postgres",
        );
        assert!(keyword.contains("password=[redacted]"));
        assert!(!keyword.contains("super-secret"));

        let url = sanitize_storage_error(
            "failed to connect to postgresql://postgres:service-role-token@db.example:5432/postgres",
        );
        assert!(url.contains("postgresql://postgres:[redacted]@db.example:5432/postgres"));
        assert!(!url.contains("service-role-token"));
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
            .replace_control_plane(ControlPlaneDocuments {
                api_keys: vec![("key_a".into(), r#"{"id":"key_a","name":"A"}"#.to_string())],
                policies: vec![(
                    "deny_a".into(),
                    r#"{"name":"deny_a","effect":"deny"}"#.to_string(),
                )],
                plugin_registrations: vec![(
                    "tool.echo".into(),
                    r#"{"id":"tool.echo","source":"builtin"}"#.to_string(),
                )],
                mcp_servers: vec![(
                    "github".into(),
                    r#"{"name":"github","transport":"streamable_http"}"#.to_string(),
                )],
                ..ControlPlaneDocuments::default()
            })
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

        block_on(repositories.append_request_log(StoredRequestLog {
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
            parent_action_fingerprint: None,
        }));
        block_on(repositories.append_request_log(StoredRequestLog {
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
            parent_action_fingerprint: None,
        }));

        let page = block_on(repositories.request_logs_page(0, 10));
        assert_eq!(page.total, 1);
        assert_eq!(page.data[0].request_id, "fg-2");

        block_on(
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
            }),
        )
        .unwrap();
        assert_eq!(
            block_on(repositories.usage_aggregates())[0]
                .usage
                .total_tokens,
            3
        );
    }

    fn memory_repositories() -> RuntimeStorageRepositories {
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 0, 0)
    }

    fn sample_tenant(id: &str, slug: &str) -> StoredTenantAccount {
        StoredTenantAccount {
            id: id.into(),
            name: format!("Tenant {id}"),
            slug: slug.into(),
            status: "active".into(),
            plan_id: "free".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_project(id: &str, tenant_id: &str, slug: &str) -> StoredProject {
        StoredProject {
            id: id.into(),
            tenant_id: tenant_id.into(),
            name: format!("Project {id}"),
            slug: slug.into(),
            status: "active".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_workspace(
        id: &str,
        project_id: &str,
        tenant_id: &str,
        slug: &str,
    ) -> StoredWorkspace {
        StoredWorkspace {
            id: id.into(),
            project_id: project_id.into(),
            tenant_id: tenant_id.into(),
            name: format!("Workspace {id}"),
            slug: slug.into(),
            environment: "dev".into(),
            status: "active".into(),
            created_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn sample_api_key(id: &str, prefix: &str) -> StoredApiKey {
        StoredApiKey {
            id: id.into(),
            workspace_id: "ws-dev".into(),
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            name: format!("API key {id}"),
            key_prefix: prefix.into(),
            key_hash: format!("sha256:{id}"),
            last4: "wxyz".into(),
            enabled: true,
            scopes: vec!["chat.completions".into()],
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            tenant: TenantContext {
                organization_id: Some("tenant-a".into()),
                team_id: None,
                project_id: Some("project-a".into()),
                workspace_id: Some("ws-dev".into()),
                user_id: None,
                api_key_id: Some(id.into()),
            },
            monthly_token_budget: None,
            request_limit_per_minute: None,
            created_at_unix: 100,
            updated_at_unix: 100,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        }
    }

    #[test]
    fn hierarchy_upsert_get_list_roundtrip() {
        let repositories = memory_repositories();

        block_on(repositories.upsert_tenant_account(sample_tenant("tenant-a", "tenant-a")))
            .unwrap();
        block_on(repositories.upsert_project(sample_project("project-a", "tenant-a", "core")))
            .unwrap();
        block_on(repositories.upsert_workspace(sample_workspace(
            "ws-dev",
            "project-a",
            "tenant-a",
            "dev",
        )))
        .unwrap();

        assert_eq!(
            block_on(repositories.get_tenant_account("tenant-a"))
                .unwrap()
                .unwrap()
                .slug,
            "tenant-a"
        );
        assert_eq!(
            block_on(repositories.get_project("project-a"))
                .unwrap()
                .unwrap()
                .tenant_id,
            "tenant-a"
        );
        let workspace = block_on(repositories.get_workspace("ws-dev"))
            .unwrap()
            .unwrap();
        assert_eq!(workspace.project_id, "project-a");
        assert_eq!(workspace.tenant_id, "tenant-a");
        assert_eq!(workspace.environment, "dev");

        assert_eq!(
            block_on(repositories.list_tenant_accounts()).unwrap().len(),
            1
        );
        assert_eq!(block_on(repositories.list_projects()).unwrap().len(), 1);
        assert_eq!(block_on(repositories.list_workspaces()).unwrap().len(), 1);
    }

    #[test]
    fn hierarchy_upsert_overwrites_existing_record() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_workspace(sample_workspace(
            "ws-dev",
            "project-a",
            "tenant-a",
            "dev",
        )))
        .unwrap();
        let mut updated = sample_workspace("ws-dev", "project-a", "tenant-a", "dev");
        updated.name = "Renamed workspace".into();
        updated.status = "disabled".into();
        block_on(repositories.upsert_workspace(updated)).unwrap();

        let stored = block_on(repositories.get_workspace("ws-dev"))
            .unwrap()
            .unwrap();
        assert_eq!(stored.name, "Renamed workspace");
        assert_eq!(stored.status, "disabled");
        assert_eq!(block_on(repositories.list_workspaces()).unwrap().len(), 1);
    }

    #[test]
    fn resolve_workspace_scope_returns_full_attribution_chain() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_tenant_account(sample_tenant("tenant-a", "tenant-a")))
            .unwrap();
        block_on(repositories.upsert_project(sample_project("project-a", "tenant-a", "core")))
            .unwrap();
        block_on(repositories.upsert_workspace(sample_workspace(
            "ws-prod",
            "project-a",
            "tenant-a",
            "prod",
        )))
        .unwrap();

        let scope = block_on(repositories.resolve_workspace_scope("ws-prod"))
            .unwrap()
            .expect("workspace resolves");
        assert_eq!(scope.tenant_id, "tenant-a");
        assert_eq!(scope.project_id, "project-a");
        assert_eq!(scope.workspace_id, "ws-prod");

        // A resolved scope backfills a TenantContext with the full chain.
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);
        assert_eq!(tenant.organization_id.as_deref(), Some("tenant-a"));
        assert_eq!(tenant.project_id.as_deref(), Some("project-a"));
        assert_eq!(tenant.workspace_id.as_deref(), Some("ws-prod"));
    }

    #[test]
    fn resolve_workspace_scope_unknown_workspace_is_none() {
        let repositories = memory_repositories();
        assert!(block_on(repositories.resolve_workspace_scope("missing"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn stored_workspace_deserializes_with_default_fields() {
        // A minimal document (predating environment/status defaults) still loads.
        let json = r#"{
            "id": "ws-1",
            "project_id": "project-1",
            "tenant_id": "tenant-1",
            "name": "Workspace 1",
            "slug": "ws-1"
        }"#;
        let workspace: StoredWorkspace = serde_json::from_str(json).unwrap();
        assert_eq!(workspace.environment, "default");
        assert_eq!(workspace.status, "active");
        assert_eq!(workspace.created_at_unix, 0);
    }

    #[test]
    fn api_key_record_upsert_get_list_and_prefix_lookup_roundtrip() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_api_key_record(sample_api_key("key-a", "fg_live"))).unwrap();
        block_on(repositories.upsert_api_key_record(sample_api_key("key-b", "fg_live"))).unwrap();
        block_on(repositories.upsert_api_key_record(sample_api_key("key-c", "fg_test"))).unwrap();

        let key = block_on(repositories.get_api_key_record("key-a"))
            .unwrap()
            .expect("api key is stored");
        assert_eq!(key.workspace_id, "ws-dev");
        assert_eq!(key.tenant.organization_id.as_deref(), Some("tenant-a"));
        assert_eq!(key.tenant.project_id.as_deref(), Some("project-a"));
        assert_eq!(key.tenant.workspace_id.as_deref(), Some("ws-dev"));
        assert_eq!(key.tenant.api_key_id.as_deref(), Some("key-a"));

        assert_eq!(
            block_on(repositories.list_api_key_records()).unwrap().len(),
            3
        );
        let live_candidates =
            block_on(repositories.find_api_key_records_by_prefix("fg_live")).unwrap();
        assert_eq!(live_candidates.len(), 2);
        assert!(live_candidates
            .iter()
            .all(|candidate| candidate.key_hash != "fg_live"));
    }

    #[test]
    fn api_key_record_upsert_overwrites_lifecycle_state() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_api_key_record(sample_api_key("key-a", "fg_live"))).unwrap();

        let mut updated = sample_api_key("key-a", "fg_live");
        updated.enabled = false;
        updated.revoked_at_unix = Some(200);
        updated.updated_at_unix = 200;
        block_on(repositories.upsert_api_key_record(updated)).unwrap();

        let stored = block_on(repositories.get_api_key_record("key-a"))
            .unwrap()
            .unwrap();
        assert!(!stored.enabled);
        assert_eq!(stored.revoked_at_unix, Some(200));
        assert_eq!(
            block_on(repositories.list_api_key_records()).unwrap().len(),
            1
        );
    }

    #[test]
    fn quota_policy_upsert_get_list_and_delete_roundtrip() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Tenant, "tenant-a"),
            scope_type: QuotaScopeKind::Tenant,
            scope_id: "tenant-a".into(),
            model_allowlist: vec!["fast-chat".into(), "smart-chat".into()],
            rpm_limit: Some(1_000),
            tpm_limit: Some(500_000),
            monthly_budget_usd: Some(250.0),
            asset_storage_quota_bytes: Some(104_857_600),
            alert_threshold_pcts: vec![],
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();
        block_on(repositories.upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Key, "key-a"),
            scope_type: QuotaScopeKind::Key,
            scope_id: "key-a".into(),
            model_allowlist: vec!["fast-chat".into()],
            rpm_limit: Some(60),
            tpm_limit: None,
            monthly_budget_usd: None,
            asset_storage_quota_bytes: None,
            alert_threshold_pcts: vec![],
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        let tenant_policy =
            block_on(repositories.get_quota_policy(QuotaScopeKind::Tenant, "tenant-a"))
                .unwrap()
                .expect("tenant policy is stored");
        assert_eq!(tenant_policy.rpm_limit, Some(1_000));
        assert_eq!(tenant_policy.monthly_budget_usd, Some(250.0));
        assert_eq!(tenant_policy.asset_storage_quota_bytes, Some(104_857_600));
        assert_eq!(
            tenant_policy.model_allowlist,
            vec!["fast-chat", "smart-chat"]
        );

        assert!(block_on(
            repositories.get_quota_policy(QuotaScopeKind::Workspace, "no-such-workspace")
        )
        .unwrap()
        .is_none());
        assert_eq!(
            block_on(repositories.list_quota_policies()).unwrap().len(),
            2
        );

        assert!(block_on(repositories.delete_quota_policy(QuotaScopeKind::Key, "key-a")).unwrap());
        assert_eq!(
            block_on(repositories.list_quota_policies()).unwrap().len(),
            1
        );
        assert!(!block_on(repositories.delete_quota_policy(QuotaScopeKind::Key, "key-a")).unwrap());
    }

    #[test]
    fn quota_policy_upsert_overwrites_existing_scope() {
        let repositories = memory_repositories();
        block_on(repositories.upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Workspace, "ws-a"),
            scope_type: QuotaScopeKind::Workspace,
            scope_id: "ws-a".into(),
            model_allowlist: vec![],
            rpm_limit: Some(100),
            tpm_limit: None,
            monthly_budget_usd: None,
            asset_storage_quota_bytes: None,
            alert_threshold_pcts: vec![],
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        block_on(repositories.upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Workspace, "ws-a"),
            scope_type: QuotaScopeKind::Workspace,
            scope_id: "ws-a".into(),
            model_allowlist: vec!["fast-chat".into()],
            rpm_limit: Some(50),
            tpm_limit: Some(10_000),
            monthly_budget_usd: Some(10.0),
            asset_storage_quota_bytes: None,
            alert_threshold_pcts: vec![],
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
            enabled: false,
            created_at_unix: 1,
            updated_at_unix: 2,
        }))
        .unwrap();

        let policy = block_on(repositories.get_quota_policy(QuotaScopeKind::Workspace, "ws-a"))
            .unwrap()
            .unwrap();
        assert_eq!(policy.rpm_limit, Some(50));
        assert_eq!(policy.tpm_limit, Some(10_000));
        assert_eq!(policy.monthly_budget_usd, Some(10.0));
        assert_eq!(policy.asset_storage_quota_bytes, None);
        assert!(!policy.enabled);
        assert_eq!(
            block_on(repositories.list_quota_policies()).unwrap().len(),
            1
        );
    }

    #[test]
    fn period_month_from_unix_matches_known_calendar_dates() {
        assert_eq!(period_month_from_unix(0), "1970-01");
        // 2026-07-03T00:00:00Z, sanity-checked against `date -u -d @1783036800`.
        assert_eq!(period_month_from_unix(1_783_036_800), "2026-07");
        // Leap-year boundary: 2024-02-29T12:00:00Z.
        assert_eq!(period_month_from_unix(1_709_208_000), "2024-02");
        // Year boundary: 2025-12-31T23:59:59Z should still read December.
        assert_eq!(period_month_from_unix(1_767_225_599), "2025-12");
        // One second later crosses into January 2026.
        assert_eq!(period_month_from_unix(1_767_225_600), "2026-01");
    }

    #[test]
    fn usage_monthly_rollup_increments_across_scopes_and_accumulates() {
        let repositories = memory_repositories();
        let tenant = TenantContext {
            organization_id: Some("tenant-a".into()),
            team_id: None,
            project_id: Some("project-a".into()),
            workspace_id: Some("workspace-a".into()),
            user_id: None,
            api_key_id: Some("key-a".into()),
        };

        block_on(repositories.append_billing_event(BillingEvent {
            request_id: "req-1".into(),
            trace_id: None,
            provider_attempt: ferrogate_billing::ProviderAttempt::for_request("req-1", 0),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: tenant.clone(),
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(100, 50, 150),
            usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1_783_036_800),
            cost_usd: Some(0.01),
            latency_ms: Some(120),
            metadata: std::collections::BTreeMap::new(),
            wallet_delta_credits: None,
            wallet_balance_after_credits: None,
        }))
        .unwrap();
        block_on(repositories.append_billing_event(BillingEvent {
            request_id: "req-2".into(),
            trace_id: None,
            provider_attempt: ferrogate_billing::ProviderAttempt::for_request("req-2", 0),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: tenant.clone(),
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(10, 5, 15),
            usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
            status_code: 500,
            occurred_at_unix: Some(1_783_036_800),
            cost_usd: Some(0.002),
            latency_ms: Some(80),
            metadata: std::collections::BTreeMap::new(),
            wallet_delta_credits: None,
            wallet_balance_after_credits: None,
        }))
        .unwrap();

        for (scope_type, scope_id) in [
            (QuotaScopeKind::Tenant, "tenant-a"),
            (QuotaScopeKind::Project, "project-a"),
            (QuotaScopeKind::Workspace, "workspace-a"),
            (QuotaScopeKind::Key, "key-a"),
        ] {
            let rollup =
                block_on(repositories.get_usage_monthly_rollup(scope_type, scope_id, "2026-07"))
                    .unwrap()
                    .unwrap_or_else(|| panic!("rollup missing for {scope_type:?}/{scope_id}"));
            assert_eq!(rollup.total_tokens, 165, "scope {scope_type:?}/{scope_id}");
            assert_eq!(rollup.request_count, 2, "scope {scope_type:?}/{scope_id}");
            assert_eq!(rollup.error_count, 1, "scope {scope_type:?}/{scope_id}");
            assert!(
                (rollup.cost_usd - 0.012).abs() < 1e-9,
                "scope {scope_type:?}/{scope_id} cost_usd={}",
                rollup.cost_usd
            );
        }

        assert!(block_on(repositories.get_usage_monthly_rollup(
            QuotaScopeKind::Tenant,
            "tenant-a",
            "2026-06"
        ))
        .unwrap()
        .is_none());
        assert_eq!(
            block_on(repositories.list_usage_monthly_rollups())
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn usage_metadata_rollup_accumulates_per_value_alongside_scope_rollups() {
        let repositories = memory_repositories();
        let tenant = TenantContext {
            organization_id: Some("tenant-b".into()),
            team_id: None,
            project_id: None,
            workspace_id: None,
            user_id: None,
            api_key_id: None,
        };

        let event =
            |request_id: &str, customer_id: &str, prompt_tokens: u64, cost_usd: f64| BillingEvent {
                request_id: request_id.into(),
                trace_id: None,
                provider_attempt: ferrogate_billing::ProviderAttempt::for_request(request_id, 0),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                cluster_id: None,
                node_id: None,
                tenant: tenant.clone(),
                logical_model: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                usage: TokenUsage::new(prompt_tokens, 0, prompt_tokens),
                usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
                status_code: 200,
                occurred_at_unix: Some(1_783_036_800),
                cost_usd: Some(cost_usd),
                latency_ms: None,
                metadata: std::collections::BTreeMap::from([(
                    "customer_id".to_string(),
                    customer_id.to_string(),
                )]),
                wallet_delta_credits: None,
                wallet_balance_after_credits: None,
            };

        block_on(repositories.append_billing_event(event("req-meta-1", "acme", 100, 0.01)))
            .unwrap();
        block_on(repositories.append_billing_event(event("req-meta-2", "acme", 50, 0.005)))
            .unwrap();
        block_on(repositories.append_billing_event(event("req-meta-3", "globex", 10, 0.001)))
            .unwrap();

        // Platform-operator view (organization_id == None): the global
        // cross-tenant breakdown.
        let acme = block_on(repositories.list_usage_metadata_rollups("customer_id", None))
            .unwrap()
            .into_iter()
            .find(|rollup| rollup.metadata_value == "acme")
            .expect("acme rollup must exist");
        assert_eq!(acme.request_count, 2);
        assert_eq!(acme.total_tokens, 150);
        assert!((acme.cost_usd - 0.015).abs() < 1e-9, "{}", acme.cost_usd);
        assert_eq!(acme.organization_id, "tenant-b");

        let globex = block_on(repositories.list_usage_metadata_rollups("customer_id", None))
            .unwrap()
            .into_iter()
            .find(|rollup| rollup.metadata_value == "globex")
            .expect("globex rollup must exist");
        assert_eq!(globex.request_count, 1);
        assert_eq!(globex.total_tokens, 10);

        // A key nothing was tagged with returns no rows -- proves rollups
        // are scoped per requested key, not a flattened union of every key
        // ever seen.
        assert!(
            block_on(repositories.list_usage_metadata_rollups("no_such_key", None))
                .unwrap()
                .is_empty()
        );

        // Per-tenant scoping (issue #226): the owning tenant sees its own rows;
        // a different tenant sees none of them.
        let tenant_b_scoped =
            block_on(repositories.list_usage_metadata_rollups("customer_id", Some("tenant-b")))
                .unwrap();
        assert_eq!(
            tenant_b_scoped.len(),
            2,
            "tenant-b must see its own acme + globex rows"
        );
        assert!(tenant_b_scoped
            .iter()
            .all(|rollup| rollup.organization_id == "tenant-b"));
        assert!(
            block_on(repositories.list_usage_metadata_rollups("customer_id", Some("other-tenant")))
                .unwrap()
                .is_empty(),
            "a different tenant must not see tenant-b's metadata breakdown"
        );

        // The same 3 events also drove the existing tenant-scope rollup
        // (issue #171 adds a new dimension, it doesn't disturb the old one).
        let tenant_rollup = block_on(repositories.get_usage_monthly_rollup(
            QuotaScopeKind::Tenant,
            "tenant-b",
            "2026-07",
        ))
        .unwrap()
        .expect("tenant rollup must still accumulate normally");
        assert_eq!(tenant_rollup.request_count, 3);
        assert_eq!(tenant_rollup.total_tokens, 160);
    }

    #[test]
    fn wallet_balance_adjusts_atomically_and_is_opt_in_per_tenant() {
        let repositories = memory_repositories();

        // No wallet row yet: adjusting a nonexistent wallet is a no-op,
        // not an error -- wallets are opt-in (issue #169).
        assert!(
            block_on(repositories.adjust_wallet_balance("tenant-wallet", -100, 1))
                .unwrap()
                .is_none()
        );
        assert!(block_on(repositories.get_wallet("tenant-wallet"))
            .unwrap()
            .is_none());

        block_on(repositories.upsert_wallet(StoredWallet {
            id: "tenant-wallet".into(),
            tenant_id: "tenant-wallet".into(),
            balance_credits: 1_000,
            auto_recharge_threshold_credits: Some(200),
            auto_recharge_amount_credits: Some(500),
            dunning: false,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        // Debit: a settled request costs 300 credits.
        let after_debit = block_on(repositories.adjust_wallet_balance("tenant-wallet", -300, 2))
            .unwrap()
            .expect("wallet exists, must return the updated row");
        assert_eq!(after_debit.balance_credits, 700);
        assert_eq!(after_debit.updated_at_unix, 2);

        // Top-up (positive delta): a manual or auto-recharge credit.
        let after_topup = block_on(repositories.adjust_wallet_balance("tenant-wallet", 500, 3))
            .unwrap()
            .unwrap();
        assert_eq!(after_topup.balance_credits, 1_200);

        // Dunning state: set, then cleared by a later successful charge.
        block_on(repositories.set_wallet_dunning("tenant-wallet", true, 4)).unwrap();
        assert!(
            block_on(repositories.get_wallet("tenant-wallet"))
                .unwrap()
                .unwrap()
                .dunning
        );
        block_on(repositories.set_wallet_dunning("tenant-wallet", false, 5)).unwrap();
        assert!(
            !block_on(repositories.get_wallet("tenant-wallet"))
                .unwrap()
                .unwrap()
                .dunning
        );

        assert_eq!(block_on(repositories.list_wallets()).unwrap().len(), 1);
    }

    #[test]
    fn settle_wallet_balance_applies_a_settlement_id_at_most_once() {
        // The auto-recharge double-credit fix credits the wallet via
        // settle_wallet_balance keyed on the Stripe charge id, relying on this
        // idempotency: a replayed settlement id must NOT re-apply the delta.
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        block_on(repositories.upsert_wallet(StoredWallet {
            id: "tenant-x".into(),
            tenant_id: "tenant-x".into(),
            balance_credits: 100,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        // First application of the charge credit: applied, balance 100 -> 600.
        let first = block_on(repositories.settle_wallet_balance(
            "auto-recharge-credit:ch_123",
            "tenant-x",
            500,
            2,
        ))
        .unwrap();
        assert!(first.newly_applied);
        assert_eq!(first.settlement.balance_after_credits, Some(600));

        // Replay of the SAME charge (a concurrent same-key recharge): NOT
        // re-applied, balance stays 600 -- no double credit.
        let replay = block_on(repositories.settle_wallet_balance(
            "auto-recharge-credit:ch_123",
            "tenant-x",
            500,
            3,
        ))
        .unwrap();
        assert!(!replay.newly_applied);
        assert_eq!(
            block_on(repositories.get_wallet("tenant-x"))
                .unwrap()
                .unwrap()
                .balance_credits,
            600,
            "a replayed settlement id must not double-credit the wallet"
        );
    }

    fn workflow_budget_repositories() -> RuntimeStorageRepositories {
        RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10)
    }

    #[test]
    fn workflow_run_budget_accumulates_spend_across_steps_and_fails_closed_on_exhaustion() {
        // #279 acceptance: a run with a cost ceiling accumulates spend across
        // steps and stops BEFORE exceeding it; the breach is fail-closed (no
        // spend applied) with a distinct dimension.
        let repositories = workflow_budget_repositories();
        let budget = block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-1",
            "tenant-1",
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(100),
                ..WorkflowRunBudgetCaps::default()
            },
            1,
        ))
        .unwrap();
        let id = budget.id.clone();

        // Two steps accumulate to 80 credits.
        for _ in 0..2 {
            assert!(matches!(
                block_on(repositories.debit_workflow_run_budget(&id, 40, 0, 0, 2)).unwrap(),
                WorkflowBudgetDebit::Applied(_)
            ));
        }
        let budget = block_on(repositories.get_workflow_run_budget(&id))
            .unwrap()
            .unwrap();
        assert_eq!(budget.spent_credits, 80);
        assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_ACTIVE);

        // A third step (30) would take the run to 110 > 100 -> fail closed on
        // cost, WITHOUT applying the 30, and the run flips to exhausted.
        match block_on(repositories.debit_workflow_run_budget(&id, 30, 0, 0, 3)).unwrap() {
            WorkflowBudgetDebit::Exceeded { dimension, budget } => {
                assert_eq!(dimension, WorkflowBudgetDimension::Cost);
                assert_eq!(dimension.denial_code(), "workflow_budget_exceeded:cost");
                assert_eq!(budget.spent_credits, 80, "denied spend must not be applied");
                assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_EXHAUSTED);
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }

        // Every further step is denied while exhausted, even a zero-cost one.
        assert!(matches!(
            block_on(repositories.debit_workflow_run_budget(&id, 0, 0, 0, 4)).unwrap(),
            WorkflowBudgetDebit::Exceeded { .. }
        ));
    }

    #[test]
    fn workflow_run_budget_is_resumable_after_a_topup() {
        // #279 acceptance: after a budget-exhaustion stop, a top-up raises the
        // cap and reactivates the run so it resumes.
        let repositories = workflow_budget_repositories();
        let id = workflow_run_budget_id("wf", 1, "run-2");
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-2",
            "tenant-1",
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(100),
                ..WorkflowRunBudgetCaps::default()
            },
            1,
        ))
        .unwrap();
        block_on(repositories.debit_workflow_run_budget(&id, 100, 0, 0, 2)).unwrap();
        // Exhaust it.
        assert!(matches!(
            block_on(repositories.debit_workflow_run_budget(&id, 1, 0, 0, 3)).unwrap(),
            WorkflowBudgetDebit::Exceeded { .. }
        ));

        // Top up by 50 credits -> cap 150, status active again.
        let topped =
            block_on(repositories.topup_workflow_run_budget(&id, 50, 0, 0, None, 4)).unwrap();
        assert_eq!(topped.cost_budget_credits, Some(150));
        assert_eq!(topped.status, WORKFLOW_RUN_BUDGET_ACTIVE);

        // The run resumes: a 30-credit step now fits (100 + 30 = 130 <= 150).
        match block_on(repositories.debit_workflow_run_budget(&id, 30, 0, 0, 5)).unwrap() {
            WorkflowBudgetDebit::Applied(budget) => assert_eq!(budget.spent_credits, 130),
            other => panic!("expected Applied after top-up, got {other:?}"),
        }
    }

    #[test]
    fn workflow_run_budget_open_is_idempotent_and_fixes_caps_at_first_open() {
        let repositories = workflow_budget_repositories();
        let first = block_on(repositories.open_workflow_run_budget(
            "wf",
            2,
            "run-3",
            "tenant-1",
            WorkflowRunBudgetCaps {
                tool_call_budget: Some(5),
                ..WorkflowRunBudgetCaps::default()
            },
            1,
        ))
        .unwrap();
        // Re-opening with DIFFERENT caps returns the original envelope unchanged
        // -- a later step can't widen (or narrow) an in-flight run's ceiling.
        let second = block_on(repositories.open_workflow_run_budget(
            "wf",
            2,
            "run-3",
            "tenant-1",
            WorkflowRunBudgetCaps {
                tool_call_budget: Some(999),
                ..WorkflowRunBudgetCaps::default()
            },
            2,
        ))
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(second.tool_call_budget, Some(5));
    }

    #[test]
    fn workflow_run_budget_wall_clock_deadline_denies_after_expiry() {
        let repositories = workflow_budget_repositories();
        let id = workflow_run_budget_id("wf", 1, "run-clock");
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-clock",
            "tenant-1",
            WorkflowRunBudgetCaps {
                wall_clock_deadline_unix: Some(50),
                ..WorkflowRunBudgetCaps::default()
            },
            1,
        ))
        .unwrap();
        // A step before the deadline is fine.
        assert!(matches!(
            block_on(repositories.debit_workflow_run_budget(&id, 0, 0, 0, 49)).unwrap(),
            WorkflowBudgetDebit::Applied(_)
        ));
        // At/after the deadline the run stops on the wall-clock dimension.
        match block_on(repositories.debit_workflow_run_budget(&id, 0, 0, 0, 50)).unwrap() {
            WorkflowBudgetDebit::Exceeded { dimension, .. } => {
                assert_eq!(dimension, WorkflowBudgetDimension::WallClock);
            }
            other => panic!("expected wall-clock Exceeded, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_workflow_budget_debits_cannot_overspend() {
        // #279 core correctness property (mirrors #281's wallet no-oversell): N
        // parallel single-tool-call debits against a tool-call budget of K let
        // exactly K through -- serialized on the row, no overspend.
        use std::sync::{Arc, Barrier};

        let repositories = Arc::new(workflow_budget_repositories());
        let id = workflow_run_budget_id("wf", 1, "run-race");
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-race",
            "tenant-1",
            WorkflowRunBudgetCaps {
                tool_call_budget: Some(9),
                ..WorkflowRunBudgetCaps::default()
            },
            1,
        ))
        .unwrap();

        let threads = 10usize; // 10 x 1 tool call, but only 9 budgeted.
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            let id = id.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                block_on(repositories.debit_workflow_run_budget(&id, 0, 0, 1, 2))
            }));
        }
        let mut applied = 0;
        let mut exceeded = 0;
        for handle in handles {
            match handle.join().unwrap().unwrap() {
                WorkflowBudgetDebit::Applied(_) => applied += 1,
                WorkflowBudgetDebit::Exceeded { .. } => exceeded += 1,
            }
        }
        assert_eq!(applied, 9, "exactly the budgeted tool calls may succeed");
        assert_eq!(exceeded, 1, "the overspend attempt must be rejected");
        let budget = block_on(repositories.get_workflow_run_budget(&id))
            .unwrap()
            .unwrap();
        assert_eq!(
            budget.spent_tool_calls, 9,
            "spent tool calls must never exceed the budget"
        );
    }

    #[test]
    fn workflow_run_budgets_are_listed_per_tenant_newest_first() {
        let repositories = workflow_budget_repositories();
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-a",
            "tenant-x",
            WorkflowRunBudgetCaps::default(),
            10,
        ))
        .unwrap();
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-b",
            "tenant-x",
            WorkflowRunBudgetCaps::default(),
            20,
        ))
        .unwrap();
        block_on(repositories.open_workflow_run_budget(
            "wf",
            1,
            "run-c",
            "tenant-y",
            WorkflowRunBudgetCaps::default(),
            30,
        ))
        .unwrap();
        let listed = block_on(repositories.list_workflow_run_budgets("tenant-x")).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].run_id, "run-b", "newest first");
        assert_eq!(listed[1].run_id, "run-a");
        // Debiting an unknown run is a NotFound, never a silent no-op.
        assert!(matches!(
            block_on(repositories.debit_workflow_run_budget("nope", 1, 0, 0, 1)),
            Err(StorageError::NotFound(_))
        ));
    }

    fn wallet_repositories_with_balance(tenant: &str, balance: i64) -> RuntimeStorageRepositories {
        let repositories =
            RuntimeStorageRepositories::in_memory(DEFAULT_DURABLE_PROVIDER_ORDER.to_vec(), 10, 10);
        block_on(repositories.upsert_wallet(StoredWallet {
            id: tenant.into(),
            tenant_id: tenant.into(),
            balance_credits: balance,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();
        repositories
    }

    #[test]
    fn wallet_reserve_reduces_available_balance_and_rejects_over_reserve() {
        // #281: a hold reduces AVAILABLE (not actual) balance, so a second
        // reserve sees less headroom and an over-reserve is rejected without
        // ever touching the real balance.
        let repositories = wallet_repositories_with_balance("tenant-r", 1_000);

        // Reserve 600 of 1_000: leaves 400 available, real balance untouched.
        let first =
            block_on(repositories.reserve_wallet_credits("hold-a", "tenant-r", 600, 100, 2))
                .unwrap();
        assert!(matches!(first, WalletReservationResult::Reserved(_)));
        assert_eq!(
            block_on(repositories.get_wallet("tenant-r"))
                .unwrap()
                .unwrap()
                .balance_credits,
            1_000,
            "a hold must not debit the real balance"
        );

        // Reserving 400 more exactly exhausts available balance.
        let second =
            block_on(repositories.reserve_wallet_credits("hold-b", "tenant-r", 400, 100, 2))
                .unwrap();
        assert!(matches!(second, WalletReservationResult::Reserved(_)));

        // One more credit is now unaffordable: no oversell.
        let third =
            block_on(repositories.reserve_wallet_credits("hold-c", "tenant-r", 1, 100, 2)).unwrap();
        assert!(matches!(
            third,
            WalletReservationResult::Insufficient {
                available_credits: 0,
                requested_credits: 1,
            }
        ));

        // Re-reserving an existing id is idempotent (returns the same hold).
        let replay =
            block_on(repositories.reserve_wallet_credits("hold-a", "tenant-r", 600, 100, 9))
                .unwrap();
        assert!(matches!(
            replay,
            WalletReservationResult::Reserved(r) if r.amount_credits == 600
        ));

        // No wallet row -> opt-in, no hold taken.
        assert!(matches!(
            block_on(repositories.reserve_wallet_credits("hold-x", "no-wallet", 5, 100, 2))
                .unwrap(),
            WalletReservationResult::NoWallet
        ));
    }

    #[test]
    fn wallet_reservation_settle_debits_the_reserved_amount_and_clears_the_hold() {
        // #281: settle captures the exact reserved amount into a real debit,
        // records a ledger row whose id references the originating hold, marks
        // the hold settled, and is idempotent on replay.
        let repositories = wallet_repositories_with_balance("tenant-s", 1_000);
        block_on(repositories.reserve_wallet_credits("hold-s", "tenant-s", 300, 100, 2)).unwrap();

        let settled = block_on(repositories.settle_wallet_reservation("hold-s", 5)).unwrap();
        assert!(settled.newly_applied);
        assert_eq!(settled.reservation.status, WALLET_RESERVATION_SETTLED);
        // The ledger entry references its originating hold (shared id).
        assert_eq!(settled.settlement.id, "hold-s");
        assert_eq!(settled.reservation.settlement_id.as_deref(), Some("hold-s"));
        assert_eq!(settled.settlement.delta_credits, -300);
        assert_eq!(settled.settlement.balance_after_credits, Some(700));
        assert_eq!(
            block_on(repositories.get_wallet("tenant-s"))
                .unwrap()
                .unwrap()
                .balance_credits,
            700,
            "settle debits the reserved amount"
        );

        // The hold no longer counts against available balance: the remaining
        // 700 is fully reservable again.
        assert!(matches!(
            block_on(repositories.reserve_wallet_credits("hold-s2", "tenant-s", 700, 100, 6))
                .unwrap(),
            WalletReservationResult::Reserved(_)
        ));

        // Settling the same hold again is an idempotent no-op (no double debit).
        let replay = block_on(repositories.settle_wallet_reservation("hold-s", 7)).unwrap();
        assert!(!replay.newly_applied);
        assert_eq!(
            block_on(repositories.get_wallet("tenant-s"))
                .unwrap()
                .unwrap()
                .balance_credits,
            700,
            "a replayed settle must not debit twice"
        );
    }

    #[test]
    fn wallet_reservation_release_restores_available_balance() {
        // #281: releasing a hold frees its credits back to available balance.
        let repositories = wallet_repositories_with_balance("tenant-rel", 500);
        block_on(repositories.reserve_wallet_credits("hold-rel", "tenant-rel", 500, 100, 2))
            .unwrap();

        // Fully reserved: nothing else fits.
        assert!(matches!(
            block_on(repositories.reserve_wallet_credits("hold-rel2", "tenant-rel", 1, 100, 2))
                .unwrap(),
            WalletReservationResult::Insufficient { .. }
        ));

        let released = block_on(repositories.release_wallet_reservation("hold-rel", 3)).unwrap();
        assert_eq!(released.status, WALLET_RESERVATION_RELEASED);

        // The freed credits are reservable again; the real balance is unchanged.
        assert!(matches!(
            block_on(repositories.reserve_wallet_credits("hold-rel3", "tenant-rel", 500, 100, 4))
                .unwrap(),
            WalletReservationResult::Reserved(_)
        ));
        assert_eq!(
            block_on(repositories.get_wallet("tenant-rel"))
                .unwrap()
                .unwrap()
                .balance_credits,
            500
        );

        // Releasing again is idempotent; settling a released hold is rejected.
        assert!(block_on(repositories.release_wallet_reservation("hold-rel", 5)).is_ok());
        assert!(matches!(
            block_on(repositories.settle_wallet_reservation("hold-rel", 6)),
            Err(StorageError::Conflict(_))
        ));
    }

    #[test]
    fn wallet_reservation_expiry_auto_releases_and_settle_after_release_is_rejected() {
        // #281 acceptance: a crash between reserve and settle expires the hold;
        // the sweeper releases it, and a later settle is rejected idempotently.
        let repositories = wallet_repositories_with_balance("tenant-exp", 1_000);
        block_on(repositories.reserve_wallet_credits("hold-exp", "tenant-exp", 400, 50, 2))
            .unwrap();

        // An expired hold stops counting against available balance even before
        // the sweep, so the full balance is reservable at now=100 (> ttl 50).
        assert!(matches!(
            block_on(repositories.reserve_wallet_credits(
                "hold-live",
                "tenant-exp",
                1_000,
                200,
                100
            ))
            .unwrap(),
            WalletReservationResult::Reserved(_)
        ));
        block_on(repositories.release_wallet_reservation("hold-live", 100)).unwrap();

        // Sweeper marks the expired hold released and reports it.
        let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
        assert_eq!(swept, vec!["hold-exp".to_string()]);

        // Settling the expired/released hold is rejected -- the spend never
        // happened, and the real balance is untouched.
        assert!(matches!(
            block_on(repositories.settle_wallet_reservation("hold-exp", 101)),
            Err(StorageError::Conflict(_))
        ));
        assert_eq!(
            block_on(repositories.get_wallet("tenant-exp"))
                .unwrap()
                .unwrap()
                .balance_credits,
            1_000
        );

        // Settling an unknown hold is a NotFound, never a silent debit.
        assert!(matches!(
            block_on(repositories.settle_wallet_reservation("nope", 101)),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_reserves_cannot_oversell_a_wallet_balance() {
        // #281 core correctness property: N parallel reserves against a balance
        // that affords only N-1 of them let exactly N-1 through -- no oversell.
        use std::sync::{Arc, Barrier};

        let repositories = Arc::new(wallet_repositories_with_balance("tenant-race", 900));
        let threads = 10usize; // 10 x 100 credits, but only 900 funded.
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        for i in 0..threads {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                // Release all threads at once for maximum contention.
                barrier.wait();
                block_on(repositories.reserve_wallet_credits(
                    &format!("hold-{i}"),
                    "tenant-race",
                    100,
                    1_000,
                    2,
                ))
            }));
        }

        let mut reserved = 0;
        let mut insufficient = 0;
        for handle in handles {
            match handle.join().unwrap().unwrap() {
                WalletReservationResult::Reserved(_) => reserved += 1,
                WalletReservationResult::Insufficient { .. } => insufficient += 1,
                WalletReservationResult::NoWallet => panic!("wallet exists"),
            }
        }
        assert_eq!(reserved, 9, "exactly floor(900/100) reserves may succeed");
        assert_eq!(insufficient, 1, "the oversell attempt must be rejected");

        // Live holds never exceed the funded balance.
        let held: i64 = block_on(repositories.list_wallet_reservations("tenant-race"))
            .unwrap()
            .iter()
            .filter(|r| r.status == WALLET_RESERVATION_ACTIVE)
            .map(|r| r.amount_credits)
            .sum();
        assert_eq!(
            held, 900,
            "held credits must never exceed the funded balance"
        );
    }

    #[test]
    fn payment_methods_are_scoped_per_tenant_and_idempotent_on_reattachment() {
        let repositories = memory_repositories();

        let method = StoredPaymentMethod {
            id: payment_method_id("tenant-pm", "stripe", "pm_123"),
            tenant_id: "tenant-pm".into(),
            provider: "stripe".into(),
            provider_customer_id: "cus_123".into(),
            provider_payment_method_id: "pm_123".into(),
            is_default: true,
            created_at_unix: 1,
        };
        block_on(repositories.upsert_payment_method(method.clone())).unwrap();
        // Re-attaching the same provider-side payment method is idempotent
        // (deterministic id), not a duplicate row.
        block_on(repositories.upsert_payment_method(method)).unwrap();

        let listed = block_on(repositories.list_payment_methods("tenant-pm")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].provider_payment_method_id, "pm_123");

        assert!(
            block_on(repositories.list_payment_methods("no-such-tenant"))
                .unwrap()
                .is_empty()
        );

        assert!(
            block_on(repositories.delete_payment_method(&payment_method_id(
                "tenant-pm",
                "stripe",
                "pm_123"
            )))
            .unwrap()
        );
        assert!(block_on(repositories.list_payment_methods("tenant-pm"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn migration_snapshot_includes_api_key_records() {
        let source = memory_repositories();
        block_on(source.upsert_api_key_record(sample_api_key("key-a", "fg_live"))).unwrap();

        let snapshot = source.export_migration_snapshot().unwrap();
        assert_eq!(snapshot.counts().api_key_records, 1);

        let target = memory_repositories();
        target.import_migration_snapshot(snapshot).unwrap();
        let stored = block_on(target.get_api_key_record("key-a"))
            .unwrap()
            .unwrap();
        assert_eq!(stored.key_prefix, "fg_live");
        assert_eq!(stored.workspace_id, "ws-dev");
    }

    #[test]
    fn guardrail_policy_revisions_are_immutable_and_bindings_transition_atomically() {
        let repositories = memory_repositories();
        let revision = |revision: u32, policy_json: &str| StoredGuardrailPolicyRevision {
            id: guardrail_policy_revision_id("pii", revision),
            policy_id: "pii".into(),
            revision,
            policy_json: policy_json.into(),
            created_at_unix: u64::from(revision),
            created_by: "admin".into(),
        };

        repositories
            .insert_guardrail_policy_revision(revision(1, r#"{"revision":1}"#))
            .unwrap();
        let duplicate = repositories
            .insert_guardrail_policy_revision(revision(1, r#"{"revision":1,"changed":true}"#))
            .unwrap_err();
        assert!(matches!(duplicate, StorageError::Conflict(_)));
        assert_eq!(
            repositories
                .get_guardrail_policy_revision("pii", 1)
                .unwrap()
                .unwrap()
                .policy_json,
            r#"{"revision":1}"#
        );

        let first = repositories
            .activate_guardrail_policy_revision("pii", 1, "admin", 10, false)
            .unwrap();
        assert!(first.previous.is_none());
        assert_eq!(first.current.active_revision, Some(1));

        repositories
            .insert_guardrail_policy_revision(revision(2, r#"{"revision":2}"#))
            .unwrap();
        let second = repositories
            .activate_guardrail_policy_revision("pii", 2, "admin", 20, false)
            .unwrap();
        assert_eq!(second.current.active_revision, Some(2));
        assert_eq!(second.current.archived_revisions, vec![1]);

        let rollback = repositories
            .activate_guardrail_policy_revision("pii", 1, "admin", 30, true)
            .unwrap();
        assert_eq!(rollback.current.active_revision, Some(1));
        assert_eq!(rollback.current.archived_revisions, vec![2]);
        assert!(repositories
            .activate_guardrail_policy_revision("pii", 3, "admin", 40, true)
            .is_err());

        let snapshot = repositories.export_migration_snapshot().unwrap();
        assert_eq!(snapshot.counts().guardrail_policy_revisions, 2);
        assert_eq!(snapshot.counts().guardrail_policy_bindings, 1);
    }

    #[test]
    fn migration_snapshot_without_guardrail_fields_remains_readable() {
        let mut legacy = serde_json::to_value(StorageMigrationSnapshot::default()).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.remove("guardrail_policy_revisions");
        object.remove("guardrail_policy_bindings");

        let restored: StorageMigrationSnapshot = serde_json::from_value(legacy).unwrap();
        assert!(restored.guardrail_policy_revisions.is_empty());
        assert!(restored.guardrail_policy_bindings.is_empty());
    }

    #[test]
    fn stored_api_key_deserializes_legacy_payload_with_durable_defaults() {
        let json = r#"{
            "id": "key-dev",
            "name": "Development key",
            "key_hash": "sha256:stored",
            "enabled": true
        }"#;
        let api_key: StoredApiKey = serde_json::from_str(json).unwrap();
        assert_eq!(api_key.workspace_id, "");
        assert_eq!(api_key.tenant_id, "");
        assert_eq!(api_key.project_id, "");
        assert_eq!(api_key.key_prefix, "");
        assert_eq!(api_key.last4, "");
        assert!(api_key.scopes.is_empty());
        assert_eq!(api_key.created_at_unix, 0);
        assert_eq!(api_key.revoked_at_unix, None);
    }

    fn in_memory_repositories() -> RuntimeStorageRepositories {
        RuntimeStorageRepositories::new(
            RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
            RuntimeControlPlaneState::new(),
            0,
            0,
        )
    }

    fn stored_project(id: &str) -> StoredProject {
        StoredProject {
            id: id.into(),
            tenant_id: "org".into(),
            name: id.into(),
            slug: id.into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn stored_workspace(id: &str, project_id: &str) -> StoredWorkspace {
        StoredWorkspace {
            id: id.into(),
            project_id: project_id.into(),
            tenant_id: "org".into(),
            name: id.into(),
            slug: id.into(),
            environment: "default".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn stored_api_key(id: &str, project_id: &str, workspace_id: &str) -> StoredApiKey {
        StoredApiKey {
            id: id.into(),
            workspace_id: workspace_id.into(),
            tenant_id: "org".into(),
            project_id: project_id.into(),
            name: id.into(),
            key_prefix: "fg_test".into(),
            key_hash: "blake2b:test".into(),
            last4: "test".into(),
            enabled: true,
            scopes: Vec::new(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            tenant: TenantContext {
                workspace_id: Some(workspace_id.into()),
                organization_id: Some("org".into()),
                team_id: None,
                project_id: Some(project_id.into()),
                user_id: None,
                api_key_id: Some(id.into()),
            },
            monthly_token_budget: None,
            request_limit_per_minute: None,
            created_at_unix: 1,
            updated_at_unix: 1,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        }
    }

    // --- Atomic reject-if-referenced deletes (issue #328, finding 4) ---

    #[test]
    fn delete_project_if_unreferenced_deletes_a_childless_project() {
        let repositories = in_memory_repositories();
        block_on(repositories.upsert_project(stored_project("p_1"))).unwrap();

        let outcome = block_on(repositories.delete_project_if_unreferenced("p_1")).unwrap();
        assert_eq!(outcome, DeleteProjectOutcome::Deleted);
        assert!(block_on(repositories.get_project("p_1")).unwrap().is_none());
    }

    #[test]
    fn delete_project_if_unreferenced_rejects_a_project_with_a_workspace() {
        let repositories = in_memory_repositories();
        block_on(repositories.upsert_project(stored_project("p_1"))).unwrap();
        block_on(repositories.upsert_workspace(stored_workspace("w_1", "p_1"))).unwrap();

        let outcome = block_on(repositories.delete_project_if_unreferenced("p_1")).unwrap();
        assert_eq!(
            outcome,
            DeleteProjectOutcome::Referenced {
                workspaces: 1,
                virtual_keys: 0,
            }
        );
        // The project must survive an atomic reject.
        assert!(block_on(repositories.get_project("p_1")).unwrap().is_some());
    }

    #[test]
    fn delete_project_if_unreferenced_rejects_a_project_with_only_a_virtual_key() {
        let repositories = in_memory_repositories();
        block_on(repositories.upsert_project(stored_project("p_1"))).unwrap();
        block_on(repositories.upsert_api_key_record(stored_api_key("k_1", "p_1", "w_1"))).unwrap();

        let outcome = block_on(repositories.delete_project_if_unreferenced("p_1")).unwrap();
        assert_eq!(
            outcome,
            DeleteProjectOutcome::Referenced {
                workspaces: 0,
                virtual_keys: 1,
            }
        );
    }

    #[test]
    fn delete_project_if_unreferenced_reports_not_found_for_an_unknown_id() {
        let repositories = in_memory_repositories();
        let outcome = block_on(repositories.delete_project_if_unreferenced("missing")).unwrap();
        assert_eq!(outcome, DeleteProjectOutcome::NotFound);
    }

    #[test]
    fn delete_workspace_if_unreferenced_deletes_a_childless_workspace() {
        let repositories = in_memory_repositories();
        block_on(repositories.upsert_workspace(stored_workspace("w_1", "p_1"))).unwrap();

        let outcome = block_on(repositories.delete_workspace_if_unreferenced("w_1")).unwrap();
        assert_eq!(outcome, DeleteWorkspaceOutcome::Deleted);
        assert!(block_on(repositories.get_workspace("w_1"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn delete_workspace_if_unreferenced_rejects_a_workspace_with_a_virtual_key() {
        let repositories = in_memory_repositories();
        block_on(repositories.upsert_workspace(stored_workspace("w_1", "p_1"))).unwrap();
        block_on(repositories.upsert_api_key_record(stored_api_key("k_1", "p_1", "w_1"))).unwrap();

        let outcome = block_on(repositories.delete_workspace_if_unreferenced("w_1")).unwrap();
        assert_eq!(
            outcome,
            DeleteWorkspaceOutcome::Referenced { virtual_keys: 1 }
        );
        assert!(block_on(repositories.get_workspace("w_1"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn delete_workspace_if_unreferenced_reports_not_found_for_an_unknown_id() {
        let repositories = in_memory_repositories();
        let outcome = block_on(repositories.delete_workspace_if_unreferenced("missing")).unwrap();
        assert_eq!(outcome, DeleteWorkspaceOutcome::NotFound);
    }

    #[test]
    fn sso_provider_config_persist_read_delete_roundtrip() {
        let repositories = in_memory_repositories();
        let mut group_role_mapping = std::collections::BTreeMap::new();
        group_role_mapping.insert("Engineering".to_string(), "admin".to_string());
        let config = StoredSsoProviderConfig {
            tenant_id: "tenant-1".into(),
            provider_kind: "saml".into(),
            default_role: "member".into(),
            group_role_mapping: group_role_mapping.clone(),
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret_ref: None,
            oidc_redirect_uri: None,
            oidc_group_claim: None,
            saml_idp_entity_id: Some("https://idp.example/entity".into()),
            saml_idp_sso_url: Some("https://idp.example/sso".into()),
            saml_idp_certificate: Some("PEM-DATA".into()),
            saml_sp_entity_id: Some("sp-entity".into()),
            saml_acs_url: Some("https://sp.example/acs".into()),
            saml_email_attribute: Some("email".into()),
            saml_name_attribute: Some("displayName".into()),
            saml_groups_attribute: Some("groups".into()),
            created_at_unix: 1_700_000_000,
            updated_at_unix: 1_700_000_000,
        };

        block_on(repositories.upsert_sso_provider_config(config.clone())).unwrap();
        let read = block_on(repositories.get_sso_provider_config("tenant-1"))
            .unwrap()
            .expect("config persisted");
        assert_eq!(read, config);
        assert_eq!(read.group_role_mapping, group_role_mapping);

        // Re-upsert replaces (one config per tenant).
        let mut updated = config.clone();
        updated.provider_kind = "oidc".into();
        updated.oidc_issuer = Some("https://issuer.example".into());
        block_on(repositories.upsert_sso_provider_config(updated.clone())).unwrap();
        let reread = block_on(repositories.get_sso_provider_config("tenant-1"))
            .unwrap()
            .unwrap();
        assert_eq!(reread.provider_kind, "oidc");

        assert!(block_on(repositories.delete_sso_provider_config("tenant-1")).unwrap());
        assert!(block_on(repositories.get_sso_provider_config("tenant-1"))
            .unwrap()
            .is_none());
        // Deleting again reports nothing removed.
        assert!(!block_on(repositories.delete_sso_provider_config("tenant-1")).unwrap());
    }

    #[test]
    fn sso_pending_flow_is_consumed_once_and_expires() {
        let repositories = in_memory_repositories();
        let flow = StoredSsoPendingFlow {
            state: "state-abc".into(),
            tenant_id: "tenant-1".into(),
            provider_kind: "oidc".into(),
            code_verifier: Some("verifier".into()),
            request_id: None,
            created_at_unix: 1_000,
            expires_at_unix: 2_000,
        };
        block_on(repositories.insert_sso_pending_flow(flow.clone())).unwrap();

        // Consumed exactly once.
        let taken = block_on(repositories.take_sso_pending_flow("state-abc", 1_500))
            .unwrap()
            .expect("flow present before expiry");
        assert_eq!(taken, flow);
        assert!(
            block_on(repositories.take_sso_pending_flow("state-abc", 1_500))
                .unwrap()
                .is_none()
        );

        // An expired flow is not returned (and is pruned).
        let expired = StoredSsoPendingFlow {
            state: "state-expired".into(),
            expires_at_unix: 2_000,
            ..flow.clone()
        };
        block_on(repositories.insert_sso_pending_flow(expired)).unwrap();
        assert!(
            block_on(repositories.take_sso_pending_flow("state-expired", 5_000))
                .unwrap()
                .is_none()
        );
    }
}
