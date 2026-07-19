// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Time-based agent schedule triggers (#246). Holds the
// control-plane schedule DEFINITIONS (cron/interval + firing target) plus the
// idempotent fire-history ledger. The scheduler tick loop lives in
// `ferrogate-cli`; this module owns the durable state and the cron/interval
// next-fire computation. Firing is at-most-once per (schedule, slot): the
// `agent_schedule_fires` UNIQUE (schedule_id, scheduled_fire_at_unix) row is
// the correctness gate, so a lost multi-instance race can never double-trigger
// the same slot. Split into its own file per the "one business entity per
// file" convention (mirrors `budget_alerts.rs`).

use std::str::FromStr as _;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use croner::Cron;

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError, StorageOperation,
};

/// How a schedule's firing cadence is expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleSpecKind {
    /// Standard 5-field cron expression evaluated in `timezone`.
    Cron,
    /// Fixed interval in seconds from the previous fire (timezone-agnostic).
    Interval,
}

impl ScheduleSpecKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleSpecKind::Cron => "cron",
            ScheduleSpecKind::Interval => "interval",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "cron" => Some(ScheduleSpecKind::Cron),
            "interval" => Some(ScheduleSpecKind::Interval),
            _ => None,
        }
    }
}

/// What a due schedule triggers when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleTargetKind {
    /// Enqueue a dispatch into the existing self-hosted lease queue.
    SelfHostedDispatch,
    /// Create an agent run via the managed/synchronous path.
    AgentRun,
}

impl ScheduleTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleTargetKind::SelfHostedDispatch => "self_hosted_dispatch",
            ScheduleTargetKind::AgentRun => "agent_run",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "self_hosted_dispatch" => Some(ScheduleTargetKind::SelfHostedDispatch),
            "agent_run" => Some(ScheduleTargetKind::AgentRun),
            _ => None,
        }
    }
}

/// Whether a new fire is suppressed while the previous one is still active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// Suppress a fire while the previous dispatch/run is still unacked/active
    /// (prevents the pile-up failure mode). Default.
    Skip,
    /// Always fire, even if the previous run is still active.
    Allow,
}

impl OverlapPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            OverlapPolicy::Skip => "skip",
            OverlapPolicy::Allow => "allow",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "skip" => Some(OverlapPolicy::Skip),
            "allow" => Some(OverlapPolicy::Allow),
            _ => None,
        }
    }
}

/// How missed slots (from downtime) are handled on catch-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupPolicy {
    /// Advance `next_fire_at` past every missed slot without firing them
    /// (n8n semantics). Default.
    SkipMissed,
    /// Fire a single catch-up for the most recent missed slot (bounded).
    FireOnce,
}

impl CatchupPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            CatchupPolicy::SkipMissed => "skip_missed",
            CatchupPolicy::FireOnce => "fire_once",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "skip_missed" => Some(CatchupPolicy::SkipMissed),
            "fire_once" => Some(CatchupPolicy::FireOnce),
            _ => None,
        }
    }
}

/// Terminal outcome recorded for a single (schedule, slot) fire attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleFireOutcome {
    Dispatched,
    SkippedOverlap,
    SkippedDisabled,
    Error,
}

impl ScheduleFireOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleFireOutcome::Dispatched => "dispatched",
            ScheduleFireOutcome::SkippedOverlap => "skipped_overlap",
            ScheduleFireOutcome::SkippedDisabled => "skipped_disabled",
            ScheduleFireOutcome::Error => "error",
        }
    }

    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "dispatched" => Some(ScheduleFireOutcome::Dispatched),
            "skipped_overlap" => Some(ScheduleFireOutcome::SkippedOverlap),
            "skipped_disabled" => Some(ScheduleFireOutcome::SkippedDisabled),
            "error" => Some(ScheduleFireOutcome::Error),
            _ => None,
        }
    }
}

/// A control-plane schedule definition (issue #246). The tick loop reads
/// `next_fire_at_unix` to decide when a schedule is due and recomputes it after
/// each fire via [`StoredAgentSchedule::compute_next_fire_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentSchedule {
    pub schedule_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub name: String,
    pub enabled: bool,
    pub spec_kind: ScheduleSpecKind,
    pub cron_expr: Option<String>,
    pub timezone: String,
    pub interval_secs: Option<i64>,
    pub target_kind: ScheduleTargetKind,
    /// Free-form JSON string (agent/workflow ref, framework_adapter, required
    /// capabilities, input payload template) interpreted by the fire action.
    pub target_json: String,
    pub overlap_policy: OverlapPolicy,
    pub catchup_policy: CatchupPolicy,
    pub jitter_secs: i64,
    pub next_fire_at_unix: Option<i64>,
    pub last_fire_at_unix: Option<i64>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
    pub revision: i64,
}

impl StoredAgentSchedule {
    /// The next fire time strictly after `after_unix`, honoring the schedule's
    /// spec kind (cron in its IANA timezone, or a fixed interval). Returns
    /// `None` only for an interval schedule with a non-positive interval (an
    /// invalid definition that must never fire).
    pub fn compute_next_fire_at(&self, after_unix: i64) -> Result<Option<i64>, ScheduleError> {
        match self.spec_kind {
            ScheduleSpecKind::Cron => {
                let expr = self
                    .cron_expr
                    .as_deref()
                    .filter(|expr| !expr.trim().is_empty())
                    .ok_or(ScheduleError::MissingCronExpr)?;
                compute_next_cron_fire_at(expr, &self.timezone, after_unix).map(Some)
            }
            ScheduleSpecKind::Interval => {
                let interval = self.interval_secs.unwrap_or(0);
                if interval <= 0 {
                    return Ok(None);
                }
                Ok(Some(after_unix.saturating_add(interval)))
            }
        }
    }
}

/// A durable fire-history record and the per-slot idempotency token. Exactly
/// one row exists per `(schedule_id, scheduled_fire_at_unix)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentScheduleFire {
    pub fire_id: String,
    pub schedule_id: String,
    pub scheduled_fire_at_unix: i64,
    pub fired_at_unix: i64,
    pub node_id: Option<String>,
    pub outcome: ScheduleFireOutcome,
    pub dispatch_id: Option<String>,
    pub run_id: Option<String>,
    pub detail: Option<String>,
}

/// Deterministic fire id so two gateway instances racing the same slot produce
/// the SAME primary key -- combined with the `(schedule_id,
/// scheduled_fire_at_unix)` unique constraint this makes the insert idempotent.
/// Length-prefixed so a crafted `schedule_id` can never alias another slot.
pub fn agent_schedule_fire_id(schedule_id: &str, scheduled_fire_at_unix: i64) -> String {
    format!(
        "{}:{schedule_id}:{scheduled_fire_at_unix}",
        schedule_id.len()
    )
}

/// Errors from cron/interval next-fire computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    InvalidTimezone(String),
    InvalidCron(String),
    InvalidTimestamp(i64),
    MissingCronExpr,
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScheduleError::InvalidTimezone(tz) => write!(f, "invalid IANA timezone '{tz}'"),
            ScheduleError::InvalidCron(message) => write!(f, "invalid cron expression: {message}"),
            ScheduleError::InvalidTimestamp(ts) => write!(f, "unrepresentable unix timestamp {ts}"),
            ScheduleError::MissingCronExpr => {
                write!(f, "cron schedule is missing its cron expression")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

impl From<ScheduleError> for StorageError {
    fn from(error: ScheduleError) -> Self {
        StorageError::Runtime(error.to_string())
    }
}

/// The next cron occurrence strictly after `after_unix`, evaluated in the given
/// IANA `timezone`. Timezone-aware so DST transitions are honored: e.g. a
/// `0 2 * * *` schedule in `America/New_York` fires at 02:00 wall-clock on both
/// sides of a DST boundary, not at a fixed UTC offset.
pub fn compute_next_cron_fire_at(
    cron_expr: &str,
    timezone: &str,
    after_unix: i64,
) -> Result<i64, ScheduleError> {
    let tz: Tz = timezone
        .parse()
        .map_err(|_| ScheduleError::InvalidTimezone(timezone.to_string()))?;
    let cron = Cron::from_str(cron_expr)
        .map_err(|error| ScheduleError::InvalidCron(format!("{error}")))?;
    let after_utc = DateTime::<Utc>::from_timestamp(after_unix, 0)
        .ok_or(ScheduleError::InvalidTimestamp(after_unix))?;
    let after_local = after_utc.with_timezone(&tz);
    let next = cron
        .find_next_occurrence(&after_local, false)
        .map_err(|error| ScheduleError::InvalidCron(format!("{error}")))?;
    Ok(next.timestamp())
}

fn schedule_from_row(row: &PostgresRow) -> Result<StoredAgentSchedule, StorageError> {
    let spec_kind_raw = row.get::<_, String>(5);
    let spec_kind = ScheduleSpecKind::from_str_opt(&spec_kind_raw).ok_or_else(|| {
        StorageError::Runtime(format!("unknown agent_schedules.spec_kind {spec_kind_raw}"))
    })?;
    let target_kind_raw = row.get::<_, String>(9);
    let target_kind = ScheduleTargetKind::from_str_opt(&target_kind_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown agent_schedules.target_kind {target_kind_raw}"
        ))
    })?;
    let overlap_raw = row.get::<_, String>(11);
    let overlap_policy = OverlapPolicy::from_str_opt(&overlap_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown agent_schedules.overlap_policy {overlap_raw}"
        ))
    })?;
    let catchup_raw = row.get::<_, String>(12);
    let catchup_policy = CatchupPolicy::from_str_opt(&catchup_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown agent_schedules.catchup_policy {catchup_raw}"
        ))
    })?;
    Ok(StoredAgentSchedule {
        schedule_id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        workspace_id: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        enabled: row.get::<_, bool>(4),
        spec_kind,
        cron_expr: row.get::<_, Option<String>>(6),
        timezone: row.get::<_, String>(7),
        interval_secs: row.get::<_, Option<i64>>(8),
        target_kind,
        target_json: row.get::<_, String>(10),
        overlap_policy,
        catchup_policy,
        jitter_secs: row.get::<_, i64>(13),
        next_fire_at_unix: row.get::<_, Option<i64>>(14),
        last_fire_at_unix: row.get::<_, Option<i64>>(15),
        created_at_unix: row.get::<_, i64>(16),
        updated_at_unix: row.get::<_, i64>(17),
        revision: row.get::<_, i64>(18),
    })
}

// `target_json::text` renders the JSONB column back to a string, mirroring how
// `request_logs.request_json` is round-tripped (the crate binds JSON as text
// and casts with `::text::jsonb` rather than enabling tokio-postgres's
// serde_json feature).
const SCHEDULE_COLUMNS: &str = "schedule_id, tenant_id, workspace_id, name, enabled, spec_kind, \
     cron_expr, timezone, interval_secs, target_kind, target_json::text, overlap_policy, \
     catchup_policy, jitter_secs, next_fire_at_unix, last_fire_at_unix, created_at_unix, \
     updated_at_unix, revision";

fn fire_from_row(row: &PostgresRow) -> Result<StoredAgentScheduleFire, StorageError> {
    let outcome_raw = row.get::<_, String>(5);
    let outcome = ScheduleFireOutcome::from_str_opt(&outcome_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown agent_schedule_fires.outcome {outcome_raw}"
        ))
    })?;
    Ok(StoredAgentScheduleFire {
        fire_id: row.get::<_, String>(0),
        schedule_id: row.get::<_, String>(1),
        scheduled_fire_at_unix: row.get::<_, i64>(2),
        fired_at_unix: row.get::<_, i64>(3),
        node_id: row.get::<_, Option<String>>(4),
        outcome,
        dispatch_id: row.get::<_, Option<String>>(6),
        run_id: row.get::<_, Option<String>>(7),
        detail: row.get::<_, Option<String>>(8),
    })
}

const FIRE_COLUMNS: &str = "fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, node_id, \
     outcome, dispatch_id, run_id, detail";

impl PostgresControlPlaneStore {
    fn agent_schedule_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn upsert_agent_schedule(
        &self,
        schedule: &StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        // Validate up front so a bad payload fails with a clear error rather
        // than a Postgres cast error; the column is bound as text + cast with
        // `$11::text::jsonb`, matching `request_logs.request_json`.
        serde_json::from_str::<serde_json::Value>(&schedule.target_json).map_err(|error| {
            StorageError::Runtime(format!(
                "agent schedule target_json is not valid JSON: {error}"
            ))
        })?;
        let operation = self.agent_schedule_operation("upsert agent schedule");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves `agent_schedules` in the configured
        // schema, not the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO agent_schedules \
                 (schedule_id, tenant_id, workspace_id, name, enabled, spec_kind, cron_expr, \
                  timezone, interval_secs, target_kind, target_json, overlap_policy, \
                  catchup_policy, jitter_secs, next_fire_at_unix, last_fire_at_unix, \
                  created_at_unix, updated_at_unix, revision) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb, $12, $13, \
                         $14, $15, $16, $17, $18, $19) \
                 ON CONFLICT (schedule_id) DO UPDATE SET \
                     tenant_id = EXCLUDED.tenant_id, \
                     workspace_id = EXCLUDED.workspace_id, \
                     name = EXCLUDED.name, \
                     enabled = EXCLUDED.enabled, \
                     spec_kind = EXCLUDED.spec_kind, \
                     cron_expr = EXCLUDED.cron_expr, \
                     timezone = EXCLUDED.timezone, \
                     interval_secs = EXCLUDED.interval_secs, \
                     target_kind = EXCLUDED.target_kind, \
                     target_json = EXCLUDED.target_json, \
                     overlap_policy = EXCLUDED.overlap_policy, \
                     catchup_policy = EXCLUDED.catchup_policy, \
                     jitter_secs = EXCLUDED.jitter_secs, \
                     next_fire_at_unix = EXCLUDED.next_fire_at_unix, \
                     last_fire_at_unix = EXCLUDED.last_fire_at_unix, \
                     updated_at_unix = EXCLUDED.updated_at_unix, \
                     revision = EXCLUDED.revision",
                &[
                    &schedule.schedule_id,
                    &schedule.tenant_id,
                    &schedule.workspace_id,
                    &schedule.name,
                    &schedule.enabled,
                    &schedule.spec_kind.as_str(),
                    &schedule.cron_expr,
                    &schedule.timezone,
                    &schedule.interval_secs,
                    &schedule.target_kind.as_str(),
                    &schedule.target_json,
                    &schedule.overlap_policy.as_str(),
                    &schedule.catchup_policy.as_str(),
                    &schedule.jitter_secs,
                    &schedule.next_fire_at_unix,
                    &schedule.last_fire_at_unix,
                    &schedule.created_at_unix,
                    &schedule.updated_at_unix,
                    &schedule.revision,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        let operation = self.agent_schedule_operation("get agent schedule");
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
                &format!("SELECT {SCHEDULE_COLUMNS} FROM agent_schedules WHERE schedule_id = $1"),
                &[&schedule_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(schedule_from_row).transpose()
    }

    pub(super) async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        let operation = self.agent_schedule_operation("list agent schedules");
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
        let rows = match workspace_id {
            Some(workspace_id) => transaction
                .query(
                    &format!(
                        "SELECT {SCHEDULE_COLUMNS} FROM agent_schedules \
                         WHERE tenant_id = $1 AND workspace_id = $2 ORDER BY name ASC"
                    ),
                    &[&tenant_id, &workspace_id],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    &format!(
                        "SELECT {SCHEDULE_COLUMNS} FROM agent_schedules \
                         WHERE tenant_id = $1 ORDER BY name ASC"
                    ),
                    &[&tenant_id],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(schedule_from_row).collect()
    }

    pub(super) async fn delete_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.agent_schedule_operation("delete agent schedule");
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
                "DELETE FROM agent_schedules WHERE schedule_id = $1",
                &[&schedule_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    pub(super) async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        let operation = self.agent_schedule_operation("list due agent schedules");
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
                &format!(
                    "SELECT {SCHEDULE_COLUMNS} FROM agent_schedules \
                     WHERE enabled AND next_fire_at_unix IS NOT NULL AND next_fire_at_unix <= $1 \
                     ORDER BY next_fire_at_unix ASC LIMIT $2"
                ),
                &[&now_unix, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(schedule_from_row).collect()
    }

    /// Idempotently record a fire. Returns `true` only when THIS caller won the
    /// insert for `(schedule_id, scheduled_fire_at_unix)` -- a concurrent
    /// instance that already recorded the same slot gets `false` and must not
    /// trigger. This is the correctness gate for at-most-once firing.
    pub(super) async fn insert_agent_schedule_fire(
        &self,
        fire: &StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        let operation = self.agent_schedule_operation("insert agent schedule fire");
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
                "INSERT INTO agent_schedule_fires \
                 (fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, node_id, outcome, \
                  dispatch_id, run_id, detail) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING",
                &[
                    &fire.fire_id,
                    &fire.schedule_id,
                    &fire.scheduled_fire_at_unix,
                    &fire.fired_at_unix,
                    &fire.node_id,
                    &fire.outcome.as_str(),
                    &fire.dispatch_id,
                    &fire.run_id,
                    &fire.detail,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }

    pub(super) async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        let operation = self.agent_schedule_operation("list agent schedule fires");
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
                &format!(
                    "SELECT {FIRE_COLUMNS} FROM agent_schedule_fires \
                     WHERE schedule_id = $1 ORDER BY scheduled_fire_at_unix DESC LIMIT $2"
                ),
                &[&schedule_id, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(fire_from_row).collect()
    }
}

impl RuntimeControlPlaneState {
    pub(super) fn upsert_agent_schedule(&mut self, schedule: StoredAgentSchedule) {
        self.agent_schedules
            .insert(schedule.schedule_id.clone(), schedule);
    }

    pub(super) fn get_agent_schedule(&self, schedule_id: &str) -> Option<StoredAgentSchedule> {
        self.agent_schedules.get(schedule_id)
    }

    pub(super) fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Vec<StoredAgentSchedule> {
        let mut schedules: Vec<_> = self
            .agent_schedules
            .list()
            .into_iter()
            .filter(|schedule| {
                schedule.tenant_id == tenant_id
                    && workspace_id.is_none_or(|workspace| schedule.workspace_id == workspace)
            })
            .collect();
        schedules.sort_by(|a, b| a.name.cmp(&b.name));
        schedules
    }

    pub(super) fn delete_agent_schedule(&mut self, schedule_id: &str) -> bool {
        self.agent_schedules.remove(schedule_id).is_some()
    }

    pub(super) fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Vec<StoredAgentSchedule> {
        let mut due: Vec<_> = self
            .agent_schedules
            .list()
            .into_iter()
            .filter(|schedule| {
                schedule.enabled
                    && schedule
                        .next_fire_at_unix
                        .is_some_and(|next| next <= now_unix)
            })
            .collect();
        due.sort_by_key(|schedule| schedule.next_fire_at_unix.unwrap_or(i64::MAX));
        due.truncate(limit);
        due
    }

    /// In-memory analogue of the idempotent fire insert: `true` only when the
    /// slot was not already recorded.
    pub(super) fn insert_agent_schedule_fire(&mut self, fire: StoredAgentScheduleFire) -> bool {
        let already = self
            .agent_schedule_fires
            .list()
            .into_iter()
            .any(|existing| {
                existing.schedule_id == fire.schedule_id
                    && existing.scheduled_fire_at_unix == fire.scheduled_fire_at_unix
            });
        if already {
            return false;
        }
        self.agent_schedule_fires.insert(fire.fire_id.clone(), fire);
        true
    }

    pub(super) fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: usize,
    ) -> Vec<StoredAgentScheduleFire> {
        let mut fires: Vec<_> = self
            .agent_schedule_fires
            .list()
            .into_iter()
            .filter(|fire| fire.schedule_id == schedule_id)
            .collect();
        fires.sort_by(|a, b| b.scheduled_fire_at_unix.cmp(&a.scheduled_fire_at_unix));
        fires.truncate(limit);
        fires
    }
}

impl RuntimeStorageRepositories {
    pub async fn upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                control_plane
                    .lock()
                    .map_err(|_| {
                        StorageError::Runtime("agent schedule repository lock poisoned".into())
                    })?
                    .upsert_agent_schedule(schedule);
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_agent_schedule(&schedule).await
            }
        }
    }

    pub async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .get_agent_schedule(schedule_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_agent_schedule(schedule_id).await
            }
        }
    }

    pub async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .list_agent_schedules(tenant_id, workspace_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_agent_schedules(tenant_id, workspace_id)
                    .await
            }
        }
    }

    pub async fn delete_agent_schedule(&self, schedule_id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .delete_agent_schedule(schedule_id)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_agent_schedule(schedule_id).await
            }
        }
    }

    pub async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .list_due_agent_schedules(now_unix, limit.max(0) as usize)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_due_agent_schedules(now_unix, limit)
                    .await
            }
        }
    }

    /// Idempotently record a fire; `true` iff this caller won the slot. See
    /// [`PostgresControlPlaneStore::insert_agent_schedule_fire`].
    pub async fn insert_agent_schedule_fire(
        &self,
        fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .insert_agent_schedule_fire(fire)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.insert_agent_schedule_fire(&fire).await
            }
        }
    }

    pub async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("agent schedule repository lock poisoned".into())
                })?
                .list_agent_schedule_fires(schedule_id, limit.max(0) as usize)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_agent_schedule_fires(schedule_id, limit)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cron_schedule(cron_expr: &str, timezone: &str) -> StoredAgentSchedule {
        StoredAgentSchedule {
            schedule_id: "sched-1".into(),
            tenant_id: "tenant-1".into(),
            workspace_id: "ws-1".into(),
            name: "nightly".into(),
            enabled: true,
            spec_kind: ScheduleSpecKind::Cron,
            cron_expr: Some(cron_expr.into()),
            timezone: timezone.into(),
            interval_secs: None,
            target_kind: ScheduleTargetKind::SelfHostedDispatch,
            target_json: "{}".into(),
            overlap_policy: OverlapPolicy::Skip,
            catchup_policy: CatchupPolicy::SkipMissed,
            jitter_secs: 0,
            next_fire_at_unix: None,
            last_fire_at_unix: None,
            created_at_unix: 0,
            updated_at_unix: 0,
            revision: 1,
        }
    }

    #[test]
    fn cron_every_minute_advances_to_next_minute_boundary() {
        // 2026-01-01T00:00:30Z -> next `*/1 * * * *` slot is 00:01:00Z.
        let at = 1_767_225_630; // 2026-01-01T00:00:30Z
        let next = compute_next_cron_fire_at("*/1 * * * *", "UTC", at).expect("cron computes");
        assert_eq!(next, 1_767_225_660, "next minute boundary after 00:00:30Z");
        assert_eq!(next % 60, 0, "fire lands on a minute boundary");
    }

    #[test]
    fn cron_daily_utc_fires_at_configured_hour() {
        // 0 2 * * * in UTC from just after midnight -> 02:00:00Z same day.
        let at = 1_767_225_600; // 2026-01-01T00:00:00Z
        let next = compute_next_cron_fire_at("0 2 * * *", "UTC", at).expect("cron computes");
        let dt = DateTime::<Utc>::from_timestamp(next, 0).unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-01-01T02:00:00+00:00");
    }

    #[test]
    fn cron_respects_iana_timezone_offset() {
        // 0 0 * * * (local midnight) in America/New_York. On 2026-01-15 EST is
        // UTC-5, so local midnight is 05:00:00Z.
        let at = 1_768_460_400; // 2026-01-15T07:00:00Z, already past local midnight
        let next =
            compute_next_cron_fire_at("0 0 * * *", "America/New_York", at).expect("cron computes");
        let dt = DateTime::<Utc>::from_timestamp(next, 0).unwrap();
        // Next local midnight is 2026-01-16T00:00 EST = 2026-01-16T05:00:00Z.
        assert_eq!(dt.to_rfc3339(), "2026-01-16T05:00:00+00:00");
    }

    #[test]
    fn cron_dst_spring_forward_keeps_wall_clock_hour() {
        // US DST 2026 starts 2026-03-08. A 0 3 * * * (local 03:00) schedule in
        // America/New_York must fire at 03:00 LOCAL on both sides of the
        // transition, i.e. the UTC offset shifts from -5 (EST) to -4 (EDT).
        // From 2026-03-06T12:00:00Z (pre-transition); next 03:00 local is EST
        // (UTC-5) -> 2026-03-07T08:00:00Z.
        let before = compute_next_cron_fire_at("0 3 * * *", "America/New_York", 1_772_798_400)
            .expect("cron computes");
        let before_dt = DateTime::<Utc>::from_timestamp(before, 0).unwrap();
        assert_eq!(before_dt.to_rfc3339(), "2026-03-07T08:00:00+00:00");
        // After the transition (query from 2026-03-09) the next 03:00 local is
        // EDT (UTC-4) -> 07:00:00Z, proving DST shifted the UTC instant while
        // the wall-clock hour stayed 03:00.
        let after = compute_next_cron_fire_at("0 3 * * *", "America/New_York", 1_773_057_600)
            .expect("cron computes");
        let after_dt = DateTime::<Utc>::from_timestamp(after, 0).unwrap();
        assert_eq!(after_dt.to_rfc3339(), "2026-03-10T07:00:00+00:00");
    }

    #[test]
    fn schedule_compute_next_fire_at_dispatches_by_spec_kind() {
        let mut schedule = cron_schedule("0 2 * * *", "UTC");
        let next = schedule
            .compute_next_fire_at(1_767_225_600)
            .expect("cron next fire computes")
            .expect("cron schedules always yield a next fire");
        assert_eq!(next, 1_767_232_800); // 2026-01-01T02:00:00Z

        schedule.spec_kind = ScheduleSpecKind::Interval;
        schedule.interval_secs = Some(300);
        let next = schedule
            .compute_next_fire_at(1_000)
            .expect("interval next fire computes")
            .expect("positive interval yields a next fire");
        assert_eq!(next, 1_300);
    }

    #[test]
    fn interval_non_positive_never_fires() {
        let mut schedule = cron_schedule("0 2 * * *", "UTC");
        schedule.spec_kind = ScheduleSpecKind::Interval;
        schedule.interval_secs = Some(0);
        assert_eq!(
            schedule.compute_next_fire_at(1_000).expect("computes"),
            None,
            "a zero interval is an invalid definition that must never fire",
        );
        schedule.interval_secs = Some(-30);
        assert_eq!(
            schedule.compute_next_fire_at(1_000).expect("computes"),
            None,
        );
    }

    #[test]
    fn invalid_timezone_and_cron_are_rejected() {
        assert!(matches!(
            compute_next_cron_fire_at("0 2 * * *", "Not/AZone", 0),
            Err(ScheduleError::InvalidTimezone(_))
        ));
        assert!(matches!(
            compute_next_cron_fire_at("not a cron", "UTC", 0),
            Err(ScheduleError::InvalidCron(_))
        ));
    }

    #[test]
    fn fire_id_is_deterministic_and_slot_specific() {
        assert_eq!(
            agent_schedule_fire_id("sched-1", 1_767_225_660),
            agent_schedule_fire_id("sched-1", 1_767_225_660),
            "same slot -> same id so concurrent inserters collide on the PK",
        );
        assert_ne!(
            agent_schedule_fire_id("sched-1", 1_767_225_660),
            agent_schedule_fire_id("sched-1", 1_767_225_720),
            "different slots produce distinct ids",
        );
        // Length prefix keeps a crafted schedule_id from aliasing another slot.
        assert_ne!(
            agent_schedule_fire_id("a", 0),
            agent_schedule_fire_id("a:0", 0),
        );
    }
}
