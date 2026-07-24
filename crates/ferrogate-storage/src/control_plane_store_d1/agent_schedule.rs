// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped agent schedules + fire-history ledger (issue #460/#246).

//! D1 backend: tenant-scoped agent schedules + fire-history ledger (issue #460/#246).
//!
//! The time-based agent-schedule triggers (issue #246) on the
//! database-per-tenant D1 topology. Like the wallet/usage/asset families (issues
//! #455/#456), a schedule DEFINITION and its fire log live in the OWNING tenant's
//! own D1 database — never the control database — so every op routes through the
//! proxy-Worker binding (issue #450) selected onto a per-tenant
//! `[[d1_databases]]` binding (`tenant_database_binding`). A REST-only deployment
//! leaves them fail-closed with the typed unimplemented-surface error, exactly
//! like the sibling tenant-scoped families.
//!
//! ## Routing / divergence (database-per-tenant)
//!
//! - `upsert`/`list` carry a `tenant_id`, so they route straight to that tenant's
//!   binding. `upsert` is a tenant-DB WRITE, so an UNPROVISIONED tenant is a typed
//!   `NotFound` — the same divergence `reserve`/`persist`/`open` make, where
//!   Postgres would just insert. `list` is an opt-in READ: an unprovisioned tenant
//!   is EMPTY, not an error (matching the `list_wallets`-style reads).
//! - `list_all`/`list_due` carry no tenant, so they FAN OUT over the provisioned
//!   tenant bindings (each tenant's rows live in its own database) and re-merge to
//!   the Postgres `ORDER BY` (`list_all`: tenant/workspace/name; `list_due`:
//!   next-fire ascending, globally truncated to `limit`).
//! - `get`/`delete`/`insert_fire`/`list_fires` carry only an id (schedule/fire),
//!   so they FAN OUT to locate the tenant database holding the schedule — the
//!   established id-only-read locate the wallet family uses — then act on it. A
//!   fire lives in the SAME tenant DB as its schedule, so `insert_fire` locates
//!   the schedule first; an unknown schedule is `NotFound` (there is no tenant DB
//!   to route the fire into — the write divergence), and `get`/`list_fires` for an
//!   unknown id answer `Ok(None)`/empty.
//!
//! ## delete cascades the fire log itself (no cross-table FK)
//!
//! Postgres drops the fire rows through `agent_schedule_fires.schedule_id
//! REFERENCES agent_schedules(schedule_id) ON DELETE CASCADE`. The D1 dialect
//! carries no cross-table FK (physical isolation), so `delete_agent_schedule`
//! deletes the fire rows AND the schedule as ONE atomic `/d1/batch` — otherwise an
//! orphan fire row would make a re-created same-id schedule think a slot already
//! fired, breaking the at-most-once gate.
//!
//! ## Numeric affinity (issue #455 lesson)
//!
//! No op here does arithmetic against a bound numeric param, so nothing needs
//! `CAST(? AS INTEGER)`. Timestamps/counters are STORED values (column affinity
//! coerces the bound TEXT to INTEGER on write) and the due/window filters compare
//! a bare INTEGER COLUMN against a bound `?` (the column's affinity is applied to
//! the param, so `next_fire_at_unix <= ?` needs no CAST — same as the billing
//! outbox due read); the CAST is only needed when a bound param enters an
//! arithmetic EXPRESSION (a complex expression has no affinity), which none do.

use serde::de::DeserializeOwned;

use super::*;

/// Column list shared by every `agent_schedules` read, kept in lockstep with
/// [`AgentScheduleD1Row`] and the Postgres `SCHEDULE_COLUMNS` projection order.
const AGENT_SCHEDULE_COLUMNS: &str = "schedule_id, tenant_id, workspace_id, name, enabled, \
     spec_kind, cron_expr, timezone, interval_secs, target_kind, target_json, overlap_policy, \
     catchup_policy, jitter_secs, next_fire_at_unix, last_fire_at_unix, created_at_unix, \
     updated_at_unix, revision";

/// Column list shared by every `agent_schedule_fires` read, matching
/// [`AgentScheduleFireD1Row`] and the Postgres `FIRE_COLUMNS` projection order.
const AGENT_SCHEDULE_FIRE_COLUMNS: &str = "fire_id, schedule_id, scheduled_fire_at_unix, \
     fired_at_unix, node_id, outcome, dispatch_id, run_id, detail";

/// One `agent_schedules` row (SQLite integer/boolean affinities decoded back to
/// the `Stored*` shape; the four enum columns decode as TEXT then map to their
/// enums, mirroring the Postgres `schedule_from_row`).
#[derive(serde::Deserialize)]
struct AgentScheduleD1Row {
    schedule_id: String,
    tenant_id: String,
    workspace_id: String,
    name: String,
    enabled: i64,
    spec_kind: String,
    cron_expr: Option<String>,
    timezone: String,
    interval_secs: Option<i64>,
    target_kind: String,
    target_json: String,
    overlap_policy: String,
    catchup_policy: String,
    jitter_secs: i64,
    next_fire_at_unix: Option<i64>,
    last_fire_at_unix: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
    revision: i64,
}

impl AgentScheduleD1Row {
    fn into_stored(self) -> Result<StoredAgentSchedule, StorageError> {
        let spec_kind = ScheduleSpecKind::from_str_opt(&self.spec_kind).ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: unknown agent_schedules.spec_kind {}",
                self.spec_kind
            ))
        })?;
        let target_kind = ScheduleTargetKind::from_str_opt(&self.target_kind).ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: unknown agent_schedules.target_kind {}",
                self.target_kind
            ))
        })?;
        let overlap_policy =
            OverlapPolicy::from_str_opt(&self.overlap_policy).ok_or_else(|| {
                StorageError::Runtime(format!(
                    "cloudflare d1: unknown agent_schedules.overlap_policy {}",
                    self.overlap_policy
                ))
            })?;
        let catchup_policy =
            CatchupPolicy::from_str_opt(&self.catchup_policy).ok_or_else(|| {
                StorageError::Runtime(format!(
                    "cloudflare d1: unknown agent_schedules.catchup_policy {}",
                    self.catchup_policy
                ))
            })?;
        Ok(StoredAgentSchedule {
            schedule_id: self.schedule_id,
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
            name: self.name,
            enabled: self.enabled != 0,
            spec_kind,
            cron_expr: self.cron_expr,
            timezone: self.timezone,
            interval_secs: self.interval_secs,
            target_kind,
            target_json: self.target_json,
            overlap_policy,
            catchup_policy,
            jitter_secs: self.jitter_secs,
            next_fire_at_unix: self.next_fire_at_unix,
            last_fire_at_unix: self.last_fire_at_unix,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
            revision: self.revision,
        })
    }
}

/// One `agent_schedule_fires` row.
#[derive(serde::Deserialize)]
struct AgentScheduleFireD1Row {
    fire_id: String,
    schedule_id: String,
    scheduled_fire_at_unix: i64,
    fired_at_unix: i64,
    node_id: Option<String>,
    outcome: String,
    dispatch_id: Option<String>,
    run_id: Option<String>,
    detail: Option<String>,
}

impl AgentScheduleFireD1Row {
    fn into_stored(self) -> Result<StoredAgentScheduleFire, StorageError> {
        let outcome = ScheduleFireOutcome::from_str_opt(&self.outcome).ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: unknown agent_schedule_fires.outcome {}",
                self.outcome
            ))
        })?;
        Ok(StoredAgentScheduleFire {
            fire_id: self.fire_id,
            schedule_id: self.schedule_id,
            scheduled_fire_at_unix: self.scheduled_fire_at_unix,
            fired_at_unix: self.fired_at_unix,
            node_id: self.node_id,
            outcome,
            dispatch_id: self.dispatch_id,
            run_id: self.run_id,
            detail: self.detail,
        })
    }
}

/// Deserialize one D1 result row (`serde_json::Value` keyed by column) into a
/// typed DTO.
fn decode_row<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, StorageError> {
    serde_json::from_value(value.clone())
        .map_err(|error| StorageError::Serialization(error.to_string()))
}

impl D1ControlPlaneStore {
    // --- Agent schedules + fires over the proxy binding, tenant-DB routed
    // (issue #460/#246) ---

    /// Upsert a schedule definition into its OWNING tenant's D1 database. A single
    /// statement (no CAS) routed through the proxy's tenant binding, mirroring the
    /// Postgres `upsert_agent_schedule` `ON CONFLICT (schedule_id) DO UPDATE`
    /// (every mutable column except `created_at_unix`). `target_json` is validated
    /// as JSON up front like Postgres, so a bad payload fails with a clear error.
    ///
    /// Divergence: an UNPROVISIONED tenant is a typed `NotFound`
    /// (`tenant_proxy_binding` required), where Postgres would just insert.
    pub(super) async fn upsert_agent_schedule_d1_async(
        &self,
        schedule: &StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        // Validate up front so a bad payload fails with a clear error, mirroring
        // the Postgres backend's pre-flight JSON check (D1's TEXT column would
        // otherwise store arbitrary bytes).
        serde_json::from_str::<serde_json::Value>(&schedule.target_json).map_err(|error| {
            StorageError::Runtime(format!(
                "agent schedule target_json is not valid JSON: {error}"
            ))
        })?;
        let proxy = self.proxy_client("upsert_agent_schedule")?;
        let binding = self.tenant_proxy_binding(&schedule.tenant_id)?;
        // Timestamps/counters/enabled are STORED values (column affinity coerces
        // the bound TEXT on write), so no CAST; nullable columns ride
        // `NULLIF(?, '')` -> SQL NULL (the crate-wide convention).
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO agent_schedules \
             (schedule_id, tenant_id, workspace_id, name, enabled, spec_kind, cron_expr, \
              timezone, interval_secs, target_kind, target_json, overlap_policy, catchup_policy, \
              jitter_secs, next_fire_at_unix, last_fire_at_unix, created_at_unix, updated_at_unix, \
              revision) \
             VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), ?, ?, ?, ?, ?, \
              NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?) \
             ON CONFLICT (schedule_id) DO UPDATE SET \
             tenant_id = excluded.tenant_id, \
             workspace_id = excluded.workspace_id, \
             name = excluded.name, \
             enabled = excluded.enabled, \
             spec_kind = excluded.spec_kind, \
             cron_expr = excluded.cron_expr, \
             timezone = excluded.timezone, \
             interval_secs = excluded.interval_secs, \
             target_kind = excluded.target_kind, \
             target_json = excluded.target_json, \
             overlap_policy = excluded.overlap_policy, \
             catchup_policy = excluded.catchup_policy, \
             jitter_secs = excluded.jitter_secs, \
             next_fire_at_unix = excluded.next_fire_at_unix, \
             last_fire_at_unix = excluded.last_fire_at_unix, \
             updated_at_unix = excluded.updated_at_unix, \
             revision = excluded.revision",
            vec![
                schedule.schedule_id.clone(),
                schedule.tenant_id.clone(),
                schedule.workspace_id.clone(),
                schedule.name.clone(),
                bool_param(schedule.enabled),
                schedule.spec_kind.as_str().to_string(),
                schedule.cron_expr.clone().unwrap_or_default(),
                schedule.timezone.clone(),
                optional_number_param(schedule.interval_secs),
                schedule.target_kind.as_str().to_string(),
                schedule.target_json.clone(),
                schedule.overlap_policy.as_str().to_string(),
                schedule.catchup_policy.as_str().to_string(),
                schedule.jitter_secs.to_string(),
                optional_number_param(schedule.next_fire_at_unix),
                optional_number_param(schedule.last_fire_at_unix),
                schedule.created_at_unix.to_string(),
                schedule.updated_at_unix.to_string(),
                schedule.revision.to_string(),
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// Read one schedule by id (the scheduler tick + admin inspect). The signature
    /// carries no tenant, so this FANS OUT over the provisioned tenant bindings and
    /// returns the first match (the id is globally unique, so at most one binding
    /// answers); `Ok(None)` when none does. Fails closed without a proxy.
    pub(super) async fn get_agent_schedule_d1_async(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        self.proxy_client("get_agent_schedule")?;
        Ok(self
            .locate_agent_schedule("get_agent_schedule", schedule_id)
            .await?
            .map(|(_binding, schedule)| schedule))
    }

    /// List a tenant's schedules by name (issue #246 admin list). Routes straight
    /// to that tenant's own database and orders `name ASC` to match Postgres
    /// row-for-row, optionally narrowed to one workspace. Opt-in: an unprovisioned
    /// tenant is EMPTY, not an error. Fails closed without a proxy.
    pub(super) async fn list_agent_schedules_d1_async(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        let proxy = self.proxy_client("list_agent_schedules")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = match workspace_id {
            Some(workspace_id) => D1ProxyStatement::with_params(
                format!(
                    "SELECT {AGENT_SCHEDULE_COLUMNS} FROM agent_schedules \
                     WHERE tenant_id = ? AND workspace_id = ? ORDER BY name ASC"
                ),
                vec![tenant_id.to_string(), workspace_id.to_string()],
            ),
            None => D1ProxyStatement::with_params(
                format!(
                    "SELECT {AGENT_SCHEDULE_COLUMNS} FROM agent_schedules \
                     WHERE tenant_id = ? ORDER BY name ASC"
                ),
                vec![tenant_id.to_string()],
            ),
        };
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<AgentScheduleD1Row>(row)?.into_stored())
            .collect()
    }

    /// List EVERY provisioned tenant's schedules (platform-operator admin list).
    /// Fans out over the provisioned tenant bindings (each tenant's rows live in
    /// its own database), then re-sorts the union to the Postgres order
    /// `tenant_id ASC, workspace_id ASC, name ASC` so the list is row-for-row
    /// identical across backends. Empty registry -> empty; fails closed without a
    /// proxy.
    pub(super) async fn list_all_agent_schedules_d1_async(
        &self,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        let proxy = self.proxy_client("list_all_agent_schedules")?;
        let mut schedules = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::new(format!(
                "SELECT {AGENT_SCHEDULE_COLUMNS} FROM agent_schedules"
            ));
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                schedules.push(decode_row::<AgentScheduleD1Row>(row)?.into_stored()?);
            }
        }
        schedules.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.workspace_id.cmp(&right.workspace_id))
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(schedules)
    }

    /// List the due schedules cheapest-first (the scheduler tick's due scan): every
    /// enabled, scheduled row whose `next_fire_at_unix` has arrived. The signature
    /// carries no tenant, so this fans out over the provisioned tenant bindings
    /// (each with its own per-binding `LIMIT`), then re-sorts the union by
    /// `next_fire_at_unix ASC` and truncates to a GLOBAL `limit` — so the returned
    /// set is the same `limit` cheapest schedules Postgres's single-table
    /// `ORDER BY next_fire_at_unix ASC LIMIT` yields. Fails closed without a proxy.
    pub(super) async fn list_due_agent_schedules_d1_async(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        let proxy = self.proxy_client("list_due_agent_schedules")?;
        // `enabled = 1` is the SQLite spelling of the Postgres boolean predicate;
        // `next_fire_at_unix <= ?` compares a bare INTEGER column to the bound
        // param (column affinity coerces it), so no CAST. `limit` is a plain i64
        // literal inlined into the per-binding LIMIT (no bound-param injection).
        let mut schedules = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!(
                    "SELECT {AGENT_SCHEDULE_COLUMNS} FROM agent_schedules \
                     WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL \
                     AND next_fire_at_unix <= ? ORDER BY next_fire_at_unix ASC LIMIT {limit}"
                ),
                vec![now_unix.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                schedules.push(decode_row::<AgentScheduleD1Row>(row)?.into_stored()?);
            }
        }
        schedules.sort_by_key(|schedule| schedule.next_fire_at_unix.unwrap_or(i64::MAX));
        schedules.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(schedules)
    }

    /// Delete a schedule (issue #246 admin delete). The signature carries no
    /// tenant, so this fans out to locate the tenant database holding the schedule,
    /// then deletes the fire rows AND the schedule as ONE atomic `/d1/batch` —
    /// replicating the Postgres `ON DELETE CASCADE` the FK-free D1 dialect drops.
    /// `Ok(true)` iff the schedule existed; `Ok(false)` when no binding holds it.
    /// Fails closed without a proxy.
    pub(super) async fn delete_agent_schedule_d1_async(
        &self,
        schedule_id: &str,
    ) -> Result<bool, StorageError> {
        let proxy = self.proxy_client("delete_agent_schedule")?;
        let Some((binding, _schedule)) = self
            .locate_agent_schedule("delete_agent_schedule", schedule_id)
            .await?
        else {
            return Ok(false);
        };
        let statements = vec![
            // S0: cascade the fire log (Postgres does this via ON DELETE CASCADE).
            D1ProxyStatement::with_params(
                "DELETE FROM agent_schedule_fires WHERE schedule_id = ?",
                vec![schedule_id.to_string()],
            ),
            // S1: delete the schedule; RETURNING signals whether it still existed
            // (a concurrent delete between locate and here yields no row).
            D1ProxyStatement::with_params(
                "DELETE FROM agent_schedules WHERE schedule_id = ? RETURNING schedule_id",
                vec![schedule_id.to_string()],
            ),
        ];
        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 2 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: delete_agent_schedule batch returned fewer than 2 \
                 per-statement results"
                    .to_string(),
            ));
        }
        Ok(!results[1].results.is_empty())
    }

    /// Idempotently record a fire (the at-most-once gate). The fire carries no
    /// tenant, and a fire lives in the SAME tenant DB as its schedule, so this
    /// locates the schedule's binding (fan-out), then runs the guarded
    /// `INSERT ... ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING
    /// RETURNING fire_id`. A RETURNING row means THIS caller won the slot
    /// (`true`); an empty set means a concurrent instance already recorded it
    /// (`false`) — the correctness gate for at-most-once firing, identical to
    /// Postgres. `Err(NotFound)` when the schedule is unknown (no tenant DB to
    /// route the fire into — the write divergence). Fails closed without a proxy.
    pub(super) async fn insert_agent_schedule_fire_d1_async(
        &self,
        fire: &StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        let proxy = self.proxy_client("insert_agent_schedule_fire")?;
        let Some((binding, _schedule)) = self
            .locate_agent_schedule("insert_agent_schedule_fire", &fire.schedule_id)
            .await?
        else {
            return Err(StorageError::NotFound(format!(
                "agent schedule {} does not exist",
                fire.schedule_id
            )));
        };
        // Timestamps are STORED values (no CAST); nullable columns ride
        // `NULLIF(?, '')`.
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO agent_schedule_fires \
             (fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, node_id, outcome, \
              dispatch_id, run_id, detail) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING \
             RETURNING fire_id",
            vec![
                fire.fire_id.clone(),
                fire.schedule_id.clone(),
                fire.scheduled_fire_at_unix.to_string(),
                fire.fired_at_unix.to_string(),
                fire.node_id.clone().unwrap_or_default(),
                fire.outcome.as_str().to_string(),
                fire.dispatch_id.clone().unwrap_or_default(),
                fire.run_id.clone().unwrap_or_default(),
                fire.detail.clone().unwrap_or_default(),
            ],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(!result.results.is_empty())
    }

    /// List a schedule's fire history newest-first (issue #246 admin inspect). The
    /// signature carries no tenant; a schedule's fires all live in the one tenant
    /// DB holding the schedule, so this fans out over the provisioned tenant
    /// bindings (each with its own per-binding `LIMIT`) and re-merges to the
    /// Postgres order `scheduled_fire_at_unix DESC`, truncated to `limit`. At most
    /// one binding answers, so the union equals that binding's page. Empty for an
    /// unknown schedule. Fails closed without a proxy.
    pub(super) async fn list_agent_schedule_fires_d1_async(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        let proxy = self.proxy_client("list_agent_schedule_fires")?;
        let mut fires = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!(
                    "SELECT {AGENT_SCHEDULE_FIRE_COLUMNS} FROM agent_schedule_fires \
                     WHERE schedule_id = ? ORDER BY scheduled_fire_at_unix DESC LIMIT {limit}"
                ),
                vec![schedule_id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                fires.push(decode_row::<AgentScheduleFireD1Row>(row)?.into_stored()?);
            }
        }
        fires.sort_by_key(|fire| std::cmp::Reverse(fire.scheduled_fire_at_unix));
        fires.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(fires)
    }

    // --- tenant-DB helpers ---

    /// Fan out over the provisioned tenant bindings to find the database holding
    /// `schedule_id`, returning `(binding, schedule)` or `None`. The id is globally
    /// unique, so at most one binding answers.
    async fn locate_agent_schedule(
        &self,
        method: &'static str,
        schedule_id: &str,
    ) -> Result<Option<(String, StoredAgentSchedule)>, StorageError> {
        let proxy = self.proxy_client(method)?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!(
                    "SELECT {AGENT_SCHEDULE_COLUMNS} FROM agent_schedules WHERE schedule_id = ?"
                ),
                vec![schedule_id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if let Some(row) = result.results.first() {
                let schedule = decode_row::<AgentScheduleD1Row>(row)?.into_stored()?;
                return Ok(Some((binding, schedule)));
            }
        }
        Ok(None)
    }
}
