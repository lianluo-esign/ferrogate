// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: agent runs/events, request/audit logs, replay floors (issue #447).

//! D1 backend: agent runs/events, request/audit logs, replay floors (issue #447).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    pub(super) async fn upsert_agent_run_async(
        &self,
        run: &StoredAgentRun,
    ) -> Result<(), StorageError> {
        let run_json = serialize_storage_document(run)?;
        let started_at_unix = saturating_i64(run.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = run.completed_at_unix.map(saturating_i64);
        self.execute_control(
            "INSERT INTO agent_runs \
             (id, request_id, tenant, started_at_unix, completed_at_unix, run_json) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             request_id = excluded.request_id, tenant = excluded.tenant, \
             started_at_unix = excluded.started_at_unix, \
             completed_at_unix = excluded.completed_at_unix, run_json = excluded.run_json",
            vec![
                run.id.clone(),
                run.request_id.clone(),
                tenant_storage_key(&run.tenant),
                started_at_unix.to_string(),
                optional_number_param(completed_at_unix),
                run_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn agent_run_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredAgentRun>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT run_json AS document_json FROM agent_runs WHERE id = ?",
                vec![id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn agent_runs_async(&self) -> Result<Vec<StoredAgentRun>, StorageError> {
        self.fetch_control_documents(
            "SELECT run_json AS document_json FROM agent_runs \
             ORDER BY started_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn agent_runs_by_ids_async(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAgentRun>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT run_json AS document_json FROM agent_runs WHERE id IN ({}) \
             ORDER BY started_at_unix ASC, id ASC",
            in_placeholders(run_ids.len())
        );
        self.fetch_control_documents(&sql, run_ids.to_vec()).await
    }

    pub(super) async fn append_agent_run_event_async(
        &self,
        event: &StoredAgentRunEvent,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.execute_control(
            "INSERT INTO agent_run_events \
             (id, run_id, request_id, tenant, occurred_at_unix, event_json) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                event.id.clone(),
                event.run_id.clone(),
                event.request_id.clone(),
                tenant_storage_key(&event.tenant),
                occurred_at_unix.to_string(),
                event_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn agent_run_events_async(
        &self,
    ) -> Result<Vec<StoredAgentRunEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT event_json AS document_json FROM agent_run_events \
             ORDER BY occurred_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn agent_run_events_for_runs_async(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAgentRunEvent>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT event_json AS document_json FROM agent_run_events WHERE run_id IN ({}) \
             ORDER BY occurred_at_unix ASC, id ASC",
            in_placeholders(run_ids.len())
        );
        self.fetch_control_documents(&sql, run_ids.to_vec()).await
    }

    pub(super) async fn append_request_log_async(
        &self,
        log: &StoredRequestLog,
    ) -> Result<(), StorageError> {
        let request_json = serialize_storage_document(log)?;
        let started_at_unix = saturating_i64(log.started_at_unix.unwrap_or_else(now_unix_seconds));
        let completed_at_unix = log.completed_at_unix.map(saturating_i64);
        self.execute_control(
            "INSERT INTO request_logs \
             (request_id, agent_run_id, tenant, started_at_unix, completed_at_unix, request_json) \
             VALUES (?, NULLIF(?, ''), ?, ?, NULLIF(?, ''), ?) \
             ON CONFLICT (request_id) DO UPDATE SET \
             agent_run_id = excluded.agent_run_id, tenant = excluded.tenant, \
             started_at_unix = excluded.started_at_unix, \
             completed_at_unix = excluded.completed_at_unix, request_json = excluded.request_json",
            vec![
                log.request_id.clone(),
                log.agent_run_id.clone().unwrap_or_default(),
                tenant_storage_key(&log.tenant),
                started_at_unix.to_string(),
                optional_number_param(completed_at_unix),
                request_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn request_logs_async(&self) -> Result<Vec<StoredRequestLog>, StorageError> {
        self.fetch_control_documents(
            "SELECT request_json AS document_json FROM request_logs \
             ORDER BY started_at_unix ASC, request_id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn request_logs_page_async(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredRequestLog>, StorageError> {
        let sql = format!(
            "SELECT request_json AS document_json, count(*) OVER() AS total FROM request_logs \
             ORDER BY started_at_unix ASC, request_id ASC LIMIT {} OFFSET {}",
            saturating_i64(limit as u64),
            saturating_i64(offset as u64)
        );
        self.fetch_control_document_page(&sql, offset, limit).await
    }

    pub(super) async fn delete_request_logs_async(
        &self,
        request_ids: &[String],
    ) -> Result<u64, StorageError> {
        if request_ids.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "DELETE FROM request_logs WHERE request_id IN ({})",
            in_placeholders(request_ids.len())
        );
        let result = self.execute_control(&sql, request_ids.to_vec()).await?;
        Ok(result.changes())
    }

    pub(super) async fn request_logs_for_agent_runs_async(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredRequestLog>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT request_json AS document_json FROM request_logs WHERE agent_run_id IN ({}) \
             ORDER BY started_at_unix ASC, request_id ASC",
            in_placeholders(run_ids.len())
        );
        self.fetch_control_documents(&sql, run_ids.to_vec()).await
    }

    pub(super) async fn append_audit_event_async(
        &self,
        event: &StoredAuditEvent,
    ) -> Result<(), StorageError> {
        let audit_json = serialize_storage_document(event)?;
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        self.execute_control(
            "INSERT INTO audit_events \
             (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json) \
             VALUES (?, ?, NULLIF(?, ''), ?, ?, ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                event.id.clone(),
                event.request_id.clone(),
                event.agent_run_id.clone().unwrap_or_default(),
                tenant_storage_key(&event.tenant),
                occurred_at_unix.to_string(),
                audit_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn audit_events_async(&self) -> Result<Vec<StoredAuditEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT audit_json AS document_json FROM audit_events \
             ORDER BY occurred_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn audit_events_page_async(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<StoredAuditEvent>, StorageError> {
        let sql = format!(
            "SELECT audit_json AS document_json, count(*) OVER() AS total FROM audit_events \
             ORDER BY occurred_at_unix ASC, id ASC LIMIT {} OFFSET {}",
            saturating_i64(limit as u64),
            saturating_i64(offset as u64)
        );
        self.fetch_control_document_page(&sql, offset, limit).await
    }

    pub(super) async fn delete_audit_events_async(
        &self,
        ids: &[String],
    ) -> Result<u64, StorageError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "DELETE FROM audit_events WHERE id IN ({})",
            in_placeholders(ids.len())
        );
        let result = self.execute_control(&sql, ids.to_vec()).await?;
        Ok(result.changes())
    }

    pub(super) async fn audit_events_for_agent_runs_async(
        &self,
        run_ids: &[String],
    ) -> Result<Vec<StoredAuditEvent>, StorageError> {
        if run_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT audit_json AS document_json FROM audit_events WHERE agent_run_id IN ({}) \
             ORDER BY occurred_at_unix ASC, id ASC",
            in_placeholders(run_ids.len())
        );
        self.fetch_control_documents(&sql, run_ids.to_vec()).await
    }

    /// Distinct agent-run ids known to the durable store, most recently seen
    /// first, LIMITed in SQL (issue #231) -- a direct translation of the
    /// Postgres four-way `UNION ALL` seed. `request_id`, when present, narrows
    /// each source; the bound value repeats once per `?` (one per subquery).
    pub(super) async fn agent_run_summary_seed_ids_async(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        let (run_filter, event_filter, params) = match request_id {
            Some(request_id) => (
                "WHERE request_id = ?",
                "AND request_id = ?",
                vec![request_id.to_string(); 4],
            ),
            None => ("", "", Vec::new()),
        };
        let sql = format!(
            "SELECT run_id FROM ( \
                 SELECT id AS run_id, coalesce(completed_at_unix, started_at_unix, 0) AS seen_at \
                 FROM agent_runs {run_filter} \
               UNION ALL \
                 SELECT run_id, occurred_at_unix AS seen_at FROM agent_run_events {run_filter} \
               UNION ALL \
                 SELECT agent_run_id AS run_id, \
                        coalesce(completed_at_unix, started_at_unix, 0) AS seen_at \
                 FROM request_logs WHERE agent_run_id IS NOT NULL {event_filter} \
               UNION ALL \
                 SELECT agent_run_id AS run_id, occurred_at_unix AS seen_at FROM audit_events \
                 WHERE agent_run_id IS NOT NULL {event_filter} \
             ) seeds \
             GROUP BY run_id \
             ORDER BY max(seen_at) DESC, run_id ASC \
             LIMIT {limit}",
            limit = saturating_i64(limit as u64)
        );
        let rows: Vec<SeedIdRow> = self.fetch_control_rows(&sql, params).await?;
        Ok(rows.into_iter().map(|row| row.run_id).collect())
    }

    // --- Snapshot replay floors (issue #206/#447, control DB) ---

    pub(super) async fn get_snapshot_replay_floor_async(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        let row: Option<ReplayFloorRow> = self
            .fetch_control_optional(
                "SELECT last_accepted_revision FROM control_plane_replay_floors \
                 WHERE tenant_id = ? AND deployment_id = ?",
                vec![tenant_id.to_string(), deployment_id.to_string()],
            )
            .await?;
        Ok(row.map(|row| u64::try_from(row.last_accepted_revision).unwrap_or(0)))
    }

    /// Monotonically raise the persisted replay floor (issue #206). SQLite
    /// `max()` in the upsert guarantees the stored floor never moves backward;
    /// a follow-up SELECT returns the resulting floor (the HTTP query API
    /// exposes no `RETURNING`, as with `take_sso_pending_flow`).
    pub(super) async fn advance_snapshot_replay_floor_async(
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
        self.execute_control(
            "INSERT INTO control_plane_replay_floors \
             (tenant_id, deployment_id, last_accepted_revision, updated_at_unix) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (tenant_id, deployment_id) DO UPDATE SET \
             last_accepted_revision = max( \
                 control_plane_replay_floors.last_accepted_revision, \
                 excluded.last_accepted_revision), \
             updated_at_unix = CASE \
                 WHEN excluded.last_accepted_revision > \
                      control_plane_replay_floors.last_accepted_revision \
                 THEN excluded.updated_at_unix \
                 ELSE control_plane_replay_floors.updated_at_unix END",
            vec![
                tenant_id.to_string(),
                deployment_id.to_string(),
                revision.to_string(),
                updated_at_unix.to_string(),
            ],
        )
        .await?;
        Ok(self
            .get_snapshot_replay_floor_async(tenant_id, deployment_id)
            .await?
            .unwrap_or(0))
    }
}
