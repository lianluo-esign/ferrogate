// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: managed + self-hosted worker stores (issue #449).

//! D1 backend: managed + self-hosted worker stores (issue #449).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    // --- Managed worker stores (issue #449, control DB) ---
    //
    // Each family is an upsert of the FULL record as a `*_json` document plus
    // the projection column its whole-table ORDER BY needs. Whole-table admin
    // reads with no routing tenant, so the CONTROL database owns them.

    pub(super) async fn upsert_managed_worker_template_async(
        &self,
        template: &StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        let template_json = serialize_storage_document(template)?;
        self.execute_control(
            "INSERT INTO managed_worker_templates (id, template_json) VALUES (?, ?) \
             ON CONFLICT (id) DO UPDATE SET template_json = excluded.template_json",
            vec![template.id.clone(), template_json],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_templates_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerTemplate>, StorageError> {
        self.fetch_control_documents(
            "SELECT template_json AS document_json FROM managed_worker_templates ORDER BY id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn upsert_agent_worker_instance_async(
        &self,
        instance: &StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        let instance_json = serialize_storage_document(instance)?;
        self.execute_control(
            "INSERT INTO agent_worker_instances (id, started_at_unix, instance_json) \
             VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             started_at_unix = excluded.started_at_unix, instance_json = excluded.instance_json",
            vec![
                instance.id.clone(),
                optional_number_param(instance.started_at_unix),
                instance_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn agent_worker_instances_async(
        &self,
    ) -> Result<Vec<StoredAgentWorkerInstance>, StorageError> {
        self.fetch_control_documents(
            "SELECT instance_json AS document_json FROM agent_worker_instances \
             ORDER BY started_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn upsert_managed_worker_session_async(
        &self,
        session: &StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        let session_json = serialize_storage_document(session)?;
        self.execute_control(
            "INSERT INTO managed_worker_sessions (id, requested_at_unix, session_json) \
             VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             requested_at_unix = excluded.requested_at_unix, session_json = excluded.session_json",
            vec![
                session.id.clone(),
                optional_number_param(session.requested_at_unix),
                session_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_sessions_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerSession>, StorageError> {
        self.fetch_control_documents(
            "SELECT session_json AS document_json FROM managed_worker_sessions \
             ORDER BY requested_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn append_managed_worker_lifecycle_event_async(
        &self,
        event: &StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        self.execute_control(
            "INSERT INTO managed_worker_lifecycle_events (id, occurred_at_unix, event_json) \
             VALUES (?, NULLIF(?, ''), ?) ON CONFLICT (id) DO NOTHING",
            vec![
                event.id.clone(),
                optional_number_param(event.occurred_at_unix),
                event_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_lifecycle_events_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerLifecycleEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT event_json AS document_json FROM managed_worker_lifecycle_events \
             ORDER BY occurred_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn upsert_managed_worker_isolation_selection_async(
        &self,
        selection: &StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        let selection_json = serialize_storage_document(selection)?;
        self.execute_control(
            "INSERT INTO managed_worker_isolation_selections \
             (session_id, selected_at_unix, selection_json) VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (session_id) DO UPDATE SET \
             selected_at_unix = excluded.selected_at_unix, \
             selection_json = excluded.selection_json",
            vec![
                selection.session_id.clone(),
                optional_number_param(selection.selected_at_unix),
                selection_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_isolation_selections_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationSelection>, StorageError> {
        self.fetch_control_documents(
            "SELECT selection_json AS document_json FROM managed_worker_isolation_selections \
             ORDER BY selected_at_unix ASC, session_id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn upsert_managed_worker_isolation_policy_async(
        &self,
        policy: &StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        let policy_json = serialize_storage_document(policy)?;
        self.execute_control(
            "INSERT INTO managed_worker_isolation_policies (session_id, policy_json) \
             VALUES (?, ?) \
             ON CONFLICT (session_id) DO UPDATE SET policy_json = excluded.policy_json",
            vec![policy.session_id.clone(), policy_json],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_isolation_policies_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationPolicy>, StorageError> {
        self.fetch_control_documents(
            "SELECT policy_json AS document_json FROM managed_worker_isolation_policies \
             ORDER BY session_id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn upsert_managed_worker_isolation_evidence_async(
        &self,
        evidence: &StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        let evidence_json = serialize_storage_document(evidence)?;
        self.execute_control(
            "INSERT INTO managed_worker_isolation_evidence (id, occurred_at_unix, evidence_json) \
             VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             occurred_at_unix = excluded.occurred_at_unix, \
             evidence_json = excluded.evidence_json",
            vec![
                evidence.id.clone(),
                optional_number_param(evidence.occurred_at_unix),
                evidence_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn managed_worker_isolation_evidence_async(
        &self,
    ) -> Result<Vec<StoredManagedWorkerIsolationEvidence>, StorageError> {
        self.fetch_control_documents(
            "SELECT evidence_json AS document_json FROM managed_worker_isolation_evidence \
             ORDER BY occurred_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    // --- Self-hosted worker stores (issue #449, control DB) ---
    //
    // Registrations/heartbeats/telemetry/artifacts/checkpoints/dispatches, each
    // a full-record `*_json` document plus the projection columns the
    // worker/run-filtered reads and orderings need. The Postgres capability
    // side-table is folded into the dispatch document. Same CONTROL-database
    // routing rationale as the managed families above.

    pub(super) async fn upsert_self_hosted_worker_registration_async(
        &self,
        registration: &StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        let registration_json = serialize_storage_document(registration)?;
        self.execute_control(
            "INSERT INTO self_hosted_worker_registrations \
             (id, registered_at_unix, registration_json) VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             registered_at_unix = excluded.registered_at_unix, \
             registration_json = excluded.registration_json",
            vec![
                registration.id.clone(),
                optional_number_param(registration.registered_at_unix),
                registration_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn self_hosted_worker_registrations_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerRegistration>, StorageError> {
        self.fetch_control_documents(
            "SELECT registration_json AS document_json FROM self_hosted_worker_registrations \
             ORDER BY registered_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn self_hosted_worker_registration_async(
        &self,
        worker_id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerRegistration>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT registration_json AS document_json FROM self_hosted_worker_registrations \
                 WHERE id = ?",
                vec![worker_id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn append_self_hosted_worker_heartbeat_async(
        &self,
        heartbeat: &StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        let heartbeat_json = serialize_storage_document(heartbeat)?;
        self.execute_control(
            "INSERT INTO self_hosted_worker_heartbeats \
             (id, worker_id, reported_at_unix, heartbeat_json) VALUES (?, ?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                heartbeat.id.clone(),
                heartbeat.worker_id.clone(),
                optional_number_param(heartbeat.reported_at_unix),
                heartbeat_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn self_hosted_worker_heartbeats_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerHeartbeat>, StorageError> {
        self.fetch_control_documents(
            "SELECT heartbeat_json AS document_json FROM self_hosted_worker_heartbeats \
             ORDER BY reported_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn latest_self_hosted_worker_heartbeat_async(
        &self,
        worker_id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerHeartbeat>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT heartbeat_json AS document_json FROM self_hosted_worker_heartbeats \
                 WHERE worker_id = ? ORDER BY reported_at_unix DESC, id DESC LIMIT 1",
                vec![worker_id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn append_self_hosted_worker_telemetry_event_async(
        &self,
        event: &StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        self.execute_control(
            "INSERT INTO self_hosted_worker_telemetry_events \
             (id, worker_id, run_id, occurred_at_unix, ingested_at_unix, event_json) \
             VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                event.id.clone(),
                event.worker_id.clone(),
                event.run_id.clone().unwrap_or_default(),
                optional_number_param(event.occurred_at_unix),
                optional_number_param(event.ingested_at_unix),
                event_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn self_hosted_worker_telemetry_events_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT event_json AS document_json FROM self_hosted_worker_telemetry_events \
             ORDER BY occurred_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn self_hosted_worker_telemetry_events_for_run_async(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        // Keep the NEWEST window (DESC + LIMIT) so a run exceeding the bound
        // preserves its latest lifecycle state, then reverse to the ascending
        // timeline the caller expects (issue #231 parity).
        let limit = if limit == 0 {
            i64::MAX
        } else {
            saturating_i64(limit as u64)
        };
        let sql = format!(
            "SELECT event_json AS document_json FROM self_hosted_worker_telemetry_events \
             WHERE run_id = ? ORDER BY occurred_at_unix DESC, ingested_at_unix DESC, id DESC \
             LIMIT {limit}"
        );
        let mut events: Vec<StoredSelfHostedWorkerTelemetryEvent> = self
            .fetch_control_documents(&sql, vec![run_id.to_string()])
            .await?;
        events.reverse();
        Ok(events)
    }

    pub(super) async fn self_hosted_worker_telemetry_events_for_worker_async(
        &self,
        worker_id: &str,
    ) -> Result<Vec<StoredSelfHostedWorkerTelemetryEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT event_json AS document_json FROM self_hosted_worker_telemetry_events \
             WHERE worker_id = ? ORDER BY occurred_at_unix ASC, ingested_at_unix ASC, id ASC",
            vec![worker_id.to_string()],
        )
        .await
    }

    pub(super) async fn upsert_self_hosted_worker_artifact_async(
        &self,
        artifact: &StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        let artifact_json = serialize_storage_document(artifact)?;
        self.execute_control(
            "INSERT INTO self_hosted_worker_artifacts \
             (id, worker_id, created_at_unix, artifact_json) VALUES (?, ?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             worker_id = excluded.worker_id, created_at_unix = excluded.created_at_unix, \
             artifact_json = excluded.artifact_json",
            vec![
                artifact.id.clone(),
                artifact.worker_id.clone(),
                optional_number_param(artifact.created_at_unix),
                artifact_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn self_hosted_worker_artifacts_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerArtifact>, StorageError> {
        self.fetch_control_documents(
            "SELECT artifact_json AS document_json FROM self_hosted_worker_artifacts \
             ORDER BY created_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn self_hosted_worker_artifact_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerArtifact>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT artifact_json AS document_json FROM self_hosted_worker_artifacts \
                 WHERE id = ?",
                vec![id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn upsert_self_hosted_worker_checkpoint_async(
        &self,
        checkpoint: &StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        let checkpoint_json = serialize_storage_document(checkpoint)?;
        self.execute_control(
            "INSERT INTO self_hosted_worker_checkpoints \
             (id, worker_id, created_at_unix, checkpoint_json) VALUES (?, ?, NULLIF(?, ''), ?) \
             ON CONFLICT (id) DO UPDATE SET \
             worker_id = excluded.worker_id, created_at_unix = excluded.created_at_unix, \
             checkpoint_json = excluded.checkpoint_json",
            vec![
                checkpoint.id.clone(),
                checkpoint.worker_id.clone(),
                optional_number_param(checkpoint.created_at_unix),
                checkpoint_json,
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn self_hosted_worker_checkpoints_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedWorkerCheckpoint>, StorageError> {
        self.fetch_control_documents(
            "SELECT checkpoint_json AS document_json FROM self_hosted_worker_checkpoints \
             ORDER BY created_at_unix ASC, id ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn self_hosted_worker_checkpoint_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredSelfHostedWorkerCheckpoint>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT checkpoint_json AS document_json FROM self_hosted_worker_checkpoints \
                 WHERE id = ?",
                vec![id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn self_hosted_worker_activity_stats_async(
        &self,
        worker_id: &str,
    ) -> Result<StoredSelfHostedWorkerActivityStats, StorageError> {
        // One control-database query with worker-filtered count/max subselects
        // -- the transaction-free equivalent of the Postgres four-table scan.
        let row: Option<SelfHostedWorkerActivityStatsRow> = self
            .fetch_control_optional(
                "SELECT \
                    (SELECT count(*) FROM self_hosted_worker_telemetry_events WHERE worker_id = ?) \
                        AS telemetry_event_count, \
                    (SELECT max(occurred_at_unix) FROM self_hosted_worker_telemetry_events \
                     WHERE worker_id = ?) AS latest_event_at_unix, \
                    (SELECT count(*) FROM self_hosted_worker_artifacts WHERE worker_id = ?) \
                        AS artifact_count, \
                    (SELECT max(created_at_unix) FROM self_hosted_worker_artifacts \
                     WHERE worker_id = ?) AS latest_artifact_at_unix, \
                    (SELECT count(*) FROM self_hosted_worker_checkpoints WHERE worker_id = ?) \
                        AS checkpoint_count, \
                    (SELECT max(created_at_unix) FROM self_hosted_worker_checkpoints \
                     WHERE worker_id = ?) AS latest_checkpoint_at_unix",
                vec![worker_id.to_string(); 6],
            )
            .await?;
        Ok(row
            .map(StoredSelfHostedWorkerActivityStats::from)
            .unwrap_or_default())
    }

    pub(super) async fn upsert_self_hosted_run_dispatch_async(
        &self,
        dispatch: &StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        let dispatch_json = serialize_storage_document(dispatch)?;
        self.execute_control(
            "INSERT INTO self_hosted_run_dispatches (dispatch_id, queued_at_unix, dispatch_json) \
             VALUES (?, NULLIF(?, ''), ?) \
             ON CONFLICT (dispatch_id) DO UPDATE SET \
             queued_at_unix = excluded.queued_at_unix, dispatch_json = excluded.dispatch_json",
            vec![
                dispatch.dispatch_id.clone(),
                optional_number_param(dispatch.queued_at_unix),
                dispatch_json,
            ],
        )
        .await
        .map(|_| ())
    }

    /// #502: reclaim one settled dispatch row. D1 keeps the whole dispatch as
    /// one JSON document, so there is no child table to drain first.
    pub(super) async fn delete_self_hosted_run_dispatch_async(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, StorageError> {
        self.execute_control(
            "DELETE FROM self_hosted_run_dispatches WHERE dispatch_id = ?",
            vec![dispatch_id.to_string()],
        )
        .await
        .map(|result| result.changes() > 0)
    }

    pub(super) async fn self_hosted_run_dispatches_async(
        &self,
    ) -> Result<Vec<StoredSelfHostedRunDispatch>, StorageError> {
        self.fetch_control_documents(
            "SELECT dispatch_json AS document_json FROM self_hosted_run_dispatches \
             ORDER BY queued_at_unix ASC, dispatch_id ASC",
            Vec::new(),
        )
        .await
    }
}
