// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Coverage for the #304 action-identity columns on timeline/audit
// rows: in-memory round trips, pre-migration (NULL) row compatibility, and a
// DSN-gated live-Postgres test proving the projection columns land populated
// in the CONFIGURED schema (#237/#239 schema-routing pin).

use ferrogate_core::TenantContext;

use crate::schema_routing_test_support::block_on;
use crate::{
    RuntimeStorageRepositories, StorageProviderKind, StoredAgentRunEvent, StoredAuditEvent,
};

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn sample_agent_run_event(id: &str) -> StoredAgentRunEvent {
    StoredAgentRunEvent {
        id: id.into(),
        run_id: "run-304".into(),
        request_id: format!("req-{id}"),
        trace_id: None,
        tenant: TenantContext {
            organization_id: Some("org_304".into()),
            ..TenantContext::default()
        },
        turn: 0,
        kind: "capability.allowed".into(),
        target: "tool:native.echo".into(),
        outcome: "allowed".into(),
        tool_call_id: None,
        message: Some("tool allowed by capability policy".into()),
        occurred_at_unix: Some(1_700_000_304),
        action_fingerprint: Some(format!(
            "sha256:{}",
            "ab".repeat(32) // 64 hex chars, canonical_target_sha256 shape
        )),
        decision: Some("allow".into()),
        decision_reason: Some("capability_allowed".into()),
        output_disposition: None,
    }
}

fn sample_audit_event(id: &str) -> StoredAuditEvent {
    StoredAuditEvent {
        id: id.into(),
        request_id: format!("req-{id}"),
        trace_id: None,
        agent_run_id: Some("run-304".into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: Some("admin".into()),
        tenant: TenantContext::default(),
        action: "tool.guardrail".into(),
        target: "tool:native.echo".into(),
        outcome: "redacted".into(),
        message: "tool output redacted by guardrail policy p (c): m".into(),
        occurred_at_unix: Some(1_700_000_304),
        action_fingerprint: None,
        decision: Some("degrade".into()),
        decision_reason: Some("audit_redacted".into()),
        output_disposition: Some("redacted".into()),
    }
}

#[test]
fn in_memory_agent_run_event_round_trips_action_identity_columns() {
    let repositories = memory_repositories();
    let event = sample_agent_run_event("evt-304-1");
    block_on(repositories.append_agent_run_event(event.clone())).expect("append");

    let events = block_on(repositories.agent_run_events());
    let stored = events
        .iter()
        .find(|stored| stored.id == "evt-304-1")
        .expect("event present");
    assert_eq!(stored, &event);
    assert_eq!(
        stored.action_fingerprint, event.action_fingerprint,
        "the fingerprint must survive persistence verbatim"
    );
    assert_eq!(stored.decision.as_deref(), Some("allow"));
    assert_eq!(
        stored.decision_reason.as_deref(),
        Some("capability_allowed")
    );
}

#[test]
fn in_memory_audit_event_round_trips_action_identity_columns() {
    let repositories = memory_repositories();
    let event = sample_audit_event("audit-304-1");
    block_on(repositories.append_audit_event(event.clone()));

    let events = block_on(repositories.audit_events());
    let stored = events
        .iter()
        .find(|stored| stored.id == "audit-304-1")
        .expect("event present");
    assert_eq!(stored, &event);
    assert_eq!(stored.output_disposition.as_deref(), Some("redacted"));
}

/// Pre-migration rows (and snapshots exported before #304) carry NO
/// action-identity keys. They must still deserialize — the new fields default
/// to `None` — so existing timeline/audit views keep rendering them.
#[test]
fn pre_migration_rows_without_action_identity_fields_still_deserialize() {
    let legacy_agent_event = serde_json::json!({
        "id": "evt-legacy",
        "run_id": "run-legacy",
        "request_id": "req-legacy",
        "trace_id": null,
        "tenant": TenantContext::default(),
        "turn": 0,
        "kind": "tool.execute",
        "target": "tool:legacy",
        "outcome": "success",
        "tool_call_id": null,
        "message": "legacy row",
        "occurred_at_unix": 1
    });
    let event: StoredAgentRunEvent =
        serde_json::from_value(legacy_agent_event).expect("legacy agent run event deserializes");
    assert_eq!(event.action_fingerprint, None);
    assert_eq!(event.decision, None);
    assert_eq!(event.decision_reason, None);
    assert_eq!(event.output_disposition, None);

    let legacy_audit_event = serde_json::json!({
        "id": "audit-legacy",
        "request_id": "req-legacy",
        "trace_id": null,
        "cluster_id": null,
        "node_id": null,
        "actor_api_key_id": null,
        "tenant": TenantContext::default(),
        "action": "config.validate",
        "target": "candidate_config",
        "outcome": "accepted",
        "message": "legacy audit row",
        "occurred_at_unix": 1
    });
    let event: StoredAuditEvent =
        serde_json::from_value(legacy_audit_event).expect("legacy audit event deserializes");
    assert_eq!(event.action_fingerprint, None);
    assert_eq!(event.decision, None);
    assert_eq!(event.output_disposition, None);

    // A NULL-column row also renders through the in-memory store views.
    let repositories = memory_repositories();
    block_on(repositories.append_audit_event(event.clone()));
    let listed = block_on(repositories.audit_events());
    assert!(listed.iter().any(|stored| stored.id == "audit-legacy"));
}

/// Rows without the new fields serialize WITHOUT the new keys
/// (`skip_serializing_if`), so snapshot/JSON documents for legacy-shaped rows
/// are byte-stable across the #304 upgrade.
#[test]
fn none_action_identity_fields_are_omitted_from_serialized_documents() {
    let mut event = sample_agent_run_event("evt-304-serde");
    event.action_fingerprint = None;
    event.decision = None;
    event.decision_reason = None;
    event.output_disposition = None;
    let value = serde_json::to_value(&event).expect("serialize");
    let object = value.as_object().expect("object");
    for key in [
        "action_fingerprint",
        "decision",
        "decision_reason",
        "output_disposition",
    ] {
        assert!(
            !object.contains_key(key),
            "None {key} must be omitted from the serialized document"
        );
    }
    let restored: StoredAgentRunEvent = serde_json::from_value(value).expect("round trip");
    assert_eq!(restored, event);
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage (#237/#239 schema routing + migration 045).
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{
    count_rows, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{PostgresStorageConfig, PostgresTlsMode, POSTGRES_SCHEMA_SQL};

/// Applying the full schema contract (incl. migration 045) to a fresh unique
/// schema, an appended timeline/audit row must land with its action-identity
/// COLUMNS populated (not just the JSON document), in the configured schema.
/// Gated on `FERROGATE_TEST_POSTGRES_DSN`; skips cleanly when unset.
#[test]
fn live_action_identity_columns_are_populated_in_configured_schema() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_action_identity_columns_are_populated_in_configured_schema: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_action_identity_test");
    let _guard = SchemaGuard::new(&dsn, &schema);

    // Provision the unique schema with the FULL schema contract, so migration
    // 045's ALTER TABLE columns exist exactly as a real deployment would have
    // them.
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL}"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN");

    let agent_event = sample_agent_run_event("evt-304-live");
    block_on(repositories.append_agent_run_event(agent_event.clone())).expect("append event");
    let audit_event = sample_audit_event("audit-304-live");
    block_on(repositories.append_audit_event(audit_event.clone()));

    // Round trip through the repository read path.
    let events = block_on(repositories.agent_run_events());
    let stored = events
        .iter()
        .find(|stored| stored.id == "evt-304-live")
        .expect("agent run event present");
    assert_eq!(stored, &agent_event);
    let audits = block_on(repositories.audit_events());
    let stored_audit = audits
        .iter()
        .find(|stored| stored.id == "audit-304-live")
        .expect("audit event present");
    assert_eq!(stored_audit, &audit_event);
    drop(repositories);

    // The queryable projection columns are populated in the configured schema.
    let fingerprint = agent_event.action_fingerprint.as_deref().unwrap();
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".agent_run_events \
                 WHERE id = 'evt-304-live' \
                   AND action_fingerprint = '{fingerprint}' \
                   AND decision = 'allow' \
                   AND decision_reason = 'capability_allowed' \
                   AND output_disposition IS NULL"
            ),
        ),
        1,
        "agent_run_events action-identity columns must be populated",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".audit_events \
                 WHERE id = 'audit-304-live' \
                   AND action_fingerprint IS NULL \
                   AND decision = 'degrade' \
                   AND decision_reason = 'audit_redacted' \
                   AND output_disposition = 'redacted'"
            ),
        ),
        1,
        "audit_events action-identity columns must be populated",
    );
}
