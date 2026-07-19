// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Backend coverage for time-based agent schedules (#246): in-memory
// CRUD round-trip, due-schedule scan, and the idempotent fire-row conflict
// dedup that guarantees at-most-once firing per (schedule, slot). A DSN-gated
// live-Postgres test proves both the schema-routing pin (#237) and that two
// concurrent inserters for the same slot yield exactly one winner.

use crate::{
    agent_schedule_fire_id, CatchupPolicy, OverlapPolicy, RuntimeStorageRepositories,
    ScheduleFireOutcome, ScheduleSpecKind, ScheduleTargetKind, StorageProviderKind,
    StoredAgentSchedule, StoredAgentScheduleFire,
};

use crate::schema_routing_test_support::block_on;

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn sample_schedule(schedule_id: &str, next_fire_at_unix: Option<i64>) -> StoredAgentSchedule {
    StoredAgentSchedule {
        schedule_id: schedule_id.into(),
        tenant_id: "tenant-a".into(),
        workspace_id: "ws-a".into(),
        name: format!("schedule {schedule_id}"),
        enabled: true,
        spec_kind: ScheduleSpecKind::Interval,
        cron_expr: None,
        timezone: "UTC".into(),
        interval_secs: Some(60),
        target_kind: ScheduleTargetKind::SelfHostedDispatch,
        target_json: "{\"workload_ref\":\"self-hosted-workload://x\"}".into(),
        overlap_policy: OverlapPolicy::Skip,
        catchup_policy: CatchupPolicy::SkipMissed,
        jitter_secs: 0,
        next_fire_at_unix,
        last_fire_at_unix: None,
        created_at_unix: 1_000,
        updated_at_unix: 1_000,
        revision: 1,
    }
}

fn sample_fire(
    schedule_id: &str,
    slot: i64,
    outcome: ScheduleFireOutcome,
) -> StoredAgentScheduleFire {
    StoredAgentScheduleFire {
        fire_id: agent_schedule_fire_id(schedule_id, slot),
        schedule_id: schedule_id.into(),
        scheduled_fire_at_unix: slot,
        fired_at_unix: slot + 1,
        node_id: Some("node-1".into()),
        outcome,
        dispatch_id: Some(format!("dispatch-{schedule_id}-{slot}")),
        run_id: None,
        detail: None,
    }
}

#[test]
fn in_memory_schedule_crud_round_trips() {
    let repositories = memory_repositories();
    let schedule = sample_schedule("sched-1", Some(2_000));
    block_on(repositories.upsert_agent_schedule(schedule.clone())).expect("upsert");

    let fetched = block_on(repositories.get_agent_schedule("sched-1"))
        .expect("get")
        .expect("schedule present");
    assert_eq!(fetched, schedule);

    // Update in place: same id, changed fields, higher revision.
    let mut updated = schedule.clone();
    updated.name = "renamed".into();
    updated.enabled = false;
    updated.revision = 2;
    block_on(repositories.upsert_agent_schedule(updated.clone())).expect("update");
    let fetched = block_on(repositories.get_agent_schedule("sched-1"))
        .expect("get")
        .expect("still present");
    assert_eq!(fetched.name, "renamed");
    assert!(!fetched.enabled);
    assert_eq!(fetched.revision, 2);

    let listed =
        block_on(repositories.list_agent_schedules("tenant-a", Some("ws-a"))).expect("list");
    assert_eq!(listed.len(), 1);

    // Wrong tenant/workspace scope yields nothing.
    assert!(
        block_on(repositories.list_agent_schedules("tenant-b", None))
            .expect("list")
            .is_empty()
    );

    assert!(block_on(repositories.delete_agent_schedule("sched-1")).expect("delete"));
    assert!(block_on(repositories.get_agent_schedule("sched-1"))
        .expect("get")
        .is_none());
    assert!(
        !block_on(repositories.delete_agent_schedule("sched-1")).expect("delete"),
        "deleting a missing schedule reports no row removed",
    );
}

#[test]
fn in_memory_list_due_filters_disabled_and_future() {
    let repositories = memory_repositories();
    block_on(repositories.upsert_agent_schedule(sample_schedule("due-now", Some(500))))
        .expect("upsert due");
    block_on(repositories.upsert_agent_schedule(sample_schedule("future", Some(5_000))))
        .expect("upsert future");
    let mut disabled = sample_schedule("disabled", Some(100));
    disabled.enabled = false;
    block_on(repositories.upsert_agent_schedule(disabled)).expect("upsert disabled");
    let mut unscheduled = sample_schedule("unscheduled", None);
    unscheduled.enabled = true;
    block_on(repositories.upsert_agent_schedule(unscheduled)).expect("upsert unscheduled");

    let due = block_on(repositories.list_due_agent_schedules(1_000, 10)).expect("list_due");
    let ids: Vec<_> = due.iter().map(|s| s.schedule_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["due-now"],
        "only the enabled, scheduled, past-due schedule is returned",
    );
}

#[test]
fn in_memory_fire_insert_is_idempotent_per_slot() {
    let repositories = memory_repositories();
    block_on(repositories.upsert_agent_schedule(sample_schedule("sched-1", Some(2_000))))
        .expect("upsert");

    let slot = 2_000;
    let first = block_on(repositories.insert_agent_schedule_fire(sample_fire(
        "sched-1",
        slot,
        ScheduleFireOutcome::Dispatched,
    )))
    .expect("first insert");
    assert!(first, "the first inserter for a slot wins");

    // A second inserter for the SAME slot (even with a different outcome) loses.
    let second = block_on(repositories.insert_agent_schedule_fire(sample_fire(
        "sched-1",
        slot,
        ScheduleFireOutcome::SkippedOverlap,
    )))
    .expect("second insert");
    assert!(!second, "a second inserter for the same slot must lose");

    // A different slot inserts cleanly.
    let next = block_on(repositories.insert_agent_schedule_fire(sample_fire(
        "sched-1",
        slot + 60,
        ScheduleFireOutcome::Dispatched,
    )))
    .expect("next slot insert");
    assert!(next, "a distinct slot is not blocked by the previous one");

    let fires =
        block_on(repositories.list_agent_schedule_fires("sched-1", 10)).expect("list fires");
    assert_eq!(fires.len(), 2, "two distinct slots recorded, no duplicate");
    assert_eq!(
        fires[0].scheduled_fire_at_unix, 2_060,
        "history is newest-slot first",
    );
    // The winning outcome for the contended slot is the FIRST writer's.
    let contended = fires
        .iter()
        .find(|fire| fire.scheduled_fire_at_unix == slot)
        .expect("contended slot present");
    assert_eq!(contended.outcome, ScheduleFireOutcome::Dispatched);
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage (#237 schema routing + #246 fire dedup).
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{
    query_i64, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{PostgresStorageConfig, PostgresTlsMode};

/// With a non-default `postgres_schema`, schedule + fire writes must land in the
/// CONFIGURED schema, not the connection-default `public`, and the fire-row
/// UNIQUE (schedule_id, scheduled_fire_at_unix) constraint must dedup a second
/// inserter for the same slot. Gated on `FERROGATE_TEST_POSTGRES_DSN`; skips
/// cleanly when unset.
#[test]
fn live_agent_schedule_writes_to_configured_schema_and_dedups_fires() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_agent_schedule_writes_to_configured_schema_and_dedups_fires: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_agent_schedule_test");
    let schedule_id = "sched-246";
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.agent_schedule_fires WHERE schedule_id = '{schedule_id}'; \
         DELETE FROM public.agent_schedules WHERE schedule_id = '{schedule_id}';"
    ));

    // Provision the two tables in BOTH the configured schema and `public`, so a
    // regression to bare (non-search-path) queries would misroute to `public`
    // and fail the negative assertion below.
    let ddl = "CREATE TABLE IF NOT EXISTS {S}.agent_schedules ( \
             schedule_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, workspace_id TEXT NOT NULL, \
             name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, spec_kind TEXT NOT NULL, \
             cron_expr TEXT, timezone TEXT NOT NULL DEFAULT 'UTC', interval_secs BIGINT, \
             target_kind TEXT NOT NULL, target_json JSONB NOT NULL DEFAULT '{}'::JSONB, \
             overlap_policy TEXT NOT NULL DEFAULT 'skip', catchup_policy TEXT NOT NULL DEFAULT 'skip_missed', \
             jitter_secs BIGINT NOT NULL DEFAULT 0, next_fire_at_unix BIGINT, last_fire_at_unix BIGINT, \
             created_at_unix BIGINT NOT NULL, updated_at_unix BIGINT NOT NULL, revision BIGINT NOT NULL DEFAULT 1); \
         CREATE TABLE IF NOT EXISTS {S}.agent_schedule_fires ( \
             fire_id TEXT PRIMARY KEY, \
             schedule_id TEXT NOT NULL REFERENCES {S}.agent_schedules(schedule_id) ON DELETE CASCADE, \
             scheduled_fire_at_unix BIGINT NOT NULL, fired_at_unix BIGINT NOT NULL, node_id TEXT, \
             outcome TEXT NOT NULL, dispatch_id TEXT, run_id TEXT, detail TEXT, \
             UNIQUE (schedule_id, scheduled_fire_at_unix));";
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; {} {}",
            ddl.replace("{S}", &format!("\"{schema}\"")),
            ddl.replace("{S}", "public"),
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

    let schedule = sample_schedule(schedule_id, Some(1_700_000_000));
    block_on(repositories.upsert_agent_schedule(schedule.clone())).expect("upsert schedule");

    let fetched = block_on(repositories.get_agent_schedule(schedule_id))
        .expect("get")
        .expect("schedule present");
    // Postgres normalizes JSONB whitespace, so compare parsed values not bytes.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&fetched.target_json).unwrap(),
        serde_json::from_str::<serde_json::Value>(&schedule.target_json).unwrap(),
        "JSONB round-trips (semantically)",
    );

    let due = block_on(repositories.list_due_agent_schedules(1_700_000_000, 10)).expect("list_due");
    assert!(due.iter().any(|s| s.schedule_id == schedule_id));

    let slot = 1_700_000_000;
    let first = block_on(repositories.insert_agent_schedule_fire(sample_fire(
        schedule_id,
        slot,
        ScheduleFireOutcome::Dispatched,
    )))
    .expect("first fire insert");
    let second = block_on(repositories.insert_agent_schedule_fire(sample_fire(
        schedule_id,
        slot,
        ScheduleFireOutcome::SkippedOverlap,
    )))
    .expect("second fire insert");
    assert!(first && !second, "exactly one inserter wins the slot");
    drop(repositories);

    // The schedule lands in the configured schema, not public.
    assert_eq!(
        query_i64(
            &dsn,
            &format!("SELECT count(*) FROM \"{schema}\".agent_schedules WHERE schedule_id = '{schedule_id}'"),
        ),
        Some(1),
    );
    assert_eq!(
        query_i64(
            &dsn,
            &format!(
                "SELECT count(*) FROM public.agent_schedules WHERE schedule_id = '{schedule_id}'"
            ),
        ),
        Some(0),
        "schedule must NOT be misrouted to public (#237)",
    );
    // Exactly one fire row for the contended slot in the configured schema.
    assert_eq!(
        query_i64(
            &dsn,
            &format!(
                "SELECT count(*) FROM \"{schema}\".agent_schedule_fires \
                 WHERE schedule_id = '{schedule_id}' AND scheduled_fire_at_unix = {slot}"
            ),
        ),
        Some(1),
        "the UNIQUE constraint dedups the contended slot to a single fire row",
    );
}
