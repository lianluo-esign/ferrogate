// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: In-memory backend coverage for the durable signed-snapshot
// replay floor (#206): monotonic advance, per-identity isolation, and
// non-colliding composite keys.

use crate::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories,
    SnapshotReplayFloorRepository, StorageProviderKind,
};

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

#[test]
fn replay_floor_is_absent_until_first_advance() {
    let repositories = memory_repositories();
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("tenant-a", "deploy-a")
            .expect("get must not error"),
        None,
        "an identity that never accepted a snapshot has no floor",
    );
}

#[test]
fn replay_floor_advances_monotonically_and_never_moves_backward() {
    let repositories = memory_repositories();
    assert_eq!(
        repositories
            .advance_snapshot_replay_floor("tenant-a", "deploy-a", 5, 1_000)
            .expect("advance must not error"),
        5,
    );
    // A stale writer with a LOWER revision must not lower the floor.
    assert_eq!(
        repositories
            .advance_snapshot_replay_floor("tenant-a", "deploy-a", 3, 2_000)
            .expect("advance must not error"),
        5,
        "a lower revision must leave the persisted floor untouched",
    );
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("tenant-a", "deploy-a")
            .expect("get must not error"),
        Some(5),
    );
    // A strictly newer revision raises it.
    assert_eq!(
        repositories
            .advance_snapshot_replay_floor("tenant-a", "deploy-a", 7, 3_000)
            .expect("advance must not error"),
        7,
    );
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("tenant-a", "deploy-a")
            .expect("get must not error"),
        Some(7),
    );
}

#[test]
fn replay_floors_are_isolated_per_identity() {
    let repositories = memory_repositories();
    repositories
        .advance_snapshot_replay_floor("tenant-a", "deploy-a", 9, 1_000)
        .expect("advance must not error");
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("tenant-a", "deploy-b")
            .expect("get must not error"),
        None,
        "a different deployment id must have an independent floor",
    );
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("tenant-b", "deploy-a")
            .expect("get must not error"),
        None,
        "a different tenant id must have an independent floor",
    );
}

#[test]
fn replay_floor_composite_keys_do_not_collide_on_crafted_ids() {
    // ("a", "b<US>c") must not alias ("a<US>b", "c"): the length-prefixed key
    // stays unambiguous even when the ids contain any candidate delimiter, so
    // shifting characters between the two fields must produce distinct floors.
    let repositories = memory_repositories();
    repositories
        .advance_snapshot_replay_floor("a", "b\u{1f}c", 4, 1_000)
        .expect("advance must not error");
    assert_eq!(
        repositories
            .get_snapshot_replay_floor("a\u{1f}b", "c")
            .expect("get must not error"),
        None,
        "crafted tenant/deployment ids must not alias another identity's floor",
    );
}

use crate::schema_routing_test_support::{
    query_i64, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};

/// #237: with a non-default `postgres_schema`, the durable replay floor must be
/// written to (and read from) the CONFIGURED schema, not the connection-default
/// `public` schema. This reproduces the live-Supabase misroute where the table
/// existed in both schemas and masked the bug: the row must land only in the
/// configured schema. Gated on `FERROGATE_TEST_POSTGRES_DSN` (non-TLS local
/// Postgres, like the other DSN-gated storage tests); skips cleanly when unset.
#[test]
fn live_replay_floor_writes_to_configured_schema_not_public() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_replay_floor_writes_to_configured_schema_not_public: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    // Serialize the DB-touching body against the sibling schema-routing tests so
    // the parallel run never opens a connection storm against the shared pooler.
    let _db = serialize_db_test();

    // A globally-unique, non-default control schema so the assertion is
    // meaningful and the test never collides with a real deployment schema or a
    // sibling test's schema.
    let schema = unique_schema("ferrogate_replay_floor_test");
    let tenant = "tenant-237";
    let deployment = "deploy-237";
    // Drop the unique schema + the test's `public` shadow row on scope exit,
    // even if an assertion below panics.
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.control_plane_replay_floors WHERE tenant_id = '{tenant}';"
    ));

    // Provision the replay-floor table in BOTH the configured schema and
    // `public`, exactly like the live project where the table's presence in both
    // schemas masked the misroute. Clear any stale `public` row so the negative
    // assertion below is unambiguous.
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             CREATE SCHEMA \"{schema}\"; \
             CREATE TABLE \"{schema}\".control_plane_replay_floors ( \
                 tenant_id TEXT NOT NULL, deployment_id TEXT NOT NULL, \
                 last_accepted_revision BIGINT NOT NULL, updated_at_unix BIGINT NOT NULL, \
                 PRIMARY KEY (tenant_id, deployment_id)); \
             CREATE TABLE IF NOT EXISTS public.control_plane_replay_floors ( \
                 tenant_id TEXT NOT NULL, deployment_id TEXT NOT NULL, \
                 last_accepted_revision BIGINT NOT NULL, updated_at_unix BIGINT NOT NULL, \
                 PRIMARY KEY (tenant_id, deployment_id)); \
             DELETE FROM public.control_plane_replay_floors WHERE tenant_id = '{tenant}';"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        // See `control_plane_schema_test::open_repositories`: generous timeouts +
        // a single connection keep the group hermetic on the shared live DB (#241).
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        // Non-default schema, no `public` fallback in the search path: a
        // regression to bare (non-search-path) queries would resolve against the
        // connection-default `public` schema and fail both assertions below.
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN");

    let advanced = repositories
        .advance_snapshot_replay_floor(tenant, deployment, 42, 1_700_000_000)
        .expect("advance must not error");
    assert_eq!(advanced, 42);
    assert_eq!(
        repositories
            .get_snapshot_replay_floor(tenant, deployment)
            .expect("get must not error"),
        Some(42),
        "the floor must read back from the configured schema",
    );
    drop(repositories);

    let in_schema = query_i64(
        &dsn,
        &format!(
            "SELECT last_accepted_revision FROM \"{schema}\".control_plane_replay_floors \
             WHERE tenant_id = '{tenant}' AND deployment_id = '{deployment}'"
        ),
    );
    assert_eq!(
        in_schema,
        Some(42),
        "the replay floor must be persisted in the configured schema",
    );

    let in_public = query_i64(
        &dsn,
        &format!(
            "SELECT last_accepted_revision FROM public.control_plane_replay_floors \
             WHERE tenant_id = '{tenant}' AND deployment_id = '{deployment}'"
        ),
    );
    assert_eq!(
        in_public, None,
        "the replay floor must NOT be misrouted to the public schema (#237)",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}
