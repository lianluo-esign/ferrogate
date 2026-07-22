// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for authoritative tenant asset
// storage accounting (#338), including a metadata-only Postgres projection.

use crate::schema_routing_test_support::{
    block_on, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{
    PostgresControlPlaneStore, PostgresStorageConfig, PostgresTlsMode, RuntimeControlPlaneBackend,
    RuntimeStorageRepositories, StorageError, StorageProviderKind, StoredAsset, StoredAssetChannel,
};

fn asset(id: &str, tenant_id: &str, size_bytes: u64) -> StoredAsset {
    StoredAsset {
        id: id.into(),
        tenant_id: tenant_id.into(),
        project_id: None,
        asset_type: "config_file".into(),
        name: id.into(),
        version: "1.0.0".into(),
        content_type: "application/octet-stream".into(),
        content_hash: "a".repeat(64),
        size_bytes,
        content: vec![7; 128],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn channel(id: &str) -> StoredAssetChannel {
    StoredAssetChannel {
        id: id.into(),
        tenant_id: "tenant-a".into(),
        asset_type: "config_file".into(),
        name: "artifact".into(),
        channel: "stable".into(),
        version: "1.0.0".into(),
        updated_at_unix: 1,
    }
}

fn poison_asset_repository(repositories: &RuntimeStorageRepositories) {
    let RuntimeControlPlaneBackend::Memory(control_plane) = &repositories.control_plane else {
        panic!("test repository must use the in-memory control plane");
    };
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = control_plane.lock().expect("lock before poisoning");
        panic!("poison the in-memory asset repository lock");
    }));
    assert!(
        panic.is_err(),
        "poisoning must unwind while holding the lock"
    );
}

fn assert_asset_repository_poisoned<T>(result: Result<T, StorageError>) {
    match result {
        Err(StorageError::Runtime(message)) => {
            assert_eq!(message, "in-memory asset repository lock is poisoned")
        }
        Err(error) => panic!("expected poisoned-lock runtime error, got {error}"),
        Ok(_) => panic!("poisoned asset repository must fail closed"),
    }
}

#[test]
fn in_memory_usage_sums_only_the_requested_tenants_rows() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    block_on(repositories.upsert_asset(asset("a", "tenant-a", 17))).expect("insert a");
    block_on(repositories.upsert_asset(asset("b", "tenant-a", 23))).expect("insert b");
    block_on(repositories.upsert_asset(asset("c", "tenant-b", 999))).expect("insert c");

    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage query"),
        40,
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-b")).expect("usage query"),
        999,
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("missing")).expect("usage query"),
        0,
    );
}

#[test]
fn poisoned_memory_lock_fails_closed_for_every_asset_repository_method() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    poison_asset_repository(&repositories);

    assert_asset_repository_poisoned(block_on(
        repositories.upsert_asset(asset("asset-a", "tenant-a", 17)),
    ));
    assert_asset_repository_poisoned(block_on(repositories.get_asset("asset-a")));
    assert_asset_repository_poisoned(block_on(repositories.list_assets("tenant-a", None)));
    assert_asset_repository_poisoned(block_on(
        repositories.tenant_asset_storage_bytes_used("tenant-a"),
    ));
    assert_asset_repository_poisoned(block_on(repositories.delete_asset("asset-a")));
    assert_asset_repository_poisoned(block_on(
        repositories.upsert_asset_channel(channel("channel-a")),
    ));
    assert_asset_repository_poisoned(block_on(repositories.list_asset_channels(
        "tenant-a",
        "config_file",
        "artifact",
    )));
    assert_asset_repository_poisoned(block_on(repositories.delete_asset_channel("channel-a")));
}

#[test]
fn postgres_usage_query_projects_only_size_bytes() {
    assert_eq!(
        PostgresControlPlaneStore::TENANT_ASSET_STORAGE_SIZE_QUERY,
        "SELECT size_bytes FROM stored_assets WHERE tenant_id = $1",
    );
}

/// The intentionally minimal live table contains none of the columns needed
/// by `list_assets`. A passing query therefore proves the durable usage path
/// reads only `tenant_id` + `size_bytes` and never fetches inline BYTEA.
#[test]
fn live_postgres_usage_uses_the_metadata_only_projection() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_postgres_usage_uses_the_metadata_only_projection: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_asset_usage_test");
    let _guard = SchemaGuard::new(&dsn, &schema);
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             CREATE SCHEMA \"{schema}\"; \
             CREATE TABLE \"{schema}\".stored_assets ( \
                 tenant_id TEXT NOT NULL, size_bytes BIGINT NOT NULL, content BYTEA NOT NULL \
             ); \
             CREATE INDEX ON \"{schema}\".stored_assets (tenant_id); \
             INSERT INTO \"{schema}\".stored_assets (tenant_id, size_bytes, content) VALUES \
                 ('tenant-a', 11, repeat('x', 100000)::bytea), \
                 ('tenant-a', 31, repeat('y', 100000)::bytea), \
                 ('tenant-b', 1000, repeat('z', 100000)::bytea);"
        ),
    );

    let repositories = RuntimeStorageRepositories::postgres_for_migration(
        PostgresStorageConfig {
            dsn: dsn.clone(),
            pool_size: 1,
            pool_acquire_timeout_millis: 30_000,
            tls_mode: PostgresTlsMode::Disable,
            tls_ca_cert_path: None,
            connect_timeout_secs: 20,
            statement_timeout_millis: 30_000,
            schema: Some(schema),
            search_path: Vec::new(),
        },
        false,
        false,
    )
    .expect("open test repository");

    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage query"),
        42,
    );
}
