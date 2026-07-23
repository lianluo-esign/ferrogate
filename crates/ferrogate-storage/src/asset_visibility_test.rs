// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the #366 asset trust-screening
// visibility state. Proves the state the push path persists is exactly the
// state the read path reads back (write-path == read-path, the #188 guard):
// a `PendingScan`/`Quarantined` row round-trips as withheld and only `Visible`
// is downloadable. In-memory always; live Postgres round trip is DSN-gated.

use crate::schema_routing_test_support::block_on;
use crate::{
    stored_asset_id, AssetVisibility, RuntimeStorageRepositories, StorageProviderKind, StoredAsset,
};

const TENANT: &str = "tenant-vis";
const ASSET_TYPE: &str = "cli_tool";
const NAME: &str = "deploy";

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn asset(version: &str, visibility: AssetVisibility) -> StoredAsset {
    StoredAsset {
        id: stored_asset_id(TENANT, ASSET_TYPE, NAME, version),
        tenant_id: TENANT.into(),
        project_id: None,
        asset_type: ASSET_TYPE.into(),
        name: NAME.into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "hash".into(),
        size_bytes: 3,
        content: vec![1, 2, 3],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn visibility_state_round_trips_and_only_visible_is_downloadable() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::Visible))).unwrap();
    block_on(repositories.upsert_asset(asset("1.1.0", AssetVisibility::PendingScan))).unwrap();
    block_on(repositories.upsert_asset(asset("1.2.0", AssetVisibility::Quarantined))).unwrap();

    // The state the push path persisted is the exact state the read path reads
    // back -- no silent downgrade to `Visible`.
    let clean =
        block_on(repositories.get_asset(&stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0")))
            .unwrap()
            .expect("clean asset present");
    assert_eq!(clean.visibility, AssetVisibility::Visible);
    assert!(clean.is_downloadable());

    let pending =
        block_on(repositories.get_asset(&stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.1.0")))
            .unwrap()
            .expect("pending asset present");
    assert_eq!(pending.visibility, AssetVisibility::PendingScan);
    assert!(!pending.is_downloadable());

    let quarantined =
        block_on(repositories.get_asset(&stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.2.0")))
            .unwrap()
            .expect("quarantined asset present");
    assert_eq!(quarantined.visibility, AssetVisibility::Quarantined);
    assert!(!quarantined.is_downloadable());

    // A withheld row is still durably persisted (present for operator
    // inspection / out-of-band promotion) -- withheld is not deleted.
    let all = block_on(repositories.list_assets(TENANT, Some(ASSET_TYPE))).unwrap();
    assert_eq!(
        all.len(),
        3,
        "withheld rows must remain persisted, not dropped"
    );
    let downloadable: Vec<&StoredAsset> =
        all.iter().filter(|asset| asset.is_downloadable()).collect();
    assert_eq!(
        downloadable.len(),
        1,
        "exactly the one Visible version is downloadable"
    );
    assert_eq!(downloadable[0].version, "1.0.0");
}

#[test]
fn unknown_persisted_state_fails_closed_to_withheld() {
    // The read path must never treat an unrecognized/poisoned state token as
    // downloadable (#188): an unknown token maps to Quarantined, not Visible.
    assert_eq!(
        AssetVisibility::from_stored("not-a-real-state"),
        AssetVisibility::Quarantined
    );
    assert!(!AssetVisibility::from_stored("").is_downloadable());
    assert!(AssetVisibility::from_stored("visible").is_downloadable());
    assert!(!AssetVisibility::from_stored("pending_scan").is_downloadable());
    assert!(!AssetVisibility::from_stored("quarantined").is_downloadable());
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage (migration 051, #366).
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{run_sql, serialize_db_test, unique_schema, SchemaGuard};
use crate::{PostgresStorageConfig, PostgresTlsMode, POSTGRES_SCHEMA_SQL};

/// Applying the full schema contract (incl. migration 051) to a fresh unique
/// schema, a withheld asset must round-trip through the repository read path
/// with its `visibility` column populated exactly as written, in the
/// configured schema. Gated on `FERROGATE_TEST_POSTGRES_DSN`; skips when unset.
#[test]
fn live_visibility_column_round_trips_in_configured_schema() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_visibility_column_round_trips_in_configured_schema: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_asset_visibility_test");
    let _guard = SchemaGuard::new(&dsn, &schema);

    // A tenants row is required by the stored_assets FK; provision it after the
    // full schema contract lands.
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL} \
             INSERT INTO \"{schema}\".tenants (id, name, slug) \
             VALUES ('{TENANT}', 'vis tenant', '{TENANT}') ON CONFLICT (id) DO NOTHING;"
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

    let quarantined = asset("9.9.9", AssetVisibility::Quarantined);
    block_on(repositories.upsert_asset(quarantined.clone())).expect("persist quarantined asset");

    let stored = block_on(repositories.get_asset(&quarantined.id))
        .expect("read asset")
        .expect("quarantined asset present");
    assert_eq!(
        stored.visibility,
        AssetVisibility::Quarantined,
        "the persisted visibility must read back exactly, not default to Visible"
    );
    assert!(!stored.is_downloadable());
}
