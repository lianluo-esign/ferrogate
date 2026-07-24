// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the ATOMIC tenant asset-storage
// quota admission (#371). The former admission was a read
// (`tenant_asset_storage_bytes_used`) then a separate `create_asset_if_absent`,
// so two commits for two DIFFERENT asset ids could both observe the same
// remaining capacity, both pass, and jointly overshoot the quota. These tests
// prove `create_asset_within_quota` folds the usage read, the quota guard, the
// immutability guard, and the insert into one atomic step: concurrent pushes
// that together exceed the quota admit exactly the fitting set and reject the
// rest, a same-id retry is never charged twice, and delete releases exactly the
// winner's bytes. Barrier/channel synchronized -- no timing sleeps.

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;

use crate::schema_routing_test_support::block_on;
use crate::{
    classify_asset_quota_admission, AssetQuotaAdmission, PostgresControlPlaneStore,
    RuntimeStorageRepositories, StorageProviderKind, StoredAsset,
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
        content: vec![7; 8],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

// -------- Single-push admit / reject --------

#[test]
fn single_push_is_admitted_when_it_fits_under_the_quota() {
    let repositories = repositories();
    let outcome = block_on(
        repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 40), Some(100)),
    )
    .expect("admission");
    assert_eq!(outcome, AssetQuotaAdmission::Admitted);
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        40,
        "an admitted push reserves exactly its bytes",
    );
}

#[test]
fn single_push_is_rejected_when_it_would_exceed_the_quota() {
    let repositories = repositories();
    // Seed 80 of a 100-byte quota, then a 40-byte push overshoots.
    assert_eq!(
        block_on(repositories.create_asset_within_quota(asset("seed", "tenant-a", 80), Some(100)))
            .expect("seed admission"),
        AssetQuotaAdmission::Admitted,
    );
    let outcome =
        block_on(repositories.create_asset_within_quota(asset("over", "tenant-a", 40), Some(100)))
            .expect("admission");
    assert_eq!(
        outcome,
        AssetQuotaAdmission::OverQuota {
            used_bytes: 80,
            attempted_bytes: 40,
            quota_bytes: 100,
        },
    );
    // The rejected push reserved nothing: no row, usage unchanged.
    assert!(
        block_on(repositories.get_asset("over"))
            .expect("read rejected")
            .is_none(),
        "a rejected push must not persist a row",
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        80,
        "a rejected push must not reserve bytes",
    );
}

#[test]
fn a_push_that_exactly_fills_the_quota_is_admitted() {
    let repositories = repositories();
    assert_eq!(
        block_on(
            repositories.create_asset_within_quota(asset("exact", "tenant-a", 100), Some(100))
        )
        .expect("admission"),
        AssetQuotaAdmission::Admitted,
        "used + size == quota is within budget",
    );
}

#[test]
fn unlimited_quota_admits_but_still_enforces_immutability() {
    let repositories = repositories();
    assert_eq!(
        block_on(repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 1_000), None))
            .expect("first admission"),
        AssetQuotaAdmission::Admitted,
    );
    // No quota bound, but the same id is still immutable (idempotent, uncharged).
    assert_eq!(
        block_on(repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 1_000), None))
            .expect("retry"),
        AssetQuotaAdmission::AlreadyExists,
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        1_000,
        "an unlimited-quota re-push of the same id is not charged twice",
    );
}

// -------- Same-id idempotent retry never double-charges (outcome-unknown retry) --------

#[test]
fn same_id_retry_is_never_charged_twice() {
    let repositories = repositories();
    assert_eq!(
        block_on(
            repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 40), Some(100))
        )
        .expect("first admission"),
        AssetQuotaAdmission::Admitted,
    );
    // A retry of the SAME id -- e.g. after an outcome-unknown result whose commit
    // actually landed -- must land on AlreadyExists and reserve nothing more, so
    // an unresolved-then-retried push can never double-reserve quota.
    for _ in 0..3 {
        assert_eq!(
            block_on(
                repositories
                    .create_asset_within_quota(asset("asset-a", "tenant-a", 40), Some(100),)
            )
            .expect("retry"),
            AssetQuotaAdmission::AlreadyExists,
        );
    }
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        40,
        "repeated same-id retries reserve the bytes exactly once",
    );
}

#[test]
fn an_existing_over_budget_id_retry_is_still_an_uncharged_conflict() {
    // Even when the tenant is already at/over quota, retrying an EXISTING id is a
    // conflict, never a false over-quota rejection and never a second charge.
    let repositories = repositories();
    assert_eq!(
        block_on(
            repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 100), Some(100))
        )
        .expect("fill the quota"),
        AssetQuotaAdmission::Admitted,
    );
    assert_eq!(
        block_on(
            repositories.create_asset_within_quota(asset("asset-a", "tenant-a", 100), Some(100))
        )
        .expect("retry at the quota ceiling"),
        AssetQuotaAdmission::AlreadyExists,
    );
}

// -------- Delete releases exactly the winner's bytes --------

#[test]
fn delete_releases_exactly_the_reserved_bytes_and_reopens_the_quota() {
    let repositories = repositories();
    assert_eq!(
        block_on(repositories.create_asset_within_quota(asset("keep", "tenant-a", 60), Some(100)))
            .expect("admit keep"),
        AssetQuotaAdmission::Admitted,
    );
    assert_eq!(
        block_on(repositories.create_asset_within_quota(asset("drop", "tenant-a", 40), Some(100)))
            .expect("admit drop"),
        AssetQuotaAdmission::Admitted,
    );
    // Quota is now full (100/100): a further push is rejected.
    assert!(matches!(
        block_on(
            repositories.create_asset_within_quota(asset("blocked", "tenant-a", 30), Some(100))
        )
        .expect("blocked"),
        AssetQuotaAdmission::OverQuota { .. }
    ));

    // Deleting `drop` releases EXACTLY its 40 bytes.
    assert!(block_on(repositories.delete_asset("drop")).expect("delete"));
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        60,
        "delete releases exactly the deleted row's bytes, no counter drift",
    );
    // The freed capacity admits the previously-blocked push.
    assert_eq!(
        block_on(
            repositories.create_asset_within_quota(asset("blocked", "tenant-a", 30), Some(100))
        )
        .expect("admit after release"),
        AssetQuotaAdmission::Admitted,
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        90,
    );
}

// -------- Concurrency: admit exactly the fitting set, reject the rest --------

/// The core acceptance: several concurrent pushes for DIFFERENT asset ids whose
/// combined size exceeds the remaining quota but each individually fits. Exactly
/// the fitting set is admitted and the rest receive the typed over-quota
/// rejection; the durable usage never exceeds the quota. Barrier-synchronized,
/// no timing sleeps.
#[test]
fn concurrent_pushes_admit_exactly_the_fitting_set_and_reject_the_rest() {
    // Quota 100; three 40-byte pushes for distinct ids. 40+40 = 80 <= 100 fits,
    // a third would be 120 > 100. So exactly two admit and one is rejected.
    const QUOTA: u64 = 100;
    const SIZE: u64 = 40;
    const PUSHES: usize = 3;
    const EXPECTED_ADMITTED: usize = 2;

    let repositories = Arc::new(repositories());
    let barrier = Arc::new(Barrier::new(PUSHES + 1));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for index in 0..PUSHES {
        let repositories = Arc::clone(&repositories);
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let candidate = asset(&format!("asset-{index}"), "tenant-a", SIZE);
            barrier.wait();
            let outcome = block_on(repositories.create_asset_within_quota(candidate, Some(QUOTA)))
                .expect("concurrent admission");
            tx.send(outcome).expect("report outcome");
        }));
    }
    drop(tx);
    barrier.wait();

    let outcomes: Vec<AssetQuotaAdmission> = rx.into_iter().collect();
    for handle in handles {
        handle.join().expect("admission worker");
    }

    let admitted = outcomes
        .iter()
        .filter(|o| matches!(o, AssetQuotaAdmission::Admitted))
        .count();
    let rejected = outcomes
        .iter()
        .filter(|o| matches!(o, AssetQuotaAdmission::OverQuota { .. }))
        .count();
    assert_eq!(
        admitted, EXPECTED_ADMITTED,
        "exactly the fitting set may be admitted concurrently",
    );
    assert_eq!(
        rejected,
        PUSHES - EXPECTED_ADMITTED,
        "every over-quota push gets a typed rejection, not a silent overshoot",
    );
    let used = block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage");
    assert_eq!(
        used,
        EXPECTED_ADMITTED as u64 * SIZE,
        "durable usage equals exactly the admitted set's bytes",
    );
    assert!(
        used <= QUOTA,
        "concurrent admission never lets durable usage exceed the quota",
    );
}

/// Two concurrent pushes that INDIVIDUALLY fit but JOINTLY exceed the quota:
/// exactly one wins, mirroring the acceptance's two-commit race directly.
#[test]
fn two_concurrent_pushes_that_jointly_exceed_the_quota_admit_exactly_one() {
    const QUOTA: u64 = 100;
    const SIZE: u64 = 60; // 60 fits alone; 120 does not.

    let repositories = Arc::new(repositories());
    let barrier = Arc::new(Barrier::new(3));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for tag in ["a", "b"] {
        let repositories = Arc::clone(&repositories);
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let candidate = asset(&format!("asset-{tag}"), "tenant-a", SIZE);
            barrier.wait();
            let outcome = block_on(repositories.create_asset_within_quota(candidate, Some(QUOTA)))
                .expect("concurrent admission");
            tx.send(outcome).expect("report outcome");
        }));
    }
    drop(tx);
    barrier.wait();

    let outcomes: Vec<AssetQuotaAdmission> = rx.into_iter().collect();
    for handle in handles {
        handle.join().expect("admission worker");
    }

    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, AssetQuotaAdmission::Admitted))
            .count(),
        1,
        "only one of two jointly-over-quota pushes may be admitted",
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, AssetQuotaAdmission::OverQuota { .. }))
            .count(),
        1,
        "the other gets the typed over-quota rejection",
    );
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used("tenant-a")).expect("usage"),
        SIZE,
        "durable usage reflects exactly the single winner",
    );
}

// -------- Truth-table classifier (shared by both backends) --------

#[test]
fn classifier_admitted_when_inserted() {
    assert_eq!(
        classify_asset_quota_admission(true, false, true, 0, 40, Some(100)),
        AssetQuotaAdmission::Admitted,
    );
}

#[test]
fn classifier_already_exists_takes_precedence_over_quota() {
    // An existing id is a conflict even if the quota guard failed -- a retry is
    // never a false over-quota rejection and never a second charge.
    assert_eq!(
        classify_asset_quota_admission(false, true, false, 100, 40, Some(100)),
        AssetQuotaAdmission::AlreadyExists,
    );
}

#[test]
fn classifier_over_quota_only_when_new_id_and_guard_failed() {
    assert_eq!(
        classify_asset_quota_admission(false, false, false, 80, 40, Some(100)),
        AssetQuotaAdmission::OverQuota {
            used_bytes: 80,
            attempted_bytes: 40,
            quota_bytes: 100,
        },
    );
}

#[test]
fn classifier_new_id_not_inserted_but_quota_ok_is_a_same_id_race_conflict() {
    // The rare Postgres `ON CONFLICT DO NOTHING` race: the id did not exist at the
    // guard snapshot and the quota guard passed, yet no row was inserted because a
    // concurrent commit won the id. That is a conflict, NOT a false over-quota.
    assert_eq!(
        classify_asset_quota_admission(false, false, true, 10, 40, Some(100)),
        AssetQuotaAdmission::AlreadyExists,
    );
}

// -------- Postgres statement shape (SQL inspection; no live DB required) --------

#[test]
fn postgres_quota_admission_is_one_conditional_insert_with_a_quota_guard() {
    let query = PostgresControlPlaneStore::CREATE_ASSET_WITHIN_QUOTA_QUERY;
    // One conditional INSERT ... SELECT guarded by the tenant usage sum and the
    // create-if-absent immutability check, classified in-statement.
    assert!(query.contains("INSERT INTO stored_assets"));
    assert!(query.contains("SUM(size_bytes)"));
    assert!(query.contains("EXISTS (SELECT 1 FROM stored_assets WHERE id = $1)"));
    assert!(query.contains("ON CONFLICT (id) DO NOTHING"));
    // The quota bound is optional (NULL = unlimited) and never an UPDATE.
    assert!(query.contains("$17::bigint IS NULL"));
    assert!(!query.contains("DO UPDATE"));
    // It reports the classification inputs back to the caller in one round trip.
    assert!(query.contains("inserted_count"));
    assert!(query.contains("id_exists"));
    assert!(query.contains("quota_ok"));
}

// -------- Live Postgres: the #369 inline immutable first-push race ------------
//
// The bounded live proof the test gate asked for: two CONCURRENT first pushes of
// the SAME immutable inline version (same `{tenant}/{type}/{name}/{version}`,
// DIFFERENT content bytes) race the `create_asset_within_quota` create-if-absent
// primitive against a real database. This is the repository floor the
// `asset_inline_publish` module (crate `ferrogate-cli`) is built on: exactly one
// concurrent push is admitted (`AssetQuotaAdmission::Admitted` -> the visible
// version), the loser observes the durable winner (`AssetQuotaAdmission::
// AlreadyExists`, which the inline-publish handler maps to the typed 409
// `asset_version_immutable`). The winner's durable row is internally consistent:
// its stored bytes, its metadata `content_hash`, its `size_bytes`, and the
// listing all belong to the SAME attempt, so a different-content race can never
// leave one attempt's hash pointing at another attempt's bytes. Unlimited quota
// (`None`) is used so the OverQuota arm is unreachable and this exercises the
// pure #369 create-if-absent invariant.
//
// Mirrors the #378 `live_promotion_cas_fires_only_from_pending` pattern exactly:
// DSN-gated (skips cleanly when `FERROGATE_TEST_POSTGRES_DSN` is unset),
// serialized against the shared pooler, unique per-run schema with RAII drop.
// Bounded: two connections, two inserts, one re-read, one listing -- no load or
// stress. The gate environment has live credentials and runs it on re-entry.
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{run_sql, serialize_db_test, unique_schema, SchemaGuard};
use crate::{stored_asset_id, PostgresStorageConfig, PostgresTlsMode, POSTGRES_SCHEMA_SQL};

const RACE_TENANT: &str = "tenant-369-first-push";
const RACE_ASSET_TYPE: &str = "cli_tool";
const RACE_NAME: &str = "deploy";
const RACE_VERSION: &str = "1.0.0";

/// One first-push candidate for the immutable version: SAME id as its rival, but
/// a DISTINCT content fingerprint (`content`, `content_hash`, and `size_bytes`
/// all keyed off `fill`) so a winner/loser mix-up would be observable as a row
/// whose stored hash does not match its stored bytes.
fn race_candidate(id: &str, fill: u8, size_bytes: u64) -> StoredAsset {
    StoredAsset {
        id: id.into(),
        tenant_id: RACE_TENANT.into(),
        project_id: None,
        asset_type: RACE_ASSET_TYPE.into(),
        name: RACE_NAME.into(),
        version: RACE_VERSION.into(),
        content_type: "application/octet-stream".into(),
        content_hash: format!("{fill:064x}"),
        size_bytes,
        content: vec![fill; size_bytes as usize],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn live_concurrent_first_pushes_admit_exactly_one_immutable_winner() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_concurrent_first_pushes_admit_exactly_one_immutable_winner: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_asset_inline_first_push_test");
    let _guard = SchemaGuard::new(&dsn, &schema);

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL} \
             INSERT INTO \"{schema}\".tenants (id, name, slug) \
             VALUES ('{RACE_TENANT}', 'first-push tenant', '{RACE_TENANT}') \
             ON CONFLICT (id) DO NOTHING;"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        // Two connections so both first pushes can genuinely hit Postgres at
        // once; the row-level `INSERT ... ON CONFLICT (id) DO NOTHING` is the
        // single serialization point that picks the one winner.
        pool_size: 2,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = Arc::new(
        RuntimeStorageRepositories::postgres_for_migration(config, false, false)
            .expect("open the postgres control plane against the test DSN"),
    );

    let id = stored_asset_id(RACE_TENANT, RACE_ASSET_TYPE, RACE_NAME, RACE_VERSION);

    // Two DIFFERENT-content first pushes of the SAME immutable version, released
    // together on a barrier (never a timing sleep).
    let attempts: [(u8, u64); 2] = [(0xAA, 8), (0xBB, 16)];
    let barrier = Arc::new(Barrier::new(attempts.len() + 1));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for (fill, size_bytes) in attempts {
        let repositories = Arc::clone(&repositories);
        let barrier = Arc::clone(&barrier);
        let id = id.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let candidate = race_candidate(&id, fill, size_bytes);
            barrier.wait();
            // Unlimited quota (`None`): the OverQuota arm is unreachable, so this
            // is the pure #369 create-if-absent first-push race.
            let outcome = block_on(repositories.create_asset_within_quota(candidate, None))
                .expect("concurrent first-push admission");
            tx.send((fill, size_bytes, outcome))
                .expect("report outcome");
        }));
    }
    drop(tx);
    barrier.wait();

    let outcomes: Vec<(u8, u64, AssetQuotaAdmission)> = rx.into_iter().collect();
    for handle in handles {
        handle.join().expect("first-push worker");
    }

    // Exactly one concurrent first push is admitted; the loser gets the typed
    // conflict (`AlreadyExists` -> 409 `asset_version_immutable` at the handler).
    let winners: Vec<&(u8, u64, AssetQuotaAdmission)> = outcomes
        .iter()
        .filter(|(_, _, outcome)| *outcome == AssetQuotaAdmission::Admitted)
        .collect();
    let losers: Vec<&(u8, u64, AssetQuotaAdmission)> = outcomes
        .iter()
        .filter(|(_, _, outcome)| *outcome == AssetQuotaAdmission::AlreadyExists)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent first push may win the immutable version: {outcomes:?}",
    );
    assert_eq!(
        losers.len(),
        1,
        "the losing first push must get the typed create-if-absent conflict, \
         never a silent overwrite: {outcomes:?}",
    );
    assert!(
        !outcomes
            .iter()
            .any(|(_, _, outcome)| matches!(outcome, AssetQuotaAdmission::OverQuota { .. })),
        "an unlimited-quota first-push race can never report OverQuota: {outcomes:?}",
    );
    let (winner_fill, winner_size, _) = *winners[0];

    // The durable winner is internally consistent: its stored bytes, its metadata
    // hash, and its size all belong to the SAME attempt -- a different-content
    // race never leaves one attempt's hash referencing another's bytes.
    let winner = block_on(repositories.get_asset(&id))
        .expect("re-read the durable winner")
        .expect("the winning immutable version must be visible");
    assert_eq!(winner.id, id);
    assert_eq!(
        winner.content_hash,
        format!("{winner_fill:064x}"),
        "the visible row's metadata hash must be the winner's own hash",
    );
    assert_eq!(
        winner.size_bytes, winner_size,
        "the visible row's size must be the winner's own size",
    );
    assert_eq!(
        winner.content,
        vec![winner_fill; winner_size as usize],
        "the visible row's stored bytes must be the winner's own bytes (no row/object hash mismatch)",
    );

    // The listing surface agrees: exactly one row for the version, and it is the
    // same winner (list / manifest / download can only resolve to one attempt).
    let listed = block_on(repositories.list_assets(RACE_TENANT, Some(RACE_ASSET_TYPE)))
        .expect("list the tenant's assets");
    assert_eq!(
        listed.len(),
        1,
        "exactly one immutable row survives the first-push race: {listed:?}",
    );
    assert_eq!(listed[0].id, id);
    assert_eq!(
        listed[0].content_hash, winner.content_hash,
        "the listed row is the same winner the download would serve",
    );

    // Only the winner's bytes were reserved; the loser reserved nothing.
    assert_eq!(
        block_on(repositories.tenant_asset_storage_bytes_used(RACE_TENANT)).expect("usage"),
        winner_size,
        "exactly the winner's bytes are reserved; the losing first push is uncharged",
    );
}
