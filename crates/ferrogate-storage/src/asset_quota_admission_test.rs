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
