// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the #378 out-of-band promotion
// CAS: a `pending_scan` asset transitions to `visible`/`quarantined` ONLY from
// the pending state, and a missing or already-terminal row is rejected
// fail-closed (never silently re-promoted). Proves the promoted state becomes
// (non-)downloadable to match the target, and that two concurrent promotions of
// the same row can never both succeed -- started together on a barrier, never a
// timing sleep. In-memory always; live Postgres CAS is DSN-gated below.

use std::sync::{Arc, Barrier};

use crate::schema_routing_test_support::block_on;
use crate::{
    stored_asset_id, AssetPromotionTarget, AssetVisibility, AssetVisibilityPromotionOutcome,
    RuntimeStorageRepositories, StorageProviderKind, StoredAsset,
};

const TENANT: &str = "tenant-promote";
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

fn visibility_of(repositories: &RuntimeStorageRepositories, id: &str) -> AssetVisibility {
    block_on(repositories.get_asset(id))
        .expect("read asset")
        .expect("asset present")
        .visibility
}

#[test]
fn pending_promotes_to_visible_and_becomes_downloadable() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::PendingScan))).unwrap();
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0");

    // A withheld asset is not downloadable before promotion.
    assert!(!block_on(repositories.get_asset(&id))
        .unwrap()
        .unwrap()
        .is_downloadable());

    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &id,
            AssetPromotionTarget::Visible,
            42,
        ))
        .expect("promote clean"),
        AssetVisibilityPromotionOutcome::Promoted {
            to: AssetVisibility::Visible
        },
    );

    let promoted = block_on(repositories.get_asset(&id)).unwrap().unwrap();
    assert_eq!(promoted.visibility, AssetVisibility::Visible);
    assert!(
        promoted.is_downloadable(),
        "a promoted-to-visible asset must be downloadable"
    );
    assert_eq!(promoted.updated_at_unix, 42, "the CAS stamps updated_at");
}

#[test]
fn pending_promotes_to_quarantined_and_stays_withheld() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::PendingScan))).unwrap();
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0");

    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &id,
            AssetPromotionTarget::Quarantined,
            7,
        ))
        .expect("promote flagged"),
        AssetVisibilityPromotionOutcome::Promoted {
            to: AssetVisibility::Quarantined
        },
    );

    let quarantined = block_on(repositories.get_asset(&id)).unwrap().unwrap();
    assert_eq!(quarantined.visibility, AssetVisibility::Quarantined);
    assert!(
        !quarantined.is_downloadable(),
        "a quarantined asset must remain withheld"
    );
}

#[test]
fn already_visible_is_rejected_fail_closed() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::Visible))).unwrap();
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0");

    // A non-pending (already terminal) asset is never re-promoted; the current
    // state is reported so the caller can classify it (409), and nothing is
    // written.
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &id,
            AssetPromotionTarget::Quarantined,
            9,
        ))
        .expect("reject already-visible"),
        AssetVisibilityPromotionOutcome::NotPending {
            current: AssetVisibility::Visible
        },
    );
    // The rejected promotion left the row untouched.
    let after = block_on(repositories.get_asset(&id)).unwrap().unwrap();
    assert_eq!(after.visibility, AssetVisibility::Visible);
    assert_eq!(
        after.updated_at_unix, 1,
        "a rejected CAS must not stamp the row"
    );
}

#[test]
fn already_quarantined_is_rejected_fail_closed() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::Quarantined))).unwrap();
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0");

    // A quarantined asset can never be laundered to visible through the
    // promotion path -- it is terminal, so the CAS refuses.
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &id,
            AssetPromotionTarget::Visible,
            9,
        ))
        .expect("reject already-quarantined"),
        AssetVisibilityPromotionOutcome::NotPending {
            current: AssetVisibility::Quarantined
        },
    );
    assert_eq!(
        visibility_of(&repositories, &id),
        AssetVisibility::Quarantined
    );
}

#[test]
fn missing_asset_is_not_found() {
    let repositories = repositories();
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "9.9.9");
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &id,
            AssetPromotionTarget::Visible,
            1,
        ))
        .expect("promote missing"),
        AssetVisibilityPromotionOutcome::NotFound,
    );
}

/// The #378 concurrency proof: two promotions racing on the SAME `pending_scan`
/// row, started together on a barrier (never a timing sleep), can never both
/// succeed. Whichever crosses the single serialization point first flips the
/// row out of `pending_scan`; the other observes a terminal state and is
/// rejected `NotPending`. Exactly one `Promoted` per race, and the row ends in
/// exactly the winner's target.
#[test]
fn concurrent_promotions_cannot_both_succeed() {
    let repositories = Arc::new(repositories());
    let id = stored_asset_id(TENANT, ASSET_TYPE, NAME, "1.0.0");

    for iteration in 0..200 {
        // Reset the row to pending before each race.
        block_on(repositories.upsert_asset(asset("1.0.0", AssetVisibility::PendingScan))).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        // One racer promotes to visible, the other to quarantined, so the
        // winner's target is observable in the final state.
        let promoter = |target: AssetPromotionTarget| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            let id = id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(repositories.promote_pending_asset_visibility(&id, target, 5))
                    .expect("concurrent promote")
            })
        };
        let a = promoter(AssetPromotionTarget::Visible);
        let b = promoter(AssetPromotionTarget::Quarantined);
        let outcome_a = a.join().expect("racer a");
        let outcome_b = b.join().expect("racer b");

        let promoted: Vec<AssetVisibility> = [outcome_a, outcome_b]
            .into_iter()
            .filter_map(|outcome| match outcome {
                AssetVisibilityPromotionOutcome::Promoted { to } => Some(to),
                AssetVisibilityPromotionOutcome::NotPending { current } => {
                    // The loser must observe a terminal state, never pending.
                    assert_ne!(
                        current,
                        AssetVisibility::PendingScan,
                        "iteration {iteration}: loser saw pending_scan -- both could promote"
                    );
                    None
                }
                AssetVisibilityPromotionOutcome::NotFound => {
                    panic!("iteration {iteration}: row vanished mid-race")
                }
            })
            .collect();

        assert_eq!(
            promoted.len(),
            1,
            "iteration {iteration}: exactly one promotion must win, got {promoted:?}"
        );
        assert_eq!(
            visibility_of(&repositories, &id),
            promoted[0],
            "iteration {iteration}: the row must end in the winner's target"
        );
    }
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage of the conditional CAS (migration 051,
// #366/#378). Proves the single data-modifying-CTE UPDATE fires only from
// `pending_scan` and classifies the zero-row case against real Postgres
// snapshot semantics. Gated on `FERROGATE_TEST_POSTGRES_DSN`; skips when unset.
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{run_sql, serialize_db_test, unique_schema, SchemaGuard};
use crate::{PostgresStorageConfig, PostgresTlsMode, POSTGRES_SCHEMA_SQL};

#[test]
fn live_promotion_cas_fires_only_from_pending() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_promotion_cas_fires_only_from_pending: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_asset_promotion_test");
    let _guard = SchemaGuard::new(&dsn, &schema);

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL} \
             INSERT INTO \"{schema}\".tenants (id, name, slug) \
             VALUES ('{TENANT}', 'promote tenant', '{TENANT}') ON CONFLICT (id) DO NOTHING;"
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

    let pending = asset("1.0.0", AssetVisibility::PendingScan);
    block_on(repositories.upsert_asset(pending.clone())).expect("persist pending asset");

    // First promotion fires from pending -> visible.
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &pending.id,
            AssetPromotionTarget::Visible,
            100,
        ))
        .expect("live promote"),
        AssetVisibilityPromotionOutcome::Promoted {
            to: AssetVisibility::Visible
        },
    );
    assert_eq!(
        visibility_of(&repositories, &pending.id),
        AssetVisibility::Visible
    );

    // Second promotion is a no-op: the row is terminal, so the CAS refuses.
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &pending.id,
            AssetPromotionTarget::Quarantined,
            101,
        ))
        .expect("live re-promote"),
        AssetVisibilityPromotionOutcome::NotPending {
            current: AssetVisibility::Visible
        },
    );

    // A missing row is NotFound.
    assert_eq!(
        block_on(repositories.promote_pending_asset_visibility(
            &stored_asset_id(TENANT, ASSET_TYPE, NAME, "0.0.1"),
            AssetPromotionTarget::Visible,
            102,
        ))
        .expect("live promote missing"),
        AssetVisibilityPromotionOutcome::NotFound,
    );
}
