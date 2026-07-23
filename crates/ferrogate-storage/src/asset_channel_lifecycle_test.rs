// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the atomic channel/version
// lifecycle coordination (#367). Proves move/yank/unyank/variant-delete keep the
// invariant "every channel points at a resolvable version" as one step, and that
// a concurrent move-vs-yank race can never strand a channel -- using a barrier,
// not a timing sleep.

use std::sync::{Arc, Barrier};

use crate::schema_routing_test_support::block_on;
use crate::{
    asset_channel_id, stored_asset_variant_id, ChannelMoveOutcome, RuntimeStorageRepositories,
    StorageProviderKind, StoredAsset, StoredAssetChannel, VariantDeleteOutcome, VersionYankOutcome,
};

const TENANT: &str = "tenant-a";
const ASSET_TYPE: &str = "config_file";
const NAME: &str = "artifact";
const CHANNEL: &str = "stable";

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn asset(version: &str, variant: &str, yanked: bool) -> StoredAsset {
    StoredAsset {
        id: stored_asset_variant_id(TENANT, ASSET_TYPE, NAME, version, variant),
        tenant_id: TENANT.into(),
        project_id: None,
        asset_type: ASSET_TYPE.into(),
        name: NAME.into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "a".repeat(64),
        size_bytes: 8,
        content: vec![7; 8],
        storage_uri: None,
        variant: variant.into(),
        yanked,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn channel(version: &str) -> StoredAssetChannel {
    StoredAssetChannel {
        id: asset_channel_id(TENANT, ASSET_TYPE, NAME, CHANNEL),
        tenant_id: TENANT.into(),
        asset_type: ASSET_TYPE.into(),
        name: NAME.into(),
        channel: CHANNEL.into(),
        version: version.into(),
        updated_at_unix: 1,
    }
}

fn upsert(repositories: &RuntimeStorageRepositories, asset: StoredAsset) {
    block_on(repositories.upsert_asset(asset)).expect("upsert asset");
}

fn channel_version(repositories: &RuntimeStorageRepositories) -> Option<String> {
    block_on(repositories.list_asset_channels(TENANT, ASSET_TYPE, NAME))
        .expect("list channels")
        .into_iter()
        .find(|channel| channel.channel == CHANNEL)
        .map(|channel| channel.version)
}

fn version_is_yanked(repositories: &RuntimeStorageRepositories, version: &str) -> bool {
    block_on(repositories.list_assets(TENANT, Some(ASSET_TYPE)))
        .expect("list assets")
        .into_iter()
        .filter(|asset| asset.version == version)
        .any(|asset| asset.yanked)
}

#[test]
fn move_succeeds_only_when_the_target_is_resolvable() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "", false));

    // A resolvable target is moved and reports no prior version.
    assert_eq!(
        block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0")))
            .expect("move to resolvable"),
        ChannelMoveOutcome::Moved {
            prior_version: None
        },
    );

    // An absent target is rejected and never writes a channel row.
    assert_eq!(
        block_on(repositories.move_asset_channel_if_resolvable(channel("9.9.9")))
            .expect("move to absent"),
        ChannelMoveOutcome::TargetNotResolvable,
    );
    assert_eq!(channel_version(&repositories).as_deref(), Some("1.0.0"));

    // A yanked target is rejected too.
    upsert(&repositories, asset("2.0.0", "", true));
    assert_eq!(
        block_on(repositories.move_asset_channel_if_resolvable(channel("2.0.0")))
            .expect("move to yanked"),
        ChannelMoveOutcome::TargetNotResolvable,
    );
    assert_eq!(channel_version(&repositories).as_deref(), Some("1.0.0"));
}

#[test]
fn move_records_the_prior_target_for_audit() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "", false));
    upsert(&repositories, asset("2.0.0", "", false));
    block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0"))).expect("first move");
    assert_eq!(
        block_on(repositories.move_asset_channel_if_resolvable(channel("2.0.0")))
            .expect("second move"),
        ChannelMoveOutcome::Moved {
            prior_version: Some("1.0.0".into())
        },
    );
}

#[test]
fn yank_is_rejected_while_a_channel_references_the_version() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "", false));
    block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0"))).expect("move");

    assert_eq!(
        block_on(repositories.set_asset_version_yank(TENANT, ASSET_TYPE, NAME, "1.0.0", true, 5))
            .expect("yank referenced"),
        VersionYankOutcome::ReferencedByChannel,
    );
    assert!(!version_is_yanked(&repositories, "1.0.0"));

    // Once the channel is moved off, the yank succeeds atomically.
    block_on(
        repositories.delete_asset_channel(&asset_channel_id(TENANT, ASSET_TYPE, NAME, CHANNEL)),
    )
    .expect("delete channel");
    assert_eq!(
        block_on(repositories.set_asset_version_yank(TENANT, ASSET_TYPE, NAME, "1.0.0", true, 6))
            .expect("yank unreferenced"),
        VersionYankOutcome::Applied { variants: 1 },
    );
    assert!(version_is_yanked(&repositories, "1.0.0"));
}

#[test]
fn yank_of_a_missing_version_is_not_found() {
    let repositories = repositories();
    assert_eq!(
        block_on(repositories.set_asset_version_yank(TENANT, ASSET_TYPE, NAME, "1.0.0", true, 5))
            .expect("yank missing"),
        VersionYankOutcome::NotFound,
    );
}

#[test]
fn unyank_restores_resolvability_without_channel_coordination() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "", true));
    // Unyank never coordinates and always applies to every variant.
    assert_eq!(
        block_on(repositories.set_asset_version_yank(TENANT, ASSET_TYPE, NAME, "1.0.0", false, 7))
            .expect("unyank"),
        VersionYankOutcome::Applied { variants: 1 },
    );
    assert!(!version_is_yanked(&repositories, "1.0.0"));
    // Now the version is resolvable and can be moved onto.
    assert!(matches!(
        block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0")))
            .expect("move after unyank"),
        ChannelMoveOutcome::Moved { .. },
    ));
}

#[test]
fn variant_delete_blocks_the_last_resolvable_variant_of_a_referenced_version() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "linux-x86_64", false));
    upsert(&repositories, asset("1.0.0", "darwin-arm64", false));
    block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0"))).expect("move");

    // A multi-variant version stays resolvable, so removing one variant is fine.
    let linux_id = stored_asset_variant_id(TENANT, ASSET_TYPE, NAME, "1.0.0", "linux-x86_64");
    assert_eq!(
        block_on(repositories.delete_asset_variant_if_unreferenced(
            &linux_id, TENANT, ASSET_TYPE, NAME, "1.0.0",
        ))
        .expect("delete one of two variants"),
        VariantDeleteOutcome::Deleted,
    );

    // Deleting the last remaining resolvable variant would strand the channel.
    let darwin_id = stored_asset_variant_id(TENANT, ASSET_TYPE, NAME, "1.0.0", "darwin-arm64");
    assert_eq!(
        block_on(
            repositories.delete_asset_variant_if_unreferenced(
                &darwin_id, TENANT, ASSET_TYPE, NAME, "1.0.0",
            )
        )
        .expect("delete last variant"),
        VariantDeleteOutcome::BlockedByChannel,
    );
    // The row and the channel both survive the rejected delete.
    assert!(block_on(repositories.get_asset(&darwin_id))
        .expect("read survivor")
        .is_some());
    assert_eq!(channel_version(&repositories).as_deref(), Some("1.0.0"));
}

#[test]
fn variant_delete_of_an_unreferenced_version_succeeds() {
    let repositories = repositories();
    upsert(&repositories, asset("1.0.0", "", false));
    let id = stored_asset_variant_id(TENANT, ASSET_TYPE, NAME, "1.0.0", "");
    assert_eq!(
        block_on(
            repositories
                .delete_asset_variant_if_unreferenced(&id, TENANT, ASSET_TYPE, NAME, "1.0.0",)
        )
        .expect("delete unreferenced"),
        VariantDeleteOutcome::Deleted,
    );
    assert!(block_on(repositories.get_asset(&id))
        .expect("read deleted")
        .is_none());
}

/// The core #367 proof: a move and a yank racing on the same version, started
/// together on a barrier (never a timing sleep), can never leave the channel
/// pointing at a yanked version. Whichever wins the single serialization point
/// the other observes: move-then-yank leaves the channel on a live version and
/// rejects the yank; yank-then-move yanks the version and rejects the move.
#[test]
fn concurrent_move_and_yank_never_strand_a_channel() {
    let repositories = Arc::new(repositories());
    let channel_id = asset_channel_id(TENANT, ASSET_TYPE, NAME, CHANNEL);

    for iteration in 0..200 {
        // Reset to a resolvable, unreferenced version before each race.
        upsert(&repositories, asset("1.0.0", "", false));
        block_on(repositories.delete_asset_channel(&channel_id)).expect("reset channel");

        let barrier = Arc::new(Barrier::new(2));
        let mover = {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                block_on(repositories.move_asset_channel_if_resolvable(channel("1.0.0")))
                    .expect("concurrent move")
            })
        };
        let yanker = {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                block_on(
                    repositories.set_asset_version_yank(TENANT, ASSET_TYPE, NAME, "1.0.0", true, 9),
                )
                .expect("concurrent yank")
            })
        };
        let move_outcome = mover.join().expect("mover thread");
        let yank_outcome = yanker.join().expect("yanker thread");

        let channel_points_at = channel_version(&repositories);
        let yanked = version_is_yanked(&repositories, "1.0.0");

        // The invariant: a channel on 1.0.0 implies the version is NOT yanked,
        // and a yanked version implies no channel points at it.
        if channel_points_at.as_deref() == Some("1.0.0") {
            assert!(
                !yanked,
                "iteration {iteration}: channel points at 1.0.0 but it is yanked \
                 (move={move_outcome:?}, yank={yank_outcome:?})"
            );
        }
        if yanked {
            assert_ne!(
                channel_points_at.as_deref(),
                Some("1.0.0"),
                "iteration {iteration}: version yanked but channel still points at it \
                 (move={move_outcome:?}, yank={yank_outcome:?})"
            );
        }

        // Exactly one of the two operations wins; the outcomes are consistent.
        match (&move_outcome, &yank_outcome) {
            (ChannelMoveOutcome::Moved { .. }, VersionYankOutcome::ReferencedByChannel) => {}
            (ChannelMoveOutcome::TargetNotResolvable, VersionYankOutcome::Applied { .. }) => {}
            other => panic!("iteration {iteration}: inconsistent race outcome {other:?}"),
        }
    }
}
