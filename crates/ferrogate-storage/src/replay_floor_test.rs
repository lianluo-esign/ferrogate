// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: In-memory backend coverage for the durable signed-snapshot
// replay floor (#206): monotonic advance, per-identity isolation, and
// non-colliding composite keys.

use crate::{RuntimeStorageRepositories, SnapshotReplayFloorRepository, StorageProviderKind};

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
