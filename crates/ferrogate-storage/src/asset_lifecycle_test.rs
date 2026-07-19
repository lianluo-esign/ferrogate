// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the #263 asset lifecycle engine -- retention
// keep-last-N / TTL / channel-pin survivors, and unreferenced-blob GC
// (dry-run/grace/fail-safe-keep). Pure logic, no Postgres, no live bucket.

use std::collections::HashSet;

use super::{
    pinned_versions, plan_blob_gc, plan_log_retention, plan_version_retention, retention_policy_id,
    BucketObject, LogRetentionCandidate, RetentionPolicy, StoredRetentionPolicy,
    RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT,
};
use crate::{stored_asset_variant_id, StoredAsset, StoredAssetChannel};

const NOW: i64 = 1_000_000;

fn asset_at(name: &str, version: &str, variant: &str, created: i64) -> StoredAsset {
    StoredAsset {
        id: stored_asset_variant_id("t1", "cli_tool", name, version, variant),
        tenant_id: "t1".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: name.into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "hash".into(),
        size_bytes: 100,
        content: Vec::new(),
        // Bucket-backed so retention has a storage_uri to reap.
        storage_uri: Some(stored_asset_variant_id(
            "t1", "cli_tool", name, version, variant,
        )),
        variant: variant.into(),
        yanked: false,
        created_at_unix: created,
        updated_at_unix: created,
    }
}

fn channel(name: &str, channel: &str, version: &str) -> StoredAssetChannel {
    StoredAssetChannel {
        id: format!("t1:cli_tool:{name}:{channel}"),
        tenant_id: "t1".into(),
        asset_type: "cli_tool".into(),
        name: name.into(),
        channel: channel.into(),
        version: version.into(),
        updated_at_unix: NOW,
    }
}

fn keep_last(n: u64) -> RetentionPolicy {
    RetentionPolicy {
        keep_last_n: Some(n),
        max_age_secs: None,
        min_age_secs: 0,
    }
}

/// Acceptance: keep-last-2 on a name with 4 versions prunes the 2 oldest
/// unpinned versions, leaving the 2 newest.
#[test]
fn keep_last_2_prunes_the_two_oldest_of_four() {
    let assets = vec![
        asset_at("rg", "1.0.0", "", 100),
        asset_at("rg", "1.1.0", "", 200),
        asset_at("rg", "1.2.0", "", 300),
        asset_at("rg", "1.3.0", "", 400),
    ];
    let plan = plan_version_retention(&assets, &HashSet::new(), NOW, &keep_last(2));
    let pruned: HashSet<&str> = plan.targets.iter().map(|t| t.version.as_str()).collect();
    assert_eq!(pruned, HashSet::from(["1.0.0", "1.1.0"]));
    assert_eq!(plan.freed_bytes, 200);
}

/// Acceptance: a channel-pinned version is never pruned, even when it falls in
/// the keep-last-N prune window.
#[test]
fn channel_pinned_version_survives_keep_last_n() {
    let assets = vec![
        asset_at("rg", "1.0.0", "", 100), // oldest, but stable-pinned
        asset_at("rg", "1.1.0", "", 200),
        asset_at("rg", "1.2.0", "", 300),
        asset_at("rg", "1.3.0", "", 400),
    ];
    let pins = pinned_versions(&[channel("rg", "stable", "1.0.0")]);
    let plan = plan_version_retention(&assets, &pins, NOW, &keep_last(2));
    let pruned: HashSet<&str> = plan.targets.iter().map(|t| t.version.as_str()).collect();
    // 1.0.0 is pinned -> survives; only 1.1.0 (next-oldest unpinned) is pruned.
    assert_eq!(pruned, HashSet::from(["1.1.0"]));
}

/// TTL: max-age prunes everything older than the cutoff, keeps younger ones,
/// and still spares a pinned old version.
#[test]
fn max_age_prunes_old_versions_but_keeps_young_and_pinned() {
    let policy = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: Some(500),
        min_age_secs: 0,
    };
    let assets = vec![
        asset_at("rg", "old", "", NOW - 1_000), // older than cutoff -> prune
        asset_at("rg", "older", "", NOW - 2_000), // older than cutoff, but pinned
        asset_at("rg", "young", "", NOW - 100), // within cutoff -> keep
    ];
    let pins = pinned_versions(&[channel("rg", "stable", "older")]);
    let plan = plan_version_retention(&assets, &pins, NOW, &policy);
    let pruned: HashSet<&str> = plan.targets.iter().map(|t| t.version.as_str()).collect();
    assert_eq!(pruned, HashSet::from(["old"]));
}

/// Grace window: a version inside `min_age_secs` is never pruned even when it
/// is beyond the keep-last-N window.
#[test]
fn grace_window_spares_recently_created_versions() {
    let policy = RetentionPolicy {
        keep_last_n: Some(1),
        max_age_secs: None,
        min_age_secs: 3_600,
    };
    let assets = vec![
        asset_at("rg", "1.0.0", "", NOW - 10), // beyond keep window but < grace
        asset_at("rg", "1.1.0", "", NOW - 5),  // newest, kept by recency
    ];
    let plan = plan_version_retention(&assets, &HashSet::new(), NOW, &policy);
    assert!(
        plan.targets.is_empty(),
        "nothing older than the grace window, so nothing prunes"
    );
}

/// A rule with no size and no age dimension is inert -- never prunes.
#[test]
fn noop_policy_prunes_nothing() {
    let policy = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: None,
        min_age_secs: 0,
    };
    assert!(policy.is_noop());
    let assets = vec![
        asset_at("rg", "1.0.0", "", 100),
        asset_at("rg", "1.1.0", "", 200),
    ];
    let plan = plan_version_retention(&assets, &HashSet::new(), NOW, &policy);
    assert!(plan.targets.is_empty());
}

/// Pruning a version reaps ALL of its platform/arch variant rows together.
#[test]
fn pruning_a_version_reaps_all_its_variants() {
    let assets = vec![
        asset_at("rg", "1.0.0", "linux-x86_64", 100),
        asset_at("rg", "1.0.0", "darwin-arm64", 100),
        asset_at("rg", "1.1.0", "", 200),
    ];
    let plan = plan_version_retention(&assets, &HashSet::new(), NOW, &keep_last(1));
    let pruned_ids: HashSet<&str> = plan.targets.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(pruned_ids.len(), 2, "both 1.0.0 variants pruned");
    assert!(plan.targets.iter().all(|t| t.version == "1.0.0"));
    assert_eq!(plan.freed_bytes, 200);
}

/// GC deletes only an unreferenced, aged-out blob -- never a referenced one.
#[test]
fn gc_deletes_only_unreferenced_aged_orphans() {
    let objects = vec![
        BucketObject {
            key: "t1:cli_tool:rg:1.0.0".into(), // referenced -> keep
            last_modified_unix: NOW - 10_000,
        },
        BucketObject {
            key: "t1:cli_tool:orphan:9.9.9".into(), // unreferenced + old -> delete
            last_modified_unix: NOW - 10_000,
        },
    ];
    let referenced: HashSet<String> = HashSet::from(["t1:cli_tool:rg:1.0.0".to_string()]);
    let orphans = plan_blob_gc(&objects, &referenced, NOW, 3_600);
    assert_eq!(orphans, vec!["t1:cli_tool:orphan:9.9.9".to_string()]);
}

/// GC never reaps an unreferenced blob still inside the grace window (an
/// in-flight presigned commit whose registry row is about to be written).
#[test]
fn gc_respects_the_orphan_grace_window() {
    let objects = vec![BucketObject {
        key: "t1:cli_tool:inflight:1.0.0".into(),
        last_modified_unix: NOW - 60, // 60s old, grace is 1h -> keep
    }];
    let orphans = plan_blob_gc(&objects, &HashSet::new(), NOW, 3_600);
    assert!(orphans.is_empty());
}

/// Fail-safe: an object whose last-modified time is unknown is never deleted.
#[test]
fn gc_keeps_objects_with_unknown_age() {
    let objects = vec![BucketObject {
        key: "t1:cli_tool:unknown:1.0.0".into(),
        last_modified_unix: 0,
    }];
    let orphans = plan_blob_gc(&objects, &HashSet::new(), NOW, 0);
    assert!(orphans.is_empty());
}

/// Tenant isolation: one tenant's referenced key protects only that tenant's
/// blob; another tenant's identically-named-but-distinct orphan is still
/// reaped, and a referenced key never masks a different tenant's orphan.
#[test]
fn gc_is_tenant_scoped_by_key_namespace() {
    let objects = vec![
        BucketObject {
            key: "t1:cli_tool:rg:1.0.0".into(),
            last_modified_unix: NOW - 10_000,
        },
        BucketObject {
            key: "t2:cli_tool:rg:1.0.0".into(), // different tenant, unreferenced
            last_modified_unix: NOW - 10_000,
        },
    ];
    // Only t1's blob is referenced.
    let referenced: HashSet<String> = HashSet::from(["t1:cli_tool:rg:1.0.0".to_string()]);
    let orphans = plan_blob_gc(&objects, &referenced, NOW, 3_600);
    assert_eq!(orphans, vec!["t2:cli_tool:rg:1.0.0".to_string()]);
}

#[test]
fn retention_policy_id_is_deterministic_per_tenant_resource_scope() {
    assert_eq!(
        retention_policy_id("t1", RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT),
        "t1:asset:*"
    );
    assert_eq!(
        retention_policy_id("t1", RETENTION_RESOURCE_ASSET, "cli_tool/rg"),
        "t1:asset:cli_tool/rg"
    );
}

// -- #284: flat operational-log retention planner (request_logs/audit_events) --

fn log_candidate(id: &str, created: i64) -> LogRetentionCandidate {
    LogRetentionCandidate {
        id: id.into(),
        created_at_unix: created,
    }
}

#[test]
fn log_retention_prunes_rows_older_than_max_age() {
    // max-age 100s, no grace: NOW-200 is expired, NOW-50 survives.
    let policy = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: Some(100),
        min_age_secs: 0,
    };
    let candidates = vec![
        log_candidate("old", NOW - 200),
        log_candidate("fresh", NOW - 50),
    ];
    let pruned = plan_log_retention(&candidates, NOW, &policy);
    assert_eq!(pruned, vec!["old".to_string()]);
}

#[test]
fn log_retention_grace_window_spares_recent_rows_below_the_floor() {
    // A longer legal floor (grace) keeps everything younger than it even when
    // max-age would otherwise expire it (audit_events longer floor case).
    let policy = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: Some(10),
        min_age_secs: 500,
    };
    let candidates = vec![
        log_candidate("within-floor", NOW - 100),
        log_candidate("beyond-floor", NOW - 600),
    ];
    let pruned = plan_log_retention(&candidates, NOW, &policy);
    assert_eq!(pruned, vec!["beyond-floor".to_string()]);
}

#[test]
fn log_retention_keep_last_n_prunes_beyond_the_cap() {
    // keep newest 2 of 4, no age dimension.
    let policy = RetentionPolicy {
        keep_last_n: Some(2),
        max_age_secs: None,
        min_age_secs: 0,
    };
    let candidates = vec![
        log_candidate("r1", NOW - 400),
        log_candidate("r2", NOW - 300),
        log_candidate("r3", NOW - 200),
        log_candidate("r4", NOW - 100),
    ];
    let mut pruned = plan_log_retention(&candidates, NOW, &policy);
    pruned.sort();
    assert_eq!(pruned, vec!["r1".to_string(), "r2".to_string()]);
}

#[test]
fn log_retention_noop_policy_and_empty_input_prune_nothing() {
    let noop = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: None,
        min_age_secs: 0,
    };
    let candidates = vec![log_candidate("r1", NOW - 10_000)];
    assert!(plan_log_retention(&candidates, NOW, &noop).is_empty());

    let active = RetentionPolicy {
        keep_last_n: None,
        max_age_secs: Some(1),
        min_age_secs: 0,
    };
    assert!(plan_log_retention(&[], NOW, &active).is_empty());
}

#[test]
fn stored_retention_policy_projects_to_evaluated_policy_and_clamps_grace() {
    let stored = StoredRetentionPolicy {
        id: retention_policy_id("t1", RETENTION_RESOURCE_ASSET, RETENTION_SCOPE_DEFAULT),
        tenant_id: "t1".into(),
        resource_type: RETENTION_RESOURCE_ASSET.into(),
        scope: RETENTION_SCOPE_DEFAULT.into(),
        keep_last_n: Some(3),
        max_age_secs: Some(86_400),
        min_age_secs: -5, // negative grace clamps to 0
        created_at_unix: NOW,
        updated_at_unix: NOW,
    };
    let policy = stored.as_retention_policy();
    assert_eq!(policy.keep_last_n, Some(3));
    assert_eq!(policy.max_age_secs, Some(86_400));
    assert_eq!(policy.min_age_secs, 0);
    assert!(!policy.is_noop());
}
