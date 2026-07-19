// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Asset lifecycle engine (issue #263) -- version retention
// policies + unreferenced-blob garbage collection. This is the pure,
// side-effect-free core: the storage/table shape (`StoredRetentionPolicy`) and
// the two planning functions the gateway sweeper applies against the real
// registry + bucket. Keeping the decisions here (rather than in the sweeper)
// makes them exhaustively unit-testable with no Postgres and no live bucket,
// and keeps the hot-path/sweeper wiring surgical.
//
// The whole engine is fail-safe: on ANY doubt it KEEPS. Retention never prunes
// a channel-pinned version or one still inside the grace window; GC never
// deletes a blob a `stored_assets` row references, nor one whose age can't be
// established, nor one still inside the grace window.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{StoredAsset, StoredAssetChannel};

/// Resource-type discriminator on a [`StoredRetentionPolicy`]. Assets are the
/// first (and, at #263, only) adopter, but the table shape is deliberately
/// general so request_logs/audit_events/metering TTL can adopt the same engine
/// later (filed separately) without a schema change.
pub const RETENTION_RESOURCE_ASSET: &str = "asset";

/// Resource-type discriminator for the compliance-data adopters (issue #284):
/// per-tenant TTL/purge over the high-write operational tables, driven by the
/// same [`StoredRetentionPolicy`] rows + sweeper #263 built for assets.
pub const RETENTION_RESOURCE_REQUEST_LOG: &str = "request_logs";
/// Resource-type discriminator for `audit_events` retention (issue #284).
/// Audit rows typically carry a LONGER legal floor than request logs.
pub const RETENTION_RESOURCE_AUDIT_EVENT: &str = "audit_events";

/// The wildcard `scope` value: the tenant-wide default policy for a
/// `resource_type`, applied to any `{asset_type}/{name}` without a more
/// specific policy row.
pub const RETENTION_SCOPE_DEFAULT: &str = "*";

/// Scope narrowing `request_logs` retention to just the rows that captured a
/// response body (`response_recorded`), which get the shortest default TTL
/// (issue #284 -- data minimization for the highest-sensitivity captures).
pub const RETENTION_SCOPE_RESPONSE_BODY: &str = "response_body";

/// A durable, generalizable retention rule (issue #263). NOT hard-coded to
/// assets: `resource_type` selects the engine (`asset` today) and `scope`
/// narrows it (`*` = the tenant default, or an exact `{asset_type}/{name}` for
/// assets). A rule keeps the newest `keep_last_n` items and/or anything younger
/// than `max_age_secs`, and NEVER touches anything younger than `min_age_secs`
/// (the safety grace window). All-`None` size/age dimensions mean "no pruning"
/// (a pure no-op), so an empty or absent policy can never delete anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRetentionPolicy {
    pub id: String,
    pub tenant_id: String,
    /// Which retention engine this rule drives; [`RETENTION_RESOURCE_ASSET`]
    /// for asset versions.
    pub resource_type: String,
    /// Narrowing selector within `resource_type`: [`RETENTION_SCOPE_DEFAULT`]
    /// (`*`) for the tenant default, or an exact `{asset_type}/{name}` for a
    /// single asset line.
    pub scope: String,
    /// Keep the newest N versions/items. `None` disables the count dimension.
    pub keep_last_n: Option<u64>,
    /// Prune anything older than this many seconds. `None` disables the age
    /// dimension.
    pub max_age_secs: Option<i64>,
    /// Grace window: never prune anything younger than this many seconds, even
    /// if it is otherwise a prune candidate. Guards a just-pushed version from
    /// being reaped between its write and a channel move.
    pub min_age_secs: i64,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Deterministic id so a retention policy is idempotent per
/// `(tenant_id, resource_type, scope)`, mirroring [`crate::stored_asset_id`].
pub fn retention_policy_id(tenant_id: &str, resource_type: &str, scope: &str) -> String {
    format!("{tenant_id}:{resource_type}:{scope}")
}

impl StoredRetentionPolicy {
    /// The [`RetentionPolicy`] evaluated by [`plan_version_retention`]. Split
    /// from the stored row so the pure planner never depends on the storage
    /// type.
    pub fn as_retention_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            keep_last_n: self.keep_last_n,
            max_age_secs: self.max_age_secs,
            min_age_secs: self.min_age_secs.max(0),
        }
    }
}

/// The evaluated retention rule (the [`StoredRetentionPolicy`] minus its
/// identity/audit columns). A rule with both size/age dimensions `None` is an
/// explicit no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub keep_last_n: Option<u64>,
    pub max_age_secs: Option<i64>,
    pub min_age_secs: i64,
}

impl RetentionPolicy {
    /// Whether this rule can ever prune anything. A rule with no count and no
    /// age dimension is inert -- the sweeper skips it entirely.
    pub fn is_noop(&self) -> bool {
        self.keep_last_n.is_none() && self.max_age_secs.is_none()
    }
}

/// One `stored_assets` row selected for pruning by [`plan_version_retention`].
/// Carries exactly what the sweeper needs to delete the blob and reconcile
/// quota, without re-fetching the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPruneTarget {
    pub id: String,
    pub version: String,
    pub variant: String,
    /// Bucket object key when the row is bucket-backed; `None` for an inline
    /// row (nothing to delete from the bucket).
    pub storage_uri: Option<String>,
    pub size_bytes: u64,
}

/// The outcome of evaluating a retention rule against one asset line's rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Every variant row belonging to a pruned version.
    pub targets: Vec<RetentionPruneTarget>,
    /// Bytes freed once the targets are deleted -- returned to the tenant's
    /// asset storage quota (the quota is a live SUM over remaining rows, so
    /// this is the reconciliation delta, surfaced for audit/metrics).
    pub freed_bytes: u64,
}

/// Decide which versions of ONE `{tenant, asset_type, name}` line to prune.
///
/// `assets` is every variant row across every version of that one line;
/// `pinned_versions` is the set of versions any channel points at. A version is
/// retained (never pruned) if ANY of these hold:
///   * it is channel-pinned;
///   * its newest row is younger than the grace window (`min_age_secs`);
///   * it is among the newest `keep_last_n` versions (when set);
///   * it is younger than `max_age_secs` (when set).
///
/// Everything else is pruned. When the rule sets neither `keep_last_n` nor
/// `max_age_secs`, nothing is pruned. Recency is by newest `created_at_unix`
/// across a version's variant rows.
pub fn plan_version_retention(
    assets: &[StoredAsset],
    pinned_versions: &HashSet<String>,
    now: i64,
    policy: &RetentionPolicy,
) -> RetentionPlan {
    if policy.is_noop() || assets.is_empty() {
        return RetentionPlan::default();
    }

    // Group variant rows by logical version and record the version's recency
    // (newest created_at across its variants).
    let mut newest_created: HashMap<&str, i64> = HashMap::new();
    for asset in assets {
        let entry = newest_created
            .entry(asset.version.as_str())
            .or_insert(i64::MIN);
        *entry = (*entry).max(asset.created_at_unix);
    }

    // Distinct versions, newest first (created_at desc, then version string
    // desc as a stable tiebreak so equal timestamps are deterministic).
    let mut versions: Vec<(&str, i64)> = newest_created
        .iter()
        .map(|(version, created)| (*version, *created))
        .collect();
    versions.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(a.0)));

    let keep_last_n = policy.keep_last_n.map(|n| n as usize);
    let mut prune_versions: HashSet<&str> = HashSet::new();
    for (index, (version, created)) in versions.iter().enumerate() {
        // Grace window: too new to touch, whatever the rule says.
        let age = now.saturating_sub(*created);
        if age < policy.min_age_secs {
            continue;
        }
        // Channel-pinned versions are never pruned.
        if pinned_versions.contains(*version) {
            continue;
        }
        // Retained by recency: within the newest N.
        let within_keep_window = keep_last_n.is_some_and(|n| index < n);
        if within_keep_window {
            continue;
        }
        // Retained by age: younger than the max-age cutoff.
        let within_max_age = policy.max_age_secs.is_some_and(|max| age <= max);
        if within_max_age {
            continue;
        }
        // A prune candidate only when a dimension actually selected it:
        // beyond the keep window, OR older than max-age. (When keep_last_n is
        // None the recency window is absent, so max-age alone decides; when
        // max_age is None, only the keep window decides.)
        let beyond_keep_window = keep_last_n.is_some_and(|n| index >= n);
        let older_than_max_age = policy.max_age_secs.is_some_and(|max| age > max);
        if beyond_keep_window || older_than_max_age {
            prune_versions.insert(*version);
        }
    }

    let mut plan = RetentionPlan::default();
    for asset in assets {
        if prune_versions.contains(asset.version.as_str()) {
            plan.freed_bytes = plan.freed_bytes.saturating_add(asset.size_bytes);
            plan.targets.push(RetentionPruneTarget {
                id: asset.id.clone(),
                version: asset.version.clone(),
                variant: asset.variant.clone(),
                storage_uri: asset.storage_uri.clone(),
                size_bytes: asset.size_bytes,
            });
        }
    }
    plan
}

/// One flat operational-log row considered for retention (issue #284). Unlike
/// assets, `request_logs` / `audit_events` rows have no version dimension, so
/// each row is its own retention unit: a stable `id` plus its creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRetentionCandidate {
    /// The row's primary key (`request_logs.request_id`, `audit_events.id`).
    pub id: String,
    /// Row creation time in unix seconds (`started_at_unix` / `occurred_at_unix`).
    pub created_at_unix: i64,
}

/// Decide which flat operational-log rows to prune for ONE tenant under a
/// resolved [`RetentionPolicy`] (issue #284). Adopts the same fail-safe rules
/// as [`plan_version_retention`], minus channel pins (flat rows have none):
///
///   * a row younger than `min_age_secs` is NEVER pruned -- this is the
///     compliance legal floor / grace window (e.g. audit_events keep a longer
///     floor than request_logs);
///   * a row among the newest `keep_last_n` (when set) is retained;
///   * a row younger than `max_age_secs` (when set) is retained;
///   * everything a dimension actually selected (beyond the keep window, or
///     older than max-age) is pruned.
///
/// A no-op policy (neither dimension set) prunes nothing. Recency is by
/// `created_at_unix`, with the `id` as a deterministic tiebreak so two rows
/// sharing a timestamp order stably. Returns the ids to delete.
pub fn plan_log_retention(
    candidates: &[LogRetentionCandidate],
    now: i64,
    policy: &RetentionPolicy,
) -> Vec<String> {
    if policy.is_noop() || candidates.is_empty() {
        return Vec::new();
    }
    // Newest first (created desc, id desc as a stable deterministic tiebreak).
    let mut ordered: Vec<&LogRetentionCandidate> = candidates.iter().collect();
    ordered.sort_by(|a, b| {
        b.created_at_unix
            .cmp(&a.created_at_unix)
            .then_with(|| b.id.cmp(&a.id))
    });

    let keep_last_n = policy.keep_last_n.map(|n| n as usize);
    let mut prune: Vec<String> = Vec::new();
    for (index, candidate) in ordered.iter().enumerate() {
        // Grace / legal floor: too new to touch, whatever the rule says.
        let age = now.saturating_sub(candidate.created_at_unix);
        if age < policy.min_age_secs {
            continue;
        }
        // Retained by recency: within the newest N.
        if keep_last_n.is_some_and(|n| index < n) {
            continue;
        }
        // Retained by age: younger than the max-age cutoff.
        if policy.max_age_secs.is_some_and(|max| age <= max) {
            continue;
        }
        // A prune candidate only when a dimension actually selected it.
        let beyond_keep_window = keep_last_n.is_some_and(|n| index >= n);
        let older_than_max_age = policy.max_age_secs.is_some_and(|max| age > max);
        if beyond_keep_window || older_than_max_age {
            prune.push(candidate.id.clone());
        }
    }
    prune
}

/// The versions any channel points at, for one asset line's channel rows.
/// A pinned version is never pruned by [`plan_version_retention`].
pub fn pinned_versions(channels: &[StoredAssetChannel]) -> HashSet<String> {
    channels
        .iter()
        .map(|channel| channel.version.clone())
        .collect()
}

/// A bucket object observed during a GC reconcile pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketObject {
    pub key: String,
    /// Object last-modified time (unix seconds). `<= 0` means "unknown", which
    /// GC treats as too-new-to-delete (fail-safe KEEP).
    pub last_modified_unix: i64,
}

/// Plan the unreferenced-blob GC for a set of bucket objects.
///
/// `referenced_keys` is every `storage_uri` currently recorded on a
/// `stored_assets` row (across all tenants -- a bucket key namespace is
/// tenant-prefixed but the bucket is shared). An object is an orphan to delete
/// only when ALL hold:
///   * no registry row references its key (a failed presigned commit from
///     slice #259, or a row already deleted);
///   * its age is known (`last_modified_unix > 0`);
///   * it is older than `grace_secs` (so an in-flight upload whose row is about
///     to be written is never reaped).
///
/// Any object failing any check is KEPT. The returned keys are sorted for
/// deterministic dry-run output and stable multi-instance behavior.
pub fn plan_blob_gc(
    bucket_objects: &[BucketObject],
    referenced_keys: &HashSet<String>,
    now: i64,
    grace_secs: i64,
) -> Vec<String> {
    let mut orphans: Vec<String> = bucket_objects
        .iter()
        .filter(|object| !referenced_keys.contains(&object.key))
        .filter(|object| object.last_modified_unix > 0)
        .filter(|object| now.saturating_sub(object.last_modified_unix) >= grace_secs.max(0))
        .map(|object| object.key.clone())
        .collect();
    orphans.sort();
    orphans.dedup();
    orphans
}

#[cfg(test)]
#[path = "asset_lifecycle_test.rs"]
mod asset_lifecycle_test;
