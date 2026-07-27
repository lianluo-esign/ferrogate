// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Asset lifecycle sweeper (issue #263). The control-plane side of
// the #263 engine: it drives the pure, exhaustively-tested planners in
// `ferrogate-storage::asset_lifecycle` against the real registry + object
// bucket. One reconcile pass (1) prunes stale asset versions per the resolved
// retention policy -- never a channel-pinned or still-in-grace version -- and
// (2) garbage-collects bucket blobs no `stored_assets` row references, after a
// grace window. `enabled = false` (default) is a no-op; `dry_run = true`
// (default when enabled) only reports what WOULD change. Modeled on the billing
// outbox / scheduler sweepers: always-spawned loop, re-reads `state.current()`,
// safe to run on every gateway instance (deletes are idempotent -- deleting an
// already-deleted row/blob is a no-op, and a bucket DELETE treats 404 as
// success, so two instances racing the same orphan never double-fault).

use std::collections::{BTreeMap, HashSet};

use ferrogate_storage::{
    pinned_versions, plan_blob_gc, plan_log_retention, plan_version_retention, retention_policy_id,
    LogRetentionCandidate, RetentionPolicy, StoredAsset, StoredRetentionPolicy,
    RETENTION_RESOURCE_ASSET, RETENTION_RESOURCE_AUDIT_EVENT, RETENTION_RESOURCE_REQUEST_LOG,
    RETENTION_SCOPE_DEFAULT, RETENTION_SCOPE_RESPONSE_BODY,
};

use super::*;

/// One asset lifecycle reconcile pass's outcome, returned for tests + folded
/// into Prometheus counters and an audit event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AssetLifecycleSweepReport {
    pub(crate) dry_run: bool,
    /// Distinct asset versions examined by the retention pass.
    pub(crate) retention_versions_scanned: u64,
    /// Version rows actually deleted (0 in `dry_run`).
    pub(crate) retention_pruned: u64,
    /// Version rows that WOULD be pruned (populated in `dry_run`).
    pub(crate) retention_would_prune: u64,
    /// Bytes returned to tenant quotas by the deleted rows.
    pub(crate) retention_freed_bytes: u64,
    /// Bucket objects scanned by the GC pass.
    pub(crate) gc_objects_scanned: u64,
    /// Unreferenced orphan blobs actually deleted (0 in `dry_run`).
    pub(crate) gc_deleted: u64,
    /// Orphan blobs that WOULD be deleted (populated in `dry_run`).
    pub(crate) gc_would_delete: u64,
    /// #284: request_logs rows examined by the compliance retention pass.
    pub(crate) request_logs_scanned: u64,
    /// #284: request_logs rows actually pruned (0 in `dry_run`).
    pub(crate) request_logs_pruned: u64,
    /// #284: request_logs rows that WOULD be pruned (populated in `dry_run`).
    pub(crate) request_logs_would_prune: u64,
    /// #284: audit_events rows examined by the compliance retention pass.
    pub(crate) audit_events_scanned: u64,
    /// #284: audit_events rows actually pruned (0 in `dry_run`).
    pub(crate) audit_events_pruned: u64,
    /// #284: audit_events rows that WOULD be pruned (populated in `dry_run`).
    pub(crate) audit_events_would_prune: u64,
    /// Delete operations (row or blob) that failed.
    pub(crate) failed: u64,
}

impl AssetLifecycleSweepReport {
    fn scanned_total(&self) -> u64 {
        self.retention_versions_scanned
            .saturating_add(self.gc_objects_scanned)
            .saturating_add(self.request_logs_scanned)
            .saturating_add(self.audit_events_scanned)
    }

    fn pruned_total(&self) -> u64 {
        self.retention_pruned
            .saturating_add(self.gc_deleted)
            .saturating_add(self.request_logs_pruned)
            .saturating_add(self.audit_events_pruned)
    }
}

impl AppState {
    /// One asset lifecycle reconcile pass. Re-reads `self.config` so a hot
    /// config reload (enable, flip `dry_run`, tune windows) applies on the next
    /// tick; no-ops immediately when the sweeper is disabled, exactly like the
    /// billing outbox and scheduler sweepers.
    pub(crate) async fn sweep_asset_lifecycle_once(&self) -> AssetLifecycleSweepReport {
        let config = self.config.asset_lifecycle.clone();
        if !config.enabled {
            return AssetLifecycleSweepReport::default();
        }
        let mut report = AssetLifecycleSweepReport {
            dry_run: config.dry_run,
            ..AssetLifecycleSweepReport::default()
        };

        self.apply_asset_retention(&config, &mut report).await;
        if config.gc_enabled {
            self.run_asset_blob_gc(&config, &mut report).await;
        }
        // #284: adopt the same engine for compliance-data TTL/purge.
        self.apply_compliance_retention(&config, &mut report).await;

        self.record_asset_lifecycle_metrics(
            report.scanned_total(),
            report.pruned_total(),
            report.failed,
        );
        tracing::info!(
            dry_run = report.dry_run,
            retention_scanned = report.retention_versions_scanned,
            retention_pruned = report.retention_pruned,
            retention_would_prune = report.retention_would_prune,
            retention_freed_bytes = report.retention_freed_bytes,
            gc_scanned = report.gc_objects_scanned,
            gc_deleted = report.gc_deleted,
            gc_would_delete = report.gc_would_delete,
            request_logs_scanned = report.request_logs_scanned,
            request_logs_pruned = report.request_logs_pruned,
            request_logs_would_prune = report.request_logs_would_prune,
            audit_events_scanned = report.audit_events_scanned,
            audit_events_pruned = report.audit_events_pruned,
            audit_events_would_prune = report.audit_events_would_prune,
            failed = report.failed,
            "asset lifecycle sweep complete"
        );
        report
    }

    /// Retention pass: group every asset row by `{tenant, asset_type, name}`,
    /// resolve its retention policy, plan the prune, and (unless `dry_run`)
    /// delete the pruned versions' rows + bucket blobs.
    async fn apply_asset_retention(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
    ) {
        let assets = match self.repositories.list_all_assets().await {
            Ok(assets) => assets,
            Err(error) => {
                tracing::warn!(error = %error, "asset lifecycle: failed to list assets");
                report.failed = report.failed.saturating_add(1);
                return;
            }
        };
        if assets.is_empty() {
            return;
        }
        // Fail-safe: if channels can't be read we CANNOT know which versions are
        // pinned, so skip pruning entirely this pass rather than risk deleting a
        // pinned version. (An empty channel table is legitimate and returns
        // Ok(vec![]) -- only a genuine read error bails.)
        let channels = match self.repositories.list_all_asset_channels().await {
            Ok(channels) => channels,
            Err(error) => {
                tracing::warn!(error = %error, "asset lifecycle: failed to list channels; skipping retention to stay fail-safe");
                report.failed = report.failed.saturating_add(1);
                return;
            }
        };

        // Group rows and channels by (tenant, asset_type, name).
        let mut groups: BTreeMap<(String, String, String), Vec<StoredAsset>> = BTreeMap::new();
        for asset in assets {
            groups
                .entry((
                    asset.tenant_id.clone(),
                    asset.asset_type.clone(),
                    asset.name.clone(),
                ))
                .or_default()
                .push(asset);
        }
        let mut group_channels: BTreeMap<(String, String, String), Vec<_>> = BTreeMap::new();
        for channel in channels {
            group_channels
                .entry((
                    channel.tenant_id.clone(),
                    channel.asset_type.clone(),
                    channel.name.clone(),
                ))
                .or_default()
                .push(channel);
        }

        let now = now_unix_seconds().unwrap_or(0) as i64;

        // Resolve policies once per tenant (a small list per tenant).
        let mut tenant_policies: BTreeMap<String, Vec<ferrogate_storage::StoredRetentionPolicy>> =
            BTreeMap::new();

        for ((tenant_id, asset_type, name), rows) in groups {
            let versions: HashSet<&str> = rows.iter().map(|row| row.version.as_str()).collect();
            report.retention_versions_scanned = report
                .retention_versions_scanned
                .saturating_add(versions.len() as u64);

            let policies = match tenant_policies.get(&tenant_id) {
                Some(policies) => policies,
                None => {
                    let loaded = self
                        .repositories
                        .list_retention_policies(&tenant_id, RETENTION_RESOURCE_ASSET)
                        .await
                        .unwrap_or_default();
                    tenant_policies.entry(tenant_id.clone()).or_insert(loaded)
                }
            };
            let policy = resolve_retention_policy(policies, &asset_type, &name, config);
            if policy.is_noop() {
                continue;
            }

            let pins = group_channels
                .get(&(tenant_id.clone(), asset_type.clone(), name.clone()))
                .map(|channels| pinned_versions(channels))
                .unwrap_or_default();
            let plan = plan_version_retention(&rows, &pins, now, &policy);
            if plan.targets.is_empty() {
                continue;
            }

            if report.dry_run {
                report.retention_would_prune = report
                    .retention_would_prune
                    .saturating_add(plan.targets.len() as u64);
                report.retention_freed_bytes = report
                    .retention_freed_bytes
                    .saturating_add(plan.freed_bytes);
                continue;
            }

            let mut pruned_here = 0_u64;
            let mut freed_here = 0_u64;
            for target in &plan.targets {
                if let Some(storage_uri) = target.storage_uri.as_deref() {
                    if let Some(bucket) = self.asset_bucket_client() {
                        if let Err(error) = bucket.delete_object(storage_uri).await {
                            // Best-effort blob delete: an orphaned blob is a
                            // lesser problem (the GC pass reaps it later) than an
                            // undeletable row, so log and still delete the row.
                            tracing::warn!(
                                asset_id = %target.id,
                                error = %error,
                                "asset lifecycle: failed to delete blob during retention prune"
                            );
                            report.failed = report.failed.saturating_add(1);
                        }
                    }
                }
                match self.repositories.delete_asset(&target.id).await {
                    Ok(_) => {
                        pruned_here = pruned_here.saturating_add(1);
                        freed_here = freed_here.saturating_add(target.size_bytes);
                    }
                    Err(error) => {
                        tracing::warn!(
                            asset_id = %target.id,
                            error = %error,
                            "asset lifecycle: failed to delete asset row during retention prune"
                        );
                        report.failed = report.failed.saturating_add(1);
                    }
                }
            }
            report.retention_pruned = report.retention_pruned.saturating_add(pruned_here);
            report.retention_freed_bytes = report.retention_freed_bytes.saturating_add(freed_here);
            if pruned_here > 0 {
                self.record_asset_lifecycle_audit(
                    &tenant_id,
                    "asset.retention.prune",
                    format!("{tenant_id}:{asset_type}:{name}"),
                    format!(
                        "pruned {pruned_here} version row(s) of {asset_type}/{name}, freed {freed_here} bytes"
                    ),
                );
            }
        }
    }

    /// GC pass: reconcile the bucket's objects against the registry's
    /// `storage_uri`s and delete unreferenced, aged-out orphans (bounded per
    /// tick). Requires a configured bucket -- inline-only deployments have no
    /// blobs to collect.
    async fn run_asset_blob_gc(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
    ) {
        let Some(bucket) = self.asset_bucket_client() else {
            return;
        };
        let objects = match bucket.list_objects().await {
            Ok(objects) => objects,
            Err(error) => {
                tracing::warn!(error = %error, "asset lifecycle: failed to list bucket objects for GC");
                report.failed = report.failed.saturating_add(1);
                return;
            }
        };
        report.gc_objects_scanned = report
            .gc_objects_scanned
            .saturating_add(objects.len() as u64);

        // Referenced keys = every storage_uri currently on a stored_assets row.
        let referenced: HashSet<String> = match self.repositories.list_all_assets().await {
            Ok(assets) => assets
                .into_iter()
                .filter_map(|asset| asset.storage_uri)
                .collect(),
            Err(error) => {
                // Fail-safe: if we can't establish the referenced set, delete
                // NOTHING (every object would look like an orphan).
                tracing::warn!(error = %error, "asset lifecycle: failed to list assets for GC referenced-set; skipping GC");
                report.failed = report.failed.saturating_add(1);
                return;
            }
        };

        let now = now_unix_seconds().unwrap_or(0) as i64;
        let mut orphans = plan_blob_gc(&objects, &referenced, now, config.gc_grace_secs);
        report.gc_would_delete = report.gc_would_delete.saturating_add(orphans.len() as u64);

        if report.dry_run {
            for orphan in &orphans {
                tracing::info!(blob = %orphan, "asset lifecycle: GC dry-run would delete orphan blob");
            }
            return;
        }

        orphans.truncate(config.max_gc_deletes_per_tick);
        let mut deleted_here = 0_u64;
        for orphan in &orphans {
            match bucket.delete_object(orphan).await {
                Ok(()) => deleted_here = deleted_here.saturating_add(1),
                Err(error) => {
                    tracing::warn!(blob = %orphan, error = %error, "asset lifecycle: failed to delete orphan blob");
                    report.failed = report.failed.saturating_add(1);
                }
            }
        }
        report.gc_deleted = report.gc_deleted.saturating_add(deleted_here);
        if deleted_here > 0 {
            self.record_asset_lifecycle_audit(
                "",
                "asset.gc.delete",
                "asset-bucket".to_string(),
                format!("garbage-collected {deleted_here} unreferenced blob(s)"),
            );
        }
    }

    /// #284: compliance-data retention. Adopts the #263 retention engine for
    /// the high-write operational tables (`request_logs`, `audit_events`) --
    /// the SAME `retention_policies` rows + sweeper, just a different
    /// `resource_type`. Each table resolves a per-tenant policy, plans the
    /// age/count prune with the same fail-safe planner (never inside the legal
    /// floor / grace window), and batch-deletes expired rows, auditing the
    /// purge itself. `dry_run` reports what WOULD be pruned without deleting.
    async fn apply_compliance_retention(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
    ) {
        self.apply_request_log_retention(config, report).await;
        self.apply_audit_event_retention(config, report).await;
    }

    /// Retention pass over `request_logs`: group rows by tenant, resolve the
    /// tenant's `request_logs` policy (a `retention_policies` row, else the
    /// config default), plan the prune, and (unless `dry_run`) batch-delete.
    /// Response-body captures (`response_recorded`) get the shortest TTL: a
    /// row is pruned as soon as EITHER the general rule OR the response-body
    /// rule selects it.
    async fn apply_request_log_retention(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
    ) {
        let logs = self.repositories.request_logs().await;
        if logs.is_empty() {
            return;
        }
        report.request_logs_scanned = report
            .request_logs_scanned
            .saturating_add(logs.len() as u64);
        let now = now_unix_seconds().unwrap_or(0) as i64;
        let min_age = config.retention_min_age_secs.max(0);

        // Group by tenant (organization); response-recorded rows also tracked
        // separately for the shorter response-body TTL.
        let mut general: BTreeMap<String, Vec<LogRetentionCandidate>> = BTreeMap::new();
        let mut response: BTreeMap<String, Vec<LogRetentionCandidate>> = BTreeMap::new();
        for log in &logs {
            let tenant = log.tenant.organization_id.clone().unwrap_or_default();
            let created = log
                .started_at_unix
                .or(log.completed_at_unix)
                .unwrap_or_default() as i64;
            let candidate = LogRetentionCandidate {
                id: log.request_id.clone(),
                created_at_unix: created,
            };
            if log.response_recorded {
                response
                    .entry(tenant.clone())
                    .or_default()
                    .push(candidate.clone());
            }
            general.entry(tenant).or_default().push(candidate);
        }

        let mut seen: HashSet<String> = HashSet::new();
        let mut to_delete: Vec<String> = Vec::new();
        for (tenant, candidates) in &general {
            let policies = self
                .repositories
                .list_retention_policies(tenant, RETENTION_RESOURCE_REQUEST_LOG)
                .await
                .unwrap_or_default();
            let general_policy = resolve_log_policy(
                &policies,
                RETENTION_SCOPE_DEFAULT,
                config.default_request_log_max_age_secs,
                min_age,
            );
            for id in plan_log_retention(candidates, now, &general_policy) {
                if seen.insert(id.clone()) {
                    to_delete.push(id);
                }
            }
            // Shorter response-body TTL: an EXTRA rule over response-recorded
            // rows only (the general rule already covered them above).
            let response_policy = resolve_log_policy(
                &policies,
                RETENTION_SCOPE_RESPONSE_BODY,
                config.default_response_body_max_age_secs,
                min_age,
            );
            if !response_policy.is_noop() {
                if let Some(resp_candidates) = response.get(tenant) {
                    for id in plan_log_retention(resp_candidates, now, &response_policy) {
                        if seen.insert(id.clone()) {
                            to_delete.push(id);
                        }
                    }
                }
            }
        }

        self.commit_request_log_prune(config, report, to_delete)
            .await;
    }

    /// Retention pass over `audit_events`: same shape as request logs but with
    /// audit_events' (typically longer) legal floor and no response-body scope.
    async fn apply_audit_event_retention(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
    ) {
        let events = self.repositories.audit_events().await;
        if events.is_empty() {
            return;
        }
        report.audit_events_scanned = report
            .audit_events_scanned
            .saturating_add(events.len() as u64);
        let now = now_unix_seconds().unwrap_or(0) as i64;
        let min_age = config.retention_min_age_secs.max(0);

        let mut groups: BTreeMap<String, Vec<LogRetentionCandidate>> = BTreeMap::new();
        for event in &events {
            let tenant = event.tenant.organization_id.clone().unwrap_or_default();
            groups
                .entry(tenant)
                .or_default()
                .push(LogRetentionCandidate {
                    id: event.id.clone(),
                    created_at_unix: event.occurred_at_unix.unwrap_or_default() as i64,
                });
        }

        let mut to_delete: Vec<String> = Vec::new();
        for (tenant, candidates) in &groups {
            let policies = self
                .repositories
                .list_retention_policies(tenant, RETENTION_RESOURCE_AUDIT_EVENT)
                .await
                .unwrap_or_default();
            let policy = resolve_log_policy(
                &policies,
                RETENTION_SCOPE_DEFAULT,
                config.default_audit_event_max_age_secs,
                min_age,
            );
            to_delete.extend(plan_log_retention(candidates, now, &policy));
        }

        self.commit_audit_event_prune(config, report, to_delete)
            .await;
    }

    /// Apply a planned `request_logs` prune: `dry_run` only counts; otherwise
    /// batch-delete (capped per tick) and audit the purge as its own evidence.
    async fn commit_request_log_prune(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
        mut ids: Vec<String>,
    ) {
        if ids.is_empty() {
            return;
        }
        report.request_logs_would_prune = report
            .request_logs_would_prune
            .saturating_add(ids.len() as u64);
        if report.dry_run {
            tracing::info!(
                would_prune = ids.len(),
                "compliance retention: request_logs dry-run"
            );
            return;
        }
        ids.truncate(config.max_log_deletes_per_tick);
        match self.repositories.delete_request_logs(&ids).await {
            Ok(deleted) => {
                report.request_logs_pruned = report.request_logs_pruned.saturating_add(deleted);
                if deleted > 0 {
                    self.record_asset_lifecycle_audit(
                        "",
                        "request_logs.retention.prune",
                        "request_logs".to_string(),
                        format!("compliance retention purged {deleted} request_logs row(s)"),
                    );
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "compliance retention: failed to prune request_logs");
                report.failed = report.failed.saturating_add(1);
            }
        }
    }

    /// Apply a planned `audit_events` prune (mirrors the request_logs commit).
    async fn commit_audit_event_prune(
        &self,
        config: &ferrogate_config::AssetLifecycleConfig,
        report: &mut AssetLifecycleSweepReport,
        mut ids: Vec<String>,
    ) {
        if ids.is_empty() {
            return;
        }
        report.audit_events_would_prune = report
            .audit_events_would_prune
            .saturating_add(ids.len() as u64);
        if report.dry_run {
            tracing::info!(
                would_prune = ids.len(),
                "compliance retention: audit_events dry-run"
            );
            return;
        }
        ids.truncate(config.max_log_deletes_per_tick);
        match self.repositories.delete_audit_events(&ids).await {
            Ok(deleted) => {
                report.audit_events_pruned = report.audit_events_pruned.saturating_add(deleted);
                if deleted > 0 {
                    self.record_asset_lifecycle_audit(
                        "",
                        "audit_events.retention.prune",
                        "audit_events".to_string(),
                        format!("compliance retention purged {deleted} audit_events row(s)"),
                    );
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "compliance retention: failed to prune audit_events");
                report.failed = report.failed.saturating_add(1);
            }
        }
    }

    /// Tenant/project offboarding cascade (issue #263): delete every asset row +
    /// bucket blob + channel pointer owned by `tenant_id`, leaving zero storage
    /// behind, and emit an audit event recording exactly what was purged. Best
    /// effort per object -- a single blob-delete failure never aborts the
    /// cascade (the GC pass reaps any stragglers). Returns the number of asset
    /// rows purged.
    ///
    /// This is the cascade primitive; FerroGate has no hard tenant/project
    /// deletion endpoint today (tenants/projects use a soft `status`), so this
    /// is invoked by the lifecycle test suite and is ready for a future
    /// offboarding trigger to call. Retained deliberately until that trigger
    /// lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn purge_tenant_assets(&self, tenant_id: &str, reason: &str) -> u64 {
        let assets = self
            .repositories
            .list_assets(tenant_id, None)
            .await
            .unwrap_or_default();
        let mut purged = 0_u64;
        let mut freed_bytes = 0_u64;
        for asset in &assets {
            if let Some(storage_uri) = asset.storage_uri.as_deref() {
                if let Some(bucket) = self.asset_bucket_client() {
                    if let Err(error) = bucket.delete_object(storage_uri).await {
                        tracing::warn!(
                            asset_id = %asset.id,
                            error = %error,
                            "asset lifecycle: failed to delete blob during tenant purge"
                        );
                    }
                }
            }
            if self
                .repositories
                .delete_asset(&asset.id)
                .await
                .unwrap_or(false)
            {
                purged = purged.saturating_add(1);
                freed_bytes = freed_bytes.saturating_add(asset.size_bytes);
            }
        }

        // Drop the tenant's channel pointers too, so nothing dangles.
        let channels = self
            .repositories
            .list_all_asset_channels()
            .await
            .unwrap_or_default();
        for channel in channels.into_iter().filter(|c| c.tenant_id == tenant_id) {
            let _ = self.repositories.delete_asset_channel(&channel.id).await;
        }

        self.record_asset_lifecycle_audit(
            tenant_id,
            "asset.tenant.purge",
            format!("tenant:{tenant_id}"),
            format!("purged {purged} asset row(s), freed {freed_bytes} bytes ({reason})"),
        );
        purged
    }

    /// Fold one lifecycle sweep's counts into the cumulative Prometheus metrics
    /// (`ferrogate_asset_lifecycle_{scanned,pruned,failed}_total`).
    fn record_asset_lifecycle_metrics(&self, scanned: u64, pruned: u64, failed: u64) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_asset_lifecycle_sweep(scanned, pruned, failed);
        }
    }

    /// Emit the compliance-evidence audit event for a purge/prune/GC action
    /// (the deletion itself is auditable, per #263). `tenant_id` may be empty
    /// for a bucket-wide GC action not attributable to one tenant.
    fn record_asset_lifecycle_audit(
        &self,
        tenant_id: &str,
        action: &str,
        target: String,
        message: String,
    ) {
        let tenant = ferrogate_core::TenantContext {
            organization_id: (!tenant_id.is_empty()).then(|| tenant_id.to_string()),
            ..ferrogate_core::TenantContext::default()
        };
        self.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: format!("asset-lifecycle-{}", now_unix_seconds().unwrap_or(0)),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant,
            action: action.to_string(),
            target,
            outcome: "committed".to_string(),
            message,
        });
    }
}

/// Resolve the retention rule for one `{asset_type}/{name}`: the most specific
/// `retention_policies` row wins (exact `{asset_type}/{name}` scope), then the
/// tenant default (`*` scope), then the deployment config defaults. Config
/// defaults never override an explicit tenant policy.
fn resolve_retention_policy(
    policies: &[ferrogate_storage::StoredRetentionPolicy],
    asset_type: &str,
    name: &str,
    config: &ferrogate_config::AssetLifecycleConfig,
) -> RetentionPolicy {
    let exact_scope = format!("{asset_type}/{name}");
    if let Some(policy) = policies.iter().find(|policy| policy.scope == exact_scope) {
        return policy.as_retention_policy();
    }
    if let Some(policy) = policies
        .iter()
        .find(|policy| policy.scope == RETENTION_SCOPE_DEFAULT)
    {
        return policy.as_retention_policy();
    }
    RetentionPolicy {
        keep_last_n: config.default_keep_last_n,
        max_age_secs: config.default_max_age_secs,
        min_age_secs: config.retention_min_age_secs.max(0),
    }
}

/// #284: resolve the retention rule for one operational-log table + scope. An
/// exact `retention_policies` row for `scope` wins; otherwise the config
/// default max-age applies (age-based, no count dimension). `min_age_secs` is
/// the compliance legal floor / grace window -- a row younger than it is never
/// pruned. A `None` config default with no row is a no-op (nothing pruned).
fn resolve_log_policy(
    policies: &[StoredRetentionPolicy],
    scope: &str,
    config_default_max_age_secs: Option<i64>,
    min_age_secs: i64,
) -> RetentionPolicy {
    if let Some(policy) = policies.iter().find(|policy| policy.scope == scope) {
        let mut resolved = policy.as_retention_policy();
        // A tenant policy may leave the floor at 0; enforce the config floor as
        // a lower bound so a per-tenant rule can never breach the grace window.
        resolved.min_age_secs = resolved.min_age_secs.max(min_age_secs.max(0));
        return resolved;
    }
    RetentionPolicy {
        keep_last_n: None,
        max_age_secs: config_default_max_age_secs,
        min_age_secs: min_age_secs.max(0),
    }
}

/// #284: convenience constructor for a `request_logs` / `audit_events`
/// retention policy row with the deterministic id, for admin tooling / tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn log_retention_policy(
    tenant_id: &str,
    resource_type: &str,
    scope: &str,
    keep_last_n: Option<u64>,
    max_age_secs: Option<i64>,
    min_age_secs: i64,
    now: i64,
) -> ferrogate_storage::StoredRetentionPolicy {
    ferrogate_storage::StoredRetentionPolicy {
        id: retention_policy_id(tenant_id, resource_type, scope),
        tenant_id: tenant_id.to_string(),
        resource_type: resource_type.to_string(),
        scope: scope.to_string(),
        keep_last_n,
        max_age_secs,
        min_age_secs,
        created_at_unix: now,
        updated_at_unix: now,
    }
}

/// A convenience constructor for a stored asset retention policy row, so admin
/// tooling / tests build a well-formed row with the deterministic id (#263).
/// Used by the lifecycle test suite; retained as the row builder for a future
/// admin retention-policy management surface.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn asset_retention_policy(
    tenant_id: &str,
    scope: &str,
    keep_last_n: Option<u64>,
    max_age_secs: Option<i64>,
    min_age_secs: i64,
    now: i64,
) -> ferrogate_storage::StoredRetentionPolicy {
    ferrogate_storage::StoredRetentionPolicy {
        id: retention_policy_id(tenant_id, RETENTION_RESOURCE_ASSET, scope),
        tenant_id: tenant_id.to_string(),
        resource_type: RETENTION_RESOURCE_ASSET.to_string(),
        scope: scope.to_string(),
        keep_last_n,
        max_age_secs,
        min_age_secs,
        created_at_unix: now,
        updated_at_unix: now,
    }
}

#[cfg(test)]
#[path = "state_asset_lifecycle_test.rs"]
mod state_asset_lifecycle_test;
