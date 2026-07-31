// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Cloudflare static-site publish reconciler (issue #411). Drives
// the configured `[static_site_publish]` target toward the desired edge state
// DERIVED each pass from the site's own authoritative state, and records what
// the edge is believed to hold in a durable, queryable row.
//
// Why declarative rather than a hook on the publish handler: the edge must
// track FerroGate through operations that have no publish request at all --
// a serving-channel rollback (#345/#397), a version yank, a version delete, a
// tenant purge, and a site flipped from public to private. An event-driven
// mirror can only ever cover the one operation it is wired to, which is how
// the first cut left a withdrawn version anonymously readable on the edge with
// no code path able to retract it. Deriving desired state from the `serving`
// channel every tick covers all of them with no per-operation hook, makes a
// failed publish retry on its own, and takes an unbounded third-party round
// trip off the publish request path.

use serde::{Deserialize, Serialize};

use ferrogate_storage::{stored_asset_id, AssetVisibility, StoredAsset};

use super::asset_bucket::SitePublishFile;
use super::sites::{SITE_ASSET_TYPE, SITE_MIRROR_ASSET_TYPE, SITE_MIRROR_STATE_VERSION};
use super::FerroGateway;

/// What the edge should hold for the configured site, derived from FerroGate's
/// own state on every pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DesiredEdgeState {
    /// The site has an active, public bundle; the edge should serve exactly it.
    Published { bundle_version: String },
    /// The edge should serve nothing for this site. Carries the reason so the
    /// audit trail says WHY a site left the edge -- rolled back to nothing,
    /// deleted, purged, or turned private -- rather than only that it did.
    Retracted { reason: &'static str },
}

impl DesiredEdgeState {
    fn status(&self) -> &'static str {
        match self {
            Self::Published { .. } => "published",
            Self::Retracted { .. } => "retracted",
        }
    }

    fn bundle_version(&self) -> Option<&str> {
        match self {
            Self::Published { bundle_version } => Some(bundle_version),
            Self::Retracted { .. } => None,
        }
    }
}

/// The durable record of what the Cloudflare edge is believed to hold, stored
/// as a `static_site_mirror` asset row so an operator can read the mirror's
/// state through the existing `/v1/assets/{type}/{name}/{version}` pull path
/// instead of reconstructing it from audit lines.
///
/// This exists because a mirror that diverges from FerroGate must leave
/// evidence that OUTLIVES the request that caused it. The first cut reported a
/// failure only in the push response body and one audit line, and the bundle
/// version was immutable, so re-pushing to retry was refused with `409
/// site_version_immutable`: the divergence was both unqueryable and
/// unrecoverable. Here the row IS the queryable state and the next tick IS the
/// retry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SiteMirrorState {
    pub(crate) tenant_id: String,
    pub(crate) site: String,
    /// Worker script the state describes. A config change that re-points the
    /// mirror at a different script makes the recorded state inapplicable, so
    /// it is compared as part of convergence.
    #[serde(default)]
    pub(crate) script_name: String,
    /// Bundle version the edge is believed to serve. `None` == the edge holds
    /// nothing (retracted, or never published).
    #[serde(default)]
    pub(crate) published_bundle_version: Option<String>,
    /// `published`, `retracted`, or `failed`.
    #[serde(default)]
    pub(crate) status: String,
    /// Error from the last failed attempt, cleared on success.
    #[serde(default)]
    pub(crate) last_error: Option<String>,
    /// Consecutive failed attempts, for operator triage of a stuck mirror.
    #[serde(default)]
    pub(crate) consecutive_failures: u64,
    #[serde(default)]
    pub(crate) file_count: u64,
    #[serde(default)]
    pub(crate) updated_at_unix: i64,
}

impl SiteMirrorState {
    /// Whether the recorded state already satisfies `desired` on `script_name`.
    ///
    /// A `failed` status never converges, so a failure is retried on the next
    /// pass. This is deliberately the ONLY retry mechanism: it needs no queue,
    /// no backoff state and no operator action, and it cannot get stuck behind
    /// bundle immutability the way "push the version again" did.
    fn satisfies(&self, desired: &DesiredEdgeState, script_name: &str) -> bool {
        self.status != "failed"
            && self.script_name == script_name
            && self.status == desired.status()
            && self.published_bundle_version.as_deref() == desired.bundle_version()
    }
}

/// One reconcile pass's outcome, returned for tests and folded into the audit
/// trail and logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SitePublishSweepReport {
    /// No `[static_site_publish]` target is configured/enabled.
    pub(crate) disabled: bool,
    /// The edge already matched the desired state; nothing was called.
    pub(crate) already_converged: bool,
    /// Desired state could not be derived (storage error). Nothing was changed
    /// -- notably NOT retracted, since an unreadable site is not a withdrawn
    /// one.
    pub(crate) indeterminate: bool,
    pub(crate) desired: Option<DesiredEdgeState>,
    /// A publish was performed and Cloudflare accepted it.
    pub(crate) published: bool,
    /// A retraction was performed (or the script was already absent).
    pub(crate) retracted: bool,
    /// The attempt failed; the recorded state carries the error and the next
    /// pass retries.
    pub(crate) failed: Option<String>,
}

impl FerroGateway {
    /// One Cloudflare static-site mirror reconcile pass (issue #411).
    ///
    /// Re-reads `state.current()` so a hot config reload (enable, re-point,
    /// re-tune the budget) applies on the next tick, matching the asset
    /// lifecycle / billing outbox sweepers. Safe to run on every gateway
    /// instance: both operations are idempotent against the same desired state
    /// (Cloudflare dedups asset bytes it already holds; a retraction treats an
    /// already-absent script as success).
    pub(crate) async fn reconcile_static_site_publish_once(&self) -> SitePublishSweepReport {
        let Some(target) = self.state.current().static_site_publish_target() else {
            return SitePublishSweepReport {
                disabled: true,
                ..SitePublishSweepReport::default()
            };
        };
        // Tenant, site and script all come from the ONE target. Re-deriving the
        // pairing from config here would be a second reader that could drift
        // from the one the target was built with, and the whole safety of a
        // shared Worker script rests on that pairing being single-sourced.
        let tenant_id = target.tenant_id().to_string();
        let site = target.site().to_string();
        let script_name = target.script_name().to_string();

        let desired = match self.desired_edge_state(&tenant_id, &site).await {
            Ok(desired) => desired,
            Err(error) => {
                // Fail SAFE, not closed: a storage read that failed does not
                // prove the site is gone, and retracting on it would take a
                // healthy public site off the edge every time the registry
                // hiccups.
                tracing::warn!(
                    tenant = %tenant_id,
                    site = %site,
                    error = %error,
                    "static-site mirror: desired state indeterminate; leaving the edge unchanged"
                );
                return SitePublishSweepReport {
                    indeterminate: true,
                    ..SitePublishSweepReport::default()
                };
            }
        };

        let recorded = self.load_site_mirror_state(&tenant_id, &site).await;
        if recorded
            .as_ref()
            .is_some_and(|state| state.satisfies(&desired, &script_name))
        {
            return SitePublishSweepReport {
                already_converged: true,
                desired: Some(desired),
                ..SitePublishSweepReport::default()
            };
        }

        let mut report = SitePublishSweepReport {
            desired: Some(desired.clone()),
            ..SitePublishSweepReport::default()
        };
        let outcome = match &desired {
            DesiredEdgeState::Published { bundle_version } => {
                self.publish_to_edge(&target, &tenant_id, &site, bundle_version)
                    .await
                    .map(|file_count| {
                        report.published = true;
                        file_count
                    })
            }
            DesiredEdgeState::Retracted { .. } => target.retract_site().await.map(|()| {
                report.retracted = true;
                0u64
            }),
        };

        let now = now_unix_seconds();
        let prior_failures = recorded
            .as_ref()
            .map(|state| state.consecutive_failures)
            .unwrap_or(0);
        let next = match &outcome {
            Ok(file_count) => SiteMirrorState {
                tenant_id: tenant_id.clone(),
                site: site.clone(),
                script_name: script_name.clone(),
                published_bundle_version: desired.bundle_version().map(str::to_string),
                status: desired.status().to_string(),
                last_error: None,
                consecutive_failures: 0,
                file_count: *file_count,
                updated_at_unix: now,
            },
            Err(error) => {
                report.failed = Some(error.to_string());
                SiteMirrorState {
                    tenant_id: tenant_id.clone(),
                    site: site.clone(),
                    script_name: script_name.clone(),
                    // The attempt failed, so what the edge holds is whatever it
                    // held before -- never the version we were trying to reach.
                    published_bundle_version: recorded
                        .as_ref()
                        .and_then(|state| state.published_bundle_version.clone()),
                    status: "failed".to_string(),
                    last_error: Some(error.to_string()),
                    consecutive_failures: prior_failures.saturating_add(1),
                    file_count: recorded.as_ref().map(|state| state.file_count).unwrap_or(0),
                    updated_at_unix: now,
                }
            }
        };
        self.store_site_mirror_state(&next).await;
        self.record_site_mirror_audit(&desired, &next);
        report
    }

    /// Derives the desired edge state from the site's OWN authoritative state.
    ///
    /// Resolution goes through the same `serving` channel the gateway serve
    /// path reads (`resolve_active_site_bundle`), so what the edge is driven
    /// toward is exactly what FerroGate serves -- write path == read path
    /// (#188). Everything that withdraws a version withdraws it here too,
    /// because they all move or remove that channel target.
    ///
    /// A site that is not `public` resolves to `Retracted`. The edge serves
    /// anonymously; mirroring a private bundle there would make a site that is
    /// authenticated in FerroGate world-readable on Cloudflare at the same
    /// time, and `public = false` is the DEFAULT (the `x-site-public` header is
    /// absent on most pushes), so this is the common case, not the corner one.
    async fn desired_edge_state(
        &self,
        tenant_id: &str,
        site: &str,
    ) -> anyhow::Result<DesiredEdgeState> {
        let Some(resolved) = self.resolve_active_site_bundle(tenant_id, site).await? else {
            return Ok(DesiredEdgeState::Retracted {
                reason: "site has no active bundle (never published, deleted, or tenant purged)",
            });
        };
        if !resolved.manifest.public {
            return Ok(DesiredEdgeState::Retracted {
                reason: "site is not public; the Cloudflare edge serves anonymously",
            });
        }
        Ok(DesiredEdgeState::Published {
            bundle_version: resolved.manifest.bundle_version.clone(),
        })
    }

    /// Loads every file of the active bundle and publishes the WHOLE set as one
    /// Cloudflare asset version, returning the file count.
    ///
    /// Files are read through `resolve_servable_site_file` + `load_asset_content`
    /// -- the same pair the gateway serve path uses -- so the bytes pushed to
    /// the edge are the bytes the gateway would serve, withheld/quarantined rows
    /// (#366/#528) are refused here exactly as they are there, and the whole
    /// read is charged against the #529 gateway buffer budget instead of
    /// drawing on no admission budget at all.
    async fn publish_to_edge(
        &self,
        target: &super::asset_bucket::StaticSitePublishTarget,
        tenant_id: &str,
        site: &str,
        bundle_version: &str,
    ) -> anyhow::Result<u64> {
        let Some(resolved) = self.resolve_active_site_bundle(tenant_id, site).await? else {
            anyhow::bail!("site {tenant_id}/{site} disappeared while its mirror was being built");
        };
        if resolved.manifest.bundle_version != bundle_version {
            // The serving channel moved between deriving desired state and
            // reading the bytes. Abandon this pass rather than publish a mix;
            // the next pass derives the new desired state cleanly.
            anyhow::bail!(
                "site {tenant_id}/{site} moved from {bundle_version} to {} mid-publish; \
                 reconciling again next pass",
                resolved.manifest.bundle_version
            );
        }

        let request_id = format!("site-publish-reconcile-{}", now_unix_seconds());
        // Bytes plus their admission permits, held together: the permit must
        // outlive the bytes it charges for (#529), so both live in this scope
        // until the publish returns.
        let mut loaded = Vec::with_capacity(resolved.manifest.files.len());
        for entry in &resolved.manifest.files {
            let asset = self
                .resolve_servable_site_file(&resolved, tenant_id, site, &entry.path)
                .await
                .map_err(|refusal| {
                    anyhow::anyhow!(
                        "site {tenant_id}/{site} file {}: {}",
                        entry.path,
                        refusal.message
                    )
                })?;
            let buffered = self
                .load_asset_content(&asset, &request_id)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "site {tenant_id}/{site} file {}: {}",
                        entry.path,
                        error.message
                    )
                })?;
            let (bytes, permit) = buffered.into_parts();
            loaded.push((entry.path.clone(), entry.content_type.clone(), bytes, permit));
        }

        let files: Vec<SitePublishFile<'_>> = loaded
            .iter()
            .map(|(path, content_type, bytes, _permit)| SitePublishFile {
                path,
                content_type,
                body: bytes,
            })
            .collect();
        let published = target.publish_site(&files).await?;
        Ok(published.file_count as u64)
    }

    /// Reads the durable mirror-state row, or `None` when absent/corrupt. A
    /// corrupt row reads as absent so the reconciler re-derives and re-applies
    /// rather than trusting a state it cannot parse.
    pub(crate) async fn load_site_mirror_state(
        &self,
        tenant_id: &str,
        site: &str,
    ) -> Option<SiteMirrorState> {
        let id = stored_asset_id(
            tenant_id,
            SITE_MIRROR_ASSET_TYPE,
            site,
            SITE_MIRROR_STATE_VERSION,
        );
        let asset = self.state.current().get_asset(&id).await.ok()??;
        serde_json::from_slice::<SiteMirrorState>(&asset.content).ok()
    }

    /// Writes the durable mirror-state row. A write failure is logged and the
    /// pass still reports its true outcome; the next pass re-derives from the
    /// site's own state, so a lost state row costs one redundant publish, never
    /// a wrong edge.
    async fn store_site_mirror_state(&self, state: &SiteMirrorState) {
        let Ok(body) = serde_json::to_vec(state) else {
            return;
        };
        let id = stored_asset_id(
            &state.tenant_id,
            SITE_MIRROR_ASSET_TYPE,
            &state.site,
            SITE_MIRROR_STATE_VERSION,
        );
        let asset = StoredAsset {
            id,
            tenant_id: state.tenant_id.clone(),
            project_id: None,
            asset_type: SITE_MIRROR_ASSET_TYPE.to_string(),
            name: state.site.clone(),
            version: SITE_MIRROR_STATE_VERSION.to_string(),
            content_type: "application/json".to_string(),
            content_hash: ferrogate_storage::sha256_hex(&body),
            size_bytes: body.len() as u64,
            content: body,
            storage_uri: None,
            variant: String::new(),
            yanked: false,
            visibility: AssetVisibility::Visible,
            created_at_unix: state.updated_at_unix,
            updated_at_unix: state.updated_at_unix,
        };
        if let Err(error) = self.state.current().upsert_asset(asset).await {
            tracing::warn!(
                tenant = %state.tenant_id,
                site = %state.site,
                error = %error,
                "static-site mirror: failed to persist mirror state"
            );
        }
    }

    /// Records the pass in the admin audit trail. Every transition the edge
    /// makes -- published, retracted (with the reason it left), or failed --
    /// leaves an inspectable line, since the edge is a surface an operator
    /// cannot see from inside FerroGate.
    fn record_site_mirror_audit(&self, desired: &DesiredEdgeState, next: &SiteMirrorState) {
        let (outcome, message) = match (&next.status[..], desired) {
            ("failed", _) => (
                "failed",
                format!(
                    "Cloudflare mirror of {}/{} failed ({} consecutive): {}",
                    next.tenant_id,
                    next.site,
                    next.consecutive_failures,
                    next.last_error.as_deref().unwrap_or("unknown error")
                ),
            ),
            (_, DesiredEdgeState::Published { bundle_version }) => (
                "published",
                format!(
                    "mirrored {}/{} bundle {} ({} files) to Cloudflare Worker {}",
                    next.tenant_id, next.site, bundle_version, next.file_count, next.script_name
                ),
            ),
            (_, DesiredEdgeState::Retracted { reason }) => (
                "retracted",
                format!(
                    "retracted {}/{} from Cloudflare Worker {}: {reason}",
                    next.tenant_id, next.site, next.script_name
                ),
            ),
        };
        let tenant = ferrogate_core::TenantContext {
            organization_id: (!next.tenant_id.is_empty()).then(|| next.tenant_id.clone()),
            ..ferrogate_core::TenantContext::default()
        };
        self.state
            .current()
            .record_admin_audit_event(crate::state::AdminAuditEventDraft {
                action_identity: Default::default(),
                request_id: format!("site-publish-reconcile-{}", next.updated_at_unix),
                trace_id: None,
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                actor_api_key_id: None,
                tenant,
                action: "site.publish.cloudflare".to_string(),
                target: stored_asset_id(
                    &next.tenant_id,
                    SITE_ASSET_TYPE,
                    &next.site,
                    next.published_bundle_version.as_deref().unwrap_or("-"),
                ),
                outcome: outcome.to_string(),
                message,
            });
    }
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
