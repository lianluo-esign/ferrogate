// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Static-site serve mode + site bundles (issue #258, asset
// hosting epic #175 slice 2). A browseable surface --
// `GET /sites/{tenant}/{site}/{path...}` -- serves the per-file objects of a
// `static_site` published as a single zip bundle, resolving `index.html` for
// directory paths, an optional SPA fallback, and per-file `Content-Type` from
// a stored site manifest. Anonymous access is per-site opt-in (default:
// authenticated, reusing the same `assets.read` key/tenant gating as
// `handle_asset_pull`); HTTP caching (ETag/Last-Modified/Range/304/206) is
// shared with the pull path through `responses::write_cacheable_response`.
//
// #397: bundles are now RETAINED and immutable (keyed by bundle version), and
// the serve path resolves the ACTIVE bundle through the `serving` asset channel
// (reusing the #367 channel model) instead of a single overwritten manifest, so
// a channel move actually re-points what is served (write-path == read-path,
// #188) and console rollback (#345) is truthful. Sites published before #397
// (no `serving` channel) fall back to the mutable `__site_manifest__` marker and
// legacy bare-`{path}` file keying. See docs/assets/channel-version-lifecycle.md.

use std::io::Read;

use bytes::Bytes;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_storage::{
    asset_channel_id, sha256_hex, stored_asset_id, AssetVisibility, ChannelMoveOutcome,
    StoredAsset, StoredAssetChannel,
};

use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_cacheable_response, write_json_error, write_json_response, AssetCacheHeaders,
    },
};

/// Asset type every static-site object (per-file content and the manifest)
/// is stored under, so publishing a bundle reuses the same `stored_assets`
/// table and tenant quota accounting as any other asset.
pub(super) const SITE_ASSET_TYPE: &str = "static_site";

/// Reserved `version` for the per-site "latest" manifest row (#258). Kept as a
/// mutable existence/latest marker after #397: it is rewritten to the newest
/// published bundle every publish, still backs the `/admin/v1/site-domains`
/// existence check, and is the backward-compat serve source for legacy sites
/// that predate the channel-resolved serve path (a site with no `serving`
/// channel). A normal file path never collides with this because it contains no
/// `/` yet is not a plausible file name a bundle would ship.
pub(super) const SITE_MANIFEST_VERSION: &str = "__site_manifest__";

/// Well-known asset channel (#367 channel model, reused per #397) whose target
/// version is the bundle a site currently serves. Publishing a bundle moves this
/// channel to the new immutable bundle version through the atomic
/// [`move_asset_channel_if_resolvable`] CAS; a truthful console rollback (#345)
/// moves it back to a retained prior bundle version. The serve path resolves the
/// ACTIVE bundle through this channel, so a channel move actually re-points what
/// is served (write-path == read-path, #188).
pub(super) const SITE_SERVE_CHANNEL: &str = "serving";

/// Reserved `version` PREFIX for a bundle's per-file object rows (#397). Under
/// the retained-bundle model a file's row is keyed by
/// `__site_file__:{bundle_version}:{path}` so two bundle versions retain both
/// full sets of file objects instead of overwriting each other in place. The
/// bare `{bundle_version}` row is the bundle manifest (the channel-resolvable
/// version target); legacy sites (pre-#397) key each file row by the bare
/// `{path}` and are still served through the manifest fallback.
const SITE_FILE_VERSION_PREFIX: &str = "__site_file__";

/// Default `Cache-Control` for served site files when the site does not set
/// its own. Public sites are cacheable; the strong `ETag` still lets a client
/// revalidate once the max-age lapses.
const DEFAULT_SITE_CACHE_CONTROL: &str = "public, max-age=300";

/// Total unpacked size ceiling for a single site bundle -- a zip-bomb guard on
/// top of the per-request `MAX_ASSET_BYTES` limit on the compressed upload.
const MAX_SITE_UNPACKED_BYTES: usize = 64 * 1024 * 1024;

/// A published static site's file tree plus its serving policy (issue #258).
/// Persisted as the JSON body of the manifest asset row so serve-mode lookups
/// need one row read to learn a site's visibility, SPA behaviour, and the set
/// of files it exposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SiteManifest {
    pub(super) site: String,
    /// Version string from the publishing push URL, recorded for provenance.
    #[serde(default)]
    pub(super) bundle_version: String,
    /// Anonymous access opt-in. `false` (the default) keeps the site behind
    /// the same `assets.read` + tenant gating as the pull API.
    #[serde(default)]
    pub(super) public: bool,
    /// When `true`, a request that matches no file falls back to the site's
    /// `index.html` (single-page-app client-side routing).
    #[serde(default)]
    pub(super) spa_fallback: bool,
    /// Optional per-site `Cache-Control` override.
    #[serde(default)]
    pub(super) cache_control: Option<String>,
    pub(super) files: Vec<SiteFileEntry>,
    #[serde(default)]
    pub(super) created_at_unix: i64,
    #[serde(default)]
    pub(super) updated_at_unix: i64,
}

/// One file in a [`SiteManifest`]. `path` doubles as the `version` key of the
/// backing per-file asset row (`stored_asset_id(tenant, static_site, site, path)`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SiteFileEntry {
    pub(super) path: String,
    pub(super) content_type: String,
    pub(super) content_hash: String,
    pub(super) size_bytes: u64,
}

impl SiteManifest {
    fn file(&self, path: &str) -> Option<&SiteFileEntry> {
        self.files.iter().find(|entry| entry.path == path)
    }
}

/// Reserved `version` key for one file object inside a retained bundle (#397):
/// `__site_file__:{bundle_version}:{path}`. Namespacing the file rows under the
/// bundle version is what lets two published bundle versions retain both full
/// sets of objects instead of overwriting each other in place.
fn site_file_version(bundle_version: &str, path: &str) -> String {
    format!("{SITE_FILE_VERSION_PREFIX}:{bundle_version}:{path}")
}

/// The bundle a serve request resolved to, plus how to key its per-file object
/// rows (#397). The two arms are the write-path == read-path (#188) contract:
///
/// - `Bundle(bundle_version)` — resolved through the `serving` channel to a
///   retained, immutable bundle version. File rows are keyed by
///   [`site_file_version`], so moving the channel to a prior version re-points
///   BOTH the manifest and every file object the serve path reads.
/// - `Legacy` — no `serving` channel exists (a site published before #397). The
///   manifest came from the `__site_manifest__` marker and file rows are keyed
///   by the bare `{path}`, exactly as the pre-#397 serve path read them.
#[derive(Debug, Clone)]
enum SiteFileKeying {
    Bundle(String),
    Legacy,
}

/// Serving policy for a bundle publish (#397), parsed from the push headers by
/// the Session-facing wrapper and passed to the Session-free commit core.
pub(super) struct SiteBundlePublish {
    pub(super) public: bool,
    pub(super) spa_fallback: bool,
    pub(super) cache_control: Option<String>,
    pub(super) project_id: Option<String>,
}

/// Definitive, non-error outcome of [`FerroGateway::commit_site_bundle`] (#397).
pub(super) enum SiteBundleCommit {
    /// The bundle was retained under its immutable version and the `serving`
    /// channel now points at it. `prior_serving_version` is the version the
    /// channel pointed at before this publish (`None` for a brand-new site).
    Committed {
        manifest: SiteManifest,
        prior_serving_version: Option<String>,
    },
    /// This bundle version already exists and is immutable; nothing was written.
    VersionExists,
    /// The manifest row was written but the `serving`-channel CAS found the
    /// target unresolvable (should be unreachable on a live path).
    ServeChannelUnresolvable,
}

/// A site's active bundle as resolved for serving: the manifest to resolve a
/// request path against, and the keying used to load the matched file object.
struct ResolvedSiteBundle {
    manifest: SiteManifest,
    keying: SiteFileKeying,
}

impl ResolvedSiteBundle {
    /// Deterministic `stored_assets` id of one file object under the resolved
    /// keying. The serve path MUST load the object through this id so what a
    /// channel move re-points is exactly what is read.
    fn file_asset_id(&self, tenant: &str, site: &str, path: &str) -> String {
        match &self.keying {
            SiteFileKeying::Bundle(bundle_version) => stored_asset_id(
                tenant,
                SITE_ASSET_TYPE,
                site,
                &site_file_version(bundle_version, path),
            ),
            SiteFileKeying::Legacy => stored_asset_id(tenant, SITE_ASSET_TYPE, site, path),
        }
    }
}

/// `true` when `data` starts with the ZIP local-file-header magic (`PK\x03\x04`).
pub(super) fn is_zip_archive(data: &[u8]) -> bool {
    data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
}

impl FerroGateway {
    /// Serve mode: `GET /sites/{tenant}/{site}/{path...}` (issue #258).
    /// Thin wrapper over [`FerroGateway::serve_site_file`] that emits a request
    /// log for the served response so browse traffic shows up in the admin
    /// request-log surface like any other gateway route.
    pub(super) async fn handle_site_serve(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        // `{tenant}/{site}/{file...}` -- the file path may itself contain `/`,
        // so only the first two separators are structural.
        let rest = path.strip_prefix("/sites/").unwrap_or("");
        let mut parts = rest.splitn(3, '/');
        let tenant = parts.next().unwrap_or("").to_string();
        let site = parts.next().unwrap_or("").to_string();
        let file_path = parts.next().unwrap_or("").to_string();

        self.serve_site_and_log(session, ctx, headers, method, &tenant, &site, &file_path)
            .await
    }

    /// Shared serve entry point for both resolution surfaces: the path-based
    /// `/sites/{tenant}/{site}/{path...}` route and a bound custom hostname
    /// (`Host: mysite.example.com`, #265). Serves the file (with the same
    /// visibility gating either way) and emits a request log so browse traffic
    /// shows up in the admin request-log surface like any other gateway route.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn serve_site_and_log(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant: &str,
        site: &str,
        file_path: &str,
    ) -> PingoraResult<()> {
        let status = self
            .serve_site_file(session, ctx, headers, method, tenant, site, file_path)
            .await?;

        self.state
            .current()
            .record_request_log(ferrogate_storage::StoredRequestLog {
                request_id: ctx.request_id.clone(),
                trace_id: ctx.trace_id.clone(),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                cluster_id: None,
                node_id: None,
                tenant: ferrogate_core::TenantContext {
                    organization_id: (!tenant.is_empty()).then(|| tenant.to_string()),
                    team_id: None,
                    project_id: None,
                    workspace_id: None,
                    user_id: None,
                    api_key_id: None,
                },
                route: Some(format!("/sites/{tenant}/{site}")),
                provider: None,
                logical_model: None,
                provider_model: None,
                gateway_config_id: None,
                gateway_config_revision: None,
                status_code: status.as_u16(),
                error_code: (status.as_u16() >= 400).then(|| status.as_u16().to_string()),
                prompt_recorded: false,
                response_recorded: false,
                prompt_body: None,
                response_body: None,
                cache_status: None,
                started_at_unix: None,
                completed_at_unix: None,
                parent_action_fingerprint: None,
            });
        Ok(())
    }

    /// Resolves and writes the response for a serve-mode request, returning the
    /// status code it produced (for request logging). Fails closed: a private
    /// site requires an `assets.read` key attributed to `tenant`, and a valid
    /// key from another tenant gets a 404 rather than confirmation the site
    /// exists.
    #[allow(clippy::too_many_arguments)]
    async fn serve_site_file(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant: &str,
        site: &str,
        file_path: &str,
    ) -> PingoraResult<StatusCode> {
        if *method != Method::GET && *method != Method::HEAD {
            write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "site serve endpoints support GET and HEAD",
                &ctx.request_id,
            )
            .await?;
            return Ok(StatusCode::METHOD_NOT_ALLOWED);
        }
        if tenant.is_empty() || site.is_empty() {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "expected /sites/{tenant}/{site}/{path}",
                &ctx.request_id,
            )
            .await?;
            return Ok(StatusCode::NOT_FOUND);
        }

        let state = self.state.current();
        // #397: resolve the ACTIVE bundle through the `serving` channel (falling
        // back to the legacy `__site_manifest__` marker for pre-#397 sites), so a
        // channel move to a prior retained bundle version actually re-points what
        // this path serves -- write-path == read-path (#188).
        let resolved = match self.resolve_active_site_bundle(tenant, site).await {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "site_not_found",
                    format!("no published site at {tenant}/{site}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(StatusCode::NOT_FOUND);
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await?;
                return Ok(StatusCode::SERVICE_UNAVAILABLE);
            }
        };
        let manifest = &resolved.manifest;

        // Visibility: a public site is served anonymously; otherwise the caller
        // must present an `assets.read` key attributed to this exact tenant.
        if !manifest.public {
            let auth = match authenticate(&state, headers, "assets.read", &ctx.request_id).await {
                Ok(auth) => auth,
                Err(error) => {
                    let status = error.status;
                    write_json_error(session, status, error.code, error.message, &ctx.request_id)
                        .await?;
                    return Ok(status);
                }
            };
            if auth.organization_id.as_deref() != Some(tenant) {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "site_not_found",
                    format!("no published site at {tenant}/{site}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(StatusCode::NOT_FOUND);
            }
        }

        let Some(entry) = resolve_site_file(manifest, file_path) else {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "site_file_not_found",
                format!("no file for {file_path} in site {tenant}/{site}"),
                &ctx.request_id,
            )
            .await?;
            return Ok(StatusCode::NOT_FOUND);
        };
        let entry = entry.clone();

        let id = resolved.file_asset_id(tenant, site, &entry.path);
        let asset = match state.get_asset(&id).await {
            Ok(Some(asset)) => asset,
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "site_file_not_found",
                    format!("manifest lists {} but its object is missing", entry.path),
                    &ctx.request_id,
                )
                .await?;
                return Ok(StatusCode::NOT_FOUND);
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await?;
                return Ok(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

        let content = match self.load_asset_content(&asset).await {
            Ok(content) => content,
            Err(response) => {
                let status = response.status;
                response.write(session, &ctx.request_id).await?;
                return Ok(status);
            }
        };
        if sha256_hex(&content) != asset.content_hash {
            write_json_error(
                session,
                StatusCode::INTERNAL_SERVER_ERROR,
                "asset_integrity_check_failed",
                "stored site file content hash does not match recorded hash",
                &ctx.request_id,
            )
            .await?;
            return Ok(StatusCode::INTERNAL_SERVER_ERROR);
        }

        let cache_control = manifest
            .cache_control
            .as_deref()
            .unwrap_or(DEFAULT_SITE_CACHE_CONTROL);
        let cache = AssetCacheHeaders {
            content_type: &entry.content_type,
            etag: format!("\"{}\"", asset.content_hash),
            last_modified_unix: asset.updated_at_unix,
            cache_control,
        };
        write_cacheable_response(
            session,
            headers,
            method,
            Bytes::from(content),
            &cache,
            &ctx.request_id,
            &[],
        )
        .await
    }

    /// Publishes a multi-file `static_site` from a single zip upload (issue
    /// #258). Called by `handle_asset_push` once the pushed `static_site`
    /// content is detected to be a zip archive. Unpacks the archive into
    /// per-file asset rows, records a [`SiteManifest`], and emits an audit
    /// event (which captures the explicit public-mode opt-in).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn publish_site_bundle(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        auth: &crate::auth::AuthContext,
        headers: &http::HeaderMap,
        tenant_id: &str,
        site: &str,
        bundle_version: &str,
        archive: &[u8],
    ) -> PingoraResult<()> {
        let files = match unzip_archive(archive, MAX_SITE_UNPACKED_BYTES) {
            Ok(files) => files,
            Err(message) => {
                return write_json_error(
                    session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "site_bundle_rejected",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        if files.is_empty() {
            return write_json_error(
                session,
                StatusCode::UNPROCESSABLE_ENTITY,
                "site_bundle_rejected",
                "the uploaded archive contains no files",
                &ctx.request_id,
            )
            .await;
        }

        // Per-file supply-chain validation (#179): each unpacked object goes
        // through the same content-type allowlist + EICAR scan as a direct
        // single-file asset push, keyed off its guessed content-type.
        let mut prepared: Vec<(String, String, Vec<u8>)> = Vec::with_capacity(files.len());
        let mut total_bytes: u64 = 0;
        for (path, content) in files {
            let content_type = guess_site_content_type(&path);
            if let Err(message) = super::asset_security::validate_asset_content(
                SITE_ASSET_TYPE,
                &content_type,
                &content,
            ) {
                return write_json_error(
                    session,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "site_bundle_rejected",
                    format!("{path}: {message}"),
                    &ctx.request_id,
                )
                .await;
            }
            total_bytes = total_bytes.saturating_add(content.len() as u64);
            prepared.push((path, content_type, content));
        }

        let state = self.state.current();

        // Tenant storage-quota check across the whole bundle. Retained bundles
        // are ADDITIVE (#397): a new version keeps every prior version's bytes,
        // so nothing is subtracted -- the tenant pays for what it retains, and
        // reclaiming space is an explicit yank/delete of an old version.
        if let Some(quota) = auth.effective_quota.asset_storage_quota_bytes {
            let used = match state.tenant_asset_storage_bytes_used(tenant_id).await {
                Ok(used) => used,
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "storage_unavailable",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            };
            if used.saturating_add(total_bytes) > quota {
                return write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "asset_storage_quota_exceeded",
                    format!(
                        "publishing this site would exceed the tenant's {quota}-byte asset storage quota"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        }

        let public = header_flag(headers, "x-site-public");
        let spa_fallback = header_flag(headers, "x-site-spa-fallback");
        let cache_control = headers
            .get("x-site-cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .filter(|value| !value.is_empty());

        // The storage-committing core is Session-free so a sibling test can drive
        // the exact write path the serve path reads (write == read, #188).
        let options = SiteBundlePublish {
            public,
            spa_fallback,
            cache_control,
            project_id: auth.project_id.clone(),
        };
        let (manifest, prior_serving_version) = match self
            .commit_site_bundle(tenant_id, site, bundle_version, &prepared, &options)
            .await
        {
            Ok(SiteBundleCommit::Committed {
                manifest,
                prior_serving_version,
            }) => (manifest, prior_serving_version),
            Ok(SiteBundleCommit::VersionExists) => {
                return write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "site_version_immutable",
                    format!(
                        "site {tenant_id}/{site} version {bundle_version} already exists and is \
                         immutable; publish a new version"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            Ok(SiteBundleCommit::ServeChannelUnresolvable) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "site_serve_channel_unresolvable",
                    format!(
                        "published bundle {bundle_version} for {tenant_id}/{site} but its serve \
                         channel target was not resolvable"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };

        let manifest_id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, site, SITE_MANIFEST_VERSION);
        let prior_note = prior_serving_version
            .as_deref()
            .map(|prior| format!(", serving moved {prior} -> {bundle_version}"))
            .unwrap_or_else(|| format!(", serving set to {bundle_version}"));
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            auth,
            "site.publish",
            &manifest_id,
            "committed",
            format!(
                "site {tenant_id}/{site} published ({} files, {total_bytes} bytes, \
                 public={public}{prior_note})",
                manifest.files.len()
            ),
        ));

        let body = serde_json::json!({
            "object": "static_site",
            "tenant": tenant_id,
            "site": site,
            "bundle_version": bundle_version,
            "public": public,
            "spa_fallback": spa_fallback,
            "file_count": manifest.files.len(),
            "size_bytes": total_bytes,
            "files": manifest
                .files
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>(),
        });
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    /// Session-free core of a static-site publish (#397): the immutability guard,
    /// the per-file retained-bundle object writes, both manifest rows, and the
    /// atomic `serving`-channel move. Extracted from [`Self::publish_site_bundle`]
    /// so the WRITE path is exercised directly by the same code the serve READ
    /// path resolves against (write == read, #188), instead of a test-only
    /// reimplementation. Storage failures surface as `Err`; the definitive
    /// non-error dispositions are the [`SiteBundleCommit`] arms.
    pub(super) async fn commit_site_bundle(
        &self,
        tenant_id: &str,
        site: &str,
        bundle_version: &str,
        prepared: &[(String, String, Vec<u8>)],
        options: &SiteBundlePublish,
    ) -> anyhow::Result<SiteBundleCommit> {
        let state = self.state.current();

        // Immutability (#397, mirroring the single-asset #260 rule): a published
        // bundle version is frozen and RETAINED. Its manifest row lives at the
        // bare `{bundle_version}` version key (the channel-resolvable target).
        // Re-publishing the same version would overwrite retained bytes a prior
        // hash/rollback pins, so it is rejected -- the operator publishes a new
        // version instead. This is the concrete "retain, do not overwrite in
        // place" behavior #397 asks for.
        let bundle_manifest_id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, site, bundle_version);
        if state.get_asset(&bundle_manifest_id).await?.is_some() {
            return Ok(SiteBundleCommit::VersionExists);
        }

        let now = now_unix_seconds();
        let mut entries = Vec::with_capacity(prepared.len());
        for (path, content_type, content) in prepared {
            // #397: key each file object under the immutable bundle version so a
            // new publish RETAINS the prior version's objects instead of
            // overwriting them in place. The bundle_version row itself is the
            // manifest below; file rows carry the `__site_file__:` prefix.
            let id = stored_asset_id(
                tenant_id,
                SITE_ASSET_TYPE,
                site,
                &site_file_version(bundle_version, path),
            );
            let content_hash = sha256_hex(content);
            let (stored_content, storage_uri) = self
                .store_asset_bytes(&id, content, content_type)
                .await
                .map_err(|error| anyhow::anyhow!(error.message))?;
            let asset = StoredAsset {
                id,
                tenant_id: tenant_id.to_string(),
                project_id: options.project_id.clone(),
                asset_type: SITE_ASSET_TYPE.to_string(),
                name: site.to_string(),
                version: site_file_version(bundle_version, path),
                content_type: content_type.clone(),
                content_hash: content_hash.clone(),
                size_bytes: content.len() as u64,
                content: stored_content,
                storage_uri,
                variant: String::new(),
                yanked: false,
                // #366: per-file site rows are published only after the parent
                // bundle screened clean (guarded in handle_asset_push), so they
                // are visible.
                visibility: AssetVisibility::Visible,
                created_at_unix: now,
                updated_at_unix: now,
            };
            state.upsert_asset(asset).await?;
            entries.push(SiteFileEntry {
                path: path.clone(),
                content_type: content_type.clone(),
                content_hash,
                size_bytes: content.len() as u64,
            });
        }

        let manifest_created_at = self
            .load_site_manifest(tenant_id, site)
            .await
            .ok()
            .flatten()
            .map_or(now, |manifest| manifest.created_at_unix);
        let manifest = SiteManifest {
            site: site.to_string(),
            bundle_version: bundle_version.to_string(),
            public: options.public,
            spa_fallback: options.spa_fallback,
            cache_control: options.cache_control.clone(),
            files: entries,
            created_at_unix: manifest_created_at,
            updated_at_unix: now,
        };
        // #397: the bundle manifest row at the bare `{bundle_version}` version is
        // the channel-resolvable target (its single row is the version's only
        // "variant"). It is written BEFORE the channel move so the target is
        // durably resolvable when the #367 CAS checks it. It is immutable and
        // retained -- one row per published bundle version.
        self.store_site_manifest_at(tenant_id, &manifest, bundle_version, now)
            .await?;
        // Also refresh the mutable `__site_manifest__` marker: it keeps the
        // `/admin/v1/site-domains` existence check and any legacy reader working,
        // and is the backward-compat serve source for sites with no channel.
        self.store_site_manifest(tenant_id, &manifest, now).await?;

        // #397 + #367: move the `serving` channel to the newly published bundle
        // version through the atomic resolvability CAS. This is the single
        // write-path == read-path point (#188): the serve path reads the ACTIVE
        // bundle through exactly this channel. A truthful console rollback (#345)
        // is the same CAS moving the channel back to a retained prior version.
        let channel = StoredAssetChannel {
            id: asset_channel_id(tenant_id, SITE_ASSET_TYPE, site, SITE_SERVE_CHANNEL),
            tenant_id: tenant_id.to_string(),
            asset_type: SITE_ASSET_TYPE.to_string(),
            name: site.to_string(),
            channel: SITE_SERVE_CHANNEL.to_string(),
            version: bundle_version.to_string(),
            updated_at_unix: now,
        };
        match state.move_asset_channel_if_resolvable(channel).await? {
            ChannelMoveOutcome::Moved { prior_version } => Ok(SiteBundleCommit::Committed {
                manifest,
                prior_serving_version: prior_version,
            }),
            // The bundle manifest row was just written and is not yanked, so this
            // should be unreachable; report it rather than silently serving stale.
            ChannelMoveOutcome::TargetNotResolvable => {
                Ok(SiteBundleCommit::ServeChannelUnresolvable)
            }
        }
    }

    /// Resolves the ACTIVE bundle a site currently serves (#397). Preferred
    /// path: the `serving` channel points at an immutable, retained bundle
    /// version whose manifest row (`stored_asset_id(.., bundle_version)`) is the
    /// channel-resolvable target; the returned keying loads that bundle's file
    /// objects. A channel move (rollback, #345) to a prior retained version
    /// therefore re-points BOTH the manifest and every file object the serve
    /// path reads. Backward-compat: a site with no `serving` channel (published
    /// before #397) falls back to the mutable `__site_manifest__` marker and the
    /// legacy bare-`{path}` file keying, so already-served sites keep serving.
    async fn resolve_active_site_bundle(
        &self,
        tenant_id: &str,
        site: &str,
    ) -> anyhow::Result<Option<ResolvedSiteBundle>> {
        let state = self.state.current();
        let serving = state
            .list_asset_channels(tenant_id, SITE_ASSET_TYPE, site)
            .await?
            .into_iter()
            .find(|channel| channel.channel == SITE_SERVE_CHANNEL);
        if let Some(serving) = serving {
            let bundle_version = serving.version;
            let manifest_id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, site, &bundle_version);
            let Some(asset) = state.get_asset(&manifest_id).await? else {
                // The channel points at a version whose manifest row is gone.
                // The #367 CAS keeps this from happening on a live path, but fail
                // closed (treat as not found) rather than serve nothing.
                return Ok(None);
            };
            let manifest =
                serde_json::from_slice::<SiteManifest>(&asset.content).map_err(|error| {
                    anyhow::anyhow!(
                        "corrupt bundle manifest for {tenant_id}/{site}@{bundle_version}: {error}"
                    )
                })?;
            return Ok(Some(ResolvedSiteBundle {
                manifest,
                keying: SiteFileKeying::Bundle(bundle_version),
            }));
        }
        // No serving channel: legacy site. Serve from the mutable marker with the
        // pre-#397 bare-path file keying.
        Ok(self
            .load_site_manifest(tenant_id, site)
            .await?
            .map(|manifest| ResolvedSiteBundle {
                manifest,
                keying: SiteFileKeying::Legacy,
            }))
    }

    /// Maps the BARE per-file reference the admin console addresses a static
    /// site's objects by (`/v1/assets/static_site/{site}/{path}`) onto the object
    /// key #397 actually stores each file under
    /// (`__site_file__:{serving_version}:{path}`), so a per-file download or
    /// unpublish resolves for a #397-published bundle -- not just legacy sites
    /// (#402, follow-up to #398). The generic `/v1/assets/*` pull and delete
    /// handlers call this to compute the effective `{version}` for the
    /// `static_site` asset type before resolving/deleting the object.
    ///
    /// Deliberately narrow and backward-compatible -- it is a no-op for every
    /// pre-#402 caller:
    /// - A reserved key (the mutable `__site_manifest__` marker, or a reference
    ///   already carrying the `__site_file__:` prefix) is returned UNCHANGED; it
    ///   already addresses a row directly (the console deletes the marker last).
    /// - Otherwise the ACTIVE bundle is resolved through the same `serving`
    ///   channel the serve path reads (write-path == read-path, #188). For a
    ///   #397 site the bare `{path}` is rewritten to the prefixed key ONLY when
    ///   that object actually exists; for a legacy site (no `serving` channel),
    ///   or a reference that is not a live per-file path of the active bundle
    ///   (e.g. a bundle-version manifest key), the reference is returned
    ///   unchanged so the #398 bare-path decode path still resolves.
    pub(super) async fn resolve_site_asset_version(
        &self,
        tenant_id: &str,
        site: &str,
        reference: &str,
    ) -> String {
        let already_prefixed = matches!(
            reference.strip_prefix(SITE_FILE_VERSION_PREFIX),
            Some(rest) if rest.starts_with(':')
        );
        if reference == SITE_MANIFEST_VERSION || already_prefixed {
            return reference.to_string();
        }
        // Resolve the ACTIVE bundle. A legacy site (bare-path keying) or a site
        // whose serving channel target is missing leaves the reference untouched.
        let Ok(Some(resolved)) = self.resolve_active_site_bundle(tenant_id, site).await else {
            return reference.to_string();
        };
        let SiteFileKeying::Bundle(bundle_version) = resolved.keying else {
            return reference.to_string();
        };
        // Only remap when the prefixed object exists, so a reference that is not
        // a live per-file path of the active bundle (e.g. `{bundle_version}`
        // itself) still addresses its own row.
        let prefixed = site_file_version(&bundle_version, reference);
        let prefixed_id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, site, &prefixed);
        match self.state.current().get_asset(&prefixed_id).await {
            Ok(Some(_)) => prefixed,
            _ => reference.to_string(),
        }
    }

    pub(super) async fn load_site_manifest(
        &self,
        tenant_id: &str,
        site: &str,
    ) -> anyhow::Result<Option<SiteManifest>> {
        let id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, site, SITE_MANIFEST_VERSION);
        let Some(asset) = self.state.current().get_asset(&id).await? else {
            return Ok(None);
        };
        let manifest = serde_json::from_slice::<SiteManifest>(&asset.content).map_err(|error| {
            anyhow::anyhow!("corrupt site manifest for {tenant_id}/{site}: {error}")
        })?;
        Ok(Some(manifest))
    }

    async fn store_site_manifest(
        &self,
        tenant_id: &str,
        manifest: &SiteManifest,
        now: i64,
    ) -> anyhow::Result<()> {
        self.store_site_manifest_at(tenant_id, manifest, SITE_MANIFEST_VERSION, now)
            .await
    }

    /// Stores a [`SiteManifest`] JSON row under an explicit `version` key (#397).
    /// Two callers share it: the mutable `__site_manifest__` marker, and the
    /// immutable per-bundle manifest at the bare `{bundle_version}` version that
    /// the `serving` channel resolves to.
    async fn store_site_manifest_at(
        &self,
        tenant_id: &str,
        manifest: &SiteManifest,
        version: &str,
        now: i64,
    ) -> anyhow::Result<()> {
        let body = serde_json::to_vec(manifest)?;
        let id = stored_asset_id(tenant_id, SITE_ASSET_TYPE, &manifest.site, version);
        // The manifest is always stored inline (not bucket-backed): it is small,
        // and serve-mode lookups must read it before deciding anything.
        let asset = StoredAsset {
            id,
            tenant_id: tenant_id.to_string(),
            project_id: None,
            asset_type: SITE_ASSET_TYPE.to_string(),
            name: manifest.site.clone(),
            version: version.to_string(),
            content_type: "application/json".to_string(),
            content_hash: sha256_hex(&body),
            size_bytes: body.len() as u64,
            content: body,
            storage_uri: None,
            variant: String::new(),
            yanked: false,
            // #366: the site manifest row is written only on a clean bundle
            // publish, so it is visible.
            visibility: AssetVisibility::Visible,
            created_at_unix: manifest.created_at_unix.min(now),
            updated_at_unix: now,
        };
        self.state.current().upsert_asset(asset).await
    }
}

/// Resolves a request path (relative to `/sites/{tenant}/{site}/`) to a file in
/// the manifest: appends `index.html` for a directory-style path, tries the
/// path as a directory when it isn't an exact file, and applies the SPA
/// fallback last. Pure so it can be unit-tested without a live gateway.
fn resolve_site_file<'a>(manifest: &'a SiteManifest, file_path: &str) -> Option<&'a SiteFileEntry> {
    let trimmed = file_path.trim_start_matches('/');
    let direct = if trimmed.is_empty() || trimmed.ends_with('/') {
        format!("{trimmed}index.html")
    } else {
        trimmed.to_string()
    };
    if let Some(entry) = manifest.file(&direct) {
        return Some(entry);
    }
    if !trimmed.is_empty() && !trimmed.ends_with('/') {
        // Extensionless directory request, e.g. `/docs` -> `/docs/index.html`.
        if let Some(entry) = manifest.file(&format!("{trimmed}/index.html")) {
            return Some(entry);
        }
    }
    if manifest.spa_fallback {
        return manifest.file("index.html");
    }
    None
}

fn header_flag(headers: &http::HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.trim();
            value.eq_ignore_ascii_case("true") || value == "1" || value.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Per-file `Content-Type` guessed from a site file's extension. Falls back to
/// `application/octet-stream` for unknown extensions.
pub(super) fn guess_site_content_type(path: &str) -> String {
    let extension = path
        .rsplit('/')
        .next()
        .and_then(|file| file.rsplit_once('.'))
        .map(|(_, ext)| ext.to_ascii_lowercase());
    let content_type = match extension.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("md" | "markdown") => "text/markdown; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    content_type.to_string()
}

/// Minimal ZIP reader supporting the two compression methods a static-site
/// bundle uses in practice -- stored (0) and deflate (8) -- decompressing via
/// the `flate2` already in the dependency tree rather than pulling in the full
/// `zip` crate. Parses the End-of-Central-Directory record and central
/// directory (the authoritative entry list), rejecting path traversal and
/// oversized (zip-bomb) archives. ZIP64 is not supported, which is fine for
/// the small bundles this slice targets.
fn unzip_archive(data: &[u8], max_total: usize) -> Result<Vec<(String, Vec<u8>)>, String> {
    const EOCD_SIGNATURE: u32 = 0x0605_4b50;
    const CENTRAL_DIR_SIGNATURE: u32 = 0x0201_4b50;
    const LOCAL_FILE_SIGNATURE: u32 = 0x0403_4b50;

    let eocd = find_eocd(data, EOCD_SIGNATURE).ok_or_else(|| {
        "not a valid zip archive (missing end-of-central-directory record)".to_string()
    })?;
    let total_entries = read_u16(data, eocd + 10).ok_or("truncated zip archive")? as usize;
    let mut pos = read_u32(data, eocd + 16).ok_or("truncated zip archive")? as usize;

    let mut files = Vec::with_capacity(total_entries);
    let mut running_total: usize = 0;
    for _ in 0..total_entries {
        if read_u32(data, pos) != Some(CENTRAL_DIR_SIGNATURE) {
            return Err("corrupt zip central directory".to_string());
        }
        let method = read_u16(data, pos + 10).ok_or("truncated zip archive")?;
        let compressed_size = read_u32(data, pos + 20).ok_or("truncated zip archive")? as usize;
        let uncompressed_size = read_u32(data, pos + 24).ok_or("truncated zip archive")? as usize;
        let name_len = read_u16(data, pos + 28).ok_or("truncated zip archive")? as usize;
        let extra_len = read_u16(data, pos + 30).ok_or("truncated zip archive")? as usize;
        let comment_len = read_u16(data, pos + 32).ok_or("truncated zip archive")? as usize;
        let local_offset = read_u32(data, pos + 42).ok_or("truncated zip archive")? as usize;
        let name_bytes = data
            .get(pos + 46..pos + 46 + name_len)
            .ok_or("truncated zip archive")?;
        let raw_name =
            std::str::from_utf8(name_bytes).map_err(|_| "non-UTF-8 zip entry name".to_string())?;
        pos = pos + 46 + name_len + extra_len + comment_len;

        // Directory entries (trailing slash) carry no content.
        if raw_name.ends_with('/') {
            continue;
        }
        let normalized = normalize_entry_path(raw_name)?;

        if read_u32(data, local_offset) != Some(LOCAL_FILE_SIGNATURE) {
            return Err("corrupt zip local file header".to_string());
        }
        let local_name_len =
            read_u16(data, local_offset + 26).ok_or("truncated zip archive")? as usize;
        let local_extra_len =
            read_u16(data, local_offset + 28).ok_or("truncated zip archive")? as usize;
        let data_start = local_offset + 30 + local_name_len + local_extra_len;
        let compressed = data
            .get(data_start..data_start + compressed_size)
            .ok_or("truncated zip entry data")?;

        let remaining = max_total - running_total;
        let content = match method {
            0 => {
                if compressed.len() > remaining {
                    return Err(format!(
                        "site bundle unpacks to more than {max_total} bytes"
                    ));
                }
                compressed.to_vec()
            }
            8 => inflate(compressed, uncompressed_size, remaining)?,
            other => return Err(format!("unsupported zip compression method {other}")),
        };
        running_total += content.len();
        files.push((normalized, content));
    }
    Ok(files)
}

fn inflate(compressed: &[u8], expected: usize, remaining: usize) -> Result<Vec<u8>, String> {
    let decoder = flate2::read::DeflateDecoder::new(compressed);
    // Read at most `remaining + 1` bytes so an over-limit (zip-bomb) entry is
    // detected without materializing the whole thing.
    let mut limited = decoder.take(remaining as u64 + 1);
    let mut out = Vec::with_capacity(expected.min(remaining));
    limited
        .read_to_end(&mut out)
        .map_err(|error| format!("failed to inflate zip entry: {error}"))?;
    if out.len() > remaining {
        return Err("site bundle unpacks beyond its size limit".to_string());
    }
    Ok(out)
}

fn normalize_entry_path(raw: &str) -> Result<String, String> {
    let path = raw.trim_start_matches('/').replace('\\', "/");
    if path.is_empty() {
        return Err("zip contains an entry with an empty name".to_string());
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(format!("unsafe zip entry path: {raw}"));
        }
    }
    Ok(path)
}

fn find_eocd(data: &[u8], signature: u32) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    // The EOCD is at least 22 bytes and may be followed by a comment of up to
    // 0xffff bytes; scan backwards from the latest possible position.
    let earliest = data.len().saturating_sub(22 + 0xffff);
    (earliest..=data.len() - 22)
        .rev()
        .find(|&i| read_u32(data, i) == Some(signature))
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
#[path = "sites_test.rs"]
mod sites_test;
