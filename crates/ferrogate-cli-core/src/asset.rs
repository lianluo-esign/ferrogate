// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Asset registry, presigned transfer, channel promotion, and static-site
//! domain command families (issue #363).
//!
//! This slice moves the asset control surface of the Control Plane API onto the
//! shared #360 `CommandGroup`/`Registry` + #361 `ResourceApi`/`build_crud`
//! foundation. As with the other families, each resource noun is a
//! [`CommandGroup`] declaring its verbs and the OpenAPI `operationId` each verb
//! invokes as compile-time metadata — the single source of truth the #365 parity
//! gate diffs against the contract — and a `build` function mapping a resolved
//! verb plus typed [`ResourceInput`] onto a [`RequestSpec`]. No request body
//! schema is hard-coded: mutations carry a complete operator-supplied JSON
//! document.
//!
//! Four families are declared:
//!
//! * **assets** — the registry itself. An asset version is addressed by the
//!   composite `{asset_type}/{name}/{version}` key rather than a single id, so
//!   `get`/`put`/`delete` take three segments. `list`/`list-by-type` read the
//!   collection and per-type views, `manifest` reads the immutable resolved
//!   manifest, `storage-summary` exposes retention/GC visibility, `withheld`
//!   reads the operator view of assets held back by the scan pipeline
//!   (`pending_scan`/`quarantined`), and
//!   `yank`/`unyank` are first-class lifecycle actions (`POST`/`DELETE` on the
//!   `.../yank` sub-path) so an operator's intent and the audit trail stay
//!   precise instead of collapsing into a generic update.
//! * **asset-transfer** — the presigned upload/download flow. The CLI follows
//!   Control Plane API-issued transfer instructions and never reaches into the
//!   private bucket configuration directly: `upload-intent` requests a presigned
//!   `PUT` target, `commit` finalizes it, and `download-url` requests a presigned
//!   read. The presigned URLs these return are one-time credentials;
//!   [`ASSET_TRANSFER_SECRET_FIELDS`] names them so the command layer can redact
//!   them from any diagnostic rendering via
//!   [`crate::resource::redact_secret_fields`].
//! * **asset-channels** — channel/tag promotion. `set` moves a channel (e.g.
//!   `stable`, `latest`) to a specific version via `PUT .../channels/{channel}`
//!   with the target version carried as a `?version=` query parameter exactly as
//!   the contract declares; `delete` retires a channel; `list` reads the current
//!   channel map.
//! * **site-domains** — the static-site custom-domain lifecycle. `bind`
//!   registers a hostname, `get` reads its verification/binding state, `unbind`
//!   removes it, and `list` enumerates a tenant's bound domains. Static-site
//!   *content* is published through the asset registry itself (an asset of type
//!   `static-site` via `assets put`); the API exposes no separate publish
//!   operation, so this family covers the domain half of the lifecycle.
//!
//! Storage credentials stay server-side throughout: every path here is an
//! authenticated Control Plane API call, never a direct database or bucket
//! reach-in.

use http::Method;

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::{CliError, CliResult};
use crate::registry_helpers::{build_crud, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/v1/assets` — the asset registry collection. Items are addressed by the
/// composite `{asset_type}/{name}/{version}` key.
pub const ASSETS: ResourceApi = ResourceApi::new("/v1/assets");
/// `/v1/assets/presign` — the presigned transfer sub-surface.
pub const ASSET_PRESIGN: ResourceApi = ResourceApi::new("/v1/assets/presign");
/// `/admin/v1/site-domains` — static-site custom-domain bindings.
pub const SITE_DOMAINS: ResourceApi = ResourceApi::new("/admin/v1/site-domains");

/// Presigned-URL fields returned by the transfer operations. These are one-time
/// storage credentials and must be redacted from any diagnostic rendering.
pub const ASSET_TRANSFER_SECRET_FIELDS: &[&str] = &["upload_url", "download_url"];

/// Require the composite `{asset_type}/{name}/{version}` key from the input
/// segments, returning an actionable usage error naming the expected shape when
/// fewer than three are supplied. Guards against an under-specified key silently
/// addressing a shorter (and therefore wrong) operation path.
fn asset_version_ref<'a>(input: &'a ResourceInput, verb: &str) -> CliResult<[&'a str; 3]> {
    let segments = input.segment_refs();
    match segments.as_slice() {
        [asset_type, name, version, ..] => Ok([asset_type, name, version]),
        _ => Err(CliError::usage(format!(
            "verb '{verb}' requires <asset_type> <name> <version>"
        ))),
    }
}

/// Require the `{asset_type}/{name}` prefix (an asset lineage without a specific
/// version), for the manifest and channel-list reads.
fn asset_name_ref<'a>(input: &'a ResourceInput, verb: &str) -> CliResult<[&'a str; 2]> {
    let segments = input.segment_refs();
    match segments.as_slice() {
        [asset_type, name, ..] => Ok([asset_type, name]),
        _ => Err(CliError::usage(format!(
            "verb '{verb}' requires <asset_type> <name>"
        ))),
    }
}

/// The asset registry: collection/per-type reads, the composite-key item verbs,
/// the immutable manifest, retention/GC visibility, and yank/unyank lifecycle.
pub struct AssetsGroup;

impl CommandGroup for AssetsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "assets",
            "Manage the asset registry, versions, and lifecycle",
            vec![
                VerbDescriptor::api("list", "List all assets", "listAssets"),
                VerbDescriptor::api(
                    "list-by-type",
                    "List assets of one type",
                    "listAssetsByType",
                ),
                VerbDescriptor::api("get", "Show one asset version", "getAsset"),
                VerbDescriptor::api("put", "Publish or replace an asset version", "putAsset"),
                VerbDescriptor::api("delete", "Delete an asset version", "deleteAsset"),
                VerbDescriptor::api(
                    "manifest",
                    "Show an asset's resolved manifest",
                    "getAssetManifest",
                ),
                VerbDescriptor::api(
                    "storage-summary",
                    "Show asset storage/retention summary",
                    "getAssetStorageSummary",
                ),
                VerbDescriptor::api(
                    "withheld",
                    "List withheld (pending_scan/quarantined) assets",
                    "listWithheldAssets",
                ),
                VerbDescriptor::api("yank", "Yank an asset version", "yankAssetVersion"),
                VerbDescriptor::api(
                    "unyank",
                    "Reverse a yank on an asset version",
                    "unyankAssetVersion",
                ),
            ],
        )
    }
}

/// Build the request for an `assets` verb. The composite-key item verbs and the
/// yank lifecycle map to their own paths; the two collection reads and the
/// storage summary read their fixed sub-paths.
pub fn build_assets(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "list" => ASSETS.read(&[], &input.list),
        "list-by-type" => {
            let asset_type = first_segment(input, "asset")?;
            ASSETS.read(&[asset_type], &input.list)
        }
        "get" => {
            let key = asset_version_ref(input, verb)?;
            ASSETS.get(&key)
        }
        "put" => {
            let key = asset_version_ref(input, verb)?;
            ASSETS.replace(&key, input.require_body(verb)?)
        }
        "delete" => {
            let key = asset_version_ref(input, verb)?;
            ASSETS.delete(&key)
        }
        "manifest" => {
            let [asset_type, name] = asset_name_ref(input, verb)?;
            ASSETS.read(&[asset_type, name, "manifest"], &input.list)
        }
        "storage-summary" => ASSETS.read(&["storage", "summary"], &input.list),
        "withheld" => ASSETS.read(&["withheld"], &input.list),
        "yank" => {
            let [asset_type, name, version] = asset_version_ref(input, verb)?;
            ASSETS.action(&[asset_type, name, version, "yank"], input.body.clone())
        }
        "unyank" => {
            let [asset_type, name, version] = asset_version_ref(input, verb)?;
            ASSETS.mutate(Method::DELETE, &[asset_type, name, version, "yank"], None)
        }
        other => build_crud(&ASSETS, other, input),
    }
}

/// Presigned asset transfer: request an upload intent, commit an upload, or
/// request a download URL. All three follow API-issued transfer instructions.
pub struct AssetTransferGroup;

impl CommandGroup for AssetTransferGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "asset-transfer",
            "Presigned asset upload and download flows",
            vec![
                VerbDescriptor::api(
                    "upload-intent",
                    "Request a presigned upload target",
                    "createAssetUploadIntent",
                ),
                VerbDescriptor::api(
                    "commit",
                    "Commit a completed presigned upload",
                    "commitAssetUpload",
                ),
                VerbDescriptor::api(
                    "download-url",
                    "Request a presigned download URL",
                    "getAssetDownloadUrl",
                ),
            ],
        )
    }
}

/// Build the request for an `asset-transfer` verb. Each verb prefixes the
/// presign action name onto the composite `{asset_type}/{name}/{version}` key.
pub fn build_asset_transfer(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    let [asset_type, name, version] = asset_version_ref(input, verb)?;
    match verb {
        "upload-intent" => ASSET_PRESIGN.action(
            &["upload", asset_type, name, version],
            Some(input.require_body(verb)?),
        ),
        "commit" => ASSET_PRESIGN.action(
            &["commit", asset_type, name, version],
            Some(input.require_body(verb)?),
        ),
        "download-url" => ASSET_PRESIGN.read(&["download", asset_type, name, version], &input.list),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not an asset-transfer verb"
        ))),
    }
}

/// Asset channel/tag promotion: read the channel map, move a channel to a
/// version, or retire a channel.
pub struct AssetChannelsGroup;

impl CommandGroup for AssetChannelsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "asset-channels",
            "Manage asset release channels and promotion",
            vec![
                VerbDescriptor::api("list", "List an asset's channels", "listAssetChannels"),
                VerbDescriptor::api("set", "Point a channel at a version", "putAssetChannel"),
                VerbDescriptor::api("delete", "Delete a channel", "deleteAssetChannel"),
            ],
        )
    }
}

/// Build the request for an `asset-channels` verb.
///
/// `list` reads `.../{asset_type}/{name}/channels`. `set` promotes a channel to
/// a version via `PUT .../channels/{channel}` with the version carried as the
/// contract's `?version=` query parameter (no request body); it therefore takes
/// four segments `<asset_type> <name> <channel> <version>`. `delete` retires a
/// channel and takes `<asset_type> <name> <channel>`.
pub fn build_asset_channels(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    let segments = input.segment_refs();
    match verb {
        "list" => {
            let [asset_type, name] = asset_name_ref(input, verb)?;
            ASSETS.read(&[asset_type, name, "channels"], &input.list)
        }
        "set" => match segments.as_slice() {
            [asset_type, name, channel, version, ..] => {
                let spec =
                    ASSETS.mutate(Method::PUT, &[asset_type, name, "channels", channel], None)?;
                Ok(spec.with_query("version", *version))
            }
            _ => Err(CliError::usage(
                "verb 'set' requires <asset_type> <name> <channel> <version>".to_string(),
            )),
        },
        "delete" => match segments.as_slice() {
            [asset_type, name, channel, ..] => ASSETS.mutate(
                Method::DELETE,
                &[asset_type, name, "channels", channel],
                None,
            ),
            _ => Err(CliError::usage(
                "verb 'delete' requires <asset_type> <name> <channel>".to_string(),
            )),
        },
        other => Err(CliError::usage(format!(
            "verb '{other}' is not an asset-channels verb"
        ))),
    }
}

/// Static-site custom-domain lifecycle: list/get/bind/unbind.
pub struct SiteDomainsGroup;

impl CommandGroup for SiteDomainsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "site-domains",
            "Manage static-site custom domain bindings",
            vec![
                VerbDescriptor::api("list", "List bound site domains", "listSiteDomains"),
                VerbDescriptor::api("get", "Show a site domain binding", "getSiteDomain"),
                VerbDescriptor::api("bind", "Bind a custom domain to a site", "bindSiteDomain"),
                VerbDescriptor::api("unbind", "Unbind a custom domain", "unbindSiteDomain"),
            ],
        )
    }
}

/// Build the request for a `site-domains` verb. `bind` posts a binding document
/// to the collection; `get`/`unbind` address one hostname; `list` reads the
/// collection (a `tenant` filter is supplied via list params).
pub fn build_site_domains(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "list" => SITE_DOMAINS.read(&[], &input.list),
        "get" => SITE_DOMAINS.get(&[first_segment(input, "site-domain")?]),
        "bind" => SITE_DOMAINS.create(input.require_body(verb)?),
        "unbind" => SITE_DOMAINS.delete(&[first_segment(input, "site-domain")?]),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not a site-domains verb"
        ))),
    }
}

/// Register every asset command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&AssetsGroup)?;
    registry.register(&AssetTransferGroup)?;
    registry.register(&AssetChannelsGroup)?;
    registry.register(&SiteDomainsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "asset_test.rs"]
mod asset_test;
