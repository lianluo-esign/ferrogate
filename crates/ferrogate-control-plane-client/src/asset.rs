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
//!   `get`/`put`/`delete` take three segments. Both content verbs are binary,
//!   not JSON: `get` is a raw `*/*` read whose bytes go to stdout unchanged
//!   (`--output` is refused, since there is nothing to render), and `put`
//!   publishes the artifact's bytes from `--body-file`. `list`/`list-by-type`
//!   read the collection and per-type views, `manifest` reads the immutable
//!   resolved manifest, `storage-summary` exposes retention/GC visibility,
//!   `withheld` reads the operator view of assets held back by the scan pipeline
//!   (`pending_scan`/`quarantined`), `promote-visibility` posts the completed
//!   out-of-band scan verdict (`{scan_outcome, evidence}`) that moves a
//!   withheld version to its **terminal** visibility — it is a one-shot,
//!   fail-closed compare-and-swap out of `pending_scan`, `quarantined`
//!   withholds the version permanently, and a repeat attempt returns 409, so
//!   the verb is confirmation-guarded — and
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
//!   registers a hostname, `verify` redeems the DNS-ownership challenge, `get`
//!   reads its verification/binding state, `unbind` removes it, and `list`
//!   enumerates a tenant's bound domains.
//!
//! # Static-site publish, status, and unpublish
//!
//! There is deliberately no `static-sites` family: the contract declares no
//! publish/status/unpublish operation, and inventing CLI verbs with no
//! `operationId` behind them is exactly what the #365 parity gate exists to
//! reject. A site is an asset of type `static_site`, so the lifecycle is the
//! registry's own verbs plus the header parameters `putAsset` declares for it:
//!
//! * **publish** — `assets put static_site <name> <version> --body-file
//!   bundle.zip --header content-type=application/zip`, adding
//!   `--header x-site-public=true`, `--header x-site-spa-fallback=true`, or
//!   `--header x-site-cache-control=…` to set how the bundle is served, and
//!   `--filter channel=stable` to move a channel once the publish is durable.
//! * **status** — `assets manifest static_site <name>` for the resolved
//!   manifest, `site-domains get <hostname>` for the binding.
//! * **unpublish** — `assets yank` to withdraw a version while keeping the
//!   audit trail, or `assets delete` to remove the object.
//!
//! Both publish-side controls that were previously unreachable — the binary body
//! and the `x-*` headers — reach the wire through the generic seams
//! (`--body-file`, `--header`), so no asset-specific flag is hard-coded into the
//! command layer (issue #363 review).
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

/// `Accept` for the asset content reads. The contract declares `getAsset`'s
/// 200/206 body as `*/*` (`format: binary`), so the CLI must not claim to want
/// JSON and must not re-encode what comes back.
const ASSET_CONTENT_MEDIA_TYPE: &str = "*/*";

/// Default `Content-Type` for the publish body. `putAsset` accepts `*/*`, which
/// is a wildcard the client cannot *send*, so the neutral binary type is the
/// default and the operator restates it (`--header content-type=application/zip`
/// for a static-site bundle) when the artifact has a more specific one.
const ASSET_UPLOAD_MEDIA_TYPE: &str = "application/octet-stream";

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
                VerbDescriptor::read("list", "List all assets", "listAssets"),
                VerbDescriptor::read(
                    "list-by-type",
                    "List assets of one type",
                    "listAssetsByType",
                ),
                // `getAsset`'s 200/206 body is the asset itself — the contract
                // declares `*/*` with `format: binary`. Routing it through the
                // structured renderer replaced every non-UTF-8 byte with
                // U+FFFD, so `ctl assets get … > out.bin` produced a
                // JSON-quoted lossy string instead of the object. A raw read
                // writes the bytes through unchanged and refuses `--output`.
                VerbDescriptor::raw_read(
                    "get",
                    "Download one asset version's bytes to stdout",
                    "getAsset",
                    ASSET_CONTENT_MEDIA_TYPE,
                ),
                // `putAsset`'s request body is the artifact — the contract
                // declares `*/*` with `format: binary`. Declared as a raw write
                // so the bytes are sent verbatim; a JSON-document verb could
                // not publish a tarball, a signed binary, or a static-site
                // bundle at all.
                VerbDescriptor::raw_write(
                    "put",
                    "Publish an asset version from a file's bytes",
                    "putAsset",
                    ASSET_UPLOAD_MEDIA_TYPE,
                ),
                VerbDescriptor::mutating("delete", "Delete an asset version", "deleteAsset"),
                VerbDescriptor::read(
                    "manifest",
                    "Show an asset's resolved manifest",
                    "getAssetManifest",
                ),
                VerbDescriptor::read(
                    "storage-summary",
                    "Show asset storage/retention summary",
                    "getAssetStorageSummary",
                ),
                VerbDescriptor::read(
                    "withheld",
                    "List withheld (pending_scan/quarantined) assets",
                    "listWithheldAssets",
                ),
                // Guarded, and the help text states the body it needs.
                // `promoteAssetVisibility` is a one-shot fail-closed CAS out of
                // `pending_scan`: `clean` publishes the version and
                // `quarantined` withholds it PERMANENTLY, and either way a
                // second attempt returns 409. Declaring it a plain `mutating`
                // verb whose about-line said "Promote an asset version's
                // visibility" hid both facts — an operator could quarantine a
                // release for good with no prompt, and had nothing telling them
                // the required `{scan_outcome, evidence}` document exists, so
                // the obvious invocation returned a 400 from the server.
                VerbDescriptor::mutating_with_confirmation(
                    "promote-visibility",
                    "Apply a completed out-of-band scan verdict to a withheld (pending_scan) \
                     asset version. IRREVERSIBLE and one-shot: scan_outcome=clean publishes, \
                     scan_outcome=quarantined withholds the version permanently, and a repeat \
                     attempt returns 409. Requires --data \
                     '{\"scan_outcome\":\"clean|quarantined\",\"evidence\":\"<scanner id or \
                     ticket>\"}'; missing or unknown values are rejected and never promote.",
                    "promoteAssetVisibility",
                ),
                VerbDescriptor::mutating("yank", "Yank an asset version", "yankAssetVersion"),
                VerbDescriptor::mutating(
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
            // `platform` (and any other contract query parameter) arrives as a
            // list filter; `getAsset` needs it to resolve a variant.
            ASSETS.read(&key, &input.list)
        }
        "put" => {
            let key = asset_version_ref(input, verb)?;
            let payload = input.require_raw_body(verb)?;
            let spec = ASSETS.replace_bytes(&key, &payload.media_type, payload.bytes.clone())?;
            // `putAsset` declares `platform` AND `channel`: which variant slot
            // these bytes occupy, and which channel moves to them once the
            // publish is durable.
            Ok(input.list.apply_filters(spec))
        }
        "delete" => {
            let key = asset_version_ref(input, verb)?;
            // `deleteAsset` declares `platform`. Dropping it does not fail the
            // call — it destroys whichever variant the server resolves by
            // default, with exit 0 and no diagnostic.
            Ok(input.list.apply_filters(ASSETS.delete(&key)?))
        }
        "manifest" => {
            let [asset_type, name] = asset_name_ref(input, verb)?;
            ASSETS.read(&[asset_type, name, "manifest"], &input.list)
        }
        "storage-summary" => ASSETS.read(&["storage", "summary"], &input.list),
        "withheld" => ASSETS.read(&["withheld"], &input.list),
        "promote-visibility" => {
            let [asset_type, name, version] = asset_version_ref(input, verb)?;
            let spec = ASSETS.action(
                &[asset_type, name, version, "visibility"],
                Some(input.require_body(verb)?),
            )?;
            Ok(input.list.apply_filters(spec))
        }
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
                VerbDescriptor::mutating(
                    "upload-intent",
                    "Request a presigned upload target",
                    "createAssetUploadIntent",
                ),
                VerbDescriptor::mutating(
                    "commit",
                    "Commit a completed presigned upload",
                    "commitAssetUpload",
                ),
                VerbDescriptor::mutating(
                    "abort",
                    "Release a presigned upload intent that will not be committed",
                    "abortAssetUpload",
                ),
                // The presigned URL IS this verb's product. It is still named
                // in ASSET_TRANSFER_SECRET_FIELDS so it stays redacted out of
                // *diagnostics* (error details, other verbs' echoes) — only
                // this operation's own success body renders it.
                VerbDescriptor::read(
                    "download-url",
                    "Request a presigned download URL",
                    "getAssetDownloadUrl",
                )
                .issuing_credential(),
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
        // #368: releasing an intent needs the same upload_id/size/sha256 body
        // the commit needs -- the staging key is derived from all three, so the
        // body is required, never optional.
        "abort" => ASSET_PRESIGN.action(
            &["abort", asset_type, name, version],
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
                VerbDescriptor::read("list", "List an asset's channels", "listAssetChannels"),
                VerbDescriptor::mutating("set", "Point a channel at a version", "putAssetChannel")
                    .with_positional_query_segments(1),
                VerbDescriptor::mutating("delete", "Delete a channel", "deleteAssetChannel"),
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

/// Static-site custom-domain lifecycle: list/get/bind/verify/unbind.
pub struct SiteDomainsGroup;

impl CommandGroup for SiteDomainsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "site-domains",
            "Manage static-site custom domain bindings",
            vec![
                VerbDescriptor::read("list", "List bound site domains", "listSiteDomains"),
                VerbDescriptor::read("get", "Show a site domain binding", "getSiteDomain"),
                VerbDescriptor::mutating(
                    "bind",
                    "Bind a custom domain to a site",
                    "bindSiteDomain",
                ),
                VerbDescriptor::mutating(
                    "verify",
                    "Verify DNS ownership of a bound custom domain",
                    "verifySiteDomain",
                ),
                VerbDescriptor::mutating("unbind", "Unbind a custom domain", "unbindSiteDomain"),
            ],
        )
    }
}

/// Build the request for a `site-domains` verb. `bind` posts a binding document
/// to the collection; `get`/`unbind` address one hostname; `verify` posts the
/// `#488` DNS-ownership challenge redemption for one hostname; `list` reads the
/// collection (a `tenant` filter is supplied via list params).
pub fn build_site_domains(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "list" => SITE_DOMAINS.read(&[], &input.list),
        "get" => SITE_DOMAINS.read(&[first_segment(input, "site-domain")?], &input.list),
        "bind" => SITE_DOMAINS.create(input.require_body(verb)?),
        // `verifySiteDomain` declares a `tenant` query parameter: which tenant's
        // binding is being redeemed. Dropping it redeems against the server's
        // default resolution instead of the one the operator named.
        "verify" => {
            let spec = SITE_DOMAINS.action(
                &[first_segment(input, "site-domain")?, "verify"],
                input.body.clone(),
            )?;
            Ok(input.list.apply_filters(spec))
        }
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
