// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for the static-site serve-mode pure logic (issue
// #258) -- path/index resolution, SPA fallback, content-type guessing, and the
// minimal zip reader (stored + deflate, path-traversal rejection, zip-bomb
// guard) -- kept out of the async gateway handler so they run without a live
// database.

use std::io::Write;
use std::sync::{Arc, Barrier};

use super::super::FerroGateway;
use super::*;
use crate::config::Config;
use crate::state::SharedAppState;
use ferrogate_storage::{
    asset_channel_id, stored_asset_id, stored_asset_variant_id, StoredAssetChannel,
    VariantDeleteOutcome,
};

fn entry(path: &str) -> SiteFileEntry {
    SiteFileEntry {
        path: path.to_string(),
        content_type: guess_site_content_type(path),
        content_hash: String::new(),
        size_bytes: 0,
    }
}

fn manifest(files: &[&str], spa_fallback: bool) -> SiteManifest {
    SiteManifest {
        site: "demo".to_string(),
        bundle_version: "1.0.0".to_string(),
        public: false,
        spa_fallback,
        cache_control: None,
        files: files.iter().map(|path| entry(path)).collect(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

/// Builds a real ZIP archive so the parser is exercised end-to-end. When
/// `deflate` is set, entries are raw-deflate compressed (method 8), otherwise
/// stored (method 0).
fn build_zip(entries: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        offsets.push(offset);
        let name_bytes = name.as_bytes();
        let (method, stored): (u16, Vec<u8>) = if deflate {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).unwrap();
            (8, encoder.finish().unwrap())
        } else {
            (0, data.to_vec())
        };

        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (not validated)
        out.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&stored);

        // Central directory header.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc32
        central.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // compressed
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End-of-central-directory record.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries this disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

#[test]
fn directory_paths_resolve_to_index_html() {
    let manifest = manifest(&["index.html", "style.css", "docs/readme.md"], false);
    // Root ("" from a trailing-slash serve path) -> index.html.
    assert_eq!(resolve_site_file(&manifest, "").unwrap().path, "index.html");
    assert_eq!(
        resolve_site_file(&manifest, "/").unwrap().path,
        "index.html"
    );
    // Exact file hits.
    assert_eq!(
        resolve_site_file(&manifest, "style.css").unwrap().path,
        "style.css"
    );
    assert_eq!(
        resolve_site_file(&manifest, "docs/readme.md").unwrap().path,
        "docs/readme.md"
    );
}

#[test]
fn subdirectory_without_trailing_slash_resolves_to_its_index() {
    let manifest = manifest(&["index.html", "docs/index.html"], false);
    assert_eq!(
        resolve_site_file(&manifest, "docs").unwrap().path,
        "docs/index.html"
    );
    assert_eq!(
        resolve_site_file(&manifest, "docs/").unwrap().path,
        "docs/index.html"
    );
}

#[test]
fn missing_file_is_none_without_spa_fallback() {
    let manifest = manifest(&["index.html"], false);
    assert!(resolve_site_file(&manifest, "app/route").is_none());
}

#[test]
fn spa_fallback_serves_root_index_for_unknown_paths() {
    let manifest = manifest(&["index.html", "style.css"], true);
    assert_eq!(
        resolve_site_file(&manifest, "app/deep/route").unwrap().path,
        "index.html"
    );
    // A real file still wins over the fallback.
    assert_eq!(
        resolve_site_file(&manifest, "style.css").unwrap().path,
        "style.css"
    );
}

#[test]
fn content_types_are_guessed_from_extension() {
    assert_eq!(
        guess_site_content_type("index.html"),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("style.css"),
        "text/css; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("docs/readme.md"),
        "text/markdown; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("app.js"),
        "application/javascript; charset=utf-8"
    );
    assert_eq!(guess_site_content_type("data.json"), "application/json");
    assert_eq!(guess_site_content_type("logo.svg"), "image/svg+xml");
    assert_eq!(guess_site_content_type("noext"), "application/octet-stream");
}

#[test]
fn is_zip_archive_detects_the_magic() {
    let zip = build_zip(&[("index.html", b"<h1>hi</h1>")], false);
    assert!(is_zip_archive(&zip));
    assert!(!is_zip_archive(b"<html>not a zip</html>"));
}

#[test]
fn unzip_stored_entries_round_trips() {
    let zip = build_zip(
        &[
            ("index.html", b"<h1>home</h1>"),
            ("style.css", b"body{color:red}"),
            ("docs/readme.md", b"# docs"),
        ],
        false,
    );
    let mut files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(files.len(), 3);
    assert_eq!(files[0], ("docs/readme.md".to_string(), b"# docs".to_vec()));
    assert_eq!(
        files[1],
        ("index.html".to_string(), b"<h1>home</h1>".to_vec())
    );
    assert_eq!(
        files[2],
        ("style.css".to_string(), b"body{color:red}".to_vec())
    );
}

#[test]
fn unzip_deflated_entries_round_trips() {
    let payload = "the quick brown fox ".repeat(64);
    let zip = build_zip(&[("index.html", payload.as_bytes())], true);
    let files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "index.html");
    assert_eq!(files[0].1, payload.as_bytes());
}

#[test]
fn unzip_skips_directory_entries() {
    let zip = build_zip(&[("docs/", b""), ("docs/readme.md", b"hi")], false);
    let files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "docs/readme.md");
}

#[test]
fn unzip_rejects_path_traversal() {
    let zip = build_zip(&[("../escape.txt", b"x")], false);
    let error = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap_err();
    assert!(error.contains("unsafe zip entry path"), "{error}");
}

#[test]
fn unzip_enforces_the_unpacked_size_cap() {
    let zip = build_zip(&[("big.txt", &vec![b'a'; 4096])], false);
    let error = unzip_archive(&zip, 1024).unwrap_err();
    assert!(error.contains("more than"), "{error}");
}

#[test]
fn unzip_rejects_non_zip_bytes() {
    let error = unzip_archive(b"not a zip at all", MAX_SITE_UNPACKED_BYTES).unwrap_err();
    assert!(error.contains("not a valid zip archive"), "{error}");
}

#[test]
fn manifest_serde_round_trips() {
    let manifest = SiteManifest {
        site: "demo".to_string(),
        bundle_version: "2.0.0".to_string(),
        public: true,
        spa_fallback: true,
        cache_control: Some("public, max-age=60".to_string()),
        files: vec![entry("index.html")],
        created_at_unix: 111,
        updated_at_unix: 222,
    };
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let parsed: SiteManifest = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.public);
    assert!(parsed.spa_fallback);
    assert_eq!(parsed.cache_control.as_deref(), Some("public, max-age=60"));
    assert_eq!(parsed.files.len(), 1);
}

#[test]
fn header_flag_parses_truthy_values() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-site-public", "true".parse().unwrap());
    assert!(header_flag(&headers, "x-site-public"));
    headers.insert("x-site-public", "1".parse().unwrap());
    assert!(header_flag(&headers, "x-site-public"));
    headers.insert("x-site-public", "false".parse().unwrap());
    assert!(!header_flag(&headers, "x-site-public"));
    assert!(!header_flag(&headers, "x-site-missing"));
}

// --- #397: retained bundles + channel-resolved serve (in-memory backend) ---
//
// These drive the real Session-free publish core (`commit_site_bundle`) and the
// real serve resolver (`resolve_active_site_bundle` + `file_asset_id`), so the
// WRITE path a publish/rollback performs is exactly the READ path the serve
// route resolves against (write == read, the #188 guard). No live database.

const T: &str = "org_demo";
const SITE: &str = "marketing";

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn gateway() -> FerroGateway {
    FerroGateway {
        state: SharedAppState::with_source_path(Config::default(), None),
    }
}

fn publish_opts() -> SiteBundlePublish {
    SiteBundlePublish {
        public: true,
        spa_fallback: false,
        cache_control: None,
        project_id: None,
    }
}

/// Publishes a bundle version through the real Session-free commit core, mapping
/// `(path, bytes)` into the `(path, content_type, content)` tuples the core takes.
fn publish(gw: &FerroGateway, version: &str, files: &[(&str, &[u8])]) -> SiteBundleCommit {
    let prepared: Vec<(String, String, Vec<u8>)> = files
        .iter()
        .map(|(path, bytes)| {
            (
                path.to_string(),
                guess_site_content_type(path),
                bytes.to_vec(),
            )
        })
        .collect();
    block_on(gw.commit_site_bundle(T, SITE, version, &prepared, &publish_opts()))
        .expect("commit_site_bundle storage error")
}

/// The bytes the serve path WOULD return for `req_path`, resolved through the
/// exact same channel/manifest/file-keying the live `serve_site_file` uses, plus
/// the bundle version the active manifest reports. `None` mirrors a serve 404.
///
/// #528: the file lookup goes through `resolve_servable_site_file`, the same
/// function the handler calls, so the withholding gate inside it is on this
/// path too. It used to inline its own `get_asset`, which would have kept every
/// assertion below green with the gate deleted.
fn served(gw: &FerroGateway, req_path: &str) -> Option<(String, Vec<u8>)> {
    let resolved = block_on(gw.resolve_active_site_bundle(T, SITE)).expect("resolve error")?;
    let entry = resolve_site_file(&resolved.manifest, req_path)?.clone();
    let asset = block_on(gw.resolve_servable_site_file(&resolved, T, SITE, &entry.path)).ok()?;
    let bytes = match block_on(gw.load_asset_content(&asset, "test-request")) {
        Ok(bytes) => bytes.into_parts().0,
        Err(error) => panic!("load content: {}", error.message),
    };
    Some((resolved.manifest.bundle_version.clone(), bytes))
}

fn serving_channel_to(version: &str) -> StoredAssetChannel {
    StoredAssetChannel {
        id: asset_channel_id(T, SITE_ASSET_TYPE, SITE, SITE_SERVE_CHANNEL),
        tenant_id: T.to_string(),
        asset_type: SITE_ASSET_TYPE.to_string(),
        name: SITE.to_string(),
        channel: SITE_SERVE_CHANNEL.to_string(),
        version: version.to_string(),
        updated_at_unix: 0,
    }
}

#[test]
fn two_bundle_versions_retain_both_and_serve_resolves_active() {
    let gw = gateway();
    publish(&gw, "1.0.0", &[("index.html", b"<h1>v1</h1>")]);
    publish(&gw, "2.0.0", &[("index.html", b"<h1>v2</h1>")]);

    // Both immutable bundle manifest rows are retained (not overwritten).
    let v1 = block_on(gw.state.current().get_asset(&stored_asset_id(
        T,
        SITE_ASSET_TYPE,
        SITE,
        "1.0.0",
    )))
    .unwrap();
    let v2 = block_on(gw.state.current().get_asset(&stored_asset_id(
        T,
        SITE_ASSET_TYPE,
        SITE,
        "2.0.0",
    )))
    .unwrap();
    assert!(v1.is_some(), "v1 bundle manifest must be retained");
    assert!(v2.is_some(), "v2 bundle manifest must be retained");

    // Both versions' file objects are retained under distinct namespaced keys.
    for version in ["1.0.0", "2.0.0"] {
        let file_id = stored_asset_id(
            T,
            SITE_ASSET_TYPE,
            SITE,
            &format!("__site_file__:{version}:index.html"),
        );
        assert!(
            block_on(gw.state.current().get_asset(&file_id))
                .unwrap()
                .is_some(),
            "file object for {version} must be retained"
        );
    }

    // The serve path resolves through the `serving` channel to the ACTIVE (latest
    // published) version.
    let (active_version, bytes) = served(&gw, "/").expect("serve index");
    assert_eq!(active_version, "2.0.0");
    assert_eq!(bytes, b"<h1>v2</h1>");
}

#[test]
fn channel_move_to_prior_version_repoints_served_bytes() {
    let gw = gateway();
    publish(&gw, "1.0.0", &[("index.html", b"<h1>v1</h1>")]);
    publish(&gw, "2.0.0", &[("index.html", b"<h1>v2</h1>")]);

    // Baseline: serving the latest.
    assert_eq!(served(&gw, "/").unwrap().1, b"<h1>v2</h1>");

    // Rollback: move the `serving` channel back to the prior retained version
    // through the SAME #367 CAS the console rollback (#345) uses.
    let outcome = block_on(
        gw.state
            .current()
            .move_asset_channel_if_resolvable(serving_channel_to("1.0.0")),
    )
    .expect("move ok");
    assert_eq!(
        outcome,
        ChannelMoveOutcome::Moved {
            prior_version: Some("2.0.0".to_string())
        }
    );

    // Write == read: the serve path now returns the PRIOR bundle's bytes.
    let (active, bytes) = served(&gw, "/").unwrap();
    assert_eq!(active, "1.0.0");
    assert_eq!(bytes, b"<h1>v1</h1>");

    // Roll forward again; serving re-points once more.
    block_on(
        gw.state
            .current()
            .move_asset_channel_if_resolvable(serving_channel_to("2.0.0")),
    )
    .expect("move ok");
    assert_eq!(served(&gw, "/").unwrap().1, b"<h1>v2</h1>");
}

#[test]
fn republishing_the_same_version_is_immutable() {
    let gw = gateway();
    publish(&gw, "1.0.0", &[("index.html", b"<h1>v1</h1>")]);
    let again = publish(&gw, "1.0.0", &[("index.html", b"<h1>tampered</h1>")]);
    assert!(
        matches!(again, SiteBundleCommit::VersionExists),
        "republishing an existing bundle version must be rejected as immutable"
    );
    // The retained bytes are untouched by the rejected republish.
    assert_eq!(served(&gw, "/").unwrap().1, b"<h1>v1</h1>");
}

#[test]
fn legacy_manifest_only_site_still_serves() {
    // Simulate a pre-#397 site: a `__site_manifest__` marker plus bare-`{path}`
    // file rows and NO `serving` channel. The serve path must fall back to the
    // manifest and legacy keying so already-served sites keep serving.
    let gw = gateway();
    let now = 100;
    let manifest = SiteManifest {
        site: SITE.to_string(),
        bundle_version: "legacy-1".to_string(),
        public: true,
        spa_fallback: false,
        cache_control: None,
        files: vec![SiteFileEntry {
            path: "index.html".to_string(),
            content_type: guess_site_content_type("index.html"),
            content_hash: sha256_hex(b"<h1>legacy</h1>"),
            size_bytes: 15,
        }],
        created_at_unix: now,
        updated_at_unix: now,
    };
    block_on(gw.store_site_manifest(T, &manifest, now)).expect("store legacy manifest");
    // Legacy per-file row keyed by the bare path.
    let file = StoredAsset {
        id: stored_asset_id(T, SITE_ASSET_TYPE, SITE, "index.html"),
        tenant_id: T.to_string(),
        project_id: None,
        asset_type: SITE_ASSET_TYPE.to_string(),
        name: SITE.to_string(),
        version: "index.html".to_string(),
        content_type: guess_site_content_type("index.html"),
        content_hash: sha256_hex(b"<h1>legacy</h1>"),
        size_bytes: 15,
        content: b"<h1>legacy</h1>".to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: AssetVisibility::Visible,
        created_at_unix: now,
        updated_at_unix: now,
    };
    block_on(gw.state.current().upsert_asset(file)).expect("store legacy file");

    // No serving channel exists -> Legacy keying resolves and serves.
    let resolved = block_on(gw.resolve_active_site_bundle(T, SITE))
        .unwrap()
        .expect("legacy site resolves");
    assert!(matches!(resolved.keying, SiteFileKeying::Legacy));
    assert_eq!(served(&gw, "/").unwrap().1, b"<h1>legacy</h1>");
}

#[test]
fn console_bare_per_file_addressing_round_trips_on_a_397_bundle() {
    // #402: the admin console addresses per-file objects by BARE path
    // (`/v1/assets/static_site/{site}/{path}`), but #397 keys each file under
    // `__site_file__:{bundle_version}:{path}`. The gateway maps the bare path
    // onto the ACTIVE bundle's prefixed key so a per-file download and unpublish
    // resolve for a #397-published bundle -- exercised here through the same
    // Session-free primitives the pull/delete handlers use (write == read, #188).
    let gw = gateway();
    let nested = "assets/img/deep/logo.png";
    let logo = b"\x89PNG nested-logo-bytes";
    publish(
        &gw,
        "2.1.0",
        &[("index.html", b"<h1>home</h1>"), (nested, logo)],
    );

    // The console decodes `%2F` back to `/` (the #398 fix) and addresses this
    // bare nested path. Under #397 the bare path is NOT a stored key, so the
    // pre-#402 console would 404 here...
    let bare_id = stored_asset_id(T, SITE_ASSET_TYPE, SITE, nested);
    assert!(
        block_on(gw.state.current().get_asset(&bare_id))
            .unwrap()
            .is_none(),
        "a #397 bundle stores no bare-path row -- the pre-#402 console 404s"
    );

    // ...but the gateway maps it onto the active bundle's prefixed key.
    let effective = block_on(gw.resolve_site_asset_version(T, SITE, nested));
    assert_eq!(effective, format!("__site_file__:2.1.0:{nested}"));

    // Download round-trip: the remapped reference resolves (exact match,
    // mirroring handle_asset_pull) and streams the intended nested file's bytes.
    let assets: Vec<StoredAsset> =
        block_on(gw.state.current().list_assets(T, Some(SITE_ASSET_TYPE)))
            .unwrap()
            .into_iter()
            .filter(|asset| asset.name == SITE && asset.is_downloadable())
            .collect();
    let channels = block_on(
        gw.state
            .current()
            .list_asset_channels(T, SITE_ASSET_TYPE, SITE),
    )
    .unwrap();
    let resolved = super::super::asset_registry::resolve_version(&assets, &channels, &effective)
        .expect("remapped per-file reference resolves for download");
    assert_eq!(resolved.version, effective);
    let downloaded = block_on(gw.state.current().get_asset(&stored_asset_id(
        T,
        SITE_ASSET_TYPE,
        SITE,
        &effective,
    )))
    .unwrap()
    .expect("downloaded object present");
    assert_eq!(
        downloaded.content, logo,
        "downloaded the intended nested file"
    );

    // Unpublish round-trip: the console DELETEs each marker-manifest file by bare
    // path; each maps onto its prefixed key and deletes. A live `serving` channel
    // references the bundle-version manifest row, not the file rows, so deleting
    // a file row is never blocked.
    let manifest = block_on(gw.load_site_manifest(T, SITE))
        .unwrap()
        .expect("marker manifest present");
    for entry in &manifest.files {
        let effective = block_on(gw.resolve_site_asset_version(T, SITE, &entry.path));
        let id = stored_asset_variant_id(T, SITE_ASSET_TYPE, SITE, &effective, "");
        let outcome = block_on(gw.state.current().delete_asset_variant_if_unreferenced(
            &id,
            T,
            SITE_ASSET_TYPE,
            SITE,
            &effective,
        ))
        .expect("delete storage ok");
        assert_eq!(
            outcome,
            VariantDeleteOutcome::Deleted,
            "per-file unpublish resolves + deletes {}",
            entry.path
        );
        assert!(
            block_on(gw.state.current().get_asset(&id))
                .unwrap()
                .is_none(),
            "per-file object {} is gone after unpublish",
            entry.path
        );
    }

    // The reserved `__site_manifest__` marker key the console deletes LAST is NOT
    // remapped -- it addresses the marker row directly, so unpublish stays intact.
    assert_eq!(
        block_on(gw.resolve_site_asset_version(T, SITE, SITE_MANIFEST_VERSION)),
        SITE_MANIFEST_VERSION
    );
}

#[test]
fn legacy_and_reserved_references_pass_through_unremapped() {
    // #402 backward-compat guard: for a LEGACY (pre-#397) site with no `serving`
    // channel, a bare per-file reference is returned UNCHANGED so the #398
    // bare-path decode path still resolves; and an already-prefixed / reserved
    // key is never double-mapped.
    let gw = gateway();
    let now = 100;
    let manifest = SiteManifest {
        site: SITE.to_string(),
        bundle_version: "legacy-1".to_string(),
        public: true,
        spa_fallback: false,
        cache_control: None,
        files: vec![SiteFileEntry {
            path: "app/main.js".to_string(),
            content_type: guess_site_content_type("app/main.js"),
            content_hash: sha256_hex(b"legacy-js"),
            size_bytes: 9,
        }],
        created_at_unix: now,
        updated_at_unix: now,
    };
    block_on(gw.store_site_manifest(T, &manifest, now)).expect("store legacy manifest");
    // Legacy per-file row keyed by the bare path (no serving channel exists).
    let file = StoredAsset {
        id: stored_asset_id(T, SITE_ASSET_TYPE, SITE, "app/main.js"),
        tenant_id: T.to_string(),
        project_id: None,
        asset_type: SITE_ASSET_TYPE.to_string(),
        name: SITE.to_string(),
        version: "app/main.js".to_string(),
        content_type: guess_site_content_type("app/main.js"),
        content_hash: sha256_hex(b"legacy-js"),
        size_bytes: 9,
        content: b"legacy-js".to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: AssetVisibility::Visible,
        created_at_unix: now,
        updated_at_unix: now,
    };
    block_on(gw.state.current().upsert_asset(file)).expect("store legacy file");

    // Legacy bare path stays bare -> the #398 decode path resolves it directly.
    assert_eq!(
        block_on(gw.resolve_site_asset_version(T, SITE, "app/main.js")),
        "app/main.js"
    );
    // Reserved marker + an already-prefixed key are returned unchanged.
    assert_eq!(
        block_on(gw.resolve_site_asset_version(T, SITE, SITE_MANIFEST_VERSION)),
        SITE_MANIFEST_VERSION
    );
    assert_eq!(
        block_on(gw.resolve_site_asset_version(T, SITE, "__site_file__:2.1.0:index.html")),
        "__site_file__:2.1.0:index.html"
    );
}

#[test]
fn concurrent_serving_channel_moves_never_strand_and_serve_reads_the_winner() {
    // Barrier-aligned race between two `serving`-channel moves to two different
    // retained bundle versions, reusing the #367 atomic move. The invariant: the
    // channel always lands on a resolvable retained version, and the serve path
    // reads exactly that version's bytes (write == read under concurrency). No
    // timing sleep -- a barrier releases both threads together.
    let gw = gateway();
    publish(&gw, "1.0.0", &[("index.html", b"<h1>v1</h1>")]);
    publish(&gw, "2.0.0", &[("index.html", b"<h1>v2</h1>")]);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for version in ["1.0.0", "2.0.0"] {
        let gw = gw.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            block_on(
                gw.state
                    .current()
                    .move_asset_channel_if_resolvable(serving_channel_to(version)),
            )
            .expect("move ok");
        }));
    }
    for handle in handles {
        handle.join().expect("thread join");
    }

    // Whichever move committed last, the serve path reads a consistent, resolvable
    // retained version -- never a stranded pointer.
    let (active, bytes) = served(&gw, "/").expect("serve after race");
    let expected: &[u8] = match active.as_str() {
        "1.0.0" => b"<h1>v1</h1>",
        "2.0.0" => b"<h1>v2</h1>",
        other => panic!("serving channel stranded on unexpected version {other}"),
    };
    assert_eq!(
        bytes, expected,
        "served bytes must match the active version"
    );
}

/// #528 (serve half): the static-site surface must refuse a file row that is
/// not `visible`, the same way the registry pull, `fetch_asset` and MCP
/// `resources/read` do.
///
/// This surface is anonymous (a public site serves without a key), browser
/// facing, and answers with the file's own content type, so an unproven object
/// reaching it is malware serving. Until #528 it had no check of its own: it
/// depended entirely on `commit_site_bundle` never writing a non-`Visible` row.
/// Here a `quarantined` row is planted under exactly the key the ACTIVE bundle's
/// manifest resolves to -- the state a broken or future writer, or a
/// hand-repaired registry, produces -- and the serve lookup must not return it.
#[test]
fn a_quarantined_site_file_is_not_served() {
    let gw = gateway();
    let commit = publish(&gw, "1.0.0", &[("index.html", b"<h1>clean</h1>")]);
    assert!(matches!(commit, SiteBundleCommit::Committed { .. }));
    assert_eq!(
        served(&gw, "/").expect("clean site serves").1,
        b"<h1>clean</h1>"
    );

    // Flip the very row the active manifest resolves to.
    let resolved = block_on(gw.resolve_active_site_bundle(T, SITE))
        .expect("resolve error")
        .expect("site resolves");
    let id = resolved.file_asset_id(T, SITE, "index.html");
    let mut row = block_on(gw.state.current().get_asset(&id))
        .expect("get_asset error")
        .expect("file row exists");
    row.visibility = AssetVisibility::Quarantined;
    block_on(gw.state.current().upsert_asset(row)).expect("store quarantined row");

    // The lookup the handler performs refuses it -- and reports it as ABSENT,
    // so the refusal does not confirm that quarantined bytes are held here.
    let refusal = block_on(gw.resolve_servable_site_file(&resolved, T, SITE, "index.html"))
        .err()
        .expect("a quarantined site file must not be servable");
    assert_eq!(refusal.status, StatusCode::NOT_FOUND);
    assert_eq!(refusal.code, "site_file_not_found");
    assert!(
        !refusal.message.contains("quarantin"),
        "the refusal must not disclose the withholding reason: {}",
        refusal.message
    );
    assert!(served(&gw, "/").is_none(), "no bytes may be served");

    // `pending_scan` is withheld on the same terms -- not yet proven clean is
    // not the same as proven safe.
    let mut row = block_on(gw.state.current().get_asset(&id))
        .expect("get_asset error")
        .expect("file row exists");
    row.visibility = AssetVisibility::PendingScan;
    block_on(gw.state.current().upsert_asset(row)).expect("store pending row");
    assert!(
        block_on(gw.resolve_servable_site_file(&resolved, T, SITE, "index.html")).is_err(),
        "a pending_scan site file must not be servable either"
    );
}
