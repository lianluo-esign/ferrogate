// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the /v1/assets/* handler's pure helpers
// (#260): query-param parsing and the self-serve manifest builder (version +
// variant grouping, yank flag, newest-first ordering).

use super::*;

fn asset(version: &str, variant: &str, yanked: bool, hash: &str) -> StoredAsset {
    StoredAsset {
        id: format!("t:cli_tool:rg:{version}:{variant}"),
        tenant_id: "t".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: hash.into(),
        size_bytes: 7,
        content: vec![0],
        storage_uri: None,
        variant: variant.into(),
        yanked,
        visibility: Default::default(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn asset_with_visibility(
    version: &str,
    visibility: ferrogate_storage::AssetVisibility,
) -> StoredAsset {
    let mut asset = asset(version, "", false, "hash");
    asset.visibility = visibility;
    asset
}

/// #366 / #188 write-path == read-path: the read path filters withheld rows
/// (`is_downloadable`) BEFORE resolution, exactly as `handle_asset_pull` does,
/// so a pending/quarantined version is absent from exact, channel, and range
/// resolution alike and can never be selected for download.
#[test]
fn pending_and_quarantined_versions_are_withheld_from_every_resolution() {
    use ferrogate_storage::AssetVisibility;

    let assets = vec![
        asset_with_visibility("1.0.0", AssetVisibility::Visible),
        asset_with_visibility("1.1.0", AssetVisibility::Quarantined),
        asset_with_visibility("1.2.0", AssetVisibility::PendingScan),
    ];
    // The read path's withholding filter (the exact expression handle_asset_pull
    // and handle_asset_manifest apply).
    let downloadable: Vec<StoredAsset> = assets
        .into_iter()
        .filter(StoredAsset::is_downloadable)
        .collect();
    assert_eq!(downloadable.len(), 1, "only the Visible version survives");

    // Exact pull of a quarantined/pending version is withheld (404), even though
    // an exact pull of a *yanked* version would still resolve.
    assert!(resolve_version(&downloadable, &[], "1.1.0").is_none());
    assert!(resolve_version(&downloadable, &[], "1.2.0").is_none());

    // latest / range never fall through to a withheld newer version.
    let latest = resolve_version(&downloadable, &[], "latest").expect("latest resolves to visible");
    assert_eq!(latest.version, "1.0.0");
    let range = resolve_version(&downloadable, &[], "^1.0").expect("range resolves to visible");
    assert_eq!(range.version, "1.0.0");

    // The one clean version still resolves exactly.
    let exact = resolve_version(&downloadable, &[], "1.0.0").expect("clean exact resolves");
    assert_eq!(exact.version, "1.0.0");
}

#[test]
fn query_param_extracts_present_nonempty_values() {
    assert_eq!(
        query_param(Some("platform=linux-x86_64"), "platform").as_deref(),
        Some("linux-x86_64")
    );
    assert_eq!(
        query_param(Some("channel=stable&platform=darwin-arm64"), "platform").as_deref(),
        Some("darwin-arm64")
    );
    assert_eq!(query_param(Some("platform="), "platform"), None);
    assert_eq!(query_param(Some("other=x"), "platform"), None);
    assert_eq!(query_param(None, "platform"), None);
}

#[test]
fn variant_suffix_only_renders_for_non_default() {
    assert_eq!(variant_suffix(""), "");
    assert_eq!(variant_suffix("linux-x86_64"), " (linux-x86_64)");
}

#[test]
fn manifest_groups_variants_under_versions_newest_first() {
    let assets = vec![
        asset("1.0.0", "linux-x86_64", false, "a"),
        asset("1.0.0", "darwin-arm64", false, "b"),
        asset("1.1.0", "linux-x86_64", true, "c"),
    ];
    let channels = vec![StoredAssetChannel {
        id: "t:cli_tool:rg:latest".into(),
        tenant_id: "t".into(),
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        channel: "latest".into(),
        version: "1.0.0".into(),
        updated_at_unix: 0,
    }];

    let manifest = build_manifest("cli_tool", "rg", &assets, &channels);
    assert_eq!(manifest.asset_type, "cli_tool");
    assert_eq!(manifest.name, "rg");
    // Newest semver version first.
    assert_eq!(manifest.versions.len(), 2);
    assert_eq!(manifest.versions[0].version, "1.1.0");
    assert!(manifest.versions[0].yanked);
    assert_eq!(manifest.versions[1].version, "1.0.0");
    assert!(!manifest.versions[1].yanked);
    // 1.0.0 carries both platform variants, each with its own hash.
    assert_eq!(manifest.versions[1].variants.len(), 2);
    let mut hashes: Vec<&str> = manifest.versions[1]
        .variants
        .iter()
        .map(|variant| variant.content_hash.as_str())
        .collect();
    hashes.sort_unstable();
    assert_eq!(hashes, vec!["a", "b"]);
    assert_eq!(manifest.channels.len(), 1);
    assert_eq!(manifest.channels[0].channel, "latest");
    assert_eq!(manifest.channels[0].version, "1.0.0");
}

#[test]
fn storage_summary_uses_effective_quota_and_saturates_remaining_bytes() {
    let summary = build_asset_storage_summary(30, Some(50), None, None);
    assert_eq!(summary.object, "asset_storage_summary");
    assert_eq!(summary.used_bytes, 30);
    assert_eq!(summary.quota_bytes, Some(50));
    assert_eq!(summary.remaining_bytes, Some(20));
    assert_eq!(summary.inline_upload_max_bytes, 50);
    assert!(!summary.presigned_upload.enabled);
    assert_eq!(summary.presigned_upload.max_object_bytes, None);
    assert_eq!(summary.presigned_upload.url_ttl_seconds, None);

    let over_quota = build_asset_storage_summary(75, Some(50), None, None);
    assert_eq!(over_quota.remaining_bytes, Some(0));
}

#[test]
fn storage_summary_exposes_presign_limits_only_when_bucket_is_available() {
    let summary = build_asset_storage_summary(7, None, None, Some((5_000, 900)));
    assert_eq!(summary.quota_bytes, None);
    assert_eq!(summary.remaining_bytes, None);
    assert_eq!(summary.inline_upload_max_bytes, INLINE_ASSET_MAX_BYTES);
    assert!(summary.presigned_upload.enabled);
    assert_eq!(summary.presigned_upload.max_object_bytes, Some(5_000));
    assert_eq!(summary.presigned_upload.url_ttl_seconds, Some(900));
}

#[test]
fn storage_summary_reports_the_plan_quota_tightened_per_object_ceiling() {
    // #259: the advertised presigned per-object ceiling is plan/quota-driven.
    // A tenant whose cumulative asset-storage quota is SMALLER than the global
    // operator ceiling sees the tighter quota-derived limit, since a single
    // object can never exceed the whole tenant quota.
    let tightened = build_asset_storage_summary(0, Some(4_096), None, Some((5_000, 900)));
    assert!(tightened.presigned_upload.enabled);
    assert_eq!(tightened.presigned_upload.max_object_bytes, Some(4_096));

    // A tenant whose quota is LARGER than the global ceiling stays bounded by
    // the operator ceiling (the tighter of the two wins).
    let bounded = build_asset_storage_summary(0, Some(10_000), None, Some((5_000, 900)));
    assert_eq!(bounded.presigned_upload.max_object_bytes, Some(5_000));
}

#[test]
fn storage_summary_reports_the_dedicated_per_object_ceiling_independently() {
    // #259: a dedicated per-object ceiling tightens the advertised presigned
    // limit AND the inline cap independently of the cumulative quota -- here it
    // binds tighter than both the global ceiling and the (larger) cumulative
    // quota.
    let summary = build_asset_storage_summary(0, Some(10_000), Some(2_048), Some((5_000, 900)));
    assert_eq!(summary.presigned_upload.max_object_bytes, Some(2_048));
    assert_eq!(summary.inline_upload_max_bytes, 2_048);

    // A None per-object ceiling is a no-op: the cumulative quota / global
    // ceiling alone bound the advertised limits, exactly as before #259.
    let unbounded = build_asset_storage_summary(0, Some(4_096), None, Some((5_000, 900)));
    assert_eq!(unbounded.presigned_upload.max_object_bytes, Some(4_096));
}

#[test]
fn channel_target_requires_an_existing_non_yanked_logical_version() {
    let healthy_variants = vec![
        asset("1.0.0", "linux-x86_64", false, "a"),
        asset("1.0.0", "darwin-arm64", false, "b"),
    ];
    assert!(channel_target_is_resolvable(&healthy_variants, "1.0.0"));
    assert!(!channel_target_is_resolvable(&healthy_variants, "9.9.9"));

    let partially_yanked = vec![
        asset("1.0.0", "linux-x86_64", false, "a"),
        asset("1.0.0", "darwin-arm64", true, "b"),
    ];
    assert!(!channel_target_is_resolvable(&partially_yanked, "1.0.0"));
}

// #398: the per-file static-site addressing encodes a file path into the
// `{version}` segment of `/v1/assets/{asset_type}/{name}/{version}`. These
// tests pin the two halves of the round-trip: (1) an encoded slash survives the
// router's raw-`/` split as a SINGLE segment (so a deeply-nested path still
// matches the 3-segment `[asset_type, name, reference]` arm), and (2) the
// segment is then percent-decoded back to the slashed object key the
// publish/unpack path stored -- so a nested per-file download/unpublish resolves
// exactly as a top-level file does.

/// Mirrors the split in `handle_assets`: strip the `/v1/assets` prefix and split
/// on RAW `/`, so `%2F` (an encoded slash) is never treated as a separator.
fn asset_path_segments(path: &str) -> Vec<&str> {
    let rest = path.strip_prefix("/v1/assets").unwrap();
    rest.split('/').filter(|part| !part.is_empty()).collect()
}

#[test]
fn deeply_nested_encoded_version_stays_a_single_routing_segment() {
    // The console builds `/v1/assets/static_site/{site}/{encodeURIComponent(path)}`,
    // so a nested file path arrives with its slashes as `%2F`.
    let path = "/v1/assets/static_site/mysite/img%2Fdeep%2Fvery%2Fnested%2Flogo.png";
    let segments = asset_path_segments(path);

    // Exactly three segments: the encoded slashes did NOT split the file path
    // into extra segments, so this matches the 3-segment asset arm rather than
    // falling through to the catch-all NOT_FOUND.
    assert_eq!(
        segments,
        vec![
            "static_site",
            "mysite",
            "img%2Fdeep%2Fvery%2Fnested%2Flogo.png",
        ]
    );
}

#[test]
fn encoded_version_segment_decodes_to_the_slashed_object_key() {
    // The reference the 3-segment arm decodes before it becomes an object key.
    let reference = "img%2Fdeep%2Fvery%2Fnested%2Flogo.png";
    let decoded = percent_decode_segment(reference);
    assert_eq!(decoded, "img/deep/very/nested/logo.png");

    // Round-trip: the decoded reference reconstructs the SAME stored id the
    // publish path wrote for that nested file (legacy bare-path keying), so a
    // nested per-file GET/DELETE resolves to the intended object.
    let stored = stored_asset_id("tenant-a", "static_site", "mysite", &decoded);
    let published = stored_asset_id(
        "tenant-a",
        "static_site",
        "mysite",
        "img/deep/very/nested/logo.png",
    );
    assert_eq!(stored, published);
    // Without the decode the raw `%2F` reference would key a DIFFERENT object
    // and 404 -- proving the decode is load-bearing for nested paths.
    assert_ne!(
        stored,
        stored_asset_id("tenant-a", "static_site", "mysite", reference)
    );
}

#[test]
fn url_safe_references_pass_through_percent_decode_unchanged() {
    // Every pre-#398 reference is URL-safe (no `%`), so the decode is a no-op:
    // exact semver, a semver range, a channel name, and the reserved static-site
    // version keys all resolve byte-for-byte as before.
    for reference in [
        "1.0.0",
        "^1.2.0",
        "latest",
        "__site_manifest__",
        "__site_file__:1.0.0:index.html",
    ] {
        assert_eq!(percent_decode_segment(reference), reference);
    }
}

#[test]
fn malformed_percent_escapes_are_left_literal() {
    // A `%` not followed by two hex digits must not truncate or corrupt the
    // reference; it stays literal so resolution still sees the intended string.
    assert_eq!(percent_decode_segment("50%off"), "50%off");
    assert_eq!(percent_decode_segment("trailing%"), "trailing%");
    assert_eq!(percent_decode_segment("half%2"), "half%2");
    // A valid escape adjacent to a literal `%` still decodes only the valid one.
    assert_eq!(percent_decode_segment("a%2Fb%zz"), "a/b%zz");
}

// ---- the gateway memory bound, shared by the pull and site-serve paths ------

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn gateway_with_buffer_budget(max_gateway_buffer_bytes: u64) -> FerroGateway {
    FerroGateway {
        state: crate::state::SharedAppState::with_source_path(
            crate::config::Config {
                asset_bucket: crate::config::AssetBucketConfig {
                    max_gateway_buffer_bytes: Some(max_gateway_buffer_bytes),
                    ..crate::config::AssetBucketConfig::default()
                },
                ..crate::config::Config::default()
            },
            None,
        ),
    }
}

fn bucket_backed(size_bytes: u64) -> StoredAsset {
    let mut asset = asset("1.0.0", "", false, "hash");
    asset.size_bytes = size_bytes;
    asset.content = Vec::new();
    asset.storage_uri = Some(".ferrogate/objects/deadbeef/obj_0123456789abcdef".to_string());
    asset
}

/// Issue #259 round 2: `load_asset_content` is where the bound lives now, so
/// the static-site serve (`serve_site_file`) inherits it instead of being the
/// one read surface that kept buffering. Round 1 put the check in
/// `write_asset_body` only, and this exact call -- with this exact asset --
/// returned the whole object.
#[test]
fn the_shared_gateway_read_refuses_an_object_above_the_buffer_budget() {
    let gateway = gateway_with_buffer_budget(8 * 1024 * 1024);
    let asset = bucket_backed(100 * 1024 * 1024);

    let error = block_on(gateway.load_asset_content(&asset, "request-1"))
        .expect_err("an over-budget object must not be materialized");
    assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code, "asset_too_large_for_inline_pull");
    assert!(
        error.message.contains("104857600")
            && error.message.contains("8388608")
            && error
                .message
                .contains("/v1/assets/presign/download/cli_tool/rg/1.0.0"),
        "the refusal must name the size, the budget and the endpoint that works: {}",
        error.message
    );
}

/// The bound is a memory budget, not a new asset-size limit: at-limit is
/// inside it, and the read proceeds (failing only on the unconfigured bucket).
/// Keeps the at-limit/one-over convention identical to the presigned commit's
/// buffered/streamed split and to the per-object ceiling.
#[test]
fn an_object_exactly_at_the_buffer_budget_is_not_refused() {
    let gateway = gateway_with_buffer_budget(8 * 1024 * 1024);
    let asset = bucket_backed(8 * 1024 * 1024);

    let error = block_on(gateway.load_asset_content(&asset, "request-1"))
        .expect_err("no bucket is configured, so this cannot succeed");
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code, "asset_bucket_unavailable");
}

/// An inline-stored asset is already in memory (it came from the registry row),
/// so the bound must not touch it no matter how the budget is set.
#[test]
fn an_inline_asset_is_never_refused_by_the_bucket_memory_bound() {
    let gateway = gateway_with_buffer_budget(1);
    let mut asset = asset("1.0.0", "", false, "hash");
    asset.content = b"inline bytes".to_vec();
    asset.size_bytes = asset.content.len() as u64;

    let content = match block_on(gateway.load_asset_content(&asset, "request-1")) {
        Ok(content) => content,
        Err(error) => panic!(
            "inline content never goes near the bucket: {}",
            error.message
        ),
    };
    assert_eq!(&*content, b"inline bytes");
}
