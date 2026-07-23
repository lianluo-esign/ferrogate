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
    let summary = build_asset_storage_summary(30, Some(50), None);
    assert_eq!(summary.object, "asset_storage_summary");
    assert_eq!(summary.used_bytes, 30);
    assert_eq!(summary.quota_bytes, Some(50));
    assert_eq!(summary.remaining_bytes, Some(20));
    assert_eq!(summary.inline_upload_max_bytes, 50);
    assert!(!summary.presigned_upload.enabled);
    assert_eq!(summary.presigned_upload.max_object_bytes, None);
    assert_eq!(summary.presigned_upload.url_ttl_seconds, None);

    let over_quota = build_asset_storage_summary(75, Some(50), None);
    assert_eq!(over_quota.remaining_bytes, Some(0));
}

#[test]
fn storage_summary_exposes_presign_limits_only_when_bucket_is_available() {
    let summary = build_asset_storage_summary(7, None, Some((5_000, 900)));
    assert_eq!(summary.quota_bytes, None);
    assert_eq!(summary.remaining_bytes, None);
    assert_eq!(summary.inline_upload_max_bytes, INLINE_ASSET_MAX_BYTES);
    assert!(summary.presigned_upload.enabled);
    assert_eq!(summary.presigned_upload.max_object_bytes, Some(5_000));
    assert_eq!(summary.presigned_upload.url_ttl_seconds, Some(900));
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
