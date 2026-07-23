// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the pure artifact-registry resolution rules
// (#260): channel resolve (incl. yank fallback), semver-range resolve, and
// platform/arch variant selection -- exercised directly against StoredAsset /
// StoredAssetChannel slices without any Session/IO.

use super::*;
use ferrogate_storage::{StoredAsset, StoredAssetChannel};

fn asset(version: &str, variant: &str, yanked: bool) -> StoredAsset {
    StoredAsset {
        id: format!("t:cli_tool:rg:{version}:{variant}"),
        tenant_id: "t".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "hash".into(),
        size_bytes: 1,
        content: vec![0],
        storage_uri: None,
        variant: variant.into(),
        yanked,
        visibility: Default::default(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn channel(name: &str, version: &str) -> StoredAssetChannel {
    StoredAssetChannel {
        id: format!("t:cli_tool:rg:{name}"),
        tenant_id: "t".into(),
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        channel: name.into(),
        version: version.into(),
        updated_at_unix: 0,
    }
}

#[test]
fn implicit_latest_resolves_to_highest_semver() {
    let assets = vec![asset("1.0.0", "", false), asset("1.1.0", "", false)];
    let resolved = resolve_version(&assets, &[], "latest").expect("resolves");
    assert_eq!(resolved.version, "1.1.0");
    assert!(!resolved.yanked);
    assert_eq!(resolved.how, VersionResolution::Channel("latest".into()));
}

#[test]
fn yanking_the_head_falls_latest_and_ranges_back_to_the_prior_version() {
    // 1.1.0 yanked -> latest + ^1.0 both drop to 1.0.0.
    let assets = vec![asset("1.0.0", "", false), asset("1.1.0", "", true)];
    assert_eq!(
        resolve_version(&assets, &[], "latest").unwrap().version,
        "1.0.0"
    );
    assert_eq!(
        resolve_version(&assets, &[], "^1.0").unwrap().version,
        "1.0.0"
    );
}

#[test]
fn exact_pull_of_a_yanked_version_still_resolves_with_the_yanked_flag() {
    let assets = vec![asset("1.0.0", "", false), asset("1.1.0", "", true)];
    let resolved = resolve_version(&assets, &[], "1.1.0").expect("exact still resolves");
    assert_eq!(resolved.version, "1.1.0");
    assert!(resolved.yanked);
    assert_eq!(resolved.how, VersionResolution::Exact);
}

#[test]
fn explicit_channel_pointer_wins_over_the_head() {
    let assets = vec![asset("1.0.0", "", false), asset("1.1.0", "", false)];
    let channels = vec![channel("stable", "1.0.0")];
    let resolved = resolve_version(&assets, &channels, "stable").expect("resolves");
    assert_eq!(resolved.version, "1.0.0");
    assert_eq!(resolved.how, VersionResolution::Channel("stable".into()));
}

#[test]
fn channel_pointing_at_a_yanked_version_falls_back() {
    let assets = vec![asset("1.0.0", "", false), asset("1.1.0", "", true)];
    let channels = vec![channel("stable", "1.1.0")];
    let resolved = resolve_version(&assets, &channels, "stable").expect("resolves");
    assert_eq!(resolved.version, "1.0.0");
}

#[test]
fn semver_ranges_pick_the_highest_match() {
    let assets = vec![
        asset("1.0.0", "", false),
        asset("1.2.0", "", false),
        asset("2.0.0", "", false),
    ];
    assert_eq!(
        resolve_version(&assets, &[], "^1.0").unwrap().version,
        "1.2.0"
    );
    assert_eq!(
        resolve_version(&assets, &[], "~1.0").unwrap().version,
        "1.0.0"
    );
    assert_eq!(resolve_version(&assets, &[], "2").unwrap().version, "2.0.0");
}

#[test]
fn unknown_reference_does_not_resolve() {
    let assets = vec![asset("1.0.0", "", false)];
    // A free-form tag with no pointer and no semver meaning.
    assert!(resolve_version(&assets, &[], "nightly").is_none());
    // A range that matches nothing.
    assert!(resolve_version(&assets, &[], "^9").is_none());
}

#[test]
fn variant_selection_prefers_explicit_platform() {
    let linux = asset("1.0.0", "linux-x86_64", false);
    let darwin = asset("1.0.0", "darwin-arm64", false);
    let rows = vec![&linux, &darwin];
    match select_variant(&rows, Some("darwin-arm64")) {
        VariantChoice::Selected(chosen) => assert_eq!(chosen.variant, "darwin-arm64"),
        other => panic!("expected darwin-arm64, got {other:?}"),
    }
    assert_eq!(
        select_variant(&rows, Some("windows-x86_64")),
        VariantChoice::NotFound
    );
}

#[test]
fn variant_selection_without_a_default_is_ambiguous() {
    let linux = asset("1.0.0", "linux-x86_64", false);
    let darwin = asset("1.0.0", "darwin-arm64", false);
    let rows = vec![&linux, &darwin];
    assert_eq!(select_variant(&rows, None), VariantChoice::Ambiguous);

    // A lone variant with no default is served without a hint.
    let only = vec![&linux];
    match select_variant(&only, None) {
        VariantChoice::Selected(chosen) => assert_eq!(chosen.variant, "linux-x86_64"),
        other => panic!("expected the lone variant, got {other:?}"),
    }
}

#[test]
fn variant_selection_prefers_the_default_variant() {
    let default = asset("1.0.0", "", false);
    let linux = asset("1.0.0", "linux-x86_64", false);
    let rows = vec![&default, &linux];
    match select_variant(&rows, None) {
        VariantChoice::Selected(chosen) => assert!(chosen.variant.is_empty()),
        other => panic!("expected the default variant, got {other:?}"),
    }
}
