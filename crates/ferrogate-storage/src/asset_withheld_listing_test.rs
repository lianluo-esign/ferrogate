// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the #379 operator-only WITHHELD
// asset listing. Proves `list_withheld_assets` is the exact inverse of the
// consumer `list_assets`: it returns only the `pending_scan`/`quarantined` rows
// the read path hides (#366), never a `visible` one, is tenant-scoped, honors
// the optional asset_type filter, and orders deterministically so offset/limit
// pagination is stable. In-memory always.

use crate::schema_routing_test_support::block_on;
use crate::{
    stored_asset_variant_id, AssetVisibility, RuntimeStorageRepositories, StorageProviderKind,
    StoredAsset,
};

const TENANT: &str = "tenant-withheld";
const OTHER_TENANT: &str = "tenant-other";

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

#[allow(clippy::too_many_arguments)]
fn asset(
    tenant: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    variant: &str,
    visibility: AssetVisibility,
) -> StoredAsset {
    StoredAsset {
        id: stored_asset_variant_id(tenant, asset_type, name, version, variant),
        tenant_id: tenant.into(),
        project_id: None,
        asset_type: asset_type.into(),
        name: name.into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "hash".into(),
        size_bytes: 3,
        content: vec![1, 2, 3],
        storage_uri: None,
        variant: variant.into(),
        yanked: false,
        visibility,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn lists_only_withheld_rows_and_never_visible_ones() {
    let repositories = repositories();
    // One visible, one pending, one quarantined, all same tenant/type.
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "cli_tool",
        "deploy",
        "1.0.0",
        "",
        AssetVisibility::Visible,
    )))
    .unwrap();
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "cli_tool",
        "deploy",
        "1.1.0",
        "",
        AssetVisibility::PendingScan,
    )))
    .unwrap();
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "cli_tool",
        "deploy",
        "1.2.0",
        "",
        AssetVisibility::Quarantined,
    )))
    .unwrap();

    let withheld = block_on(repositories.list_withheld_assets(TENANT, None)).unwrap();
    let versions: Vec<&str> = withheld.iter().map(|a| a.version.as_str()).collect();
    assert_eq!(
        versions,
        vec!["1.1.0", "1.2.0"],
        "only pending_scan + quarantined rows, ordered deterministically"
    );
    assert!(
        withheld.iter().all(|a| !a.is_downloadable()),
        "no visible/downloadable row may appear in the withheld listing"
    );
    // The states are surfaced intact for the operator.
    assert_eq!(withheld[0].visibility, AssetVisibility::PendingScan);
    assert_eq!(withheld[1].visibility, AssetVisibility::Quarantined);
}

#[test]
fn withheld_listing_is_tenant_scoped() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "cli_tool",
        "mine",
        "1.0.0",
        "",
        AssetVisibility::PendingScan,
    )))
    .unwrap();
    // A different tenant's withheld asset must never leak into this tenant's view.
    block_on(repositories.upsert_asset(asset(
        OTHER_TENANT,
        "cli_tool",
        "theirs",
        "1.0.0",
        "",
        AssetVisibility::Quarantined,
    )))
    .unwrap();

    let mine = block_on(repositories.list_withheld_assets(TENANT, None)).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].tenant_id, TENANT);
    assert_eq!(mine[0].name, "mine");

    let theirs = block_on(repositories.list_withheld_assets(OTHER_TENANT, None)).unwrap();
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].name, "theirs");
}

#[test]
fn withheld_listing_honors_optional_asset_type_filter() {
    let repositories = repositories();
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "cli_tool",
        "tool",
        "1.0.0",
        "",
        AssetVisibility::PendingScan,
    )))
    .unwrap();
    block_on(repositories.upsert_asset(asset(
        TENANT,
        "mcp_manifest",
        "conn",
        "1.0.0",
        "",
        AssetVisibility::Quarantined,
    )))
    .unwrap();

    let all = block_on(repositories.list_withheld_assets(TENANT, None)).unwrap();
    assert_eq!(all.len(), 2, "unfiltered view spans every asset type");

    let cli_only = block_on(repositories.list_withheld_assets(TENANT, Some("cli_tool"))).unwrap();
    assert_eq!(cli_only.len(), 1);
    assert_eq!(cli_only[0].asset_type, "cli_tool");
}

#[test]
fn withheld_listing_orders_deterministically_for_stable_pagination() {
    let repositories = repositories();
    // Insert out of order across type/name/version/variant; the listing must
    // come back in a stable (asset_type, name, version, variant) order so an
    // offset/limit page is repeatable.
    let inserts = [
        ("mcp_manifest", "beta", "2.0.0", ""),
        ("cli_tool", "alpha", "1.2.0", "linux"),
        ("cli_tool", "alpha", "1.2.0", "darwin"),
        ("cli_tool", "alpha", "1.10.0", ""),
    ];
    for (asset_type, name, version, variant) in inserts {
        block_on(repositories.upsert_asset(asset(
            TENANT,
            asset_type,
            name,
            version,
            variant,
            AssetVisibility::PendingScan,
        )))
        .unwrap();
    }

    let listing = block_on(repositories.list_withheld_assets(TENANT, None)).unwrap();
    let ordered: Vec<(String, String, String, String)> = listing
        .iter()
        .map(|a| {
            (
                a.asset_type.clone(),
                a.name.clone(),
                a.version.clone(),
                a.variant.clone(),
            )
        })
        .collect();
    assert_eq!(
        ordered,
        vec![
            (
                "cli_tool".into(),
                "alpha".into(),
                "1.10.0".into(),
                String::new()
            ),
            (
                "cli_tool".into(),
                "alpha".into(),
                "1.2.0".into(),
                "darwin".into()
            ),
            (
                "cli_tool".into(),
                "alpha".into(),
                "1.2.0".into(),
                "linux".into()
            ),
            (
                "mcp_manifest".into(),
                "beta".into(),
                "2.0.0".into(),
                String::new()
            ),
        ],
        "deterministic lexical order over (asset_type, name, version, variant)"
    );

    // A repeated call yields the identical order -- the pagination invariant.
    let again = block_on(repositories.list_withheld_assets(TENANT, None)).unwrap();
    let again_ids: Vec<String> = again.iter().map(|a| a.id.clone()).collect();
    let first_ids: Vec<String> = listing.iter().map(|a| a.id.clone()).collect();
    assert_eq!(again_ids, first_ids);
}
