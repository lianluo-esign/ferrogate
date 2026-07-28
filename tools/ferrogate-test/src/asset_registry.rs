// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Docker-free E2E coverage for the #344 static-resource REGISTRY
// lifecycle surface the admin console drives (gate-owned harness growth).

//! End-to-end proof, over a REAL gateway process, of the #344 acceptance boxes
//! that had no runnable harness scenario. `asset-presign-api` covers the #368
//! presign CONTRACT (intent headers, bucket refusals, rejection classes); it
//! does NOT touch the registry the console browses. This does:
//!
//! * **Every supported asset type is a first-class registry row** — the five
//!   the console's picker enumerates plus a custom family, each addressable by
//!   the `(asset_type, name)` pair the console's `?rtype=&rname=` link uses,
//!   with no route path or raw asset id required.
//! * **The manifest is the source of truth for the detail panel** — versions,
//!   variants, yank state, channels, hashes, sizes and storage mode are
//!   compared FIELD BY FIELD against what `GET /v1/assets` reports for the same
//!   rows, so a console that renders the manifest cannot be rendering a
//!   fixture that disagrees with the registry.
//! * **Every lifecycle mutation lands its own audit record** — promote,
//!   rollback, yank, unyank, channel delete, permanent delete and a REJECTED
//!   permanent delete are asserted as distinct `action`/`outcome` pairs whose
//!   details name the specific transition, not one generic "asset changed".
//! * **A failure never appears as published** — an inline push refused at the
//!   byte ceiling leaves NO registry row and does NOT move the quota.
//! * **A withheld publish is not a clean publish** — a threshold-deferred push
//!   answers exactly 202 with `pending_scan`, stays absent from GET/list, while
//!   a clean positive control answers exactly 200 and remains downloadable.
//! * **Permanent delete is not yank** — a yank keeps the row, the bytes and the
//!   quota and is reversible; a delete removes all three. A delete blocked by a
//!   live channel answers 409 `asset_version_referenced` naming the remedy,
//!   never a generic error.
//! * **Quota is authoritative over the WHOLE registry** — with a registry far
//!   larger than any page, `used_bytes` equals the sum over every row and
//!   exceeds every proper prefix sum, so it cannot have been computed from a
//!   first page; and it tracks a delete by exactly the deleted size.
//!
//! No load, stress or sustained-throughput traffic: a few dozen small local
//! requests, no Supabase, no Docker.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, http_request_addr_bytes, HttpResponse},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ADMIN_AUTH: &str = "Authorization: Bearer registry-e2e-admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer registry-e2e-client-secret";
const TENANT: &str = "org_registry_e2e";
/// Big enough that a 40-row registry fits, small enough that the ceiling and
/// the headroom arithmetic are both checkable in one run.
const QUOTA_BYTES: u64 = 1_000_000;
/// The per-object ceiling. Deliberately small so a refused push is one request.
const MAX_OBJECT_BYTES: u64 = 4096;

/// Exactly the families `admin-console/src/pages/assets.tsx` `ASSET_TYPES`
/// enumerates. If the gateway ever stopped serving one of these as an ordinary
/// registry row the console's picker would be advertising a dead option.
const SUPPORTED_TYPES: &[&str] = &[
    "cli_tool",
    "mcp_manifest",
    "skill_bundle",
    "static_site",
    "config_file",
];
/// A family the console has no catalog label for. It must still be listed and
/// manageable (the page renders the raw identifier); dropping it would be a
/// silent exclusion.
const CUSTOM_TYPE: &str = "tenant_custom_family";

pub(crate) fn run_asset_registry_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    {
        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("asset-registry.yaml");
        fs::write(&config_path, scenario_config(&gateway_addr))?;
        let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

        provision_registry(&gateway_addr)?;
        verify_every_type_is_a_registry_row(&gateway_addr)?;
        verify_manifest_agrees_with_the_registry(&gateway_addr)?;
        verify_a_refused_push_is_never_published(&gateway_addr)?;
        verify_yank_is_not_delete(&gateway_addr)?;
        verify_quota_is_authoritative_over_the_whole_registry(&gateway_addr)?;
        verify_every_mutation_has_its_own_audit_record(&gateway_addr)?;
    }

    verify_withheld_push_is_distinct_on_the_wire(&args.ferrogate_bin)?;

    println!("asset-registry-api scenario passed");
    Ok(())
}

fn provision_registry(addr: &str) -> Result<()> {
    expect_created(
        http_request_addr(
            addr,
            "POST",
            "/admin/v1/plans",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"registry-e2e-plan","name":"Registry E2E plan","slug":"registry-e2e-plan","asset_hosting_enabled":true,"default_asset_storage_quota_bytes":{QUOTA_BYTES},"default_asset_max_object_bytes":{MAX_OBJECT_BYTES}}}"#
            ),
        )?,
        "create hosting plan",
    )?;
    expect_created(
        http_request_addr(
            addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"{TENANT}","name":"Registry E2E","slug":"registry-e2e","plan_id":"registry-e2e-plan"}}"#
            ),
        )?,
        "create hosting tenant",
    )
}

/// The real endpoint contract for #528. A two-byte payload is forced above the
/// async-scan threshold while a one-byte positive control still scans inline.
/// The exact status assertions make changing either publish terminal to the
/// other's status observable instead of merely accepting any successful 2xx.
fn verify_withheld_push_is_distinct_on_the_wire(binary: &Path) -> Result<()> {
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("asset-registry-withheld.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway =
        GatewayGuard::start_with_async_scan_threshold(binary, &config_path, &gateway_addr, 1)?;
    provision_registry(&gateway_addr)?;

    let withheld_path = "/v1/assets/cli_tool/withheld-wire-probe/1.0.0";
    let withheld = http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        withheld_path,
        &[CLIENT_AUTH, "Content-Type: application/octet-stream"],
        b"xx",
    )?;
    check(
        withheld.status == 202,
        &format!(
            "a pending_scan push must answer exactly 202 Accepted, got {}",
            withheld.raw
        ),
    )?;
    let withheld_body = json(&withheld)?;
    check(
        withheld_body["asset"]["visibility"] == "pending_scan",
        &format!(
            "the 202 body must report asset.visibility=pending_scan: {}",
            withheld.body
        ),
    )?;

    let withheld_get = get(&gateway_addr, withheld_path)?;
    check(
        withheld_get.status == 404,
        &format!(
            "a pending_scan asset must be withheld from immediate GET-by-id, got {}",
            withheld_get.raw
        ),
    )?;
    let rows_before_control = list(&gateway_addr)?;
    check(
        !rows_before_control
            .iter()
            .any(|row| row["name"] == "withheld-wire-probe"),
        "a pending_scan asset must be absent from the normal registry list",
    )?;

    let visible_path = "/v1/assets/cli_tool/visible-wire-control/1.0.0";
    let visible = http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        visible_path,
        &[CLIENT_AUTH, "Content-Type: application/octet-stream"],
        b"v",
    )?;
    check(
        visible.status == 200,
        &format!(
            "a clean inline push must answer exactly 200 OK, got {}",
            visible.raw
        ),
    )?;
    let visible_body = json(&visible)?;
    check(
        visible_body["asset"]["visibility"] == "visible",
        &format!(
            "the 200 positive control must report asset.visibility=visible: {}",
            visible.body
        ),
    )?;

    let rows = list(&gateway_addr)?;
    check(
        rows.iter()
            .any(|row| row["name"] == "visible-wire-control" && row["visibility"] == "visible"),
        "the clean positive control must appear as visible in the normal registry list",
    )?;
    check(
        !rows.iter().any(|row| row["name"] == "withheld-wire-probe"),
        "the clean control must not make the pending_scan row appear in the normal list",
    )?;

    let visible_get = get(&gateway_addr, visible_path)?;
    check(
        visible_get.status == 200 && visible_get.body == "v",
        &format!(
            "the clean positive control must remain downloadable with its exact bytes, got {}",
            visible_get.raw
        ),
    )
}

// ---------------------------------------------------------------------------
// Box 1: all supported asset types searchable/manageable without raw ids.
// ---------------------------------------------------------------------------

fn verify_every_type_is_a_registry_row(addr: &str) -> Result<()> {
    for asset_type in SUPPORTED_TYPES.iter().chain([&CUSTOM_TYPE]) {
        let (content_type, body) = family_payload(asset_type);
        push_typed(
            addr,
            asset_type,
            "catalog-probe",
            "1.0.0",
            "",
            content_type,
            &body,
        )?;
    }
    let rows = list(addr)?;
    for asset_type in SUPPORTED_TYPES.iter().chain([&CUSTOM_TYPE]) {
        let row = rows
            .iter()
            .find(|row| row["asset_type"] == **asset_type && row["name"] == "catalog-probe")
            .with_context(|| format!("{asset_type} never appears in GET /v1/assets"))?;
        // The console browses by the (asset_type, name) pair and never by id.
        // Both must be present and non-empty for the row to be reachable
        // without the operator typing a route path or a raw asset id.
        check(
            row["asset_type"].as_str().is_some_and(|v| !v.is_empty())
                && row["name"].as_str().is_some_and(|v| !v.is_empty()),
            &format!("{asset_type} row is not addressable by (asset_type, name)"),
        )?;
        // ...and the same pair must resolve the manifest the detail panel opens.
        let manifest = json(&get(
            addr,
            &format!("/v1/assets/{asset_type}/catalog-probe/manifest"),
        )?)?;
        check(
            manifest["asset_type"] == **asset_type && manifest["name"] == "catalog-probe",
            &format!("{asset_type} manifest is not reachable from the browse pair"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Box 2: the detail view's fields come from the typed manifest and agree with
// the registry, field by field.
// ---------------------------------------------------------------------------

fn verify_manifest_agrees_with_the_registry(addr: &str) -> Result<()> {
    push(
        addr,
        "cli_tool",
        "harness-tool",
        "1.0.0",
        "",
        b"v1-default\n",
    )?;
    push(
        addr,
        "cli_tool",
        "harness-tool",
        "1.0.0",
        "linux-arm64",
        b"v1-arm64-payload\n",
    )?;
    push(
        addr,
        "cli_tool",
        "harness-tool",
        "2.0.0",
        "",
        b"v2-default\n",
    )?;
    set_channel(addr, "cli_tool", "harness-tool", "stable", "1.0.0")?;

    let manifest = json(&get(addr, "/v1/assets/cli_tool/harness-tool/manifest")?)?;
    let versions = manifest["versions"]
        .as_array()
        .context("manifest must carry a versions array")?;
    check(
        versions.len() == 2,
        "the manifest must carry every logical version of the resource",
    )?;
    let channels = manifest["channels"]
        .as_array()
        .context("manifest must carry a channels array")?;
    check(
        channels.len() == 1
            && channels[0]["channel"] == "stable"
            && channels[0]["version"] == "1.0.0",
        "the manifest must carry the live channel pointer the detail panel renders",
    )?;

    let rows = list(addr)?;
    let mut compared = 0;
    for version in versions {
        let version_id = version["version"].as_str().unwrap_or_default();
        check(
            version["yanked"].is_boolean(),
            "every manifest version must carry an explicit yank state",
        )?;
        for variant in version["variants"]
            .as_array()
            .context("every manifest version must carry a variants array")?
        {
            let variant_id = variant["variant"].as_str().unwrap_or_default();
            // The registry row for the SAME (version, variant). The console's
            // detail panel renders the manifest; if the two ever disagreed the
            // panel would be describing bytes the registry does not hold.
            let row = rows
                .iter()
                .find(|row| {
                    row["asset_type"] == "cli_tool"
                        && row["name"] == "harness-tool"
                        && row["version"] == version_id
                        && row["id"]
                            .as_str()
                            .is_some_and(|id| id == expected_row_id(version_id, variant_id))
                })
                .with_context(|| {
                    format!("no registry row for harness-tool {version_id} [{variant_id}]")
                })?;
            for field in [
                "content_hash",
                "size_bytes",
                "content_type",
                "storage_backed",
            ] {
                check(
                    variant[field] == row[field],
                    &format!(
                        "manifest {field} for {version_id} [{variant_id}] is {} but the registry says {}",
                        variant[field], row[field]
                    ),
                )?;
            }
            check(
                variant["content_hash"]
                    .as_str()
                    .is_some_and(|hash| hash.len() == 64),
                "the manifest must carry a full content hash, not a placeholder",
            )?;
            compared += 1;
        }
    }
    check(
        compared == 3,
        &format!("expected 3 (version, variant) rows to compare, compared {compared}"),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Box 4 (registry half): a refused upload never appears as published.
// ---------------------------------------------------------------------------

fn verify_a_refused_push_is_never_published(addr: &str) -> Result<()> {
    let before = json(&get(addr, "/v1/assets/storage/summary")?)?;
    let used_before = before["used_bytes"].as_u64().context("used_bytes")?;

    let oversized = vec![b'x'; (MAX_OBJECT_BYTES + 1) as usize];
    let refused = http_request_addr_bytes(
        addr,
        "PUT",
        "/v1/assets/cli_tool/never-published/9.9.9",
        &[CLIENT_AUTH, "Content-Type: application/octet-stream"],
        &oversized,
    )?;
    check(
        refused.status == 413,
        &format!(
            "an over-ceiling inline push must be refused, got {}",
            refused.raw
        ),
    )?;

    let rows = list(addr)?;
    check(
        !rows.iter().any(|row| row["name"] == "never-published"),
        "a refused push must leave NO registry row -- a console that listed it would be \
         reporting a publish that never happened",
    )?;
    let missing = get(addr, "/v1/assets/cli_tool/never-published/manifest")?;
    check(
        missing.status == 404,
        &format!(
            "a refused push must leave no manifest, got {}",
            missing.status
        ),
    )?;
    let after = json(&get(addr, "/v1/assets/storage/summary")?)?;
    check(
        after["used_bytes"].as_u64() == Some(used_before),
        "a refused push must not move the authoritative quota",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Boxes 3 + 5: promote / rollback / yank / unyank, and permanent delete kept
// distinct from yank, with the blocker named rather than a generic error.
// ---------------------------------------------------------------------------

fn verify_yank_is_not_delete(addr: &str) -> Result<()> {
    // `stable` currently points at 1.0.0 (set above). Promote it to 2.0.0 and
    // then roll it back: two moves whose audit details must differ.
    set_channel(addr, "cli_tool", "harness-tool", "stable", "2.0.0")?;
    set_channel(addr, "cli_tool", "harness-tool", "stable", "1.0.0")?;
    let manifest = json(&get(addr, "/v1/assets/cli_tool/harness-tool/manifest")?)?;
    check(
        manifest["channels"][0]["version"] == "1.0.0",
        "a rollback must re-point the channel at the earlier version",
    )?;

    // A yank blocked by a live channel names the remedy.
    let blocked_yank = http_request_addr(
        addr,
        "POST",
        "/v1/assets/cli_tool/harness-tool/1.0.0/yank",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        blocked_yank.status == 409 && blocked_yank.body.contains("asset_version_referenced"),
        &format!(
            "a channel-referenced yank must be refused by code, got {}",
            blocked_yank.raw
        ),
    )?;

    // 2.0.0 is unreferenced, so it yanks. A YANK KEEPS THE BYTES.
    let used_before_yank = used_bytes(addr)?;
    let yank = http_request_addr(
        addr,
        "POST",
        "/v1/assets/cli_tool/harness-tool/2.0.0/yank",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        yank.status == 200,
        &format!("an unreferenced version must yank, got {}", yank.raw),
    )?;
    let manifest = json(&get(addr, "/v1/assets/cli_tool/harness-tool/manifest")?)?;
    let yanked = manifest["versions"]
        .as_array()
        .context("versions")?
        .iter()
        .find(|version| version["version"] == "2.0.0")
        .context("a yanked version must still appear in the manifest")?;
    check(
        yanked["yanked"] == Value::Bool(true),
        "a yanked version must be RETAINED and flagged, not removed",
    )?;
    check(
        used_bytes(addr)? == used_before_yank,
        "a yank must not release stored bytes -- that is what makes it reversible",
    )?;

    // ...and it reverses.
    let unyank = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/harness-tool/2.0.0/yank",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        unyank.status == 200,
        &format!("a yank must be reversible, got {}", unyank.raw),
    )?;
    let manifest = json(&get(addr, "/v1/assets/cli_tool/harness-tool/manifest")?)?;
    check(
        manifest["versions"]
            .as_array()
            .context("versions")?
            .iter()
            .any(|version| {
                version["version"] == "2.0.0" && version["yanked"] == Value::Bool(false)
            }),
        "an unyank must clear the flag on the same retained version",
    )?;

    // A permanent delete blocked by a live channel reports the BLOCKER, with
    // the remedy, not a generic failure. 1.0.0's default variant is the last
    // resolvable variant of the `stable`-referenced version once the
    // platform-specific one is gone -- exactly the order the console purges in.
    let arm64 = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/harness-tool/1.0.0?platform=linux-arm64",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        arm64.status == 200,
        &format!(
            "a non-last variant of a referenced version must delete, got {}",
            arm64.raw
        ),
    )?;
    let blocked = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/harness-tool/1.0.0",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        blocked.status == 409,
        &format!(
            "the last resolvable variant of a referenced version must be blocked, got {}",
            blocked.raw
        ),
    )?;
    check(
        blocked.body.contains("asset_version_referenced")
            && blocked.body.contains("move or delete the channel first"),
        &format!(
            "a blocked delete must name the blocker and the remedy, not a generic error: {}",
            blocked.body
        ),
    )?;

    // Clear the blocker, then the delete succeeds and RELEASES the bytes --
    // the property that makes it categorically different from a yank.
    let channel_delete = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/harness-tool/channels/stable",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        channel_delete.status == 200,
        &format!(
            "the channel pointer must be deletable, got {}",
            channel_delete.raw
        ),
    )?;
    let target_size = registry_row_size(addr, "cli_tool", "harness-tool", "1.0.0")?;
    let used_before_delete = used_bytes(addr)?;
    let purge = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/harness-tool/1.0.0",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        purge.status == 200,
        &format!(
            "an unblocked permanent delete must succeed, got {}",
            purge.raw
        ),
    )?;
    let manifest = json(&get(addr, "/v1/assets/cli_tool/harness-tool/manifest")?)?;
    check(
        !manifest["versions"]
            .as_array()
            .context("versions")?
            .iter()
            .any(|version| version["version"] == "1.0.0"),
        "a permanently deleted version must be GONE, not flagged -- otherwise delete and \
         yank are the same operation wearing two labels",
    )?;
    check(
        used_bytes(addr)? == used_before_delete - target_size,
        "a permanent delete must release exactly the deleted bytes",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Box 6: quota is authoritative over the whole registry, not a page of it.
// ---------------------------------------------------------------------------

fn verify_quota_is_authoritative_over_the_whole_registry(addr: &str) -> Result<()> {
    // A registry far larger than any plausible page, with DISTINCT ascending
    // sizes so no proper prefix of the rows can coincidentally sum to the
    // whole -- which is what makes "computed from the first page only"
    // detectable rather than merely unlikely.
    for index in 0..40u64 {
        let payload = vec![b'q'; (64 + index * 7) as usize];
        push(
            addr,
            "cli_tool",
            &format!("quota-probe-{index:02}"),
            "1.0.0",
            "",
            &payload,
        )?;
    }

    let rows = list(addr)?;
    check(
        rows.len() > 40,
        &format!(
            "the quota registry must exceed one page, has {} rows",
            rows.len()
        ),
    )?;
    let mut sizes: Vec<u64> = rows
        .iter()
        .map(|row| row["size_bytes"].as_u64().unwrap_or_default())
        .collect();
    let total: u64 = sizes.iter().sum();

    let summary = json(&get(addr, "/v1/assets/storage/summary")?)?;
    let used = summary["used_bytes"].as_u64().context("used_bytes")?;
    check(
        used == total,
        &format!("used_bytes {used} must equal the sum over EVERY registry row {total}"),
    )?;

    // Any first-page computation is a PROPER prefix of the rows. Sorting
    // descending makes the largest prefix sum of every length maximal, so if
    // `used` still exceeds all of them it cannot be a prefix of any ordering.
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let mut prefix = 0u64;
    for size in sizes.iter().take(sizes.len() - 1) {
        prefix += size;
        check(
            used > prefix,
            &format!(
                "used_bytes {used} coincides with a proper prefix sum {prefix}; a \
                      first-page computation would be indistinguishable"
            ),
        )?;
    }

    check(
        summary["quota_bytes"].as_u64() == Some(QUOTA_BYTES),
        "the summary must report the plan's cumulative quota",
    )?;
    check(
        summary["remaining_bytes"].as_u64() == Some(QUOTA_BYTES - used),
        "remaining_bytes must be the gateway's own quota-minus-usage, not a client subtraction",
    )?;

    // ...and it tracks a mutation by exactly the mutated size.
    let victim = registry_row_size(addr, "cli_tool", "quota-probe-00", "1.0.0")?;
    let deleted = http_request_addr(
        addr,
        "DELETE",
        "/v1/assets/cli_tool/quota-probe-00/1.0.0",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        deleted.status == 200,
        &format!("the quota probe must delete, got {}", deleted.raw),
    )?;
    let after = json(&get(addr, "/v1/assets/storage/summary")?)?;
    check(
        after["used_bytes"].as_u64() == Some(used - victim)
            && after["remaining_bytes"].as_u64() == Some(QUOTA_BYTES - (used - victim)),
        "the authoritative quota must track a delete by exactly the deleted size",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Box 3: every lifecycle mutation lands its OWN audit record.
// ---------------------------------------------------------------------------

fn verify_every_mutation_has_its_own_audit_record(addr: &str) -> Result<()> {
    let events = json(&http_request_addr(
        addr,
        "GET",
        "/admin/v1/audit-events?limit=500",
        &[ADMIN_AUTH],
        "",
    )?)?;
    let events = events["data"]
        .as_array()
        .context("audit-events must return a data array")?
        .clone();

    // Each mutation the console can fire is its own action/outcome pair. A
    // single generic "asset changed" event would satisfy none of these.
    for (action, outcome) in [
        ("asset.push", "committed"),
        ("asset.channel.move", "committed"),
        ("asset.yank", "committed"),
        ("asset.unyank", "committed"),
        ("asset.yank", "rejected"),
        ("asset.channel.delete", "committed"),
        ("asset.delete", "committed"),
        ("asset.delete", "rejected"),
    ] {
        check(
            events
                .iter()
                .any(|event| event["action"] == action && event["outcome"] == outcome),
            &format!("missing distinct audit evidence for {action}/{outcome}"),
        )?;
    }
    // A yank and an unyank of the SAME version must not collapse into one
    // action -- the console offers them as opposite buttons, and an audit that
    // could not tell them apart would make the trail unusable for review.
    check(
        events
            .iter()
            .any(|event| event["action"] == "asset.yank" && event["outcome"] == "committed")
            && events
                .iter()
                .any(|event| event["action"] == "asset.unyank" && event["outcome"] == "committed"),
        "yank and unyank must be separately auditable actions",
    )?;

    // Promote and rollback are both `asset.channel.move`, so the DETAIL is what
    // distinguishes them. Both transitions must be individually recoverable.
    let moves: Vec<&str> = events
        .iter()
        .filter(|event| event["action"] == "asset.channel.move")
        .filter_map(|event| event["message"].as_str())
        .collect();
    check(
        moves.iter().any(|detail| detail.contains("1.0.0 -> 2.0.0")),
        &format!("the promote transition is not recoverable from the audit trail: {moves:?}"),
    )?;
    check(
        moves.iter().any(|detail| detail.contains("2.0.0 -> 1.0.0")),
        &format!("the rollback transition is not recoverable from the audit trail: {moves:?}"),
    )?;

    // The rejected mutations are audited as rejections, never as commits of a
    // change that did not happen.
    let rejected_delete = events
        .iter()
        .find(|event| event["action"] == "asset.delete" && event["outcome"] == "rejected")
        .context("the blocked permanent delete must be audited")?;
    check(
        rejected_delete["message"]
            .as_str()
            .is_some_and(|message| message.contains("channel-referenced")),
        "a rejected delete's audit message must name the blocker",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// The gateway enforces a per-family `Content-Type` allowlist
/// (`gateway/asset_security.rs::content_type_allowed`), so a probe payload has
/// to be a plausible member of its family rather than generic bytes. An unknown
/// family has no allowlist and accepts anything.
fn family_payload(asset_type: &str) -> (&'static str, Vec<u8>) {
    match asset_type {
        "mcp_manifest" => (
            "application/json",
            br#"{"transport":"http","name":"catalog-probe"}"#.to_vec(),
        ),
        "skill_bundle" => ("text/markdown", b"# catalog probe\n".to_vec()),
        "static_site" => (
            "text/html",
            b"<!doctype html><title>probe</title>\n".to_vec(),
        ),
        "config_file" => ("text/plain", b"probe = true\n".to_vec()),
        _ => ("application/octet-stream", b"catalog\n".to_vec()),
    }
}

fn push(
    addr: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    variant: &str,
    body: &[u8],
) -> Result<()> {
    push_typed(
        addr,
        asset_type,
        name,
        version,
        variant,
        "application/octet-stream",
        body,
    )
}

fn push_typed(
    addr: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    variant: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let query = if variant.is_empty() {
        String::new()
    } else {
        format!("?platform={variant}")
    };
    let response = http_request_addr_bytes(
        addr,
        "PUT",
        &format!("/v1/assets/{asset_type}/{name}/{version}{query}"),
        &[CLIENT_AUTH, &format!("Content-Type: {content_type}")],
        body,
    )?;
    check(
        response.status == 200 || response.status == 201,
        &format!(
            "push {asset_type}/{name}/{version} failed: {}",
            response.raw
        ),
    )
}

fn set_channel(
    addr: &str,
    asset_type: &str,
    name: &str,
    channel: &str,
    version: &str,
) -> Result<()> {
    let response = http_request_addr(
        addr,
        "PUT",
        &format!("/v1/assets/{asset_type}/{name}/channels/{channel}?version={version}"),
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        response.status == 200 || response.status == 201,
        &format!(
            "set channel {channel} -> {version} failed: {}",
            response.raw
        ),
    )
}

fn get(addr: &str, path: &str) -> Result<HttpResponse> {
    http_request_addr(addr, "GET", path, &[CLIENT_AUTH], "")
}

fn list(addr: &str) -> Result<Vec<Value>> {
    let body = json(&get(addr, "/v1/assets")?)?;
    Ok(body["data"]
        .as_array()
        .context("GET /v1/assets must return a data array")?
        .clone())
}

fn used_bytes(addr: &str) -> Result<u64> {
    json(&get(addr, "/v1/assets/storage/summary")?)?["used_bytes"]
        .as_u64()
        .context("storage summary must report used_bytes")
}

fn registry_row_size(addr: &str, asset_type: &str, name: &str, version: &str) -> Result<u64> {
    list(addr)?
        .iter()
        .find(|row| {
            row["asset_type"] == asset_type && row["name"] == name && row["version"] == version
        })
        .and_then(|row| row["size_bytes"].as_u64())
        .with_context(|| format!("no registry row for {asset_type}/{name}/{version}"))
}

/// The registry id for a `harness-tool` (version, variant) row, mirroring
/// `ferrogate_storage::stored_asset_variant_id`. Matching on a suffix would let
/// the DEFAULT variant (empty suffix) match every row, which is exactly how a
/// field-by-field comparison silently becomes vacuous.
fn expected_row_id(version: &str, variant: &str) -> String {
    if variant.is_empty() {
        format!("{TENANT}:cli_tool:harness-tool:{version}")
    } else {
        format!("{TENANT}:cli_tool:harness-tool:{version}:v:{variant}")
    }
}

fn json(response: &HttpResponse) -> Result<Value> {
    serde_json::from_str(&response.body)
        .with_context(|| format!("response body was not JSON: {}", response.raw))
}

fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!("{message}")
    }
}

fn expect_created(response: HttpResponse, what: &str) -> Result<()> {
    check(
        response.status == 200 || response.status == 201,
        &format!("{what} failed: {}", response.raw),
    )
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
api_keys:
  - id: "registry-e2e-admin"
    name: "Registry E2E operator"
    key: "registry-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
    # #540: platform root is stated, never inherited from an omitted field.
    platform_operator: true
  - id: "registry-e2e-client"
    name: "Registry E2E tenant client"
    key: "registry-e2e-client-secret"
    scopes: ["assets.read", "assets.write"]
    organization_id: {TENANT:?}
    project_id: "project_registry_e2e"
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        Self::start_process(binary, config_path, gateway_addr, None)
    }

    fn start_with_async_scan_threshold(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        threshold_bytes: usize,
    ) -> Result<Self> {
        Self::start_process(binary, config_path, gateway_addr, Some(threshold_bytes))
    }

    fn start_process(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        async_scan_threshold_bytes: Option<usize>,
    ) -> Result<Self> {
        let mut command = Command::new(binary);
        command.env_remove("FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES");
        if let Some(threshold_bytes) = async_scan_threshold_bytes {
            command.env(
                "FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES",
                threshold_bytes.to_string(),
            );
        }
        let child = command
            .args(["run", "--config"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before asset-registry E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the asset-registry E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
