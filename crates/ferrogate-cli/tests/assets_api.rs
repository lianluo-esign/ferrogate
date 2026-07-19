// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for /v1/assets/* (issue #176/#177) --
// push/pull/list/delete through a real gateway process, with the
// stored_assets row independently verified against a real
// Postgres/Supabase-protocol database (not just the in-memory backend).
//
// Opt-in: requires FERROGATE_SUPABASE_DSN to point at a reachable
// Postgres-compatible database (local Postgres or a real Supabase
// connection-pooler DSN both work, since FerroGate's "supabase" storage
// provider is the plain Postgres wire protocol). Skips with a message when
// unset, matching the existing opt-in-live pattern used by
// `ferrogate-test supabase-live-smoke`.

mod support;

use std::io::Write;
use std::process::Command;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn assets_push_pull_list_delete_round_trip_through_real_postgres() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping assets_push_pull_list_delete_round_trip_through_real_postgres: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, assets_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // 1. Create the tenant (org_demo) via the admin API, landing on the
    // seeded "free" plan, which has asset_hosting_enabled = true and a
    // 10 MiB quota (default_free_plan(), crates/ferrogate-storage/src/lib.rs).
    //
    // Note: /admin/v1/tenant-accounts (not /admin/v1/tenants -- that's a
    // separate, GET-only legacy endpoint listing tenant refs derived from
    // API key attribution, unrelated to StoredTenantAccount) is the real
    // CRUD surface for StoredTenantAccount.
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_demo","name":"Org Demo","slug":"org-demo"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // 2. Push an asset.
    let content = "#!/bin/sh\necho hello from the closed-loop E2E test\n";
    let push = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/hello/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        content,
    ));
    assert_eq!(push["asset"]["asset_type"], "cli_tool");
    assert_eq!(push["asset"]["name"], "hello");
    assert_eq!(push["asset"]["version"], "1.0.0");
    assert_eq!(push["asset"]["size_bytes"], content.len());
    let content_hash = push["asset"]["content_hash"]
        .as_str()
        .expect("content_hash must be present")
        .to_string();

    // 3. Pull it back and confirm the bytes and Content-Type round-trip.
    let pull = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(pull.contains("HTTP/1.1 200"), "pull failed: {pull}");
    assert!(
        pull.to_lowercase().contains("content-type: text/plain"),
        "{pull}"
    );
    assert!(pull.ends_with(content), "pull body mismatch: {pull}");

    // 4. List and confirm the asset is visible.
    let list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    let listed = list["data"]
        .as_array()
        .expect("list response must have a data array");
    assert!(
        listed
            .iter()
            .any(|asset| asset["name"] == "hello" && asset["content_hash"] == content_hash),
        "pushed asset not present in list response: {list}"
    );

    // 5. Independently verify the row landed in the real database -- not
    // just the gateway's in-process view of it. Queries the exact schema
    // FerroGate itself creates (postgres_schema = ferrogate_control below),
    // bypassing the gateway process entirely.
    let db_row = psql_query(
        &dsn,
        "SELECT tenant_id, asset_type, name, version, content_hash, size_bytes, \
         encode(content, 'escape') \
         FROM ferrogate_control.stored_assets \
         WHERE tenant_id = 'org_demo' AND asset_type = 'cli_tool' AND name = 'hello'",
    );
    assert!(
        db_row.contains("org_demo")
            && db_row.contains("cli_tool")
            && db_row.contains(&content_hash)
            && db_row.contains(content.trim_end()),
        "stored_assets row not found (or content mismatch) in the real database: {db_row}"
    );

    // 6. Delete through the API, then confirm both the API and the
    // database agree it is gone.
    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(delete.contains("HTTP/1.1 200"), "delete failed: {delete}");

    let pull_after_delete = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        pull_after_delete.contains("HTTP/1.1 404"),
        "expected 404 after delete: {pull_after_delete}"
    );

    let db_row_after_delete = psql_query(
        &dsn,
        "SELECT count(*) FROM ferrogate_control.stored_assets \
         WHERE tenant_id = 'org_demo' AND asset_type = 'cli_tool' AND name = 'hello'",
    );
    assert_eq!(
        db_row_after_delete.trim(),
        "0",
        "row still present in the real database after delete"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #301: the registry pull path must combine HTTP conditional caching
/// (304/Range from #258) with the #260 registry-resolution metadata headers.
/// A conditional re-pull short-circuits to 304 and a Range pull to 206, and
/// both still carry `x-ferrogate-asset-resolved`/`-version` (and the yank
/// `warning` when the resolved version is yanked).
#[test]
fn asset_pull_serves_304_and_206_with_resolution_headers() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping asset_pull_serves_304_and_206_with_resolution_headers: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, assets_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_demo","name":"Org Demo","slug":"org-demo"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // Push a concrete version, then point the `stable` channel at it so the
    // pull can resolve via a channel (exercising the resolution metadata).
    let content = "cache-me: the quick brown fox jumps over the lazy dog\n";
    let push = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/cacheable/1.2.3?channel=stable",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        content,
    ));
    let content_hash = push["asset"]["content_hash"]
        .as_str()
        .expect("content_hash must be present")
        .to_string();
    let etag = format!("\"{content_hash}\"");

    // 1. A full pull via the `stable` channel returns 200 with the resolution
    //    metadata headers and a strong ETag.
    let full = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/cacheable/stable",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(full.contains("HTTP/1.1 200"), "full pull failed: {full}");
    let lower = full.to_lowercase();
    assert!(
        lower.contains("x-ferrogate-asset-resolved:"),
        "full pull missing x-ferrogate-asset-resolved: {full}"
    );
    assert!(
        lower.contains("x-ferrogate-asset-version: 1.2.3"),
        "full pull missing resolved version: {full}"
    );
    assert!(
        lower.contains(&format!("etag: {etag}")),
        "full pull missing strong ETag: {full}"
    );

    // 2. A conditional re-pull with the matching ETag short-circuits to 304 --
    //    and still carries the resolution metadata headers.
    let not_modified = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/cacheable/stable",
        &[
            "Authorization: Bearer asset-secret",
            &format!("If-None-Match: {etag}"),
        ],
        "",
    );
    assert!(
        not_modified.contains("HTTP/1.1 304"),
        "expected 304 for matching If-None-Match: {not_modified}"
    );
    let nm_lower = not_modified.to_lowercase();
    assert!(
        nm_lower.contains("x-ferrogate-asset-resolved:"),
        "304 response dropped x-ferrogate-asset-resolved: {not_modified}"
    );
    assert!(
        nm_lower.contains("x-ferrogate-asset-version: 1.2.3"),
        "304 response dropped x-ferrogate-asset-version: {not_modified}"
    );

    // 3. A Range pull returns 206 Partial Content + Content-Range, still with
    //    the resolution metadata headers.
    let partial = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/cacheable/1.2.3",
        &["Authorization: Bearer asset-secret", "Range: bytes=0-9"],
        "",
    );
    assert!(
        partial.contains("HTTP/1.1 206"),
        "expected 206 for Range request: {partial}"
    );
    let p_lower = partial.to_lowercase();
    assert!(
        p_lower.contains(&format!("content-range: bytes 0-9/{}", content.len())),
        "206 response missing Content-Range: {partial}"
    );
    assert!(
        p_lower.contains("x-ferrogate-asset-version: 1.2.3"),
        "206 response dropped x-ferrogate-asset-version: {partial}"
    );

    // 4. Yank the version; an exact pull now also carries the yank warning +
    //    x-ferrogate-asset-yanked alongside the caching validators.
    let yank = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/cacheable/1.2.3/yank",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(yank.contains("HTTP/1.1 200"), "yank failed: {yank}");
    let yanked_pull = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/cacheable/1.2.3",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        yanked_pull.contains("HTTP/1.1 200"),
        "yanked exact pull should still serve: {yanked_pull}"
    );
    let y_lower = yanked_pull.to_lowercase();
    assert!(
        y_lower.contains("warning:") && y_lower.contains("x-ferrogate-asset-yanked: true"),
        "yanked pull missing yank warning headers: {yanked_pull}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn assets_are_denied_when_the_tenants_plan_disables_hosting() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping assets_are_denied_when_the_tenants_plan_disables_hosting: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, assets_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // A plan with asset_hosting_enabled left at its default (false).
    let plan = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/should-fail/1.0.0",
        &[
            "Authorization: Bearer no-tenant-secret",
            "Content-Type: text/plain",
        ],
        "irrelevant",
    );
    assert!(
        plan.contains("HTTP/1.1 403"),
        "expected 403 for a key with no organization_id: {plan}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn assets_config(gateway_addr: &str, dsn: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_demo"

[[api_keys]]
id = "no-tenant-client"
name = "No tenant client"
key = "no-tenant-secret"
scopes = ["assets.read", "assets.write"]
"#
    )
}

fn response_json(response: String) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("invalid JSON body: {error}\n{response}"))
}

fn psql_query(dsn: &str, query: &str) -> String {
    let output = Command::new("psql")
        .arg(dsn)
        .arg("-t")
        .arg("-A")
        .arg("-c")
        .arg(query)
        .output()
        .expect("psql must be installed for this test's independent DB verification");
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        panic!("psql query failed: {query}");
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}
