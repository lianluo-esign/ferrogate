// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for the `default_asset_storage_quota_bytes`
// enforcement path in /v1/assets/* (issue #177's last open acceptance
// item -- the 403 `asset_storage_quota_exceeded` code existed in
// gateway/assets.rs but had no automated test). Uses the /admin/v1/plans
// and PATCH /admin/v1/tenant-accounts/{id} surfaces landed for issue #168
// to assign a tenant a plan with a tiny quota, rather than needing to push
// megabytes of content against the 10 MiB default free-plan quota.
// Runs against the default in-memory backend -- no FERROGATE_SUPABASE_DSN
// dependency, since this exercises gateway-side quota arithmetic, not
// storage-layer persistence (already covered by assets_api.rs).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

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
organization_id = "tenant-quota-e2e"
"#
        ),
    )
    .unwrap();
}

fn admin_headers() -> Vec<&'static str> {
    vec![
        "Authorization: Bearer admin-secret",
        "Content-Type: application/json",
    ]
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn push_asset(gateway_addr: &str, name: &str, content: &str) -> String {
    http_request(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/config_file/{name}/1.0.0"),
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        content,
    )
}

#[test]
fn asset_push_is_denied_once_the_tenants_storage_quota_is_exceeded() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap the tenant (lands on the seeded "free" plan, 10 MiB
    // quota) then create and assign a plan with a 50-byte quota -- tiny
    // enough to exceed without pushing megabytes of test content.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-quota-e2e","name":"Tenant Quota E2E","slug":"tenant-quota-e2e"}"#,
    ));

    let plan = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"tiny-quota","name":"Tiny Quota","slug":"tiny-quota","asset_hosting_enabled":true,"default_asset_storage_quota_bytes":50}"#,
    ));
    assert_eq!(plan["plan"]["default_asset_storage_quota_bytes"], 50);

    let assigned = response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/tenant-quota-e2e",
        &admin_headers(),
        r#"{"plan_id":"tiny-quota"}"#,
    ));
    assert_eq!(assigned["tenant"]["plan_id"], "tiny-quota");

    // 2. A 30-byte asset fits comfortably within the 50-byte quota.
    let first_content = "a".repeat(30);
    let first_push = push_asset(&gateway_addr, "one", &first_content);
    assert!(
        status_line(&first_push).contains("200 OK"),
        "first push (30/50 bytes) must succeed: {first_push}"
    );

    // 3. A second, different 30-byte asset would bring cumulative usage to
    // 60 bytes, over the 50-byte quota -- must be rejected, not silently
    // accepted.
    let second_content = "b".repeat(30);
    let second_push = push_asset(&gateway_addr, "two", &second_content);
    assert!(
        status_line(&second_push).contains("403"),
        "second push (would total 60/50 bytes) must be rejected: {second_push}"
    );
    assert!(
        second_push.contains("asset_storage_quota_exceeded"),
        "expected the asset_storage_quota_exceeded error code: {second_push}"
    );

    // 4. The rejected push must not have been partially recorded -- listing
    // must show only the first asset.
    let list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    let names: Vec<&str> = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| asset["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["one"],
        "a quota-rejected push must not land any row: {list}"
    );

    // 5. Overwriting the SAME asset (same type/name/version) with content
    // that still fits once its own prior size is excluded from the "used
    // by others" calculation must succeed -- proves the quota check
    // doesn't double-count an asset against itself on replace.
    let replacement_content = "c".repeat(40);
    let replace_push = push_asset(&gateway_addr, "one", &replacement_content);
    assert!(
        status_line(&replace_push).contains("200 OK"),
        "replacing the only existing asset with 40/50 bytes must succeed \
         (its own prior 30 bytes must not count against itself): {replace_push}"
    );

    // 6. But now that "one" is 40 bytes, adding a second 30-byte asset
    // (40 + 30 = 70 > 50) must still be rejected.
    let third_push = push_asset(&gateway_addr, "two", &second_content);
    assert!(
        status_line(&third_push).contains("403"),
        "40 + 30 = 70 bytes exceeds the 50-byte quota: {third_push}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
