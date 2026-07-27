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
platform_operator = true

[[api_keys]]
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "tenant-quota-e2e"

[[api_keys]]
id = "unscoped-asset-client"
name = "Unscoped asset client"
key = "unscoped-asset-secret"
scopes = ["assets.read"]
platform_operator = true
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

    // 5. Published versions are immutable since the #260 registry semantics:
    // re-pushing the SAME type/name/version must be rejected with 409, not
    // silently replaced (this test predated #260 and used to expect an
    // in-place overwrite; the immutability contract supersedes that).
    let replacement_content = "c".repeat(40);
    let replace_push = push_asset(&gateway_addr, "one", &replacement_content);
    assert!(
        status_line(&replace_push).contains("409"),
        "re-publishing an existing version must be rejected as immutable: {replace_push}"
    );
    assert!(
        replace_push.contains("asset_version_immutable"),
        "expected the asset_version_immutable error code: {replace_push}"
    );

    // 5b. The supported replace flow is delete-then-republish. After the
    // delete frees the original 30 bytes, a 40-byte republish of the same
    // name/version fits 40/50 -- proving the quota calculation no longer
    // counts the deleted asset's bytes (no double-counting on replace).
    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/v1/assets/config_file/one/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        status_line(&delete).contains("200 OK"),
        "deleting the published asset must succeed: {delete}"
    );
    let republish = push_asset(&gateway_addr, "one", &replacement_content);
    assert!(
        status_line(&republish).contains("200 OK"),
        "republishing 40/50 bytes after the delete freed 30 must succeed \
         (freed bytes must not count against the quota): {republish}"
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

fn set_tenant_asset_quota_override(gateway_addr: &str, tenant_id: &str, bytes: u64) {
    let response = response_json(http_request(
        gateway_addr,
        "PUT",
        &format!("/admin/v1/quota-policies/tenant/{tenant_id}"),
        &admin_headers(),
        &format!(r#"{{"asset_storage_quota_bytes":{bytes},"enabled":true}}"#),
    ));
    assert_eq!(
        response["policy"]["asset_storage_quota_bytes"], bytes,
        "quota policy upsert must echo back the override: {response}"
    );
}

// Issue #188: a tenant-scoped StoredQuotaPolicy.asset_storage_quota_bytes
// override must be enforced instead of the tenant's plan default, in both
// directions -- tighter than the plan (should reject sooner) and looser
// than the plan (should allow more than the plan alone would).
#[test]
fn asset_push_quota_tenant_override_is_tighter_than_the_plan_default() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-quota-e2e","name":"Tenant Quota E2E","slug":"tenant-quota-e2e"}"#,
    ));

    // Plan default is generous (1000 bytes) -- would allow both pushes on
    // its own.
    let plan = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"generous-quota","name":"Generous Quota","slug":"generous-quota","asset_hosting_enabled":true,"default_asset_storage_quota_bytes":1000}"#,
    ));
    assert_eq!(plan["plan"]["default_asset_storage_quota_bytes"], 1000);

    response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/tenant-quota-e2e",
        &admin_headers(),
        r#"{"plan_id":"generous-quota"}"#,
    ));

    // A tighter tenant-scoped override (50 bytes) must win over the plan's
    // 1000-byte default.
    set_tenant_asset_quota_override(&gateway_addr, "tenant-quota-e2e", 50);

    let first_push = push_asset(&gateway_addr, "one", &"a".repeat(30));
    assert!(
        status_line(&first_push).contains("200 OK"),
        "first push (30/50 override bytes) must succeed: {first_push}"
    );

    // The operator summary reads the authoritative repository total and the
    // already-resolved tenant override. It is not derived from a client-side
    // asset list (and therefore cannot miss rows because of pagination).
    let summary = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/storage/summary",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(summary["object"], "asset_storage_summary");
    assert_eq!(summary["used_bytes"], 30);
    assert_eq!(summary["quota_bytes"], 50);
    assert_eq!(summary["remaining_bytes"], 20);
    assert_eq!(summary["inline_upload_max_bytes"], 50);
    assert_eq!(summary["presigned_upload"]["enabled"], false);
    assert_eq!(
        summary["presigned_upload"]["max_object_bytes"],
        serde_json::Value::Null
    );
    assert_eq!(
        summary["presigned_upload"]["url_ttl_seconds"],
        serde_json::Value::Null
    );

    let wrong_method = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/storage/summary",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(status_line(&wrong_method).contains("405"), "{wrong_method}");
    assert!(
        wrong_method.contains("method_not_allowed"),
        "{wrong_method}"
    );

    let no_tenant = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/storage/summary",
        &["Authorization: Bearer unscoped-asset-secret"],
        "",
    );
    assert!(status_line(&no_tenant).contains("403"), "{no_tenant}");
    assert!(no_tenant.contains("tenant_required"), "{no_tenant}");

    let second_push = push_asset(&gateway_addr, "two", &"b".repeat(30));
    assert!(
        status_line(&second_push).contains("403"),
        "second push (60 bytes) exceeds the 50-byte override even though \
         the 1000-byte plan default alone would allow it: {second_push}"
    );
    assert!(second_push.contains("asset_storage_quota_exceeded"));

    // Rejected writes are absent from backend accounting.
    let after_rejection = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/storage/summary",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(after_rejection["used_bytes"], 30);
    assert_eq!(after_rejection["remaining_bytes"], 20);

    // A channel must never fabricate success when its target does not exist.
    let missing_channel_target = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/config_file/missing/channels/stable?version=9.9.9",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        status_line(&missing_channel_target).contains("404"),
        "{missing_channel_target}"
    );
    assert!(
        missing_channel_target.contains("channel_target_not_found"),
        "{missing_channel_target}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn asset_push_quota_tenant_override_is_looser_than_the_plan_default() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-quota-e2e","name":"Tenant Quota E2E","slug":"tenant-quota-e2e"}"#,
    ));

    // Plan default is tiny (50 bytes) -- would reject the second push on
    // its own.
    let plan = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"tiny-quota","name":"Tiny Quota","slug":"tiny-quota","asset_hosting_enabled":true,"default_asset_storage_quota_bytes":50}"#,
    ));
    assert_eq!(plan["plan"]["default_asset_storage_quota_bytes"], 50);

    response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/tenant-quota-e2e",
        &admin_headers(),
        r#"{"plan_id":"tiny-quota"}"#,
    ));

    // A looser tenant-scoped override (1000 bytes) must win over the
    // plan's 50-byte default.
    set_tenant_asset_quota_override(&gateway_addr, "tenant-quota-e2e", 1000);

    let first_push = push_asset(&gateway_addr, "one", &"a".repeat(30));
    assert!(
        status_line(&first_push).contains("200 OK"),
        "first push (30/1000 override bytes) must succeed: {first_push}"
    );

    let second_push = push_asset(&gateway_addr, "two", &"b".repeat(30));
    assert!(
        status_line(&second_push).contains("200 OK"),
        "second push (60 bytes) exceeds the 50-byte plan default but must \
         succeed under the 1000-byte tenant override: {second_push}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// A tenant with no StoredQuotaPolicy override at all must still fall back
// to the plan default exactly as before -- no regression from issue #188.
#[test]
fn asset_push_quota_falls_back_to_plan_default_with_no_tenant_override() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

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

    response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/tenant-quota-e2e",
        &admin_headers(),
        r#"{"plan_id":"tiny-quota"}"#,
    ));

    let first_push = push_asset(&gateway_addr, "one", &"a".repeat(30));
    assert!(status_line(&first_push).contains("200 OK"));

    let second_push = push_asset(&gateway_addr, "two", &"b".repeat(30));
    assert!(
        status_line(&second_push).contains("403"),
        "with no tenant override, the 50-byte plan default must still \
         govern: {second_push}"
    );
    assert!(second_push.contains("asset_storage_quota_exceeded"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
