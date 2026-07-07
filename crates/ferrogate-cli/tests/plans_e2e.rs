// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of the sellable plan/tier admin surface
// (issue #168) against a real running gateway: create a plan over HTTP,
// bootstrap a tenant (which lands on the seeded "free" plan by default),
// then assign the new plan via PATCH /admin/v1/tenant-accounts/{id} --
// the HTTP surface `StoredPlan`/quota-merge/feature-gating (already landed
// in earlier commits) was missing until now.

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
name = "Admin bootstrap key"
key = "admin-secret"
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

#[test]
fn plans_admin_surface_creates_lists_and_assigns_to_a_tenant() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Unauthenticated requests must be rejected before any storage lookup.
    let unauthenticated = http_request(&gateway_addr, "GET", "/admin/v1/plans", &[], "");
    assert!(
        status_line(&unauthenticated).contains("401"),
        "plans list must require admin auth: {unauthenticated}"
    );

    // 2. The seeded "free" plan always exists on a fresh gateway.
    let initial = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plans",
        &admin_headers(),
        "",
    ));
    let initial_rows = initial["data"].as_array().unwrap();
    assert!(
        initial_rows.iter().any(|plan| plan["id"] == "free"),
        "the seeded free plan must always exist: {initial}"
    );

    // 3. Create a new "pro" plan over the real admin HTTP surface.
    let created = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"pro","name":"Pro","slug":"pro","mcp_enabled":true,"self_hosted_workers_enabled":true,"default_rpm_limit":1000,"default_tpm_limit":500000}"#,
    ));
    assert_eq!(created["plan"]["id"], "pro");
    assert_eq!(created["plan"]["mcp_enabled"], true);
    assert_eq!(created["plan"]["default_rpm_limit"], 1000);

    // Creating the same id twice is a conflict, not a silent overwrite.
    let duplicate = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"pro","name":"Pro Again","slug":"pro-2"}"#,
    );
    assert!(
        status_line(&duplicate).contains("409"),
        "creating a plan id that already exists must conflict: {duplicate}"
    );

    // 4. GET the single plan back.
    let fetched = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plans/pro",
        &admin_headers(),
        "",
    ));
    assert_eq!(fetched["plan"]["slug"], "pro");
    assert_eq!(fetched["plan"]["self_hosted_workers_enabled"], true);

    // 5. PATCH merges: only tpm_limit changes, mcp_enabled/rpm_limit survive.
    let patched = response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/plans/pro",
        &admin_headers(),
        r#"{"default_tpm_limit":750000}"#,
    ));
    assert_eq!(patched["plan"]["default_tpm_limit"], 750000);
    assert_eq!(
        patched["plan"]["mcp_enabled"], true,
        "PATCH must merge, not replace: mcp_enabled from creation must survive"
    );
    assert_eq!(patched["plan"]["default_rpm_limit"], 1000);

    // 6. Bootstrap a tenant -- it lands on the seeded "free" plan by default.
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-plans-e2e","name":"Tenant Plans E2E","slug":"tenant-plans-e2e"}"#,
    ));
    assert_eq!(tenant["tenant"]["plan_id"], "free");
    let tenant_id = tenant["tenant"]["id"].as_str().unwrap().to_string();

    // 7. GET the tenant back by id.
    let fetched_tenant = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/tenant-accounts/{tenant_id}"),
        &admin_headers(),
        "",
    ));
    assert_eq!(fetched_tenant["tenant"]["plan_id"], "free");

    // 8. Assigning a nonexistent plan is rejected.
    let bad_assign = http_request(
        &gateway_addr,
        "PATCH",
        &format!("/admin/v1/tenant-accounts/{tenant_id}"),
        &admin_headers(),
        r#"{"plan_id":"no-such-plan"}"#,
    );
    assert!(
        status_line(&bad_assign).contains("400"),
        "assigning an unknown plan_id must be rejected: {bad_assign}"
    );

    // 9. Assign the "pro" plan -- the actual "assign" operation.
    let assigned = response_json(http_request(
        &gateway_addr,
        "PATCH",
        &format!("/admin/v1/tenant-accounts/{tenant_id}"),
        &admin_headers(),
        r#"{"plan_id":"pro"}"#,
    ));
    assert_eq!(assigned["tenant"]["plan_id"], "pro");
    assert_eq!(
        assigned["tenant"]["name"], "Tenant Plans E2E",
        "PATCH must merge: name from creation must survive an unrelated plan_id update"
    );

    let reread = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/tenant-accounts/{tenant_id}"),
        &admin_headers(),
        "",
    ));
    assert_eq!(reread["tenant"]["plan_id"], "pro");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
