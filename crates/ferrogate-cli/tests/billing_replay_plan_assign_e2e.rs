// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: End-to-end proof of the two admin operations added for issue
// #388 against a real running gateway (in-memory storage, no Postgres):
// (1) assignTenantPlan -- PUT /admin/v1/tenant-accounts/{id}/plan assigns a
// plan, is platform-operator-only (a tenant-scoped key is rejected), validates
// the plan exists, and records audit evidence; (2) replayBillingOutboxDeadLetter
// -- POST /admin/v1/billing-outbox-dead-letters/{id}/replay is wired, requires
// admin auth, and fails closed (404) on an unknown report id. The replay
// success path (a dead-lettered row transitioning back to pending + its audit
// row) cannot be seeded across the spawned-process boundary and is proved
// instead by the in-process storage CAS tests (billing_outbox_replay_test.rs)
// and the AppState replay tests (state_billing_outbox_test.rs).

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
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A admin-console session key"
key = "tenant-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-388"
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

fn tenant_headers() -> Vec<&'static str> {
    vec![
        "Authorization: Bearer tenant-a-secret",
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
fn assign_tenant_plan_operation_assigns_validates_scopes_and_audits() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // Seed a "pro" plan and a tenant (defaults to the seeded "free" plan).
    let _ = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &admin_headers(),
        r#"{"id":"pro","name":"Pro","slug":"pro","mcp_enabled":true}"#,
    );
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-388","name":"Tenant 388","slug":"tenant-388"}"#,
    ));
    assert_eq!(tenant["tenant"]["plan_id"], "free");

    // Unauthenticated assignment is rejected before any storage lookup.
    let unauth = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-388/plan",
        &[],
        r#"{"plan_id":"pro"}"#,
    );
    assert!(
        status_line(&unauth).contains("401"),
        "plan assignment must require auth: {unauth}"
    );

    // A tenant-scoped key may not assign a plan (self-escalation guard).
    let tenant_scoped = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-388/plan",
        &tenant_headers(),
        r#"{"plan_id":"pro"}"#,
    );
    assert!(
        status_line(&tenant_scoped).contains("403"),
        "a tenant-scoped key must not assign plans: {tenant_scoped}"
    );

    // Assigning an unknown plan is rejected.
    let bad_plan = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-388/plan",
        &admin_headers(),
        r#"{"plan_id":"no-such-plan"}"#,
    );
    assert!(
        status_line(&bad_plan).contains("400"),
        "assigning an unknown plan must be rejected: {bad_plan}"
    );

    // A missing plan_id field is rejected.
    let missing_field = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-388/plan",
        &admin_headers(),
        r#"{}"#,
    );
    assert!(
        status_line(&missing_field).contains("400"),
        "a missing plan_id must be rejected: {missing_field}"
    );

    // Assigning to an unknown tenant is a 404.
    let missing_tenant = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/ghost/plan",
        &admin_headers(),
        r#"{"plan_id":"pro"}"#,
    );
    assert!(
        status_line(&missing_tenant).contains("404"),
        "assigning to an unknown tenant must be 404: {missing_tenant}"
    );

    // The happy path: assign "pro" and read it back.
    let assigned = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-388/plan",
        &admin_headers(),
        r#"{"plan_id":"pro"}"#,
    ));
    assert_eq!(assigned["object"], "tenant_account");
    assert_eq!(assigned["tenant"]["plan_id"], "pro");
    assert_eq!(
        assigned["tenant"]["name"], "Tenant 388",
        "assignment must preserve the rest of the account"
    );

    let reread = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-388",
        &admin_headers(),
        "",
    ));
    assert_eq!(reread["tenant"]["plan_id"], "pro");

    // Audit evidence links the assignment to the tenant.
    let audit = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &admin_headers(),
        "",
    ));
    let rows = audit["data"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|row| row["action"] == "tenant_account.assign_plan"
                && row["target"] == "tenant-388"),
        "an assign_plan audit row must be recorded: {audit}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn replay_dead_letter_operation_is_wired_and_fails_closed() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // Unauthenticated replay is rejected before any storage lookup.
    let unauth = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/billing-outbox-dead-letters/whatever/replay",
        &[],
        "",
    );
    assert!(
        status_line(&unauth).contains("401"),
        "replay must require admin auth: {unauth}"
    );

    // Replaying an unknown report id fails closed with a 404, never a silent
    // success.
    let missing = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/billing-outbox-dead-letters/no-such-report/replay",
        &admin_headers(),
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "replaying an unknown report must be 404: {missing}"
    );
    let body = response_json(missing);
    assert_eq!(body["error"]["code"], "dead_letter_not_found");

    // Only POST is accepted on the replay sub-resource.
    let wrong_method = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-outbox-dead-letters/no-such-report/replay",
        &admin_headers(),
        "",
    );
    assert!(
        status_line(&wrong_method).contains("405"),
        "replay only supports POST: {wrong_method}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
