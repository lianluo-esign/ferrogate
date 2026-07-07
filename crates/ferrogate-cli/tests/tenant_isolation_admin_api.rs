// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end regression coverage for issue #185 -- a critical,
// live-verified cross-tenant IDOR spanning most of the /admin/v1/* admin
// API surface. Before the fix, `authenticate()` only ever checked *scope*
// (`admin.read`/`admin.write`), never whether the caller's own tenant
// matched the tenant the request actually targeted; any tenant-scoped
// admin.read+admin.write key (exactly the shape the admin-console
// auto-provisions on every login via `provision_gateway_api_key`) could
// read AND financially mutate every *other* tenant's wallets, virtual
// keys, quota policies, and RBAC bindings. This reproduces the exact
// manually-curl-verified scenario from the issue (tenant-A-scoped key
// reads then adjusts tenant B's wallet balance) plus the same class of gap
// across the other admin surfaces fixed alongside it, against a real
// running gateway process -- no Postgres required (in-memory storage,
// matching tests/wallet_e2e.rs's convention).

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
organization_id = "tenant-iso-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-iso-b"
"#
        ),
    )
    .unwrap();
}

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];
const TENANT_A: [&str; 2] = [
    "Authorization: Bearer tenant-a-secret",
    "Content-Type: application/json",
];
const TENANT_B: [&str; 2] = [
    "Authorization: Bearer tenant-b-secret",
    "Content-Type: application/json",
];

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

fn register_tenant(gateway_addr: &str, tenant_id: &str) {
    let register = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed for {tenant_id}: {register}"
    );
}

/// The primary regression: the exact scenario manually verified with curl
/// before this fix landed. Tenant A's own admin-console session key could
/// read, and then financially adjust, tenant B's wallet balance.
#[test]
fn cross_tenant_admin_key_cannot_read_or_mutate_another_tenants_wallet() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    register_tenant(&gateway_addr, "tenant-iso-a");
    register_tenant(&gateway_addr, "tenant-iso-b");

    let created_wallet = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &ADMIN,
        r#"{"tenant_id":"tenant-iso-a"}"#,
    ));
    assert_eq!(created_wallet["wallet"]["balance_credits"], 0);
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-iso-a/adjust",
        &ADMIN,
        r#"{"delta_credits":500000}"#,
    ));

    // Tenant A reading its own wallet is fine.
    let own_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &TENANT_A,
        "",
    );
    assert!(
        own_read.contains("HTTP/1.1 200"),
        "tenant A must be able to read its own wallet: {own_read}"
    );

    // Tenant B reading tenant A's wallet must be denied -- this is the
    // exact cross-tenant read confirmed live before the fix.
    let stolen_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_read).contains("403"),
        "tenant B must not be able to read tenant A's wallet: {stolen_read}"
    );
    assert!(stolen_read.contains("tenant_scope_denied"));

    // Tenant B financially adjusting tenant A's wallet must be denied --
    // the worst-case exploit path called out in the issue.
    let stolen_adjust = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-iso-a/adjust",
        &TENANT_B,
        r#"{"delta_credits":999999999}"#,
    );
    assert!(
        status_line(&stolen_adjust).contains("403"),
        "tenant B must not be able to adjust tenant A's wallet balance: {stolen_adjust}"
    );

    // The balance must be completely unaffected by tenant B's attempt.
    let balance_after = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &ADMIN,
        "",
    ));
    assert_eq!(
        balance_after["wallet"]["balance_credits"], 500000,
        "tenant B's denied adjust must not have changed tenant A's balance: {balance_after}"
    );

    // Tenant B's own bulk wallet list must not include tenant A's wallet.
    let tenant_b_list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets",
        &TENANT_B,
        "",
    ));
    let listed_tenants: Vec<&str> = tenant_b_list["data"]
        .as_array()
        .expect("wallets list must have a data array")
        .iter()
        .map(|wallet| wallet["tenant_id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !listed_tenants.contains(&"tenant-iso-a"),
        "tenant A's wallet must not appear in tenant B's list: {tenant_b_list}"
    );

    // The platform operator is completely unaffected by this fix -- it
    // must retain full cross-tenant access.
    let operator_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &ADMIN,
        "",
    );
    assert!(
        operator_read.contains("HTTP/1.1 200"),
        "the platform-operator key must retain unrestricted cross-tenant access: {operator_read}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The same class of gap, across the other admin surfaces fixed alongside
/// wallets: tenant-accounts, projects, virtual-keys, and quota-policies.
#[test]
fn cross_tenant_admin_key_is_denied_across_identity_and_quota_surfaces() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    register_tenant(&gateway_addr, "tenant-iso-a");
    register_tenant(&gateway_addr, "tenant-iso-b");

    // Tenant B cannot read tenant A's tenant-account record.
    let stolen_tenant = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_tenant).contains("403"),
        "tenant B must not be able to read tenant A's account: {stolen_tenant}"
    );

    // Tenant A creates a project + workspace + virtual key under its own
    // tenant.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &ADMIN,
        r#"{"id":"project-iso-a","tenant_id":"tenant-iso-a","name":"Project A","slug":"project-iso-a"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &ADMIN,
        r#"{"id":"workspace-iso-a","project_id":"project-iso-a","name":"Workspace A","slug":"workspace-iso-a"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &ADMIN,
        r#"{"name":"Tenant A virtual key","workspace_id":"workspace-iso-a","scopes":["chat.completions"]}"#,
    ));
    let virtual_key_id = created_key["key"]["id"]
        .as_str()
        .expect("created virtual key must have an id")
        .to_string();

    // Tenant B cannot read tenant A's virtual key by id.
    let stolen_key = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/virtual-keys/{virtual_key_id}"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_key).contains("403"),
        "tenant B must not be able to read tenant A's virtual key: {stolen_key}"
    );

    // Tenant B cannot revoke tenant A's virtual key either.
    let stolen_revoke = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/virtual-keys/{virtual_key_id}/revoke"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_revoke).contains("403"),
        "tenant B must not be able to revoke tenant A's virtual key: {stolen_revoke}"
    );

    // Tenant B's own project/workspace/virtual-key lists must not leak
    // tenant A's rows.
    let tenant_b_projects = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/projects",
        &TENANT_B,
        "",
    ));
    let project_ids: Vec<&str> = tenant_b_projects["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|project| project["id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !project_ids.contains(&"project-iso-a"),
        "tenant A's project must not appear in tenant B's list: {tenant_b_projects}"
    );

    // Tenant B cannot read or write a quota policy scoped to tenant A.
    let stolen_quota_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_quota_read).contains("403"),
        "tenant B must not be able to read a quota policy scoped to tenant A -- the tenant-scope \
         check must run before the not-found check: {stolen_quota_read}"
    );
    let stolen_quota_write = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_B,
        r#"{"rpm_limit":1}"#,
    );
    assert!(
        status_line(&stolen_quota_write).contains("403"),
        "tenant B must not be able to write a quota policy scoped to tenant A: {stolen_quota_write}"
    );
    // Project-scoped quota policy, resolved indirectly via the project's
    // owning tenant rather than a bare tenant_id.
    let stolen_quota_project = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/project/project-iso-a",
        &TENANT_B,
        r#"{"rpm_limit":1}"#,
    );
    assert!(
        status_line(&stolen_quota_project).contains("403"),
        "tenant B must not be able to write a quota policy scoped to tenant A's project: {stolen_quota_project}"
    );

    // Tenant A can still manage its own quota policy.
    let own_quota_write = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_A,
        r#"{"rpm_limit":100}"#,
    );
    assert!(
        own_quota_write.contains("HTTP/1.1 200"),
        "tenant A must still be able to manage its own quota policy: {own_quota_write}"
    );

    // Tenant B cannot bind or list RBAC roles on tenant A.
    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &ADMIN,
        r#"{"name":"Isolation Test Role","slug":"iso-test-role","permission_keys":[]}"#,
    ));
    let role_id = role["role"]["id"].as_str().unwrap().to_string();
    let stolen_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &TENANT_B,
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(
        status_line(&stolen_bind).contains("403"),
        "tenant B must not be able to bind a role onto tenant A: {stolen_bind}"
    );
    let stolen_role_list = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_role_list).contains("403"),
        "tenant B must not be able to list tenant A's role bindings: {stolen_role_list}"
    );

    // Sanity: the platform operator can still do all of the above.
    let operator_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &ADMIN,
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(
        operator_bind.contains("HTTP/1.1 200"),
        "the platform operator must retain unrestricted cross-tenant RBAC access: {operator_bind}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
