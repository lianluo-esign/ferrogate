// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for the tenant-level RBAC entitlement
// system (issue #182) -- Permission -> Role -> TenantRoleBinding -- through
// a real gateway process, with every row independently verified against a
// real Postgres/Supabase-protocol database, and a real enforcement call
// site (/v1/assets/* push, #176/#177) proving the closed loop end to end:
// a tenant on a plan that does NOT grant asset hosting is denied, then
// granted purely by binding a role that bundles the "assets.host"
// permission -- no plan change, no redeploy.
//
// Opt-in: requires FERROGATE_SUPABASE_DSN (see tests/assets_api.rs for the
// same convention).

mod support;

use std::io::Write;
use std::process::Command;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn permission_role_and_tenant_binding_round_trip_through_real_postgres() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping permission_role_and_tenant_binding_round_trip_through_real_postgres: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, rbac_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // This test is re-run against a persistent local/real database across
    // dev iterations, unlike a fresh-per-run Docker fixture -- clean up any
    // leftovers from a prior run of this exact test before creating
    // anything, so it stays idempotent rather than tripping the UNIQUE
    // constraints on permissions.key / roles.slug on a second run.
    psql_exec(
        &dsn,
        "DELETE FROM ferrogate_control.tenant_role_bindings WHERE tenant_id = 'org_rbac_only'; \
         DELETE FROM ferrogate_control.roles WHERE slug = 'e2e-asset-hoster'; \
         DELETE FROM ferrogate_control.permissions WHERE key = 'assets.host'; \
         DELETE FROM ferrogate_control.stored_assets WHERE tenant_id = 'org_rbac_only';",
    );

    // A tenant on a plan that does NOT grant asset hosting -- the closed
    // loop this test proves is that binding a role is a *sufficient*,
    // independent path to the same capability, not that it's the only one.
    // Inserted after the gateway is up so its schema-init (CREATE SCHEMA
    // ferrogate_control + the plans table) has already run.
    psql_exec(
        &dsn,
        "INSERT INTO ferrogate_control.plans (id, name, slug, asset_hosting_enabled) \
         VALUES ('no-assets', 'No Assets', 'no-assets', FALSE) \
         ON CONFLICT (id) DO UPDATE SET asset_hosting_enabled = FALSE",
    );

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_rbac_only","name":"RBAC Only","slug":"org-rbac-only","plan_id":"no-assets"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // 1. Confirm the plan alone does NOT grant asset hosting.
    let denied = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/rbac-demo/1.0.0",
        &[
            "Authorization: Bearer rbac-only-secret",
            "Content-Type: text/plain",
        ],
        "should be denied",
    );
    assert!(
        denied.contains("HTTP/1.1 403"),
        "expected the plan-only push to be denied: {denied}"
    );

    // 2. Create a new permission via the admin API -- no code change.
    let permission = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"key":"assets.host","name":"Host static assets"}"#,
    ));
    assert_eq!(permission["permission"]["key"], "assets.host");

    // 3. Bundle it into a new role -- no code change.
    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"Asset Hoster","slug":"e2e-asset-hoster","permission_keys":["assets.host"]}"#,
    ));
    let role_id = role["role"]["id"]
        .as_str()
        .expect("role id must be present")
        .to_string();
    assert_eq!(role["role"]["permission_keys"][0], "assets.host");

    // 4. Bind the role to the tenant -- one write, no redeploy.
    let bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/org_rbac_only",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(bind.contains("HTTP/1.1 200"), "bind failed: {bind}");

    // 5. Independently verify the binding landed in the real database.
    let db_binding = psql_query(
        &dsn,
        &format!(
            "SELECT tenant_id, role_id FROM ferrogate_control.tenant_role_bindings \
             WHERE tenant_id = 'org_rbac_only' AND role_id = '{role_id}'"
        ),
    );
    assert!(
        db_binding.contains("org_rbac_only") && db_binding.contains(&role_id),
        "tenant_role_bindings row not found in the real database: {db_binding}"
    );

    // 6. The SAME plan-gated endpoint now succeeds -- purely via the role,
    // the tenant's plan is still "no-assets" the whole time.
    let allowed = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/rbac-demo/1.0.0",
        &[
            "Authorization: Bearer rbac-only-secret",
            "Content-Type: text/plain",
        ],
        "granted via role",
    );
    assert!(
        allowed.contains("HTTP/1.1 200"),
        "expected the role-granted push to succeed: {allowed}"
    );

    // 7. List the tenant's bound roles through the admin API.
    let bindings = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/org_rbac_only",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let listed = bindings["data"]
        .as_array()
        .expect("bindings list response must have a data array");
    assert!(
        listed.iter().any(|binding| binding["role_id"] == role_id),
        "bound role not present in tenant-roles list: {bindings}"
    );

    // 8. Unbind, and confirm the endpoint is denied again.
    let unbind = http_request(
        &gateway_addr,
        "DELETE",
        &format!("/admin/v1/tenant-roles/org_rbac_only/{role_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(unbind.contains("HTTP/1.1 200"), "unbind failed: {unbind}");

    let denied_again = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/rbac-demo/2.0.0",
        &[
            "Authorization: Bearer rbac-only-secret",
            "Content-Type: text/plain",
        ],
        "should be denied again",
    );
    assert!(
        denied_again.contains("HTTP/1.1 403"),
        "expected the push to be denied again after unbind: {denied_again}"
    );

    let db_binding_after_unbind = psql_query(
        &dsn,
        &format!(
            "SELECT count(*) FROM ferrogate_control.tenant_role_bindings \
             WHERE tenant_id = 'org_rbac_only' AND role_id = '{role_id}'"
        ),
    );
    assert_eq!(
        db_binding_after_unbind.trim(),
        "0",
        "binding still present in the real database after unbind"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn rbac_config(gateway_addr: &str, dsn: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "rbac-only-client"
name = "RBAC-only client"
key = "rbac-only-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_rbac_only"
"#
    )
}

fn response_json(response: String) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("invalid JSON body: {error}\n{response}"))
}

fn psql_exec(dsn: &str, statement: &str) {
    let output = Command::new("psql")
        .arg(dsn)
        .arg("-c")
        .arg(statement)
        .output()
        .expect("psql must be installed for this test's setup step");
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        panic!("psql setup statement failed: {statement}");
    }
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
