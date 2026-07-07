// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Proves the RBAC/plan enforcement points wired across this
// session's retrofitting pass (issue #182's continuation, per #168's
// originally-scoped-but-never-wired mcp_enabled/self_hosted_workers_enabled,
// and #183's follow-up closing the Extension-backend tool-execution gap
// that mcp_enabled left open) actually gate access -- not just that they
// don't regress existing behavior (see agentic_lite.rs /
// self-hosted-worker unit tests for that). For a tenant with a formal
// StoredTenantAccount whose plan disables the capability, the request is
// denied; binding a role granting the matching permission lifts the
// denial. Opt-in via FERROGATE_SUPABASE_DSN, same convention as
// tests/rbac_api.rs.

mod support;

use std::io::Write;
use std::process::Command;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn mcp_tool_execution_is_gated_by_plan_then_lifted_by_role() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping mcp_tool_execution_is_gated_by_plan_then_lifted_by_role: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, gates_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    cleanup(&dsn, "org_mcp_gate");

    psql_exec(
        &dsn,
        "INSERT INTO ferrogate_control.plans (id, name, slug, mcp_enabled) \
         VALUES ('no-mcp', 'No MCP', 'no-mcp', FALSE) \
         ON CONFLICT (id) DO UPDATE SET mcp_enabled = FALSE",
    );
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_mcp_gate","name":"MCP Gate","slug":"org-mcp-gate","plan_id":"no-mcp"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // Denied: the tenant's plan explicitly disables MCP, no role bound yet.
    let denied = http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer mcp-gate-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"whatever","arguments":{}}"#,
    );
    assert!(denied.contains("HTTP/1.1 403"), "expected 403: {denied}");
    assert!(
        denied.contains("mcp_tools_disabled"),
        "expected mcp_tools_disabled error code: {denied}"
    );

    // Create a permission + role granting mcp.execute, bind it to the tenant.
    let permission = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"key":"mcp.execute","name":"Execute MCP tools"}"#,
    );
    assert!(permission.contains("HTTP/1.1 200"), "{permission}");

    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"MCP Executor","slug":"e2e-mcp-executor","permission_keys":["mcp.execute"]}"#,
    ));
    let role_id = role["role"]["id"].as_str().unwrap().to_string();

    let bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/org_mcp_gate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(bind.contains("HTTP/1.1 200"), "bind failed: {bind}");

    // No longer denied by the plan/permission gate -- the request now
    // fails for a *different* reason (no such MCP tool is registered),
    // proving the gate itself was lifted rather than the whole endpoint
    // becoming a no-op.
    let after_bind = http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer mcp-gate-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"whatever","arguments":{}}"#,
    );
    assert!(
        !after_bind.contains("mcp_tools_disabled"),
        "gate should have been lifted by the role binding: {after_bind}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn extension_tool_execution_is_gated_by_plan_then_lifted_by_role() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping extension_tool_execution_is_gated_by_plan_then_lifted_by_role: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, gates_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    cleanup(&dsn, "org_extension_gate");

    psql_exec(
        &dsn,
        "INSERT INTO ferrogate_control.plans (id, name, slug, extension_tools_enabled) \
         VALUES ('no-extensions', 'No Extensions', 'no-extensions', FALSE) \
         ON CONFLICT (id) DO UPDATE SET extension_tools_enabled = FALSE",
    );
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_extension_gate","name":"Extension Gate","slug":"org-extension-gate","plan_id":"no-extensions"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // Denied: the tenant's plan explicitly disables extension tools, no
    // role bound yet. Exercises /v1/tools/execute (the Extension backend),
    // distinct from /v1/mcp/tool/execute above -- proves the two backends
    // are gated independently, not by one shared flag.
    let denied = http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer extension-gate-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"whatever","arguments":{}}"#,
    );
    assert!(denied.contains("HTTP/1.1 403"), "expected 403: {denied}");
    assert!(
        denied.contains("extension_tools_disabled"),
        "expected extension_tools_disabled error code: {denied}"
    );

    // Create a permission + role granting extensions.execute, bind it.
    let permission = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"key":"extensions.execute","name":"Execute extension tools"}"#,
    );
    assert!(permission.contains("HTTP/1.1 200"), "{permission}");

    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"Extension Executor","slug":"e2e-extension-executor","permission_keys":["extensions.execute"]}"#,
    ));
    let role_id = role["role"]["id"].as_str().unwrap().to_string();

    let bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/org_extension_gate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(bind.contains("HTTP/1.1 200"), "bind failed: {bind}");

    // No longer denied by the plan/permission gate -- the request now
    // fails for a *different* reason (no such tool is registered), proving
    // the gate itself was lifted rather than the whole endpoint becoming a
    // no-op.
    let after_bind = http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer extension-gate-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"whatever","arguments":{}}"#,
    );
    assert!(
        !after_bind.contains("extension_tools_disabled"),
        "gate should have been lifted by the role binding: {after_bind}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn self_hosted_worker_registration_is_gated_by_plan_then_lifted_by_role() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping self_hosted_worker_registration_is_gated_by_plan_then_lifted_by_role: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, gates_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    cleanup(&dsn, "org_worker_gate");

    psql_exec(
        &dsn,
        "INSERT INTO ferrogate_control.plans (id, name, slug, self_hosted_workers_enabled) \
         VALUES ('no-workers', 'No Workers', 'no-workers', FALSE) \
         ON CONFLICT (id) DO UPDATE SET self_hosted_workers_enabled = FALSE",
    );
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_worker_gate","name":"Worker Gate","slug":"org-worker-gate","plan_id":"no-workers"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    let registration_body = r#"{
        "tenant": {"organization_id": "org_worker_gate"},
        "workspace_id": "ws-1",
        "worker_name": "worker-1",
        "identity_fingerprint": "sha256:test-fingerprint"
    }"#;

    // Denied: the tenant's plan explicitly disables self-hosted workers.
    let denied = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        registration_body,
    );
    assert!(denied.contains("HTTP/1.1 403"), "expected 403: {denied}");
    assert!(
        denied.contains("self_hosted_workers_disabled"),
        "expected self_hosted_workers_disabled error code: {denied}"
    );

    let permission = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"key":"workers.self_hosted","name":"Register self-hosted workers"}"#,
    );
    assert!(permission.contains("HTTP/1.1 200"), "{permission}");

    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"Worker Registrar","slug":"e2e-worker-registrar","permission_keys":["workers.self_hosted"]}"#,
    ));
    let role_id = role["role"]["id"].as_str().unwrap().to_string();

    let bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/org_worker_gate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(bind.contains("HTTP/1.1 200"), "bind failed: {bind}");

    // Allowed now: registration succeeds through to completion.
    let after_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        registration_body,
    );
    assert!(
        after_bind.contains("HTTP/1.1 201") || after_bind.contains("HTTP/1.1 200"),
        "expected registration to succeed after the role binding: {after_bind}"
    );
    assert!(
        !after_bind.contains("self_hosted_workers_disabled"),
        "gate should have been lifted by the role binding: {after_bind}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn gates_config(gateway_addr: &str, dsn: &str) -> String {
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
id = "mcp-gate-client"
name = "MCP gate client"
key = "mcp-gate-secret"
scopes = ["tools.execute"]
organization_id = "org_mcp_gate"

[[api_keys]]
id = "extension-gate-client"
name = "Extension gate client"
key = "extension-gate-secret"
scopes = ["tools.execute"]
organization_id = "org_extension_gate"
"#
    )
}

fn cleanup(dsn: &str, tenant_id: &str) {
    // Delete bindings by role slug (not just this test's tenant_id): the
    // tests in this file share the same role-slug namespace and run in
    // the same process, so a leftover binding from a *different* test's
    // tenant would otherwise block the role delete below on its foreign
    // key.
    psql_exec(
        dsn,
        &format!(
            "DELETE FROM ferrogate_control.tenant_role_bindings WHERE tenant_id = '{tenant_id}' \
             OR role_id IN (SELECT id FROM ferrogate_control.roles WHERE slug IN \
             ('e2e-mcp-executor', 'e2e-worker-registrar', 'e2e-extension-executor')); \
             DELETE FROM ferrogate_control.roles WHERE slug IN \
             ('e2e-mcp-executor', 'e2e-worker-registrar', 'e2e-extension-executor'); \
             DELETE FROM ferrogate_control.permissions WHERE key IN \
             ('mcp.execute', 'workers.self_hosted', 'extensions.execute');"
        ),
    );
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
