// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: End-to-end proof of the P1-4 usage/cost report admin surface
// against a real running gateway: bootstrap a durable virtual key over HTTP,
// settle a real chat completion through the durable-key hot path, then read
// the resulting monthly rollup back through /admin/v1/usage-reports.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
input_price_per_1m = 1.0
output_price_per_1m = 2.0

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
fn usage_report_admin_surface_reflects_settled_billing_cost() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_usage","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1000,"completion_tokens":1000,"total_tokens":2000}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap tenant -> project -> workspace -> virtual key over the
    // real admin HTTP surface.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-usage","name":"Tenant Usage","slug":"tenant-usage"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-usage","tenant_id":"tenant-usage","name":"Project Usage","slug":"project-usage"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-usage","project_id":"project-usage","name":"Workspace Usage","slug":"workspace-usage"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"Usage E2E key","workspace_id":"workspace-usage","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"]
        .as_str()
        .expect("create response must include the plaintext secret")
        .to_string();
    let key_id = created_key["key"]["id"]
        .as_str()
        .expect("create response must include the key id")
        .to_string();

    // 2. Before any request settles, the report must have nothing for this
    // key yet.
    let before = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/usage-reports?scope_type=key&scope_id={key_id}"),
        &admin_headers(),
        "",
    ));
    assert_eq!(
        before["data"].as_array().unwrap().len(),
        0,
        "no billing event has settled yet: {before}"
    );

    // 3. Unauthenticated requests must be rejected before any storage lookup.
    let unauthenticated = http_request(&gateway_addr, "GET", "/admin/v1/usage-reports", &[], "");
    assert!(
        status_line(&unauthenticated).contains("401"),
        "usage reports must require admin auth: {unauthenticated}"
    );

    // 4. Drive a real chat completion through the durable-key hot path; the
    // mock provider reports 1000 prompt + 1000 completion tokens, which at
    // the configured $1/$2 per-1M pricing settles to $0.003.
    let completion = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&completion).contains("200 OK"),
        "chat completion should succeed: {completion}"
    );

    // 5. The key-scoped report row now reflects the settled cost and token
    // counts from that single request.
    let after = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/usage-reports?scope_type=key&scope_id={key_id}"),
        &admin_headers(),
        "",
    ));
    let rows = after["data"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "exactly one rollup row for this key: {after}"
    );
    assert_eq!(rows[0]["scope_type"], "key");
    assert_eq!(rows[0]["scope_id"], key_id);
    assert_eq!(rows[0]["total_tokens"], 2000);
    assert_eq!(rows[0]["request_count"], 1);
    let cost = rows[0]["cost_usd"].as_f64().unwrap();
    assert!(
        (cost - 0.003).abs() < 1e-9,
        "1000 prompt @ $1/1M + 1000 completion @ $2/1M = $0.003, got {cost}"
    );

    // 6. The tenant-scope report (no scope_id filter, tenant scope_type)
    // rolls the same event up one level, and group_by=scope collapses the
    // (currently single) matching row identically.
    let tenant_report = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/usage-reports?scope_type=tenant&scope_id=tenant-usage&group_by=scope",
        &admin_headers(),
        "",
    ));
    let tenant_rows = tenant_report["data"].as_array().unwrap();
    assert_eq!(tenant_rows.len(), 1, "{tenant_report}");
    assert_eq!(tenant_rows[0]["scope_type"], "tenant");
    assert_eq!(tenant_rows[0]["scope_id"], "tenant-usage");
    assert_eq!(tenant_rows[0]["total_tokens"], 2000);

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// --- issue #516: both branches of `authorize_scoped_resource` ------------
//
// `/admin/v1/usage-reports?scope_type=..&scope_id=..` is the second of the
// two surfaces guarded by `crate::auth::authorize_scoped_resource`. Until
// #516 neither of that guard's two deny branches was held by a test in this
// suite -- the suite that owns the surface: a test-gate mutation that made an
// *unresolvable* `scope_id` return `Ok(())` (fail open) left it green, and so
// did a mutation of the resolved-owner-mismatch branch.
//
// Both branches are reachable over plain HTTP with a tenant-scoped caller,
// which is exactly the shape `provision_gateway_api_key` mints on every
// admin-console login and is modelled here by a static config key carrying
// `organization_id`.

const USAGE_ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];
const USAGE_TENANT_A: [&str; 2] = [
    "Authorization: Bearer usage-a-secret",
    "Content-Type: application/json",
];
const USAGE_TENANT_B: [&str; 2] = [
    "Authorization: Bearer usage-b-secret",
    "Content-Type: application/json",
];

fn write_scope_auth_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "usage-a-console"
name = "Tenant A admin-console session key"
key = "usage-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-usage-a"

[[api_keys]]
id = "usage-b-console"
name = "Tenant B admin-console session key"
key = "usage-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-usage-b"
"#
        ),
    )
    .unwrap();
}

/// Bootstraps tenant A's full scope chain (tenant -> project -> workspace ->
/// virtual key) plus an empty tenant B, and returns tenant A's key id and
/// plaintext secret.
fn bootstrap_usage_scope_chain(gateway_addr: &str) -> (String, String) {
    for tenant_id in ["tenant-usage-a", "tenant-usage-b"] {
        let registered = http_request(
            gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &USAGE_ADMIN,
            &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
        );
        assert!(
            status_line(&registered).contains("200") || status_line(&registered).contains("201"),
            "tenant registration failed for {tenant_id}: {registered}"
        );
    }
    let project = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/projects",
        &USAGE_ADMIN,
        r#"{"id":"project-usage-a","tenant_id":"tenant-usage-a","name":"Project A","slug":"project-usage-a"}"#,
    ));
    assert_eq!(project["project"]["tenant_id"], "tenant-usage-a");
    let workspace = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &USAGE_ADMIN,
        r#"{"id":"workspace-usage-a","project_id":"project-usage-a","name":"Workspace A","slug":"workspace-usage-a"}"#,
    ));
    assert_eq!(workspace["workspace"]["project_id"], "project-usage-a");
    let created_key = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &USAGE_ADMIN,
        r#"{"name":"Tenant A usage key","workspace_id":"workspace-usage-a","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    assert_eq!(created_key["key"]["tenant_id"], "tenant-usage-a");
    (
        created_key["key"]["id"].as_str().unwrap().to_string(),
        created_key["secret"].as_str().unwrap().to_string(),
    )
}

/// Issue #516, branch 1 of `authorize_scoped_resource` -- **fail closed on an
/// unresolvable `scope_id`**.
///
/// A tenant-scoped caller filters the usage report by a project / workspace /
/// key scope id that does not exist. The guard cannot resolve an owning
/// tenant and must deny with 403 `tenant_scope_denied`. Failing open here
/// does not merely return an empty report: the caller-supplied filter is then
/// applied verbatim against `usage_monthly_rollups` with no tenant narrowing
/// at all, which is the same primitive as a cross-tenant read the instant
/// that id becomes live under another tenant.
///
/// Mutation check: making the unresolvable case return `Ok(())` turns each
/// tenant-scoped request below into a 200, and this test goes red.
#[test]
fn unresolvable_usage_report_scope_id_is_denied_not_treated_as_absent() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_unused","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_scope_auth_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    bootstrap_usage_scope_chain(&gateway_addr);

    for scope_type in ["project", "workspace", "key"] {
        let denied = http_request(
            &gateway_addr,
            "GET",
            &format!(
                "/admin/v1/usage-reports?scope_type={scope_type}&scope_id=dangling-{scope_type}-id"
            ),
            &USAGE_TENANT_A,
            "",
        );
        assert!(
            status_line(&denied).contains("403"),
            "a tenant-scoped caller filtering by a nonexistent {scope_type} scope id must be \
             denied (fail closed), not served an unnarrowed report: {denied}"
        );
        assert!(
            denied.contains("tenant_scope_denied"),
            "the denial must be the tenant-scope guard, not some other error: {denied}"
        );
    }

    // The platform operator, which bypasses the guard, still gets a 200 --
    // proving the 403s above come from the tenant-scope guard and not from
    // the dangling id being rejected somewhere earlier in the pipeline.
    let operator = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/usage-reports?scope_type=project&scope_id=dangling-project-id",
        &USAGE_ADMIN,
        "",
    );
    assert!(
        status_line(&operator).contains("200"),
        "a dangling scope id is not itself an error -- only a tenant-scoped caller is denied: \
         {operator}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #516, branch 2 of `authorize_scoped_resource` -- **deny when the
/// scope resolves to a different tenant**.
///
/// Tenant B filters the usage report by tenant A's tenant / project /
/// workspace / virtual key. Resolution succeeds, so the fail-closed branch
/// never fires; only the owner-mismatch comparison stands between tenant B
/// and tenant A's settled spend. A real billing event is settled first, so
/// failing open is an actual cross-tenant disclosure of token counts and USD
/// cost, not an empty list.
///
/// Mutation check: making the resolved-owner-mismatch case return `Ok(())`
/// turns each request below into a 200 carrying tenant A's rollup row, and
/// this test goes red.
#[test]
fn usage_report_scope_owned_by_another_tenant_is_denied() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_scope","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1000,"completion_tokens":1000,"total_tokens":2000}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_scope_auth_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let (key_id, secret) = bootstrap_usage_scope_chain(&gateway_addr);

    // Settle one real billing event under tenant A so there is something
    // worth stealing at every level of the scope chain.
    let completion = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&completion).contains("200 OK"),
        "chat completion should succeed: {completion}"
    );

    for (scope_type, scope_id) in [
        ("tenant", "tenant-usage-a".to_string()),
        ("project", "project-usage-a".to_string()),
        ("workspace", "workspace-usage-a".to_string()),
        ("key", key_id.clone()),
    ] {
        let path = format!("/admin/v1/usage-reports?scope_type={scope_type}&scope_id={scope_id}");

        // Tenant A reading its own rollup is the guard's Ok() arm, and must
        // keep working -- and must actually return the settled row, so the
        // deny assertions below are about authorization, not emptiness.
        let own = response_json(http_request(
            &gateway_addr,
            "GET",
            &path,
            &USAGE_TENANT_A,
            "",
        ));
        let own_rows = own["data"].as_array().unwrap();
        assert_eq!(
            own_rows.len(),
            1,
            "tenant A must still see its own {scope_type} rollup: {own}"
        );
        assert_eq!(own_rows[0]["total_tokens"], 2000, "{own}");

        // Tenant B must not.
        let stolen = http_request(&gateway_addr, "GET", &path, &USAGE_TENANT_B, "");
        assert!(
            status_line(&stolen).contains("403"),
            "tenant B must not read a usage report whose {scope_type} scope resolves to tenant A: \
             {stolen}"
        );
        assert!(
            stolen.contains("tenant_scope_denied"),
            "the denial must be the tenant-scope guard: {stolen}"
        );
        assert!(
            !stolen.contains("\"total_tokens\":2000"),
            "tenant A's settled usage must never reach tenant B: {stolen}"
        );
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
