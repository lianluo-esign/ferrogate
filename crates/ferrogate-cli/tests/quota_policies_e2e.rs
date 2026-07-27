// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: End-to-end proof of the P1-3 multi-level quota/rate-limit
// admin surface against a real running gateway: bootstrap a tenant ->
// project -> workspace -> virtual key over HTTP, attach a quota policy over
// HTTP, then drive a real chat completion request through the durable-key
// hot path to prove enforcement (not just that the code compiles).

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
fn quota_policy_admin_surface_bootstraps_hierarchy_and_enforces_tpm_and_model_allowlist() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_quota","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap tenant -> project -> workspace over the real admin HTTP
    // surface (not by touching storage in-process).
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-e2e","name":"Tenant E2E","slug":"tenant-e2e"}"#,
    ));
    assert_eq!(tenant["tenant"]["id"], "tenant-e2e");

    let project = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-e2e","tenant_id":"tenant-e2e","name":"Project E2E","slug":"project-e2e"}"#,
    ));
    assert_eq!(project["project"]["tenant_id"], "tenant-e2e");

    let workspace = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-e2e","project_id":"project-e2e","name":"Workspace E2E","slug":"workspace-e2e"}"#,
    ));
    assert_eq!(workspace["workspace"]["project_id"], "project-e2e");

    // 2. Create a durable virtual key bound to the workspace; the plaintext
    // secret is only ever returned here.
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"E2E key","workspace_id":"workspace-e2e","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"]
        .as_str()
        .expect("create response must include the plaintext secret")
        .to_string();
    assert!(secret.starts_with("fg_"));
    let key_id = created_key["key"]["id"]
        .as_str()
        .expect("create response must include the key id")
        .to_string();
    assert_eq!(created_key["key"]["workspace_id"], "workspace-e2e");
    assert_eq!(created_key["key"]["tenant_id"], "tenant-e2e");

    // A list call must never leak the hash or the secret.
    let listed = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        "",
    );
    assert!(!listed.contains(&secret));
    assert!(!listed.contains("key_hash"));

    // 3. The freshly created key authenticates and can call chat.completions
    // before any quota policy narrows it.
    let baseline = http_request(
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
        status_line(&baseline).contains("200 OK"),
        "baseline request should succeed before any quota policy applies: {baseline}"
    );

    // 4. Attach a project-scoped quota policy that narrows the model
    // allowlist to a model this key was never granted -- the effective
    // allowlist becomes the (empty) intersection, so every model is denied.
    let quota_models = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/quota-policies",
        &admin_headers(),
        r#"{"scope_type":"project","scope_id":"project-e2e","model_allowlist":["other-model"]}"#,
    ));
    assert_eq!(quota_models["policy"]["scope_type"], "project");

    let denied_by_allowlist = http_request(
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
        status_line(&denied_by_allowlist).contains("403"),
        "project quota policy must narrow the allowlist: {denied_by_allowlist}"
    );
    assert!(denied_by_allowlist.contains("model_not_allowed"));

    // 5. Replace the project policy with one that permits fast-chat again,
    // and add a tenant-scoped TPM cap tight enough that this single
    // request's estimated usage (~8 tokens) exceeds it.
    let replace_models = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        r#"{"model_allowlist":["fast-chat"]}"#,
    ));
    assert_eq!(
        replace_models["policy"]["model_allowlist"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The request below asks for max_tokens=4 (and near-zero prompt tokens
    // from an empty message list), so its estimated usage is ~4 tokens; a
    // tpm_limit of 2 is comfortably below that regardless of exact rounding
    // in the prompt-token estimator.
    let quota_tpm = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/quota-policies",
        &admin_headers(),
        r#"{"scope_type":"tenant","scope_id":"tenant-e2e","tpm_limit":2}"#,
    ));
    assert_eq!(quota_tpm["policy"]["tpm_limit"], 2);

    let denied_by_tpm = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[],"max_tokens":4}"#,
    );
    assert!(
        status_line(&denied_by_tpm).contains("429"),
        "tenant TPM policy tighter than the estimated usage must reject: {denied_by_tpm}"
    );
    assert!(denied_by_tpm.contains("tpm_limit_exceeded"));

    // 6. PATCH-disabling the tenant-level quota policy is a hard deny
    // regardless of RPM/TPM/model-allowlist specifics -- and, since PATCH
    // merges rather than replaces, the tpm_limit set in step 5 must survive
    // this call untouched (proving PATCH doesn't silently wipe it the way a
    // naive full-replace would).
    let disable = response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/quota-policies/tenant/tenant-e2e",
        &admin_headers(),
        r#"{"enabled":false}"#,
    ));
    assert_eq!(disable["policy"]["enabled"], false);
    assert_eq!(
        disable["policy"]["tpm_limit"], 2,
        "PATCH must merge, not replace: tpm_limit from step 5 must survive"
    );

    let denied_by_disabled_scope = http_request(
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
        status_line(&denied_by_disabled_scope).contains("403"),
        "disabling the tenant scope must hard-deny: {denied_by_disabled_scope}"
    );
    assert!(denied_by_disabled_scope.contains("quota_scope_disabled"));

    // 7. Clean up the tenant-level policy and confirm the key id survives a
    // GET, then delete the project-level policy and confirm 404 afterward.
    let get_key = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/virtual-keys/{key_id}"),
        &admin_headers(),
        "",
    ));
    assert_eq!(get_key["key"]["id"], key_id);
    assert!(get_key.get("secret").is_none() || get_key["secret"].is_null());

    let delete_response = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        "",
    );
    assert!(status_line(&delete_response).contains("200 OK"));

    let get_after_delete = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        "",
    );
    assert!(status_line(&get_after_delete).contains("404"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// --- issue #516: both branches of `authorize_scoped_resource` ------------
//
// `/admin/v1/quota-policies/{scope_type}/{scope_id}` is one of the two
// surfaces guarded by `crate::auth::authorize_scoped_resource`, and until
// #516 neither of that guard's two deny branches was held by a test in this
// suite: a test-gate mutation that made an *unresolvable* `scope_id` return
// `Ok(())` (fail open) left every suite in the crate green.
//
// Both branches are reachable over plain HTTP: a tenant-scoped caller is
// exactly the shape `provision_gateway_api_key` mints on every admin-console
// login, and it is modelled here by a static config key carrying
// `organization_id` (the same construction
// tests/tenant_isolation_admin_api.rs uses).

const QUOTA_ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];
const QUOTA_TENANT_A: [&str; 2] = [
    "Authorization: Bearer scope-a-secret",
    "Content-Type: application/json",
];
const QUOTA_TENANT_B: [&str; 2] = [
    "Authorization: Bearer scope-b-secret",
    "Content-Type: application/json",
];

/// Config for the two scope-authorization tests below: a platform-operator
/// key plus one tenant-scoped admin-console-shaped key per tenant. No
/// provider/model is needed -- these tests never leave the admin surface.
fn write_scope_auth_config(path: &std::path::Path, gateway_addr: &str) {
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
id = "scope-a-console"
name = "Tenant A admin-console session key"
key = "scope-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-scope-a"

[[api_keys]]
id = "scope-b-console"
name = "Tenant B admin-console session key"
key = "scope-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-scope-b"
"#
        ),
    )
    .unwrap();
}

fn bootstrap_scope_auth_tenants(gateway_addr: &str) {
    for tenant_id in ["tenant-scope-a", "tenant-scope-b"] {
        let registered = http_request(
            gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &QUOTA_ADMIN,
            &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
        );
        assert!(
            status_line(&registered).contains("200") || status_line(&registered).contains("201"),
            "tenant registration failed for {tenant_id}: {registered}"
        );
    }
}

/// Issue #516, branch 1 of `authorize_scoped_resource` -- **fail closed on an
/// unresolvable `scope_id`**.
///
/// A tenant-scoped caller names a project / workspace / virtual-key scope id
/// that does not exist at all. The guard cannot resolve an owning tenant, and
/// must deny: "nonexistent means safe to touch" is the wrong default, because
/// a dangling id today is a live id the moment some other tenant creates it
/// (and, on the PUT path, failing open would *create* a policy row keyed on
/// another tenant's future resource).
///
/// Mutation check: making the unresolvable case return `Ok(())` turns the GET
/// into a 404 `quota_policy_not_found` and the PUT into a 200 write, and this
/// test goes red on both.
#[test]
fn unresolvable_quota_policy_scope_id_is_denied_not_treated_as_absent() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_scope_auth_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    bootstrap_scope_auth_tenants(&gateway_addr);

    // Every scope kind that resolves through storage, with an id that was
    // never created by anyone.
    for scope_type in ["project", "workspace", "key"] {
        let read = http_request(
            &gateway_addr,
            "GET",
            &format!("/admin/v1/quota-policies/{scope_type}/dangling-{scope_type}-id"),
            &QUOTA_TENANT_A,
            "",
        );
        assert!(
            status_line(&read).contains("403"),
            "a tenant-scoped caller naming a nonexistent {scope_type} scope id must be denied \
             (fail closed), not fall through to the handler's not-found path: {read}"
        );
        assert!(
            read.contains("tenant_scope_denied"),
            "the denial must be the tenant-scope guard, not some other error: {read}"
        );

        let write = http_request(
            &gateway_addr,
            "PUT",
            &format!("/admin/v1/quota-policies/{scope_type}/dangling-{scope_type}-id"),
            &QUOTA_TENANT_A,
            r#"{"rpm_limit":1}"#,
        );
        assert!(
            status_line(&write).contains("403"),
            "writing a quota policy at a nonexistent {scope_type} scope id must be denied for a \
             tenant-scoped caller: {write}"
        );
        assert!(
            write.contains("tenant_scope_denied"),
            "the denial must be the tenant-scope guard, not some other error: {write}"
        );

        let delete = http_request(
            &gateway_addr,
            "DELETE",
            &format!("/admin/v1/quota-policies/{scope_type}/dangling-{scope_type}-id"),
            &QUOTA_TENANT_A,
            "",
        );
        assert!(
            status_line(&delete).contains("403"),
            "deleting a quota policy at a nonexistent {scope_type} scope id must be denied for a \
             tenant-scoped caller: {delete}"
        );
        assert!(delete.contains("tenant_scope_denied"), "{delete}");
    }

    // The denied PUTs must not have leaked a policy row into existence: the
    // platform operator, who bypasses the guard entirely, still sees nothing
    // at the dangling scope.
    let operator_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies/project/dangling-project-id",
        &QUOTA_ADMIN,
        "",
    );
    assert!(
        status_line(&operator_read).contains("404"),
        "the denied PUT must not have written a policy at the dangling scope: {operator_read}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #516, branch 2 of `authorize_scoped_resource` -- **deny when the
/// scope resolves to a different tenant**.
///
/// Tenant B names tenant A's project / workspace / virtual key. Resolution
/// succeeds, so the fail-closed branch above never fires; only the
/// owner-mismatch comparison stands between tenant B and tenant A's quota
/// policy. Failing open here is a real cross-tenant read *and* write on a
/// live policy row, not a 404.
///
/// Mutation check: making the resolved-owner-mismatch case return `Ok(())`
/// turns the GET into a 200 that hands tenant B tenant A's policy body, and
/// this test goes red.
#[test]
fn quota_policy_scope_owned_by_another_tenant_is_denied() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_scope_auth_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    bootstrap_scope_auth_tenants(&gateway_addr);

    // Tenant A's resource chain, built by the platform operator.
    let project = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &QUOTA_ADMIN,
        r#"{"id":"project-scope-a","tenant_id":"tenant-scope-a","name":"Project A","slug":"project-scope-a"}"#,
    ));
    assert_eq!(project["project"]["tenant_id"], "tenant-scope-a");
    let workspace = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &QUOTA_ADMIN,
        r#"{"id":"workspace-scope-a","project_id":"project-scope-a","name":"Workspace A","slug":"workspace-scope-a"}"#,
    ));
    assert_eq!(workspace["workspace"]["project_id"], "project-scope-a");
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &QUOTA_ADMIN,
        r#"{"name":"Tenant A key","workspace_id":"workspace-scope-a","scopes":["chat.completions"]}"#,
    ));
    assert_eq!(created_key["key"]["tenant_id"], "tenant-scope-a");
    let key_id = created_key["key"]["id"].as_str().unwrap().to_string();

    // A live quota policy at each of tenant A's scopes, so a fail-open guard
    // would hand tenant B a real policy body rather than a 404.
    for (scope_type, scope_id) in [
        ("tenant", "tenant-scope-a".to_string()),
        ("project", "project-scope-a".to_string()),
        ("workspace", "workspace-scope-a".to_string()),
        ("key", key_id.clone()),
    ] {
        let seeded = http_request(
            &gateway_addr,
            "PUT",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_ADMIN,
            r#"{"rpm_limit":11}"#,
        );
        assert!(
            status_line(&seeded).contains("200"),
            "operator must be able to seed tenant A's {scope_type} policy: {seeded}"
        );

        // Tenant A itself is still allowed through -- this is the guard's
        // Ok() arm, and it must not be collateral damage of the deny arms.
        let own_read = response_json(http_request(
            &gateway_addr,
            "GET",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_TENANT_A,
            "",
        ));
        assert_eq!(
            own_read["policy"]["rpm_limit"], 11,
            "tenant A must still read its own {scope_type} policy: {own_read}"
        );

        // Tenant B must not.
        let stolen_read = http_request(
            &gateway_addr,
            "GET",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_TENANT_B,
            "",
        );
        assert!(
            status_line(&stolen_read).contains("403"),
            "tenant B must not read a quota policy whose {scope_type} scope resolves to tenant A: \
             {stolen_read}"
        );
        assert!(
            stolen_read.contains("tenant_scope_denied"),
            "the denial must be the tenant-scope guard: {stolen_read}"
        );
        assert!(
            !stolen_read.contains("\"rpm_limit\":11"),
            "tenant A's policy body must never reach tenant B: {stolen_read}"
        );

        let stolen_write = http_request(
            &gateway_addr,
            "PATCH",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_TENANT_B,
            r#"{"rpm_limit":1}"#,
        );
        assert!(
            status_line(&stolen_write).contains("403"),
            "tenant B must not write a quota policy whose {scope_type} scope resolves to tenant \
             A: {stolen_write}"
        );
        assert!(
            stolen_write.contains("tenant_scope_denied"),
            "{stolen_write}"
        );

        let stolen_delete = http_request(
            &gateway_addr,
            "DELETE",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_TENANT_B,
            "",
        );
        assert!(
            status_line(&stolen_delete).contains("403"),
            "tenant B must not delete a quota policy whose {scope_type} scope resolves to tenant \
             A: {stolen_delete}"
        );
        assert!(
            stolen_delete.contains("tenant_scope_denied"),
            "{stolen_delete}"
        );

        // The denied DELETE must not have taken effect.
        let survives = response_json(http_request(
            &gateway_addr,
            "GET",
            &format!("/admin/v1/quota-policies/{scope_type}/{scope_id}"),
            &QUOTA_ADMIN,
            "",
        ));
        assert_eq!(
            survives["policy"]["rpm_limit"], 11,
            "tenant A's {scope_type} policy must survive tenant B's denied mutations: {survives}"
        );
    }

    // The list endpoint runs the same guard per row: tenant B sees none of
    // tenant A's four policies.
    let listed = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies",
        &QUOTA_TENANT_B,
        "",
    ));
    assert_eq!(
        listed["data"].as_array().unwrap().len(),
        0,
        "tenant B's quota-policy listing must not include tenant A's policies: {listed}"
    );
    let listed_a = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies",
        &QUOTA_TENANT_A,
        "",
    ));
    assert_eq!(
        listed_a["data"].as_array().unwrap().len(),
        4,
        "tenant A must still see all four of its own policies: {listed_a}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
