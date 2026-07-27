// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: End-to-end regression coverage for issue #518 -- the four
// `admin.read` GETs under /admin/v1/permissions* and /admin/v1/roles*
// authenticated and then DISCARDED the resulting AuthContext
// (`Ok(_) => match state.list_roles()`), so any tenant-scoped admin.read
// key read the platform's entire RBAC catalog: every role name, every
// permission key, and how the two compose. Live-probed on a tenant-a key:
// GET /admin/v1/permissions and GET /admin/v1/roles both returned 200 with
// the full global catalog.
//
// Every assertion below is on the ROWS a scoped caller actually receives,
// never on handler source text or a query string: revert any one of the
// four handlers to `Ok(_) => ...` and the corresponding assertion sees the
// out-of-scope rows come back and fails. Runs against a real gateway
// process with in-memory storage -- no Postgres, no Docker (matching
// tests/tenant_isolation_admin_api.rs's convention).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

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
organization_id = "tenant-cat-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-cat-b"
"#
        ),
    )
    .unwrap();
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

/// Creates a permission through the platform-operator key, returning its id.
fn create_permission(gateway_addr: &str, key: &str) -> String {
    let created = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &ADMIN,
        &format!(r#"{{"key":"{key}","name":"{key}"}}"#),
    ));
    created["permission"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("permission {key} was not created: {created}"))
        .to_string()
}

/// Creates a role bundling `permission_key`, returning its id.
fn create_role(gateway_addr: &str, slug: &str, permission_key: &str) -> String {
    let created = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/roles",
        &ADMIN,
        &format!(r#"{{"name":"{slug}","slug":"{slug}","permission_keys":["{permission_key}"]}}"#),
    ));
    created["role"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("role {slug} was not created: {created}"))
        .to_string()
}

fn bind_role(gateway_addr: &str, tenant_id: &str, role_id: &str) {
    let bind = http_request(
        gateway_addr,
        "POST",
        &format!("/admin/v1/tenant-roles/{tenant_id}"),
        &ADMIN,
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(
        bind.contains("HTTP/1.1 200"),
        "binding role {role_id} to {tenant_id} failed: {bind}"
    );
}

/// The `data` array of a list response, as a plain `Vec<String>` of one
/// field -- the assertions below compare ROW SETS, not response text.
fn listed_field(response: String, field: &str) -> Vec<String> {
    let body = response_json(response);
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list response has no data array: {body}"))
        .iter()
        .map(|row| {
            row[field]
                .as_str()
                .unwrap_or_else(|| panic!("row is missing {field}: {row}"))
                .to_string()
        })
        .collect()
}

struct Catalog {
    alpha_permission_id: String,
    beta_permission_id: String,
    orphan_permission_id: String,
    alpha_role_id: String,
    beta_role_id: String,
    orphan_role_id: String,
}

/// Seeds a three-role / three-permission catalog: one role reachable by
/// tenant A, one by tenant B, and one bound to nobody at all. The orphan
/// pair is what makes the test non-vacuous for the "platform operator keeps
/// the full catalog" half -- it is visible ONLY to the operator.
fn seed_catalog(gateway_addr: &str) -> Catalog {
    let alpha_permission_id = create_permission(gateway_addr, "catalog.alpha");
    let beta_permission_id = create_permission(gateway_addr, "catalog.beta");
    let orphan_permission_id = create_permission(gateway_addr, "catalog.orphan");

    let alpha_role_id = create_role(gateway_addr, "catalog-alpha", "catalog.alpha");
    let beta_role_id = create_role(gateway_addr, "catalog-beta", "catalog.beta");
    let orphan_role_id = create_role(gateway_addr, "catalog-orphan", "catalog.orphan");

    bind_role(gateway_addr, "tenant-cat-a", &alpha_role_id);
    bind_role(gateway_addr, "tenant-cat-b", &beta_role_id);

    Catalog {
        alpha_permission_id,
        beta_permission_id,
        orphan_permission_id,
        alpha_role_id,
        beta_role_id,
        orphan_role_id,
    }
}

fn start(dir: &tempfile::TempDir) -> (std::process::Child, String, Catalog) {
    let gateway_addr = free_addr();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);
    let gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    register_tenant(&gateway_addr, "tenant-cat-a");
    register_tenant(&gateway_addr, "tenant-cat-b");
    let catalog = seed_catalog(&gateway_addr);
    (gateway, gateway_addr, catalog)
}

/// Site 1 -- `GET /admin/v1/roles` (rbac.rs:369 in the issue). Before the
/// fix this returned EVERY role, permission_keys and all, to a tenant-scoped
/// key. Now tenant A sees exactly the one role bound to tenant A.
#[test]
fn tenant_scoped_key_lists_only_its_own_bound_roles() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr, catalog) = start(&dir);

    let tenant_a_roles = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &TENANT_A, ""),
        "id",
    );
    assert_eq!(
        tenant_a_roles,
        vec![catalog.alpha_role_id.clone()],
        "tenant A must see only the role bound to tenant A"
    );
    assert!(
        !tenant_a_roles.contains(&catalog.beta_role_id),
        "tenant A received tenant B's role: {tenant_a_roles:?}"
    );
    assert!(
        !tenant_a_roles.contains(&catalog.orphan_role_id),
        "tenant A received an unbound platform role: {tenant_a_roles:?}"
    );

    // The symmetric half: B's view is B's, not a copy of A's -- so the
    // filter is keyed on the CALLER, not on some fixed subset.
    let tenant_b_roles = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &TENANT_B, ""),
        "id",
    );
    assert_eq!(
        tenant_b_roles,
        vec![catalog.beta_role_id.clone()],
        "tenant B must see only the role bound to tenant B"
    );

    // And the platform operator still gets the whole catalog, so the fix
    // is a scoping of the view and not a blanket deny.
    let operator_roles = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &ADMIN, ""),
        "id",
    );
    for role_id in [
        &catalog.alpha_role_id,
        &catalog.beta_role_id,
        &catalog.orphan_role_id,
    ] {
        assert!(
            operator_roles.contains(role_id),
            "platform operator lost role {role_id} from the full catalog: {operator_roles:?}"
        );
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 2 -- `GET /admin/v1/permissions` (rbac.rs:44). Before the fix this
/// returned the whole permission-key catalog to a tenant-scoped key.
#[test]
fn tenant_scoped_key_lists_only_permissions_its_roles_compose() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr, catalog) = start(&dir);

    let tenant_a_keys = listed_field(
        http_request(&addr, "GET", "/admin/v1/permissions", &TENANT_A, ""),
        "key",
    );
    assert_eq!(
        tenant_a_keys,
        vec!["catalog.alpha".to_string()],
        "tenant A must see only the permission keys its bound roles compose"
    );
    assert!(
        !tenant_a_keys.contains(&"catalog.beta".to_string()),
        "tenant A received tenant B's permission key: {tenant_a_keys:?}"
    );
    assert!(
        !tenant_a_keys.contains(&"catalog.orphan".to_string()),
        "tenant A received an unreachable permission key: {tenant_a_keys:?}"
    );
    let tenant_a_permission_ids = listed_field(
        http_request(&addr, "GET", "/admin/v1/permissions", &TENANT_A, ""),
        "id",
    );
    assert_eq!(
        tenant_a_permission_ids,
        vec![catalog.alpha_permission_id.clone()],
        "tenant A received out-of-scope permission rows: {tenant_a_permission_ids:?}"
    );

    let tenant_b_keys = listed_field(
        http_request(&addr, "GET", "/admin/v1/permissions", &TENANT_B, ""),
        "key",
    );
    assert_eq!(
        tenant_b_keys,
        vec!["catalog.beta".to_string()],
        "tenant B must see only the permission keys its bound roles compose"
    );

    let operator_keys = listed_field(
        http_request(&addr, "GET", "/admin/v1/permissions", &ADMIN, ""),
        "key",
    );
    for key in ["catalog.alpha", "catalog.beta", "catalog.orphan"] {
        assert!(
            operator_keys.contains(&key.to_string()),
            "platform operator lost permission {key} from the full catalog: {operator_keys:?}"
        );
    }

    // The `search` filter must not be a bypass: it runs AFTER the scope
    // filter, so searching for another tenant's key still returns nothing.
    let searched = listed_field(
        http_request(
            &addr,
            "GET",
            "/admin/v1/permissions?search=catalog.beta",
            &TENANT_A,
            "",
        ),
        "key",
    );
    assert!(
        searched.is_empty(),
        "search let tenant A pull tenant B's permission key back out: {searched:?}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 3 -- `GET /admin/v1/roles/{id}` (rbac.rs:435). A scoped list is
/// worthless if the by-id read can be walked to rebuild the same catalog.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_role_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr, catalog) = start(&dir);

    // Its own bound role: readable, permission_keys and all.
    let own = response_json(http_request(
        &addr,
        "GET",
        &format!("/admin/v1/roles/{}", catalog.alpha_role_id),
        &TENANT_A,
        "",
    ));
    assert_eq!(own["role"]["id"], catalog.alpha_role_id.as_str());
    assert_eq!(own["role"]["permission_keys"][0], "catalog.alpha");

    // Another tenant's role, and an unbound platform role: refused, and
    // refused the SAME way as a role that does not exist at all, so the
    // endpoint is not an existence oracle for the catalog.
    for role_id in [
        catalog.beta_role_id.as_str(),
        catalog.orphan_role_id.as_str(),
        "role-that-does-not-exist",
    ] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/roles/{role_id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused role {role_id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for role {role_id}: {response}"
        );
        assert!(
            !response.contains("catalog.beta") && !response.contains("catalog.orphan"),
            "refusal for role {role_id} still leaked permission keys: {response}"
        );
    }

    // The platform operator still reads any role by id.
    let operator = response_json(http_request(
        &addr,
        "GET",
        &format!("/admin/v1/roles/{}", catalog.orphan_role_id),
        &ADMIN,
        "",
    ));
    assert_eq!(operator["role"]["permission_keys"][0], "catalog.orphan");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 4 -- `GET /admin/v1/permissions/{id}` (rbac.rs:131).
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_permission_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr, catalog) = start(&dir);

    let own = response_json(http_request(
        &addr,
        "GET",
        &format!("/admin/v1/permissions/{}", catalog.alpha_permission_id),
        &TENANT_A,
        "",
    ));
    assert_eq!(own["permission"]["key"], "catalog.alpha");

    for permission_id in [
        catalog.beta_permission_id.as_str(),
        catalog.orphan_permission_id.as_str(),
        "permission-that-does-not-exist",
    ] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/permissions/{permission_id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused permission {permission_id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for permission {permission_id}: {response}"
        );
        assert!(
            !response.contains("catalog.beta") && !response.contains("catalog.orphan"),
            "refusal for permission {permission_id} still leaked the key: {response}"
        );
    }

    let operator = response_json(http_request(
        &addr,
        "GET",
        &format!("/admin/v1/permissions/{}", catalog.orphan_permission_id),
        &ADMIN,
        "",
    ));
    assert_eq!(operator["permission"]["key"], "catalog.orphan");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The catalog view must track BINDINGS, not be a static allowlist: unbind
/// tenant A's role and the same key stops seeing it, with no restart. This
/// is what makes the scope genuinely derived from the AuthContext plus live
/// state rather than from anything baked in at startup.
#[test]
fn catalog_view_follows_the_tenants_live_role_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr, catalog) = start(&dir);

    let before = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &TENANT_A, ""),
        "id",
    );
    assert_eq!(before, vec![catalog.alpha_role_id.clone()]);

    let unbind = http_request(
        &addr,
        "DELETE",
        &format!(
            "/admin/v1/tenant-roles/tenant-cat-a/{}",
            catalog.alpha_role_id
        ),
        &ADMIN,
        "",
    );
    assert!(unbind.contains("HTTP/1.1 200"), "unbind failed: {unbind}");

    let after = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &TENANT_A, ""),
        "id",
    );
    assert!(
        after.is_empty(),
        "tenant A still sees roles after its only binding was removed: {after:?}"
    );

    let permissions_after = listed_field(
        http_request(&addr, "GET", "/admin/v1/permissions", &TENANT_A, ""),
        "key",
    );
    assert!(
        permissions_after.is_empty(),
        "tenant A still sees permission keys after its only binding was removed: {permissions_after:?}"
    );

    // The rows are still there for the operator -- the tenant's view
    // narrowed, the catalog itself did not shrink.
    let operator_roles = listed_field(
        http_request(&addr, "GET", "/admin/v1/roles", &ADMIN, ""),
        "id",
    );
    assert!(
        operator_roles.contains(&catalog.alpha_role_id),
        "the role was deleted rather than merely unbound: {operator_roles:?}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
