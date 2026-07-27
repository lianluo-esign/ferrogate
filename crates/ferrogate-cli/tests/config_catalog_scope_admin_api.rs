// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: End-to-end regression coverage for issue #535 -- the siblings
// of #518. `GET /admin/v1/policies[/{name}]` and
// `GET /admin/v1/gateway-configs[/{id}]` authenticated and then DISCARDED the
// resulting AuthContext (`Ok(_) => { let body = AdminList::new(
// state.config.policies.clone()) }`), so any tenant-scoped `admin.read` key --
// the shape `provision_gateway_api_key` mints on every admin-console login --
// read every tenant's organization ids, project ids and api-key ids, plus the
// models/providers each is denied.
//
// Every assertion below is on the ROWS (and the ids inside them) a scoped
// caller actually receives, never on handler source text: revert any one of
// the four handlers to `Ok(_) => ...` and the matching assertion sees the
// out-of-scope rows come back and fails. Runs against a real gateway process
// with in-memory storage -- no Postgres, no Docker.

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

/// Static config carrying the multi-tenant selector shapes the scope helper
/// has to tell apart:
///
/// * `global-deny` -- no selectors at all: genuinely platform-wide, so every
///   caller sees it verbatim;
/// * `deny-tenant-a` / `deny-tenant-b` -- single-tenant rules;
/// * `deny-both-tenants` -- names A *and* B: A must see it (it is denied by
///   it) with B's id stripped out;
/// * `deny-key-b` -- an EMPTY `organization_ids` but a non-empty
///   `api_key_ids` naming only B's key. This is the case that separates
///   "empty selector = wildcard" from "narrowed to nothing": it must be
///   hidden from A, not rendered as a global rule;
/// * `deny-both-keys` -- names A's and B's key: visible to A with only A's;
/// * `deny-project-b` -- project selector naming a project A does not own.
///
/// Gateway profiles mirror the same three shapes (unrestricted / A's / B's).
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
scopes = ["admin.read"]
organization_id = "tenant-pol-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read"]
organization_id = "tenant-pol-b"

[[api_keys]]
id = "key-a-data"
name = "Tenant A data key"
key = "key-a-secret"
organization_id = "tenant-pol-a"
project_id = "project-pol-a"

[[api_keys]]
id = "key-b-data"
name = "Tenant B data key"
key = "key-b-secret"
organization_id = "tenant-pol-b"
project_id = "project-pol-b"

[[policies]]
name = "global-deny"
effect = "deny"
code = "global_denied"
message = "denied everywhere"

[[policies]]
name = "deny-tenant-a"
effect = "deny"
organization_ids = ["tenant-pol-a"]

[[policies]]
name = "deny-tenant-b"
effect = "deny"
organization_ids = ["tenant-pol-b"]

[[policies]]
name = "deny-both-tenants"
effect = "deny"
organization_ids = ["tenant-pol-a", "tenant-pol-b"]

[[policies]]
name = "deny-key-b"
effect = "deny"
api_key_ids = ["key-b-data"]

[[policies]]
name = "deny-both-keys"
effect = "deny"
api_key_ids = ["key-a-data", "key-b-data"]

[[policies]]
name = "deny-project-b"
effect = "deny"
project_ids = ["project-pol-b"]

[[gateway_configs]]
id = "profile-shared"
name = "Shared profile"
revision = 1
cache_enabled = true

[[gateway_configs]]
id = "profile-a"
name = "Tenant A profile"
revision = 1
cache_enabled = true
api_key_ids = ["key-a-data"]

[[gateway_configs]]
id = "profile-b"
name = "Tenant B profile"
revision = 1
cache_enabled = false
api_key_ids = ["key-b-data"]
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

/// The `data` array of a list response as a plain `Vec<String>` of one field
/// -- the assertions below compare ROW SETS by identity, never counts.
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

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .map(|entry| entry.as_str().unwrap_or_default().to_string())
        .collect()
}

fn row_named<'a>(body: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list response has no data array: {body}"))
        .iter()
        .find(|row| row["name"] == name || row["id"] == name)
        .unwrap_or_else(|| panic!("row {name} is missing from {body}"))
}

fn start(dir: &tempfile::TempDir) -> (std::process::Child, String) {
    let gateway_addr = free_addr();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);
    let gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    (gateway, gateway_addr)
}

/// Site 1 -- `GET /admin/v1/policies` (local.rs:8589 in the issue). Before the
/// fix this returned EVERY `PolicyRule` verbatim to a tenant-scoped key.
#[test]
fn tenant_scoped_key_lists_only_policies_that_can_act_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_A, "");
    // The blunt cross-tenant assertion first: tenant B's ids must not appear
    // ANYWHERE in the payload, in any field, in any rule.
    assert!(
        !raw.contains("tenant-pol-b"),
        "tenant A's policy list leaked tenant B's organization id: {raw}"
    );
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's policy list leaked tenant B's api key id: {raw}"
    );
    assert!(
        !raw.contains("project-pol-b"),
        "tenant A's policy list leaked tenant B's project id: {raw}"
    );

    let names = listed_field(raw.clone(), "name");
    assert_eq!(
        names,
        vec![
            "global-deny".to_string(),
            "deny-tenant-a".to_string(),
            "deny-both-tenants".to_string(),
            "deny-both-keys".to_string(),
        ],
        "tenant A must see exactly the rules that can act on tenant A"
    );

    let body = response_json(raw);
    // A rule naming both tenants stays visible -- A is denied by it -- but is
    // rendered with only A's id.
    assert_eq!(
        string_list(&row_named(&body, "deny-both-tenants")["organization_ids"]),
        vec!["tenant-pol-a".to_string()],
        "the shared rule still names another tenant"
    );
    // ...and a rule naming both keys keeps only A's key id.
    assert_eq!(
        string_list(&row_named(&body, "deny-both-keys")["api_key_ids"]),
        vec!["key-a-data".to_string()],
        "the shared rule still names another tenant's api key"
    );
    // The genuinely global rule is unchanged: empty selectors are a wildcard,
    // not something to narrow away.
    assert!(
        string_list(&row_named(&body, "global-deny")["organization_ids"]).is_empty(),
        "the global rule gained a selector"
    );
    assert_eq!(row_named(&body, "global-deny")["code"], "global_denied");

    // The symmetric half: B's view is B's, not a copy of A's, so the filter is
    // keyed on the CALLER.
    let tenant_b = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_B, "");
    assert!(
        !tenant_b.contains("tenant-pol-a") && !tenant_b.contains("key-a-data"),
        "tenant B's policy list leaked tenant A's ids: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "name"),
        vec![
            "global-deny".to_string(),
            "deny-tenant-b".to_string(),
            "deny-both-tenants".to_string(),
            "deny-key-b".to_string(),
            "deny-both-keys".to_string(),
            "deny-project-b".to_string(),
        ],
        "tenant B must see exactly the rules that can act on tenant B"
    );

    // And the platform operator still gets every rule verbatim, so the fix is
    // a scoping of the view and not a blanket deny.
    let operator = http_request(&addr, "GET", "/admin/v1/policies", &ADMIN, "");
    let operator_body = response_json(operator.clone());
    assert_eq!(
        listed_field(operator, "name").len(),
        7,
        "platform operator lost rules from the full catalog"
    );
    assert_eq!(
        string_list(&row_named(&operator_body, "deny-both-tenants")["organization_ids"]),
        vec!["tenant-pol-a".to_string(), "tenant-pol-b".to_string()],
        "platform operator received a narrowed rule"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 2 -- `GET /admin/v1/policies/{name}`. Names came free from the list,
/// so the by-id read was the second half of an enumeration primitive; it must
/// answer identically for out-of-scope and nonexistent.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_policy_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-tenant-a",
        &TENANT_A,
        "",
    ));
    assert_eq!(own["policy"]["name"], "deny-tenant-a");
    assert_eq!(
        string_list(&own["policy"]["organization_ids"]),
        vec!["tenant-pol-a".to_string()]
    );

    // The by-id read narrows exactly like the list does.
    let shared = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-both-tenants",
        &TENANT_A,
        "",
    ));
    assert_eq!(
        string_list(&shared["policy"]["organization_ids"]),
        vec!["tenant-pol-a".to_string()],
        "the by-id read returned another tenant's id"
    );

    for name in [
        "deny-tenant-b",
        "deny-key-b",
        "deny-project-b",
        "policy-that-does-not-exist",
    ] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused policy {name}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for policy {name}: {response}"
        );
        assert!(
            !response.contains("tenant-pol-b") && !response.contains("key-b-data"),
            "the refusal for {name} still leaked tenant B's ids: {response}"
        );
    }

    // The platform operator still reads any rule by name...
    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-tenant-b",
        &ADMIN,
        "",
    ));
    assert_eq!(
        string_list(&operator["policy"]["organization_ids"]),
        vec!["tenant-pol-b".to_string()]
    );

    // ...and still gets 404, NOT 403, for a name that genuinely does not
    // exist. This is what pins the `&& !scope.is_full()` clause on this
    // handler: delete it and the operator gets `tenant_scope_denied` here
    // while every scope assertion above still passes, which is exactly how
    // #518's reviewer found the same clause unpinned.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/policies/policy-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent policy, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("policy_not_found"),
        "operator 404 must name policy_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 3 -- `GET /admin/v1/gateway-configs` (leak 2: per-profile
/// `api_key_ids` across tenants).
#[test]
fn tenant_scoped_key_lists_only_gateway_profiles_its_keys_may_select() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/gateway-configs", &TENANT_A, "");
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's gateway-config list leaked tenant B's api key id: {raw}"
    );
    assert_eq!(
        listed_field(raw.clone(), "id"),
        vec!["profile-shared".to_string(), "profile-a".to_string()],
        "tenant A must see only the profiles one of its own keys may select"
    );
    let body = response_json(raw);
    assert_eq!(
        string_list(&row_named(&body, "profile-a")["api_key_ids"]),
        vec!["key-a-data".to_string()]
    );
    assert!(
        string_list(&row_named(&body, "profile-shared")["api_key_ids"]).is_empty(),
        "the unrestricted profile gained a key selector"
    );

    let tenant_b = http_request(&addr, "GET", "/admin/v1/gateway-configs", &TENANT_B, "");
    assert!(
        !tenant_b.contains("key-a-data"),
        "tenant B's gateway-config list leaked tenant A's api key id: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "id"),
        vec!["profile-shared".to_string(), "profile-b".to_string()]
    );

    let operator = http_request(&addr, "GET", "/admin/v1/gateway-configs", &ADMIN, "");
    assert_eq!(
        listed_field(operator, "id"),
        vec![
            "profile-shared".to_string(),
            "profile-a".to_string(),
            "profile-b".to_string(),
        ],
        "platform operator lost profiles from the full catalog"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 4 -- `GET /admin/v1/gateway-configs/{id}`.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_gateway_profile_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-a",
        &TENANT_A,
        "",
    ));
    assert_eq!(own["gateway_config"]["id"], "profile-a");
    assert_eq!(
        string_list(&own["gateway_config"]["api_key_ids"]),
        vec!["key-a-data".to_string()]
    );

    for id in ["profile-b", "profile-that-does-not-exist"] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused gateway profile {id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for gateway profile {id}: {response}"
        );
        assert!(
            !response.contains("key-b-data"),
            "the refusal for {id} still leaked tenant B's api key id: {response}"
        );
    }

    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-b",
        &ADMIN,
        "",
    ));
    assert_eq!(
        string_list(&operator["gateway_config"]["api_key_ids"]),
        vec!["key-b-data".to_string()]
    );

    // Sibling of the policy assertion: the operator still gets 404, NOT 403,
    // for an absent id -- this pins `&& !scope.is_full()` on this handler.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent gateway profile, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("gateway_config_not_found"),
        "operator 404 must name gateway_config_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
