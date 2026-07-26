// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Live regression for issue #340 acceptance box 4 -- "cross-tenant
// combinations are blocked client-side AND rejected authoritatively by the
// API". Before this landed, `api_key_from_mutation` copied `project_id` and
// `workspace_id` verbatim and the POST/PUT handler ran no existence, parenting,
// or tenant check: the exact request in
// `cross_project_workspace_pair_is_rejected_on_update` returned 200 and
// persisted project A paired with a workspace owned by project B (a different
// tenant). Runs against a real gateway process with in-memory storage, matching
// tests/tenant_isolation_admin_api.rs's convention.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
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
"#
        ),
    )
    .unwrap();
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn body_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn post(gateway_addr: &str, path: &str, body: &str) -> String {
    http_request(gateway_addr, "POST", path, &ADMIN, body)
}

fn seed_two_tenant_hierarchies(gateway_addr: &str) {
    for tenant in ["tenant-key-a", "tenant-key-b"] {
        let response = post(
            gateway_addr,
            "/admin/v1/tenant-accounts",
            &format!(r#"{{"id":"{tenant}","name":"{tenant}","slug":"{tenant}"}}"#),
        );
        assert!(
            status_line(&response).contains("200") || status_line(&response).contains("201"),
            "tenant {tenant} setup failed: {response}"
        );
    }
    for (project, tenant) in [
        ("project-key-a", "tenant-key-a"),
        ("project-key-b", "tenant-key-b"),
    ] {
        let response = post(
            gateway_addr,
            "/admin/v1/projects",
            &format!(
                r#"{{"id":"{project}","tenant_id":"{tenant}","name":"{project}","slug":"{project}"}}"#
            ),
        );
        assert!(
            status_line(&response).contains("201"),
            "project {project} setup failed: {response}"
        );
    }
    for (workspace, project) in [
        ("workspace-key-a", "project-key-a"),
        ("workspace-key-b", "project-key-b"),
    ] {
        let response = post(
            gateway_addr,
            "/admin/v1/workspaces",
            &format!(
                r#"{{"id":"{workspace}","project_id":"{project}","name":"{workspace}","slug":"{workspace}"}}"#
            ),
        );
        assert!(
            status_line(&response).contains("201"),
            "workspace {workspace} setup failed: {response}"
        );
    }
}

/// The reviewer's reproduction, verbatim: create a key that is legally scoped to
/// project A + workspace A, then PUT project A paired with project B's
/// workspace. That update must be refused and must not overwrite the stored
/// pair.
#[test]
fn cross_project_workspace_pair_is_rejected_on_update() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    seed_two_tenant_hierarchies(&gateway_addr);

    let created = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k1","name":"Scoped key","key":"k1-secret","organization_id":"tenant-key-a","project_id":"project-key-a","workspace_id":"workspace-key-a"}"#,
    );
    assert!(
        status_line(&created).contains("201"),
        "a consistent project+workspace pair must be accepted: {created}"
    );

    // The secret is repeated so the pre-existing "key_env, key, or key_hash is
    // required" rejection cannot stand in for the tenancy one: without the #340
    // check this exact request returns 200 and persists the cross-project pair.
    let rejected = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/api-keys/k1",
        &ADMIN,
        r#"{"id":"k1","name":"Scoped key","key":"k1-secret","project_id":"project-key-a","workspace_id":"workspace-key-b"}"#,
    );
    assert!(
        status_line(&rejected).contains("400"),
        "project A + project B's workspace must be rejected: {rejected}"
    );
    let error = body_json(&rejected);
    assert_eq!(error["error"]["code"], "invalid_api_key");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("workspace-key-b"),
        "rejection must name the offending workspace: {rejected}"
    );

    // The stored key still carries the original, valid pair -- the refused
    // update never reached the runtime snapshot.
    let stored = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/k1",
        &ADMIN,
        "",
    ));
    assert_eq!(stored["key"]["project_id"], "project-key-a");
    assert_eq!(stored["key"]["workspace_id"], "workspace-key-a");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The remaining rejection edge on the create path -- a project owned by a
/// different tenant than the key's `organization_id` -- plus the deliberate
/// non-rejections: a reference that names no control-plane row, and a key with
/// no hierarchy reference at all.
#[test]
fn create_rejects_cross_tenant_pairs_but_tolerates_dangling_references() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    seed_two_tenant_hierarchies(&gateway_addr);

    let cross_tenant = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-cross","name":"Cross tenant","key":"s","organization_id":"tenant-key-a","project_id":"project-key-b"}"#,
    );
    assert!(
        status_line(&cross_tenant).contains("400"),
        "a project owned by another tenant must be rejected: {cross_tenant}"
    );
    assert_eq!(
        body_json(&cross_tenant)["error"]["code"],
        "invalid_api_key",
        "{cross_tenant}"
    );

    // The rejected key never reached the runtime snapshot.
    let lookup = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/k-cross",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&lookup).contains("404"),
        "the rejected key must not have been persisted: {lookup}"
    );

    // A reference that names no control-plane row is NOT a cross-tenant
    // combination: the same key is declarable in ferrogate.toml, where
    // `Config::validate` performs no storage lookup, so refusing it here would
    // make the admin API stricter than the config path. It is accepted and
    // reported (audit event + operator warning) instead.
    let dangling = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-ghost","name":"Dangling project","key":"s","project_id":"project-ghost"}"#,
    );
    assert!(
        status_line(&dangling).contains("201"),
        "an unresolvable project reference must not be refused: {dangling}"
    );
    let audit = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &ADMIN,
        "",
    ));
    let warned = audit["data"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["target"] == "k-ghost"
                    && event["outcome"] == "warning"
                    && event["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("project-ghost")
            })
        })
        .unwrap_or(false);
    assert!(
        warned,
        "an unresolvable reference must leave audit evidence: {audit}"
    );

    // A key that references no project/workspace at all stays legal: this
    // validation constrains the combination, it does not make the control-plane
    // hierarchy mandatory for native keys.
    let unscoped = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-unscoped","name":"Unscoped","key":"s","organization_id":"tenant-key-a"}"#,
    );
    assert!(
        status_line(&unscoped).contains("201"),
        "a key without hierarchy references must still be accepted: {unscoped}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
