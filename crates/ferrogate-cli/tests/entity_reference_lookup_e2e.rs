// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-21
// description: Runtime proof for the paginated, searchable Admin API lookup
// contract consumed by the Admin Console entity-reference picker (#337).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn post(gateway_addr: &str, path: &str, body: &str) -> serde_json::Value {
    let response = http_request(gateway_addr, "POST", path, &ADMIN, body);
    assert!(
        response.contains("HTTP/1.1 200") || response.contains("HTTP/1.1 201"),
        "POST {path} failed: {response}"
    );
    response_json(response)
}

#[test]
fn entity_reference_collections_filter_search_and_page_at_the_gateway_boundary() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config_path,
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

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    post(
        &gateway_addr,
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-acme","name":"Acme Corporation","slug":"acme"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-globex","name":"Globex Corporation","slug":"globex"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/projects",
        r#"{"id":"project-acme-prod","tenant_id":"tenant-acme","name":"Production","slug":"prod"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/projects",
        r#"{"id":"project-globex-prod","tenant_id":"tenant-globex","name":"Production","slug":"prod"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/workspaces",
        r#"{"id":"workspace-acme-us","project_id":"project-acme-prod","name":"US East","slug":"us-east"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/workspaces",
        r#"{"id":"workspace-globex-eu","project_id":"project-globex-prod","name":"EU West","slug":"eu-west"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/permissions",
        r#"{"id":"permission-admin-read","key":"admin.read","name":"Read administration","description":"Read resources"}"#,
    );
    post(
        &gateway_addr,
        "/admin/v1/permissions",
        r#"{"id":"permission-admin-write","key":"admin.write","name":"Write administration","description":"Write resources"}"#,
    );

    let tenants = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts?search=globex&offset=0&limit=1",
        &ADMIN,
        "",
    ));
    assert_eq!(tenants["total"], 1);
    assert_eq!(tenants["offset"], 0);
    assert_eq!(tenants["limit"], 1);
    assert_eq!(tenants["data"][0]["id"], "tenant-globex");

    let projects = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/projects?tenant_id=tenant-acme&search=production&offset=0&limit=20",
        &ADMIN,
        "",
    ));
    assert_eq!(projects["total"], 1);
    assert_eq!(projects["data"][0]["id"], "project-acme-prod");

    let workspaces = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/workspaces?project_id=project-acme-prod&search=east&offset=0&limit=20",
        &ADMIN,
        "",
    ));
    assert_eq!(workspaces["total"], 1);
    assert_eq!(workspaces["data"][0]["id"], "workspace-acme-us");

    let permissions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/permissions?search=write&offset=0&limit=20",
        &ADMIN,
        "",
    ));
    assert_eq!(permissions["total"], 1);
    assert_eq!(permissions["data"][0]["key"], "admin.write");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
