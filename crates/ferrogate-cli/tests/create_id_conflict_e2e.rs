// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Handler-level regression for issue #512: POST create IDs are
// insert-only and cannot reactivate or repoint existing hierarchy/key rows.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn admin(gateway_addr: &str, method: &str, path: &str, body: &str) -> String {
    http_request(gateway_addr, method, path, &ADMIN, body)
}

fn response_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn assert_status(response: &str, status: u16, context: &str) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{context}: {response}"
    );
}

fn assert_conflict(response: &str, code: &str) {
    assert_status(response, 409, "caller-supplied existing id must conflict");
    assert_eq!(response_json(response)["error"]["code"], code);
}

#[test]
fn post_create_cannot_reactivate_or_repoint_existing_ids() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    for request in [
        (
            "/admin/v1/tenant-accounts",
            r#"{"id":"tenant-conflict","name":"Tenant","slug":"tenant-conflict"}"#,
        ),
        (
            "/admin/v1/projects",
            r#"{"id":"project-original","tenant_id":"tenant-conflict","name":"Original project","slug":"project-original"}"#,
        ),
        (
            "/admin/v1/projects",
            r#"{"id":"project-destination","tenant_id":"tenant-conflict","name":"Destination project","slug":"project-destination"}"#,
        ),
        (
            "/admin/v1/workspaces",
            r#"{"id":"workspace-original","project_id":"project-original","name":"Original workspace","slug":"workspace-original"}"#,
        ),
        (
            "/admin/v1/workspaces",
            r#"{"id":"workspace-destination","project_id":"project-destination","name":"Destination workspace","slug":"workspace-destination"}"#,
        ),
    ] {
        assert_status(
            &admin(&gateway_addr, "POST", request.0, request.1),
            201,
            "hierarchy setup",
        );
    }

    let created_key = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"id":"key-original","name":"Original key","workspace_id":"workspace-original","scopes":["models.read"]}"#,
    );
    assert_status(&created_key, 201, "key setup");

    assert_status(
        &admin(
            &gateway_addr,
            "PUT",
            "/admin/v1/projects/project-original",
            r#"{"status":"disabled"}"#,
        ),
        200,
        "disable original project",
    );
    let duplicate_project = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"project-original","tenant_id":"tenant-conflict","name":"Replacement project","slug":"replacement-project","status":"active"}"#,
    );
    assert_conflict(&duplicate_project, "project_already_exists");
    let original_project = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/projects/project-original",
        "",
    ));
    assert_eq!(original_project["project"]["status"], "disabled");
    assert_eq!(original_project["project"]["name"], "Original project");

    assert_status(
        &admin(
            &gateway_addr,
            "PUT",
            "/admin/v1/workspaces/workspace-original",
            r#"{"status":"disabled"}"#,
        ),
        200,
        "disable original workspace",
    );
    let duplicate_workspace = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"workspace-original","project_id":"project-destination","name":"Replacement workspace","slug":"replacement-workspace","status":"active"}"#,
    );
    assert_conflict(&duplicate_workspace, "workspace_already_exists");
    let original_workspace = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/workspaces/workspace-original",
        "",
    ));
    assert_eq!(original_workspace["workspace"]["status"], "disabled");
    assert_eq!(
        original_workspace["workspace"]["project_id"],
        "project-original"
    );

    assert_status(
        &admin(
            &gateway_addr,
            "POST",
            "/admin/v1/virtual-keys/key-original/revoke",
            "",
        ),
        200,
        "revoke original key",
    );
    let duplicate_key = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"id":"key-original","name":"Replacement key","workspace_id":"workspace-destination","scopes":["models.read"]}"#,
    );
    assert_conflict(&duplicate_key, "virtual_key_already_exists");
    assert!(!response_json(&duplicate_key).to_string().contains("fg_"));
    let original_key = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/virtual-keys/key-original",
        "",
    ));
    assert_eq!(original_key["key"]["workspace_id"], "workspace-original");
    assert!(original_key["key"]["revoked_at_unix"].as_u64().is_some());

    let _ = gateway.kill();
    let _ = gateway.wait();
}
