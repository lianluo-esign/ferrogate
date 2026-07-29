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

    let original_tenant = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-conflict",
        "",
    ))["tenant"]
        .clone();
    let duplicate_tenant = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-conflict","name":"Replacement tenant","slug":"replacement-tenant","status":"suspended","plan_id":"free"}"#,
    );
    assert_conflict(&duplicate_tenant, "tenant_account_already_exists");
    let tenant_after_duplicate = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-conflict",
        "",
    ))["tenant"]
        .clone();
    assert_eq!(
        tenant_after_duplicate, original_tenant,
        "duplicate tenant-account POST must not mutate the existing row"
    );
    let updated_tenant = admin(
        &gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/tenant-conflict",
        r#"{"name":"Tenant updated by PATCH"}"#,
    );
    assert_status(&updated_tenant, 200, "tenant PATCH remains the update path");
    assert_eq!(
        response_json(&updated_tenant)["tenant"]["name"],
        "Tenant updated by PATCH"
    );

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

    let created_schedule = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/agent-schedules",
        r#"{"id":"schedule-original","tenant_id":"tenant-conflict","workspace_id":"workspace-destination","name":"Original schedule","spec_kind":"interval","interval_secs":3600,"target_kind":"self_hosted_dispatch","target":{"required_capabilities":["shell"],"workload_ref":"original-workload"}}"#,
    );
    assert_status(&created_schedule, 201, "schedule setup");
    let original_schedule = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-schedules/schedule-original",
        "",
    ))["agent_schedule"]
        .clone();
    let fire_history_before_duplicate = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-schedules/schedule-original/fires",
        "",
    ))["data"]
        .clone();
    assert_eq!(
        fire_history_before_duplicate.as_array().map(Vec::len),
        Some(0)
    );
    let duplicate_schedule = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/agent-schedules",
        r#"{"id":"schedule-original","tenant_id":"tenant-conflict","workspace_id":"workspace-original","name":"Replacement schedule","spec_kind":"interval","interval_secs":60,"target_kind":"self_hosted_dispatch","target":{"required_capabilities":["shell"],"workload_ref":"replacement-workload"}}"#,
    );
    assert_conflict(&duplicate_schedule, "agent_schedule_already_exists");
    let schedule_after_duplicate = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-schedules/schedule-original",
        "",
    ))["agent_schedule"]
        .clone();
    assert_eq!(
        schedule_after_duplicate, original_schedule,
        "duplicate agent-schedule POST must not mutate the existing row"
    );
    let fire_history_after_duplicate = response_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/agent-schedules/schedule-original/fires",
        "",
    ))["data"]
        .clone();
    assert_eq!(
        fire_history_after_duplicate, fire_history_before_duplicate,
        "duplicate agent-schedule POST must not alter dispatch/fire state"
    );
    let patched_schedule = admin(
        &gateway_addr,
        "PATCH",
        "/admin/v1/agent-schedules/schedule-original",
        r#"{"enabled":false}"#,
    );
    assert_status(
        &patched_schedule,
        200,
        "agent schedule PATCH remains the update path",
    );
    assert_eq!(
        response_json(&patched_schedule)["agent_schedule"]["enabled"],
        false
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
