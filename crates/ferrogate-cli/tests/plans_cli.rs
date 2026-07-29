// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for `ferrogate plans create/list/assign`
// (issue #168) -- runs the real CLI binary (not a library call) against a
// real gateway process, then independently verifies the resulting state
// through the raw admin HTTP surface (not just trusting the CLI's own
// stdout).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin bootstrap key"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true
"#
        ),
    )
    .unwrap();
}

fn run_cli(args: &[&str]) -> std::process::Output {
    support::ferrogate_command()
        .args(args)
        .output()
        .expect("failed to run the ferrogate CLI binary")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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

#[test]
fn plans_cli_create_list_and_assign_round_trip_through_the_admin_api() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let gateway_url = format!("http://{gateway_addr}");

    // Bootstrap a tenant over the raw admin HTTP surface (not the CLI --
    // this test exercises the plans CLI, not tenant bootstrap).
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-plans-cli","name":"Tenant Plans CLI","slug":"tenant-plans-cli"}"#,
    ));
    assert_eq!(tenant["tenant"]["plan_id"], "free");

    // create
    let create = run_cli(&[
        "plans",
        "create",
        "--id",
        "enterprise",
        "--name",
        "Enterprise",
        "--slug",
        "enterprise",
        "--mcp-enabled",
        "--self-hosted-workers-enabled",
        "--default-rpm-limit",
        "5000",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "admin-secret",
    ]);
    assert!(
        create.status.success(),
        "create failed: {}",
        stderr(&create)
    );
    let create_body: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(create_body["plan"]["id"], "enterprise");
    assert_eq!(create_body["plan"]["mcp_enabled"], true);
    assert_eq!(create_body["plan"]["default_rpm_limit"], 5000);

    // list
    let list = run_cli(&[
        "plans",
        "list",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "admin-secret",
    ]);
    assert!(list.status.success(), "list failed: {}", stderr(&list));
    let list_body: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let plan_ids: Vec<&str> = list_body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|plan| plan["id"].as_str().unwrap())
        .collect();
    assert!(
        plan_ids.contains(&"free") && plan_ids.contains(&"enterprise"),
        "CLI list must show both the seeded free plan and the newly created one: {list_body}"
    );

    // assign
    let assign = run_cli(&[
        "plans",
        "assign",
        "--tenant-id",
        "tenant-plans-cli",
        "--plan-id",
        "enterprise",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "admin-secret",
    ]);
    assert!(
        assign.status.success(),
        "assign failed: {}",
        stderr(&assign)
    );
    let assign_body: serde_json::Value = serde_json::from_slice(&assign.stdout).unwrap();
    assert_eq!(assign_body["tenant"]["plan_id"], "enterprise");

    // Independently verify through the raw admin HTTP surface, not just the
    // CLI's own stdout.
    let reread = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-plans-cli",
        &admin_headers(),
        "",
    ));
    assert_eq!(reread["tenant"]["plan_id"], "enterprise");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
