// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for `ferrogate assets push/pull/list/
// delete` (issue #178) -- runs the real CLI binary (not a library call)
// against a real gateway process, with the pushed content independently
// verified against a real Postgres/Supabase-protocol database.
//
// Opt-in: requires FERROGATE_SUPABASE_DSN (see tests/assets_api.rs).

mod support;

use std::io::Write;
use std::process::Command;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn assets_cli_push_pull_list_delete_round_trip_through_real_postgres() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping assets_cli_push_pull_list_delete_round_trip_through_real_postgres: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, cli_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_cli_e2e","name":"CLI E2E","slug":"org-cli-e2e"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    let source_path = dir.path().join("hello.sh");
    let content = "#!/bin/sh\necho hello from the ferrogate assets CLI e2e test\n";
    std::fs::write(&source_path, content).unwrap();

    let gateway_url = format!("http://{gateway_addr}");

    // push
    let push = run_cli(&[
        "assets",
        "push",
        source_path.to_str().unwrap(),
        "--type",
        "cli_tool",
        "--name",
        "hello",
        "--version",
        "1.0.0",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "cli-e2e-secret",
    ]);
    assert!(push.status.success(), "push failed: {}", stderr(&push));
    let push_body: serde_json::Value = serde_json::from_slice(&push.stdout).unwrap();
    let content_hash = push_body["asset"]["content_hash"]
        .as_str()
        .expect("content_hash must be present")
        .to_string();

    // list
    let list = run_cli(&[
        "assets",
        "list",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "cli-e2e-secret",
    ]);
    assert!(list.status.success(), "list failed: {}", stderr(&list));
    let list_body: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        list_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|asset| asset["content_hash"] == content_hash),
        "pushed asset not present in CLI list output: {list_body}"
    );

    // pull
    let pulled_path = dir.path().join("hello-pulled.sh");
    let pull = run_cli(&[
        "assets",
        "pull",
        "--type",
        "cli_tool",
        "--name",
        "hello",
        "--version",
        "1.0.0",
        "--output",
        pulled_path.to_str().unwrap(),
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "cli-e2e-secret",
    ]);
    assert!(pull.status.success(), "pull failed: {}", stderr(&pull));
    let pulled_content = std::fs::read_to_string(&pulled_path).unwrap();
    assert_eq!(
        pulled_content, content,
        "pulled content does not match what was pushed"
    );

    // Independently verify the row landed in the real database.
    let db_row = psql_query(
        &dsn,
        "SELECT tenant_id, content_hash FROM ferrogate_control.stored_assets \
         WHERE tenant_id = 'org_cli_e2e' AND asset_type = 'cli_tool' AND name = 'hello'",
    );
    assert!(
        db_row.contains("org_cli_e2e") && db_row.contains(&content_hash),
        "stored_assets row not found in the real database: {db_row}"
    );

    // delete
    let delete = run_cli(&[
        "assets",
        "delete",
        "--type",
        "cli_tool",
        "--name",
        "hello",
        "--version",
        "1.0.0",
        "--gateway-url",
        &gateway_url,
        "--api-key",
        "cli-e2e-secret",
    ]);
    assert!(
        delete.status.success(),
        "delete failed: {}",
        stderr(&delete)
    );

    let db_row_after_delete = psql_query(
        &dsn,
        "SELECT count(*) FROM ferrogate_control.stored_assets \
         WHERE tenant_id = 'org_cli_e2e' AND asset_type = 'cli_tool' AND name = 'hello'",
    );
    assert_eq!(
        db_row_after_delete.trim(),
        "0",
        "row still present in the real database after CLI delete"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn cli_config(gateway_addr: &str, dsn: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "cli-e2e-client"
name = "CLI E2E client"
key = "cli-e2e-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_cli_e2e"
"#
    )
}

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args(args)
        .output()
        .expect("failed to run the ferrogate CLI binary")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn psql_query(dsn: &str, query: &str) -> String {
    let output = Command::new("psql")
        .arg(dsn)
        .arg("-t")
        .arg("-A")
        .arg("-c")
        .arg(query)
        .output()
        .expect("psql must be installed for this test's independent DB verification");
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        panic!("psql query failed: {query}");
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}
