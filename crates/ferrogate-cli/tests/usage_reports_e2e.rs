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
