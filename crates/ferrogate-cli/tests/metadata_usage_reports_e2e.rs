// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of arbitrary metadata tagging for usage/cost
// attribution (issue #171) against a real running gateway: drive real chat
// completion requests carrying a `metadata` object, then read the resulting
// per-metadata-value breakdown back through
// /admin/v1/usage-reports?group_by=metadata.<key> -- an aggregation
// dimension orthogonal to the built-in tenant/project/workspace/key scope
// chain that usage_reports_e2e.rs already covers.

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
id = "tagged_client"
name = "Tagged client"
key = "tagged-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Admin bootstrap key"
key = "admin-secret"
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

fn admin_headers() -> Vec<&'static str> {
    vec!["Authorization: Bearer admin-secret"]
}

fn chat(addr: &str, body: &str) -> String {
    http_request(
        addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer tagged-secret",
            "Content-Type: application/json",
        ],
        body,
    )
}

#[test]
fn metadata_group_by_breaks_down_cost_per_distinct_value_and_ignores_unset_metadata() {
    let gateway_addr = free_addr();
    // 4 requests: two carry customer_id metadata (acme x2, globex x1), one
    // carries none at all -- proving metadata is optional/backward
    // compatible and doesn't collide with the tagged rows.
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        4,
        r#"{"id":"chatcmpl_meta","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1000,"completion_tokens":0,"total_tokens":1000}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let acme_1 = chat(
        &gateway_addr,
        r#"{"model":"fast-chat","messages":[],"metadata":{"customer_id":"acme"}}"#,
    );
    assert!(
        status_line(&acme_1).contains("200 OK"),
        "acme request 1 should succeed: {acme_1}"
    );
    let acme_2 = chat(
        &gateway_addr,
        r#"{"model":"fast-chat","messages":[],"metadata":{"customer_id":"acme","feature":"beta"}}"#,
    );
    assert!(
        status_line(&acme_2).contains("200 OK"),
        "acme request 2 should succeed: {acme_2}"
    );
    let globex = chat(
        &gateway_addr,
        r#"{"model":"fast-chat","messages":[],"metadata":{"customer_id":"globex"}}"#,
    );
    assert!(
        status_line(&globex).contains("200 OK"),
        "globex request should succeed: {globex}"
    );
    let untagged = chat(&gateway_addr, r#"{"model":"fast-chat","messages":[]}"#);
    assert!(
        status_line(&untagged).contains("200 OK"),
        "a request with no metadata at all must still succeed: {untagged}"
    );

    let report = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/usage-reports?group_by=metadata.customer_id",
        &admin_headers(),
        "",
    ));
    let rows = report["data"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        2,
        "exactly one row per distinct customer_id value (the untagged request contributes to neither): {report}"
    );

    let acme_row = rows
        .iter()
        .find(|row| row["metadata_value"] == "acme")
        .unwrap_or_else(|| panic!("no acme row in {report}"));
    assert_eq!(acme_row["metadata_key"], "customer_id");
    assert_eq!(acme_row["request_count"], 2);
    assert_eq!(acme_row["total_tokens"], 2000);
    let acme_cost = acme_row["cost_usd"].as_f64().unwrap();
    assert!(
        (acme_cost - 0.002).abs() < 1e-9,
        "2 requests x 1000 prompt tokens @ $1/1M = $0.002, got {acme_cost}"
    );

    let globex_row = rows
        .iter()
        .find(|row| row["metadata_value"] == "globex")
        .unwrap_or_else(|| panic!("no globex row in {report}"));
    assert_eq!(globex_row["request_count"], 1);
    assert_eq!(globex_row["total_tokens"], 1000);

    // A second metadata key present only on the acme_2 request breaks down
    // independently -- proves rollups are per (key, value), not a single
    // flattened dimension.
    let feature_report = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/usage-reports?group_by=metadata.feature",
        &admin_headers(),
        "",
    ));
    let feature_rows = feature_report["data"].as_array().unwrap();
    assert_eq!(feature_rows.len(), 1, "{feature_report}");
    assert_eq!(feature_rows[0]["metadata_value"], "beta");
    assert_eq!(feature_rows[0]["request_count"], 1);

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn oversized_metadata_is_rejected_with_a_clear_error_not_silently_truncated() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(0, "{}");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 9 metadata entries exceeds the 8-entry cap.
    let too_many_keys: String = (0..9)
        .map(|index| format!(r#""k{index}":"v""#))
        .collect::<Vec<_>>()
        .join(",");
    let response = chat(
        &gateway_addr,
        &format!(r#"{{"model":"fast-chat","messages":[],"metadata":{{{too_many_keys}}}}}"#),
    );
    assert!(
        status_line(&response).contains("400"),
        "a metadata map exceeding the entry cap must be rejected, not silently truncated: {response}"
    );
    assert!(response.contains("invalid_request_metadata"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
