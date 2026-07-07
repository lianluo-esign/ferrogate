// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of proactive budget-threshold alerting
// (issue #170) against a real running gateway: configure a webhook and a
// tenant-scoped quota policy with alert tiers over the real admin HTTP
// surface, then drive real chat completion requests through the durable-key
// hot path far enough to cross each tier, proving the webhook actually
// fires exactly once per tier and that the existing 100% hard-deny still
// engages afterward.

mod support;

use support::{
    free_addr, http_request, spawn_provider_upstream, spawn_webhook_capture_server, start_gateway,
    wait_for_gateway,
};

fn write_config(
    path: &std::path::Path,
    gateway_addr: &str,
    provider_addr: &str,
    webhook_url: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[billing_alerts]
webhook_url = "{webhook_url}"
webhook_timeout_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
input_price_per_1m = 1.0
output_price_per_1m = 0.0

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
fn budget_threshold_webhook_fires_once_per_tier_then_hard_deny_still_engages_at_100_pct() {
    let gateway_addr = free_addr();
    // 500_000 prompt tokens at $1/1M => $0.50 settled per request, against
    // a $1.00 tenant budget with alert tiers at 50%/90% -- request 1 lands
    // exactly on the 50% tier, request 2 lands on 100% (crossing 90%), and
    // a third request must be hard-denied before ever reaching upstream.
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_budget","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":500000,"completion_tokens":0,"total_tokens":500000}}"#,
    );
    let (webhook_url, captured) = spawn_webhook_capture_server();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr, &webhook_url);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap tenant -> project -> workspace -> durable virtual key
    // over the real admin HTTP surface, mirroring quota_policies_e2e.rs.
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-budget-e2e","name":"Tenant Budget E2E","slug":"tenant-budget-e2e"}"#,
    ));
    assert_eq!(tenant["tenant"]["id"], "tenant-budget-e2e");

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-budget-e2e","tenant_id":"tenant-budget-e2e","name":"Project Budget E2E","slug":"project-budget-e2e"}"#,
    ));

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-budget-e2e","project_id":"project-budget-e2e","name":"Workspace Budget E2E","slug":"workspace-budget-e2e"}"#,
    ));

    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"Budget E2E key","workspace_id":"workspace-budget-e2e","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"]
        .as_str()
        .expect("create response must include the plaintext secret")
        .to_string();

    // 2. Attach a tenant-scoped quota policy with a $1.00 monthly budget and
    // 50%/90% alert tiers over the real admin HTTP surface.
    let quota = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/quota-policies",
        &admin_headers(),
        r#"{"scope_type":"tenant","scope_id":"tenant-budget-e2e","monthly_budget_usd":1.0,"alert_threshold_pcts":[50,90]}"#,
    ));
    assert_eq!(
        quota["policy"]["alert_threshold_pcts"].as_array().unwrap(),
        &[serde_json::json!(50), serde_json::json!(90)]
    );

    // 3. First request settles $0.50 (50% of budget) -- must fire exactly
    // the 50% tier webhook.
    let first = http_request(
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
        status_line(&first).contains("200 OK"),
        "first request must succeed (spend not yet at the 100% hard-deny): {first}"
    );

    wait_for_webhook_count(&captured, 1);
    {
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "expected exactly one webhook after crossing 50%: {captured:?}"
        );
        assert_eq!(captured[0]["threshold_pct"], 50);
        assert_eq!(captured[0]["scope_type"], "tenant");
        assert_eq!(captured[0]["scope_id"], "tenant-budget-e2e");
        assert_eq!(captured[0]["event"], "budget_threshold_crossed");
    }

    // 4. Second request settles another $0.50 (100% of budget) -- crosses
    // the 90% tier (fires once), does NOT refire the already-notified 50%
    // tier, and is itself still allowed (the hard-deny check runs BEFORE
    // this request, when spend was only $0.50 < $1.00).
    let second = http_request(
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
        status_line(&second).contains("200 OK"),
        "second request must still succeed: pre-request spend was $0.50 < $1.00 budget: {second}"
    );

    wait_for_webhook_count(&captured, 2);
    {
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            2,
            "expected exactly one additional webhook after crossing 90%, and 50% must not repeat: {captured:?}"
        );
        assert_eq!(captured[1]["threshold_pct"], 90);
    }

    // 5. A third request is now hard-denied by the pre-existing 100%
    // monthly_budget_exceeded enforcement (unrelated to this issue, proving
    // alerting is additive and doesn't disturb it) -- and fires no further
    // webhook, since it never reaches the billing-settlement path.
    let third = http_request(
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
        status_line(&third).contains("429"),
        "third request must be hard-denied: spend is now $1.00 >= $1.00 budget: {third}"
    );
    assert!(third.contains("monthly_budget_exceeded"));

    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        captured.lock().unwrap().len(),
        2,
        "a hard-denied request must not fire any additional webhook"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn wait_for_webhook_count(
    captured: &std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    count: usize,
) {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(5) {
        if captured.lock().unwrap().len() >= count {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for {count} webhook(s); got {}",
        captured.lock().unwrap().len()
    );
}
