// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of the prepaid-credit wallet admin surface
// and admission gate (issue #169) against a real running gateway: create a
// wallet, top it up, drive real chat completion requests to drain it via
// the real settlement/debit path, and confirm the request is rejected once
// the balance is exhausted -- distinct from and independent of the
// pre-existing monthly_budget_usd hard-deny (proven by never configuring a
// quota_policy in this test at all). Also covers payment-method CRUD.

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
fn wallet_admission_gate_drains_via_real_settlement_then_rejects_then_recovers_after_topup() {
    let gateway_addr = free_addr();
    // 500_000 prompt tokens @ $1/1M => $0.50 settled => 500_000 credits
    // debited per request (DEFAULT_CREDITS_PER_USD = 1_000_000).
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_wallet","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":500000,"completion_tokens":0,"total_tokens":500000}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap tenant -> project -> workspace -> virtual key. No
    // quota_policy is ever created in this test, so any 429 that shows up
    // can only be the wallet gate, not monthly_budget_usd.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-wallet-e2e","name":"Tenant Wallet E2E","slug":"tenant-wallet-e2e"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-wallet-e2e","tenant_id":"tenant-wallet-e2e","name":"Project Wallet E2E","slug":"project-wallet-e2e"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-wallet-e2e","project_id":"project-wallet-e2e","name":"Workspace Wallet E2E","slug":"workspace-wallet-e2e"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"Wallet E2E key","workspace_id":"workspace-wallet-e2e","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"].as_str().unwrap().to_string();

    // 2. Before any wallet exists, requests are unaffected by the wallet
    // gate (opt-in).
    let before_wallet = http_request(
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
        status_line(&before_wallet).contains("200 OK"),
        "no wallet exists yet; the gate must be a no-op: {before_wallet}"
    );

    // 3. Create a wallet (starts at 0 balance) and top it up to exactly
    // 500_000 credits -- enough for exactly one more settled request.
    let created_wallet = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &admin_headers(),
        r#"{"tenant_id":"tenant-wallet-e2e","auto_recharge_threshold_credits":100000,"auto_recharge_amount_credits":1000000}"#,
    ));
    assert_eq!(created_wallet["wallet"]["balance_credits"], 0);
    assert_eq!(created_wallet["wallet"]["dunning"], false);

    // Creating a second wallet for the same tenant is a conflict.
    let duplicate_wallet = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &admin_headers(),
        r#"{"tenant_id":"tenant-wallet-e2e"}"#,
    );
    assert!(
        status_line(&duplicate_wallet).contains("409"),
        "creating a wallet for a tenant that already has one must conflict: {duplicate_wallet}"
    );

    let topped_up = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-wallet-e2e/adjust",
        &admin_headers(),
        r#"{"delta_credits":500000}"#,
    ));
    assert_eq!(topped_up["wallet"]["balance_credits"], 500000);

    // 4. With a nonzero balance, the request succeeds and the real
    // settlement path debits the wallet by the settled cost.
    let with_balance = http_request(
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
        status_line(&with_balance).contains("200 OK"),
        "balance is 500_000 > 0 at admission time: {with_balance}"
    );

    let after_settlement = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-wallet-e2e",
        &admin_headers(),
        "",
    ));
    assert_eq!(
        after_settlement["wallet"]["balance_credits"], 0,
        "500_000 prompt tokens @ $1/1M = $0.50 = 500_000 credits must be debited: {after_settlement}"
    );

    // 5. Balance is now exactly 0 -- the next request is rejected by the
    // wallet gate specifically (never reaches the provider, since
    // spawn_provider_upstream was only primed for 2 requests total).
    let exhausted = http_request(
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
        status_line(&exhausted).contains("429"),
        "balance is 0; the wallet gate must reject: {exhausted}"
    );
    assert!(exhausted.contains("wallet_balance_exhausted"));

    // 6. Manually topping up again (simulating an operator- or
    // auto-recharge-driven credit) immediately lifts the gate.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-wallet-e2e/adjust",
        &admin_headers(),
        r#"{"delta_credits":1000000}"#,
    ));
    let recovered = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    // Not necessarily 200 (the mock upstream was only primed for 2 calls,
    // so this may 502 at dispatch) -- the point is it's no longer the
    // wallet gate rejecting it.
    assert!(
        !recovered.contains("wallet_balance_exhausted"),
        "topping up must lift the gate: {recovered}"
    );

    // 7. PATCH reconfigures auto-recharge settings without touching
    // balance.
    let reconfigured = response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/wallets/tenant-wallet-e2e",
        &admin_headers(),
        r#"{"auto_recharge_threshold_credits":50000}"#,
    ));
    assert_eq!(
        reconfigured["wallet"]["auto_recharge_threshold_credits"],
        50000
    );
    assert_eq!(
        reconfigured["wallet"]["auto_recharge_amount_credits"], 1000000,
        "PATCH must merge: the amount set at creation must survive an unrelated threshold update"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn payment_methods_admin_surface_creates_lists_and_deletes() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(0, "{}");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-pm-e2e","name":"Tenant PM E2E","slug":"tenant-pm-e2e"}"#,
    ));

    let missing_query = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/payment-methods",
        &admin_headers(),
        "",
    );
    assert!(
        status_line(&missing_query).contains("400"),
        "listing payment methods requires ?tenant_id=: {missing_query}"
    );

    let created = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/payment-methods",
        &admin_headers(),
        r#"{"tenant_id":"tenant-pm-e2e","provider":"stripe","provider_customer_id":"cus_123","provider_payment_method_id":"pm_123","is_default":true}"#,
    ));
    assert_eq!(created["payment_method"]["provider"], "stripe");
    let payment_method_id = created["payment_method"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let listed = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/payment-methods?tenant_id=tenant-pm-e2e",
        &admin_headers(),
        "",
    ));
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);

    let deleted = http_request(
        &gateway_addr,
        "DELETE",
        &format!("/admin/v1/payment-methods/{payment_method_id}"),
        &admin_headers(),
        "",
    );
    assert!(status_line(&deleted).contains("200 OK"));

    let listed_after_delete = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/payment-methods?tenant_id=tenant-pm-e2e",
        &admin_headers(),
        "",
    ));
    assert!(listed_after_delete["data"].as_array().unwrap().is_empty());

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
