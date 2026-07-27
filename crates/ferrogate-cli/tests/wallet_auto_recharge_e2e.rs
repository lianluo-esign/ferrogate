// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of prepaid-credit wallet auto-recharge
// orchestration (issue #169) against a real running gateway: drain a
// wallet below its configured threshold via a real settled chat
// completion, and confirm the fire-and-forget background task calls a
// local mock Stripe API and credits the wallet -- without ever touching
// the real Stripe network. `FERROGATE_STRIPE_API_BASE` is a
// production-code environment override that exists specifically so this
// path (which has no other injection point, since it's reached from deep
// inside the billing-settlement call chain, not from an admin handler)
// can be redirected at a local mock server. Also covers the
// missing-payment-method dunning path, which requires no network mock at
// all.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
platform_operator = true
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

#[derive(Debug, Clone)]
struct CapturedCharge {
    path: String,
    body: String,
    idempotency_key: Option<String>,
}

/// Spawns a persistent (multi-request) plain-HTTP mock Stripe API,
/// unlike `payments.rs`'s test-only one-shot mock -- the auto-recharge
/// background task may retry or this test may probe more than once
/// before the fire-and-forget `tokio::spawn` completes, so the mock must
/// stay alive for the whole test rather than exiting after one request.
fn spawn_stripe_recharge_mock(succeed: bool) -> (String, Arc<Mutex<Vec<CapturedCharge>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_base = format!("http://{}", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_captured = Arc::clone(&captured);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    return;
                }
                raw.extend_from_slice(&buffer[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
            }
            let body =
                String::from_utf8_lossy(&raw[header_end..header_end + content_length]).into_owned();
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let idempotency_key = head.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("idempotency-key")
                        .then(|| value.trim().to_string())
                })
            });
            server_captured.lock().unwrap().push(CapturedCharge {
                path,
                body,
                idempotency_key,
            });

            let response_body = if succeed {
                r#"{"id":"pi_auto123","status":"succeeded"}"#
            } else {
                r#"{"id":"pi_auto123","status":"requires_payment_method"}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    (api_base, captured)
}

/// Serializes the two tests in this file: both set the process-global
/// `FERROGATE_STRIPE_SECRET_KEY`/`FERROGATE_STRIPE_API_BASE` env vars to
/// per-test mock-server addresses before spawning the gateway
/// subprocess, and `cargo test` runs tests in the same binary
/// concurrently by default -- without this lock, one test's `set_var`
/// can race the other's `Command::spawn`, pointing its gateway at the
/// wrong mock server.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn poll_until<F: Fn() -> Option<T>, T>(timeout: Duration, poll: F) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = poll() {
            return value;
        }
        if started.elapsed() > timeout {
            panic!("condition was not met within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn wallet_auto_recharge_fires_in_the_background_and_credits_the_wallet_on_success() {
    let _env_guard = lock_env();
    let (stripe_api_base, captured) = spawn_stripe_recharge_mock(true);
    std::env::set_var("FERROGATE_STRIPE_SECRET_KEY", "sk_test_auto_recharge");
    std::env::set_var("FERROGATE_STRIPE_API_BASE", &stripe_api_base);

    let gateway_addr = free_addr();
    // 400_000 prompt tokens @ $1/1M => $0.40 settled => 400_000 credits
    // debited by the one real chat completion this test drives.
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_recharge","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":400000,"completion_tokens":0,"total_tokens":400000}}"#,
    );
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
        r#"{"id":"tenant-recharge-e2e","name":"Tenant Recharge E2E","slug":"tenant-recharge-e2e"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-recharge-e2e","tenant_id":"tenant-recharge-e2e","name":"Project Recharge E2E","slug":"project-recharge-e2e"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-recharge-e2e","project_id":"project-recharge-e2e","name":"Workspace Recharge E2E","slug":"workspace-recharge-e2e"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"Recharge E2E key","workspace_id":"workspace-recharge-e2e","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"].as_str().unwrap().to_string();

    // Wallet auto-recharges to 2_000_000 credits whenever the balance
    // drops to or below 200_000.
    let created_wallet = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &admin_headers(),
        r#"{"tenant_id":"tenant-recharge-e2e","auto_recharge_threshold_credits":200000,"auto_recharge_amount_credits":2000000}"#,
    ));
    assert_eq!(created_wallet["wallet"]["balance_credits"], 0);

    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/payment-methods",
        &admin_headers(),
        r#"{"tenant_id":"tenant-recharge-e2e","provider":"stripe","provider_customer_id":"cus_recharge","provider_payment_method_id":"pm_recharge","is_default":true}"#,
    ));

    // Top up to exactly 400_000 credits: above the 200_000 threshold, so
    // no auto-recharge fires yet.
    let topped_up = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-recharge-e2e/adjust",
        &admin_headers(),
        r#"{"delta_credits":400000}"#,
    ));
    assert_eq!(topped_up["wallet"]["balance_credits"], 400000);

    // One real settled request drains the balance to exactly 0, which is
    // <= the 200_000 threshold -- this is what must trigger the
    // background auto-recharge.
    let drained = http_request(
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
        status_line(&drained).contains("200 OK"),
        "balance was 400_000 > 0 at admission time: {drained}"
    );

    // The recharge is fire-and-forget (`tokio::spawn`), so poll rather
    // than asserting immediately.
    let recharged = poll_until(Duration::from_secs(5), || {
        let wallet = response_json(http_request(
            &gateway_addr,
            "GET",
            "/admin/v1/wallets/tenant-recharge-e2e",
            &admin_headers(),
            "",
        ));
        (wallet["wallet"]["balance_credits"] == 2000000).then_some(wallet)
    });
    assert_eq!(
        recharged["wallet"]["dunning"], false,
        "a successful auto-recharge must clear dunning: {recharged}"
    );

    let requests = captured.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        1,
        "exactly one charge must be sent to the payment provider: {requests:?}"
    );
    assert_eq!(requests[0].path, "/v1/payment_intents");
    // 2_000_000 credits / (1_000_000 credits per USD) = $2.00 = 200 cents.
    assert!(
        requests[0].body.contains("amount=200&"),
        "must charge the configured auto_recharge_amount_credits worth of USD cents: {requests:?}"
    );
    assert!(requests[0].body.contains("customer=cus_recharge"));
    assert!(requests[0].body.contains("payment_method=pm_recharge"));
    let idempotency_key = requests[0]
        .idempotency_key
        .as_deref()
        .expect("charge must carry an idempotency key");
    assert!(
        idempotency_key.starts_with("auto-recharge:tenant-recharge-e2e:"),
        "idempotency key must be derived from the tenant id: {idempotency_key}"
    );

    // The ledger must show both the settlement debit (from the real chat
    // completion) and the auto-recharge credit, in that causal order --
    // proving background/non-admin-handler code paths write to the same
    // audit-event log the admin-initiated /adjust and /charge endpoints
    // already do.
    let ledger = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-recharge-e2e/ledger",
        &admin_headers(),
        "",
    ));
    let entries = ledger["data"].as_array().expect("ledger must be a list");
    let actions: Vec<&str> = entries
        .iter()
        .map(|entry| entry["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"wallet.settle"),
        "ledger must record the settlement debit: {ledger}"
    );
    assert!(
        actions.contains(&"wallet.auto_recharge"),
        "ledger must record the auto-recharge charge: {ledger}"
    );
    let settle_index = actions.iter().position(|a| *a == "wallet.settle").unwrap();
    let recharge_index = actions
        .iter()
        .position(|a| *a == "wallet.auto_recharge")
        .unwrap();
    assert!(
        settle_index < recharge_index,
        "the debit must be recorded before the recharge it triggered: {ledger}"
    );
    let recharge_entry = &entries[recharge_index];
    assert_eq!(recharge_entry["outcome"], "committed");
    assert_eq!(recharge_entry["target"], "tenant-recharge-e2e");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn missing_payment_method_marks_the_wallet_dunning_instead_of_erroring() {
    let _env_guard = lock_env();
    let (stripe_api_base, captured) = spawn_stripe_recharge_mock(true);
    std::env::set_var("FERROGATE_STRIPE_SECRET_KEY", "sk_test_auto_recharge");
    std::env::set_var("FERROGATE_STRIPE_API_BASE", &stripe_api_base);

    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_no_pm","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":400000,"completion_tokens":0,"total_tokens":400000}}"#,
    );
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
        r#"{"id":"tenant-recharge-no-pm","name":"Tenant Recharge No PM","slug":"tenant-recharge-no-pm"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-recharge-no-pm","tenant_id":"tenant-recharge-no-pm","name":"Project","slug":"project-recharge-no-pm"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-recharge-no-pm","project_id":"project-recharge-no-pm","name":"Workspace","slug":"workspace-recharge-no-pm"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"No PM key","workspace_id":"workspace-recharge-no-pm","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"].as_str().unwrap().to_string();

    // Auto-recharge configured, but deliberately NO payment method is
    // ever attached for this tenant.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &admin_headers(),
        r#"{"tenant_id":"tenant-recharge-no-pm","auto_recharge_threshold_credits":200000,"auto_recharge_amount_credits":2000000}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-recharge-no-pm/adjust",
        &admin_headers(),
        r#"{"delta_credits":400000}"#,
    ));

    let drained = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(status_line(&drained).contains("200 OK"));

    let dunning = poll_until(Duration::from_secs(5), || {
        let wallet = response_json(http_request(
            &gateway_addr,
            "GET",
            "/admin/v1/wallets/tenant-recharge-no-pm",
            &admin_headers(),
            "",
        ));
        (wallet["wallet"]["dunning"] == true).then_some(wallet)
    });
    assert_eq!(
        dunning["wallet"]["balance_credits"], 0,
        "with no payment method, the balance must stay at 0 (no charge can be attempted): {dunning}"
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "no charge request should ever be sent when there is no payment method on file"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
