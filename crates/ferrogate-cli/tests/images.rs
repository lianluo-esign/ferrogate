// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Crate integration coverage for the governed
// /v1/images/generations endpoint (issue #275): success E2E through an
// OpenAI-compatible upstream with a priced per-image (non-token) ledger entry,
// request-stage Guardrail deny, unsupported-family fail-closed, and request
// validation.

mod support;

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, base_url: &str) {
    write_config_with_extra(path, gateway_addr, base_url, "");
}

fn write_config_with_extra(
    path: &std::path::Path,
    gateway_addr: &str,
    base_url: &str,
    extra_toml: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[telemetry]
log_bodies = true

[[providers]]
name = "openai"
kind = "openai"
base_url = "{base_url}"

# Priced per generated image (issue #275): the image count rides the
# completion-token dimension, so output_price_per_1m is USD per 1,000,000
# images (40000.0 == $0.04 per image). input_price_per_1m must be present for
# the route to settle a cost at all (settled_cost_usd requires both sides);
# image prompts carry no priced input dimension, so it is 0.
[[models]]
name = "art"
provider = "openai"
provider_model = "gpt-image-1"
capabilities = ["images"]
input_price_per_1m = 0.0
output_price_per_1m = 40000.0

[[api_keys]]
id = "art-key"
name = "Images client"
key = "art-secret"
scopes = ["images.generate"]
allowed_models = ["art"]
platform_operator = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true

{extra_toml}
"#
        ),
    )
    .unwrap();
}

fn generate_images(addr: &str, body: &str) -> String {
    http_request(
        addr,
        "POST",
        "/v1/images/generations",
        &[
            "Authorization: Bearer art-secret",
            "Content-Type: application/json",
        ],
        body,
    )
}

fn response_json(response: String) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("response body was not valid JSON ({error}): {response}"))
}

/// Spawns a single-shot mock OpenAI-compatible images upstream that returns
/// exactly `response_body` and records the request body it received.
fn spawn_images_upstream(response_body: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

#[test]
fn images_success_settles_a_priced_per_image_ledger_entry() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_images_upstream(
        r#"{"created":1710000000,"data":[{"url":"https://cdn.example/a.png"},{"url":"https://cdn.example/b.png"}]}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(
        &config,
        &gateway_addr,
        &format!("http://{provider_addr}/v1"),
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = generate_images(
        &gateway_addr,
        r#"{"model":"art","prompt":"a red fox","n":2}"#,
    );
    assert!(response.contains("200 OK"), "{response}");
    let body = response_json(response);
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    assert_eq!(body["data"][0]["url"], "https://cdn.example/a.png");

    let request = provider_handle.join().unwrap();
    assert!(request.contains("POST /v1/images/generations"), "{request}");
    assert!(request.contains("\"model\":\"gpt-image-1\""));
    assert!(request.contains("\"prompt\":\"a red fox\""));

    // Non-token billing (issue #275): the settled event bills the two
    // generated images (completion-token dimension) at $0.04 each = $0.08.
    let billing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let event = billing["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["logical_model"] == "art")
        .expect("art billing event settled");
    assert_eq!(event["usage"]["completion_tokens"], 2);
    let cost = event["cost_usd"].as_f64().expect("priced cost_usd");
    assert!((cost - 0.08).abs() < 1e-9, "expected $0.08, got {cost}");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn images_guardrail_request_deny_blocks_before_provider_dispatch_and_billing() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config_with_extra(
        &config,
        &gateway_addr,
        "http://127.0.0.1:9/v1",
        r#"
[[guardrails]]
id = "block-secret"
name = "Block secret"
stage = "request"
keywords = ["forbidden-secret"]
effect = "deny"
code = "guardrail_blocked"
message = "blocked by guardrail"
enabled = true
"#,
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = generate_images(
        &gateway_addr,
        r#"{"model":"art","prompt":"draw a forbidden-secret diagram"}"#,
    );
    let body = response_json(response);
    assert_eq!(body["error"]["code"], "guardrail_blocked");

    let billing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert!(
        billing["data"].as_array().unwrap().is_empty(),
        "guardrail deny must not settle a billing event: {billing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn images_fail_closed_for_a_provider_family_without_image_support() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    // An Anthropic-family route does not expose image generation, so the
    // request must fail closed with a normalized capability error rather than
    // dispatching an unsupported call.
    write_config_with_extra(
        &config,
        &gateway_addr,
        "http://127.0.0.1:9/v1",
        r#"
[[providers]]
name = "anthropic"
kind = "anthropic"
base_url = "http://127.0.0.1:9/v1"

[[models]]
name = "claude-art"
provider = "anthropic"
provider_model = "claude-3-5-sonnet-latest"
capabilities = ["images"]

[[api_keys]]
id = "anthropic-key"
name = "Anthropic images client"
key = "anthropic-secret"
scopes = ["images.generate"]
allowed_models = ["claude-art"]
platform_operator = true
"#,
    );

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = http_request(
        &gateway_addr,
        "POST",
        "/v1/images/generations",
        &[
            "Authorization: Bearer anthropic-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"claude-art","prompt":"a red fox"}"#,
    );
    assert!(response.contains("422"), "{response}");
    let body = response_json(response);
    assert_eq!(body["error"]["code"], "image_generation_unsupported");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn images_reject_a_missing_prompt_field() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "http://127.0.0.1:9/v1");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = generate_images(&gateway_addr, r#"{"model":"art"}"#);
    let body = response_json(response);
    assert_eq!(body["error"]["code"], "invalid_request");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
