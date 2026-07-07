// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of the AWS Bedrock provider adapter (issue
// #172) against a real running gateway: drive a real chat completion
// request through a "bedrock"-kind provider and confirm the mock upstream
// received a correctly-shaped, SigV4-signed Converse API request (path,
// Authorization/X-Amz-Date/Host headers, JSON body), and that the mock's
// Converse-shaped response makes it back to the client unchanged (same
// raw-pass-through behavior every other non-OpenAI-compatible adapter in
// this codebase already has -- FerroGate doesn't reshape a dedicated
// provider's native response back into OpenAI format).
//
// No live AWS credentials needed or used: this validates request shape and
// signature structure against a local mock server, exactly how every other
// adapter in ferrogate-providers is already tested (none of them hit a
// real upstream provider either).

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "bedrock"
kind = "bedrock"
base_url = "http://{provider_addr}"
region = "us-east-1"
aws_access_key_id = "AKIDEXAMPLE"
aws_secret_access_key_env = "FERROGATE_TEST_BEDROCK_SECRET_KEY"

[[models]]
name = "bedrock-chat"
provider = "bedrock"
provider_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"

[[api_keys]]
id = "bedrock-client"
name = "Bedrock client"
key = "bedrock-secret"
scopes = ["chat.completions"]
allowed_models = ["bedrock-chat"]
"#
        ),
    )
    .unwrap();
}

#[test]
fn chat_completion_dispatches_a_signed_converse_request_to_bedrock() {
    // The gateway subprocess inherits this process's environment, so
    // setting the secret here (never written to the config file itself)
    // is how the adapter resolves aws_secret_access_key_env at runtime.
    std::env::set_var(
        "FERROGATE_TEST_BEDROCK_SECRET_KEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let gateway_addr = free_addr();
    let converse_response = r#"{"output":{"message":{"role":"assistant","content":[{"text":"hello from bedrock"}]}},"stopReason":"end_turn","usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8}}"#;
    let (provider_addr, provider_handle) = spawn_provider_upstream(1, converse_response);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer bedrock-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"bedrock-chat","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"max_tokens":256}"#,
    );
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "chat completion through the bedrock provider should succeed: {response}"
    );
    // Raw pass-through: the client receives Bedrock's native Converse
    // response shape unchanged, the same behavior every other
    // non-OpenAI-compatible adapter (Anthropic, Gemini, ...) already has.
    assert!(
        response.contains("hello from bedrock"),
        "response body must be the mock Converse response verbatim: {response}"
    );
    assert!(response.contains(r#""stopReason":"end_turn""#));

    gateway.kill().unwrap();
    gateway.wait().unwrap();

    let captured_requests = provider_handle.join().unwrap();
    assert_eq!(captured_requests.len(), 1, "exactly one upstream request");
    let request = &captured_requests[0];

    // Path: model id percent-encoded (":" -> "%3A"), /converse suffix.
    assert!(
        request
            .contains("POST /model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse HTTP/1.1"),
        "unexpected request line: {request}"
    );

    // SigV4 headers: correct credential scope (access key/date/region/
    // service/aws4_request), the exact signed-headers set this adapter
    // commits to signing, and a well-formed 64-hex-char signature.
    assert!(
        request.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
            || request.contains("Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "missing or malformed Authorization header: {request}"
    );
    assert!(
        request
            .to_lowercase()
            .contains("/us-east-1/bedrock/aws4_request"),
        "credential scope must be region=us-east-1, service=bedrock: {request}"
    );
    assert!(
        request
            .to_lowercase()
            .contains("signedheaders=host;x-amz-date"),
        "signed headers must be exactly host;x-amz-date: {request}"
    );
    assert!(
        request.to_lowercase().contains("x-amz-date:"),
        "missing X-Amz-Date header: {request}"
    );
    assert!(
        !request.to_lowercase().contains("x-amz-security-token:"),
        "long-lived credentials (no session token) must not send x-amz-security-token: {request}"
    );

    // The secret access key itself must never appear on the wire in any
    // form -- only derived signature material should.
    assert!(
        !request.contains("wJalrXUtnFEMI"),
        "the raw AWS secret access key must never be sent over the wire: {request}"
    );

    // Body: OpenAI-shaped input correctly translated to Bedrock's
    // Converse shape (system message split out, user message converted,
    // max_tokens -> inferenceConfig.maxTokens).
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    let body_json: serde_json::Value = serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("upstream request body must be JSON: {error}\n{body}"));
    assert_eq!(body_json["messages"][0]["role"], "user");
    assert_eq!(body_json["messages"][0]["content"][0]["text"], "hello");
    assert_eq!(body_json["system"][0]["text"], "be concise");
    assert_eq!(body_json["inferenceConfig"]["maxTokens"], 256);
}
