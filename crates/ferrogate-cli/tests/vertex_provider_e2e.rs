// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of the Google Vertex AI provider adapter
// (issue #172) against a real running gateway: drive a real chat
// completion request through a "vertex"-kind provider and confirm the
// mock upstream received a correctly-shaped generateContent request (URL
// path with project/location/model, Bearer-token Authorization header,
// JSON body), and that the mock's response makes it back to the client
// unchanged (same raw-pass-through behavior every other
// non-OpenAI-compatible adapter in this codebase already has).
//
// No live GCP credentials needed or used: the "access token" here is an
// operator-supplied static value read from an env var (see
// `GcpProviderCredentials`'s doc comment in ferrogate-providers for why
// FerroGate doesn't mint/refresh one itself), so this validates request
// shape against a local mock server, exactly how every other adapter in
// ferrogate-providers is already tested.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "vertex"
kind = "vertex"
base_url = "http://{provider_addr}"
region = "us-central1"
gcp_project_id = "my-gcp-project"
gcp_access_token_env = "FERROGATE_TEST_VERTEX_ACCESS_TOKEN"

[[models]]
name = "vertex-chat"
provider = "vertex"
provider_model = "gemini-1.5-pro"

[[api_keys]]
id = "vertex-client"
name = "Vertex client"
key = "vertex-secret"
scopes = ["chat.completions"]
allowed_models = ["vertex-chat"]
"#
        ),
    )
    .unwrap();
}

#[test]
fn chat_completion_dispatches_a_bearer_authenticated_generate_content_request_to_vertex() {
    // The gateway subprocess inherits this process's environment, so
    // setting the token here (never written to the config file itself)
    // is how the adapter resolves gcp_access_token_env at runtime.
    std::env::set_var(
        "FERROGATE_TEST_VERTEX_ACCESS_TOKEN",
        "ya29.EXAMPLE_ACCESS_TOKEN",
    );

    let gateway_addr = free_addr();
    let generate_content_response = r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hello from vertex"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}"#;
    let (provider_addr, provider_handle) = spawn_provider_upstream(1, generate_content_response);
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
            "Authorization: Bearer vertex-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"vertex-chat","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"max_tokens":256}"#,
    );
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "chat completion through the vertex provider should succeed: {response}"
    );
    // Raw pass-through: the client receives Vertex's native
    // generateContent response shape unchanged, the same behavior every
    // other non-OpenAI-compatible adapter (Anthropic, Bedrock, ...)
    // already has.
    assert!(
        response.contains("hello from vertex"),
        "response body must be the mock generateContent response verbatim: {response}"
    );
    assert!(response.contains(r#""finishReason":"STOP""#));

    gateway.kill().unwrap();
    gateway.wait().unwrap();

    let captured_requests = provider_handle.join().unwrap();
    assert_eq!(captured_requests.len(), 1, "exactly one upstream request");
    let request = &captured_requests[0];

    // Path: project/location/model REST shape, generateContent suffix.
    assert!(
        request.contains(
            "POST /v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent HTTP/1.1"
        ),
        "unexpected request line: {request}"
    );

    // Auth: static Bearer token, not SigV4 or an API-key header.
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer ya29.example_access_token"),
        "missing or malformed Authorization header: {request}"
    );

    // Body: OpenAI-shaped input correctly translated to Gemini/Vertex's
    // contents shape (system message split out, user message converted,
    // max_tokens -> generationConfig.maxOutputTokens).
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    let body_json: serde_json::Value = serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("upstream request body must be JSON: {error}\n{body}"));
    assert_eq!(body_json["contents"][0]["role"], "user");
    assert_eq!(body_json["contents"][0]["parts"][0]["text"], "hello");
    assert_eq!(
        body_json["systemInstruction"]["parts"][0]["text"],
        "be concise"
    );
    assert_eq!(body_json["generationConfig"]["maxOutputTokens"], 256);
}
