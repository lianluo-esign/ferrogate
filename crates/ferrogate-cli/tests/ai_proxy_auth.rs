mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_kind: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "{provider_kind}"
base_url = "http://127.0.0.1:65535/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[models]]
name = "blocked-chat"
provider = "openai"
provider_model = "gpt-4.1"

[[api_keys]]
id = "models_only"
name = "Models only"
key = "models-secret"
scopes = ["models.read"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "chat_limited"
name = "Chat limited"
key = "chat-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
}

fn chat(addr: &str, token: Option<&str>, model: &str) -> String {
    let mut headers = vec!["Content-Type: application/json"];
    let auth;
    if let Some(token) = token {
        auth = format!("Authorization: Bearer {token}");
        headers.push(&auth);
    }
    http_request(
        addr,
        "POST",
        "/v1/chat/completions",
        &headers,
        &format!(r#"{{"model":"{model}","messages":[]}}"#),
    )
}

#[test]
fn ai_proxy_rejects_missing_invalid_scope_and_model_auth() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "openai");
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let missing = chat(&gateway_addr, None, "fast-chat");
    assert!(missing.contains("401 Unauthorized"));
    assert!(missing.contains("missing_api_key"));

    let invalid = chat(&gateway_addr, Some("wrong-secret"), "fast-chat");
    assert!(invalid.contains("401 Unauthorized"));
    assert!(invalid.contains("invalid_api_key"));

    let denied_scope = chat(&gateway_addr, Some("models-secret"), "fast-chat");
    assert!(denied_scope.contains("403 Forbidden"));
    assert!(denied_scope.contains("scope_denied"));

    let denied_model = chat(&gateway_addr, Some("chat-secret"), "blocked-chat");
    assert!(denied_model.contains("403 Forbidden"));
    assert!(denied_model.contains("model_not_allowed"));

    let non_object = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer chat-secret",
            "Content-Type: application/json",
        ],
        r#""not-an-object""#,
    );
    assert!(non_object.contains("400 Bad Request"));
    assert!(non_object.contains("invalid_request"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn ai_proxy_maps_adapter_errors_without_leaking_provider_secret() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, "anthropic");
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr, Some("chat-secret"), "fast-chat");
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("provider_adapter_error"));
    assert!(response.contains("UnsupportedProviderKind"));
    assert!(!response.contains("provider-secret"));
    assert!(!response.contains("chat-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
