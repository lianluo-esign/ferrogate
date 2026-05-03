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

[[providers]]
name = "other-provider"
kind = "openai"
base_url = "http://127.0.0.1:65534/v1"

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

[[api_keys]]
id = "disabled_key"
name = "Disabled key"
key = "disabled-secret"
enabled = false
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "expired_key"
name = "Expired key"
key = "expired-secret"
expires_at_unix = 1
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "budget_empty"
name = "Budget empty"
key = "budget-secret"
monthly_token_budget = 0
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "rate_empty"
name = "Rate empty"
key = "rate-secret"
request_limit_per_minute = 0
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "provider_limited"
name = "Provider limited"
key = "provider-limited-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
allowed_providers = ["other-provider"]

[[api_keys]]
id = "policy_key"
name = "Policy key"
key = "policy-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[policies]]
name = "deny policy key fast chat"
effect = "deny"
api_key_ids = ["policy_key"]
models = ["fast-chat"]
providers = ["openai"]
code = "policy_model_denied"
message = "model blocked by policy"
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

    let disabled = chat(&gateway_addr, Some("disabled-secret"), "fast-chat");
    assert!(disabled.contains("403 Forbidden"));
    assert!(disabled.contains("api_key_disabled"));
    assert!(!disabled.contains("disabled-secret"));

    let expired = chat(&gateway_addr, Some("expired-secret"), "fast-chat");
    assert!(expired.contains("403 Forbidden"));
    assert!(expired.contains("api_key_expired"));
    assert!(!expired.contains("expired-secret"));

    let budget = chat(&gateway_addr, Some("budget-secret"), "fast-chat");
    assert!(budget.contains("429 Too Many Requests"));
    assert!(budget.contains("token_budget_exceeded"));
    assert!(!budget.contains("budget-secret"));

    let rate = chat(&gateway_addr, Some("rate-secret"), "fast-chat");
    assert!(rate.contains("429 Too Many Requests"));
    assert!(rate.contains("rate_limit_exceeded"));
    assert!(!rate.contains("rate-secret"));

    let denied_provider = chat(&gateway_addr, Some("provider-limited-secret"), "fast-chat");
    assert!(denied_provider.contains("403 Forbidden"));
    assert!(denied_provider.contains("provider_not_allowed"));
    assert!(!denied_provider.contains("provider-limited-secret"));

    let denied_policy = chat(&gateway_addr, Some("policy-secret"), "fast-chat");
    assert!(denied_policy.contains("403 Forbidden"));
    assert!(denied_policy.contains("policy_model_denied"));
    assert!(denied_policy.contains("model blocked by policy"));
    assert!(!denied_policy.contains("policy-secret"));

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
    write_config(&config, &gateway_addr, "unsupported-test");
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
