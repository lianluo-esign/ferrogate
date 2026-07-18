// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

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

[[models]]
name = "tenant-chat"
provider = "openai"
provider_model = "gpt-4o"
visible_organization_ids = ["org_demo"]

[[api_keys]]
id = "models_only"
name = "Models only"
key = "models-secret"
scopes = ["models.read"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

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
id = "model_denied"
name = "Model denied"
key = "model-denied-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
denied_models = ["fast-chat"]

[[api_keys]]
id = "provider_denied"
name = "Provider denied"
key = "provider-denied-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
allowed_providers = ["openai"]
denied_providers = ["openai"]

[[api_keys]]
id = "tenant_denied"
name = "Tenant denied"
key = "tenant-denied-secret"
scopes = ["chat.completions"]
allowed_models = ["tenant-chat"]

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
    chat_with_body(
        addr,
        token,
        &format!(r#"{{"model":"{model}","messages":[]}}"#),
    )
}

fn chat_with_body(addr: &str, token: Option<&str>, body: &str) -> String {
    let mut headers = vec!["Content-Type: application/json"];
    let auth;
    if let Some(token) = token {
        auth = format!("Authorization: Bearer {token}");
        headers.push(&auth);
    }
    http_request(addr, "POST", "/v1/chat/completions", &headers, body)
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

    let metrics_missing = http_request(&gateway_addr, "GET", "/metrics", &[], "");
    assert!(metrics_missing.contains("401 Unauthorized"));
    assert!(metrics_missing.contains("missing_api_key"));

    let metrics_scope_denied = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer models-secret"],
        "",
    );
    assert!(metrics_scope_denied.contains("403 Forbidden"));
    assert!(metrics_scope_denied.contains("scope_denied"));

    let metrics_ok = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(metrics_ok.contains("200 OK"));
    assert!(metrics_ok.contains("ferrogate_request_logs_total"));
    assert!(!metrics_ok.contains("admin-secret"));

    let denied_scope = chat(&gateway_addr, Some("models-secret"), "fast-chat");
    assert!(denied_scope.contains("403 Forbidden"));
    assert!(denied_scope.contains("scope_denied"));

    let denied_model = chat(&gateway_addr, Some("chat-secret"), "blocked-chat");
    assert!(denied_model.contains("403 Forbidden"));
    assert!(denied_model.contains("model_not_allowed"));

    let denied_tenant = chat(&gateway_addr, Some("tenant-denied-secret"), "tenant-chat");
    assert!(denied_tenant.contains("403 Forbidden"));
    assert!(denied_tenant.contains("model_not_visible"));
    assert!(!denied_tenant.contains("tenant-denied-secret"));

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

    let denied_model_list = chat(&gateway_addr, Some("model-denied-secret"), "fast-chat");
    assert!(denied_model_list.contains("403 Forbidden"));
    assert!(denied_model_list.contains("model_not_allowed"));
    assert!(!denied_model_list.contains("model-denied-secret"));

    let denied_provider_list = chat(&gateway_addr, Some("provider-denied-secret"), "fast-chat");
    assert!(denied_provider_list.contains("403 Forbidden"));
    assert!(denied_provider_list.contains("provider_not_allowed"));
    assert!(!denied_provider_list.contains("provider-denied-secret"));

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
fn ai_proxy_enforces_real_request_rate_limit_per_api_key() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_limit","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
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

[[api_keys]]
id = "rate_limited"
name = "Rate limited"
key = "rate-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
request_limit_per_minute = 1
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let first = chat(&gateway_addr, Some("rate-secret"), "fast-chat");
    assert!(first.contains("200 OK"));
    assert!(first.contains("\"id\":\"chatcmpl_limit\""));

    let second = chat(&gateway_addr, Some("rate-secret"), "fast-chat");
    assert!(second.contains("429 Too Many Requests"));
    assert!(second.contains("rate_limit_exceeded"));
    assert!(!second.contains("rate-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    assert_eq!(provider_handle.join().unwrap().len(), 1);
}

#[test]
fn ai_proxy_enforces_token_budget_after_recorded_usage() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_budget","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
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

[[api_keys]]
id = "budget_limited"
name = "Budget limited"
key = "budget-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
monthly_token_budget = 8
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let first = chat_with_body(
        &gateway_addr,
        Some("budget-secret"),
        r#"{"model":"fast-chat","messages":[],"max_tokens":4}"#,
    );
    assert!(first.contains("200 OK"));
    assert!(first.contains("\"id\":\"chatcmpl_budget\""));

    let second = chat(&gateway_addr, Some("budget-secret"), "fast-chat");
    assert!(second.contains("429 Too Many Requests"));
    assert!(second.contains("token_budget_exceeded"));
    assert!(!second.contains("budget-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    assert_eq!(provider_handle.join().unwrap().len(), 1);
}

#[test]
fn ai_proxy_reserves_token_budget_before_provider_dispatch() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        0,
        r#"{"id":"chatcmpl_budget","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
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

[[api_keys]]
id = "budget_limited"
name = "Budget limited"
key = "budget-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
monthly_token_budget = 8
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat_with_body(
        &gateway_addr,
        Some("budget-secret"),
        r#"{"model":"fast-chat","messages":[],"max_tokens":9}"#,
    );
    assert!(response.contains("429 Too Many Requests"));
    assert!(response.contains("token_budget_exceeded"));
    assert!(!response.contains("budget-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    assert_eq!(provider_handle.join().unwrap().len(), 0);
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

fn write_visibility_config(path: &std::path::Path, gateway_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:65535/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "public-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[models]]
name = "org-a-private"
provider = "openai"
provider_model = "gpt-4o"
visible_organization_ids = ["org_a"]

[[api_keys]]
id = "tenant_a_models"
name = "Tenant A models"
key = "tenant-a-models-secret"
scopes = ["models.read"]
organization_id = "org_a"

[[api_keys]]
id = "tenant_b_models"
name = "Tenant B models"
key = "tenant-b-models-secret"
scopes = ["models.read"]
organization_id = "org_b"

[[api_keys]]
id = "operator_models"
name = "Operator models"
key = "operator-models-secret"
scopes = ["models.read"]
"#
        ),
    )
    .unwrap();
}

// Regression for #85: GET /v1/models must not leak a model whose
// `visible_organization_ids` excludes the caller's tenant. A tenant-scoped key
// sees only models its tenant may invoke; a platform-operator key (no
// organization_id) sees every enabled model.
#[test]
fn ai_proxy_models_listing_hides_cross_tenant_private_models() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_visibility_config(&config, &gateway_addr);
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let list = |token: &str| {
        http_request(
            &gateway_addr,
            "GET",
            "/v1/models",
            &[&format!("Authorization: Bearer {token}")],
            "",
        )
    };

    // Tenant A owns the restricted model: sees both the public and its private model.
    let tenant_a = list("tenant-a-models-secret");
    assert!(tenant_a.contains("200 OK"), "{tenant_a}");
    assert!(tenant_a.contains("\"id\":\"public-chat\""), "{tenant_a}");
    assert!(tenant_a.contains("\"id\":\"org-a-private\""), "{tenant_a}");

    // Tenant B is excluded by visible_organization_ids: the private model MUST NOT
    // appear (no leak of the logical name or provider mapping), only the public one.
    let tenant_b = list("tenant-b-models-secret");
    assert!(tenant_b.contains("200 OK"), "{tenant_b}");
    assert!(tenant_b.contains("\"id\":\"public-chat\""), "{tenant_b}");
    assert!(!tenant_b.contains("org-a-private"), "{tenant_b}");

    // Platform-operator key (no organization_id) sees every enabled model.
    let operator = list("operator-models-secret");
    assert!(operator.contains("200 OK"), "{operator}");
    assert!(operator.contains("\"id\":\"public-chat\""), "{operator}");
    assert!(operator.contains("\"id\":\"org-a-private\""), "{operator}");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
