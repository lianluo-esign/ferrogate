// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Runtime proof that GET /admin/v1/models and /admin/v1/providers
// honor server-side search/offset/limit for the Admin Console entity-reference
// pickers (#377), while keeping the legacy unpaged envelope backward compatible.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn get(gateway_addr: &str, path: &str) -> serde_json::Value {
    let response = http_request(gateway_addr, "GET", path, &ADMIN, "");
    assert!(
        response.contains("HTTP/1.1 200"),
        "GET {path} failed: {response}"
    );
    response_json(response)
}

fn names(list: &serde_json::Value) -> Vec<String> {
    list["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn models_and_providers_honor_search_and_pagination_at_the_gateway_boundary() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai-us"
kind = "openai"
base_url = "http://127.0.0.1:9/us"

[[providers]]
name = "openai-eu"
kind = "openai"
base_url = "http://127.0.0.1:9/eu"

[[providers]]
name = "anthropic-main"
kind = "anthropic"
base_url = "http://127.0.0.1:9/anthropic"

[[models]]
name = "fast-chat"
provider = "openai-us"
provider_model = "gpt-4o-mini"

[[models]]
name = "smart-chat"
provider = "openai-eu"
provider_model = "gpt-4o"

[[models]]
name = "claude-sonnet"
provider = "anthropic-main"
provider_model = "claude-3-5-sonnet"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // No query params: legacy unpaged envelope is preserved verbatim -- object
    // is a list, every entity is returned, and the pagination fields stay
    // absent so existing clients see no shape change (backward compatibility).
    let all_models = get(&gateway_addr, "/admin/v1/models");
    assert_eq!(all_models["object"], "list");
    assert_eq!(all_models["data"].as_array().unwrap().len(), 3);
    assert_eq!(all_models["total"], serde_json::Value::Null);
    assert_eq!(all_models["offset"], serde_json::Value::Null);
    assert_eq!(all_models["limit"], serde_json::Value::Null);

    let all_providers = get(&gateway_addr, "/admin/v1/providers");
    assert_eq!(all_providers["object"], "list");
    assert_eq!(all_providers["data"].as_array().unwrap().len(), 3);
    assert_eq!(all_providers["total"], serde_json::Value::Null);

    // search filters models on the canonical logical name (substring, case
    // insensitive) -- "chat" matches the two *-chat logical models only.
    let chat_models = get(&gateway_addr, "/admin/v1/models?search=CHAT");
    assert_eq!(chat_models["total"], 2);
    let mut chat_names = names(&chat_models);
    chat_names.sort();
    assert_eq!(chat_names, vec!["fast-chat", "smart-chat"]);

    // search also matches the underlying provider model id -- "claude-3-5"
    // resolves the single Anthropic logical model.
    let claude_models = get(&gateway_addr, "/admin/v1/models?search=claude-3-5");
    assert_eq!(claude_models["total"], 1);
    assert_eq!(claude_models["data"][0]["name"], "claude-sonnet");

    // search filters providers on name/kind -- "openai" matches the two OpenAI
    // providers by both their names and their shared kind.
    let openai_providers = get(&gateway_addr, "/admin/v1/providers?search=openai");
    assert_eq!(openai_providers["total"], 2);
    let mut openai_names = names(&openai_providers);
    openai_names.sort();
    assert_eq!(openai_names, vec!["openai-eu", "openai-us"]);

    // offset/limit paginate against the full (unfiltered) collection and report
    // the pre-page total, echoing the requested window.
    let paged_models = get(&gateway_addr, "/admin/v1/models?offset=1&limit=1");
    assert_eq!(paged_models["total"], 3);
    assert_eq!(paged_models["offset"], 1);
    assert_eq!(paged_models["limit"], 1);
    assert_eq!(paged_models["data"].as_array().unwrap().len(), 1);

    // search + pagination compose: filter first, then page the filtered set.
    let paged_openai = get(
        &gateway_addr,
        "/admin/v1/providers?search=openai&offset=1&limit=1",
    );
    assert_eq!(paged_openai["total"], 2);
    assert_eq!(paged_openai["offset"], 1);
    assert_eq!(paged_openai["limit"], 1);
    assert_eq!(paged_openai["data"].as_array().unwrap().len(), 1);

    // Out-of-range offset yields an empty page but still reports the true total
    // (defaults/bounds behave rather than erroring).
    let empty_page = get(&gateway_addr, "/admin/v1/models?offset=100&limit=10");
    assert_eq!(empty_page["total"], 3);
    assert_eq!(empty_page["offset"], 100);
    assert!(empty_page["data"].as_array().unwrap().is_empty());

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
