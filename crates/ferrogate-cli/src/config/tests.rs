use super::*;

#[test]
fn default_config_uses_localhost_8080() {
    let config = Config::default();
    assert_eq!(config.listen, "127.0.0.1:8080");
    assert!(config.providers.is_empty());
    assert!(config.models.is_empty());
    assert!(config.api_keys.is_empty());
    assert!(config.upstreams.is_empty());
    assert!(config.routes.is_empty());
}

#[test]
fn parses_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "0.0.0.0:8080"

[telemetry]
service_name = "ferrogate-dev"
otlp_endpoint = "http://127.0.0.1:4318"

[[upstreams]]
name = "example"
url = "https://example.com/base"

[[routes]]
name = "example"
upstream = "example"
path_prefixes = ["/proxy"]
strip_prefix = "/proxy"

[[providers]]
name = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
context_window = 128000
input_price_per_1m = 0.15
output_price_per_1m = 0.60
visible_organization_ids = ["org_demo"]
visible_project_ids = ["project_gateway"]

[[models.fallbacks]]
provider = "openai"
provider_model = "gpt-4.1-mini"
priority = 10
weight = 2

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "dev-secret"
scopes = ["models.read", "chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
team_id = "team_platform"
project_id = "project_gateway"
log_bodies = true
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(config.listen, "0.0.0.0:8080");
    assert_eq!(config.telemetry.service_name, "ferrogate-dev");
    assert_eq!(
        config.telemetry.otlp_endpoint.as_deref(),
        Some("http://127.0.0.1:4318")
    );
    assert_eq!(config.providers.len(), 1);
    assert_eq!(config.providers[0].name, "openai");
    assert_eq!(config.models.len(), 1);
    assert_eq!(config.models[0].name, "fast-chat");
    assert_eq!(config.models[0].fallbacks.len(), 1);
    assert_eq!(config.models[0].fallbacks[0].provider_model, "gpt-4.1-mini");
    assert_eq!(config.models[0].fallbacks[0].priority, Some(10));
    assert_eq!(config.models[0].fallbacks[0].weight, Some(2));
    assert_eq!(config.models[0].visible_organization_ids, ["org_demo"]);
    assert_eq!(config.models[0].visible_project_ids, ["project_gateway"]);
    assert_eq!(config.api_keys.len(), 1);
    assert_eq!(config.api_keys[0].id, "key_dev");
    assert_eq!(config.api_keys[0].log_bodies, Some(true));
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}
