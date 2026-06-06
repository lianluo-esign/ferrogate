mod support;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use support::{
    free_addr, http_request, spawn_provider_upstream, spawn_provider_upstream_response,
    start_gateway, wait_for_gateway,
};

#[test]
fn openai_models_and_chat_non_streaming_dispatch_work() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cluster]
enabled = true
cluster_id = "test-cluster"
node_id = "test-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[models]]
name = "smart-chat"
provider = "openai"
provider_model = "gpt-4.1"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat", "smart-chat"]
organization_id = "org_demo"
team_id = "team_platform"
project_id = "project_gateway"
user_id = "user_demo"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[policies]]
name = "disabled smart chat audit"
effect = "deny"
api_key_ids = ["key_dev"]
models = ["smart-chat"]
providers = ["openai"]
code = "policy_disabled"
message = "disabled policy"
enabled = false
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let models = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(models.contains("200 OK"));
    assert!(models.contains("\"id\":\"fast-chat\""));
    assert!(models.contains("\"id\":\"smart-chat\""));

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"object\":\"chat.completion\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));
    assert!(!chat.contains("Bearer"));

    let smart_chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &["x-api-key: client-secret", "Content-Type: application/json"],
        r#"{"model":"smart-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(smart_chat.contains("200 OK"));

    let admin_status = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(admin_status.contains("200 OK"));
    assert!(admin_status.contains("\"runtime\":\"pingora\""));
    assert!(admin_status.contains("\"auth_required\":true"));
    assert!(admin_status.contains("\"cluster\":"));
    assert!(admin_status.contains("\"enabled\":true"));
    assert!(admin_status.contains("\"cluster_id\":\"test-cluster\""));
    assert!(admin_status.contains("\"node_id\":\"test-node-a\""));
    assert!(admin_status.contains("\"node_region\":\"local\""));
    assert!(admin_status.contains("\"node_zone\":\"local-a\""));
    assert!(admin_status.contains("\"state_backend\":\"local\""));
    assert!(admin_status.contains("\"counter_backend\":\"local\""));
    assert!(admin_status.contains("\"active_revision\":\""));
    assert!(admin_status.contains("\"last_sync_at_unix\":"));
    assert!(admin_status.contains("\"last_sync_error\":null"));
    assert!(admin_status.contains("\"stale\":false"));
    assert!(!admin_status.contains("admin-secret"));

    let dashboard = http_request(&gateway_addr, "GET", "/admin/", &[], "");
    assert!(dashboard.contains("200 OK"));
    assert!(dashboard.contains("Content-Type: text/html"));
    assert!(dashboard.contains("FerroGate Admin"));
    assert!(dashboard.contains("/admin/v1/status"));
    assert!(dashboard.contains("/admin/v1/api-keys"));
    assert!(dashboard.contains("/admin/v1/provider-health"));
    assert!(dashboard.contains("/admin/v1/request-logs"));
    assert!(dashboard.contains("/admin/v1/config/validate"));
    assert!(dashboard.contains("/admin/v1/config/reload"));
    assert!(dashboard.contains("/admin/v1/audit-events"));
    assert!(!dashboard.contains("admin-secret"));
    assert!(!dashboard.contains("client-secret"));
    assert!(!dashboard.contains("provider-secret"));

    let valid_candidate = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"config_toml":"listen = \"127.0.0.1:19090\"\n"}"#,
    );
    assert!(valid_candidate.contains("200 OK"));
    assert!(valid_candidate.contains("\"valid\":true"));
    assert!(valid_candidate.contains("\"snapshot\":"));
    assert!(valid_candidate.contains("\"reload_mode\":\"listener-level-required\""));
    assert!(valid_candidate.contains("\"listener_reload_required\":true"));
    assert!(valid_candidate.contains("listen address changes require listener-level reload"));
    assert!(!valid_candidate.contains("admin-secret"));

    let process_local_candidate_body =
        serde_json::json!({ "config_toml": format!("listen = \"{gateway_addr}\"\n") }).to_string();
    let process_local_candidate = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &process_local_candidate_body,
    );
    assert!(process_local_candidate.contains("200 OK"));
    assert!(process_local_candidate.contains("\"valid\":true"));
    assert!(process_local_candidate.contains("\"reload_mode\":\"process-local\""));
    assert!(process_local_candidate.contains("\"listener_reload_required\":false"));

    let source_file_candidate = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"source":"file"}"#,
    );
    assert!(source_file_candidate.contains("200 OK"));
    assert!(source_file_candidate.contains("\"valid\":true"));
    assert!(source_file_candidate.contains("\"reload_mode\":\"process-local\""));
    assert!(source_file_candidate.contains("\"listener_reload_required\":false"));

    let invalid_candidate = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"config_toml":"listen = \"not-an-address\"\n"}"#,
    );
    assert!(invalid_candidate.contains("200 OK"));
    assert!(invalid_candidate.contains("\"valid\":false"));
    assert!(invalid_candidate.contains("field listen"));
    assert!(!invalid_candidate.contains("admin-secret"));

    let denied_write = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"config_toml":"listen = \"127.0.0.1:19090\"\n"}"#,
    );
    assert!(denied_write.contains("403 Forbidden"));
    assert!(denied_write.contains("scope_denied"));

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"));
    assert!(audit_events.contains("\"action\":\"config.validate\""));
    assert!(audit_events.contains("\"actor_api_key_id\":\"admin\""));
    assert!(audit_events.contains("\"cluster_id\":\"test-cluster\""));
    assert!(audit_events.contains("\"node_id\":\"test-node-a\""));
    assert!(audit_events.contains("\"outcome\":\"accepted\""));
    assert!(audit_events.contains("\"outcome\":\"rejected\""));
    assert!(!audit_events.contains("client-secret"));
    assert!(!audit_events.contains("admin-secret"));

    let providers = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/providers",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(providers.contains("200 OK"));
    assert!(providers.contains("\"name\":\"openai\""));
    assert!(providers.contains("\"kind\":\"openai\""));
    assert!(providers.contains("\"has_api_key\":true"));
    assert!(!providers.contains("FERROGATE_PROVIDER_SECRET"));
    assert!(!providers.contains("provider-secret"));

    let provider_health = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/provider-health",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(provider_health.contains("200 OK"));
    assert!(provider_health.contains("\"name\":\"openai\""));
    assert!(provider_health.contains("\"status\":"));
    assert!(provider_health.contains("\"reachable\":"));
    assert!(provider_health.contains("\"routing\":"));
    assert!(provider_health.contains("\"observed_requests\":2"));
    assert!(provider_health.contains("\"successful_requests\":2"));
    assert!(provider_health.contains("\"failed_requests\":0"));
    assert!(provider_health.contains("\"average_latency_ms\":"));
    assert!(provider_health.contains("\"failure_rate\":0.0"));
    assert!(provider_health.contains("\"health_rank\":0"));
    assert!(provider_health.contains("\"health_reason\":\"healthy_observations\""));
    assert!(!provider_health.contains("FERROGATE_PROVIDER_SECRET"));
    assert!(!provider_health.contains("provider-secret"));

    let models_admin = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/models",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(models_admin.contains("200 OK"));
    assert!(models_admin.contains("\"name\":\"fast-chat\""));
    assert!(models_admin.contains("\"provider_model\":\"gpt-4o-mini\""));
    assert!(models_admin.contains("\"input_price_per_1m\":1.0"));

    let api_keys = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(api_keys.contains("200 OK"));
    assert!(api_keys.contains("\"id\":\"key_dev\""));
    assert!(api_keys.contains("\"key_source\":\"inline\""));
    assert!(api_keys.contains("\"organization_id\":\"org_demo\""));
    assert!(!api_keys.contains("client-secret"));
    assert!(!api_keys.contains("admin-secret"));
    assert!(!api_keys.contains("key_hash"));
    assert!(!api_keys.contains("key_env"));

    let policies = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/policies",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(policies.contains("200 OK"));
    assert!(policies.contains("\"name\":\"disabled smart chat audit\""));
    assert!(policies.contains("\"enabled\":false"));

    let tenants = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenants",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(tenants.contains("200 OK"));
    assert!(tenants.contains("\"organization_id\":\"org_demo\""));
    assert!(tenants.contains("\"team_id\":\"team_platform\""));
    assert!(tenants.contains("\"project_id\":\"project_gateway\""));
    assert!(tenants.contains("\"user_id\":\"user_demo\""));
    assert!(tenants.contains("\"api_key_id\":\"key_dev\""));

    let request_logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(request_logs.contains("200 OK"));
    assert!(request_logs.contains("\"logical_model\":\"fast-chat\""));
    assert!(request_logs.contains("\"logical_model\":\"smart-chat\""));
    assert!(request_logs.contains("\"cluster_id\":\"test-cluster\""));
    assert!(request_logs.contains("\"node_id\":\"test-node-a\""));
    assert!(request_logs.contains("\"status_code\":200"));
    assert!(!request_logs.contains("client-secret"));

    let billing_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(billing_events.contains("200 OK"));
    assert!(billing_events.contains("\"logical_model\":\"fast-chat\""));
    assert!(billing_events.contains("\"provider\":\"openai\""));
    assert!(billing_events.contains("\"cluster_id\":\"test-cluster\""));
    assert!(billing_events.contains("\"node_id\":\"test-node-a\""));
    assert!(billing_events.contains("\"total_tokens\":8"));
    assert!(billing_events.contains("\"currency\":\"USD\""));

    let usage_aggregates = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/usage-aggregates",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(usage_aggregates.contains("200 OK"));
    assert!(usage_aggregates.contains("\"organization_id\":\"org_demo\""));
    assert!(usage_aggregates.contains("\"api_key_id\":\"key_dev\""));
    assert!(usage_aggregates.contains("\"logical_model\":\"fast-chat\""));
    assert!(usage_aggregates.contains("\"logical_model\":\"smart-chat\""));
    assert!(usage_aggregates.contains("\"total_tokens\":8"));

    let denied_request_logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(denied_request_logs.contains("403 Forbidden"));
    assert!(denied_request_logs.contains("scope_denied"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0].contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_requests[0].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[0].contains(r#""model":"gpt-4o-mini""#));
    assert!(!provider_requests[0].contains("fast-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
    assert!(provider_requests[1].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[1].contains(r#""model":"gpt-4.1""#));
    assert!(!provider_requests[1].contains("smart-chat"));
    assert!(!provider_requests[1].contains("client-secret"));
}

#[test]
fn openrouter_chat_dispatch_uses_openai_compatible_path_and_metadata_headers() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openrouter"
kind = "openrouter"
base_url = "http://{provider_addr}/api/v1"
api_key_env = "FERROGATE_OPENROUTER_SECRET"
openrouter_http_referer = "https://ferrogate.example"
openrouter_x_title = "FerroGate Test"

[[models]]
name = "router-chat"
provider = "openrouter"
provider_model = "openai/gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["router-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_OPENROUTER_SECRET", "openrouter-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"router-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"object\":\"chat.completion\""));
    assert!(!chat.contains("openrouter-secret"));
    assert!(!chat.contains("client-secret"));
    assert!(!chat.contains("Bearer"));

    gateway.kill().ok();
    gateway.wait().ok();
    let requests = provider_handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    let provider_request = &requests[0];
    assert!(provider_request.contains("POST /api/v1/chat/completions HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer openrouter-secret"));
    assert!(provider_request.contains("http-referer: https://ferrogate.example"));
    assert!(provider_request.contains("x-title: FerroGate Test"));
    assert!(provider_request.contains(r#""model":"openai/gpt-4o-mini""#));
    assert!(!provider_request.contains("router-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn openai_responses_non_streaming_dispatch_work() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"resp_test","object":"response","output_text":"ok","usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}"#,
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
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4.1-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = http_request(
        &gateway_addr,
        "POST",
        "/v1/responses",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","input":"hello"}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response.contains("\"object\":\"response\""));
    assert!(!response.contains("provider-secret"));
    assert!(!response.contains("client-secret"));

    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(logs.contains("200 OK"));
    assert!(logs.contains("\"route\":\"openai.responses\""));
    assert!(logs.contains("\"logical_model\":\"fast-chat\""));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    let provider_request = &provider_requests[0];
    assert!(provider_request.contains("POST /v1/responses HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer provider-secret"));
    assert!(provider_request.contains(r#""model":"gpt-4.1-mini""#));
    assert!(provider_request.contains(r#""input":"hello""#));
    assert!(provider_request.contains(r#""stream":false"#));
    assert!(!provider_request.contains("fast-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn anthropic_responses_dispatch_converts_request_shape() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"msg_test","type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":3,"output_tokens":5}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "anthropic"
kind = "anthropic"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "claude-chat"
provider = "anthropic"
provider_model = "claude-3-5-sonnet-latest"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create"]
allowed_models = ["claude-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = http_request(
        &gateway_addr,
        "POST",
        "/v1/responses",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"claude-chat","instructions":"be concise","input":"hello","max_output_tokens":64}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response.contains("\"type\":\"message\""));
    assert!(!response.contains("provider-secret"));
    assert!(!response.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    let provider_request = &provider_requests[0];
    assert!(provider_request.contains("POST /v1/messages HTTP/1.1"));
    assert!(provider_request.contains("x-api-key: provider-secret"));
    assert!(provider_request.contains("anthropic-version: 2023-06-01"));
    assert!(provider_request.contains(r#""model":"claude-3-5-sonnet-latest""#));
    assert!(provider_request.contains(r#""system":"be concise""#));
    assert!(provider_request.contains(r#""content":"hello""#));
    assert!(provider_request.contains(r#""max_tokens":64"#));
    assert!(!provider_request.contains("claude-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn admin_process_local_reload_swaps_request_state_without_rebinding_listener() {
    let gateway_addr = free_addr();
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
base_url = "http://127.0.0.1:1/v1"

[[models]]
name = "old-chat"
provider = "openai"
provider_model = "gpt-old"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read"]
allowed_models = ["old-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let before = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(before.contains("200 OK"));
    assert!(before.contains("\"id\":\"old-chat\""));
    assert!(!before.contains("\"id\":\"new-chat\""));

    let candidate = format!(
        r#"
"{gateway_addr}" {{
    ai_gateway {{
        provider openai {{
            base_url http://127.0.0.1:1/v1
        }}
        model new-chat -> openai:gpt-new {{
            capabilities chat
        }}
        api_key client {{
            name Client
            key client-secret
            scopes models.read
            allowed_models new-chat
        }}
        api_key admin {{
            name Admin
            key admin-secret
            scopes admin.read admin.write
        }}
    }}
}}
"#
    );
    let reload_body = serde_json::json!({
        "config_caddyfile": candidate,
        "filename": "candidate.Caddyfile"
    })
    .to_string();
    let reload = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &reload_body,
    );
    assert!(reload.contains("200 OK"));
    assert!(reload.contains("\"valid\":true"));
    assert!(reload.contains("\"committed\":true"));
    assert!(reload.contains("\"mode\":\"process-local\""));
    assert!(!reload.contains("admin-secret"));

    let after = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(after.contains("200 OK"));
    assert!(after.contains("\"id\":\"new-chat\""));
    assert!(!after.contains("\"id\":\"old-chat\""));

    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:1/v1"

[[models]]
name = "file-chat"
provider = "openai"
provider_model = "gpt-file"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read"]
allowed_models = ["file-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();
    let file_reload = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args([
            "reload",
            "--config",
            config.to_str().unwrap(),
            "--admin-url",
            &format!("http://{gateway_addr}"),
            "--admin-token",
            "admin-secret",
        ])
        .output()
        .unwrap();
    assert!(
        file_reload.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&file_reload.stderr)
    );
    let file_reload_stdout = String::from_utf8_lossy(&file_reload.stdout);
    assert!(file_reload_stdout.contains("FerroGate reload request OK"));
    assert!(file_reload_stdout.contains("valid=true"));
    assert!(file_reload_stdout.contains("committed=true"));
    assert!(file_reload_stdout.contains("mode=process-local"));
    assert!(!file_reload_stdout.contains("admin-secret"));

    let after_file_reload = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(after_file_reload.contains("200 OK"));
    assert!(after_file_reload.contains("\"id\":\"file-chat\""));
    assert!(!after_file_reload.contains("\"id\":\"new-chat\""));

    let rejected_candidate = r#"
127.0.0.1:1 {
    ai_gateway {
        provider openai {
            base_url http://127.0.0.1:1/v1
        }
        model rejected-chat -> openai:gpt-rejected {
            capabilities chat
        }
        api_key client {
            name Client
            key client-secret
            scopes models.read
        }
        api_key admin {
            name Admin
            key admin-secret
            scopes admin.read admin.write
        }
    }
}
"#;
    let rejected_body = serde_json::json!({
        "config_caddyfile": rejected_candidate,
        "filename": "candidate.Caddyfile"
    })
    .to_string();
    let rejected = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &rejected_body,
    );
    assert!(rejected.contains("200 OK"));
    assert!(rejected.contains("\"valid\":true"));
    assert!(rejected.contains("\"committed\":false"));
    assert!(rejected.contains("listener-level reload"));

    let after_reject = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(after_reject.contains("200 OK"));
    assert!(after_reject.contains("\"id\":\"file-chat\""));
    assert!(!after_reject.contains("\"id\":\"rejected-chat\""));

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"));
    assert!(audit_events.contains("\"action\":\"config.reload\""));
    assert!(audit_events.contains("\"outcome\":\"committed\""));
    assert!(audit_events.contains("\"outcome\":\"rejected\""));
    assert!(!audit_events.contains("admin-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn admin_api_key_crud_updates_runtime_auth_state() {
    let gateway_addr = free_addr();
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
base_url = "http://127.0.0.1:1/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[models]]
name = "slow-chat"
provider = "openai"
provider_model = "gpt-4.1"
capabilities = ["chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let create_body = serde_json::json!({
        "id": "client",
        "name": "Client key",
        "key": "client-secret",
        "scopes": ["models.read"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_admin_crud",
        "log_bodies": true
    })
    .to_string();
    let created = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/api-keys",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &create_body,
    );
    assert!(created.contains("201 Created"));
    assert!(created.contains("\"object\":\"api_key\""));
    assert!(created.contains("\"id\":\"client\""));
    assert!(created.contains("\"key_source\":\"inline\""));
    assert!(created.contains("\"organization_id\":\"org_admin_crud\""));
    assert!(created.contains("\"log_bodies\":true"));
    assert!(!created.contains("client-secret"));
    assert!(!created.contains("admin-secret"));

    let models_with_new_key = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(models_with_new_key.contains("200 OK"));
    assert!(models_with_new_key.contains("\"id\":\"fast-chat\""));
    assert!(models_with_new_key.contains("\"id\":\"slow-chat\""));

    let update_body = serde_json::json!({
        "id": "client",
        "name": "Updated client key",
        "key": "client-secret-2",
        "scopes": ["models.read"],
        "allowed_models": ["slow-chat"],
        "enabled": true
    })
    .to_string();
    let updated = http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/api-keys/client",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &update_body,
    );
    assert!(updated.contains("200 OK"));
    assert!(updated.contains("\"name\":\"Updated client key\""));
    assert!(updated.contains("\"allowed_models\":[\"slow-chat\"]"));
    assert!(!updated.contains("client-secret-2"));

    let old_secret_rejected = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(old_secret_rejected.contains("401 Unauthorized"));
    assert!(old_secret_rejected.contains("invalid_api_key"));

    let new_secret_allowed = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret-2"],
        "",
    );
    assert!(new_secret_allowed.contains("200 OK"));
    assert!(new_secret_allowed.contains("\"id\":\"fast-chat\""));
    assert!(new_secret_allowed.contains("\"id\":\"slow-chat\""));

    let get_one = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/client",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(get_one.contains("200 OK"));
    assert!(get_one.contains("\"object\":\"api_key\""));
    assert!(get_one.contains("\"id\":\"client\""));
    assert!(!get_one.contains("client-secret-2"));

    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/api-keys/client",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(delete.contains("200 OK"));
    assert!(delete.contains("\"deleted\":true"));

    let deleted_secret_rejected = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret-2"],
        "",
    );
    assert!(deleted_secret_rejected.contains("401 Unauthorized"));
    assert!(deleted_secret_rejected.contains("invalid_api_key"));

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"));
    assert!(audit_events.contains("\"action\":\"api_key.upsert\""));
    assert!(audit_events.contains("\"action\":\"api_key.delete\""));
    assert!(!audit_events.contains("client-secret"));
    assert!(!audit_events.contains("client-secret-2"));
    assert!(!audit_events.contains("admin-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn admin_policy_crud_updates_runtime_policy_engine() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_policy","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
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
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let create_body = serde_json::json!({
        "name": "block-client-fast-chat",
        "api_key_ids": ["client"],
        "models": ["fast-chat"],
        "providers": ["openai"],
        "code": "blocked_by_admin",
        "message": "blocked by admin policy"
    })
    .to_string();
    let created = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/policies",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &create_body,
    );
    assert!(created.contains("201 Created"));
    assert!(created.contains("\"object\":\"policy\""));
    assert!(created.contains("\"name\":\"block-client-fast-chat\""));
    assert!(created.contains("\"enabled\":true"));
    assert!(!created.contains("admin-secret"));
    assert!(!created.contains("client-secret"));

    let blocked_chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(blocked_chat.contains("403 Forbidden"));
    assert!(blocked_chat.contains("blocked_by_admin"));
    assert!(blocked_chat.contains("blocked by admin policy"));

    let update_body = serde_json::json!({
        "name": "block-client-fast-chat",
        "api_key_ids": ["client"],
        "models": ["fast-chat"],
        "providers": ["openai"],
        "code": "blocked_by_admin",
        "message": "blocked by admin policy",
        "enabled": false
    })
    .to_string();
    let updated = http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/policies/block-client-fast-chat",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &update_body,
    );
    assert!(updated.contains("200 OK"));
    assert!(updated.contains("\"enabled\":false"));

    let allowed_chat_after_disable = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(allowed_chat_after_disable.contains("200 OK"));
    assert!(allowed_chat_after_disable.contains("\"id\":\"chatcmpl_policy\""));

    let get_one = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/policies/block-client-fast-chat",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(get_one.contains("200 OK"));
    assert!(get_one.contains("\"object\":\"policy\""));
    assert!(get_one.contains("\"name\":\"block-client-fast-chat\""));

    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/policies/block-client-fast-chat",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(delete.contains("200 OK"));
    assert!(delete.contains("\"object\":\"policy\""));
    assert!(delete.contains("\"deleted\":true"));

    let allowed_chat_after_delete = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(allowed_chat_after_delete.contains("200 OK"));
    assert!(allowed_chat_after_delete.contains("\"id\":\"chatcmpl_policy\""));

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"));
    assert!(audit_events.contains("\"action\":\"policy.upsert\""));
    assert!(audit_events.contains("\"action\":\"policy.delete\""));
    assert!(!audit_events.contains("admin-secret"));
    assert!(!audit_events.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
}

#[test]
fn graceful_upgrade_reload_transfers_listener_to_new_process() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let pid_file = dir.path().join("ferrogate.pid");
    let upgrade_sock = dir.path().join("ferrogate_upgrade.sock");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[reliability]
graceful_shutdown_grace_period_secs = 1
graceful_shutdown_timeout_secs = 1
graceful_upgrade_pid_file = "{}"
graceful_upgrade_sock = "{}"
graceful_upgrade_sock_retries = 8

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:1/v1"

[[models]]
name = "old-chat"
provider = "openai"
provider_model = "gpt-old"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read"]
allowed_models = ["old-chat"]
"#,
            pid_file.display(),
            upgrade_sock.display()
        ),
    )
    .unwrap();

    let mut old_gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let before = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(before.contains("200 OK"));
    assert!(before.contains("\"id\":\"old-chat\""));

    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[reliability]
graceful_shutdown_grace_period_secs = 1
graceful_shutdown_timeout_secs = 1
graceful_upgrade_pid_file = "{}"
graceful_upgrade_sock = "{}"
graceful_upgrade_sock_retries = 8

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:1/v1"

[[models]]
name = "new-chat"
provider = "openai"
provider_model = "gpt-new"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read"]
allowed_models = ["new-chat"]
"#,
            pid_file.display(),
            upgrade_sock.display()
        ),
    )
    .unwrap();

    let reload = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args([
            "reload",
            "--config",
            config.to_str().unwrap(),
            "--graceful-upgrade",
        ])
        .output()
        .unwrap();
    assert!(
        reload.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&reload.stderr)
    );
    let reload_stdout = String::from_utf8_lossy(&reload.stdout);
    assert!(reload_stdout.contains("FerroGate graceful upgrade requested"));
    assert!(reload_stdout.contains("mode=listener-level"));

    let upgraded = wait_for_models_contains(&gateway_addr, "client-secret", "\"id\":\"new-chat\"");
    assert!(upgraded.contains("200 OK"));
    assert!(!upgraded.contains("\"id\":\"old-chat\""));

    let new_pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .to_string();
    terminate_pid(&new_pid);
    let _ = old_gateway.wait();
}

#[test]
fn openai_chat_streaming_sse_dispatch_works() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream();
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
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(chat.contains("data: {\"choices\""));
    assert!(chat.contains("data: [DONE]"));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer provider-secret"));
    assert!(provider_request.contains(r#""model":"gpt-4o-mini""#));
    assert!(provider_request.contains(r#""stream":true"#));
    assert!(!provider_request.contains("fast-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn openai_chat_streaming_sse_forwards_first_chunk_before_provider_finishes() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_slow_sse_provider_upstream();
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
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let started = Instant::now();
    let mut stream = TcpStream::connect(&gateway_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let body =
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer client-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();

    let mut response = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "gateway closed before first SSE chunk");
        response.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&response);
        if text.contains("data: {\"choices\"") {
            assert!(
                started.elapsed() < Duration::from_millis(900),
                "first SSE chunk was buffered until provider completion"
            );
            assert!(!text.contains("data: [DONE]"));
            break;
        }
    }

    let mut rest = String::new();
    stream.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains(r#""stream":true"#));
}

#[test]
fn gemini_chat_non_streaming_dispatch_converts_request_shape() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "gemini"
kind = "gemini"
base_url = "http://{provider_addr}/v1beta"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "flash-chat"
provider = "gemini"
provider_model = "gemini-2.5-flash"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["flash-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"flash-chat","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"max_tokens":64}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"usageMetadata\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0]
        .contains("POST /v1beta/models/gemini-2.5-flash:generateContent HTTP/1.1"));
    assert!(provider_requests[0].contains("x-goog-api-key: provider-secret"));
    assert!(provider_requests[0].contains(r#""role":"user""#));
    assert!(provider_requests[0].contains(r#""text":"hello""#));
    assert!(provider_requests[0].contains(r#""systemInstruction""#));
    assert!(provider_requests[0].contains(r#""maxOutputTokens":64"#));
    assert!(!provider_requests[0].contains("flash-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
}

#[test]
fn azure_openai_chat_non_streaming_dispatch_uses_deployment_endpoint() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_azure","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "azure-eastus"
kind = "azure-openai"
base_url = "http://{provider_addr}?api-version=2024-02-15-preview"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "azure-eastus"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}],"stream":false}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"id\":\"chatcmpl_azure\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0].contains(
        "POST /openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview HTTP/1.1"
    ));
    assert!(provider_requests[0].contains("api-key: provider-secret"));
    assert!(provider_requests[0].contains(r#""messages""#));
    assert!(provider_requests[0].contains(r#""role":"user""#));
    assert!(provider_requests[0].contains(r#""content":"hello""#));
    assert!(!provider_requests[0].contains(r#""model":"fast-chat""#));
    assert!(!provider_requests[0].contains("client-secret"));
}

#[test]
fn chat_dispatch_falls_back_after_primary_provider_5xx() {
    let gateway_addr = free_addr();
    let (primary_addr, primary_handle) = spawn_provider_response(
        "HTTP/1.1 503 Service Unavailable",
        r#"{"error":{"message":"temporarily unavailable","type":"server_error","code":"unavailable"}}"#,
    );
    let (fallback_addr, fallback_handle) = spawn_provider_response(
        "HTTP/1.1 200 OK",
        r#"{"id":"chatcmpl_fallback","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "primary"
kind = "openai"
base_url = "http://{primary_addr}/v1"

[[providers]]
name = "backup"
kind = "openai"
base_url = "http://{fallback_addr}/v1"

[[models]]
name = "fast-chat"
provider = "primary"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[models.fallbacks]]
provider = "backup"
provider_model = "gpt-4.1-mini"
priority = 10
weight = 1

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"id\":\"chatcmpl_fallback\""));
    assert!(!chat.contains("temporarily unavailable"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let primary_request = primary_handle.join().unwrap();
    let fallback_request = fallback_handle.join().unwrap();
    assert!(primary_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(primary_request.contains(r#""model":"gpt-4o-mini""#));
    assert!(fallback_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(fallback_request.contains(r#""model":"gpt-4.1-mini""#));
    assert!(!fallback_request.contains("fast-chat"));
    assert!(!fallback_request.contains("client-secret"));
}

#[test]
fn provider_circuit_breaker_skips_unhealthy_primary_after_threshold() {
    let gateway_addr = free_addr();
    let (primary_addr, primary_handle) = spawn_provider_upstream_response(
        2,
        "503 Service Unavailable",
        "application/json",
        r#"{"error":{"message":"temporarily unavailable","type":"server_error","code":"unavailable"}}"#,
    );
    let (fallback_addr, fallback_handle) = spawn_provider_upstream_response(
        3,
        "200 OK",
        "application/json",
        r#"{"id":"chatcmpl_fallback","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[reliability]
provider_circuit_breaker_failure_threshold = 2
provider_circuit_breaker_cooldown_secs = 60

[[providers]]
name = "primary"
kind = "openai"
base_url = "http://{primary_addr}/v1"

[[providers]]
name = "backup"
kind = "openai"
base_url = "http://{fallback_addr}/v1"

[[models]]
name = "fast-chat"
provider = "primary"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[models.fallbacks]]
provider = "backup"
provider_model = "gpt-4.1-mini"
priority = 10
weight = 1

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    for _ in 0..3 {
        let chat = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer client-secret",
                "Content-Type: application/json",
            ],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        );
        assert!(chat.contains("200 OK"));
        assert!(chat.contains("\"id\":\"chatcmpl_fallback\""));
        assert!(!chat.contains("client-secret"));
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let primary_requests = primary_handle.join().unwrap();
    let fallback_requests = fallback_handle.join().unwrap();
    assert_eq!(primary_requests.len(), 2);
    assert_eq!(fallback_requests.len(), 3);
    assert!(fallback_requests
        .iter()
        .all(|request| request.contains(r#""model":"gpt-4.1-mini""#)));
}

#[test]
fn chat_retries_retryable_provider_status_before_fallback() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sequenced_provider_upstream(vec![
        (
            "503 Service Unavailable",
            r#"{"error":{"message":"temporarily unavailable","type":"server_error","code":"unavailable"}}"#,
        ),
        (
            "200 OK",
            r#"{"id":"chatcmpl_retry","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
        ),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[reliability]
provider_dispatch_timeout_secs = 2
provider_dispatch_max_retries = 1

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"id\":\"chatcmpl_retry\""));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
    assert!(provider_requests
        .iter()
        .all(|request| request.contains(r#""model":"gpt-4o-mini""#)));
}

#[test]
fn admin_provider_health_reports_reachable_provider_without_secret() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_tcp_probe_target();
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
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let health = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/provider-health",
        &["Authorization: Bearer admin-secret"],
        "",
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    provider_handle.join().unwrap();

    assert!(health.contains("200 OK"));
    assert!(health.contains("\"name\":\"openai\""));
    assert!(health.contains("\"status\":\"healthy\""));
    assert!(health.contains("\"reachable\":true"));
    assert!(!health.contains("FERROGATE_PROVIDER_SECRET"));
    assert!(!health.contains("provider-secret"));
    assert!(!health.contains("admin-secret"));
}

fn spawn_sse_provider_upstream() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

fn spawn_slow_sse_provider_upstream() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream
            .write_all(b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
            .unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(1200));
        stream.write_all(b"data: [DONE]\n\n").unwrap();
        request
    });
    (addr, handle)
}

fn spawn_provider_response(
    status_line: &'static str,
    body: &'static str,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        write!(
            stream,
            "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

fn spawn_sequenced_provider_upstream(
    responses: Vec<(&'static str, &'static str)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status_line, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

fn spawn_tcp_probe_target() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
    });
    (addr, handle)
}

fn wait_for_models_contains(addr: &str, token: &str, needle: &str) -> String {
    let started = Instant::now();
    let auth = format!("Authorization: Bearer {token}");
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(15) {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write!(
                stream,
                "GET /v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.contains(needle) {
                return response;
            }
            last = response;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!("models response did not contain {needle}; last response: {last}");
}

fn terminate_pid(pid: &str) {
    let _ = Command::new("kill").args(["-TERM", pid]).status();
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if request.len().saturating_sub(header_end + 4) >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
