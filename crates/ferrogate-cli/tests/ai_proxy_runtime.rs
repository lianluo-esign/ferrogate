// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

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
fn clustered_gateways_report_shared_cluster_and_distinct_nodes() {
    let first_addr = free_addr();
    let second_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let first_config = dir.path().join("ferrogate-node-a.toml");
    let second_config = dir.path().join("ferrogate-node-b.toml");
    std::fs::write(
        &first_config,
        cluster_status_config(&first_addr, "test-node-a", "admin-secret-a"),
    )
    .unwrap();
    std::fs::write(
        &second_config,
        cluster_status_config(&second_addr, "test-node-b", "admin-secret-b"),
    )
    .unwrap();

    let mut first_gateway = start_gateway(&first_config);
    let mut second_gateway = start_gateway(&second_config);
    wait_for_gateway(&first_addr);
    wait_for_gateway(&second_addr);

    let first_status = admin_status_json(&first_addr, "admin-secret-a");
    let second_status = admin_status_json(&second_addr, "admin-secret-b");
    let first_ready = readiness_json(&first_addr);
    let second_ready = readiness_json(&second_addr);
    let first_cluster = &first_status["cluster"];
    let second_cluster = &second_status["cluster"];

    assert_eq!(first_status["service"], "ferrogate");
    assert_eq!(second_status["service"], "ferrogate");
    assert_eq!(first_ready["service"], "ferrogate");
    assert_eq!(second_ready["service"], "ferrogate");
    assert_eq!(first_cluster["enabled"], true);
    assert_eq!(second_cluster["enabled"], true);
    assert_eq!(first_cluster["cluster_id"], "test-cluster");
    assert_eq!(second_cluster["cluster_id"], "test-cluster");
    assert_eq!(first_cluster["node_id"], "test-node-a");
    assert_eq!(second_cluster["node_id"], "test-node-b");
    assert_ne!(first_cluster["node_id"], second_cluster["node_id"]);
    assert_eq!(first_cluster["node_region"], "local");
    assert_eq!(second_cluster["node_region"], "local");
    assert_eq!(first_cluster["node_zone"], "local-a");
    assert_eq!(second_cluster["node_zone"], "local-b");
    assert_eq!(first_cluster["state_backend"], "local");
    assert_eq!(second_cluster["state_backend"], "local");
    assert_eq!(first_cluster["counter_backend"], "local");
    assert_eq!(second_cluster["counter_backend"], "local");
    assert!(first_cluster["active_revision"].as_str().unwrap().len() >= 16);
    assert!(second_cluster["active_revision"].as_str().unwrap().len() >= 16);
    assert!(first_cluster["last_sync_at_unix"].as_u64().is_some());
    assert!(second_cluster["last_sync_at_unix"].as_u64().is_some());
    assert!(first_cluster["last_sync_error"].is_null());
    assert!(second_cluster["last_sync_error"].is_null());
    assert_eq!(first_cluster["stale"], false);
    assert_eq!(second_cluster["stale"], false);
    assert_eq!(first_cluster["ready"], true);
    assert_eq!(second_cluster["ready"], true);
    assert_eq!(first_cluster["readiness_reason"], "state_loaded");
    assert_eq!(second_cluster["readiness_reason"], "state_loaded");
    assert_eq!(first_ready["status"], "ready");
    assert_eq!(second_ready["status"], "ready");
    assert_eq!(first_ready["cluster"]["cluster_id"], "test-cluster");
    assert_eq!(second_ready["cluster"]["cluster_id"], "test-cluster");
    assert_eq!(first_ready["cluster"]["node_id"], "test-node-a");
    assert_eq!(second_ready["cluster"]["node_id"], "test-node-b");

    first_gateway.kill().unwrap();
    first_gateway.wait().unwrap();
    second_gateway.kill().unwrap();
    second_gateway.wait().unwrap();
}

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
    assert!(admin_status.contains("\"service\":\"ferrogate\""));
    assert!(!admin_status.contains("\"service\":\"ferrogate-cli\""));
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
    assert!(admin_status.contains("\"ready\":true"));
    assert!(admin_status.contains("\"readiness_reason\":\"state_loaded\""));
    assert!(admin_status.contains("\"draining\":false"));
    assert!(admin_status.contains("\"accepting_new_requests\":true"));
    assert!(!admin_status.contains("admin-secret"));

    let drain_status = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/drain",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(drain_status.contains("200 OK"));
    assert!(drain_status.contains("\"object\":\"drain_status\""));
    assert!(drain_status.contains("\"draining\":false"));
    assert!(drain_status.contains("\"accepting_new_requests\":true"));
    assert!(drain_status.contains("\"drain_reason\":\"not_draining\""));

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
    assert!(providers.contains("\"compatibility\":\"openai-compatible\""));
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
    assert!(provider_health.contains("\"local_observations\":"));
    assert!(provider_health.contains("\"cluster_observations\":null"));
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
id = "tenant-a"
name = "Tenant A"
key = "tenant-a-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_a"
project_id = "project_a"
user_id = "user_a"

[[api_keys]]
id = "tenant-b"
name = "Tenant B"
key = "tenant-b-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_b"
project_id = "project_b"
user_id = "user_b"

[[api_keys]]
id = "tenant-c"
name = "Tenant C"
key = "tenant-c-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_c"
project_id = "project_c"
user_id = "user_c"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
"#
        ),
    )
    .unwrap();
    let reload = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "config_toml": std::fs::read_to_string(&config).unwrap(),
            "filename": "ferrogate.toml"
        })
        .to_string(),
    );
    assert!(reload.contains("200 OK"), "{reload}");
    assert!(reload.contains("\"committed\":true"), "{reload}");

    let tenants_after_reload = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenants",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        tenants_after_reload.contains("200 OK"),
        "{tenants_after_reload}"
    );
    assert!(
        tenants_after_reload.contains("\"organization_id\":\"org_a\""),
        "{tenants_after_reload}"
    );
    assert!(
        tenants_after_reload.contains("\"api_key_id\":\"tenant-a\""),
        "{tenants_after_reload}"
    );

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

    let metering_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/metering-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(metering_events.contains("200 OK"));
    assert!(metering_events.contains("\"logical_model\":\"fast-chat\""));
    assert!(metering_events.contains("\"provider\":\"openai\""));
    assert!(metering_events.contains("\"cluster_id\":\"test-cluster\""));
    assert!(metering_events.contains("\"node_id\":\"test-node-a\""));
    assert!(metering_events.contains("\"total_tokens\":8"));
    assert!(!metering_events.contains("\"cost\""));
    assert!(!metering_events.contains("\"currency\""));

    let billing_alias = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(billing_alias.contains("200 OK"));
    assert!(billing_alias.contains("\"total_tokens\":8"));
    assert!(!billing_alias.contains("\"cost\""));

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
        &["Authorization: Bearer tenant-c-secret"],
        "",
    );
    assert!(denied_request_logs.contains("403 Forbidden"));
    assert!(denied_request_logs.contains("scope_denied"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
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
fn openai_compatible_client_shape_preserves_framework_traffic_evidence() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_framework","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"framework ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":11,"total_tokens":18}}"#,
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
kind = "openai-compatible"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "agent-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "framework-key"
name = "Framework key"
key = "client-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["agent-chat"]
organization_id = "org_agents"
team_id = "team_orchestration"
project_id = "project_framework_smoke"
user_id = "user_agent_runner"
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
            "User-Agent: OpenAI/Python framework-smoke",
            "X-FerroGate-Framework: langchain",
        ],
        r#"{"model":"agent-chat","messages":[{"role":"system","content":"You are a terse assistant."},{"role":"user","content":"hello from a framework client"}],"temperature":0.2,"stream":false}"#,
    );
    assert!(chat.contains("200 OK"), "{chat}");
    assert!(chat.contains("\"id\":\"chatcmpl_framework\""), "{chat}");
    assert!(chat.contains("x-request-id:"), "{chat}");
    assert!(chat.contains("x-trace-id:"), "{chat}");
    assert!(!chat.contains("provider-secret"), "{chat}");
    assert!(!chat.contains("client-secret"), "{chat}");

    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(logs.contains("200 OK"), "{logs}");
    assert!(
        logs.contains("\"route\":\"openai.chat.completions\""),
        "{logs}"
    );
    assert!(logs.contains("\"logical_model\":\"agent-chat\""), "{logs}");
    assert!(logs.contains("\"provider\":\"openai\""), "{logs}");
    assert!(
        logs.contains("\"provider_model\":\"gpt-4o-mini\""),
        "{logs}"
    );
    assert!(
        logs.contains("\"organization_id\":\"org_agents\""),
        "{logs}"
    );
    assert!(
        logs.contains("\"team_id\":\"team_orchestration\""),
        "{logs}"
    );
    assert!(
        logs.contains("\"project_id\":\"project_framework_smoke\""),
        "{logs}"
    );
    assert!(logs.contains("\"user_id\":\"user_agent_runner\""), "{logs}");
    assert!(!logs.contains("client-secret"), "{logs}");

    let metrics = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(metrics.contains("200 OK"), "{metrics}");
    assert!(
        metrics.contains(
            "ferrogate_model_provider_requests_total{logical_model=\"agent-chat\",provider=\"openai\"} 1"
        ),
        "{metrics}"
    );
    assert!(
        metrics.contains(
            "ferrogate_model_provider_tokens_total{logical_model=\"agent-chat\",provider=\"openai\"} 18"
        ),
        "{metrics}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    let provider_request = &provider_requests[0];
    assert!(provider_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer provider-secret"));
    assert!(provider_request.contains(r#""model":"gpt-4o-mini""#));
    assert!(provider_request.contains(r#""temperature":0.2"#));
    assert!(provider_request.contains(r#""stream":false"#));
    assert!(!provider_request.contains("agent-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn agent_run_admin_views_support_tenant_and_request_filters() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_agent_run","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
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
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "tenant-a"
name = "Tenant A"
key = "tenant-a-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_a"
project_id = "project_a"
user_id = "user_a"

[[api_keys]]
id = "tenant-b"
name = "Tenant B"
key = "tenant-b-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_b"
project_id = "project_b"
user_id = "user_b"

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

    let agent_run_id = "run-agent-1";
    let tenant_a_chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer tenant-a-secret",
            "Content-Type: application/json",
            &format!("X-FerroGate-Agent-Run-Id: {agent_run_id}"),
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(tenant_a_chat.contains("200 OK"), "{tenant_a_chat}");
    let request_id = response_header(&tenant_a_chat, "x-request-id")
        .expect("tenant-a chat response should include x-request-id");

    let filtered_list = http_request(
        &gateway_addr,
        "GET",
        &format!(
            "/admin/v1/agent-runs?organization_id=org_a&api_key_id=tenant-a&request_id={request_id}"
        ),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(filtered_list.contains("200 OK"), "{filtered_list}");
    assert!(
        filtered_list.contains("\"object\":\"list\""),
        "{filtered_list}"
    );
    assert!(
        filtered_list.contains(&format!("\"id\":\"{agent_run_id}\"")),
        "{filtered_list}"
    );
    assert!(
        filtered_list.contains("\"tenant\":{\"organization_id\":\"org_a\""),
        "{filtered_list}"
    );
    assert!(
        !filtered_list.contains("\"organization_id\":\"org_b\""),
        "{filtered_list}"
    );

    let filtered_timeline = http_request(
        &gateway_addr,
        "GET",
        &format!(
            "/admin/v1/agent-runs/{agent_run_id}?organization_id=org_a&api_key_id=tenant-a&request_id={request_id}"
        ),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(filtered_timeline.contains("200 OK"), "{filtered_timeline}");
    assert!(
        filtered_timeline.contains("\"object\":\"agent_run_timeline\""),
        "{filtered_timeline}"
    );
    assert!(
        filtered_timeline.contains("\"request_count\":1"),
        "{filtered_timeline}"
    );

    let tenant_b_filtered_list = http_request(
        &gateway_addr,
        "GET",
        &format!(
            "/admin/v1/agent-runs?organization_id=org_b&api_key_id=tenant-b&request_id={request_id}"
        ),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        tenant_b_filtered_list.contains("200 OK"),
        "{tenant_b_filtered_list}"
    );
    assert!(
        tenant_b_filtered_list.contains("\"data\":[]"),
        "{tenant_b_filtered_list}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    assert!(provider_requests[0].contains("POST /v1/chat/completions HTTP/1.1"));
}

#[test]
fn prompt_template_admin_render_and_chat_submission_work() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_prompt_template","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"template ok"}}],"usage":{"prompt_tokens":4,"completion_tokens":6,"total_tokens":10}}"#,
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
kind = "openai-compatible"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "prompt-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[models]]
name = "other-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "prompt-client"
name = "Prompt client"
key = "client-secret"
scopes = ["chat.completions", "prompts.render", "admin.read"]
allowed_models = ["prompt-chat"]
organization_id = "org_prompt"
project_id = "project_templates"

[[api_keys]]
id = "prompt-denied"
name = "Prompt denied"
key = "denied-secret"
scopes = ["prompts.render"]
allowed_models = ["other-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let customer_value = "Ada Sensitive-Customer-8713";

    let create = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/prompt-templates",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"support-reply","name":"Support Reply","model":"prompt-chat","variables":[{"name":"customer","required":true},{"name":"tone","required":false,"default":"brief"}],"version":{"messages":[{"role":"system","content":"Reply in {{tone}} mode."},{"role":"user","content":"Hello {{customer}}"}],"temperature":0.2}}"#,
    );
    assert!(create.contains("201 Created"), "{create}");
    assert!(
        create.contains("\"object\":\"prompt_template\""),
        "{create}"
    );
    assert!(create.contains("\"active_revision\":1"), "{create}");
    assert!(!create.contains("admin-secret"), "{create}");

    let status = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(status.contains("200 OK"), "{status}");
    assert!(status.contains("\"prompt_templates\":1"), "{status}");

    let render = http_request(
        &gateway_addr,
        "POST",
        "/v1/prompts/support-reply/render",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"variables":{{"customer":"{customer_value}"}}}}"#),
    );
    assert!(render.contains("200 OK"), "{render}");
    let rendered: serde_json::Value =
        serde_json::from_str(render.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(rendered["model"], "prompt-chat");
    assert_eq!(rendered["temperature"], 0.2);
    assert_eq!(rendered["messages"][0]["content"], "Reply in brief mode.");
    assert_eq!(
        rendered["messages"][1]["content"],
        format!("Hello {customer_value}")
    );

    let denied_render = http_request(
        &gateway_addr,
        "POST",
        "/v1/prompts/support-reply/render",
        &[
            "Authorization: Bearer denied-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"variables":{{"customer":"{customer_value}"}}}}"#),
    );
    assert!(denied_render.contains("403 Forbidden"), "{denied_render}");
    assert!(
        denied_render.contains("model_not_allowed"),
        "{denied_render}"
    );
    assert!(
        !denied_render.contains(&format!("Hello {customer_value}")),
        "{denied_render}"
    );
    assert!(!denied_render.contains(customer_value), "{denied_render}");
    assert!(!denied_render.contains("denied-secret"), "{denied_render}");

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        &rendered.to_string(),
    );
    assert!(chat.contains("200 OK"), "{chat}");
    assert!(
        chat.contains("\"id\":\"chatcmpl_prompt_template\""),
        "{chat}"
    );
    assert!(!chat.contains("client-secret"), "{chat}");
    assert!(!chat.contains("provider-secret"), "{chat}");

    let update = http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/prompt-templates/support-reply",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"version":{"messages":[{"role":"user","content":"V2 hello {{customer}}"}],"temperature":0.1}}"#,
    );
    assert!(update.contains("200 OK"), "{update}");
    assert!(update.contains("\"active_revision\":2"), "{update}");
    assert!(update.contains("\"revision\":1"), "{update}");
    assert!(update.contains("\"revision\":2"), "{update}");

    let missing_variable = http_request(
        &gateway_addr,
        "POST",
        "/v1/prompts/support-reply/render",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"variables":{}}"#,
    );
    assert!(
        missing_variable.contains("400 Bad Request"),
        "{missing_variable}"
    );
    assert!(
        missing_variable.contains("prompt_template_render_failed"),
        "{missing_variable}"
    );
    assert!(missing_variable.contains("required prompt variable customer is missing"));

    let archive = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/prompt-templates/support-reply",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(archive.contains("200 OK"), "{archive}");
    assert!(
        archive.contains("\"object\":\"prompt_template\""),
        "{archive}"
    );
    assert!(archive.contains("\"deleted\":false"), "{archive}");

    let inactive_render = http_request(
        &gateway_addr,
        "POST",
        "/v1/prompts/support-reply/render",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"variables":{{"customer":"{customer_value}"}}}}"#),
    );
    assert!(
        inactive_render.contains("409 Conflict"),
        "{inactive_render}"
    );
    assert!(inactive_render.contains("prompt_template_inactive"));

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"), "{audit_events}");
    assert!(audit_events.contains("\"action\":\"prompt_template.upsert\""));
    assert!(audit_events.contains("\"action\":\"prompt_template.render\""));
    assert!(audit_events.contains("\"action\":\"prompt_template.archive\""));
    assert!(audit_events.contains("\"actor_api_key_id\":\"prompt-client\""));
    let audit_body = audit_events.split("\r\n\r\n").nth(1).unwrap();
    let audit_json: serde_json::Value = serde_json::from_str(audit_body).unwrap();
    let render_audit = audit_json["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["action"] == "prompt_template.render" && event["outcome"] == "success")
        .unwrap();
    assert_eq!(render_audit["target"], "support-reply");
    assert_eq!(render_audit["actor_api_key_id"], "prompt-client");
    assert_eq!(render_audit["tenant"]["organization_id"], "org_prompt");
    assert_eq!(render_audit["tenant"]["project_id"], "project_templates");
    let render_message = render_audit["message"].as_str().unwrap();
    assert!(render_message.contains("revision=1"), "{render_message}");
    assert!(
        render_message.contains("target=chat_completions"),
        "{render_message}"
    );
    assert!(
        render_message.contains("model=prompt-chat"),
        "{render_message}"
    );
    assert!(
        render_message.contains("variable_count=1"),
        "{render_message}"
    );
    assert!(
        render_message.contains("variable_schema_hash=fnv1a64:"),
        "{render_message}"
    );
    assert!(!audit_events.contains("client-secret"), "{audit_events}");
    assert!(!audit_events.contains("admin-secret"), "{audit_events}");
    assert!(!audit_events.contains(customer_value), "{audit_events}");
    assert!(
        !audit_events.contains(&format!("Hello {customer_value}")),
        "{audit_events}"
    );
    assert!(
        !audit_events.contains("Reply in brief mode."),
        "{audit_events}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    assert!(provider_requests[0].contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_requests[0].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[0].contains(r#""model":"gpt-4o-mini""#));
    assert!(provider_requests[0].contains("Reply in brief mode."));
    assert!(provider_requests[0].contains(&format!("Hello {customer_value}")));
    assert!(!provider_requests[0].contains("prompt-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
}

#[test]
fn retired_turso_libsql_storage_config_fails_with_migration_message() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let db_path = dir.path().join("control-plane.db");
    let db_url = format!("file://{}", db_path.display());
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

storage = {{ provider = "turso_libsql", libsql_url = "{db_url}" }}

[[providers]]
name = "openai"
kind = "openai-compatible"
base_url = "http://127.0.0.1:1/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
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

    let output = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args(["check", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("turso_libsql has been removed"), "{stderr}");
    assert!(stderr.contains("storage.provider: supabase"), "{stderr}");
}

#[test]
fn exact_match_cache_serves_repeated_non_streaming_chat_without_provider_call() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_cached","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"cached ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 60
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
cache_enabled = true
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello cache"}],"temperature":0}"#;
    let first = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        body,
    );
    assert!(first.contains("200 OK"), "{first}");
    assert!(first.contains("cached ok"));

    let second_body = r#"{"temperature":0,"messages":[{"content":"hello cache","role":"user"}],"model":"fast-chat"}"#;
    let second = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        second_body,
    );
    assert!(second.contains("200 OK"), "{second}");
    assert!(second.contains("cached ok"));
    assert!(!second.contains("provider-secret"));
    assert!(!second.contains("client-secret"));

    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(logs.contains("200 OK"), "{logs}");
    assert!(logs.contains("\"cache_status\":\"miss\""), "{logs}");
    assert!(logs.contains("\"cache_status\":\"hit\""), "{logs}");
    assert!(!logs.contains("provider-secret"));
    assert!(!logs.contains("client-secret"));

    let metrics = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(metrics.contains("200 OK"), "{metrics}");
    assert!(
        metrics.contains("ferrogate_ai_cache_requests_total{status=\"miss\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("ferrogate_ai_cache_requests_total{status=\"hit\"} 1"),
        "{metrics}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
    assert!(provider_requests[0].contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_requests[0].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[0].contains(r#""model":"gpt-4o-mini""#));
    assert!(!provider_requests[0].contains("fast-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
}

/// #233: a response cached BEFORE a Response-stage guardrail redaction rule is
/// added must not keep serving the pre-redaction body on cache hits after the
/// policy is tightened. The guardrail-policy fingerprint is part of the cache
/// key, so the tightened policy misses the stale entry, re-fetches from the
/// provider, and serves the redacted body.
#[test]
fn tightened_response_guardrail_policy_invalidates_cached_pre_redaction_body() {
    let gateway_addr = free_addr();
    // Two provider calls expected: the initial miss, and the post-tighten miss
    // (the stale pre-redaction cache entry must NOT satisfy the second call).
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_leak","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"the access code is ferro-secret-9922"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let base_config = format!(
        r#"
listen = "{gateway_addr}"

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 300
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
cache_enabled = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    );
    std::fs::write(&config, &base_config).unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = r#"{"model":"fast-chat","messages":[{"role":"user","content":"what is the access code"}],"temperature":0}"#;
    let request = |addr: &str| {
        http_request(
            addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer client-secret",
                "Content-Type: application/json",
            ],
            body,
        )
    };

    // Cache the response under the loose policy (no guardrails): the secret is
    // served raw and stored raw.
    let first = request(&gateway_addr);
    assert!(first.contains("200 OK"), "{first}");
    assert!(first.contains("ferro-secret-9922"), "{first}");

    // Prove the entry is actually served from cache pre-tightening.
    let cached_hit = request(&gateway_addr);
    assert!(cached_hit.contains("200 OK"), "{cached_hit}");
    assert!(cached_hit.contains("ferro-secret-9922"), "{cached_hit}");

    // Tighten the policy: add a Response-stage redaction rule that matches the
    // already-cached content, and reload.
    let tightened_config = format!(
        r#"{base_config}
[[guardrails]]
id = "redact-access-code"
name = "Redact leaked access code"
stage = "response"
keywords = ["ferro-secret-9922"]
effect = "redact"
code = "guardrail_redacted"
message = "response redacted by guardrail"
enabled = true
"#
    );
    std::fs::write(&config, &tightened_config).unwrap();
    let reload = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "config_toml": tightened_config,
            "filename": "ferrogate.toml"
        })
        .to_string(),
    );
    assert!(reload.contains("200 OK"), "{reload}");
    assert!(reload.contains("\"committed\":true"), "{reload}");

    // The identical request must NOT serve the stale pre-redaction cache entry:
    // the rotated guardrail-policy fingerprint misses it, the provider is hit
    // again, and the tightened Response-stage rule redacts the new body.
    let after_tighten = request(&gateway_addr);
    assert!(after_tighten.contains("200 OK"), "{after_tighten}");
    assert!(
        !after_tighten.contains("ferro-secret-9922"),
        "pre-redaction body leaked from the response cache after the guardrail \
         policy was tightened: {after_tighten}"
    );

    // And the redacted body is what got re-cached: a further hit stays redacted.
    let redacted_hit = request(&gateway_addr);
    assert!(redacted_hit.contains("200 OK"), "{redacted_hit}");
    assert!(
        !redacted_hit.contains("ferro-secret-9922"),
        "{redacted_hit}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    // Exactly two provider round-trips: pre-tighten miss + post-tighten miss.
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
}

#[test]
fn gateway_config_profile_header_controls_cache_and_records_evidence() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_profile","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"profile ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 60
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
cache_enabled = true

[[api_keys]]
id = "other"
name = "Other key"
key = "other-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read"]

[[gateway_configs]]
id = "no-cache-agent"
name = "No-cache agent workflow"
revision = 7
cache_enabled = false
api_key_ids = ["key_dev"]

[[gateway_configs]]
id = "disabled-agent"
name = "Disabled agent workflow"
revision = 2
enabled = false
cache_enabled = false
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello profile"}]}"#;
    for _ in 0..2 {
        let response = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer client-secret",
                "Content-Type: application/json",
                "x-ferrogate-config: no-cache-agent",
            ],
            body,
        );
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("profile ok"), "{response}");
    }

    let missing = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
            "x-ferrogate-config: missing-agent",
        ],
        body,
    );
    assert!(missing.contains("400 Bad Request"), "{missing}");
    assert!(missing.contains("gateway_config_not_found"), "{missing}");

    let disabled = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
            "x-ferrogate-config: disabled-agent",
        ],
        body,
    );
    assert!(disabled.contains("403 Forbidden"), "{disabled}");
    assert!(disabled.contains("gateway_config_disabled"), "{disabled}");

    let forbidden = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer other-secret",
            "Content-Type: application/json",
            "x-ferrogate-config: no-cache-agent",
        ],
        body,
    );
    assert!(forbidden.contains("403 Forbidden"), "{forbidden}");
    assert!(
        forbidden.contains("gateway_config_not_allowed"),
        "{forbidden}"
    );

    let profiles = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/gateway-configs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(profiles.contains("200 OK"), "{profiles}");
    assert!(profiles.contains("\"id\":\"no-cache-agent\""), "{profiles}");
    assert!(profiles.contains("\"revision\":7"), "{profiles}");
    assert!(profiles.contains("\"cache_enabled\":false"), "{profiles}");
    assert!(!profiles.contains("client-secret"), "{profiles}");

    // A platform-operator key (issue #185: a tenant-scoped key like
    // client-secret now only sees its own tenant's logs) is used here
    // since this assertion spans logs from both client-secret and the
    // unscoped other-secret key.
    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(logs.contains("200 OK"), "{logs}");
    assert!(
        logs.contains("\"gateway_config_id\":\"no-cache-agent\""),
        "{logs}"
    );
    assert!(logs.contains("\"gateway_config_revision\":7"), "{logs}");
    assert!(!logs.contains("\"cache_status\":\"hit\""), "{logs}");
    assert!(!logs.contains("\"cache_status\":\"miss\""), "{logs}");
    assert!(logs.contains("gateway_config_not_found"), "{logs}");
    assert!(logs.contains("gateway_config_disabled"), "{logs}");
    assert!(logs.contains("gateway_config_not_allowed"), "{logs}");
    assert!(!logs.contains("client-secret"), "{logs}");
    assert!(!logs.contains("provider-secret"), "{logs}");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
    assert!(provider_requests
        .iter()
        .all(|request| request.contains(r#""model":"gpt-4o-mini""#)));
    assert!(provider_requests
        .iter()
        .all(|request| !request.contains("client-secret")));
}

#[test]
fn exact_match_cache_hit_does_not_require_token_budget_headroom() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_cached_budget","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"cached budget ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cache]
enabled = true
ttl_secs = 60
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "key_budget"
name = "Budget key"
key = "budget-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
monthly_token_budget = 8
cache_enabled = true
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = r#"{"model":"fast-chat","messages":[],"max_tokens":8}"#;
    let first = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer budget-secret",
            "Content-Type: application/json",
        ],
        body,
    );
    assert!(first.contains("200 OK"), "{first}");
    assert!(first.contains("cached budget ok"), "{first}");

    let second = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer budget-secret",
            "Content-Type: application/json",
        ],
        body,
    );
    assert!(second.contains("200 OK"), "{second}");
    assert!(second.contains("cached budget ok"), "{second}");
    assert!(!second.contains("token_budget_exceeded"), "{second}");

    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer budget-secret"],
        "",
    );
    assert!(logs.contains("200 OK"), "{logs}");
    assert!(logs.contains("\"cache_status\":\"miss\""), "{logs}");
    assert!(logs.contains("\"cache_status\":\"hit\""), "{logs}");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 1);
}

#[test]
fn api_key_cache_disable_keeps_repeated_requests_on_provider_path() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_uncached","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"uncached ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cache]
enabled = true
ttl_secs = 60
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
cache_enabled = false
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let body = r#"{"model":"fast-chat","messages":[{"role":"user","content":"tenant no cache"}]}"#;
    for _ in 0..2 {
        let response = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer client-secret",
                "Content-Type: application/json",
            ],
            body,
        );
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("uncached ok"), "{response}");
    }

    let logs = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(logs.contains("200 OK"), "{logs}");
    assert!(!logs.contains("\"cache_status\":\"hit\""), "{logs}");
    assert!(!logs.contains("\"cache_status\":\"miss\""), "{logs}");

    let metrics = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(metrics.contains("200 OK"), "{metrics}");
    assert!(
        metrics.contains("ferrogate_ai_cache_requests_total{status=\"miss\"} 0"),
        "{metrics}"
    );
    assert!(
        metrics.contains("ferrogate_ai_cache_requests_total{status=\"hit\"} 0"),
        "{metrics}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
}

#[test]
fn token_metering_export_posts_normalized_usage_without_gateway_cost() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_metering","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let (metering_addr, metering_handle) = spawn_metering_service();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[metering]
export_enabled = true
export_endpoint = "http://{metering_addr}/v1/metering/events"
export_token = "metering-token"
export_timeout_secs = 2

[[providers]]
name = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
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
    assert!(chat.contains("200 OK"), "{chat}");

    let metering_request = metering_handle.join().unwrap();
    assert!(metering_request.contains("POST /v1/metering/events HTTP/1.1"));
    assert!(metering_request.contains("Authorization: Bearer metering-token"));
    assert!(metering_request.contains(r#""object":"token_metering_event""#));
    assert!(metering_request.contains(r#""idempotency_key":"ferrogate:"#));
    assert!(metering_request.contains(r#""organization_id":"org_demo""#));
    assert!(metering_request.contains(r#""project_id":"project_gateway""#));
    assert!(metering_request.contains(r#""api_key_id":"key_dev""#));
    assert!(metering_request.contains(r#""logical_model":"fast-chat""#));
    assert!(metering_request.contains(r#""provider":"openai""#));
    assert!(metering_request.contains(r#""total_tokens":8"#));
    assert!(!metering_request.contains(r#""cost""#));
    assert!(!metering_request.contains(r#""currency""#));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    provider_handle.join().unwrap();
}

fn spawn_metering_service() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n")
                && String::from_utf8_lossy(&request).contains("\"token_metering_event\"")
            {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });
    (addr, handle)
}

fn cluster_status_config(addr: &str, node_id: &str, admin_secret: &str) -> String {
    let node_zone = if node_id.ends_with("-a") {
        "local-a"
    } else {
        "local-b"
    };
    format!(
        r#"
listen = "{addr}"

[cluster]
enabled = true
cluster_id = "test-cluster"
node_id = "{node_id}"
node_region = "local"
node_zone = "{node_zone}"
state_backend = "local"
counter_backend = "local"
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[api_keys]]
id = "admin"
name = "Admin"
key = "{admin_secret}"
scopes = ["admin.read"]
"#
    )
}

fn admin_status_json(addr: &str, admin_secret: &str) -> serde_json::Value {
    let auth = format!("Authorization: Bearer {admin_secret}");
    let response = http_request(addr, "GET", "/admin/v1/status", &[auth.as_str()], "");
    assert!(response.contains("200 OK"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_else(|| panic!("admin status response missing body: {response}"));
    serde_json::from_str(body).unwrap()
}

fn readiness_json(addr: &str) -> serde_json::Value {
    let response = http_request(addr, "GET", "/readyz", &[], "");
    assert!(response.contains("200 OK"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_else(|| panic!("readiness response missing body: {response}"));
    serde_json::from_str(body).unwrap()
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
fn shared_openai_compatible_provider_dispatch_uses_openai_compatible_path() {
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
name = "deepseek"
kind = "deepseek"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_DEEPSEEK_SECRET"

[[models]]
name = "deepseek-chat"
provider = "deepseek"
provider_model = "deepseek-chat"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["deepseek-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_DEEPSEEK_SECRET", "deepseek-secret");

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
        r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"object\":\"chat.completion\""));
    assert!(!chat.contains("deepseek-secret"));
    assert!(!chat.contains("client-secret"));
    assert!(!chat.contains("Bearer"));

    let providers = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/providers",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(providers.contains("200 OK"), "{providers}");
    assert!(providers.contains("\"name\":\"deepseek\""));
    assert!(providers.contains("\"compatibility\":\"openai-compatible\""));

    gateway.kill().ok();
    gateway.wait().ok();
    let requests = provider_handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    let provider_request = &requests[0];
    assert!(provider_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer deepseek-secret"));
    assert!(provider_request.contains(r#""model":"deepseek-chat""#));
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
fn openai_responses_streaming_events_are_normalized() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream_with_body(
        r#"data: {"choices":[{"delta":{"content":"hello"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}

data: [DONE]

"#,
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
provider_model = "gpt-4.1-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

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
        r#"{"model":"fast-chat","stream":true,"input":"hello"}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(response.contains("event: response.output_text.delta"));
    assert!(response.contains("event: response.completed"));
    assert!(response.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("POST /v1/responses HTTP/1.1"));
    assert!(provider_request.contains(r#""stream":true"#));
}

#[test]
fn openai_responses_streaming_forwards_first_chunk_before_provider_finishes() {
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
provider_model = "gpt-4.1-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create"]
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
    let body = r#"{"model":"fast-chat","stream":true,"input":"hello"}"#;
    write!(
        stream,
        "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer client-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();

    let mut response = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "gateway closed before first normalized SSE chunk");
        response.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&response);
        if text.contains("event: response.output_text.delta") {
            assert!(
                started.elapsed() < Duration::from_millis(900),
                "first normalized SSE chunk was buffered until provider completion"
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
fn openai_responses_streaming_tool_call_events_are_normalized() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream_with_body(
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"lookup","arguments":"{\"query\":\""}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ferrogate\"}"}}]}}]}

data: [DONE]

"#,
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
provider_model = "gpt-4.1-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

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
        r#"{"model":"fast-chat","stream":true,"input":"hello"}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response.contains("event: response.function_call_arguments.delta"));
    assert!(response.contains("event: response.function_call_arguments.done"));
    assert!(response.contains(r#""name":"lookup""#));
    assert!(response.contains(r#""arguments":"{\"query\":\"ferrogate\"}"#));
    assert!(response.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("POST /v1/responses HTTP/1.1"));
    assert!(provider_request.contains(r#""stream":true"#));
}

#[test]
fn anthropic_responses_streaming_events_are_normalized() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream_with_body(
        r#"event: content_block_delta
data: {"delta":{"text":"hello"}}

event: message_stop
data: {}

"#,
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
        r#"{"model":"claude-chat","stream":true,"input":"hello"}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response.contains("event: response.output_text.delta"));
    assert!(response.contains("event: response.completed"));
    assert!(response.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("POST /v1/messages HTTP/1.1"));
}

#[test]
fn gemini_responses_streaming_events_are_normalized() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream_with_body(
        r#"data: {"candidates":[{"content":{"parts":[{"text":"hello"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8}}

data: [DONE]

"#,
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

[[models]]
name = "flash-chat"
provider = "gemini"
provider_model = "gemini-2.5-flash"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["responses.create"]
allowed_models = ["flash-chat"]
"#
        ),
    )
    .unwrap();

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
        r#"{"model":"flash-chat","stream":true,"input":"hello"}"#,
    );
    assert!(response.contains("200 OK"));
    assert!(response.contains("event: response.output_text.delta"));
    assert!(response.contains("event: response.completed"));
    assert!(response.contains(r#""prompt_tokens":3"#));
    assert!(response.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request
        .contains("POST /v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse HTTP/1.1"));
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
fn admin_plugin_crud_updates_runtime_plugin_registry() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

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

    let denied_secret_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "enabled": true,
            "source": "builtin",
            "order": 10,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false,
                "secrets": false,
                "admin_mutation": false
            },
            "config": {
                "api_token": "plugin-secret-token"
            }
        })
        .to_string(),
    );
    assert!(
        denied_secret_plugin.contains("400 Bad Request"),
        "{denied_secret_plugin}"
    );
    assert!(
        denied_secret_plugin.contains("invalid_plugin"),
        "{denied_secret_plugin}"
    );
    assert!(
        denied_secret_plugin.contains("config.api_token"),
        "{denied_secret_plugin}"
    );
    assert!(
        denied_secret_plugin.contains("permissions.secrets = true"),
        "{denied_secret_plugin}"
    );

    let plugins_after_denied_secret = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        !plugins_after_denied_secret.contains("\"id\":\"tool.echo\""),
        "{plugins_after_denied_secret}"
    );

    let denied_tenant_scope_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "enabled": true,
            "source": "builtin",
            "order": 10,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false,
                "tenant_scope": false,
                "secrets": false,
                "admin_mutation": false
            },
            "config": {
                "tenant_allowlist": ["org-demo"]
            }
        })
        .to_string(),
    );
    assert!(
        denied_tenant_scope_plugin.contains("400 Bad Request"),
        "{denied_tenant_scope_plugin}"
    );
    assert!(
        denied_tenant_scope_plugin.contains("invalid_plugin"),
        "{denied_tenant_scope_plugin}"
    );
    assert!(
        denied_tenant_scope_plugin.contains("permissions.tenant_scope = true"),
        "{denied_tenant_scope_plugin}"
    );

    let plugins_after_denied_tenant_scope = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        !plugins_after_denied_tenant_scope.contains("\"id\":\"tool.echo\""),
        "{plugins_after_denied_tenant_scope}"
    );

    let denied_required_permission_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "version": "1.0.0",
            "manifest": {
                "name": "Echo tools",
                "required_permissions": {
                    "tools": ["tool.echo"],
                    "secrets": true
                }
            },
            "enabled": true,
            "source": "builtin",
            "order": 10,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false,
                "tenant_scope": false,
                "secrets": false,
                "admin_mutation": false
            }
        })
        .to_string(),
    );
    assert!(
        denied_required_permission_plugin.contains("400 Bad Request"),
        "{denied_required_permission_plugin}"
    );
    assert!(
        denied_required_permission_plugin.contains("invalid_plugin"),
        "{denied_required_permission_plugin}"
    );
    assert!(
        denied_required_permission_plugin.contains("manifest.required_permissions.secrets"),
        "{denied_required_permission_plugin}"
    );

    let create_body = serde_json::json!({
        "id": "tool.echo",
        "kind": "tool_provider",
        "version": "1.2.3",
        "manifest": {
            "name": "Echo tools",
            "description": "Safe echo fixture",
            "capabilities": ["tool_provider", "safe:echo"],
            "required_permissions": {
                "tools": ["tool.echo"],
                "tenant_scope": true,
                "secrets": true
            },
            "hooks": ["tool.execute"],
            "config_schema": {
                "type": "object"
            }
        },
        "compatibility": {
            "min_gateway_version": "0.1.0",
            "max_gateway_version": "9999.0.0"
        },
        "enabled": true,
        "source": "builtin",
        "order": 10,
        "permissions": {
            "tools": ["tool.echo"],
            "network": [],
            "filesystem": false,
            "shell": false,
            "tenant_scope": true,
            "secrets": true,
            "admin_mutation": false
        },
        "config": {
            "timeout_ms": 30000,
            "api_token": "plugin-secret-token",
            "tenant_allowlist": ["*"],
            "headers": {
                "authorization": "Bearer plugin-secret-token"
            }
        }
    })
    .to_string();
    let created = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &create_body,
    );
    assert!(created.contains("201 Created"), "{created}");
    assert!(created.contains("\"object\":\"plugin\""), "{created}");
    assert!(created.contains("\"id\":\"tool.echo\""), "{created}");
    assert!(created.contains("\"kind\":\"tool_provider\""), "{created}");
    assert!(created.contains("\"version\":\"1.2.3\""), "{created}");
    assert!(created.contains("\"name\":\"Echo tools\""), "{created}");
    assert!(created.contains("\"safe:echo\""), "{created}");
    assert!(created.contains("\"required_permissions\""), "{created}");
    assert!(created.contains("\"tenant_scope\":true"), "{created}");
    assert!(
        created.contains("\"min_gateway_version\":\"0.1.0\""),
        "{created}"
    );
    assert!(created.contains("\"enabled\":true"), "{created}");
    assert!(created.contains("\"active\":true"), "{created}");
    assert!(created.contains("\"lifecycle\":\"enabled\""), "{created}");
    assert!(created.contains("\"health\":\"ok\""), "{created}");
    assert!(created.contains("\"tools\":[\"tool.echo\"]"), "{created}");
    assert!(created.contains("\"tenant_scope\":true"), "{created}");
    assert!(
        created.contains("\"tenant_allowlist\":[\"*\"]"),
        "{created}"
    );
    assert!(created.contains("\"secrets\":true"), "{created}");
    assert!(created.contains("\"admin_mutation\":false"), "{created}");
    assert!(created.contains("\"timeout_ms\":30000"), "{created}");
    assert!(
        created.contains("\"api_token\":\"[redacted]\""),
        "{created}"
    );
    assert!(
        created.contains("\"authorization\":\"[redacted]\""),
        "{created}"
    );
    assert!(!created.contains("plugin-secret-token"), "{created}");
    assert!(!created.contains("admin-secret"), "{created}");

    let listed = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(listed.contains("200 OK"), "{listed}");
    assert!(listed.contains("\"id\":\"tool.echo\""), "{listed}");
    assert!(listed.contains("\"active\":true"), "{listed}");

    let fetched = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins/tool.echo",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(fetched.contains("200 OK"), "{fetched}");
    assert!(fetched.contains("\"id\":\"tool.echo\""), "{fetched}");
    assert!(fetched.contains("\"kind\":\"tool_provider\""), "{fetched}");
    assert!(fetched.contains("\"version\":\"1.2.3\""), "{fetched}");
    assert!(fetched.contains("\"name\":\"Echo tools\""), "{fetched}");
    assert!(fetched.contains("\"active\":true"), "{fetched}");
    assert!(fetched.contains("\"health\":\"ok\""), "{fetched}");

    let tools = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins/tool.echo/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(tools.contains("200 OK"), "{tools}");
    assert!(tools.contains("\"name\":\"tool.echo\""), "{tools}");

    let denied_network_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "mcp.http",
            "kind": "tool_provider",
            "enabled": true,
            "source": "builtin",
            "order": 20,
            "permissions": {
                "tools": ["search"],
                "network": [],
                "filesystem": false,
                "shell": false
            },
            "config": {
                "endpoint": "http://127.0.0.1:1/mcp",
                "timeout_ms": 100
            }
        })
        .to_string(),
    );
    assert!(
        denied_network_plugin.contains("400 Bad Request"),
        "{denied_network_plugin}"
    );
    assert!(
        denied_network_plugin.contains("invalid_plugin"),
        "{denied_network_plugin}"
    );
    assert!(
        denied_network_plugin.contains("permissions.network"),
        "{denied_network_plugin}"
    );
    assert!(
        denied_network_plugin.contains("must allow MCP host 127.0.0.1"),
        "{denied_network_plugin}"
    );

    let plugins_after_denied_network = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        !plugins_after_denied_network.contains("\"id\":\"mcp.http\""),
        "{plugins_after_denied_network}"
    );

    let failed_mcp_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "mcp.http",
            "kind": "tool_provider",
            "enabled": true,
            "source": "builtin",
            "order": 20,
            "permissions": {
                "tools": ["search"],
                "network": ["127.0.0.1"],
                "filesystem": false,
                "shell": false
            },
            "config": {
                "endpoint": "http://127.0.0.1:1/mcp",
                "timeout_ms": 100
            }
        })
        .to_string(),
    );
    assert!(
        failed_mcp_plugin.contains("201 Created"),
        "{failed_mcp_plugin}"
    );
    assert!(
        failed_mcp_plugin.contains("\"id\":\"mcp.http\""),
        "{failed_mcp_plugin}"
    );
    assert!(
        failed_mcp_plugin.contains("\"active\":false"),
        "{failed_mcp_plugin}"
    );
    assert!(
        failed_mcp_plugin.contains("\"health\":\"failed\""),
        "{failed_mcp_plugin}"
    );
    assert!(
        failed_mcp_plugin.contains("\"lifecycle\":\"failed\""),
        "{failed_mcp_plugin}"
    );
    assert!(
        failed_mcp_plugin.contains("failed to list MCP tools for mcp.http"),
        "{failed_mcp_plugin}"
    );

    let failed_mcp_tools = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins/mcp.http/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(failed_mcp_tools.contains("200 OK"), "{failed_mcp_tools}");
    assert!(
        !failed_mcp_tools.contains("\"name\":\"search\""),
        "{failed_mcp_tools}"
    );

    let invalid_manifest_plugin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.health_check",
            "kind": "tool_provider",
            "version": "1.0.0",
            "manifest": {
                "name": "Health check",
                "capabilities": ["bad capability"]
            },
            "enabled": true,
            "source": "builtin",
            "order": 30,
            "permissions": {
                "tools": ["tool.health_check"],
                "network": [],
                "filesystem": false,
                "shell": false
            }
        })
        .to_string(),
    );
    assert!(
        invalid_manifest_plugin.contains("400 Bad Request"),
        "{invalid_manifest_plugin}"
    );
    assert!(
        invalid_manifest_plugin.contains("invalid_plugin"),
        "{invalid_manifest_plugin}"
    );
    assert!(
        invalid_manifest_plugin.contains("manifest.capabilities"),
        "{invalid_manifest_plugin}"
    );
    assert!(
        invalid_manifest_plugin.contains("must contain only letters"),
        "{invalid_manifest_plugin}"
    );

    let plugins_after_invalid_manifest = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        !plugins_after_invalid_manifest.contains("\"id\":\"tool.health_check\""),
        "{plugins_after_invalid_manifest}"
    );

    let duplicate_update = http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/plugins/tool.echo",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "enabled": true,
            "source": "builtin",
            "order": 10,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false,
                "tenant_scope": true,
                "secrets": true,
                "admin_mutation": false
            },
            "config": {
                "timeout_ms": 15000,
                "mode": "updated",
                "tenant_allowlist": ["*"],
                "client_secret": "updated-plugin-secret"
            }
        })
        .to_string(),
    );
    assert!(duplicate_update.contains("200 OK"), "{duplicate_update}");
    assert!(
        duplicate_update.contains("\"mode\":\"updated\""),
        "{duplicate_update}"
    );
    assert!(
        duplicate_update.contains("\"client_secret\":\"[redacted]\""),
        "{duplicate_update}"
    );
    assert!(
        !duplicate_update.contains("updated-plugin-secret"),
        "{duplicate_update}"
    );

    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/plugins/tool.echo",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(delete.contains("200 OK"), "{delete}");
    assert!(delete.contains("\"deleted\":true"), "{delete}");

    let incompatible = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/plugins",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::json!({
            "id": "tool.health_check",
            "kind": "tool_provider",
            "version": "1.0.0",
            "manifest": {
                "name": "Health check",
                "capabilities": ["tool_provider"]
            },
            "compatibility": {
                "min_gateway_version": "9999.0.0"
            },
            "enabled": true,
            "source": "builtin",
            "order": 30,
            "permissions": {
                "tools": ["tool.health_check"],
                "network": [],
                "filesystem": false,
                "shell": false
            }
        })
        .to_string(),
    );
    assert!(incompatible.contains("201 Created"), "{incompatible}");
    assert!(
        incompatible.contains("\"health\":\"version_incompatible\""),
        "{incompatible}"
    );
    assert!(
        incompatible.contains("\"lifecycle\":\"version_incompatible\""),
        "{incompatible}"
    );
    assert!(incompatible.contains("\"active\":false"), "{incompatible}");
    assert!(
        incompatible.contains("requires gateway version &gt;= 9999.0.0")
            || incompatible.contains("requires gateway version >= 9999.0.0"),
        "{incompatible}"
    );

    let missing = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/plugins/tool.echo",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(missing.contains("404 Not Found"), "{missing}");
    assert!(missing.contains("plugin_not_found"), "{missing}");

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"));
    assert!(audit_events.contains("\"action\":\"plugin.upsert\""));
    assert!(audit_events.contains("\"action\":\"plugin.delete\""));
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
fn admin_gateway_config_crud_updates_runtime_profile_selection() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_gateway_config_crud","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"profile crud ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 60
max_records = 16

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
cache_enabled = true

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
cache_enabled = true

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
        "id": "no-cache-agent",
        "name": "No-cache agent",
        "revision": 3,
        "api_key_ids": ["client"],
        "cache_enabled": false
    })
    .to_string();
    let created = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/gateway-configs",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &create_body,
    );
    assert!(created.contains("201 Created"), "{created}");
    assert!(
        created.contains("\"object\":\"gateway_config\""),
        "{created}"
    );
    assert!(created.contains("\"id\":\"no-cache-agent\""), "{created}");
    assert!(created.contains("\"revision\":3"), "{created}");
    assert!(created.contains("\"cache_enabled\":false"), "{created}");
    assert!(!created.contains("client-secret"), "{created}");
    assert!(!created.contains("admin-secret"), "{created}");

    let unknown_field = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/gateway-configs",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"bad","name":"Bad","revision":1,"cache_enabled":false,"routing_strategy":"latency"}"#,
    );
    assert!(unknown_field.contains("400 Bad Request"), "{unknown_field}");
    assert!(
        unknown_field.contains("invalid_request_body"),
        "{unknown_field}"
    );

    let bad_api_key = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/gateway-configs",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"bad-api-key","name":"Bad API key","revision":1,"cache_enabled":false,"api_key_ids":["missing"]}"#,
    );
    assert!(bad_api_key.contains("400 Bad Request"), "{bad_api_key}");
    assert!(
        bad_api_key.contains("invalid_gateway_config"),
        "{bad_api_key}"
    );
    assert!(
        bad_api_key.contains("unknown api key missing"),
        "{bad_api_key}"
    );

    let body =
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello profile crud"}]}"#;
    for _ in 0..2 {
        let chat = http_request(
            &gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                "Authorization: Bearer client-secret",
                "Content-Type: application/json",
                "x-ferrogate-config: no-cache-agent",
            ],
            body,
        );
        assert!(chat.contains("200 OK"), "{chat}");
        assert!(chat.contains("profile crud ok"), "{chat}");
    }

    let update_body = serde_json::json!({
        "id": "no-cache-agent",
        "name": "Disabled no-cache agent",
        "revision": 4,
        "enabled": false,
        "api_key_ids": ["client"],
        "cache_enabled": false
    })
    .to_string();
    let updated = http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/gateway-configs/no-cache-agent",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &update_body,
    );
    assert!(updated.contains("200 OK"), "{updated}");
    assert!(updated.contains("\"revision\":4"), "{updated}");
    assert!(updated.contains("\"enabled\":false"), "{updated}");

    let disabled = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
            "x-ferrogate-config: no-cache-agent",
        ],
        body,
    );
    assert!(disabled.contains("403 Forbidden"), "{disabled}");
    assert!(disabled.contains("gateway_config_disabled"), "{disabled}");

    let get_one = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/gateway-configs/no-cache-agent",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(get_one.contains("200 OK"), "{get_one}");
    assert!(
        get_one.contains("\"object\":\"gateway_config\""),
        "{get_one}"
    );
    assert!(get_one.contains("\"id\":\"no-cache-agent\""), "{get_one}");

    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/gateway-configs/no-cache-agent",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(delete.contains("200 OK"), "{delete}");
    assert!(delete.contains("\"object\":\"gateway_config\""), "{delete}");
    assert!(delete.contains("\"deleted\":true"), "{delete}");

    let missing_after_delete = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
            "x-ferrogate-config: no-cache-agent",
        ],
        body,
    );
    assert!(
        missing_after_delete.contains("400 Bad Request"),
        "{missing_after_delete}"
    );
    assert!(
        missing_after_delete.contains("gateway_config_not_found"),
        "{missing_after_delete}"
    );

    let audit_events = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(audit_events.contains("200 OK"), "{audit_events}");
    assert!(
        audit_events.contains("\"action\":\"gateway_config.upsert\""),
        "{audit_events}"
    );
    assert!(
        audit_events.contains("\"action\":\"gateway_config.delete\""),
        "{audit_events}"
    );
    assert!(!audit_events.contains("client-secret"), "{audit_events}");
    assert!(!audit_events.contains("admin-secret"), "{audit_events}");

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
    let request_id =
        response_header(&chat, "x-request-id").expect("retry response should include x-request-id");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert_eq!(provider_requests.len(), 2);
    assert!(provider_requests
        .iter()
        .all(|request| request.contains(r#""model":"gpt-4o-mini""#)));
    assert!(provider_requests[0].contains(&format!(
        "x-ferrogate-provider-attempt-id: {request_id}:provider-attempt:0"
    )));
    assert!(provider_requests[0].contains("x-ferrogate-provider-attempt-index: 0"));
    assert!(provider_requests[1].contains(&format!(
        "x-ferrogate-provider-attempt-id: {request_id}:provider-attempt:1"
    )));
    assert!(provider_requests[1].contains("x-ferrogate-provider-attempt-index: 1"));
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
    assert!(health.contains("\"local_observations\":"));
    assert!(health.contains("\"cluster_observations\":null"));
    assert!(!health.contains("FERROGATE_PROVIDER_SECRET"));
    assert!(!health.contains("provider-secret"));
    assert!(!health.contains("admin-secret"));
}

fn spawn_sse_provider_upstream() -> (String, thread::JoinHandle<String>) {
    spawn_sse_provider_upstream_with_body(
        "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n",
    )
}

fn spawn_sse_provider_upstream_with_body(
    body: &'static str,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
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

fn response_header(response: &str, header: &str) -> Option<String> {
    response.lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.trim()
                .eq_ignore_ascii_case(header)
                .then(|| value.trim().to_string())
        })
    })
}
