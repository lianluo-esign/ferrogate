// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;
use ferrogate_providers::RoutingStrategy;
use ferrogate_storage::StorageProviderKind;

#[test]
fn default_config_uses_localhost_8080() {
    let config = Config::default();
    assert_eq!(config.listen, "127.0.0.1:8080");
    assert!(config.providers.is_empty());
    assert!(config.models.is_empty());
    assert!(config.api_keys.is_empty());
    assert!(!config.auth_service.enabled);
    assert_eq!(config.auth_service.endpoint, "http://127.0.0.1:8090");
    assert_eq!(config.auth_service.timeout_millis, 500);
    assert_eq!(config.auth_service.max_retries, 0);
    assert_eq!(config.auth_service.retry_backoff_millis, 50);
    assert!(config.upstreams.is_empty());
    assert!(config.routes.is_empty());
    assert!(!config.agent_runtime.enabled);
    assert_eq!(
        config.agent_runtime.provider,
        AgentRuntimeProvider::ManagedWorker
    );
    assert_eq!(config.agent_runtime.max_turns, 4);
    assert_eq!(config.agent_runtime.timeout_millis, 30_000);
    // #542: the omitted `[auth]` section lands on "authentication required".
    // Before #542 there was no section and the answer was inferred from the
    // three assertions above it -- empty api_keys and a disabled auth service
    // meant no request had to present anything, and every one of them was
    // admitted as an unrestricted platform operator.
    assert!(!config.auth.disabled);
    assert!(config.auth_required());
}

/// #542: the open posture is a named field, spelled the way the startup error
/// tells an operator to spell it. Rename or re-type the field and this stops
/// compiling; drop the `#[serde(default)]` on `Config::auth` and every config
/// file without an `[auth]` section stops loading.
#[test]
fn auth_section_is_the_named_switch_for_the_open_posture() {
    let config = Config::from_toml_str("[auth]\ndisabled = true\n")
        .expect("[auth] disabled = true is a valid config on its own");

    assert!(config.auth.disabled);
    assert!(!config.auth_required());

    let default_posture =
        Config::from_toml_str("[auth]\n").expect("an empty [auth] section is valid");
    assert!(default_posture.auth_required());

    // The section is closed: a typo is refused rather than silently ignored,
    // which for this field would mean "I thought I disabled auth" or, worse,
    // "I thought I enabled it".
    let typo = Config::from_toml_str("[auth]\ndisable = true\n");
    assert!(typo.is_err(), "an unknown [auth] field must be rejected");
}

/// #542: what counts as a credential source, asked once so the gateway's
/// startup gate and the Control Plane API service's cannot disagree.
#[test]
fn credential_sources_are_static_keys_external_auth_or_a_durable_backend() {
    assert!(!Config::default().has_credential_source());

    let with_static_key = Config::from_toml_str(
        "[[api_keys]]\nid = \"k1\"\nname = \"k1\"\nkey = \"secret\"\nplatform_operator = true\n",
    )
    .unwrap();
    assert!(with_static_key.has_credential_source());

    let mut with_auth_service = Config::default();
    with_auth_service.auth_service.enabled = true;
    assert!(with_auth_service.has_credential_source());

    let mut with_durable_backend = Config::default();
    with_durable_backend.storage.provider = ferrogate_storage::StorageProviderKind::Postgres;
    assert!(
        with_durable_backend.has_credential_source(),
        "#542: virtual keys live in the durable control plane and are a credential source"
    );
}

/// Every `StorageProviderKind`, paired with whether a deployment on it can
/// resolve a durable/virtual API key -- the #542 question -- and with the reason
/// that answer is what it is.
///
/// This table is the point of the section below. The first version of
/// `has_credential_source` spelled its storage arm as
/// `matches!(provider, Postgres | Supabase)`, and the tests that covered it
/// exercised one variant each; nothing pinned the SET, so `CloudflareD1` was
/// simply absent and deleting `Postgres |` changed no assertion anywhere. A
/// table enumerated from the enum itself cannot have that hole: every variant
/// appears, with a stated answer, or `every_storage_provider_is_in_the_table`
/// stops compiling.
const DURABLE_KEY_STORE_BY_PROVIDER: [(StorageProviderKind, bool, &str); 6] = [
    (
        StorageProviderKind::Memory,
        false,
        "process-local; runtime-minted keys die with the process",
    ),
    (
        StorageProviderKind::Supabase,
        true,
        "implemented durable control plane (postgres wire)",
    ),
    (
        StorageProviderKind::TursoLibsql,
        false,
        "not implemented(); no control-plane store exists behind it",
    ),
    (
        StorageProviderKind::Postgres,
        true,
        "implemented durable control plane",
    ),
    (
        StorageProviderKind::Mysql,
        false,
        "not implemented(); no control-plane store exists behind it",
    ),
    (
        StorageProviderKind::CloudflareD1,
        true,
        "implemented durable control plane (control_plane_store_d1); the \
         hosted-on-Cloudflare posture #542's first fix locked out",
    ),
];

/// Compile-time proof that the table above names every variant: a new backend
/// makes this match non-exhaustive, so it cannot be added to the enum without
/// stating whether it can hold a credential.
fn every_storage_provider_is_in_the_table(provider: StorageProviderKind) -> usize {
    match provider {
        StorageProviderKind::Memory => 0,
        StorageProviderKind::Supabase => 1,
        StorageProviderKind::TursoLibsql => 2,
        StorageProviderKind::Postgres => 3,
        StorageProviderKind::Mysql => 4,
        StorageProviderKind::CloudflareD1 => 5,
    }
}

/// #542 rework, finding 1: the credential-source predicate is pinned as a SET,
/// per storage provider, with no other credential source in the config.
///
/// Pins `Config::durable_api_key_store` (`config/types.rs`) and, through it, the
/// storage arm of `has_credential_source`.
///
/// Mutations this catches:
/// - deleting `StorageProviderKind::Postgres |` from the true-arm (the mutation
///   the review found surviving): the Postgres row asserts a credential source;
/// - the shipped omission of `CloudflareD1`: the D1 row asserts one, and asserts
///   that a D1 gateway with no static key still REQUIRES authentication rather
///   than being told to disable it;
/// - promoting `Memory` to a key store: the Memory row asserts none;
/// - letting a variant fall through a wildcard: the table's answers are checked
///   against `StorageProviderKind::implemented()`, a source of truth in a
///   different crate, so an unimplemented backend claiming to hold keys (or an
///   implemented durable one silently excluded) reds here.
#[test]
fn credential_sources_cover_every_storage_provider() {
    assert_eq!(
        DURABLE_KEY_STORE_BY_PROVIDER.len(),
        6,
        "the table must list every StorageProviderKind variant"
    );

    for (index, (provider, holds_keys, why)) in DURABLE_KEY_STORE_BY_PROVIDER.iter().enumerate() {
        assert_eq!(
            every_storage_provider_is_in_the_table(*provider),
            index,
            "the table is out of step with the enum at {}",
            provider.as_str()
        );

        let mut config = Config::default();
        config.storage.provider = *provider;
        assert!(config.api_keys.is_empty());
        assert!(!config.auth_service.enabled);

        assert_eq!(
            config.durable_api_key_store(),
            holds_keys.then_some(*provider),
            "storage.provider = {} must {}hold durable virtual keys ({why})",
            provider.as_str(),
            if *holds_keys { "" } else { "not " }
        );
        assert_eq!(
            config.has_credential_source(),
            *holds_keys,
            "storage.provider = {} is the only possible credential source here ({why})",
            provider.as_str()
        );
        // ...and one that has one boots REQUIRING authentication, which is the
        // whole of #542: the keys are in the control plane, not in the file.
        assert!(config.auth_required());

        // Cross-check against a different source of truth: nothing may be
        // treated as a durable key store unless the storage crate says it is
        // implemented, and the two exclusions below are excluded FOR that
        // reason -- implement either and this reds, forcing the decision.
        if *holds_keys {
            assert!(
                provider.implemented(),
                "{} cannot hold keys it has no implementation to store",
                provider.as_str()
            );
            assert!(provider.is_durable());
        } else if !matches!(provider, StorageProviderKind::Memory) {
            assert!(
                !provider.implemented(),
                "{} is now implemented; decide whether it holds durable API keys \
                 in Config::durable_api_key_store",
                provider.as_str()
            );
        }
    }
}

#[test]
fn parses_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "prod-us"
node_id = "gateway-a"
node_region = "us-east-1"
node_zone = "us-east-1a"
state_backend = "local"
file_state_path = "/var/lib/ferrogate/cluster-state.json"
counter_backend = "local"
heartbeat_interval_secs = 15
config_poll_interval_secs = 7

[telemetry]
service_name = "ferrogate-dev"
otlp_endpoint = "http://127.0.0.1:4318"

[observability]
enabled = true
provider = "vector"
otlp_endpoint = "http://vector:4318"
prometheus_metrics_path = "/metrics"
export_timeout_secs = 4

[auth_service]
enabled = true
endpoint = "http://127.0.0.1:8090"
timeout_millis = 750
max_retries = 2
retry_backoff_millis = 25

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 120
max_records = 256

[reliability]
provider_circuit_breaker_failure_threshold = 2
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 5
provider_dispatch_max_retries = 1
mcp_dispatch_timeout_secs = 7
mcp_dispatch_max_concurrency = 4
graceful_shutdown_grace_period_secs = 3
graceful_shutdown_timeout_secs = 15
graceful_upgrade_pid_file = "/tmp/ferrogate.pid"
graceful_upgrade_sock = "/tmp/ferrogate_upgrade.sock"
graceful_upgrade_sock_retries = 5

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
openrouter_http_referer = "https://ferrogate.example"
openrouter_x_title = "FerroGate"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
routing_strategy = "lowest_cost"
capabilities = ["chat", "streaming"]
context_window = 128000
input_price_per_1m = 0.15
output_price_per_1m = 0.60
visible_organization_ids = ["org_demo"]
visible_project_ids = ["project_gateway"]

[[models.fallbacks]]
provider = "openai"
provider_model = "gpt-4.1-mini"
input_price_per_1m = 0.10
output_price_per_1m = 0.40
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

[[plugins]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[plugins.permissions]
tools = ["tool.echo"]
network = []
filesystem = false
shell = false

[plugins.config]
timeout_ms = 30000
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(config.listen, "0.0.0.0:8080");
    assert!(config.cluster.enabled);
    assert!(config.cache.enabled);
    assert_eq!(config.cache.mode, CacheMode::ExactMatch);
    assert_eq!(config.cache.ttl_secs, 120);
    assert_eq!(config.cache.max_records, 256);
    assert_eq!(config.cluster.cluster_id, "prod-us");
    assert_eq!(config.cluster.node_id, "gateway-a");
    assert_eq!(config.cluster.node_region.as_deref(), Some("us-east-1"));
    assert_eq!(config.cluster.node_zone.as_deref(), Some("us-east-1a"));
    assert_eq!(config.cluster.state_backend, "local");
    assert_eq!(
        config.cluster.file_state_path.as_deref(),
        Some("/var/lib/ferrogate/cluster-state.json")
    );
    assert_eq!(config.cluster.counter_backend, "local");
    assert_eq!(config.cluster.heartbeat_interval_secs, 15);
    assert_eq!(config.cluster.config_poll_interval_secs, 7);
    assert_eq!(config.telemetry.service_name, "ferrogate-dev");
    assert_eq!(
        config.telemetry.otlp_endpoint.as_deref(),
        Some("http://127.0.0.1:4318")
    );
    assert!(config.observability.enabled);
    assert_eq!(config.observability.provider, ObservabilityProvider::Vector);
    assert_eq!(
        config.observability.otlp_endpoint.as_deref(),
        Some("http://vector:4318")
    );
    assert_eq!(config.observability.prometheus_metrics_path, "/metrics");
    assert_eq!(config.observability.export_timeout_secs, 4);
    assert!(config.auth_service.enabled);
    assert_eq!(config.auth_service.endpoint, "http://127.0.0.1:8090");
    assert_eq!(config.auth_service.timeout_millis, 750);
    assert_eq!(config.auth_service.max_retries, 2);
    assert_eq!(config.auth_service.retry_backoff_millis, 25);
    assert_eq!(
        config
            .reliability
            .provider_circuit_breaker_failure_threshold,
        Some(2)
    );
    assert_eq!(
        config.reliability.provider_circuit_breaker_cooldown_secs,
        Some(30)
    );
    assert_eq!(config.reliability.provider_dispatch_timeout_secs, Some(5));
    assert_eq!(config.reliability.provider_dispatch_max_retries, Some(1));
    assert_eq!(config.reliability.mcp_dispatch_timeout_secs, 7);
    assert_eq!(config.reliability.mcp_dispatch_max_concurrency, 4);
    assert_eq!(
        config.reliability.graceful_shutdown_grace_period_secs,
        Some(3)
    );
    assert_eq!(config.reliability.graceful_shutdown_timeout_secs, Some(15));
    assert_eq!(
        config.reliability.graceful_upgrade_pid_file.as_deref(),
        Some("/tmp/ferrogate.pid")
    );
    assert_eq!(
        config.reliability.graceful_upgrade_sock.as_deref(),
        Some("/tmp/ferrogate_upgrade.sock")
    );
    assert_eq!(config.reliability.graceful_upgrade_sock_retries, Some(5));
    assert_eq!(config.providers.len(), 1);
    assert_eq!(config.providers[0].name, "openai");
    assert_eq!(
        config.providers[0].openrouter_http_referer.as_deref(),
        Some("https://ferrogate.example")
    );
    assert_eq!(
        config.providers[0].openrouter_x_title.as_deref(),
        Some("FerroGate")
    );
    assert_eq!(config.models.len(), 1);
    assert_eq!(config.models[0].name, "fast-chat");
    assert_eq!(
        config.models[0].routing_strategy,
        RoutingStrategy::LowestCost
    );
    assert_eq!(config.models[0].fallbacks.len(), 1);
    assert_eq!(config.models[0].fallbacks[0].provider_model, "gpt-4.1-mini");
    assert_eq!(config.models[0].fallbacks[0].priority, Some(10));
    assert_eq!(config.models[0].fallbacks[0].weight, Some(2));
    assert_eq!(config.models[0].visible_organization_ids, ["org_demo"]);
    assert_eq!(config.models[0].visible_project_ids, ["project_gateway"]);
    assert_eq!(config.api_keys.len(), 1);
    assert_eq!(config.api_keys[0].id, "key_dev");
    assert_eq!(config.api_keys[0].log_bodies, Some(true));
    assert_eq!(config.plugins.len(), 1);
    assert_eq!(config.plugins[0].id, "tool.echo");
    assert_eq!(config.plugins[0].kind, ExtensionKind::ToolProvider);
    assert_eq!(config.plugins[0].source, "builtin");
    assert_eq!(config.plugins[0].permissions.tools, ["tool.echo"]);
    assert_eq!(
        config.plugins[0].config.get("timeout_ms"),
        Some(&toml::Value::Integer(30000))
    );
    assert_eq!(config.plugin_registrations().len(), 1);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}

#[test]
fn rejects_yaml_storage_libsql_config_file_with_migration_message() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        r#"
listen: "127.0.0.1:8080"
storage:
  provider: turso_libsql
  required: true
  provider_order:
    - supabase
    - postgres
  libsql_url: "libsql://example.turso.io"
  libsql_auth_token: "test-token"
  migration_mode: auto
"#,
    )
    .unwrap();

    let error = format!("{:?}", Config::load(&path).unwrap_err());
    assert!(error.contains("turso_libsql has been removed"));
    assert!(error.contains("supabase"));
}

#[test]
fn parses_yaml_external_agent_runtime_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        r#"
listen: "127.0.0.1:8080"
agent_runtime:
  enabled: true
  provider: external
  max_turns: 4
  timeout_millis: 15000
  external:
    command: sh
    args: ["-c", "printf 'finish\\tfrom-config\\n'"]
    timeout_millis: 1000
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert!(config.agent_runtime.enabled);
    assert_eq!(
        config.agent_runtime.provider,
        AgentRuntimeProvider::External
    );
    assert_eq!(config.agent_runtime.external.command, "sh");
    assert_eq!(
        config.agent_runtime.external.args,
        ["-c", "printf 'finish\\tfrom-config\\n'"]
    );
    assert_eq!(config.agent_runtime.external.timeout_millis, Some(1000));
}

#[test]
fn parses_yaml_managed_worker_authorizer_socket_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    let authorizer_socket = dir.path().join("agent-actions.sock");
    std::fs::write(
        &path,
        format!(
            r#"
listen: "127.0.0.1:8080"
agent_runtime:
  enabled: true
  provider: managed_worker
  managed_worker:
    external_action_authorizer_socket: {}
    external_action_authorizer_max_requests: 2
    allowed_actions: [tool, mcp_tool, network_egress]
    approval_required_actions: [cli, rest]
    allow_direct_network_egress: true
    class_only_policy_mode: legacy_class_wide
"#,
            authorizer_socket.display()
        ),
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert!(config.agent_runtime.enabled);
    assert_eq!(
        config.agent_runtime.provider,
        AgentRuntimeProvider::ManagedWorker
    );
    assert_eq!(
        config
            .agent_runtime
            .managed_worker
            .external_action_authorizer_socket
            .as_deref(),
        Some(authorizer_socket.to_str().unwrap())
    );
    assert_eq!(
        config
            .agent_runtime
            .managed_worker
            .external_action_authorizer_max_requests,
        Some(2)
    );
    assert_eq!(
        config.agent_runtime.managed_worker.allowed_actions,
        [
            crate::config::ManagedWorkerCapabilityActionConfig::Tool,
            crate::config::ManagedWorkerCapabilityActionConfig::McpTool,
            crate::config::ManagedWorkerCapabilityActionConfig::NetworkEgress,
        ]
    );
    assert_eq!(
        config
            .agent_runtime
            .managed_worker
            .approval_required_actions,
        [
            crate::config::ManagedWorkerCapabilityActionConfig::Cli,
            crate::config::ManagedWorkerCapabilityActionConfig::Rest,
        ]
    );
    assert!(
        config
            .agent_runtime
            .managed_worker
            .allow_direct_network_egress
    );
}

#[test]
fn parses_yaml_storage_postgres_operational_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        r#"
listen: "127.0.0.1:8080"
storage:
  provider: postgres
  required: true
  provider_order:
    - supabase
    - postgres
  postgres_dsn_env: FERROGATE_POSTGRES_DSN
  postgres_pool_size: 3
  postgres_pool_acquire_timeout_millis: 750
  postgres_tls_mode: prefer
  postgres_tls_ca_cert_path: "/tmp/ferrogate-postgres-ca.pem"
  postgres_connect_timeout_secs: 7
  postgres_statement_timeout_millis: 4000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: auto
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.storage.provider,
        ferrogate_storage::StorageProviderKind::Postgres
    );
    assert_eq!(
        config.storage.postgres_dsn_env.as_deref(),
        Some("FERROGATE_POSTGRES_DSN")
    );
    assert_eq!(config.storage.postgres_pool_size, 3);
    assert_eq!(config.storage.postgres_pool_acquire_timeout_millis, 750);
    assert_eq!(
        config.storage.postgres_tls_mode,
        ferrogate_storage::PostgresTlsMode::Prefer
    );
    assert_eq!(
        config.storage.postgres_tls_ca_cert_path.as_deref(),
        Some("/tmp/ferrogate-postgres-ca.pem")
    );
    assert_eq!(config.storage.postgres_connect_timeout_secs, 7);
    assert_eq!(config.storage.postgres_statement_timeout_millis, 4000);
    assert_eq!(
        config.storage.postgres_schema.as_deref(),
        Some("ferrogate_control")
    );
    assert_eq!(config.storage.postgres_search_path, ["public"]);
}

#[test]
fn parses_yaml_storage_supabase_operational_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        r#"
listen: "127.0.0.1:8080"
storage:
  provider: supabase
  required: true
  provider_order:
    - supabase
    - postgres
  supabase_dsn_env: FERROGATE_SUPABASE_DSN
  postgres_pool_size: 3
  postgres_pool_acquire_timeout_millis: 800
  postgres_tls_mode: require
  postgres_connect_timeout_secs: 7
  postgres_statement_timeout_millis: 4000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: auto
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.storage.provider,
        ferrogate_storage::StorageProviderKind::Supabase
    );
    assert_eq!(
        config.storage.supabase_dsn_env.as_deref(),
        Some("FERROGATE_SUPABASE_DSN")
    );
    assert_eq!(config.storage.postgres_pool_size, 3);
    assert_eq!(config.storage.postgres_pool_acquire_timeout_millis, 800);
    assert_eq!(
        config.storage.postgres_tls_mode,
        ferrogate_storage::PostgresTlsMode::Require
    );
    assert_eq!(config.storage.postgres_connect_timeout_secs, 7);
    assert_eq!(config.storage.postgres_statement_timeout_millis, 4000);
    assert_eq!(
        config.storage.postgres_schema.as_deref(),
        Some("ferrogate_control")
    );
    assert_eq!(config.storage.postgres_search_path, ["public"]);
}

#[test]
fn rejects_yaml_storage_mysql_config_file_with_migration_message() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        r#"
listen: "127.0.0.1:8080"
storage:
  provider: mysql
  required: true
  provider_order:
    - supabase
    - postgres
  migration_mode: auto
"#,
    )
    .unwrap();

    let error = format!("{:?}", Config::load(&path).unwrap_err());
    assert!(error.contains("mysql has been removed"));
    assert!(error.contains("supabase"));
}

#[test]
fn rejects_yaml_storage_libsql_file_config_with_migration_message() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("ferrogate-control-plane.db");
    let path = dir.path().join("ferrogate.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
listen: "127.0.0.1:8080"
storage:
  provider: turso_libsql
  required: true
  provider_order:
    - supabase
    - postgres
  libsql_url: "file://{}"
  migration_mode: auto
"#,
            db_path.display()
        ),
    )
    .unwrap();

    let error = format!("{:?}", Config::load(&path).unwrap_err());
    assert!(error.contains("turso_libsql has been removed"));
    assert!(error.contains("supabase"));
}

#[test]
fn rejects_unsupported_cache_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
[cache]
enabled = true
mode = "fuzzy"
"#,
    )
    .unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(error.contains("unknown variant"), "{error}");
    assert!(error.contains("fuzzy"), "{error}");
}

#[test]
fn accepts_semantic_cache_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
[cache]
enabled = true
mode = "semantic"
semantic_similarity_threshold = 0.9
"#,
    )
    .unwrap();

    let config = Config::load(&path).expect("semantic cache mode should load");
    assert_eq!(config.cache.mode, CacheMode::Semantic);
    assert!((config.cache.semantic_similarity_threshold - 0.9).abs() < 1e-6);
}

#[test]
fn rejects_semantic_threshold_out_of_range() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
[cache]
enabled = true
mode = "semantic"
semantic_similarity_threshold = 1.5
"#,
    )
    .unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(
        error.contains("cache.semantic_similarity_threshold"),
        "{error}"
    );
}

#[test]
fn parses_caddyfile_tls_paths_relative_to_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    if !write_self_signed_test_certificate(&cert, &key) {
        return;
    }

    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"
:8443 {
    tls cert.pem key.pem
    respond /healthz "ok" 200
}
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert!(config.tls.is_enabled());
    assert_eq!(
        config.tls.cert_path.as_deref(),
        Some(cert.to_string_lossy().as_ref())
    );
    assert_eq!(
        config.tls.key_path.as_deref(),
        Some(key.to_string_lossy().as_ref())
    );
}

#[test]
fn parses_acme_tls_paths_relative_to_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "127.0.0.1:8080"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
terms_agreed = true
storage_dir = "./acme"
dns_provider = "cloudflare"
dns_config = { api_token = "cf-token", zone_id = "zone-123" }
dns_hook_set = "./hooks/dns-set"
dns_hook_cleanup = "./hooks/dns-cleanup"
renewal_window_secs = 1209600
renewal_check_interval_secs = 300
renewal_retry_interval_secs = 60
auto_graceful_reload = false
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();

    assert!(config.tls.is_enabled());
    assert!(config.tls.acme.enabled);
    assert_eq!(
        config.tls.acme.storage_dir,
        dir.path().join("acme").to_string_lossy().into_owned()
    );
    assert_eq!(
        config.tls.acme.dns_hook_set.as_deref(),
        Some(dir.path().join("hooks/dns-set").to_string_lossy().as_ref())
    );
    assert_eq!(config.tls.acme.dns_provider.as_deref(), Some("cloudflare"));
    assert_eq!(
        config.tls.acme.dns_config.get("api_token").unwrap(),
        "cf-token"
    );
    assert_eq!(
        config.tls.acme.dns_config.get("zone_id").unwrap(),
        "zone-123"
    );
    assert_eq!(
        config.tls.acme.dns_hook_cleanup.as_deref(),
        Some(
            dir.path()
                .join("hooks/dns-cleanup")
                .to_string_lossy()
                .as_ref()
        )
    );
    assert_eq!(config.tls.acme.renewal_window_secs, 1_209_600);
    assert_eq!(config.tls.acme.renewal_check_interval_secs, 300);
    assert_eq!(config.tls.acme.renewal_retry_interval_secs, 60);
    assert!(!config.tls.acme.auto_graceful_reload);
}

#[test]
fn parses_caddyfile_acme_tls_paths_relative_to_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage ./acme
        renewal_window_secs 1209600
        renewal_check_interval_secs 300
        renewal_retry_interval_secs 60
        auto_graceful_reload false
        dns exec ./hooks/dns-set ./hooks/dns-cleanup {
            provider cloudflare
            api_token cf-token
        }
    }
}
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();

    assert!(config.tls.acme.enabled);
    assert_eq!(config.tls.acme.domains, ["api.example.com"]);
    assert_eq!(config.tls.acme.email.as_deref(), Some("ops@example.com"));
    assert_eq!(config.tls.acme.dns_provider.as_deref(), Some("cloudflare"));
    assert_eq!(
        config.tls.acme.dns_config.get("api_token").unwrap(),
        "cf-token"
    );
    assert_eq!(
        config.tls.acme.storage_dir,
        dir.path().join("acme").to_string_lossy().into_owned()
    );
    assert_eq!(config.tls.acme.renewal_window_secs, 1_209_600);
    assert_eq!(config.tls.acme.renewal_check_interval_secs, 300);
    assert_eq!(config.tls.acme.renewal_retry_interval_secs, 60);
    assert!(!config.tls.acme.auto_graceful_reload);
}

#[test]
fn parses_caddyfile_ai_gateway_into_valid_runtime_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"
:8080 {
    ai_gateway {
        provider openai {
            kind openai
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
            openrouter_http_referer https://ferrogate.example
            openrouter_x_title FerroGate Local
        }
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
            context_window 128000
            input_price_per_1m 0.15
            output_price_per_1m 0.60
        }
        api_key key_dev {
            name Development key
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions
            allowed_models fast-chat
            denied_models fast-chat
            denied_providers openai
            monthly_token_budget 1000000
            request_limit_per_minute 60
            platform_operator on
        }
    }
}
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();

    assert_eq!(config.providers.len(), 1);
    assert_eq!(config.providers[0].kind, "openai");
    assert_eq!(
        config.providers[0].api_key_env.as_deref(),
        Some("OPENAI_API_KEY")
    );
    assert_eq!(
        config.providers[0].openrouter_http_referer.as_deref(),
        Some("https://ferrogate.example")
    );
    assert_eq!(
        config.providers[0].openrouter_x_title.as_deref(),
        Some("FerroGate Local")
    );
    assert_eq!(config.models.len(), 1);
    assert_eq!(config.models[0].capabilities, ["chat", "streaming"]);
    assert_eq!(config.models[0].context_window, Some(128000));
    assert_eq!(config.models[0].input_price_per_1m, Some(0.15));
    assert_eq!(config.models[0].output_price_per_1m, Some(0.60));
    assert_eq!(config.api_keys.len(), 1);
    assert_eq!(
        config.api_keys[0].key_env.as_deref(),
        Some("FERROGATE_DEV_KEY")
    );
    assert_eq!(config.api_keys[0].allowed_models, ["fast-chat"]);
    assert_eq!(config.api_keys[0].denied_models, ["fast-chat"]);
    assert_eq!(config.api_keys[0].denied_providers, ["openai"]);
    assert_eq!(config.api_keys[0].request_limit_per_minute, Some(60));
}

fn write_self_signed_test_certificate(cert: &std::path::Path, key: &std::path::Path) -> bool {
    let Ok(status) = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    else {
        return false;
    };
    status.success()
}

/// #515/#540: the two tenant-identity semantics are declarable in the config
/// file and round-trip through serde, and a config that says nothing lands on
/// the fail-closed answer.
#[test]
fn tenancy_section_parses_and_defaults_to_declared_identity() {
    let declared = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[tenancy]
implicit_platform_operator = false
require_registered_tenant = true

[[api_keys]]
id = "operator"
name = "Operator"
key = "operator-secret"
platform_operator = true

[[api_keys]]
id = "tenant-key"
name = "Tenant key"
key = "tenant-secret"
organization_id = "tenant-a"
"#,
    )
    .expect("a config that declares both identities must load");

    assert!(!declared.tenancy.implicit_platform_operator);
    assert!(declared.tenancy.require_registered_tenant);
    assert_eq!(declared.api_keys[0].platform_operator, Some(true));
    assert_eq!(declared.api_keys[0].organization_id, None);
    assert_eq!(declared.api_keys[1].platform_operator, None);
    assert_eq!(
        declared.api_keys[1].organization_id.as_deref(),
        Some("tenant-a")
    );

    // #540: omitting `[tenancy]` is the fail-closed answer, not the legacy one.
    //
    // #540 rework, correcting this comment. It used to claim that restoring
    // `#[serde(default = "default_true")]` on `implicit_platform_operator`
    // "would red exactly here". It would not, and the review was right: an
    // ABSENT `[tenancy]` section is filled by `Config.tenancy`'s own
    // `#[serde(default)]`, which calls `TenancyConfig::default()` -- the
    // hand-written `impl Default` -- and never consults the field attribute at
    // all. The case that reaches the attribute is a `[tenancy]` section that is
    // PRESENT and does not mention the field; it is the very next assertion
    // below, and it is the one that reds on that mutation.
    let silent = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
platform_operator = true
"#,
    )
    .expect("a config whose every key declares an identity loads with no [tenancy] section");

    assert!(
        !silent.tenancy.implicit_platform_operator,
        "an omitted [tenancy] section must not re-grant root by omission"
    );
    assert!(!silent.tenancy.require_registered_tenant);
    assert_eq!(
        silent.warn_implicit_platform_operators(),
        Vec::<&str>::new(),
        "nothing is relying on the legacy answer here, and the warning must not fire for a key \
         that declared itself"
    );

    // #540 rework: the serde attribute's own case. A `[tenancy]` section that
    // IS present and simply does not mention `implicit_platform_operator` is
    // the only input that routes through `#[serde(default)]` on the field, and
    // it is a shape real deployments write -- a config that sets
    // `require_registered_tenant` and nothing else. Restore `#[serde(default =
    // "default_true")]` on that field and this assertion, alone in this file,
    // goes red; every other case here either omits the section or states the
    // field.
    let partial_section = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[tenancy]
require_registered_tenant = true

[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
platform_operator = true
"#,
    )
    .expect("a [tenancy] section that states only the other field must load");
    assert!(
        !partial_section.tenancy.implicit_platform_operator,
        "a PRESENT [tenancy] section that omits this line must still fail closed -- this is the \
         one input that reads the field's #[serde(default)], and a default of `true` here would \
         silently restore root-by-omission for a deployment that wrote a [tenancy] block for an \
         unrelated reason"
    );
    assert!(partial_section.tenancy.require_registered_tenant);

    // The same file with the declaration removed is refused -- so the pass
    // above is the annotation doing work, not the check being absent.
    let undeclared = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

# #540-undeclared-on-purpose: this is the shape the refusal exists for
[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
"#,
    )
    .expect_err("#540: a key that declares no tenant identity must not load");
    assert!(
        undeclared.to_string().contains("bootstrap"),
        "unexpected error: {undeclared}"
    );

    // ...and the legacy opt-in restores it, naming the key it promotes.
    let opted_in = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[tenancy]
implicit_platform_operator = true

# #540-undeclared-on-purpose: the key the escape hatch has to keep working
[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
"#,
    )
    .expect("the documented escape hatch must actually load an un-annotated config");
    assert_eq!(opted_in.api_keys[0].platform_operator, None);
    assert_eq!(
        opted_in.warn_implicit_platform_operators(),
        vec!["bootstrap"],
        "...and must say out loud which key that leaves holding platform root"
    );
}

/// #540 rework, review finding 2: the refusal is written in every dialect it
/// can fire on, not only in TOML.
///
/// A Caddyfile deployment that omits the directives is stopped by this exact
/// message, and before this commit every remedy in it was unwritable there:
/// `[[api_keys]]`, `organization_id = "..."` and `[tenancy]
/// implicit_platform_operator = true` are TOML, and the last is *deliberately*
/// unreachable from a Caddyfile (`GatewayConfig::into_config` hard-codes
/// `TenancyConfig::default()`), so an operator following it literally got an
/// `unsupported directive` parse error on top of a gateway that would not
/// start. `platform_operator on` -- the grammar #540 added for precisely this
/// -- was not mentioned at all.
///
/// The precedent is `lifecycle::ensure_auth_posture_is_declared`, which prints
/// "In TOML or YAML: ... In a Caddyfile, in the global options block: ...".
///
/// Pins the `In a Caddyfile` arm of `undeclared_tenant_identity_refusal`
/// (`validate.rs`). Delete those lines and this test reds; it cannot be
/// satisfied by annotating any fixture, because the input is a config that
/// declares nothing on purpose.
#[test]
fn the_undeclared_key_refusal_is_written_in_the_caddyfile_grammar_too() {
    let error = Config::from_caddyfile_str(
        r#"
:8080 {
    ai_gateway {
        provider openai {
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat
        }
        # #540-undeclared-on-purpose: the bridged key the refusal must name
        api_key bridged {
            key bridged-secret
            scopes admin.read
        }
    }
}
"#,
        "Ferrogate/Caddyfile",
    )
    .expect_err("#540: a bridged key that declares nothing must not load")
    .to_string();

    assert!(
        error.contains("bridged"),
        "the refusal names the key that has to change: {error}"
    );
    assert!(
        error.contains("platform_operator on"),
        "and offers the Caddyfile spelling of root, which is the ONLY spelling that file can \
         write: {error}"
    );
    assert!(
        error.contains("organization_id <tenants.id>"),
        "and the Caddyfile spelling of a tenant, without the TOML quotes and equals sign that \
         make it a parse error there: {error}"
    );
    assert!(
        error.contains("A Caddyfile has no [tenancy] section"),
        "and says out loud that the deployment-wide escape hatch it mentions is not reachable \
         from this format, instead of pointing an operator at a section the parser rejects: \
         {error}"
    );
    // The TOML half is still there: one message serves both, so the two can
    // never drift into disagreeing about what the fix is.
    assert!(
        error.contains("[[api_keys]]") && error.contains("implicit_platform_operator = true"),
        "{error}"
    );
}

/// #540 rework, review minor 7: `undeclared.join(", ")` is load-bearing and
/// nothing held it -- no test had ever put more than one undeclared key in a
/// config, so `undeclared[0]` would have passed every assertion in the tree
/// while turning a one-pass migration into an N-restart one.
///
/// Pins the `join` in `undeclared_tenant_identity_refusal`. Replace it with
/// `undeclared[0]` (or `.first().unwrap()`) and the `second-undeclared`
/// assertion reds.
#[test]
fn the_refusal_names_every_undeclared_key_not_just_the_first() {
    let error = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

# #540-undeclared-on-purpose: two of them, which is the whole point
[[api_keys]]
id = "first-undeclared"
name = "First"
key = "first-secret"

[[api_keys]]
id = "declared"
name = "Declared"
key = "declared-secret"
organization_id = "tenant-a"

# #540-undeclared-on-purpose: the second one the message must also name
[[api_keys]]
id = "second-undeclared"
name = "Second"
key = "second-secret"
"#,
    )
    .expect_err("#540: two undeclared keys must not load either")
    .to_string();

    assert!(
        error.contains("first-undeclared"),
        "unexpected error: {error}"
    );
    assert!(
        error.contains("second-undeclared"),
        "every undeclared key is named, or the operator restarts once per key: {error}"
    );
    assert!(
        !error.contains("declared,") && !error.contains(", declared"),
        "and a key that DID declare a tenant is not swept into the list: {error}"
    );
}

/// #540 rework, review finding 3: the refusal is about a config *document*.
/// Applied to the durable control plane it is a lockout, not a migration.
///
/// `apply_control_plane_snapshot_to_config` replaces `config.api_keys`
/// wholesale with the durable documents and only then calls `validate()`, and
/// it does so on ~20 runtime mutation paths. So one pre-#515 row answered `400
/// invalid_api_key` to every admin write -- naming a key the request never
/// touched, and blocking the `PUT` that would have repaired it. With two such
/// rows there was no order in which they could be fixed at all.
///
/// This pins both halves of `ensure_every_key_declares_tenant_identity`'s
/// provenance branch:
///
/// * flip `api_keys_are_control_plane_documents` to `true` in the document case
///   (or delete the `bail!`) and the first assertion reds;
/// * delete the `if self.api_keys_are_control_plane_documents { ... return
///   Ok(()) }` arm and the second reds.
///
/// Neither can be satisfied by annotating a fixture: the same key, byte for
/// byte, must be refused in one config and accepted in the other, so an
/// annotation would red the first assertion.
#[test]
fn an_undeclared_key_stops_a_config_document_and_only_warns_for_a_durable_row() {
    let mut document = Config::default();
    document.api_keys.push(
        // #540-undeclared-on-purpose: a pre-#515 row is exactly the input
        serde_json::from_value(serde_json::json!({
            "id": "legacy-durable",
            "name": "Minted before #515",
            "key": "legacy-secret",
            "scopes": ["admin.read"],
        }))
        .expect("test api key"),
    );

    let refused = document
        .validate()
        .expect_err("a config document's undeclared key must still stop the gateway");
    assert!(
        refused.to_string().contains("legacy-durable"),
        "unexpected error: {refused}"
    );

    let mut durable = document.clone();
    durable.api_keys_are_control_plane_documents = true;
    durable.validate().expect(
        "the same key as a durable control-plane row must NOT stop an admin mutation: the \
         operator cannot edit it out of a file, and refusing here blocks the very write that \
         repairs it",
    );

    // The list is unchanged either way -- the key is still undeclared, still
    // not platform root, and still refused at authentication by
    // `finalize_auth`. Only where the operator is told has changed.
    assert_eq!(
        durable.api_keys_without_tenant_identity(),
        vec!["legacy-durable"],
        "the durable branch reports the key, it does not stop seeing it"
    );
    assert!(
        !durable.tenancy.implicit_platform_operator,
        "and it emphatically does not promote it: the resolver still answers `not root`"
    );
}

/// #540 rework, review finding 3, the other door: the runtime mint refusal must
/// survive the change above, or `POST /admin/v1/api-keys` would go back to
/// minting a credential with no tenant identity.
///
/// Pins `Config::ensure_api_key_declares_tenant_identity`, which `state.rs`'s
/// `upsert_api_key` calls on the one key the request produces. Delete that call
/// (or make this function return `Ok(())` unconditionally) and the first
/// assertion reds. The message is the same text as the config-file refusal, so
/// the admin API and the file cannot disagree about what is acceptable.
#[test]
fn the_per_key_mint_refusal_asks_only_about_the_key_in_the_request() {
    let mut config = Config::default();
    // A legacy durable row is already present and undeclared: the exact state
    // that used to make every mutation 400.
    config.api_keys_are_control_plane_documents = true;
    config.api_keys.push(
        // #540-undeclared-on-purpose: a pre-#515 row is exactly the input
        serde_json::from_value(serde_json::json!({
            "id": "legacy-durable",
            "name": "Minted before #515",
            "key": "legacy-secret",
            "scopes": ["admin.read"],
        }))
        .expect("test api key"),
    );

    // #540-undeclared-on-purpose: the mint request the admin API must refuse
    let minted: super::ApiKey = serde_json::from_value(serde_json::json!({
        "id": "brand-new",
        "name": "Brand new",
        "key": "brand-new-secret",
        "scopes": ["admin.read"],
    }))
    .expect("test api key");
    let refused = config
        .ensure_api_key_declares_tenant_identity(&minted)
        .expect_err("#540: the admin API must not mint a credential with no tenant identity");
    assert!(
        refused.to_string().contains("brand-new"),
        "and the 400 names the key the CALLER sent, not the legacy rows it never touched: \
         {refused}"
    );
    assert!(!refused.to_string().contains("legacy-durable"), "{refused}");

    let declared: super::ApiKey = serde_json::from_value(serde_json::json!({
        "id": "brand-new",
        "name": "Brand new",
        "key": "brand-new-secret",
        "scopes": ["admin.read"],
        "organization_id": "tenant-a",
    }))
    .expect("test api key");
    config
        .ensure_api_key_declares_tenant_identity(&declared)
        .expect("declaring the tenant is the fix the refusal names, so it must be accepted");

    // The legacy opt-in is deferred to here exactly as it is for a file, so an
    // operator who took the documented way past an upgrade can still use the
    // admin API.
    config.tenancy.implicit_platform_operator = true;
    config
        .ensure_api_key_declares_tenant_identity(&minted)
        .expect("the documented escape hatch must reach the admin API too");
}

/// #540 rework, review minors 1 and 3: two postures an operator could hold
/// forever without `ferrogate check` ever mentioning them.
///
/// 1. `implicit_platform_operator = true` reverts #540 for every undeclared key
///    the deployment holds. It was a bare `tracing::warn!` that
///    `format_validate_report` never consulted, so the pre-flight printed
///    `FerroGate config OK` and exited 0.
/// 2. `platform_operator = false` with no `organization_id` loads clean and
///    then answers `tenant_identity_required` to every request, because the
///    validator's predicate (`is_none() && is_none()`) was strictly narrower
///    than `finalize_auth`'s (`!platform_operator && is_none()`). It fails
///    closed, so it is reported rather than refused -- but "the operator finds
///    out at load" is #540's own thesis and this defeated it.
///
/// Pins `Config::tenancy_posture_warnings` and both lists it reads. Delete
/// either arm and its assertion reds; a fixture annotation cannot satisfy
/// them, because the input is the un-annotated posture itself.
#[test]
fn ferrogate_check_can_see_the_legacy_opt_in_and_the_key_that_authorizes_nothing() {
    let clean = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[[api_keys]]
id = "operator"
name = "Operator"
key = "operator-secret"
platform_operator = true
"#,
    )
    .expect("a fully declared config");
    assert!(
        clean.tenancy_posture_warnings().is_empty(),
        "a declared config says nothing, or the warning is noise every operator learns to skip"
    );

    let opted_in = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[tenancy]
implicit_platform_operator = true

# #540-undeclared-on-purpose: the key the warning has to name
[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
"#,
    )
    .expect("the escape hatch loads");
    let warnings = opted_in.tenancy_posture_warnings().join("\n");
    assert!(
        warnings.contains("implicit_platform_operator = true") && warnings.contains("bootstrap"),
        "the pre-flight has to name the switch AND every key it is promoting to platform root: \
         {warnings}"
    );

    let authorizes_nothing = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[[api_keys]]
id = "operator"
name = "Operator"
key = "operator-secret"
platform_operator = true

[[api_keys]]
id = "refuses-root"
name = "Explicitly not root, and no tenant"
key = "refuses-secret"
platform_operator = false
"#,
    )
    .expect(
        "#540 rework: this is a mistake, not a privilege defect -- it fails closed, so it is \
         reported and NOT refused. Refusing would stop a gateway over a harmless key, and would \
         break the declared/effective fixtures that model this shape deliberately.",
    );
    assert_eq!(
        authorizes_nothing.api_keys_that_authorize_nothing(),
        vec!["refuses-root"],
        "the operator key is not swept in: it declared root, so it authorizes plenty"
    );
    let warnings = authorizes_nothing.tenancy_posture_warnings().join("\n");
    assert!(
        warnings.contains("refuses-root") && warnings.contains("tenant_identity_required"),
        "and the pre-flight names it and says what will happen to it: {warnings}"
    );
}

/// #515: the contradiction is refused at load, not resolved by precedence.
#[test]
fn platform_operator_with_a_tenant_fails_config_load() {
    let error = Config::from_toml_str(
        r#"
listen = "127.0.0.1:8080"

[[api_keys]]
id = "confused"
name = "Confused"
key = "confused-secret"
platform_operator = true
organization_id = "tenant-a"
"#,
    )
    .expect_err("root and a tenant are mutually exclusive");

    assert!(
        error.to_string().contains("platform_operator"),
        "unexpected error: {error}"
    );
}
