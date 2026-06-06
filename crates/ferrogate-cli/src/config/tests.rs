use super::*;
use ferrogate_providers::RoutingStrategy;

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

[cluster]
enabled = true
cluster_id = "prod-us"
node_id = "gateway-a"
node_region = "us-east-1"
node_zone = "us-east-1a"
state_backend = "local"
counter_backend = "local"
heartbeat_interval_secs = 15
config_poll_interval_secs = 7

[telemetry]
service_name = "ferrogate-dev"
otlp_endpoint = "http://127.0.0.1:4318"

[reliability]
provider_circuit_breaker_failure_threshold = 2
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 5
provider_dispatch_max_retries = 1
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
"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(config.listen, "0.0.0.0:8080");
    assert!(config.cluster.enabled);
    assert_eq!(config.cluster.cluster_id, "prod-us");
    assert_eq!(config.cluster.node_id, "gateway-a");
    assert_eq!(config.cluster.node_region.as_deref(), Some("us-east-1"));
    assert_eq!(config.cluster.node_zone.as_deref(), Some("us-east-1a"));
    assert_eq!(config.cluster.state_backend, "local");
    assert_eq!(config.cluster.counter_backend, "local");
    assert_eq!(config.cluster.heartbeat_interval_secs, 15);
    assert_eq!(config.cluster.config_poll_interval_secs, 7);
    assert_eq!(config.telemetry.service_name, "ferrogate-dev");
    assert_eq!(
        config.telemetry.otlp_endpoint.as_deref(),
        Some("http://127.0.0.1:4318")
    );
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
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
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
