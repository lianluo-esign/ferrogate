// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{Context, Result as AnyResult};
use ferrogate_config::{
    is_caddyfile_path, load_caddyfile, parse_caddyfile, GatewayConfig, GatewayTlsAcmeConfig,
};
use std::path::{Path, PathBuf};
use tracing::warn;

use super::{
    AdminConfig, Config, HeaderMutation, Model, Provider, RouteRule, TelemetryConfig, TlsConfig,
    Upstream,
};

impl Config {
    pub(crate) fn load(path: &PathBuf) -> AnyResult<Self> {
        if !path.exists() {
            warn!(
                config = %path.display(),
                "configuration file not found; using built-in defaults"
            );
            return Ok(Self::default());
        }

        if is_caddyfile_path(path) {
            let mut config = Self::from_gateway_config(load_caddyfile(path)?);
            config.resolve_paths_relative_to(path.parent());
            config.materialize_skill_package_resources();
            config
                .validate()
                .with_context(|| format!("failed to validate config file {}", path.display()))?;
            return Ok(config);
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut config: Self = parse_structured_config(path, &raw)?;
        config.resolve_paths_relative_to(path.parent());
        config.materialize_skill_package_resources();
        config
            .validate()
            .with_context(|| format!("failed to validate config file {}", path.display()))?;
        Ok(config)
    }

    pub(crate) fn from_toml_str(raw: &str) -> AnyResult<Self> {
        let mut config: Self = toml::from_str(raw).context("failed to parse TOML config")?;
        config.materialize_skill_package_resources();
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn from_yaml_str(raw: &str) -> AnyResult<Self> {
        let mut config: Self = serde_yaml::from_str(raw).context("failed to parse YAML config")?;
        config.materialize_skill_package_resources();
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn from_caddyfile_str(raw: &str, file: &str) -> AnyResult<Self> {
        let mut config = Self::from_gateway_config(parse_caddyfile(raw, file)?);
        config.materialize_skill_package_resources();
        config.validate()?;
        Ok(config)
    }

    /// Map the Caddyfile intermediate model into the runtime config shape.
    fn from_gateway_config(config: GatewayConfig) -> Self {
        Self {
            listen: config.listen,
            admin: AdminConfig {
                listen: config.admin,
            },
            auth_service: crate::config::AuthServiceConfig::default(),
            tls: match (config.tls, config.tls_acme) {
                (Some(tls), None) => TlsConfig {
                    enabled: true,
                    cert_path: Some(tls.cert_path),
                    key_path: Some(tls.key_path),
                    http2: false,
                    acme: crate::config::TlsAcmeConfig::default(),
                },
                (None, Some(acme)) => Self::tls_from_gateway_acme(acme),
                (Some(tls), Some(_)) => TlsConfig {
                    enabled: true,
                    cert_path: Some(tls.cert_path),
                    key_path: Some(tls.key_path),
                    http2: false,
                    acme: crate::config::TlsAcmeConfig::default(),
                },
                (None, None) => TlsConfig::default(),
            },
            providers: config
                .providers
                .into_iter()
                .map(|provider| Provider {
                    name: provider.name,
                    kind: provider.kind,
                    base_url: provider.base_url,
                    api_key_env: provider.api_key_env,
                    openrouter_http_referer: provider.openrouter_http_referer,
                    openrouter_x_title: provider.openrouter_x_title,
                    enabled: true,
                })
                .collect(),
            models: config
                .models
                .into_iter()
                .map(|model| Model {
                    name: model.name,
                    provider: model.provider,
                    provider_model: model.provider_model,
                    routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
                    fallbacks: Vec::new(),
                    visible_organization_ids: Vec::new(),
                    visible_project_ids: Vec::new(),
                    capabilities: model.capabilities,
                    context_window: model.context_window,
                    input_price_per_1m: model
                        .input_price_per_1m
                        .as_deref()
                        .and_then(|value| value.parse().ok()),
                    output_price_per_1m: model
                        .output_price_per_1m
                        .as_deref()
                        .and_then(|value| value.parse().ok()),
                    enabled: true,
                    cache_enabled: None,
                })
                .collect(),
            guardrails: Vec::new(),
            api_keys: config
                .api_keys
                .into_iter()
                .map(|key| crate::config::ApiKey {
                    id: key.id,
                    name: key.name,
                    key_env: key.key_env,
                    key: key.key,
                    key_hash: key.key_hash,
                    enabled: true,
                    scopes: key.scopes,
                    allowed_models: key.allowed_models,
                    denied_models: key.denied_models,
                    allowed_providers: key.allowed_providers,
                    denied_providers: key.denied_providers,
                    organization_id: None,
                    team_id: None,
                    project_id: None,
                    user_id: None,
                    monthly_token_budget: key.monthly_token_budget,
                    request_limit_per_minute: key.request_limit_per_minute,
                    expires_at_unix: None,
                    log_bodies: None,
                    cache_enabled: None,
                })
                .collect(),
            policies: Vec::new(),
            gateway_configs: Vec::new(),
            agent_workflows: Vec::new(),
            skill_packages: Vec::new(),
            prompt_templates: Vec::new(),
            plugins: Vec::new(),
            extensions: Vec::new(),
            mcp_servers: Vec::new(),
            agent_upstreams: Vec::new(),
            telemetry: TelemetryConfig::default(),
            observability: crate::config::ObservabilityConfig::default(),
            analytics: crate::config::AnalyticsConfig::default(),
            metering: crate::config::MeteringConfig::default(),
            cache: crate::config::CacheConfig::default(),
            storage: crate::config::StorageConfig::default(),
            reliability: crate::config::ReliabilityConfig::default(),
            agent_runtime: crate::config::AgentRuntimeConfig::default(),
            cluster: crate::config::ClusterConfig::default(),
            upstreams: config
                .upstreams
                .into_iter()
                .map(|upstream| Upstream {
                    name: upstream.name,
                    url: Some(upstream.url),
                    urls: upstream.urls,
                    enabled: true,
                })
                .collect(),
            routes: config
                .routes
                .into_iter()
                .filter_map(|route| {
                    route.upstream.map(|upstream| RouteRule {
                        name: route.name,
                        upstream,
                        hosts: route.hosts,
                        path_prefixes: route.path_prefixes,
                        match_headers: Vec::new(),
                        strip_prefix: route.strip_prefix,
                        add_prefix: None,
                        request_headers: route
                            .request_headers
                            .into_iter()
                            .map(|header| HeaderMutation {
                                name: header.name,
                                value: header.value,
                            })
                            .collect(),
                        response_headers: route
                            .response_headers
                            .into_iter()
                            .map(|header| HeaderMutation {
                                name: header.name,
                                value: header.value,
                            })
                            .collect(),
                        enabled: true,
                    })
                })
                .collect(),
        }
    }

    fn tls_from_gateway_acme(acme: GatewayTlsAcmeConfig) -> TlsConfig {
        let mut tls_acme = crate::config::TlsAcmeConfig {
            enabled: true,
            domains: acme.domains,
            email: acme.email,
            dns_provider: acme.dns_provider,
            dns_config: acme.dns_config,
            dns_hook_set: acme.dns_hook_set,
            dns_hook_cleanup: acme.dns_hook_cleanup,
            terms_agreed: true,
            ..crate::config::TlsAcmeConfig::default()
        };
        if let Some(directory_url) = acme.directory_url {
            tls_acme.directory_url = directory_url;
        }
        if let Some(challenge) = acme.challenge {
            tls_acme.challenge = challenge;
        }
        if let Some(http_challenge_listen) = acme.http_challenge_listen {
            tls_acme.http_challenge_listen = http_challenge_listen;
        }
        if let Some(storage_dir) = acme.storage_dir {
            tls_acme.storage_dir = storage_dir;
        }
        if let Some(renewal_window_secs) = acme.renewal_window_secs {
            tls_acme.renewal_window_secs = renewal_window_secs;
        }
        if let Some(renewal_check_interval_secs) = acme.renewal_check_interval_secs {
            tls_acme.renewal_check_interval_secs = renewal_check_interval_secs;
        }
        if let Some(renewal_retry_interval_secs) = acme.renewal_retry_interval_secs {
            tls_acme.renewal_retry_interval_secs = renewal_retry_interval_secs;
        }
        if let Some(auto_graceful_reload) = acme.auto_graceful_reload {
            tls_acme.auto_graceful_reload = auto_graceful_reload;
        }
        TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: None,
            http2: false,
            acme: tls_acme,
        }
    }

    fn resolve_paths_relative_to(&mut self, base_dir: Option<&Path>) {
        let Some(base_dir) = base_dir else {
            return;
        };
        if let Some(cert_path) = &mut self.tls.cert_path {
            *cert_path = resolve_relative_path(base_dir, cert_path);
        }
        if let Some(key_path) = &mut self.tls.key_path {
            *key_path = resolve_relative_path(base_dir, key_path);
        }
        if self.tls.acme.enabled {
            self.tls.acme.storage_dir = resolve_relative_path(base_dir, &self.tls.acme.storage_dir);
            if let Some(dns_hook_set) = &mut self.tls.acme.dns_hook_set {
                *dns_hook_set = resolve_relative_path(base_dir, dns_hook_set);
            }
            if let Some(dns_hook_cleanup) = &mut self.tls.acme.dns_hook_cleanup {
                *dns_hook_cleanup = resolve_relative_path(base_dir, dns_hook_cleanup);
            }
        }
    }
}

fn parse_structured_config(path: &Path, raw: &str) -> AnyResult<Config> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("yaml" | "yml") => serde_yaml::from_str(raw).context("failed to parse YAML config"),
        _ => toml::from_str(raw).context("failed to parse TOML config"),
    }
}

fn resolve_relative_path(base_dir: &Path, raw: &str) -> String {
    let path = Path::new(raw);
    if path.is_absolute() {
        raw.to_string()
    } else {
        base_dir
            .join(path)
            .components()
            .collect::<PathBuf>()
            .to_string_lossy()
            .into_owned()
    }
}
