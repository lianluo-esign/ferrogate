use anyhow::{Context, Result as AnyResult};
use ferrogate_config::{is_caddyfile_path, load_caddyfile, GatewayConfig};
use std::path::PathBuf;
use tracing::warn;

use super::{
    AdminConfig, Config, HeaderMutation, Model, Provider, RouteRule, TelemetryConfig, Upstream,
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
            let config = Self::from_gateway_config(load_caddyfile(path)?);
            config.validate()?;
            return Ok(config);
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn from_gateway_config(config: GatewayConfig) -> Self {
        Self {
            listen: config.listen,
            admin: AdminConfig {
                listen: config.admin,
            },
            providers: config
                .providers
                .into_iter()
                .map(|provider| Provider {
                    name: provider.name,
                    kind: "openai".to_string(),
                    base_url: provider.base_url,
                    api_key_env: None,
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
                    capabilities: Vec::new(),
                    context_window: None,
                    input_price_per_1m: None,
                    output_price_per_1m: None,
                    enabled: true,
                })
                .collect(),
            api_keys: Vec::new(),
            telemetry: TelemetryConfig::default(),
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
}
