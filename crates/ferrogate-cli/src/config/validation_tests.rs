// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;
use ferrogate_providers::RoutingStrategy;

#[test]
fn rejects_model_with_unknown_provider() {
    let config = Config {
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "missing".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("unknown provider"));
}

#[test]
fn rejects_model_with_unknown_fallback_provider() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "missing".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: None,
        output_price_per_1m: None,
        priority: Some(10),
        weight: Some(1),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("fallback provider missing"));
}

#[test]
fn rejects_model_fallback_with_zero_weight() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: None,
        output_price_per_1m: None,
        priority: Some(10),
        weight: Some(0),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("fallbacks[0].weight"));
}

#[test]
fn accepts_model_lowest_cost_strategy_with_prices() {
    let mut model = model();
    model.routing_strategy = RoutingStrategy::LowestCost;
    model.input_price_per_1m = Some(1.0);
    model.output_price_per_1m = Some(2.0);
    model.fallbacks = vec![ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: Some(0.5),
        output_price_per_1m: Some(1.0),
        priority: Some(10),
        weight: Some(1),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_latency_and_balanced_routing_strategies_without_prices() {
    for routing_strategy in [RoutingStrategy::LowestLatency, RoutingStrategy::Balanced] {
        let mut model = model();
        model.routing_strategy = routing_strategy;
        let config = Config {
            providers: vec![provider()],
            models: vec![model],
            ..Config::default()
        };

        config.validate().unwrap();
    }
}

#[test]
fn rejects_model_lowest_cost_strategy_without_prices() {
    let mut model = model();
    model.routing_strategy = RoutingStrategy::LowestCost;
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("lowest_cost requires input_price_per_1m and output_price_per_1m"));
}

#[test]
fn accepts_builtin_extension_config_with_explicit_permissions() {
    let config = Config {
        plugins: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_legacy_extensions_as_plugin_registrations() {
    let config = Config {
        extensions: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        ..Config::default()
    };

    config.validate().unwrap();
    assert_eq!(config.plugin_registrations().len(), 1);
}

#[test]
fn accepts_multiple_builtin_noop_hooks_for_ordered_pipelines() {
    let config = Config {
        extensions: vec![
            extension("hook.noop.first", ExtensionKind::RequestHook, 10),
            extension("hook.noop.second", ExtensionKind::RequestHook, 20),
        ],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_duplicate_extension_ids() {
    let config = Config {
        plugins: vec![
            extension("tool.echo", ExtensionKind::ToolProvider, 10),
            extension("tool.echo", ExtensionKind::EventSink, 20),
        ],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate plugin id tool.echo"));
}

#[test]
fn rejects_duplicate_plugin_ids_across_plugins_and_extensions() {
    let config = Config {
        plugins: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        extensions: vec![extension("tool.echo", ExtensionKind::ToolProvider, 20)],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate plugin id tool.echo"));
}

#[test]
fn rejects_extension_sources_that_can_execute_out_of_tree_code() {
    let mut extension = extension("mcp-tools", ExtensionKind::ToolProvider, 10);
    extension.source = "wasm".into();
    let config = Config {
        extensions: vec![extension],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("only builtin plugins are supported"));
}

#[test]
fn rejects_duplicate_enabled_extension_order_for_same_kind() {
    let config = Config {
        extensions: vec![
            extension("tool.echo", ExtensionKind::ToolProvider, 10),
            extension("tool.health_check", ExtensionKind::ToolProvider, 10),
        ],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate enabled plugin order 10"));

    let mut disabled = extension("tool.health_check", ExtensionKind::ToolProvider, 10);
    disabled.enabled = false;
    let config = Config {
        extensions: vec![
            extension("tool.echo", ExtensionKind::ToolProvider, 10),
            disabled,
        ],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_invalid_extension_permission_values() {
    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.permissions.tools = vec!["tool.echo".into(), "tool.echo".into()];
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate permission value tool.echo"));

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.permissions.network = vec!["".into()];
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("permissions.network[0]: cannot be empty"));

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.config.insert(
        "api_token".into(),
        toml::Value::String("secret-token".into()),
    );
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("config.api_token"));
    assert!(error.contains("permissions.secrets = true"));

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.permissions.secrets = true;
    extension_config.config.insert(
        "headers".into(),
        toml::Value::Table(
            [(
                "authorization".into(),
                toml::Value::String("Bearer secret-token".into()),
            )]
            .into_iter()
            .collect(),
        ),
    );
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };
    config.validate().unwrap();

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.config.insert(
        "tenant_allowlist".into(),
        toml::Value::Array(vec![toml::Value::String("org-demo".into())]),
    );
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("permissions.tenant_scope = true"));

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.permissions.tenant_scope = true;
    extension_config.config.insert(
        "tenant_allowlist".into(),
        toml::Value::Array(vec![toml::Value::String("org-demo".into())]),
    );
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };
    config.validate().unwrap();

    let mut extension_config = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    extension_config.permissions.tenant_scope = true;
    extension_config.config.insert(
        "route_allowlist".into(),
        toml::Value::Array(vec![toml::Value::String(String::new())]),
    );
    let config = Config {
        extensions: vec![extension_config],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("config.route_allowlist[0]: cannot be empty"));
}

#[test]
fn validates_builtin_extension_kind_and_mcp_network_boundary() {
    let mut wrong_kind = extension("tool.echo", ExtensionKind::EventSink, 10);
    wrong_kind.permissions.tools = vec!["tool.echo".into()];
    let config = Config {
        extensions: vec![wrong_kind],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must be tool_provider"));

    let mut mcp = extension("mcp.http", ExtensionKind::ToolProvider, 10);
    mcp.permissions.tools = vec!["github.search".into()];
    let config = Config {
        extensions: vec![mcp],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("config.endpoint"));

    let mut mcp = extension("mcp.http", ExtensionKind::ToolProvider, 10);
    mcp.permissions.tools = vec!["github.search".into()];
    mcp.config.insert(
        "endpoint".into(),
        toml::Value::String("http://127.0.0.1:9000/mcp".into()),
    );
    let config = Config {
        extensions: vec![mcp],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("permissions.network"));

    let mut mcp = extension("mcp.http", ExtensionKind::ToolProvider, 10);
    mcp.permissions.tools = vec!["github.search".into()];
    mcp.permissions.network = vec!["127.0.0.1".into()];
    mcp.config.insert(
        "endpoint".into(),
        toml::Value::String("http://127.0.0.1:9000/mcp".into()),
    );
    let config = Config {
        extensions: vec![mcp],
        ..Config::default()
    };
    config.validate().unwrap();
}

#[test]
fn validates_plugin_manifest_and_compatibility_contract() {
    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.version = "1.2.3".into();
    plugin.manifest.name = Some("Echo tools".into());
    plugin.manifest.description = Some("Safe local echo plugin".into());
    plugin.manifest.capabilities = vec!["tool_provider".into(), "safe:echo".into()];
    plugin.manifest.required_permissions.tools = vec!["tool.echo".into()];
    plugin.manifest.hooks = vec!["tool.execute".into()];
    plugin.manifest.config_schema = Some(toml::Value::Table(toml::map::Map::new()));
    plugin.compatibility.min_gateway_version = Some("0.1.0".into());
    plugin.compatibility.max_gateway_version = Some("9999.0.0".into());
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    config.validate().unwrap();

    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.permissions.tools.clear();
    plugin.manifest.required_permissions.tools = vec!["tool.echo".into()];
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("manifest.required_permissions.tools value tool.echo"));

    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.manifest.required_permissions.secrets = true;
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("permissions.secrets"));
    assert!(error.contains("manifest.required_permissions.secrets"));

    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.version = "not-a-version".into();
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("plugins[0].version"));

    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.manifest.capabilities = vec!["bad capability".into()];
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("plugins[0].manifest.capabilities[0]"));

    let mut plugin = extension("tool.echo", ExtensionKind::ToolProvider, 10);
    plugin.compatibility.min_gateway_version = Some("2.0.0".into());
    plugin.compatibility.max_gateway_version = Some("1.0.0".into());
    let config = Config {
        plugins: vec![plugin],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("min_gateway_version must be <= max_gateway_version"));
}

#[test]
fn validates_optional_metering_export_boundary() {
    let config = Config::default();
    assert_eq!(
        config.metering.export_endpoint,
        "https://api.token4ai.cloud/v1/metering/events"
    );
    assert_eq!(
        config.metering.export_provider,
        MeteringExportProvider::Legacy
    );
    config.validate().unwrap();

    let mut enabled = Config::default();
    enabled.metering.export_enabled = true;
    let error = enabled.validate().unwrap_err().to_string();
    assert!(error.contains("metering.export_token_env"));

    enabled.metering.export_token_env = Some("FERROGATE_METERING_TOKEN".into());
    enabled.validate().unwrap();

    enabled.metering.export_provider = MeteringExportProvider::Openmeter;
    enabled.metering.export_endpoint = "http://127.0.0.1:8888/api/v1/events".into();
    enabled.metering.export_event_type = "ai.tokens".into();
    enabled.metering.export_source = "ferrogate-test".into();
    enabled.metering.export_subject = MeteringExportSubject::Organization;
    enabled.validate().unwrap();
}

#[test]
fn validates_guardrail_keyword_scope_and_effect() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "block-secret".into(),
            name: "Block secret".into(),
            enabled: true,
            stage: GuardrailStage::Request,
            organization_ids: vec!["org_demo".into()],
            project_ids: vec!["project_demo".into()],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            effect: GuardrailEffect::Deny,
            code: "guardrail_blocked".into(),
            message: "blocked by guardrail".into(),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn validates_response_guardrail_redact_effect() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "redact-secret".into(),
            name: "Redact secret".into(),
            enabled: true,
            stage: GuardrailStage::Response,
            organization_ids: vec!["org_demo".into()],
            project_ids: vec!["project_demo".into()],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            effect: GuardrailEffect::Redact,
            code: "guardrail_redacted".into(),
            message: "redacted by guardrail".into(),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn validates_guardrail_regex_and_max_input_bytes() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![
            GuardrailRule {
                id: "block-pattern".into(),
                name: "Block pattern".into(),
                enabled: true,
                stage: GuardrailStage::Request,
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec!["key_dev".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec![],
                regex: vec![r"ABC-[0-9]+".into()],
                max_input_bytes: None,
                effect: GuardrailEffect::Deny,
                code: "guardrail_regex_blocked".into(),
                message: "blocked by regex guardrail".into(),
            },
            GuardrailRule {
                id: "max-input".into(),
                name: "Max input".into(),
                enabled: true,
                stage: GuardrailStage::Request,
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec!["key_dev".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec![],
                regex: vec![],
                max_input_bytes: Some(1024),
                effect: GuardrailEffect::Deny,
                code: "guardrail_input_too_large".into(),
                message: "input is too large".into(),
            },
        ],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_invalid_guardrail_regex() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "block-pattern".into(),
            name: "Block pattern".into(),
            enabled: true,
            stage: GuardrailStage::Request,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec![],
            regex: vec!["[".into()],
            max_input_bytes: None,
            effect: GuardrailEffect::Deny,
            code: "guardrail_regex_blocked".into(),
            message: "blocked by regex guardrail".into(),
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("invalid regex"));
}

#[test]
fn rejects_response_guardrail_max_input_bytes() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "response-max-input".into(),
            name: "Response max input".into(),
            enabled: true,
            stage: GuardrailStage::Response,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec![],
            regex: vec![],
            max_input_bytes: Some(1024),
            effect: GuardrailEffect::Deny,
            code: "guardrail_input_too_large".into(),
            message: "input is too large".into(),
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("max input length guardrails apply to request stage only"));
}

#[test]
fn rejects_request_guardrail_redact_effect() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "redact-secret".into(),
            name: "Redact secret".into(),
            enabled: true,
            stage: GuardrailStage::Request,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            effect: GuardrailEffect::Redact,
            code: "guardrail_redacted".into(),
            message: "redacted by guardrail".into(),
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("request guardrails support deny only"));
}

#[test]
fn rejects_guardrail_with_unknown_model() {
    let config = Config {
        providers: vec![provider()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![GuardrailRule {
            id: "block-secret".into(),
            name: "Block secret".into(),
            enabled: true,
            stage: GuardrailStage::Request,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["missing-model".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            effect: GuardrailEffect::Deny,
            code: "guardrail_blocked".into(),
            message: "blocked by guardrail".into(),
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown model missing-model"));
}

#[test]
fn rejects_route_with_unknown_upstream() {
    let config = Config {
        routes: vec![route("missing", vec!["/"])],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown upstream"));
}

#[test]
fn rejects_upstream_without_any_endpoint() {
    let config = Config {
        upstreams: vec![Upstream {
            name: "empty".into(),
            url: None,
            urls: vec![],
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must define url or urls"));
}

#[test]
fn rejects_invalid_endpoint_in_upstream_pool() {
    let config = Config {
        upstreams: vec![Upstream {
            name: "pool".into(),
            url: Some("http://127.0.0.1:8081".into()),
            urls: vec!["ftp://127.0.0.1:8082".into()],
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("invalid endpoint"));
}

#[test]
fn rejects_invalid_listen_address_with_field_name() {
    let config = Config {
        listen: "not-an-address".into(),
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field listen"));
    assert!(error.contains("invalid listen address"));
}

#[test]
fn rejects_invalid_admin_listen_address_with_field_name() {
    let config = Config {
        admin: AdminConfig {
            listen: Some("not-an-admin-address".into()),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field admin.listen"));
}

#[test]
fn rejects_tls_enabled_without_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some("cert.pem".into()),
            key_path: None,
            http2: false,
            acme: crate::config::TlsAcmeConfig::default(),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.key_path"));
}

#[test]
fn rejects_invalid_tls_certificate_files() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, "not a certificate").unwrap();
    std::fs::write(&key, "not a private key").unwrap();

    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some(cert.to_string_lossy().into_owned()),
            key_path: Some(key.to_string_lossy().into_owned()),
            http2: true,
            acme: crate::config::TlsAcmeConfig::default(),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.cert_path/tls.key_path"));
}

#[test]
fn accepts_acme_dns01_tls_without_manual_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_hook_set: Some("/usr/local/bin/ferrogate-dns-set".into()),
                dns_hook_cleanup: Some("/usr/local/bin/ferrogate-dns-cleanup".into()),
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_acme_dns01_tls_without_dns_hooks() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.acme.dns_provider"));
}

#[test]
fn accepts_acme_dns01_tls_with_builtin_cloudflare_provider() {
    let mut dns_config = std::collections::BTreeMap::new();
    dns_config.insert("api_token".into(), "cf-token".into());
    dns_config.insert("zone_id".into(), "zone-123".into());
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_provider: Some("cloudflare".into()),
                dns_config,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_acme_http01_tls_without_dns_hooks() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["token4aicloud.com".into()],
                email: Some("ops@token4aicloud.com".into()),
                challenge: "http-01".into(),
                http_challenge_listen: "0.0.0.0:80".into(),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_acme_http01_for_wildcard_domains() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["*.token4aicloud.com".into()],
                email: Some("ops@token4aicloud.com".into()),
                challenge: "http-01".into(),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("wildcard domains require dns-01"));
}

#[test]
fn rejects_acme_tls_mixed_with_manual_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some("cert.pem".into()),
            key_path: Some("key.pem".into()),
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_hook_set: Some("/usr/local/bin/ferrogate-dns-set".into()),
                dns_hook_cleanup: Some("/usr/local/bin/ferrogate-dns-cleanup".into()),
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.acme.enabled"));
}

#[test]
fn rejects_duplicate_api_key_id_with_field_name() {
    let config = Config {
        api_keys: vec![api_key("key_dev", "one"), api_key("key_dev", "two")],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[1].id"));
    assert!(error.contains("duplicate api key id key_dev"));
}

#[test]
fn rejects_api_key_with_unknown_allowed_model() {
    let mut key = api_key("key_dev", "Development key");
    key.allowed_models = vec!["missing-model".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].allowed_models"));
    assert!(error.contains("missing-model"));
}

#[test]
fn rejects_api_key_with_unknown_denied_model() {
    let mut key = api_key("key_dev", "Development key");
    key.denied_models = vec!["missing-model".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].denied_models"));
    assert!(error.contains("missing-model"));
}

#[test]
fn rejects_api_key_with_unknown_allowed_provider() {
    let mut key = api_key("key_dev", "Development key");
    key.allowed_providers = vec!["missing-provider".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].allowed_providers"));
    assert!(error.contains("missing-provider"));
}

#[test]
fn rejects_api_key_with_unknown_denied_provider() {
    let mut key = api_key("key_dev", "Development key");
    key.denied_providers = vec!["missing-provider".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].denied_providers"));
    assert!(error.contains("missing-provider"));
}

#[test]
fn rejects_api_key_with_unsupported_hash_format() {
    let mut key = api_key("key_dev", "Development key");
    key.key = None;
    key.key_hash = Some("sha256:not-supported".into());
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].key_hash"));
    assert!(error.contains("unsupported key hash format"));
}

#[test]
fn rejects_policy_with_unknown_references() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        policies: vec![PolicyRule {
            name: "deny missing".into(),
            effect: "deny".into(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["missing-key".into()],
            models: vec!["missing-model".into()],
            providers: vec!["missing-provider".into()],
            code: "policy_denied".into(),
            message: "blocked".into(),
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field policies[0].api_key_ids"));
    assert!(error.contains("missing-key"));
}

#[test]
fn validates_gateway_config_profiles() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        gateway_configs: vec![GatewayConfigProfile {
            id: "no-cache-agent".into(),
            name: "No-cache agent workflow".into(),
            revision: 1,
            enabled: true,
            api_key_ids: vec!["key_dev".into()],
            cache_enabled: Some(false),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_invalid_gateway_config_profiles() {
    let mut missing_behavior = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        gateway_configs: vec![GatewayConfigProfile {
            id: "empty".into(),
            name: "Empty".into(),
            revision: 1,
            enabled: true,
            api_key_ids: vec!["key_dev".into()],
            cache_enabled: None,
        }],
        ..Config::default()
    };
    let error = missing_behavior.validate().unwrap_err().to_string();
    assert!(error.contains("field gateway_configs[0]"));
    assert!(error.contains("cache_enabled"));

    missing_behavior.gateway_configs[0].cache_enabled = Some(false);
    missing_behavior.gateway_configs[0].api_key_ids = vec!["missing-key".into()];
    let error = missing_behavior.validate().unwrap_err().to_string();
    assert!(error.contains("field gateway_configs[0].api_key_ids"));
    assert!(error.contains("missing-key"));

    missing_behavior.gateway_configs.push(GatewayConfigProfile {
        id: "empty".into(),
        name: "Duplicate".into(),
        revision: 1,
        enabled: true,
        api_key_ids: vec![],
        cache_enabled: Some(false),
    });
    missing_behavior.gateway_configs[0].api_key_ids = vec![];
    let error = missing_behavior.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate gateway config id empty"));
}

#[test]
fn rejects_invalid_otlp_endpoint_with_field_name() {
    let config = Config {
        telemetry: TelemetryConfig {
            service_name: "ferrogate".into(),
            log_bodies: false,
            otlp_endpoint: Some("collector:4318".into()),
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.otlp_endpoint"));
}

#[test]
fn rejects_enabled_observability_without_otlp_endpoint() {
    let config = Config {
        observability: ObservabilityConfig {
            enabled: true,
            provider: ObservabilityProvider::Vector,
            otlp_endpoint: None,
            ..ObservabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field observability.otlp_endpoint"));
}

#[test]
fn rejects_invalid_observability_metrics_path() {
    let config = Config {
        observability: ObservabilityConfig {
            prometheus_metrics_path: "metrics".into(),
            ..ObservabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field observability.prometheus_metrics_path"));
}

#[test]
fn validates_analytics_pipeline_and_direct_warehouse_config() {
    let config = Config {
        analytics: AnalyticsConfig {
            enabled: true,
            provider: AnalyticsProvider::Vector,
            vector_endpoint: Some("http://127.0.0.1:4318/v1/logs".into()),
            ..AnalyticsConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        analytics: AnalyticsConfig {
            enabled: true,
            provider: AnalyticsProvider::Clickhouse,
            clickhouse_url_env: Some("FERROGATE_CLICKHOUSE_URL".into()),
            ..AnalyticsConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        analytics: AnalyticsConfig {
            enabled: true,
            provider: AnalyticsProvider::Vector,
            ..AnalyticsConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field analytics.vector_endpoint"));

    let config = Config {
        analytics: AnalyticsConfig {
            enabled: true,
            provider: AnalyticsProvider::Clickhouse,
            ..AnalyticsConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field analytics.clickhouse_url_env"));
}

#[test]
fn rejects_incomplete_provider_circuit_breaker_config() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(2),
            provider_circuit_breaker_cooldown_secs: None,
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_circuit_breaker_cooldown_secs"));
}

#[test]
fn rejects_zero_provider_circuit_breaker_threshold() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(0),
            provider_circuit_breaker_cooldown_secs: Some(30),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_circuit_breaker_failure_threshold"));
}

#[test]
fn rejects_zero_provider_dispatch_timeout() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_dispatch_timeout_secs: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_dispatch_timeout_secs"));
}

#[test]
fn rejects_invalid_mcp_dispatch_limits() {
    let config = Config {
        reliability: ReliabilityConfig {
            mcp_dispatch_timeout_secs: 0,
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.mcp_dispatch_timeout_secs"));

    let config = Config {
        reliability: ReliabilityConfig {
            mcp_dispatch_max_concurrency: 0,
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.mcp_dispatch_max_concurrency"));
}

#[test]
fn rejects_invalid_agent_runtime_limits() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            max_turns: 0,
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field agent_runtime.max_turns"));

    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            timeout_millis: 0,
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field agent_runtime.timeout_millis"));

    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            wasm: AgentRuntimeWasmConfig {
                max_fuel: 0,
                ..AgentRuntimeWasmConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field agent_runtime.wasm.max_fuel"));
}

#[test]
fn rejects_wasi_until_agent_runtime_host_abi_exists() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            wasm: AgentRuntimeWasmConfig {
                allow_wasi: true,
                ..AgentRuntimeWasmConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();

    assert!(error.contains("field agent_runtime.wasm.allow_wasi"));
}

#[test]
fn accepts_agent_runtime_opt_in_config() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            max_turns: 3,
            timeout_millis: 5_000,
            wasm: AgentRuntimeWasmConfig {
                max_fuel: 500_000,
                allow_wasi: false,
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_zero_provider_response_body_max_bytes() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_response_body_max_bytes: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_response_body_max_bytes"));
}

#[test]
fn rejects_zero_graceful_shutdown_settings() {
    let config = Config {
        reliability: ReliabilityConfig {
            graceful_shutdown_grace_period_secs: Some(0),
            graceful_shutdown_timeout_secs: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_shutdown_grace_period_secs"));
}

#[test]
fn rejects_invalid_graceful_upgrade_settings() {
    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some(" ".into()),
            graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
            graceful_upgrade_sock_retries: Some(5),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_pid_file"));

    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
            graceful_upgrade_sock: Some(" ".into()),
            graceful_upgrade_sock_retries: Some(5),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_sock"));

    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
            graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
            graceful_upgrade_sock_retries: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_sock_retries"));
}

#[test]
fn rejects_zero_access_log_sample_rate() {
    let config = Config {
        telemetry: TelemetryConfig {
            access_log: AccessLogMode::Sampled,
            access_log_sample_rate: 0,
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.access_log_sample_rate"));
}

#[test]
fn rejects_zero_access_log_error_rate_limit() {
    let config = Config {
        telemetry: TelemetryConfig {
            access_log_error_rate_limit_per_sec: 0,
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.access_log_error_rate_limit_per_sec"));
}

#[test]
fn rejects_route_path_prefix_without_leading_slash() {
    let config = Config {
        upstreams: vec![upstream()],
        routes: vec![route("backend", vec!["api"])],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field routes[0].path_prefixes"));
}

#[test]
fn rejects_invalid_request_header_name_with_route_context() {
    let mut route = route("backend", vec!["/api"]);
    route.request_headers = vec![HeaderMutation {
        name: "bad header".into(),
        value: "value".into(),
    }];
    let config = Config {
        upstreams: vec![upstream()],
        routes: vec![route],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field routes[0].request_headers[0].name"));
    assert!(error.contains("invalid header name"));
}

#[test]
fn rejects_invalid_analytics_retention_and_storage_admin_list_limits() {
    let config = Config {
        analytics: crate::config::AnalyticsConfig {
            request_log_retention_records: 0,
            ..crate::config::AnalyticsConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field analytics.request_log_retention_records"));

    let config = Config {
        storage: StorageConfig {
            admin_list_default_limit: 200,
            admin_list_max_limit: 100,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.admin_list_default_limit"));
}

#[test]
fn validates_storage_provider_contract_order_and_fail_closed_provider_selection() {
    let config = Config::default();
    config.validate().unwrap();
    assert_eq!(
        config.storage.provider_order,
        vec![
            ferrogate_storage::StorageProviderKind::TursoLibsql,
            ferrogate_storage::StorageProviderKind::Postgres,
            ferrogate_storage::StorageProviderKind::Mysql,
        ]
    );

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::TursoLibsql,
            required: true,
            libsql_url: Some("libsql://example.turso.io".into()),
            libsql_auth_token: Some("test-token".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn: Some(
                "host=127.0.0.1 port=5432 user=postgres dbname=ferrogate sslmode=disable".into(),
            ),
            postgres_pool_size: 2,
            postgres_tls_mode: ferrogate_storage::PostgresTlsMode::Prefer,
            postgres_connect_timeout_secs: 5,
            postgres_statement_timeout_millis: 5_000,
            postgres_schema: Some("ferrogate_control".into()),
            postgres_search_path: vec!["public".into()],
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            mysql_dsn: Some(
                "mysql://root:mysql@127.0.0.1:3306/ferrogate?prefer_socket=false".into(),
            ),
            mysql_pool_size: 2,
            mysql_tls_mode: ferrogate_storage::MySqlTlsMode::VerifyCa,
            mysql_tls_ca_cert_path: Some("/tmp/ferrogate-mysql-ca.pem".into()),
            mysql_connect_timeout_secs: 5,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            mysql_dsn_env: Some("FERROGATE_MYSQL_DSN".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.mysql_dsn_env"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            mysql_dsn_env: Some("FERROGATE_MYSQL_DSN".into()),
            mysql_pool_size: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.mysql_pool_size"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            mysql_dsn_env: Some("FERROGATE_MYSQL_DSN".into()),
            mysql_tls_ca_cert_path: Some(" ".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.mysql_tls_ca_cert_path"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            mysql_dsn_env: Some("FERROGATE_MYSQL_DSN".into()),
            mysql_connect_timeout_secs: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.mysql_connect_timeout_secs"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_dsn_env"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            postgres_pool_size: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_pool_size"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            postgres_connect_timeout_secs: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_connect_timeout_secs"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            postgres_statement_timeout_millis: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_statement_timeout_millis"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            postgres_tls_ca_cert_path: Some(" ".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_tls_ca_cert_path"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Postgres,
            required: true,
            postgres_dsn_env: Some("FERROGATE_POSTGRES_DSN".into()),
            postgres_schema: Some("bad-schema".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_schema"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::TursoLibsql,
            required: true,
            libsql_url: Some("file:///tmp/ferrogate-control-plane.db".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    config.validate().unwrap();

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::TursoLibsql,
            required: true,
            libsql_url: Some("libsql://example.turso.io".into()),
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.libsql_auth_token_env"));

    let config = Config {
        storage: StorageConfig {
            required: true,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.required"));

    let config = Config {
        storage: StorageConfig {
            provider_order: vec![
                ferrogate_storage::StorageProviderKind::Postgres,
                ferrogate_storage::StorageProviderKind::TursoLibsql,
            ],
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("storage.provider_order[0]"));
}

#[test]
fn rejects_invalid_ai_cache_limits() {
    let config = Config {
        cache: CacheConfig {
            enabled: true,
            ttl_secs: 0,
            ..CacheConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cache.ttl_secs"));

    let config = Config {
        cache: CacheConfig {
            enabled: true,
            max_records: 0,
            ..CacheConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cache.max_records"));
}

#[test]
fn accepts_enabled_local_cluster_identity_config() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "auto".into(),
            node_region: Some("us-east-1".into()),
            node_zone: Some("us-east-1a".into()),
            state_backend: "local".into(),
            file_state_path: None,
            counter_backend: "local".into(),
            redis_url: None,
            counter_timeout_millis: 500,
            heartbeat_interval_secs: 10,
            config_poll_interval_secs: 5,
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_file_cluster_state_backend_with_path() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            state_backend: "file".into(),
            file_state_path: Some("/var/lib/ferrogate/cluster-state.json".into()),
            counter_backend: "local".into(),
            redis_url: None,
            counter_timeout_millis: 500,
            heartbeat_interval_secs: 10,
            config_poll_interval_secs: 5,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_redis_cluster_counter_backend_with_url() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            counter_backend: "redis".into(),
            redis_url: Some("redis://redis:6379/0".into()),
            counter_timeout_millis: 250,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_redis_cluster_counter_backend_without_url() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            counter_backend: "redis".into(),
            redis_url: None,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.redis_url"));
}

#[test]
fn rejects_invalid_enabled_cluster_config() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: String::new(),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.cluster_id"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            state_backend: "postgres".into(),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.state_backend"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            state_backend: "file".into(),
            file_state_path: None,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.file_state_path"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            heartbeat_interval_secs: 0,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.heartbeat_interval_secs"));
}

#[test]
fn validates_mcp_server_config_shape() {
    let mut missing_allowlist = mcp_server();
    missing_allowlist.tools_to_execute = vec![];
    let config = Config {
        mcp_servers: vec![missing_allowlist],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("tools_to_execute"), "{error}");

    let mut duplicate = mcp_server();
    duplicate.url = Some("http://127.0.0.1:9001/mcp".into());
    let config = Config {
        mcp_servers: vec![mcp_server(), duplicate],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate MCP server name"), "{error}");

    let mut stdio = mcp_server();
    stdio.name = "local".into();
    stdio.transport = McpTransport::Stdio;
    stdio.url = None;
    stdio.command = None;
    let config = Config {
        mcp_servers: vec![stdio],
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("requires command"), "{error}");
}

#[test]
fn accepts_mcp_policy_targets() {
    let mut key = api_key("blocked", "Blocked");
    key.scopes = vec!["tools.execute".into()];
    let config = Config {
        api_keys: vec![key],
        mcp_servers: vec![mcp_server()],
        policies: vec![PolicyRule {
            name: "deny github search".into(),
            effect: "deny".into(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["blocked".into()],
            models: vec!["mcp_tool:github-search".into()],
            providers: vec!["mcp:github".into()],
            code: "mcp_denied".into(),
            message: "blocked".into(),
            enabled: true,
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

fn upstream() -> Upstream {
    Upstream {
        name: "backend".into(),
        url: Some("http://127.0.0.1:8081".into()),
        urls: vec![],
        enabled: true,
    }
}

fn provider() -> Provider {
    Provider {
        name: "openai".into(),
        kind: "openai".into(),
        base_url: "http://127.0.0.1:8081/v1".into(),
        api_key_env: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        enabled: true,
    }
}

fn model() -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        routing_strategy: RoutingStrategy::Priority,
        fallbacks: vec![],
        visible_organization_ids: vec![],
        visible_project_ids: vec![],
        capabilities: vec![],
        context_window: None,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
        cache_enabled: None,
    }
}

fn route(upstream: &str, prefixes: Vec<&str>) -> RouteRule {
    RouteRule {
        name: "api".into(),
        upstream: upstream.into(),
        hosts: vec![],
        path_prefixes: prefixes.into_iter().map(str::to_string).collect(),
        match_headers: vec![],
        strip_prefix: None,
        add_prefix: None,
        request_headers: vec![],
        response_headers: vec![],
        enabled: true,
    }
}

fn api_key(id: &str, name: &str) -> ApiKey {
    ApiKey {
        id: id.into(),
        name: name.into(),
        key_env: None,
        key: Some(format!("secret-{name}")),
        key_hash: None,
        enabled: true,
        scopes: vec![],
        allowed_models: vec![],
        denied_models: vec![],
        allowed_providers: vec![],
        denied_providers: vec![],
        organization_id: None,
        team_id: None,
        project_id: None,
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
        log_bodies: None,
        cache_enabled: None,
    }
}

fn extension(id: &str, kind: ExtensionKind, order: u32) -> ExtensionConfig {
    ExtensionConfig {
        id: id.into(),
        kind,
        version: "0.1.0".into(),
        manifest: PluginManifest::default(),
        compatibility: PluginCompatibility::default(),
        enabled: true,
        source: "builtin".into(),
        order,
        approval_policy: ferrogate_core::ApprovalPolicy::Never,
        permissions: ExtensionPermissions {
            tools: vec![id.into()],
            network: vec![],
            filesystem: false,
            shell: false,
            tenant_scope: false,
            secrets: false,
            admin_mutation: false,
        },
        config: std::collections::BTreeMap::new(),
    }
}

fn mcp_server() -> McpServerConfig {
    McpServerConfig {
        name: "github".into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1:9000/mcp".into()),
        command: None,
        args: vec![],
        auth_type: McpAuthType::None,
        headers: vec![],
        tools_to_execute: vec!["search".into()],
        tools_to_auto_execute: vec![],
        approval_policy: ferrogate_core::ApprovalPolicy::Never,
        tool_include: vec![],
        tool_regex: vec![],
        tls: McpTlsConfig::default(),
        timeout_ms: 1_000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    }
}
