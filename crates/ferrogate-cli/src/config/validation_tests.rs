// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;
use ferrogate_providers::RoutingStrategy;

#[test]
fn rejects_enabled_auth_service_with_non_http_endpoint() {
    let config = Config {
        auth_service: AuthServiceConfig {
            enabled: true,
            endpoint: "https://auth.example.test".into(),
            timeout_millis: 500,
            max_retries: 0,
            retry_backoff_millis: 50,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field auth_service.endpoint: must start with http://"));
}

#[test]
fn rejects_auth_service_with_zero_timeout() {
    let config = Config {
        auth_service: AuthServiceConfig {
            enabled: false,
            endpoint: "http://127.0.0.1:8090".into(),
            timeout_millis: 0,
            max_retries: 0,
            retry_backoff_millis: 50,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field auth_service.timeout_millis"));
}

#[test]
fn rejects_auth_service_retry_without_backoff() {
    let config = Config {
        auth_service: AuthServiceConfig {
            enabled: false,
            endpoint: "http://127.0.0.1:8090".into(),
            timeout_millis: 500,
            max_retries: 1,
            retry_backoff_millis: 0,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field auth_service.retry_backoff_millis"));
}

#[test]
fn rejects_model_with_unknown_provider() {
    let config = Config {
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "missing".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            canary: None,
            shadow: None,
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
fn rejects_canary_with_unknown_provider() {
    let mut model = model();
    model.canary = Some(CanaryRoute {
        provider: "missing".into(),
        provider_model: "gpt-4o".into(),
        percent: 10,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
    });
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("unknown canary provider"));
}

#[test]
fn rejects_canary_percent_above_one_hundred() {
    let mut model = model();
    model.canary = Some(CanaryRoute {
        provider: "openai".into(),
        provider_model: "gpt-4o".into(),
        percent: 150,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
    });
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("canary.percent"));
}

#[test]
fn accepts_valid_canary_and_shadow_targets() {
    let mut model = model();
    model.canary = Some(CanaryRoute {
        provider: "openai".into(),
        provider_model: "gpt-4o".into(),
        percent: 10,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
    });
    model.shadow = Some(ShadowRoute {
        provider: "openai".into(),
        provider_model: "gpt-4o".into(),
        sample_percent: 5,
        max_requests: 100,
        enabled: true,
    });
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    config.validate().expect("valid canary + shadow config");
}

#[test]
fn rejects_shadow_with_unknown_provider() {
    let mut model = model();
    model.shadow = Some(ShadowRoute {
        provider: "missing".into(),
        provider_model: "gpt-4o".into(),
        sample_percent: 5,
        max_requests: 0,
        enabled: true,
    });
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("unknown shadow provider"));
}

#[test]
fn accepts_provider_with_env_secret_ref() {
    let mut provider = provider();
    provider.secret_ref = Some("env://OPENAI_API_KEY".into());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_empty_provider_region() {
    let mut provider = provider();
    provider.region = Some(String::new());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].region: cannot be empty"));
}

#[test]
fn accepts_provider_with_declared_region() {
    let mut provider = provider();
    provider.region = Some("eu-west-1".into());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    config.validate().unwrap();
}

fn bedrock_provider() -> Provider {
    Provider {
        kind: "bedrock".into(),
        aws_access_key_id: Some("AKIDEXAMPLE".into()),
        aws_secret_access_key_env: Some("BEDROCK_SECRET_KEY".into()),
        region: Some("us-east-1".into()),
        ..provider()
    }
}

#[test]
fn accepts_a_fully_configured_bedrock_provider() {
    let config = Config {
        providers: vec![bedrock_provider()],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_bedrock_provider_missing_aws_access_key_id() {
    let mut provider = bedrock_provider();
    provider.aws_access_key_id = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].aws_access_key_id: required when kind = bedrock"));
}

#[test]
fn rejects_bedrock_provider_missing_aws_secret_access_key_env() {
    let mut provider = bedrock_provider();
    provider.aws_secret_access_key_env = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error
        .contains("field providers[0].aws_secret_access_key_env: required when kind = bedrock"));
}

#[test]
fn rejects_bedrock_provider_missing_region() {
    let mut provider = bedrock_provider();
    provider.region = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].region: required when kind = bedrock"));
}

#[test]
fn rejects_empty_aws_secret_access_key_env() {
    let mut provider = bedrock_provider();
    provider.aws_secret_access_key_env = Some(String::new());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].aws_secret_access_key_env: cannot be empty"));
}

#[test]
fn a_non_bedrock_provider_does_not_require_aws_credentials() {
    let config = Config {
        providers: vec![provider()],
        ..Config::default()
    };

    config.validate().unwrap();
}

fn vertex_provider() -> Provider {
    Provider {
        kind: "vertex".into(),
        gcp_project_id: Some("my-gcp-project".into()),
        gcp_access_token_env: Some("VERTEX_ACCESS_TOKEN".into()),
        region: Some("us-central1".into()),
        ..provider()
    }
}

#[test]
fn accepts_a_fully_configured_vertex_provider() {
    let config = Config {
        providers: vec![vertex_provider()],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_vertex_provider_missing_gcp_project_id() {
    let mut provider = vertex_provider();
    provider.gcp_project_id = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].gcp_project_id: required when kind = vertex"));
}

#[test]
fn rejects_vertex_provider_missing_gcp_access_token_env() {
    let mut provider = vertex_provider();
    provider.gcp_access_token_env = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].gcp_access_token_env: required when kind = vertex"));
}

#[test]
fn rejects_vertex_provider_missing_region() {
    let mut provider = vertex_provider();
    provider.region = None;
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].region: required when kind = vertex"));
}

#[test]
fn rejects_empty_gcp_access_token_env() {
    let mut provider = vertex_provider();
    provider.gcp_access_token_env = Some(String::new());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].gcp_access_token_env: cannot be empty"));
}

#[test]
fn a_non_vertex_provider_does_not_require_gcp_credentials() {
    let config = Config {
        providers: vec![provider()],
        ..Config::default()
    };

    config.validate().unwrap();
}

fn enabled_asset_bucket() -> AssetBucketConfig {
    AssetBucketConfig {
        enabled: true,
        endpoint: Some("https://project.supabase.co/storage/v1/s3".into()),
        bucket: Some("ferrogate-assets".into()),
        region: Some("us-east-1".into()),
        access_key_id: Some("AKIDEXAMPLE".into()),
        secret_access_key_env: Some("FERROGATE_ASSET_BUCKET_SECRET".into()),
        ..AssetBucketConfig::default()
    }
}

#[test]
fn accepts_a_fully_configured_asset_bucket() {
    let config = Config {
        asset_bucket: enabled_asset_bucket(),
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn asset_bucket_disabled_by_default_requires_nothing() {
    assert!(!Config::default().asset_bucket.enabled);
    Config::default().validate().unwrap();
}

#[test]
fn rejects_enabled_asset_bucket_missing_endpoint() {
    let mut asset_bucket = enabled_asset_bucket();
    asset_bucket.endpoint = None;
    let config = Config {
        asset_bucket,
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field asset_bucket.endpoint: required when asset_bucket.enabled = true")
    );
}

#[test]
fn rejects_enabled_asset_bucket_missing_secret_access_key_env() {
    let mut asset_bucket = enabled_asset_bucket();
    asset_bucket.secret_access_key_env = None;
    let config = Config {
        asset_bucket,
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains(
        "field asset_bucket.secret_access_key_env: required when asset_bucket.enabled = true"
    ));
}

#[test]
fn rejects_empty_asset_bucket_bucket() {
    let mut asset_bucket = enabled_asset_bucket();
    asset_bucket.bucket = Some(String::new());
    let config = Config {
        asset_bucket,
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field asset_bucket.bucket: cannot be empty"));
}

#[test]
fn rejects_api_key_region_allowlist_entry_with_no_matching_provider() {
    let mut provider = provider();
    provider.region = Some("eu-west-1".into());
    let mut key = api_key("tenant-key", "Tenant Key");
    key.region_allowlist = vec!["us-east-1".into()];
    let config = Config {
        providers: vec![provider],
        api_keys: vec![key],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("region_allowlist"));
    assert!(error.contains("us-east-1"));
}

#[test]
fn rejects_empty_api_key_region_allowlist_entry() {
    let mut key = api_key("tenant-key", "Tenant Key");
    key.region_allowlist = vec![String::new()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field api_keys[0].region_allowlist: cannot contain an empty value"));
}

#[test]
fn accepts_api_key_region_allowlist_matching_a_declared_provider_region() {
    let mut provider = provider();
    provider.region = Some("eu-west-1".into());
    let mut key = api_key("tenant-key", "Tenant Key");
    key.region_allowlist = vec!["eu-west-1".into()];
    let config = Config {
        providers: vec![provider],
        api_keys: vec![key],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_provider_with_vault_secret_ref() {
    let mut provider = provider();
    provider.secret_ref = Some("vault://secret/data/openai#api_key".into());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_provider_secret_ref_with_unsupported_scheme() {
    let mut provider = provider();
    provider.secret_ref = Some("aws-sm://openai/api-key".into());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].secret_ref"));
    assert!(error.contains("env:// or vault://"));
}

#[test]
fn rejects_provider_vault_secret_ref_missing_field() {
    let mut provider = provider();
    provider.secret_ref = Some("vault://secret/data/openai".into());
    let config = Config {
        providers: vec![provider],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field providers[0].secret_ref"));
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
fn accepts_model_without_prices_when_billing_service_disabled() {
    // billing_service defaults to disabled, so a priceless model is fine —
    // matches every other test in this file that uses the bare model().
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_model_without_prices_when_billing_service_enabled() {
    // Issue #146: a model with no gateway-side price settles cost_usd = None,
    // so its real spend never counts against the monthly budget even though
    // the standalone billing service (its own, separately-configured rate
    // card) may still price and record it in the ledger. Fail closed here
    // instead of letting the two systems silently diverge at runtime.
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        billing_service: crate::config::BillingServiceConfig {
            enabled: true,
            ..crate::config::BillingServiceConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error
        .contains("billing_service.enabled requires input_price_per_1m and output_price_per_1m"));
}

#[test]
fn rejects_fallback_route_without_prices_when_billing_service_enabled() {
    let mut model = model();
    model.input_price_per_1m = Some(1.0);
    model.output_price_per_1m = Some(2.0);
    model.fallbacks.push(ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4o".into(),
        input_price_per_1m: None,
        output_price_per_1m: None,
        priority: Some(0),
        weight: Some(1),
        enabled: true,
    });
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        billing_service: crate::config::BillingServiceConfig {
            enabled: true,
            ..crate::config::BillingServiceConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains(
        "fallbacks[0]: billing_service.enabled requires input_price_per_1m and output_price_per_1m"
    ));
}

#[test]
fn accepts_agent_workflow_policy_with_model_graph() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("client", "client")],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "support-flow".into(),
            name: "Support flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["client".into()],
            nodes: vec![
                AgentWorkflowNode {
                    id: "draft".into(),
                    kind: AgentWorkflowNodeKind::Model,
                    model: Some("fast-chat".into()),
                    providers: vec!["openai".into()],
                    tool: None,
                    max_iterations: Some(2),
                    token_budget: Some(600),
                },
                AgentWorkflowNode {
                    id: "review".into(),
                    kind: AgentWorkflowNodeKind::Human,
                    model: None,
                    providers: vec![],
                    tool: None,
                    max_iterations: None,
                    token_budget: None,
                },
            ],
            edges: vec![AgentWorkflowEdge {
                from: "draft".into(),
                to: "review".into(),
                condition: Some("ok".into()),
            }],
            max_model_calls: Some(1),
            max_tool_calls: Some(1),
            max_parallelism: Some(1),
            max_iterations: Some(2),
            timeout_millis: Some(1_000),
            token_budget: Some(600),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_agent_workflow_with_unknown_model_api_key_and_bad_budget() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("client", "client")],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "support-flow".into(),
            name: "Support flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["missing-client".into()],
            nodes: vec![AgentWorkflowNode {
                id: "draft".into(),
                kind: AgentWorkflowNodeKind::Model,
                model: Some("missing-chat".into()),
                providers: vec![],
                tool: None,
                max_iterations: None,
                token_budget: None,
            }],
            edges: vec![],
            max_model_calls: Some(0),
            max_tool_calls: None,
            max_parallelism: None,
            max_iterations: None,
            timeout_millis: None,
            token_budget: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("references unknown api key missing-client"));

    let mut config = config;
    config.agent_workflows[0].api_key_ids = vec!["client".into()];
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field agent_workflows[0].max_model_calls"));

    config.agent_workflows[0].max_model_calls = Some(1);
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("references unknown model missing-chat"));
}

#[test]
fn rejects_agent_workflow_with_bad_graph_references() {
    let base_workflow = AgentWorkflowPolicy {
        id: "support-flow".into(),
        name: "Support flow".into(),
        version: 1,
        enabled: true,
        organization_ids: vec![],
        project_ids: vec![],
        api_key_ids: vec![],
        nodes: vec![AgentWorkflowNode {
            id: "draft".into(),
            kind: AgentWorkflowNodeKind::Model,
            model: Some("fast-chat".into()),
            providers: vec![],
            tool: None,
            max_iterations: None,
            token_budget: None,
        }],
        edges: vec![AgentWorkflowEdge {
            from: "draft".into(),
            to: "missing".into(),
            condition: None,
        }],
        max_model_calls: None,
        max_tool_calls: None,
        max_parallelism: None,
        max_iterations: None,
        timeout_millis: None,
        token_budget: None,
    };
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        agent_workflows: vec![base_workflow],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("edges[0].to: unknown node missing"));

    let mut config = config;
    config.agent_workflows[0].edges.clear();
    config.agent_workflows[0].nodes.push(AgentWorkflowNode {
        id: "draft".into(),
        kind: AgentWorkflowNodeKind::Tool,
        model: None,
        providers: vec![],
        tool: Some("tool.echo".into()),
        max_iterations: None,
        token_budget: None,
    });
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("duplicate node id draft"));
}

#[test]
fn accepts_agent_workflow_tool_nodes_with_registered_tools() {
    let config = Config {
        plugins: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        mcp_servers: vec![mcp_server()],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "tool-flow".into(),
            name: "Tool flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            nodes: vec![
                AgentWorkflowNode {
                    id: "echo".into(),
                    kind: AgentWorkflowNodeKind::Tool,
                    model: None,
                    providers: vec![],
                    tool: Some("tool.echo".into()),
                    max_iterations: Some(2),
                    token_budget: None,
                },
                AgentWorkflowNode {
                    id: "search".into(),
                    kind: AgentWorkflowNodeKind::Tool,
                    model: None,
                    providers: vec![],
                    tool: Some("github-search".into()),
                    max_iterations: None,
                    token_budget: None,
                },
            ],
            edges: vec![],
            max_model_calls: None,
            max_tool_calls: Some(2),
            max_parallelism: Some(1),
            max_iterations: Some(3),
            timeout_millis: Some(1_000),
            token_budget: None,
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_agent_workflow_tool_node_with_unknown_tool() {
    let config = Config {
        plugins: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "tool-flow".into(),
            name: "Tool flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            nodes: vec![AgentWorkflowNode {
                id: "missing".into(),
                kind: AgentWorkflowNodeKind::Tool,
                model: None,
                providers: vec![],
                tool: Some("tool.missing".into()),
                max_iterations: None,
                token_budget: None,
            }],
            edges: vec![],
            max_model_calls: None,
            max_tool_calls: Some(1),
            max_parallelism: None,
            max_iterations: None,
            timeout_millis: None,
            token_budget: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("references unknown tool tool.missing"));
}

#[test]
fn rejects_agent_workflow_non_tool_node_declaring_tool() {
    let config = Config {
        plugins: vec![extension("tool.echo", ExtensionKind::ToolProvider, 10)],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "bad-flow".into(),
            name: "Bad flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            nodes: vec![AgentWorkflowNode {
                id: "draft".into(),
                kind: AgentWorkflowNodeKind::Model,
                model: None,
                providers: vec![],
                tool: Some("tool.echo".into()),
                max_iterations: None,
                token_budget: None,
            }],
            edges: vec![],
            max_model_calls: None,
            max_tool_calls: None,
            max_parallelism: None,
            max_iterations: None,
            timeout_millis: None,
            token_budget: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("only tool nodes may declare a tool"));
}

#[test]
fn rejects_agent_workflow_model_node_with_unknown_provider() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "bad-provider-flow".into(),
            name: "Bad provider flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            nodes: vec![AgentWorkflowNode {
                id: "draft".into(),
                kind: AgentWorkflowNodeKind::Model,
                model: Some("fast-chat".into()),
                providers: vec!["missing-provider".into()],
                tool: None,
                max_iterations: None,
                token_budget: None,
            }],
            edges: vec![],
            max_model_calls: None,
            max_tool_calls: None,
            max_parallelism: None,
            max_iterations: None,
            timeout_millis: None,
            token_budget: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("references unknown provider missing-provider"));
}

#[test]
fn rejects_agent_workflow_non_model_node_declaring_provider() {
    let config = Config {
        providers: vec![provider()],
        agent_workflows: vec![AgentWorkflowPolicy {
            id: "bad-provider-flow".into(),
            name: "Bad provider flow".into(),
            version: 1,
            enabled: true,
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            nodes: vec![AgentWorkflowNode {
                id: "review".into(),
                kind: AgentWorkflowNodeKind::Human,
                model: None,
                providers: vec!["openai".into()],
                tool: None,
                max_iterations: None,
                token_budget: None,
            }],
            edges: vec![],
            max_model_calls: None,
            max_tool_calls: None,
            max_parallelism: None,
            max_iterations: None,
            timeout_millis: None,
            token_budget: None,
        }],
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("only model nodes may declare providers"));
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec!["org_demo".into()],
            project_ids: vec!["project_demo".into()],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec!["org_demo".into()],
            project_ids: vec!["project_demo".into()],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
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
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec!["key_dev".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec![],
                regex: vec![r"ABC-[0-9]+".into()],
                max_input_bytes: None,
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_language: None,
                provider_score_threshold_percent: None,
                provider_entities: None,
                provider_fingerprint_secret_ref: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: GuardrailEffect::Deny,
                code: "guardrail_regex_blocked".into(),
                message: "blocked by regex guardrail".into(),
            },
            GuardrailRule {
                id: "max-input".into(),
                name: "Max input".into(),
                enabled: true,
                stage: GuardrailStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec!["key_dev".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec![],
                regex: vec![],
                max_input_bytes: Some(1024),
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_language: None,
                provider_score_threshold_percent: None,
                provider_entities: None,
                provider_fingerprint_secret_ref: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec![],
            regex: vec!["[".into()],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec![],
            regex: vec![],
            max_input_bytes: Some(1024),
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
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
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["key_dev".into()],
            models: vec!["missing-model".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_language: None,
            provider_score_threshold_percent: None,
            provider_entities: None,
            provider_fingerprint_secret_ref: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: GuardrailEffect::Deny,
            code: "guardrail_blocked".into(),
            message: "blocked by guardrail".into(),
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown model missing-model"));
}

fn custom_http_guardrail() -> GuardrailRule {
    GuardrailRule {
        id: "pii-detector".into(),
        name: "External PII detector".into(),
        enabled: true,
        stage: GuardrailStage::Request,
        sources: ferrogate_guardrails::all_content_sources(),
        organization_ids: vec![],
        project_ids: vec![],
        api_key_ids: vec![],
        models: vec![],
        providers: vec![],
        keywords: vec![],
        regex: vec![],
        max_input_bytes: None,
        provider: GuardrailProviderKind::CustomHttp,
        provider_endpoint: Some("https://guardrails.example.test/check".into()),
        provider_language: None,
        provider_score_threshold_percent: None,
        provider_entities: None,
        provider_fingerprint_secret_ref: None,
        provider_timeout_ms: 2_000,
        provider_runtime: Default::default(),
        effect: GuardrailEffect::Deny,
        code: "guardrail_pii_detected".into(),
        message: "blocked by external PII detector".into(),
    }
}

#[test]
fn accepts_guardrail_with_custom_http_provider_only() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![custom_http_guardrail()],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_guardrail_without_declared_content_sources() {
    let mut guardrail = custom_http_guardrail();
    guardrail.sources.clear();
    let config = Config {
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("guardrails[0].sources"));
}

#[test]
fn rejects_custom_http_guardrail_without_endpoint() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_endpoint = None;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("required when provider is custom_http"));
}

#[test]
fn rejects_custom_http_guardrail_with_invalid_endpoint_scheme() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_endpoint = Some("ftp://guardrails.example.test/check".into());
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must be an http(s) URL"));
}

#[test]
fn rejects_private_custom_http_guardrail_endpoint_without_explicit_opt_in() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_endpoint = Some("http://127.0.0.1:8080/check".into());
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("requires explicit allow_private_network"));
}

#[test]
fn accepts_private_custom_http_guardrail_endpoint_with_explicit_opt_in() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_endpoint = Some("http://127.0.0.1:8080/check".into());
    guardrail.provider_runtime.provider_allow_private_network = true;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_custom_http_guardrail_fallback_mode_without_local_detector() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_runtime.provider_on_error = GuardrailProviderErrorMode::FallbackDetector;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("fallback_detector requires a keyword, regex, or max_input_bytes"));
}

#[test]
fn rejects_invalid_custom_http_guardrail_runtime_limits() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_runtime.provider_max_concurrency = 0;
    let mut config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider_max_concurrency"));

    config.guardrails[0]
        .provider_runtime
        .provider_max_concurrency = 1;
    config.guardrails[0].provider_runtime.provider_max_retries = 2;
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider_max_retries"));
}

#[test]
fn rejects_invalid_custom_http_guardrail_secret_reference() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_runtime.provider_secret_ref = Some("aws-sm://detector".into());
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("provider_secret_ref"));
    assert!(error.contains("env:// or vault://"));
}

#[test]
fn rejects_guardrail_provider_endpoint_when_provider_is_none() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider = GuardrailProviderKind::None;
    guardrail.keywords = vec!["secret".into()];
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("only valid when provider is custom_http"));
}

#[test]
fn rejects_guardrail_with_zero_provider_timeout() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_timeout_ms = 0;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("provider_timeout_ms: must be greater than zero"));
}

#[test]
fn rejects_guardrail_provider_timeout_above_runtime_ceiling() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider_timeout_ms = 30_001;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must not exceed 30000 milliseconds"));
}

#[test]
fn rejects_guardrail_with_no_detection_mechanism_and_no_provider() {
    let mut guardrail = custom_http_guardrail();
    guardrail.provider = GuardrailProviderKind::None;
    guardrail.provider_endpoint = None;
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        guardrails: vec![guardrail],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("at least one keyword, regex, max_input_bytes, or provider is required"));
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
            cors_allowed_origin: None,
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
}

#[test]
fn accepts_agent_runtime_opt_in_config() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            max_turns: 3,
            timeout_millis: 5_000,
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_invalid_managed_worker_authorizer_socket_config() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                external_action_authorizer_http_listen: Some("127.0.0.1:7778".into()),
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("field agent_runtime.managed_worker.external_action_authorizer_http_listen")
            && error.contains("insecure plaintext")
    );

    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                external_action_authorizer_socket: Some(" ".into()),
                external_action_authorizer_max_requests: None,
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field agent_runtime.managed_worker.external_action_authorizer_socket"));

    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                external_action_authorizer_socket: Some("/tmp/ferrogate.sock".into()),
                external_action_authorizer_max_requests: Some(0),
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error
        .contains("field agent_runtime.managed_worker.external_action_authorizer_max_requests"));

    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                allowed_actions: vec![
                    crate::config::ManagedWorkerCapabilityActionConfig::Tool,
                    crate::config::ManagedWorkerCapabilityActionConfig::Tool,
                ],
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field agent_runtime.managed_worker.allowed_actions"));
}

#[test]
fn rejects_external_agent_runtime_without_command() {
    let config = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            provider: AgentRuntimeProvider::External,
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();

    assert!(error.contains("field agent_runtime.external.command"));
}

#[test]
fn rejects_incompatible_or_duplicate_managed_worker_target_selectors() {
    let implicit_legacy = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                allowed_actions: vec![
                    crate::config::ManagedWorkerCapabilityActionConfig::Filesystem,
                ],
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    assert!(implicit_legacy
        .validate()
        .unwrap_err()
        .to_string()
        .contains("explicit legacy_class_wide migration mode"));

    let incompatible = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                target_grants: vec![crate::config::ManagedWorkerCapabilityTargetGrantConfig {
                    selector_id: "wrong-kind".into(),
                    permission_key: "managed_actions.crm.lookup".into(),
                    action: crate::config::ManagedWorkerCapabilityActionConfig::Cli,
                    selector: ferrogate_runtime::CapabilityTargetSelector::Secret {
                        reference_namespace: "vault".into(),
                        reference_name: "provider-key".into(),
                        destination_adapter: "codex".into(),
                        destination_action: "provider.call".into(),
                    },
                }],
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    assert!(incompatible
        .validate()
        .unwrap_err()
        .to_string()
        .contains("incompatible with action cli"));

    let grant = crate::config::ManagedWorkerCapabilityTargetGrantConfig {
        selector_id: "duplicate".into(),
        permission_key: "managed_actions.provider.secret".into(),
        action: crate::config::ManagedWorkerCapabilityActionConfig::Secret,
        selector: ferrogate_runtime::CapabilityTargetSelector::Secret {
            reference_namespace: "vault".into(),
            reference_name: "provider-key".into(),
            destination_adapter: "codex".into(),
            destination_action: "provider.call".into(),
        },
    };
    let duplicate = Config {
        agent_runtime: AgentRuntimeConfig {
            enabled: true,
            managed_worker: crate::config::AgentRuntimeManagedWorkerConfig {
                target_grants: vec![grant.clone(), grant],
                ..crate::config::AgentRuntimeManagedWorkerConfig::default()
            },
            ..AgentRuntimeConfig::default()
        },
        ..Config::default()
    };
    assert!(duplicate
        .validate()
        .unwrap_err()
        .to_string()
        .contains("duplicate selector_id duplicate"));
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

/// #312: `[limits]` knobs reject zero -- a zero cap would reject every
/// request carrying a body.
#[test]
fn rejects_zero_limits_body_caps() {
    type KnobSelector = fn(&mut LimitsConfig) -> &mut Option<usize>;
    let knobs: [(&str, KnobSelector); 9] = [
        ("limits.inference_body_max_bytes", |limits| {
            &mut limits.inference_body_max_bytes
        }),
        ("limits.admin_body_max_bytes", |limits| {
            &mut limits.admin_body_max_bytes
        }),
        ("limits.admin_small_body_max_bytes", |limits| {
            &mut limits.admin_small_body_max_bytes
        }),
        ("limits.admin_config_body_max_bytes", |limits| {
            &mut limits.admin_config_body_max_bytes
        }),
        ("limits.tool_body_max_bytes", |limits| {
            &mut limits.tool_body_max_bytes
        }),
        ("limits.asset_control_body_max_bytes", |limits| {
            &mut limits.asset_control_body_max_bytes
        }),
        ("limits.agent_ingress_body_max_bytes", |limits| {
            &mut limits.agent_ingress_body_max_bytes
        }),
        ("limits.worker_transport_body_max_bytes", |limits| {
            &mut limits.worker_transport_body_max_bytes
        }),
        ("limits.guardrail_policy_body_max_bytes", |limits| {
            &mut limits.guardrail_policy_body_max_bytes
        }),
    ];
    for (field, select) in knobs {
        let mut limits = LimitsConfig::default();
        *select(&mut limits) = Some(0);
        let config = Config {
            limits,
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(&format!("field {field}: must be greater than zero")),
            "unexpected error for {field}: {error}"
        );
    }
}

/// #312: `[limits]` knobs reject absurd values (above 1 GiB) because the
/// gateway buffers request bodies in memory.
#[test]
fn rejects_absurd_limits_body_caps() {
    let config = Config {
        limits: LimitsConfig {
            inference_body_max_bytes: Some(2 * 1024 * 1024 * 1024),
            ..LimitsConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("field limits.inference_body_max_bytes: must not exceed"),
        "unexpected error: {error}"
    );
}

/// #312: defaults mirror the pre-centralization literals so an absent
/// `[limits]` section leaves behavior unchanged, and an explicit value
/// overrides the default.
#[test]
fn limits_body_caps_resolve_documented_defaults() {
    let limits = LimitsConfig::default();
    assert_eq!(limits.inference_body_max_bytes(), 1024 * 1024);
    assert_eq!(limits.admin_body_max_bytes(), 64 * 1024);
    assert_eq!(limits.admin_small_body_max_bytes(), 16 * 1024);
    assert_eq!(limits.admin_config_body_max_bytes(), 256 * 1024);
    assert_eq!(limits.tool_body_max_bytes(), 64 * 1024);
    assert_eq!(limits.asset_control_body_max_bytes(), 64 * 1024);
    assert_eq!(limits.agent_ingress_body_max_bytes(), 128 * 1024);
    assert_eq!(limits.worker_transport_body_max_bytes(), 1024 * 1024);
    assert_eq!(limits.guardrail_policy_body_max_bytes(), 1024 * 1024);

    let overridden = LimitsConfig {
        inference_body_max_bytes: Some(4 * 1024 * 1024),
        ..LimitsConfig::default()
    };
    assert_eq!(overridden.inference_body_max_bytes(), 4 * 1024 * 1024);
    let config = Config {
        limits: overridden,
        ..Config::default()
    };
    config.validate().expect("in-range override must validate");
}

/// #312: the `[limits]` TOML section wires into `Config.limits`; unset
/// knobs keep their documented defaults.
#[test]
fn limits_section_deserializes_from_toml() {
    let config = Config::from_toml_str(
        r#"
[limits]
inference_body_max_bytes = 2097152
admin_body_max_bytes = 131072
"#,
    )
    .expect("limits section must parse and validate");
    assert_eq!(config.limits.inference_body_max_bytes(), 2 * 1024 * 1024);
    assert_eq!(config.limits.admin_body_max_bytes(), 128 * 1024);
    assert_eq!(config.limits.admin_small_body_max_bytes(), 16 * 1024);
    assert_eq!(config.limits.worker_transport_body_max_bytes(), 1024 * 1024);
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
        analytics: crate::config::AnalyticsConfig {
            guardrail_evaluation_retention_records: 0,
            ..crate::config::AnalyticsConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field analytics.guardrail_evaluation_retention_records"));

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
            ferrogate_storage::StorageProviderKind::Supabase,
            ferrogate_storage::StorageProviderKind::Postgres,
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
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("turso_libsql has been removed"));
    assert!(error.contains("migrate"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Mysql,
            required: true,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("mysql has been removed"));
    assert!(error.contains("migrate"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Supabase,
            required: true,
            supabase_dsn_env: Some("FERROGATE_SUPABASE_DSN".into()),
            postgres_tls_mode: ferrogate_storage::PostgresTlsMode::Require,
            postgres_pool_size: 2,
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
            provider: ferrogate_storage::StorageProviderKind::Supabase,
            required: true,
            postgres_tls_mode: ferrogate_storage::PostgresTlsMode::Require,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.supabase_dsn_env"));

    let config = Config {
        storage: StorageConfig {
            provider: ferrogate_storage::StorageProviderKind::Supabase,
            required: true,
            supabase_dsn_env: Some("FERROGATE_SUPABASE_DSN".into()),
            postgres_tls_mode: ferrogate_storage::PostgresTlsMode::Prefer,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_tls_mode"));

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
            postgres_pool_acquire_timeout_millis: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.postgres_pool_acquire_timeout_millis"));

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
            provider_order: vec![
                ferrogate_storage::StorageProviderKind::Supabase,
                ferrogate_storage::StorageProviderKind::TursoLibsql,
                ferrogate_storage::StorageProviderKind::Postgres,
            ],
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.provider_order"));
    assert!(error.contains("turso_libsql has been removed"));

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
                ferrogate_storage::StorageProviderKind::Supabase,
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
            ..ClusterConfig::default()
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

// Signed control-plane snapshot key/identity validation (#206). Validation runs
// the SAME builder the runtime uses, so a config that validates is guaranteed
// to construct.
#[test]
fn rejects_snapshot_signing_key_without_key_id() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            snapshot_signing_key: Some("c2lnbmluZy1zZWVkLTMyLWJ5dGVzLWFhYWFhYWFh".into()),
            snapshot_tenant_id: Some("tenant-a".into()),
            snapshot_deployment_id: Some("deploy-a".into()),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cluster.snapshot_signing_key_id"), "{error}");
}

#[test]
fn rejects_snapshot_signing_without_identity() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            snapshot_signing_key: Some("c2lnbmluZy1zZWVkLTMyLWJ5dGVzLWFhYWFhYWFh".into()),
            snapshot_signing_key_id: Some("k1".into()),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cluster.snapshot_tenant_id"), "{error}");
}

#[test]
fn rejects_snapshot_trusted_key_with_malformed_base64() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            snapshot_trusted_keys: vec![ClusterSnapshotKey {
                key_id: "k1".into(),
                public_key: "not valid base64!!!".into(),
            }],
            snapshot_tenant_id: Some("tenant-a".into()),
            snapshot_deployment_id: Some("deploy-a".into()),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must be valid base64"), "{error}");
}

#[test]
fn accepts_valid_snapshot_signing_config() {
    use base64::Engine as _;
    // Any 32 bytes is a valid ed25519 signing seed; encode exactly 32 bytes.
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            snapshot_signing_key: Some(seed_b64),
            snapshot_signing_key_id: Some("k1".into()),
            snapshot_tenant_id: Some("tenant-a".into()),
            snapshot_deployment_id: Some("deploy-a".into()),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    config.validate().expect("valid snapshot signing config");
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

#[test]
fn accepts_empty_network_access_config_by_default() {
    let config = Config::default();
    config.validate().unwrap();
}

#[test]
fn accepts_valid_ip_and_cidr_allowlist_entries() {
    let config = Config {
        network_access: NetworkAccessConfig {
            ip_allowlist: vec![
                "203.0.113.7".into(),
                "10.0.0.0/8".into(),
                "2001:db8::/32".into(),
            ],
            trust_forwarded_for: false,
            trusted_proxy_hops: None,
            unauthenticated_rate_limit_per_minute: Some(600),
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_invalid_ip_allowlist_entry() {
    let config = Config {
        network_access: NetworkAccessConfig {
            ip_allowlist: vec!["not-an-ip".into()],
            trust_forwarded_for: false,
            trusted_proxy_hops: None,
            unauthenticated_rate_limit_per_minute: None,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field network_access.ip_allowlist[0]"));
}

#[test]
fn rejects_ip_allowlist_entry_with_invalid_prefix_length() {
    let config = Config {
        network_access: NetworkAccessConfig {
            ip_allowlist: vec!["10.0.0.0/33".into()],
            trust_forwarded_for: false,
            trusted_proxy_hops: None,
            unauthenticated_rate_limit_per_minute: None,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field network_access.ip_allowlist[0]"));
}

#[test]
fn rejects_zero_unauthenticated_rate_limit() {
    let config = Config {
        network_access: NetworkAccessConfig {
            ip_allowlist: vec![],
            trust_forwarded_for: false,
            trusted_proxy_hops: None,
            unauthenticated_rate_limit_per_minute: Some(0),
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field network_access.unauthenticated_rate_limit_per_minute"));
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
        region: None,
        aws_access_key_id: None,
        aws_secret_access_key_env: None,
        aws_session_token_env: None,
        gcp_project_id: None,
        gcp_access_token_env: None,
        name: "openai".into(),
        kind: "openai".into(),
        base_url: "http://127.0.0.1:8081/v1".into(),
        api_key_env: None,
        secret_ref: None,
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
        canary: None,
        shadow: None,
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
        region_allowlist: Vec::new(),
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
        workspace_id: None,
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
        oauth: None,
        signed_jwt_audience: None,
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

/// #315: `[admin_api]` rejects a `gateway_url` that is not an internal
/// `http://` base URL -- the proxied hop is service-to-service, mirroring
/// the `auth_service.endpoint` contract.
#[test]
fn rejects_admin_api_with_non_http_gateway_url() {
    let config = Config {
        admin_api: AdminApiConfig {
            gateway_url: "https://gateway.internal:8080".into(),
            ..AdminApiConfig::default()
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field admin_api.gateway_url: must start with http://"),
        "unexpected error: {error}"
    );
}

/// #315: `[admin_api]` rejects an unparseable listen address and an empty
/// gateway host, so a broken section fails `ferrogate validate` instead of
/// failing at first console request.
#[test]
fn rejects_admin_api_with_invalid_listen_or_empty_host() {
    let config = Config {
        admin_api: AdminApiConfig {
            listen: "not-an-address".into(),
            ..AdminApiConfig::default()
        },
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field admin_api.listen: invalid listen address"),
        "unexpected error: {error}"
    );

    let config = Config {
        admin_api: AdminApiConfig {
            gateway_url: "http:///".into(),
            ..AdminApiConfig::default()
        },
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field admin_api.gateway_url: host cannot be empty"),
        "unexpected error: {error}"
    );
}

/// #315: `[admin_api]` timeout must be non-zero and TLS cert/key must be
/// configured as a pair.
#[test]
fn rejects_admin_api_zero_timeout_and_half_configured_tls() {
    let config = Config {
        admin_api: AdminApiConfig {
            upstream_timeout_millis: 0,
            ..AdminApiConfig::default()
        },
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field admin_api.upstream_timeout_millis: must be greater than zero"),
        "unexpected error: {error}"
    );

    let config = Config {
        admin_api: AdminApiConfig {
            tls_cert_path: Some("/etc/ferrogate/tls.crt".into()),
            ..AdminApiConfig::default()
        },
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("admin_api.tls_cert_path and admin_api.tls_key_path"),
        "unexpected error: {error}"
    );
}

/// #315: the `[admin_api]` TOML section wires into `Config.admin_api`;
/// absent knobs keep their documented defaults and an absent section
/// validates as a complete no-op.
#[test]
fn admin_api_section_deserializes_from_toml_with_defaults() {
    let config = Config::from_toml_str(
        r#"
[admin_api]
listen = "0.0.0.0:9095"
gateway_url = "http://ferrogate.internal:8080"
cors_allowed_origin = "https://admin.example.test"
"#,
    )
    .expect("admin_api section must parse and validate");
    assert_eq!(config.admin_api.listen, "0.0.0.0:9095");
    assert_eq!(
        config.admin_api.gateway_url,
        "http://ferrogate.internal:8080"
    );
    assert_eq!(config.admin_api.upstream_timeout_millis, 30_000);
    assert_eq!(
        config.admin_api.cors_allowed_origin.as_deref(),
        Some("https://admin.example.test")
    );

    let defaults = Config::default();
    assert_eq!(defaults.admin_api.listen, "127.0.0.1:8095");
    assert_eq!(defaults.admin_api.gateway_url, "http://127.0.0.1:8080");
    defaults.validate().expect("defaults must validate");
}

// --------------------------------------------------------------------------
// #400: x402 wallet hold TTL must outlive the settlement confirmation window.
// The wallet primitive refuses to capture a hold past its TTL and auto-releases
// it, so a confirmed-on-chain payment whose hold already expired can no longer
// charge the wallet -- money delivered, not captured. `validate()` rejects such
// a money-losing config at load time (only when the reconciler is enabled).
// --------------------------------------------------------------------------

#[test]
fn rejects_x402_hold_ttl_not_outliving_confirmation_window() {
    // window = confirmation_deadline(900) + check_delay(60) + tick(30) = 990.
    // hold_ttl 990 is not STRICTLY greater than the window, so it must fail.
    let config = Config {
        x402_reconciler: X402ReconcilerConfig {
            enabled: true,
            tick_interval_secs: 30,
            max_reconciles_per_tick: 100,
            reconcile_check_delay_secs: 60,
            confirmation_deadline_secs: 900,
            hold_ttl_secs: 990,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field x402_reconciler.hold_ttl_secs"),
        "error should name the offending field: {error}"
    );
    // The structured error names both operands and the derived window.
    assert!(
        error.contains("990s"),
        "error should name the window/hold: {error}"
    );
    assert!(
        error.contains("900s"),
        "error should name the deadline: {error}"
    );
    assert!(
        error.contains("60s"),
        "error should name the check delay: {error}"
    );
}

#[test]
fn rejects_x402_hold_ttl_shorter_than_confirmation_deadline_alone() {
    // A blatantly money-losing case: the hold expires before the deadline even
    // fires, let alone the reconcile slack.
    let config = Config {
        x402_reconciler: X402ReconcilerConfig {
            enabled: true,
            tick_interval_secs: 30,
            max_reconciles_per_tick: 100,
            reconcile_check_delay_secs: 60,
            confirmation_deadline_secs: 900,
            hold_ttl_secs: 300,
        },
        ..Config::default()
    };

    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field x402_reconciler.hold_ttl_secs"),
        "error should name the offending field: {error}"
    );
}

#[test]
fn accepts_x402_hold_ttl_comfortably_outliving_confirmation_window() {
    // hold_ttl 3600 comfortably outlives 900 + 60 + 30 = 990.
    let config = Config {
        x402_reconciler: X402ReconcilerConfig {
            enabled: true,
            tick_interval_secs: 30,
            max_reconciles_per_tick: 100,
            reconcile_check_delay_secs: 60,
            confirmation_deadline_secs: 900,
            hold_ttl_secs: 3600,
        },
        ..Config::default()
    };

    config
        .validate()
        .expect("a hold TTL that outlives the confirmation window must validate");
}

#[test]
fn accepts_x402_hold_ttl_one_second_above_the_window() {
    // Boundary: window = 990, hold_ttl = 991 (strictly greater) must pass.
    let config = Config {
        x402_reconciler: X402ReconcilerConfig {
            enabled: true,
            tick_interval_secs: 30,
            max_reconciles_per_tick: 100,
            reconcile_check_delay_secs: 60,
            confirmation_deadline_secs: 900,
            hold_ttl_secs: 991,
        },
        ..Config::default()
    };

    config
        .validate()
        .expect("hold TTL one second above the window must validate");
}

#[test]
fn ignores_x402_hold_ttl_invariant_when_reconciler_disabled() {
    // Even a money-losing hold_ttl passes while the reconciler is disabled: it
    // never captures a submitted attempt on this path, so there is nothing to
    // lose. This guards against erroring on an all-off config.
    let config = Config {
        x402_reconciler: X402ReconcilerConfig {
            enabled: false,
            tick_interval_secs: 30,
            max_reconciles_per_tick: 100,
            reconcile_check_delay_secs: 60,
            confirmation_deadline_secs: 900,
            hold_ttl_secs: 1,
        },
        ..Config::default()
    };

    config
        .validate()
        .expect("a disabled reconciler must not trigger the hold-TTL invariant");
}

#[test]
fn default_config_passes_x402_hold_ttl_invariant() {
    // The default reconciler is disabled with hold_ttl 3600 vs a 990s window;
    // the shipped default must always validate.
    let config = Config::default();
    assert!(!config.x402_reconciler.enabled);
    config
        .validate()
        .expect("default config must validate the x402 hold-TTL invariant");
}

#[test]
fn absent_cloudflare_block_is_valid() {
    // #405: no [cloudflare] block = Cloudflare disabled; must always validate.
    let config = Config::default();
    assert!(config.cloudflare.is_none());
    config
        .validate()
        .expect("a config without a [cloudflare] block must validate");
}

#[test]
fn valid_cloudflare_block_passes() {
    let config = Config {
        cloudflare: Some(CloudflareConfig::new("acct-123", "env://CF_API_TOKEN")),
        ..Config::default()
    };
    config
        .validate()
        .expect("a well-formed [cloudflare] block must validate");
}

#[test]
fn rejects_cloudflare_with_empty_account_id() {
    let config = Config {
        cloudflare: Some(CloudflareConfig::new("   ", "env://CF_API_TOKEN")),
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field cloudflare.account_id"),
        "was: {error}"
    );
}

#[test]
fn rejects_cloudflare_with_empty_token() {
    let config = Config {
        cloudflare: Some(CloudflareConfig::new("acct-123", "")),
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("field cloudflare.api_token"), "was: {error}");
}

#[test]
fn rejects_cloudflare_with_malformed_base_url() {
    let mut cf = CloudflareConfig::new("acct-123", "env://CF_API_TOKEN");
    cf.api_base_url = "ftp://api.cloudflare.com".to_string();
    let config = Config {
        cloudflare: Some(cf),
        ..Config::default()
    };
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(
        error.contains("field cloudflare.api_base_url"),
        "was: {error}"
    );
}
