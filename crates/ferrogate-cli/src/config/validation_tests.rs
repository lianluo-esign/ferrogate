use super::*;

#[test]
fn rejects_model_with_unknown_provider() {
    let config = Config {
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "missing".into(),
            provider_model: "gpt-4o-mini".into(),
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown provider"));
}

#[test]
fn rejects_model_with_unknown_fallback_provider() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "missing".into(),
        provider_model: "gpt-4.1-mini".into(),
        priority: Some(10),
        weight: Some(1),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("fallback provider missing"));
}

#[test]
fn rejects_model_fallback_with_zero_weight() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4.1-mini".into(),
        priority: Some(10),
        weight: Some(0),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("fallbacks[0].weight"));
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
        enabled: true,
    }
}

fn model() -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        fallbacks: vec![],
        visible_organization_ids: vec![],
        visible_project_ids: vec![],
        capabilities: vec![],
        context_window: None,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
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
        allowed_providers: vec![],
        organization_id: None,
        team_id: None,
        project_id: None,
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
    }
}
