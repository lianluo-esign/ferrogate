// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::test_support::test_config;
use serde_json::json;

#[test]
fn deny_by_default_requires_execute_allowlist() {
    let config = McpServerConfig {
        name: "github".into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        oauth: None,
        signed_jwt_audience: None,
        tools_to_execute: Vec::new(),
        tools_to_auto_execute: Vec::new(),
        approval_policy: ApprovalPolicy::Never,
        tool_include: Vec::new(),
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    };

    let error = validate_mcp_server_config(&config).unwrap_err().to_string();

    assert!(error.contains("tools_to_execute"));
}

#[test]
fn namespaces_and_filters_tools() {
    let config = McpServerConfig {
        name: "github".into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        oauth: None,
        signed_jwt_audience: None,
        tools_to_execute: vec!["search".into()],
        tools_to_auto_execute: vec!["search".into()],
        approval_policy: ApprovalPolicy::Never,
        tool_include: vec!["sea*".into()],
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    };

    assert!(tool_selected(&config, "search"));
    assert!(!tool_selected(&config, "write"));
    assert!(tool_allowlisted(&config.tools_to_execute, "search"));
    assert!(!tool_allowlisted(&config.tools_to_execute, "write"));
}

#[test]
fn mcp_server_config_applies_serde_defaults() {
    let config: McpServerConfig = serde_json::from_value(json!({
        "name": "local",
        "transport": "stdio",
        "command": "mcp-server"
    }))
    .expect("minimal config must parse");
    assert_eq!(config.timeout_ms, 30_000);
    assert_eq!(
        config.health_ping_interval_secs,
        DEFAULT_HEALTH_PING_INTERVAL_SECS
    );
    assert_eq!(
        config.max_reconnect_attempts,
        DEFAULT_MAX_RECONNECT_ATTEMPTS
    );
    assert_eq!(config.auth_type, McpAuthType::None);
    assert!(config.tools_to_execute.is_empty());
    assert_eq!(config.transport, McpTransport::Stdio);
}

#[test]
fn legacy_headers_auth_parses_but_serializes_as_explicit_shared_credentials() {
    let config: McpServerConfig = serde_json::from_value(json!({
        "name": "shared",
        "transport": "streamable_http",
        "url": "http://127.0.0.1/mcp",
        "auth_type": "headers",
        "headers": [{"name": "Authorization", "value_env": "SHARED_TOKEN"}],
        "tools_to_execute": ["search"]
    }))
    .unwrap();
    assert_eq!(config.auth_type, McpAuthType::SharedHeaders);
    assert_eq!(
        serde_json::to_value(&config).unwrap()["auth_type"],
        "shared_headers"
    );
    validate_mcp_server_config(&config).unwrap();
}

#[test]
fn unsupported_identity_modes_fail_config_validation_exactly() {
    let mut oauth = test_config("oauth");
    oauth.auth_type = McpAuthType::Oauth;
    assert_eq!(
        validate_mcp_server_config(&oauth).unwrap_err().to_string(),
        "MCP auth_type oauth is not implemented; use per_user_oauth for user-isolated OAuth or shared_headers for shared credentials"
    );

    let mut headers = test_config("peruser");
    headers.auth_type = McpAuthType::PerUserHeaders;
    assert_eq!(
        validate_mcp_server_config(&headers).unwrap_err().to_string(),
        "MCP auth_type per_user_headers is not implemented; use per_user_oauth, original_bearer, or ferrogate_signed_jwt"
    );
}

#[test]
fn per_user_oauth_requires_complete_https_authorization_code_config() {
    let mut config = test_config("identity");
    config.auth_type = McpAuthType::PerUserOauth;
    assert!(validate_mcp_server_config(&config)
        .unwrap_err()
        .to_string()
        .contains("requires oauth configuration"));

    config.oauth = Some(McpOauthConfig {
        issuer: "http://idp.invalid".into(),
        client_id: "client".into(),
        client_secret_ref: Some("env://OIDC_SECRET".into()),
        redirect_uri: Some("https://gateway.example/v1/mcp/identity/callback".into()),
        scopes: vec!["openid".into()],
        audience: None,
        allow_insecure_http: false,
    });
    assert!(validate_mcp_server_config(&config)
        .unwrap_err()
        .to_string()
        .contains("must use https"));
    config.oauth.as_mut().unwrap().allow_insecure_http = true;
    validate_mcp_server_config(&config).unwrap();
}
