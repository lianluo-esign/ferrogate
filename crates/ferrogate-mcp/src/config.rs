// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP upstream server configuration types, serde defaults, config
//! validation, and the tool selection/allowlist matchers.

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ApprovalPolicy;
use http::{header::HeaderName, HeaderValue, Uri};
use serde::{Deserialize, Serialize};

use crate::http_client::validate_http_endpoint;
use crate::tls::validate_mcp_tls_config;

pub const DEFAULT_HEALTH_PING_INTERVAL_SECS: u64 = 10;
pub const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 5;
pub const DEFAULT_MIN_RECONNECT_BACKOFF_SECS: u64 = 1;
pub const DEFAULT_MAX_RECONNECT_BACKOFF_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    StreamableHttp,
    Sse,
    Stdio,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpAuthType {
    #[default]
    None,
    #[serde(alias = "headers")]
    SharedHeaders,
    Oauth,
    PerUserOauth,
    PerUserHeaders,
    OriginalBearer,
    FerrogateSignedJwt,
}

impl McpAuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SharedHeaders => "shared_headers",
            Self::Oauth => "oauth",
            Self::PerUserOauth => "per_user_oauth",
            Self::PerUserHeaders => "per_user_headers",
            Self::OriginalBearer => "original_bearer",
            Self::FerrogateSignedJwt => "ferrogate_signed_jwt",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpOauthConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default = "default_oauth_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

fn default_oauth_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: McpTransport,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub auth_type: McpAuthType,
    #[serde(default)]
    pub headers: Vec<McpHeaderConfig>,
    #[serde(default)]
    pub oauth: Option<McpOauthConfig>,
    #[serde(default)]
    pub signed_jwt_audience: Option<String>,
    #[serde(default)]
    pub tools_to_execute: Vec<String>,
    #[serde(default)]
    pub tools_to_auto_execute: Vec<String>,
    #[serde(default)]
    pub approval_policy: ApprovalPolicy,
    #[serde(default)]
    pub tool_include: Vec<String>,
    #[serde(default)]
    pub tool_regex: Vec<String>,
    #[serde(default)]
    pub tls: McpTlsConfig,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_ping_interval_secs")]
    pub health_ping_interval_secs: u64,
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,
    #[serde(default = "default_min_reconnect_backoff_secs")]
    pub min_reconnect_backoff_secs: u64,
    #[serde(default = "default_max_reconnect_backoff_secs")]
    pub max_reconnect_backoff_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpHeaderConfig {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpTlsConfig {
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

pub(crate) fn default_timeout_ms() -> u64 {
    30_000
}

pub(crate) fn default_health_ping_interval_secs() -> u64 {
    DEFAULT_HEALTH_PING_INTERVAL_SECS
}

pub(crate) fn default_max_reconnect_attempts() -> u32 {
    DEFAULT_MAX_RECONNECT_ATTEMPTS
}

pub(crate) fn default_min_reconnect_backoff_secs() -> u64 {
    DEFAULT_MIN_RECONNECT_BACKOFF_SECS
}

pub(crate) fn default_max_reconnect_backoff_secs() -> u64 {
    DEFAULT_MAX_RECONNECT_BACKOFF_SECS
}

pub(crate) fn resolved_headers(config: &McpServerConfig) -> AnyResult<Vec<(String, String)>> {
    config
        .headers
        .iter()
        .map(|header| {
            validate_static_header(header)?;
            let value = match (&header.value, &header.value_env) {
                (Some(value), _) => value.clone(),
                (None, Some(env_name)) => std::env::var(env_name).with_context(|| {
                    format!("missing MCP header environment variable {env_name}")
                })?,
                (None, None) => String::new(),
            };
            Ok((header.name.clone(), value))
        })
        .collect()
}

pub(crate) fn tool_selected(config: &McpServerConfig, remote_name: &str) -> bool {
    (config.tool_include.is_empty()
        || config
            .tool_include
            .iter()
            .any(|pattern| selector_matches(pattern, remote_name)))
        && (config.tool_regex.is_empty()
            || config
                .tool_regex
                .iter()
                .any(|pattern| selector_matches(pattern, remote_name)))
}

pub(crate) fn tool_allowlisted(allowlist: &[String], remote_name: &str) -> bool {
    allowlist
        .iter()
        .any(|allowed| allowed == "*" || selector_matches(allowed, remote_name))
}

fn selector_matches(pattern: &str, value: &str) -> bool {
    pattern == value
        || pattern == "*"
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| value.starts_with(prefix))
        || pattern
            .strip_prefix('/')
            .and_then(|rest| rest.strip_suffix('/'))
            .is_some_and(|needle| value.contains(needle))
}

pub fn validate_mcp_server_config(config: &McpServerConfig) -> AnyResult<()> {
    if config.name.trim().is_empty() {
        bail!("MCP server name cannot be empty");
    }
    if config.name.contains('-') {
        bail!("MCP server name cannot contain '-' because tool names use serverName-toolName");
    }
    if config.tools_to_execute.is_empty() {
        bail!(
            "MCP server {} must set tools_to_execute; execution is deny-by-default",
            config.name
        );
    }
    if config.max_reconnect_attempts == 0 {
        bail!(
            "MCP server {} max_reconnect_attempts must be greater than 0",
            config.name
        );
    }
    if config.min_reconnect_backoff_secs == 0 || config.max_reconnect_backoff_secs == 0 {
        bail!(
            "MCP server {} reconnect backoff values must be greater than 0",
            config.name
        );
    }
    if config.min_reconnect_backoff_secs > config.max_reconnect_backoff_secs {
        bail!(
            "MCP server {} min reconnect backoff cannot exceed max",
            config.name
        );
    }
    match config.auth_type {
        McpAuthType::Oauth => bail!(
            "MCP auth_type oauth is not implemented; use per_user_oauth for user-isolated OAuth or shared_headers for shared credentials"
        ),
        McpAuthType::PerUserHeaders => bail!(
            "MCP auth_type per_user_headers is not implemented; use per_user_oauth, original_bearer, or ferrogate_signed_jwt"
        ),
        McpAuthType::SharedHeaders if config.headers.is_empty() => {
            bail!("MCP auth_type shared_headers requires at least one static header")
        }
        McpAuthType::None if !config.headers.is_empty() => {
            bail!("MCP static headers require auth_type shared_headers")
        }
        McpAuthType::PerUserOauth | McpAuthType::OriginalBearer => {
            let oauth = config.oauth.as_ref().ok_or_else(|| {
                anyhow::anyhow!("MCP auth_type {} requires oauth configuration", config.auth_type.as_str())
            })?;
            validate_oauth_config(oauth, matches!(config.auth_type, McpAuthType::PerUserOauth))?;
        }
        McpAuthType::FerrogateSignedJwt => {
            if config.signed_jwt_audience.as_deref().is_none_or(str::is_empty) {
                bail!("MCP auth_type ferrogate_signed_jwt requires signed_jwt_audience");
            }
        }
        McpAuthType::None | McpAuthType::SharedHeaders => {}
    }
    for header in &config.headers {
        validate_static_header(header)?;
    }
    if !matches!(config.auth_type, McpAuthType::SharedHeaders) && !config.headers.is_empty() {
        bail!("per-user MCP identity modes cannot define static headers");
    }
    match config.transport {
        McpTransport::StreamableHttp | McpTransport::Sse => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("MCP network server {} requires url", config.name)
            })?;
            validate_http_endpoint(url)?;
            validate_mcp_tls_config(&config.tls)
                .with_context(|| format!("MCP server {}", config.name))?;
        }
        McpTransport::Stdio => {
            if config.command.as_deref().is_none_or(str::is_empty) {
                bail!("MCP stdio server {} requires command", config.name);
            }
        }
    }
    Ok(())
}

fn validate_oauth_config(config: &McpOauthConfig, authorization_code: bool) -> AnyResult<()> {
    let issuer: Uri = config
        .issuer
        .parse()
        .context("MCP oauth.issuer is invalid")?;
    if !matches!(issuer.scheme_str(), Some("http" | "https")) || issuer.authority().is_none() {
        bail!("MCP oauth.issuer must be an http or https URL");
    }
    if issuer.scheme_str() == Some("http") && !config.allow_insecure_http {
        bail!("MCP oauth.issuer must use https unless allow_insecure_http is explicitly enabled");
    }
    if config.client_id.trim().is_empty() {
        bail!("MCP oauth.client_id cannot be empty");
    }
    if config.scopes.is_empty() || config.scopes.iter().any(|scope| scope.trim().is_empty()) {
        bail!("MCP oauth.scopes must contain non-empty values");
    }
    if authorization_code {
        if config
            .client_secret_ref
            .as_deref()
            .is_none_or(str::is_empty)
        {
            bail!("MCP per_user_oauth requires oauth.client_secret_ref");
        }
        if config.redirect_uri.as_deref().is_none_or(str::is_empty) {
            bail!("MCP per_user_oauth requires oauth.redirect_uri");
        }
    }
    Ok(())
}

fn validate_static_header(header: &McpHeaderConfig) -> AnyResult<()> {
    HeaderName::from_bytes(header.name.as_bytes()).context("MCP static header name is invalid")?;
    if [
        crate::protocol::MCP_PROTOCOL_VERSION_HEADER,
        crate::protocol::MCP_METHOD_HEADER,
        crate::protocol::MCP_NAME_HEADER,
        "mcp-session-id",
    ]
    .iter()
    .any(|reserved| header.name.eq_ignore_ascii_case(reserved))
    {
        bail!("MCP static header {} is protocol-owned", header.name);
    }
    match (&header.value, &header.value_env) {
        (Some(value), None) => {
            HeaderValue::from_str(value).context("MCP static header value is invalid")?;
        }
        (None, Some(name)) if !name.trim().is_empty() => {}
        _ => bail!("MCP static header must set exactly one of value or value_env"),
    }
    Ok(())
}

#[cfg(test)]
#[path = "config_test.rs"]
mod tests;
