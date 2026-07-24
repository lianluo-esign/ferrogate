// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cloudflare-hosted managed MCP servers (issue #408): URL constants and
//! detection plus bearer-auth config builders for registering them as
//! ordinary [`McpServerConfig`] upstreams.

use ferrogate_core::ApprovalPolicy;
use http::Uri;

use crate::config::{
    default_health_ping_interval_secs, default_max_reconnect_attempts,
    default_max_reconnect_backoff_secs, default_min_reconnect_backoff_secs, default_timeout_ms,
    McpAuthType, McpHeaderConfig, McpServerConfig, McpTlsConfig, McpTransport,
};

/// Cloudflare's general-purpose managed MCP server. Exposes "Code Mode"
/// (`search()` + `execute()` over Cloudflare's managed catalog) over the
/// Streamable HTTP transport FerroGate already speaks.
pub const CLOUDFLARE_MANAGED_MCP_URL: &str = "https://mcp.cloudflare.com/mcp";

/// Streamable HTTP URL of a Cloudflare product-scoped managed MCP server, e.g.
/// `cloudflare_product_mcp_url("docs")` ->
/// `https://docs.mcp.cloudflare.com/mcp`. Cloudflare publishes product servers
/// for `docs`, `bindings`, `observability`, `ai-gateway`, `containers`,
/// `browser`, `radar`, `graphql`, and more.
pub fn cloudflare_product_mcp_url(product: &str) -> String {
    format!("https://{product}.mcp.cloudflare.com/mcp")
}

/// True when `url` targets a Cloudflare-hosted managed MCP server: the managed
/// catalog and product servers on `*.mcp.cloudflare.com`, or a tenant Worker
/// MCP endpoint on `*.workers.dev` (`/mcp` Streamable HTTP or `/sse`). Used to
/// apply the Cloudflare-specific config guardrails at load time (issue #408) —
/// a `*.workers.dev` host is only treated as an MCP upstream when its path is
/// the conventional `/mcp` or `/sse`, so ordinary Workers are not flagged.
pub fn is_cloudflare_managed_mcp_url(url: &str) -> bool {
    let Ok(uri) = url.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let host = authority.host().to_ascii_lowercase();
    if host == "mcp.cloudflare.com" || host.ends_with(".mcp.cloudflare.com") {
        return true;
    }
    if host != "workers.dev" && !host.ends_with(".workers.dev") {
        return false;
    }
    let path = uri.path().trim_end_matches('/');
    path == "/mcp" || path == "/sse" || path.ends_with("/mcp") || path.ends_with("/sse")
}

/// Build the `Authorization: Bearer <token>` static header a Cloudflare managed
/// MCP server accepts as a Cloudflare API bearer token. `api_token` is an
/// already-resolved secret — source it through FerroGate's secrets seam rather
/// than inlining it in a persisted config.
pub fn cloudflare_bearer_header(api_token: &str) -> McpHeaderConfig {
    McpHeaderConfig {
        name: "Authorization".to_string(),
        value: Some(format!("Bearer {api_token}")),
        value_env: None,
    }
}

/// Construct a deny-by-default [`McpServerConfig`] for a Cloudflare managed MCP
/// server authenticated with a Cloudflare API bearer token (`shared_headers`).
/// `url` should be [`CLOUDFLARE_MANAGED_MCP_URL`] or a
/// [`cloudflare_product_mcp_url`]; `tools_to_execute` is the execution
/// allowlist (e.g. `["search", "execute"]` for Code Mode). The returned config
/// still passes through [`validate_mcp_server_config`] like any other upstream.
///
/// [`validate_mcp_server_config`]: crate::validate_mcp_server_config
pub fn cloudflare_managed_bearer_config(
    name: impl Into<String>,
    url: impl Into<String>,
    api_token: &str,
    tools_to_execute: Vec<String>,
) -> McpServerConfig {
    McpServerConfig {
        name: name.into(),
        transport: McpTransport::StreamableHttp,
        url: Some(url.into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::SharedHeaders,
        headers: vec![cloudflare_bearer_header(api_token)],
        oauth: None,
        signed_jwt_audience: None,
        tools_to_execute,
        tools_to_auto_execute: Vec::new(),
        approval_policy: ApprovalPolicy::default(),
        tool_include: Vec::new(),
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: default_timeout_ms(),
        health_ping_interval_secs: default_health_ping_interval_secs(),
        max_reconnect_attempts: default_max_reconnect_attempts(),
        min_reconnect_backoff_secs: default_min_reconnect_backoff_secs(),
        max_reconnect_backoff_secs: default_max_reconnect_backoff_secs(),
    }
}

#[cfg(test)]
#[path = "cloudflare_test.rs"]
mod tests;
