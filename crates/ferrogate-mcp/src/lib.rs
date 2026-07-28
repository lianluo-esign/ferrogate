// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP host/client manager for FerroGate.
//!
//! The crate depends on the official `rmcp` SDK and keeps FerroGate's runtime
//! boundary explicit: long-lived server sessions are owned by `McpManager`,
//! while the gateway applies auth, policy, billing, and audit before calling it.
//!
//! # Recipe: register a Cloudflare-hosted managed MCP server (issue #408)
//!
//! Cloudflare hosts remote MCP servers over the same Streamable HTTP transport
//! FerroGate already speaks, so a Cloudflare managed server is registered as an
//! ordinary [`McpServerConfig`] upstream — no new transport. Cloudflare's
//! general-purpose "Code Mode" catalog lives at
//! [`CLOUDFLARE_MANAGED_MCP_URL`] (`https://mcp.cloudflare.com/mcp`, exposing a
//! `search`/`execute` tool pair), and product servers live at
//! `https://<product>.mcp.cloudflare.com/mcp` (see
//! [`cloudflare_product_mcp_url`]). Both require auth — either a Cloudflare API
//! bearer token or the Cloudflare OAuth flow (Cloudflare is the OAuth provider).
//!
//! Execution is deny-by-default: only tools named in `tools_to_execute` are
//! listed or callable, so Code Mode's `search`/`execute` are allowlisted like
//! any other tool and flow through the normal `tools/list` -> `tools/call` path.
//!
//! Bearer auth (a scoped Cloudflare API token) via `shared_headers`:
//!
//! ```json
//! {
//!   "name": "cfmanaged",
//!   "transport": "streamable_http",
//!   "url": "https://mcp.cloudflare.com/mcp",
//!   "auth_type": "shared_headers",
//!   "headers": [{"name": "Authorization", "value_env": "CLOUDFLARE_MCP_BEARER"}],
//!   "tools_to_execute": ["search", "execute"]
//! }
//! ```
//!
//! The `CLOUDFLARE_MCP_BEARER` environment variable holds the full
//! `Bearer <cf-api-token>` value; keep the token out of the config file and
//! source it through the secrets seam. [`cloudflare_bearer_header`] and
//! [`cloudflare_managed_bearer_config`] build the same shape programmatically
//! from an already-resolved token.
//!
//! Per-user OAuth (Cloudflare as the OAuth provider, isolating each end-user's
//! grant) reuses the existing `per_user_oauth` machinery — point `oauth.issuer`
//! at Cloudflare's authorization server and supply `client_id`,
//! `client_secret_ref` (resolved via the secrets seam), and `redirect_uri`:
//!
//! ```json
//! {
//!   "name": "cfoauth",
//!   "transport": "streamable_http",
//!   "url": "https://docs.mcp.cloudflare.com/mcp",
//!   "auth_type": "per_user_oauth",
//!   "oauth": {
//!     "issuer": "https://mcp.cloudflare.com",
//!     "client_id": "<registered-client-id>",
//!     "client_secret_ref": "env://CLOUDFLARE_MCP_OAUTH_SECRET",
//!     "redirect_uri": "https://gateway.example/v1/mcp/identity/callback"
//!   },
//!   "tools_to_execute": ["search", "execute"]
//! }
//! ```

mod cloudflare;
mod config;
mod http_client;
mod jsonrpc;
mod manager;
mod protocol;
mod stdio_client;
mod tls;

/// Deploy / lifecycle pipeline for a FerroGate-hosted MCP server Worker on
/// Cloudflare (issue #409). See [`mcp_worker_deploy`] for the module docs.
pub mod mcp_worker_deploy;

pub use cloudflare::{
    cloudflare_bearer_header, cloudflare_managed_bearer_config, cloudflare_product_mcp_url,
    is_cloudflare_managed_mcp_url, CLOUDFLARE_MANAGED_MCP_URL,
};
pub use config::{
    validate_mcp_server_config, McpAuthType, McpHeaderConfig, McpOauthConfig, McpServerConfig,
    McpTlsConfig, McpTransport, DEFAULT_HEALTH_PING_INTERVAL_SECS, DEFAULT_MAX_RECONNECT_ATTEMPTS,
    DEFAULT_MAX_RECONNECT_BACKOFF_SECS, DEFAULT_MIN_RECONNECT_BACKOFF_SECS,
};
pub use manager::{
    McpDispatchCleanup, McpDispatchHeaders, McpExecutionError, McpManager, McpServerStatus,
    McpTool, McpToolExecutionRequest, McpToolExecutionResult,
};
pub use protocol::{
    is_supported_protocol_version, negotiate_protocol_version, resolve_negotiated_version,
    verify_routing_headers, RoutingHeaderMismatch, MCP_LEGACY_PROTOCOL_VERSION, MCP_METHOD_HEADER,
    MCP_NAME_HEADER, MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION_FALLBACK,
    MCP_PROTOCOL_VERSION_HEADER, SUPPORTED_MCP_PROTOCOL_VERSIONS,
};

#[cfg(test)]
pub(crate) mod test_support;
