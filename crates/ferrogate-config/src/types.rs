// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Caddyfile-compatible intermediate configuration model.
///
/// This crate owns parse-time shape only; `ferrogate-cli::Config` is the runtime
/// truth after normalization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub listen: String,
    pub admin: Option<String>,
    pub tls: Option<GatewayTlsConfig>,
    pub tls_acme: Option<GatewayTlsAcmeConfig>,
    pub upstreams: Vec<GatewayUpstream>,
    pub routes: Vec<GatewayRoute>,
    pub providers: Vec<GatewayProvider>,
    pub models: Vec<GatewayModel>,
    pub api_keys: Vec<GatewayApiKey>,
    pub logs: Vec<GatewayLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayTlsAcmeConfig {
    pub domains: Vec<String>,
    pub email: Option<String>,
    pub directory_url: Option<String>,
    pub challenge: Option<String>,
    pub http_challenge_listen: Option<String>,
    pub storage_dir: Option<String>,
    pub dns_provider: Option<String>,
    pub dns_config: BTreeMap<String, String>,
    pub dns_hook_set: Option<String>,
    pub dns_hook_cleanup: Option<String>,
    pub renewal_window_secs: Option<u64>,
    pub renewal_check_interval_secs: Option<u64>,
    pub renewal_retry_interval_secs: Option<u64>,
    pub auto_graceful_reload: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayUpstream {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRoute {
    pub name: String,
    pub upstream: Option<String>,
    pub hosts: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub strip_prefix: Option<String>,
    pub request_headers: Vec<GatewayHeader>,
    pub response_headers: Vec<GatewayHeader>,
    pub static_response: Option<StaticResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticResponse {
    pub body: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayProvider {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub openrouter_http_referer: Option<String>,
    #[serde(default)]
    pub openrouter_x_title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayModel {
    pub name: String,
    pub provider: String,
    pub provider_model: String,
    pub capabilities: Vec<String>,
    pub context_window: Option<u32>,
    pub input_price_per_1m: Option<String>,
    pub output_price_per_1m: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayApiKey {
    pub id: String,
    pub name: String,
    pub key_env: Option<String>,
    pub key: Option<String>,
    pub key_hash: Option<String>,
    pub scopes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub denied_models: Vec<String>,
    pub allowed_providers: Vec<String>,
    pub denied_providers: Vec<String>,
    pub monthly_token_budget: Option<u64>,
    pub request_limit_per_minute: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayLog {
    pub route: Option<String>,
}
