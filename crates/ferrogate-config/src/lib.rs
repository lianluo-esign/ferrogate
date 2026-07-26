// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Configuration parsing and typed adapter boundaries.
//!
//! The Caddyfile support in this crate is a deliberately small compatibility
//! contract. It accepts the initial FerroGate subset, maps it to a typed gateway
//! model, and returns clear diagnostics for unsupported directives.

mod caddyfile;
mod diagnostic;
mod loader;
mod types;
mod x402;
mod x402_scope;

pub use caddyfile::parse_caddyfile;
pub use diagnostic::CaddyfileDiagnostic;
pub use loader::{is_caddyfile_path, load_caddyfile};
pub use types::{
    GatewayApiKey, GatewayConfig, GatewayHeader, GatewayLog, GatewayModel, GatewayProvider,
    GatewayRoute, GatewayTlsAcmeConfig, GatewayTlsConfig, GatewayUpstream, StaticResponse,
};
pub use x402::{
    default_x402_spend_policy, load_x402_spend_policy_toml, AllowedAsset, ApprovalPolicy,
    ConversionRule, PolicyNetwork, ResourceRule, Rounding, ValidatedX402SpendPolicy,
    X402ConfigError, X402PolicyConfigError, X402SpendCaps, X402SpendPolicy, X402SpendPolicyConfig,
};
pub use x402_scope::{
    resolve_effective_x402_spend_policy, validate_scoped_x402_spend_policies,
    EffectiveX402SpendPolicy, X402PolicyScopeKind, X402PolicyScopeRef, X402ScopeChain,
    X402ScopedPolicyError, X402ScopedSpendPolicy,
};
