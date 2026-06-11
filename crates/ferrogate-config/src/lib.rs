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

pub use caddyfile::parse_caddyfile;
pub use diagnostic::CaddyfileDiagnostic;
pub use loader::{is_caddyfile_path, load_caddyfile};
pub use types::{
    GatewayApiKey, GatewayConfig, GatewayHeader, GatewayLog, GatewayModel, GatewayProvider,
    GatewayRoute, GatewayTlsAcmeConfig, GatewayTlsConfig, GatewayUpstream, StaticResponse,
};
