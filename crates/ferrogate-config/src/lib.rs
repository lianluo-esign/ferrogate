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
    GatewayConfig, GatewayHeader, GatewayLog, GatewayModel, GatewayProvider, GatewayRoute,
    GatewayUpstream, StaticResponse,
};
