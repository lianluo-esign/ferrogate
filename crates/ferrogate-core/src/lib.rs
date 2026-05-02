//! Shared FerroGate domain primitives.

use serde::{Deserialize, Serialize};

/// Request identity that can be passed across runtime, auth, routing, and logs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub trace_id: Option<String>,
    pub route: Option<String>,
    pub upstream: Option<String>,
    pub tenant: TenantContext,
}

/// Tenant fields resolved from virtual API keys or future admin control-plane data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    pub organization_id: Option<String>,
    pub team_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
}

pub type Result<T> = std::result::Result<T, GatewayError>;

/// Boundary error used by skeleton crates until domain-specific errors are added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayError {
    pub code: String,
    pub message: String,
}

impl GatewayError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
