//! Virtual API key and tenant resolution boundaries.

use ferrogate_core::TenantContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub tenant: TenantContext,
    pub scopes: Vec<String>,
}

pub trait ApiKeyAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision>;
}
