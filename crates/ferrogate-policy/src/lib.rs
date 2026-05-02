//! Policy decision boundaries.

use ferrogate_core::RequestContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { code: String, message: String },
}

pub trait PolicyEngine {
    fn evaluate(&self, request: &RequestContext, model: Option<&str>) -> PolicyDecision;
}
