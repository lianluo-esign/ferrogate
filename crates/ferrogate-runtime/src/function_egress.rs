// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Fail-closed egress governance for gateway-brokered function invocation (#117).
//!
//! Before the gateway mints any credential or makes any call, a function
//! invocation must clear a per-tenant allowlist of permitted
//! `{project_base_url, function_slug}` targets. Deny-by-default: an empty
//! allowlist, an unknown tenant, or a non-listed target all reject. This is the
//! policy gate for the [Function Egress Broker](../../docs/design/function-egress-broker.md).

use serde::{Deserialize, Serialize};

use crate::supabase_edge_function::{SupabaseEdgeFunctionError, SupabaseEdgeFunctionTarget};

/// Wildcard slug that permits any function under an allowed base URL for a tenant.
pub const ANY_FUNCTION_SLUG: &str = "*";

/// One allowlist entry: a tenant may invoke the listed slugs at one base URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEgressRule {
    /// Tenant id this rule applies to (matched exactly).
    pub tenant: String,
    /// Permitted project base URL, e.g. `https://abcdefgh.supabase.co`.
    pub base_url: String,
    /// Permitted function slugs, or a single `"*"` to allow any slug at `base_url`.
    pub function_slugs: Vec<String>,
}

/// A fail-closed, per-tenant allowlist of edge-function egress targets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEgressAllowlist {
    rules: Vec<FunctionEgressRule>,
}

/// Why a target was denied by the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionEgressDenied {
    /// The target itself failed fail-closed validation (https, slug, key ref).
    InvalidTarget(SupabaseEdgeFunctionError),
    /// No allowlist rule exists for the tenant at all.
    NoRuleForTenant(String),
    /// The tenant has rules, but none permit this base URL + slug.
    TargetNotAllowed {
        tenant: String,
        base_url: String,
        function_slug: String,
    },
}

impl std::fmt::Display for FunctionEgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(error) => write!(f, "invalid function target: {error}"),
            Self::NoRuleForTenant(tenant) => {
                write!(f, "no function egress rule for tenant {tenant}")
            }
            Self::TargetNotAllowed {
                tenant,
                base_url,
                function_slug,
            } => write!(
                f,
                "tenant {tenant} may not invoke {function_slug} at {base_url}"
            ),
        }
    }
}

impl std::error::Error for FunctionEgressDenied {}

/// Normalize a base URL for comparison: trim surrounding and trailing-slash noise.
fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

impl FunctionEgressAllowlist {
    pub fn new(rules: Vec<FunctionEgressRule>) -> Self {
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Authorize a target for a tenant, fail-closed. Validates the target first,
    /// then requires an exact base-URL match and either an exact slug match or a
    /// `"*"` wildcard within the tenant's rules.
    pub fn authorize(
        &self,
        tenant: &str,
        target: &SupabaseEdgeFunctionTarget,
    ) -> Result<(), FunctionEgressDenied> {
        target
            .validate()
            .map_err(FunctionEgressDenied::InvalidTarget)?;

        let requested_base = normalize_base_url(&target.base_url);
        let requested_slug = target.function_slug.trim();

        let mut tenant_has_rule = false;
        for rule in &self.rules {
            if rule.tenant != tenant {
                continue;
            }
            tenant_has_rule = true;
            if normalize_base_url(&rule.base_url) != requested_base {
                continue;
            }
            let slug_allowed = rule
                .function_slugs
                .iter()
                .any(|slug| slug == ANY_FUNCTION_SLUG || slug.trim() == requested_slug);
            if slug_allowed {
                return Ok(());
            }
        }

        if !tenant_has_rule {
            return Err(FunctionEgressDenied::NoRuleForTenant(tenant.to_string()));
        }
        Err(FunctionEgressDenied::TargetNotAllowed {
            tenant: tenant.to_string(),
            base_url: requested_base,
            function_slug: requested_slug.to_string(),
        })
    }
}

/// The request an agent/worker sends to `/v1/functions/execute` (no secrets).
///
/// `tenant` is advisory only — the gateway attributes the call to the
/// authenticated identity, never this field — so it is optional on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInvocationRequest {
    #[serde(default)]
    pub tenant: String,
    pub target: SupabaseEdgeFunctionTarget,
    #[serde(default = "default_invocation_method")]
    pub method: String,
    #[serde(default)]
    pub body_json: String,
}

fn default_invocation_method() -> String {
    "POST".to_string()
}

/// The structured result the gateway returns after a brokered invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInvocationOutcome {
    pub function_slug: String,
    pub status_code: u16,
    /// A bounded excerpt of the response body (never the raw credential).
    pub body_excerpt: String,
}

#[cfg(test)]
#[path = "function_egress_test.rs"]
mod function_egress_test;

#[cfg(test)]
#[path = "function_egress_red_team_test.rs"]
mod function_egress_red_team_test;
