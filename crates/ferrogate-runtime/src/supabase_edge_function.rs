// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Supabase edge-functions invocation entry for governed tools/functions (#115).
//!
//! A "function" in the agent-native loop is invoked through a Supabase edge
//! function at `{project_base_url}/functions/v1/{slug}`. This module models that
//! target, validates it (fail-closed), and builds the governed HTTP request —
//! including the `Authorization`/`apikey` headers — from a *reference* to a
//! stored secret rather than an inline credential, so the invocation flows
//! through the same capability/tenant governance as any other external egress.
//!
//! Request construction is pure and fully testable; live TLS execution reuses
//! the managed REST egress path (`ManagedExternalAction::Rest`) via
//! [`SupabaseEdgeFunctionInvocation::into_managed_rest_action`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::managed_external_action::ManagedRestAction;

/// Default per-call timeout for an edge-function invocation.
pub const DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS: u64 = 30_000;

/// Where a Supabase edge function lives and how to authenticate to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupabaseEdgeFunctionTarget {
    /// Project base URL, e.g. `https://abcdefgh.supabase.co` (no trailing slash required).
    pub base_url: String,
    /// Function slug, e.g. `charge-credits`. Must be a single path segment.
    pub function_slug: String,
    /// Reference (id) of the stored secret that holds the bearer key; never the
    /// raw key itself. Resolved from the tenant secret store at execution time.
    pub auth_key_ref: String,
}

/// A concrete, governed invocation of a Supabase edge function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupabaseEdgeFunctionInvocation {
    pub target: SupabaseEdgeFunctionTarget,
    /// HTTP method; edge functions are POST by default.
    pub method: String,
    /// JSON request body (already serialized). Empty string means no body.
    pub body_json: String,
    pub timeout_millis: u64,
}

/// The built, ready-to-send HTTP request. `headers` values that carry secrets are
/// filled from the *resolved* key at build time; the struct is never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeFunctionHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// Fail-closed validation errors for an edge-function target/invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupabaseEdgeFunctionError {
    InsecureBaseUrl(String),
    EmptyBaseUrl,
    InvalidSlug(String),
    EmptyAuthKeyRef,
    UnsupportedMethod(String),
    EmptyResolvedKey,
}

impl std::fmt::Display for SupabaseEdgeFunctionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureBaseUrl(url) => {
                write!(f, "edge-function base_url must be https: {url}")
            }
            Self::EmptyBaseUrl => write!(f, "edge-function base_url must not be empty"),
            Self::InvalidSlug(slug) => write!(
                f,
                "edge-function slug must be a single non-empty path segment: {slug}"
            ),
            Self::EmptyAuthKeyRef => {
                write!(f, "edge-function auth_key_ref must not be empty")
            }
            Self::UnsupportedMethod(method) => {
                write!(f, "edge-function method not allowed: {method}")
            }
            Self::EmptyResolvedKey => {
                write!(f, "resolved edge-function auth key must not be empty")
            }
        }
    }
}

impl std::error::Error for SupabaseEdgeFunctionError {}

const ALLOWED_METHODS: [&str; 2] = ["POST", "GET"];

impl SupabaseEdgeFunctionTarget {
    /// Validate the target, fail-closed. Enforces https, a clean single-segment
    /// slug (no traversal / query / nested paths), and a non-empty key reference.
    pub fn validate(&self) -> Result<(), SupabaseEdgeFunctionError> {
        let base = self.base_url.trim();
        if base.is_empty() {
            return Err(SupabaseEdgeFunctionError::EmptyBaseUrl);
        }
        if !base.starts_with("https://") {
            return Err(SupabaseEdgeFunctionError::InsecureBaseUrl(base.to_string()));
        }
        let slug = self.function_slug.trim();
        if slug.is_empty()
            || slug.contains('/')
            || slug.contains('?')
            || slug.contains('#')
            || slug.contains("..")
            || slug.contains(char::is_whitespace)
        {
            return Err(SupabaseEdgeFunctionError::InvalidSlug(
                self.function_slug.clone(),
            ));
        }
        if self.auth_key_ref.trim().is_empty() {
            return Err(SupabaseEdgeFunctionError::EmptyAuthKeyRef);
        }
        Ok(())
    }

    /// Fully-qualified invocation URL: `{base}/functions/v1/{slug}`.
    pub fn invocation_url(&self) -> String {
        format!(
            "{}/functions/v1/{}",
            self.base_url.trim().trim_end_matches('/'),
            self.function_slug.trim()
        )
    }
}

impl SupabaseEdgeFunctionInvocation {
    /// Construct a POST invocation with the default timeout.
    pub fn post(target: SupabaseEdgeFunctionTarget, body_json: impl Into<String>) -> Self {
        Self {
            target,
            method: "POST".to_string(),
            body_json: body_json.into(),
            timeout_millis: DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS,
        }
    }

    fn normalized_method(&self) -> Result<String, SupabaseEdgeFunctionError> {
        let method = self.method.trim().to_ascii_uppercase();
        if ALLOWED_METHODS.contains(&method.as_str()) {
            Ok(method)
        } else {
            Err(SupabaseEdgeFunctionError::UnsupportedMethod(
                self.method.clone(),
            ))
        }
    }

    /// Build the governed HTTP request. `resolved_key` is the secret value looked
    /// up from the tenant secret store for `target.auth_key_ref`; it is injected
    /// into the `Authorization` and `apikey` headers and never stored elsewhere.
    pub fn build_http_request(
        &self,
        resolved_key: &str,
    ) -> Result<EdgeFunctionHttpRequest, SupabaseEdgeFunctionError> {
        self.target.validate()?;
        let method = self.normalized_method()?;
        if resolved_key.trim().is_empty() {
            return Err(SupabaseEdgeFunctionError::EmptyResolvedKey);
        }
        let mut headers = BTreeMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {resolved_key}"),
        );
        headers.insert("apikey".to_string(), resolved_key.to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        Ok(EdgeFunctionHttpRequest {
            method,
            url: self.target.invocation_url(),
            headers,
            body: self.body_json.clone(),
        })
    }

    /// Adapt into a governed managed REST action so the invocation flows through
    /// the existing external-action capability/tenant governance and egress path.
    /// The credential is resolved at execution time via `auth_key_ref`, so no
    /// secret material is embedded here.
    pub fn into_managed_rest_action(self) -> Result<ManagedRestAction, SupabaseEdgeFunctionError> {
        let method = self.normalized_method()?;
        self.target.validate()?;
        Ok(ManagedRestAction {
            method,
            url: self.target.invocation_url(),
            headers_policy: format!("supabase_edge_function:{}", self.target.auth_key_ref),
            body_policy: if self.body_json.trim().is_empty() {
                "none".to_string()
            } else {
                "json".to_string()
            },
            timeout_millis: self.timeout_millis.max(1),
            retry_limit: 0,
        })
    }
}

#[cfg(test)]
#[path = "supabase_edge_function_test.rs"]
mod supabase_edge_function_test;
