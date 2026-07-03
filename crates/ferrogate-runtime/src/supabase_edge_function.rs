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
//! including the `Authorization`/`apikey` headers — from a [`FunctionCredential`]
//! resolved at call time rather than an inline secret.
//!
//! Request construction is pure and fully testable. The gateway function egress
//! broker (`/v1/functions/execute`) authorizes the target against a per-tenant
//! allowlist, mints a scoped token, calls [`SupabaseEdgeFunctionInvocation::build_http_request`],
//! and executes the result through the gateway's TLS egress executor.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    /// raw key itself.
    ///
    /// **Reserved — not yet dereferenced.** The field is validated non-empty
    /// (fail-closed, so a target without a reference is rejected), but the
    /// broker does not currently resolve it: today the gateway sources the
    /// bearer/apikey from its process-wide env config (`FG_FN_JWT_SECRET` +
    /// `FG_FN_APIKEY`) — see `FunctionEgressGatewayConfig`. Wiring this to a
    /// per-tenant secret store is deferred; it is coupled to the multi-project
    /// credential work (single shared apikey/signing secret today). Until then,
    /// treat this as a forward-looking placeholder, not a live lookup key.
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

/// The credential the gateway injects when it executes an edge-function call.
///
/// `bearer_token` is what goes into `Authorization: Bearer …` — either a static
/// resolved key (interim) or, preferably, a short-lived scoped JWT minted per
/// call (#118). `apikey` is the project `apikey` header value. Modeling both
/// lets a scoped-token credential carry the (public) project anon key as its
/// apikey while the bearer is a narrowly-scoped JWT. Never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCredential {
    pub bearer_token: String,
    pub apikey: String,
}

impl FunctionCredential {
    /// Interim credential where the same resolved key is used for both headers.
    /// Replace with [`FunctionCredential::scoped_token`] once JWT minting lands.
    pub fn static_key(key: impl Into<String>) -> Self {
        let key = key.into();
        Self {
            bearer_token: key.clone(),
            apikey: key,
        }
    }

    /// A short-lived scoped JWT as the bearer, with the project apikey separate.
    pub fn scoped_token(jwt: impl Into<String>, apikey: impl Into<String>) -> Self {
        Self {
            bearer_token: jwt.into(),
            apikey: apikey.into(),
        }
    }

    fn is_usable(&self) -> bool {
        !self.bearer_token.trim().is_empty() && !self.apikey.trim().is_empty()
    }
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

    /// Build the governed HTTP request. `credential` carries the bearer token
    /// (a minted scoped JWT, or an interim static key) and the project apikey,
    /// supplied by the caller at call time; they are injected into the
    /// `Authorization`/`apikey` headers and never stored elsewhere. The broker
    /// mints/sources the credential from its process-wide config today;
    /// `target.auth_key_ref` is reserved and not yet consulted (see its docs).
    pub fn build_http_request(
        &self,
        credential: &FunctionCredential,
    ) -> Result<EdgeFunctionHttpRequest, SupabaseEdgeFunctionError> {
        self.target.validate()?;
        let method = self.normalized_method()?;
        if !credential.is_usable() {
            return Err(SupabaseEdgeFunctionError::EmptyResolvedKey);
        }
        let mut headers = BTreeMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", credential.bearer_token),
        );
        headers.insert("apikey".to_string(), credential.apikey.clone());
        headers.insert("content-type".to_string(), "application/json".to_string());
        Ok(EdgeFunctionHttpRequest {
            method,
            url: self.target.invocation_url(),
            headers,
            body: self.body_json.clone(),
        })
    }
}

#[cfg(test)]
#[path = "supabase_edge_function_test.rs"]
mod supabase_edge_function_test;
