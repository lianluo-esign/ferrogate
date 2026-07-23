// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Cloudflare account credential/config model.

//! Cloudflare account + credential configuration (issue #405).
//!
//! [`CloudflareConfig`] is the serde-friendly model an operator writes under a
//! top-level `[cloudflare]` block. It carries the account id, a token
//! *reference* (resolved through the [`crate::TokenResolver`] seam, not stored
//! decoded here), optional per-tenant token overrides, and the three Cloudflare
//! base URLs with sensible defaults. It performs no I/O.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Default Cloudflare REST API base (the `client/v4` surface).
pub fn default_api_base_url() -> String {
    "https://api.cloudflare.com/client/v4".to_string()
}

/// Default AI Gateway base host.
pub fn default_ai_gateway_base_url() -> String {
    "https://gateway.ai.cloudflare.com".to_string()
}

/// Account credential + endpoint configuration for Cloudflare.
///
/// Absent from the parent config = Cloudflare disabled. When present it is
/// validated (see the CLI's `validate_cloudflare`) for account-id/token
/// presence and URL well-formedness.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CloudflareConfig {
    /// Cloudflare account id (the `{account_id}` path segment).
    pub account_id: String,

    /// The default API token reference, resolved via [`crate::TokenResolver`]
    /// (`env://VAR`, an inline plaintext token, or — deferred to #417 —
    /// `cf://…`). This is a *reference*, not necessarily the secret itself.
    pub api_token: String,

    /// Optional per-tenant token references, keyed by tenant id. A request
    /// scoped to a tenant present here uses this reference instead of
    /// `api_token`; anything not listed falls back to the default token.
    #[serde(default)]
    pub tenant_tokens: BTreeMap<String, String>,

    /// Cloudflare REST API base (`client/v4`). Defaulted.
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,

    /// AI Gateway base host. Defaulted.
    #[serde(default = "default_ai_gateway_base_url")]
    pub ai_gateway_base_url: String,

    /// R2 S3-compatible endpoint host. When `None`, derived per-account as
    /// `https://<account_id>.r2.cloudflarestorage.com` via
    /// [`r2_s3_endpoint`](Self::r2_s3_endpoint).
    #[serde(default)]
    pub r2_s3_endpoint: Option<String>,
}

impl CloudflareConfig {
    /// Minimal constructor for programmatic use / tests. Base URLs default.
    pub fn new(account_id: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            api_token: api_token.into(),
            tenant_tokens: BTreeMap::new(),
            api_base_url: default_api_base_url(),
            ai_gateway_base_url: default_ai_gateway_base_url(),
            r2_s3_endpoint: None,
        }
    }

    /// The effective R2 S3 endpoint: the configured override, else the
    /// per-account default host.
    pub fn r2_s3_endpoint(&self) -> String {
        self.r2_s3_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{}.r2.cloudflarestorage.com", self.account_id))
    }

    /// The token reference to use for a request, honoring a per-tenant
    /// override when `tenant` is `Some` and present in `tenant_tokens`.
    pub fn token_reference(&self, tenant: Option<&str>) -> &str {
        tenant
            .and_then(|t| self.tenant_tokens.get(t))
            .map(String::as_str)
            .unwrap_or(&self.api_token)
    }
}
