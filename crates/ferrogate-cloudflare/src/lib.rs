// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Shared Cloudflare API client + credential/config model for FerroGate.

//! # `ferrogate-cloudflare` — shared Cloudflare API client (issue #405)
//!
//! The foundation every FerroGate Cloudflare integration (AI Gateway, R2,
//! Secrets Store, D1, Workers, Pages, Workflows) builds on, so auth, retries,
//! and error mapping are written **once**. This crate is a clean client
//! library: it contains NO product logic for any of those sub-systems.
//!
//! ## Surface
//!
//! - [`CloudflareConfig`] — account id, a token *reference* (resolved via a
//!   seam, not stored decoded), optional per-tenant token overrides, and the
//!   three Cloudflare base URLs with defaults.
//! - [`TokenResolver`] — the credential seam. [`EnvTokenResolver`] ships
//!   `env://` + inline-plaintext resolution; the `cf://` Secrets Store backend
//!   is a **separate sub-issue (#417)** and is a documented extension point,
//!   not implemented here.
//! - [`CloudflareClient`] — thin reqwest-based client with Bearer auth,
//!   `{account_id}` templating, [`CloudflareEnvelope`] decoding, typed
//!   [`CloudflareError`] mapping, and a deterministic retry/backoff loop that
//!   honors Cloudflare's global API rate limit (~1,200 req / 5 min / user).
//!   The HTTP transport ([`HttpTransport`]) and clock ([`Clock`]) are
//!   injectable seams so the client is fully unit-testable without a network
//!   or real sleeps.
//! - [`preflight`](CloudflareClient::preflight) — a cheap GET that verifies the
//!   token + account and names missing permission groups.
//! - [`scopes`] — the machine-adjacent list of required token permission
//!   groups the preflight references (the prose doc is sibling #421).

mod client;
mod config;
pub mod d1;
pub mod d1_proxy;
mod envelope;
mod error;
pub mod r2;
pub mod r2_token;
mod resolver;
pub mod scopes;

pub use client::{
    Clock, CloudflareClient, HttpMethod, HttpRequest, HttpResponse, HttpTransport,
    ReqwestTransport, RetryPolicy, TokioClock,
};
pub use config::{default_ai_gateway_base_url, default_api_base_url, CloudflareConfig};
pub use d1_proxy::{D1ProxyClient, D1ProxyStatement};
pub use envelope::{CloudflareEnvelope, CloudflareMessage};
pub use error::{CloudflareApiError, CloudflareError, AUTHENTICATION_CODES, MISSING_SCOPE_CODES};
pub use r2::{
    r2_bucket_name_for_tenant, r2_legacy_bucket_name_for_tenant, R2Bucket, R2BucketCreation,
    R2BucketProvision, R2CreateBucketRequest, R2_BUCKET_ALREADY_EXISTS_CODES,
    R2_BUCKET_NAME_MAX_LEN, R2_BUCKET_NAME_MIN_LEN,
};
pub use r2_token::{
    R2CredentialProvision, R2ScopedToken, R2ScopedTokenRequest, R2TokenAccess,
    R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID, R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
    R2_DEFAULT_JURISDICTION,
};
pub use resolver::{EnvTokenResolver, ResolvedToken, TokenResolver};
pub use scopes::{TokenPermissionGroup, REQUIRED_TOKEN_PERMISSION_GROUPS};

#[cfg(test)]
#[path = "backoff_test.rs"]
mod backoff_test;
#[cfg(test)]
#[path = "config_test.rs"]
mod config_test;
#[cfg(test)]
#[path = "d1_proxy_test.rs"]
mod d1_proxy_test;
#[cfg(test)]
#[path = "d1_test.rs"]
mod d1_test;
#[cfg(test)]
#[path = "envelope_test.rs"]
mod envelope_test;
#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
#[cfg(test)]
#[path = "r2_test.rs"]
mod r2_test;
#[cfg(test)]
#[path = "r2_token_test.rs"]
mod r2_token_test;
#[cfg(test)]
#[path = "resolver_test.rs"]
mod resolver_test;
