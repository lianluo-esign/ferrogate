// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Pluggable, typed credential sources (issue #360).
//!
//! The client authenticates to the Control Plane API with a bearer token, but
//! it must never persist that token in plaintext by default. [`AuthSource`]
//! describes *where* the token comes from — an environment variable, stdin, or
//! an explicitly-provided inline value — and [`resolve_credential`] turns a
//! source into a [`Credential`] using an injected reader so resolution is
//! testable without touching the real process environment or terminal.
//!
//! [`Credential`] deliberately redacts itself in `Debug`/`Display`; the raw
//! secret is only reachable through [`Credential::expose`], which every call
//! site should treat as a red flag to review.

use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};

/// How the bearer token is obtained. This is what a [`crate::context::Context`]
/// stores — never the token itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthSource {
    /// No credential (anonymous). Requests that require auth will be rejected
    /// by the server; used for local unauthenticated dev gateways.
    #[default]
    None,
    /// Read the token from a named environment variable at call time. This is
    /// the recommended default for scripting: the secret lives in the
    /// process environment, never on disk.
    Env {
        /// Environment variable name holding the bearer token.
        var: String,
    },
    /// Read the token from stdin (e.g. piped from a secret manager). Consumed
    /// once per invocation.
    Stdin,
    /// An inline literal token. Supported for completeness but discouraged for
    /// stored contexts because it lands the secret in the config file; a
    /// stored inline token is a review smell, not a default.
    Inline {
        /// The literal bearer token.
        token: String,
    },
}

impl AuthSource {
    /// The canonical environment variable the CLI reads when a context selects
    /// [`AuthSource::Env`] without naming one, and the conventional default
    /// used by `--token-env` shorthand.
    pub const DEFAULT_TOKEN_VAR: &'static str = "FERROGATE_TOKEN";

    /// Whether this source can ever yield a token. `None` cannot.
    pub fn is_anonymous(&self) -> bool {
        matches!(self, AuthSource::None)
    }

    /// A short, secret-free label for diagnostics and `context show`.
    pub fn describe(&self) -> String {
        match self {
            AuthSource::None => "none (anonymous)".to_string(),
            AuthSource::Env { var } => format!("env:{var}"),
            AuthSource::Stdin => "stdin".to_string(),
            AuthSource::Inline { .. } => "inline (redacted)".to_string(),
        }
    }
}

/// A resolved bearer token that refuses to print itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    token: String,
}

impl Credential {
    /// Wrap a raw token. Rejects empty/whitespace-only tokens so a blank
    /// environment variable becomes an actionable auth error instead of a
    /// silently unauthenticated request.
    pub fn new(token: impl Into<String>) -> CliResult<Credential> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(CliError::auth(
                "resolved an empty credential; the configured token source produced no token",
            ));
        }
        Ok(Credential { token })
    }

    /// The `Authorization` header value for this credential.
    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Expose the raw token. Named loudly on purpose: every call site is a
    /// place a secret can leak.
    pub fn expose(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted credential>")
    }
}

/// Injected inputs for credential resolution, so resolution is a pure function
/// of its inputs and unit tests never touch real env/stdin.
pub trait SecretResolver {
    /// Look up an environment variable by name.
    fn env(&self, name: &str) -> Option<String>;
    /// Read the full contents of stdin (used once per invocation).
    fn read_stdin(&self) -> CliResult<String>;
}

/// Resolve an [`AuthSource`] into an optional [`Credential`].
///
/// Returns `Ok(None)` only for [`AuthSource::None`]; every other source must
/// yield a non-empty token or fail with an auth-class error. Precedence
/// between sources is intentionally *not* decided here — the caller has
/// already collapsed flag/env/context precedence into a single chosen
/// `AuthSource` via [`crate::context::resolve`]; this function honours exactly
/// that one source, so credential selection stays deterministic and auditable.
pub fn resolve_credential(
    source: &AuthSource,
    resolver: &dyn SecretResolver,
) -> CliResult<Option<Credential>> {
    match source {
        AuthSource::None => Ok(None),
        AuthSource::Env { var } => {
            let raw = resolver.env(var).ok_or_else(|| {
                CliError::auth(format!(
                    "credential source is env:{var} but {var} is not set in the environment"
                ))
            })?;
            Ok(Some(Credential::new(raw)?))
        }
        AuthSource::Stdin => {
            let raw = resolver.read_stdin()?;
            Ok(Some(Credential::new(raw.trim())?))
        }
        AuthSource::Inline { token } => Ok(Some(Credential::new(token.clone())?)),
    }
}

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
