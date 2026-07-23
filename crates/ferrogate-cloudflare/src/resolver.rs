// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token-resolver seam for Cloudflare API credentials (env/plaintext now, cf:// deferred to #417).

//! Token resolution seam (issue #405).
//!
//! A Cloudflare API token is *referenced* in config, never necessarily stored
//! inline. [`TokenResolver`] is the seam that turns a reference string into the
//! actual secret at request time. This crate ships one implementation,
//! [`EnvTokenResolver`], covering the two backends that need no external
//! infrastructure:
//!
//! - `env://VAR_NAME` — read the token from an environment variable.
//! - anything without a recognised `scheme://` prefix — treated as an inline
//!   plaintext token (convenient for tests / dev; discouraged for prod).
//!
//! The `cf://` scheme (Cloudflare Secrets Store) is a **separate sub-issue
//! (#417)** and is deliberately NOT implemented here. It is left as a clearly
//! documented extension point: `EnvTokenResolver` returns a typed
//! [`CloudflareError::TokenResolution`] naming #417, and a future
//! `CfSecretsStoreResolver` can implement [`TokenResolver`] without touching
//! any consumer of this trait.

use std::fmt;

use crate::error::CloudflareError;

/// A resolved secret token. `Debug` is redacted so a token never lands in a
/// log line or panic message by accident; use [`expose`](Self::expose) at the
/// exact call site that needs the bytes.
#[derive(Clone)]
pub struct ResolvedToken(String);

impl ResolvedToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Borrow the raw token. Only call this immediately before handing it to
    /// the HTTP `Authorization` header.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResolvedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvedToken(<redacted>)")
    }
}

/// The seam every Cloudflare credential backend implements.
///
/// Implementations MUST be side-effect-free beyond reading the referenced
/// secret, and MUST NOT log the resolved value. The client resolves a token
/// per request (cheap for env/plaintext) so tenant overrides and rotation take
/// effect without rebuilding the client.
pub trait TokenResolver: Send + Sync {
    /// Resolve `reference` (an `env://…`, `cf://…`, or inline plaintext string)
    /// into a [`ResolvedToken`], or a typed error explaining why it could not.
    fn resolve(&self, reference: &str) -> Result<ResolvedToken, CloudflareError>;
}

/// An environment-variable lookup: name -> value. The default reads the
/// process environment; tests inject a closure so resolution is exercised
/// without mutating `std::env`.
type EnvLookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The default resolver: `env://` + inline plaintext. `cf://` is rejected with
/// a pointer to #417.
///
/// A custom `getenv` can be injected for tests so environment resolution is
/// exercised without mutating the process environment.
pub struct EnvTokenResolver {
    getenv: EnvLookup,
}

impl Default for EnvTokenResolver {
    fn default() -> Self {
        Self::from_process_env()
    }
}

impl EnvTokenResolver {
    /// Resolver backed by the real process environment.
    pub fn from_process_env() -> Self {
        Self {
            getenv: Box::new(|name| std::env::var(name).ok()),
        }
    }

    /// Resolver with an injected environment lookup (test seam).
    pub fn with_env_lookup<F>(getenv: F) -> Self
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        Self {
            getenv: Box::new(getenv),
        }
    }
}

impl TokenResolver for EnvTokenResolver {
    fn resolve(&self, reference: &str) -> Result<ResolvedToken, CloudflareError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(CloudflareError::TokenResolution(
                "empty Cloudflare API token reference".to_string(),
            ));
        }

        if let Some(name) = reference.strip_prefix("env://") {
            let name = name.trim();
            if name.is_empty() {
                return Err(CloudflareError::TokenResolution(
                    "env:// token reference requires a variable name, e.g. env://CF_API_TOKEN"
                        .to_string(),
                ));
            }
            return match (self.getenv)(name) {
                Some(value) if !value.trim().is_empty() => Ok(ResolvedToken::new(value)),
                Some(_) => Err(CloudflareError::TokenResolution(format!(
                    "environment variable {name} is set but empty"
                ))),
                None => Err(CloudflareError::TokenResolution(format!(
                    "environment variable {name} referenced by env://{name} is not set"
                ))),
            };
        }

        // Extension point (#417): the Cloudflare Secrets Store backend. Left
        // unimplemented on purpose so this foundation crate carries no cf://
        // storage logic; a `CfSecretsStoreResolver` will slot in here.
        if reference.starts_with("cf://") {
            return Err(CloudflareError::TokenResolution(
                "cf:// (Cloudflare Secrets Store) token references are not yet supported; \
                 that backend is deferred to issue #417 — use env:// or an inline token for now"
                    .to_string(),
            ));
        }

        // No recognised scheme: treat as an inline plaintext token.
        Ok(ResolvedToken::new(reference))
    }
}
