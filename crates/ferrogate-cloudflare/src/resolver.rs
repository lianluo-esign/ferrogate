// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token-resolver seam for Cloudflare API credentials (env/plaintext here; cf:// is a permanent crate-boundary rejection).

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
//! The `cf://` scheme (Cloudflare Secrets Store) is **permanently out of this
//! crate's scope** — not a deferral. `EnvTokenResolver` rejects it with a typed
//! [`CloudflareError::TokenResolution`] that says why and what to write
//! instead. Three independent reasons, none of which time out:
//!
//! 1. **Dependency direction.** `cf://` resolution lives in
//!    `ferrogate-secrets` (`SecretRef::CfSecret` + `SecretResolverRegistry`,
//!    issue #417), and that crate already depends on this one for its API
//!    client. Resolving `cf://` here would require the reverse edge — a cycle.
//! 2. **Secrets Store values are write-only over REST** (decision #423). The
//!    REST surface this client speaks cannot read a value back at all, so
//!    there is no implementation to defer to; values arrive only via a Workers
//!    binding, which reaches a process as an ordinary environment variable.
//! 3. **Bootstrap circularity.** The credential in question is the token that
//!    authenticates *to* the Cloudflare API, so sourcing it from a Cloudflare
//!    API-managed store cannot bootstrap itself.
//!
//! An operator inside a Worker-bound runtime writes
//! `env://FERROGATE_CF_SECRET_<NAME>` (the binding variable the
//! `ferrogate-secrets` convention exports); everyone else writes `env://VAR`.
//! A future `TokenResolver` impl for any other backend still slots in without
//! touching a consumer of this trait — the seam is unchanged.

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

        // Permanent crate boundary, not a deferral — see the module docs.
        // `cf://` is owned by `ferrogate-secrets`, which depends on this crate;
        // resolving it here would invert that edge.
        if reference.starts_with("cf://") {
            return Err(CloudflareError::TokenResolution(
                "cf:// (Cloudflare Secrets Store) token references are not resolvable by \
                 ferrogate-cloudflare, and will not become so: cf:// is owned by the \
                 ferrogate-secrets SecretResolverRegistry, which already depends on this crate \
                 (resolving it here would be a dependency cycle); Secrets Store values are \
                 write-only over the REST API this client speaks, so a value only ever reaches a \
                 process through a Workers binding; and a token that authenticates to the \
                 Cloudflare API cannot be bootstrapped from a Cloudflare API-managed store. \
                 Write env://FERROGATE_CF_SECRET_<NAME> to read a Worker-bound Secrets Store \
                 value, or env://VAR / an inline token otherwise — see \
                 docs/cloudflare-secrets-resolution.md"
                    .to_string(),
            ));
        }

        // No recognised scheme: treat as an inline plaintext token.
        Ok(ResolvedToken::new(reference))
    }
}
