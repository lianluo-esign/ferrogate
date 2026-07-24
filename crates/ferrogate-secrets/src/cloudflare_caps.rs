// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Cloudflare Secrets Store
// beta-cap guardrails: fail-fast value-size + secret-count budget checks for
// the write/manage plane (issue #418).

//! Capacity guardrails for the Cloudflare Secrets Store write path (issue
//! #418).
//!
//! The Secrets Store beta caps an account at **1 store**, **100 secrets**, and
//! **1024 bytes** per secret value. Per the #418 tenancy decision
//! (`docs/cloudflare-secrets-tenancy.md`), FerroGate keeps only a bounded set
//! of *system/platform* secrets in the store — per-tenant credentials stay in
//! the existing readable backends — so the budget must never be consumed
//! silently. This module makes every write pay a fail-fast toll:
//!
//! - a value larger than the per-value byte cap errors precisely **before any
//!   API call** (no partial state, no opaque Cloudflare rejection);
//! - creating a **new** secret once the store already holds the full budget
//!   errors precisely, pointing at the tenancy doc (overwriting an existing
//!   name never consumes a slot and stays allowed);
//! - crossing a configurable soft threshold surfaces a
//!   [`CfSecretsCapacityWarning`] the caller logs, so operators see the
//!   ceiling approaching well before a hard failure.
//!
//! Thresholds default to the published beta caps and can be tuned through
//! environment variables (see [`CfSecretsCapacityPolicy::from_env`]) — e.g.
//! when Cloudflare lifts a cap at GA, or to reserve headroom below it.

use anyhow::{bail, Result as AnyResult};

use crate::cloudflare::{
    CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT, CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
};
use crate::non_empty_env;

/// Environment variable overriding the hard secret-count budget
/// (default [`CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT`]).
pub const CF_SECRETS_MAX_SECRETS_ENV: &str = "FERROGATE_CF_SECRETS_MAX_SECRETS";
/// Environment variable overriding the soft warning threshold
/// (default [`DEFAULT_CF_SECRETS_WARN_AT`]; clamped to the hard budget).
pub const CF_SECRETS_WARN_AT_ENV: &str = "FERROGATE_CF_SECRETS_WARN_AT";
/// Environment variable overriding the per-value byte cap
/// (default [`CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES`]).
pub const CF_SECRETS_MAX_VALUE_BYTES_ENV: &str = "FERROGATE_CF_SECRETS_MAX_VALUE_BYTES";

/// Default soft warning threshold: 90 of the 100-secret beta budget, i.e.
/// operators hear about the ceiling with 10 slots of headroom left.
pub const DEFAULT_CF_SECRETS_WARN_AT: usize = 90;

/// A soft-cap crossing on the secret-count budget: the write is allowed, but
/// the store is close enough to the hard budget that the operator should act
/// (prune stale secrets, or verify no per-tenant fan-out is leaking into the
/// store — see `docs/cloudflare-secrets-tenancy.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfSecretsCapacityWarning {
    /// Secrets the store will hold once this write lands.
    pub used_after_write: usize,
    /// The hard secret-count budget in force.
    pub max_secrets: usize,
    /// The soft threshold that was crossed.
    pub warn_at_secrets: usize,
}

impl std::fmt::Display for CfSecretsCapacityWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cloudflare Secrets Store is approaching its secret-count budget: {} of {} secrets \
             used after this write (soft warning threshold {}). Per-tenant credentials must not \
             fan out into the store — see docs/cloudflare-secrets-tenancy.md",
            self.used_after_write, self.max_secrets, self.warn_at_secrets
        )
    }
}

/// Fail-fast capacity thresholds enforced by
/// [`crate::CloudflareSecretResolver::create_secret`] before it touches the
/// Cloudflare API. Defaults mirror the published Secrets Store beta caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfSecretsCapacityPolicy {
    /// Hard budget for secrets in the account's store; creating a **new**
    /// secret at/above this count fails. Default
    /// [`CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT`] (100).
    pub max_secrets: usize,
    /// Soft threshold: a write that lands the store at/above this count
    /// succeeds but yields a [`CfSecretsCapacityWarning`]. Default
    /// [`DEFAULT_CF_SECRETS_WARN_AT`] (90); always clamped to `max_secrets`.
    pub warn_at_secrets: usize,
    /// Per-value byte cap. Default [`CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES`]
    /// (1024).
    pub max_value_bytes: usize,
}

impl Default for CfSecretsCapacityPolicy {
    fn default() -> Self {
        Self {
            max_secrets: CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT,
            warn_at_secrets: DEFAULT_CF_SECRETS_WARN_AT,
            max_value_bytes: CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
        }
    }
}

impl CfSecretsCapacityPolicy {
    /// Build a policy from the environment overrides
    /// ([`CF_SECRETS_MAX_SECRETS_ENV`], [`CF_SECRETS_WARN_AT_ENV`],
    /// [`CF_SECRETS_MAX_VALUE_BYTES_ENV`]), falling back to the beta-cap
    /// defaults for anything unset, non-numeric, or zero. `warn_at_secrets`
    /// is clamped to `max_secrets` so a raised hard budget cannot silently
    /// disable the warning, and a lowered one cannot leave the warning
    /// unreachable.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let max_secrets =
            positive_env_usize(CF_SECRETS_MAX_SECRETS_ENV).unwrap_or(defaults.max_secrets);
        let warn_at_secrets = positive_env_usize(CF_SECRETS_WARN_AT_ENV)
            .unwrap_or(defaults.warn_at_secrets)
            .min(max_secrets);
        let max_value_bytes =
            positive_env_usize(CF_SECRETS_MAX_VALUE_BYTES_ENV).unwrap_or(defaults.max_value_bytes);
        Self {
            max_secrets,
            warn_at_secrets,
            max_value_bytes,
        }
    }

    /// Fail fast on a value larger than the per-value byte cap — **before any
    /// network call**, so an operator learns the exact byte count and limit
    /// instead of decoding a Cloudflare API rejection. Values that cannot fit
    /// (PEM private keys, service-account JSON blobs, …) belong in the
    /// readable backends per `docs/cloudflare-secrets-tenancy.md`.
    pub fn check_value_size(&self, store: &str, name: &str, value: &str) -> AnyResult<()> {
        if value.len() > self.max_value_bytes {
            bail!(
                "Cloudflare Secrets Store value for cf://{store}/{name} is {} bytes, exceeding \
                 the {} cap of {} bytes per secret value; store oversized credentials (PEM keys, \
                 service-account JSON, …) in the readable backends instead — see \
                 docs/cloudflare-secrets-tenancy.md",
                value.len(),
                if self.max_value_bytes == CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES {
                    "beta"
                } else {
                    "configured"
                },
                self.max_value_bytes
            );
        }
        Ok(())
    }

    /// Enforce the secret-count budget for a write into a store currently
    /// holding `existing_secret_count` secrets, `name_already_exists` telling
    /// whether the write overwrites an existing name (which consumes no new
    /// slot) or creates a new one.
    ///
    /// - New secret with the hard budget already consumed → precise error,
    ///   **before** the create request is issued.
    /// - Write landing the store at/above the soft threshold →
    ///   `Ok(Some(warning))` for the caller to log.
    /// - Otherwise → `Ok(None)`.
    pub fn check_secret_budget(
        &self,
        store: &str,
        name: &str,
        existing_secret_count: usize,
        name_already_exists: bool,
    ) -> AnyResult<Option<CfSecretsCapacityWarning>> {
        if !name_already_exists && existing_secret_count >= self.max_secrets {
            bail!(
                "cannot create Cloudflare secret cf://{store}/{name}: the store already holds \
                 {existing_secret_count} secrets, meeting the {} budget of {} secrets per \
                 account; free a slot or keep this credential in the readable backends — \
                 per-tenant credentials must never fan out into the store (see \
                 docs/cloudflare-secrets-tenancy.md)",
                if self.max_secrets == CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT {
                    "beta"
                } else {
                    "configured"
                },
                self.max_secrets
            );
        }
        let used_after_write = if name_already_exists {
            existing_secret_count
        } else {
            existing_secret_count + 1
        };
        if used_after_write >= self.warn_at_secrets {
            return Ok(Some(CfSecretsCapacityWarning {
                used_after_write,
                max_secrets: self.max_secrets,
                warn_at_secrets: self.warn_at_secrets,
            }));
        }
        Ok(None)
    }
}

/// Parse an environment variable as a positive integer; unset, empty,
/// non-numeric, and zero all yield `None` (→ the default applies).
fn positive_env_usize(name: &str) -> Option<usize> {
    non_empty_env(name)?
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
}
