// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Worker-binding value
// resolution for cf:// Cloudflare Secrets Store references (issue #423).

//! Worker-binding value resolution for `cf://` references (decision #423,
//! Option A).
//!
//! Cloudflare Secrets Store values are **write-only over REST** — the only
//! way a stored value reaches a consumer is a Workers binding at runtime.
//! This module is the Rust-side representation of that binding context: a
//! small name→value lookup consulted by
//! [`crate::SecretResolverRegistry::resolve`] **before** any REST call, so the
//! same `cf://<store>/<name>` reference in FerroGate config resolves:
//!
//! - **inside a Worker-bound runtime** — from the binding context, with zero
//!   network I/O and no Cloudflare API token needed; and
//! - **outside one** — never; the REST backend
//!   ([`crate::CloudflareSecretResolver`]) then surfaces a precise
//!   unsupported-resolve error pointing back here.
//!
//! Two injection paths feed the context:
//!
//! 1. **Environment convention** (always on, zero-config): the deployment glue
//!    that receives the Worker binding — a `wrangler.jsonc`
//!    `secrets_store_secrets` binding surfaced by the Worker/Container
//!    runtime, or any equivalent operator plumbing — exports the value as
//!    `FERROGATE_CF_SECRET_<NAME>`, where `<NAME>` is the secret's name
//!    uppercased with every non-alphanumeric character replaced by `_`
//!    ([`cf_binding_env_var`]). E.g. `cf://provider-keys/openai-api-key` reads
//!    `FERROGATE_CF_SECRET_OPENAI_API_KEY`.
//! 2. **Injected map** ([`CfSecretBindings::from_map`] /
//!    [`insert`](CfSecretBindings::insert)): embedding code that holds the
//!    binding values directly (e.g. Worker glue enumerating its env) hands
//!    them over keyed by secret name, checked before the env convention.
//!
//! Only the secret *name* keys the lookup — the store segment does not — since
//! the Secrets Store beta allows exactly one store per account
//! ([`crate::CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT`]); if that cap is
//! ever lifted the convention can grow a store qualifier without breaking
//! existing single-store deployments. See
//! `docs/cloudflare-secrets-resolution.md` for the full decision record.

use std::collections::HashMap;

use anyhow::{bail, Result as AnyResult};

use crate::{SecretRef, SecretResolver};

/// Prefix for the environment-variable convention by which a Worker-bound
/// Cloudflare secret value is exposed to FerroGate (see the module docs).
pub const CF_BINDING_ENV_PREFIX: &str = "FERROGATE_CF_SECRET_";

/// The environment variable that exposes a Worker-bound Cloudflare secret
/// value to FerroGate: [`CF_BINDING_ENV_PREFIX`] plus the secret name
/// uppercased, with every non-ASCII-alphanumeric character mapped to `_`.
///
/// `openai-api-key` → `FERROGATE_CF_SECRET_OPENAI_API_KEY`.
pub fn cf_binding_env_var(secret_name: &str) -> String {
    let mut variable = String::with_capacity(CF_BINDING_ENV_PREFIX.len() + secret_name.len());
    variable.push_str(CF_BINDING_ENV_PREFIX);
    for character in secret_name.chars() {
        if character.is_ascii_alphanumeric() {
            variable.push(character.to_ascii_uppercase());
        } else {
            variable.push('_');
        }
    }
    variable
}

/// The Worker-binding context for `cf://` value resolution: an injected
/// name→value map checked first, then the [`cf_binding_env_var`] environment
/// convention. The default (empty-map) context is always installed on
/// [`crate::SecretResolverRegistry`], so the env convention works with zero
/// configuration — mirroring how `env://` needs no setup.
#[derive(Debug, Default, Clone)]
pub struct CfSecretBindings {
    /// Explicitly injected binding values, keyed by secret name exactly as it
    /// appears in the `cf://<store>/<name>` reference.
    bindings: HashMap<String, String>,
}

impl CfSecretBindings {
    /// An empty binding context: only the environment convention applies.
    pub fn new() -> Self {
        Self::default()
    }

    /// A binding context seeded from values the embedding runtime already
    /// holds (e.g. Worker glue enumerating its secret bindings), keyed by
    /// secret name.
    pub fn from_map(bindings: HashMap<String, String>) -> Self {
        Self { bindings }
    }

    /// Add (or replace) one injected binding value.
    pub fn insert(&mut self, secret_name: impl Into<String>, value: impl Into<String>) {
        self.bindings.insert(secret_name.into(), value.into());
    }

    /// Look up a secret's bound value: the injected map first, then the
    /// [`cf_binding_env_var`] environment convention. Empty/whitespace values
    /// count as unset (matching [`crate::EnvSecretResolver`] semantics).
    pub fn lookup(&self, secret_name: &str) -> Option<String> {
        self.bindings
            .get(secret_name)
            .cloned()
            .or_else(|| std::env::var(cf_binding_env_var(secret_name)).ok())
            .filter(|value| !value.trim().is_empty())
    }
}

impl SecretResolver for CfSecretBindings {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>> {
        let SecretRef::CfSecret { name, .. } = reference else {
            bail!("CfSecretBindings cannot resolve a non-cf:// reference: {reference:?}");
        };
        Ok(self.lookup(name))
    }
}
