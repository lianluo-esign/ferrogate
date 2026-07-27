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
//!
//! # Aliasing: why the env convention only accepts canonical names
//!
//! [`cf_binding_env_var`] is a **lossy** mapping — it uppercases and collapses
//! every non-alphanumeric character to `_` — so `openai-api-key`,
//! `openai.api.key`, `openai_api_key` and `OpenAI-API-Key` are four *distinct*
//! Cloudflare secrets that all name `FERROGATE_CF_SECRET_OPENAI_API_KEY`.
//! Resolving all four from that one variable would let a `cf://` reference
//! silently hand back **a different credential than the operator named** — the
//! worst failure mode a secret resolver has.
//!
//! The mapping is injective exactly on the *canonical* name shape
//! `^[a-z0-9-]+$` ([`cf_binding_name_is_unambiguous`]): lowercase letters,
//! digits and `-` each land in a disjoint part of `[A-Z0-9_]`, so no two
//! distinct canonical names can collide. Every documented example
//! (`openai-api-key`) is canonical, and it matches Cloudflare's own naming
//! style.
//!
//! So the env convention is **restricted to canonical names**. A non-canonical
//! name is refused with a precise error naming the collision instead of being
//! resolved from an ambiguous variable. The lossless escape hatch is the
//! injected map ([`CfSecretBindings::from_map`] / [`insert`](CfSecretBindings::insert)),
//! which is keyed by the exact secret name and therefore works for any name
//! Cloudflare accepts.

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
///
/// This mapping is **lossy** and is only injective on canonical names — see
/// [`cf_binding_name_is_unambiguous`] and the module docs. It is exposed so
/// errors and docs can name the exact variable an operator has to set; it is
/// not, on its own, a safe lookup key.
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

/// Whether [`cf_binding_env_var`] is injective on `secret_name`, i.e. whether
/// no *other* secret name can produce the same environment variable.
///
/// True exactly for the canonical shape `^[a-z0-9-]+$`: lowercase ASCII
/// letters map 1:1 onto `A-Z`, digits onto themselves, and `-` onto `_`, three
/// disjoint image sets — so distinct canonical names always yield distinct
/// variables. Anything else (uppercase, `_`, `.`, `/`, spaces, non-ASCII)
/// collapses into the same image as some other name and is therefore ambiguous.
///
/// Only the environment convention needs this guard; the injected binding map
/// is keyed by the exact name and is lossless for any name.
pub fn cf_binding_name_is_unambiguous(secret_name: &str) -> bool {
    !secret_name.is_empty()
        && secret_name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// The Worker-binding context for `cf://` value resolution: an injected
/// name→value map checked first, then the [`cf_binding_env_var`] environment
/// convention. The default (empty-map) context is always installed on
/// [`crate::SecretResolverRegistry`], so the env convention works with zero
/// configuration — mirroring how `env://` needs no setup.
///
/// `Debug` is hand-written for the same reason [`crate::VaultConfig`]'s is
/// (issue #492): `bindings` holds **resolved plaintext secret values** — every
/// provider API key and OAuth client secret a Worker binding delivered. The
/// [`SecretResolver`] trait requires `Debug`, this type implements it, and
/// [`crate::SecretResolverRegistry`] derives `Debug` over a field of this type,
/// so a single `tracing::debug!(?registry)`, `{bindings:?}`, `unwrap()` panic
/// or failing assertion three levels up would otherwise spill every bound
/// credential in cleartext. Secret *names* are not secret (they are written
/// verbatim in config as `cf://<store>/<name>`), so they are rendered — a
/// redaction that leaves the operator unable to see which bindings arrived
/// would have traded a leak for an undiagnosable context.
#[derive(Default, Clone)]
pub struct CfSecretBindings {
    /// Explicitly injected binding values, keyed by secret name exactly as it
    /// appears in the `cf://<store>/<name>` reference.
    bindings: HashMap<String, String>,
}

impl std::fmt::Debug for CfSecretBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self.bindings.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("CfSecretBindings")
            .field("bound_secret_count", &self.bindings.len())
            .field("bound_secret_names", &names)
            .field("bound_secret_values", &"<redacted>")
            .finish()
    }
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

    /// Look up a secret's bound value: the injected map first (keyed by the
    /// **exact** name, so it is lossless), then the [`cf_binding_env_var`]
    /// environment convention. Empty/whitespace values count as unset
    /// (matching [`crate::EnvSecretResolver`] semantics).
    ///
    /// Returns `Err` — never a value — when `secret_name` is **not** canonical
    /// ([`cf_binding_name_is_unambiguous`]) and no exact injected binding
    /// exists, because the environment variable such a name would read is
    /// shared with other distinct secrets. Resolving it would risk serving a
    /// credential the operator did not name; failing loudly is the only safe
    /// outcome. See the module docs.
    pub fn lookup(&self, secret_name: &str) -> AnyResult<Option<String>> {
        // The injected map is keyed by the exact name — no collapsing, no
        // aliasing — so it is consulted first and is valid for *any* name
        // Cloudflare accepts. A present-but-empty binding still short-circuits
        // (an explicitly injected empty value means "unset", not "fall back").
        if let Some(value) = self.bindings.get(secret_name) {
            return Ok(Some(value.clone()).filter(|value| !value.trim().is_empty()));
        }
        if !cf_binding_name_is_unambiguous(secret_name) {
            let variable = cf_binding_env_var(secret_name);
            bail!(
                "cf:// secret name {secret_name:?} cannot be resolved from the Worker-binding \
                 environment convention: it is not canonical, so the variable it maps to \
                 ({variable}) is shared with other distinct Cloudflare secrets (e.g. \
                 openai-api-key, openai.api.key, openai_api_key and OpenAI-API-Key all map to \
                 FERROGATE_CF_SECRET_OPENAI_API_KEY) and reading it could return a credential \
                 you did not name. Fix by either (1) renaming the Secrets Store secret to the \
                 canonical shape [a-z0-9-]+ (e.g. openai-api-key) so the mapping is \
                 collision-free, or (2) injecting the value under its exact name via \
                 CfSecretBindings::from_map/insert + SecretResolverRegistry::with_cf_bindings, \
                 which is keyed exactly and never collapses. See \
                 docs/cloudflare-secrets-resolution.md"
            );
        }
        Ok(std::env::var(cf_binding_env_var(secret_name))
            .ok()
            .filter(|value| !value.trim().is_empty()))
    }
}

impl SecretResolver for CfSecretBindings {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>> {
        let SecretRef::CfSecret { name, .. } = reference else {
            bail!("CfSecretBindings cannot resolve a non-cf:// reference: {reference:?}");
        };
        self.lookup(name)
    }
}
