// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Cloudflare Secrets Store
// REST backend for cf:// secret references — write/manage + existence checks
// (issues #417, #423).

//! Cloudflare Secrets Store REST backend for `cf://` references (issue #417),
//! scoped by decision #423.
//!
//! Cloudflare Secrets Store secret **values are write-only over REST**: no
//! endpoint returns a stored value; values are only readable by a Worker the
//! secret is bound to at runtime. This module therefore implements the
//! *manage plane* — create/write secrets plus existence checks — and never
//! value retrieval. Load-time value resolution for `cf://` references happens
//! through the Worker-binding context in [`crate::CfSecretBindings`]
//! (decision #423, Option A); see `docs/cloudflare-secrets-resolution.md`.

use std::sync::Arc;

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpMethod,
};
use serde::Deserialize;

use crate::cloudflare_bindings::cf_binding_env_var;
use crate::{non_empty_env, SecretRef, SecretResolver};

/// Cloudflare Secrets Store **beta** capacity caps, per account. The resolver
/// surfaces these in its errors/docs rather than letting an operator discover
/// them via an opaque Cloudflare API rejection. See the resolver docs.
///
/// - At most **one** Secrets Store per account.
pub const CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT: usize = 1;
/// - At most **100** secrets per account.
pub const CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT: usize = 100;
/// - At most **1024 bytes** per secret value.
pub const CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES: usize = 1024;

/// Connection details for a Cloudflare Secrets Store, sourced from environment
/// variables (mirroring how [`crate::VaultConfig::from_env`] reads `VAULT_ADDR`
/// / `VAULT_TOKEN`) so the synchronous [`crate::SecretResolverRegistry::from_env`]
/// can enable the backend without threading the parsed `[cloudflare]` config
/// block through this crate. The same account id + token an operator writes
/// under `[cloudflare]` are exported here for the loader that constructs the
/// registry.
///
/// - `CLOUDFLARE_ACCOUNT_ID` — the account the Secrets Store lives in.
/// - `CLOUDFLARE_API_TOKEN` — a token with Secrets Store Read/Write.
/// - `CLOUDFLARE_API_BASE_URL` — optional `client/v4` base override (defaults
///   to the public Cloudflare API; handy for tests / self-hosted proxies).
#[derive(Debug, Clone)]
pub struct CfSecretsStoreConfig {
    pub account_id: String,
    pub api_token: String,
    pub api_base_url: Option<String>,
}

impl CfSecretsStoreConfig {
    /// Reads `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` (optionally
    /// `CLOUDFLARE_API_BASE_URL`). Returns `None` if either required value is
    /// unset/empty, so callers can treat "no Cloudflare Secrets Store
    /// configured" as a normal, non-error case (mirrors Vault).
    pub fn from_env() -> Option<Self> {
        let account_id = non_empty_env("CLOUDFLARE_ACCOUNT_ID")?;
        let api_token = non_empty_env("CLOUDFLARE_API_TOKEN")?;
        Some(Self {
            account_id,
            api_token,
            api_base_url: non_empty_env("CLOUDFLARE_API_BASE_URL"),
        })
    }
}

/// A Cloudflare Secrets Store list/detail item (`GET .../stores` and
/// `GET .../secrets`). Only the fields we match on are decoded; unknown fields
/// (timestamps, `status`, `comment`, `scopes`, …) are ignored. Note there is
/// deliberately **no** `value` field anywhere: the REST API never returns
/// secret values (they are write-only), so this backend never decodes one.
#[derive(Debug, Deserialize)]
struct CfNamedResource {
    id: String,
    #[serde(default)]
    name: String,
}

/// The write-side body for `POST .../secrets` (batch create). `value` is
/// write-only on Cloudflare's side. `scopes` is fixed to `["workers"]` (the
/// only scope Secrets Store currently supports).
#[derive(Debug, serde::Serialize)]
struct CfSecretCreate<'a> {
    name: &'a str,
    value: &'a str,
    scopes: [&'a str; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

/// Manages `cf://<store>/<name>` secrets against a Cloudflare Secrets Store
/// via the shared [`CloudflareClient`] (issue #417) — **write/manage-only**
/// by decision #423.
///
/// # Value retrieval is unsupported here — by design
///
/// Cloudflare Secrets Store secret **values are write-only** over REST: no
/// documented endpoint returns a value; the only consumption path is a
/// Workers binding at runtime. This resolver therefore walks only the
/// documented *metadata* read path — list stores → resolve the store id, list
/// secrets → resolve the secret id — and then:
///
/// - store or secret **absent** → `Ok(None)` ("not found", mirrors Vault), so
///   callers can distinguish a missing ref from a hard failure;
/// - secret **present** → a **precise error** pointing the operator at the
///   supported value paths (Worker binding via [`crate::CfSecretBindings`],
///   or a readable copy in Vault/env for self-hosted gateways), rather than
///   fabricating a value or silently returning "unset".
///
/// The [`crate::SecretResolverRegistry`] consults the Worker-binding context
/// **before** this backend, so in a properly-bound deployment resolve never
/// reaches this error. See `docs/cloudflare-secrets-resolution.md`.
///
/// # Beta caps
///
/// The Secrets Store beta caps an account at
/// [`CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT`] store,
/// [`CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT`] secrets, and
/// [`CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES`] per value. The
/// [`create_secret`](Self::create_secret) write path enforces the value-size
/// cap client-side before any network call, and documents the account-level
/// count caps (which Cloudflare enforces server-side).
pub struct CloudflareSecretResolver {
    client: CloudflareClient,
}

// `CloudflareClient` intentionally does not derive `Debug` (it holds redacted
// credential + transport seams), so provide a hand-written impl that satisfies
// the `SecretResolver: Debug` bound without leaking anything sensitive.
impl std::fmt::Debug for CloudflareSecretResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSecretResolver")
            .field("account_id", &self.client.account_id())
            .finish_non_exhaustive()
    }
}

impl CloudflareSecretResolver {
    /// Build a production resolver from account/token config: a real reqwest
    /// transport via [`CloudflareClient::new`]. The token is passed inline (the
    /// value already resolved from `CLOUDFLARE_API_TOKEN`) so no further token
    /// indirection is needed here.
    pub fn new(config: CfSecretsStoreConfig) -> AnyResult<Self> {
        let mut cf_config = CloudflareConfig::new(config.account_id, config.api_token);
        if let Some(base) = config.api_base_url {
            cf_config.api_base_url = base;
        }
        let client = CloudflareClient::new(cf_config, Arc::new(EnvTokenResolver::default()))
            .map_err(|error| {
                anyhow::anyhow!("failed to build Cloudflare Secrets Store client: {error}")
            })?;
        Ok(Self { client })
    }

    /// Assemble a resolver from an already-built [`CloudflareClient`] — the
    /// seam tests use to inject a scripted [`ferrogate_cloudflare::HttpTransport`]
    /// so resolution is exercised with no network.
    pub fn from_client(client: CloudflareClient) -> Self {
        Self { client }
    }

    /// Create (or overwrite) a secret value in the store — the **write** side
    /// of the manage plane (`POST .../secrets`). Enforces the beta value-size
    /// cap ([`CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES`]) client-side before any
    /// network call; the account-level 1-store / 100-secret caps are enforced
    /// by Cloudflare and surfaced verbatim through the returned error. Returns
    /// the new secret's id on success.
    pub fn create_secret(
        &self,
        store: &str,
        name: &str,
        value: &str,
        comment: Option<&str>,
    ) -> AnyResult<String> {
        if value.len() > CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES {
            bail!(
                "Cloudflare Secrets Store value for cf://{store}/{name} is {} bytes, exceeding the beta cap of {} bytes per secret value",
                value.len(),
                CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES
            );
        }
        if name.is_empty() {
            bail!("Cloudflare Secrets Store secret name must not be empty");
        }
        block_on_cloudflare(self.create_secret_async(store, name, value, comment))
    }

    async fn create_secret_async(
        &self,
        store: &str,
        name: &str,
        value: &str,
        comment: Option<&str>,
    ) -> AnyResult<String> {
        let store_id = self.resolve_store_id(store).await?.ok_or_else(|| {
            anyhow::anyhow!(
                "Cloudflare Secrets Store {store} not found (the beta allows {CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT} store per account)"
            )
        })?;
        let batch = [CfSecretCreate {
            name,
            value,
            scopes: ["workers"],
            comment,
        }];
        let body =
            serde_json::to_vec(&batch).context("failed to encode Secrets Store create body")?;
        let created: Vec<CfNamedResource> = self
            .client
            .request_json(
                HttpMethod::Post,
                &format!("accounts/{{account_id}}/secrets_store/stores/{store_id}/secrets"),
                Some(body),
                None,
            )
            .await
            .map_err(|error| {
                map_cf_error(
                    error,
                    &format!("failed to create Cloudflare secret cf://{store}/{name}"),
                )
            })?;
        created
            .into_iter()
            .next()
            .map(|resource| resource.id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cloudflare Secrets Store create for cf://{store}/{name} returned no secret id"
                )
            })
    }

    /// The async body of [`resolve`](SecretResolver::resolve), driven to
    /// completion by [`block_on_cloudflare`] from the synchronous trait method.
    ///
    /// This is an **existence check only** — the value itself is unreadable
    /// over REST (see the type-level docs), so a secret that exists surfaces a
    /// precise unsupported-resolve error pointing at the Worker-binding path.
    async fn resolve_async(&self, store: &str, name: &str) -> AnyResult<Option<String>> {
        let Some(store_id) = self.resolve_store_id(store).await? else {
            // Store absent → treat as "not found" so callers can distinguish a
            // missing ref from a hard failure (mirrors Vault's None-on-missing).
            return Ok(None);
        };
        let Some(secret_id) = self.resolve_secret_id(&store_id, name).await? else {
            return Ok(None);
        };
        let binding_env = cf_binding_env_var(name);
        bail!(
            "Cloudflare Secrets Store secret cf://{store}/{name} exists (id {secret_id}) but its \
             value cannot be read back: Secrets Store secret values are write-only over the REST \
             API and are only readable by a Worker the secret is bound to. Supported paths: \
             (1) Worker-binding resolution — bind the secret to the consuming Worker and expose \
             it to FerroGate via the {binding_env} environment variable or an injected binding \
             map (see docs/cloudflare-secrets-resolution.md); (2) for a self-hosted gateway, \
             keep a readable copy in HashiCorp Vault or the environment and reference it as \
             vault:// or env:// instead. FerroGate manages cf:// secrets over REST \
             (create/write) but will not fabricate a value."
        )
    }

    /// List stores and resolve `store` (a store id OR name) to a store id.
    async fn resolve_store_id(&self, store: &str) -> AnyResult<Option<String>> {
        let stores: Vec<CfNamedResource> = self
            .client
            .get_json("accounts/{account_id}/secrets_store/stores", None)
            .await
            .map_err(|error| map_cf_error(error, "failed to list Cloudflare Secrets Stores"))?;
        Ok(stores
            .into_iter()
            .find(|candidate| candidate.id == store || candidate.name == store)
            .map(|candidate| candidate.id))
    }

    /// List a store's secrets and resolve `name` to a secret id.
    async fn resolve_secret_id(&self, store_id: &str, name: &str) -> AnyResult<Option<String>> {
        let secrets: Vec<CfNamedResource> = self
            .client
            .get_json(
                &format!("accounts/{{account_id}}/secrets_store/stores/{store_id}/secrets"),
                None,
            )
            .await
            .map_err(|error| {
                map_cf_error(
                    error,
                    &format!("failed to list secrets in Cloudflare Secrets Store {store_id}"),
                )
            })?;
        Ok(secrets
            .into_iter()
            .find(|candidate| candidate.name == name)
            .map(|candidate| candidate.id))
    }
}

impl SecretResolver for CloudflareSecretResolver {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>> {
        let SecretRef::CfSecret { store, name } = reference else {
            bail!("CloudflareSecretResolver cannot resolve a non-cf:// reference: {reference:?}");
        };
        block_on_cloudflare(self.resolve_async(store, name))
    }
}

/// Attach context to a [`CloudflareError`] while flattening it into `anyhow`.
fn map_cf_error(error: CloudflareError, context: &str) -> anyhow::Error {
    anyhow::anyhow!("{context}: {error}")
}

/// Drive a Cloudflare (async) future to completion from a synchronous context.
///
/// The [`SecretResolver`] trait is synchronous, but [`CloudflareClient`] is
/// async (reqwest/tokio). A resolve can be invoked either outside any runtime
/// (CLI validation) or from within the gateway's async runtime, so we run the
/// future on a **dedicated thread with its own current-thread runtime**: this
/// never panics with "cannot start a runtime from within a runtime" and needs
/// no `Handle` to be in scope. The future is `Send` (the Cloudflare client and
/// all transports are `Send + Sync`), so moving it across the thread boundary
/// is sound.
fn block_on_cloudflare<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread runtime for Cloudflare Secrets Store resolve")
                    .block_on(future)
            })
            .join()
            .expect("Cloudflare Secrets Store resolver bridge thread panicked")
    })
}
