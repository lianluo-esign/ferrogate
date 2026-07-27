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
use crate::cloudflare_caps::CfSecretsCapacityPolicy;
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

/// Environment variable naming the Cloudflare account the Secrets Store lives
/// in.
pub const CF_ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
/// Environment variable holding a Cloudflare API token with Secrets Store
/// Read/Write. Its **value is never copied into any FerroGate struct** — see
/// [`CfSecretsStoreConfig::api_token_ref`].
pub const CF_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
/// Optional `client/v4` base override (defaults to the public Cloudflare API;
/// handy for tests / self-hosted proxies).
pub const CF_API_BASE_URL_ENV: &str = "CLOUDFLARE_API_BASE_URL";

/// Connection details for a Cloudflare Secrets Store, sourced from environment
/// variables (mirroring how [`crate::VaultConfig::from_env`] reads `VAULT_ADDR`
/// / `VAULT_TOKEN`) so the synchronous [`crate::SecretResolverRegistry::from_env`]
/// can enable the backend without threading the parsed `[cloudflare]` config
/// block through this crate.
///
/// - [`CF_ACCOUNT_ID_ENV`] — the account the Secrets Store lives in.
/// - [`CF_API_TOKEN_ENV`] — a token with Secrets Store Read/Write.
/// - [`CF_API_BASE_URL_ENV`] — optional `client/v4` base override.
///
/// # The token is held as a *reference*, never as a value
///
/// `api_token_ref` is a `ferrogate_cloudflare::TokenResolver` reference
/// (`env://VAR`, or an inline plaintext token for tests) — **not** the token
/// itself. [`from_env`](Self::from_env) only *probes* [`CF_API_TOKEN_ENV`] for
/// presence and stores `env://CLOUDFLARE_API_TOKEN`; the live token is
/// materialized by `EnvTokenResolver` at the moment the `Authorization` header
/// is written, exactly as #405 designed. That keeps a live CF API token out of
/// this struct, out of the `Debug + Serialize`
/// [`ferrogate_cloudflare::CloudflareConfig`] it is copied into, and makes
/// token rotation take effect without rebuilding the client.
///
/// `Debug` is hand-written anyway (issue #492's pattern, as for
/// [`crate::VaultConfig`]): a caller may still construct this type with an
/// inline plaintext token, and that must not be printable. A recognised
/// non-secret `env://` reference *is* rendered, because redacting it would
/// leave the operator unable to see which variable the client will read.
#[derive(Clone)]
pub struct CfSecretsStoreConfig {
    pub account_id: String,
    /// A token *reference*, not a token. See the type docs.
    pub api_token_ref: String,
    pub api_base_url: Option<String>,
}

impl std::fmt::Debug for CfSecretsStoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `env://VAR` names a variable, not a credential — safe and useful to
        // print. Anything else may be an inline plaintext token.
        let token_ref: &dyn std::fmt::Debug = if self.api_token_ref.starts_with("env://") {
            &self.api_token_ref
        } else {
            &"<redacted inline token>"
        };
        f.debug_struct("CfSecretsStoreConfig")
            .field("account_id", &self.account_id)
            .field("api_token_ref", token_ref)
            .field("api_base_url", &self.api_base_url)
            .finish()
    }
}

impl CfSecretsStoreConfig {
    /// Reads [`CF_ACCOUNT_ID_ENV`] and probes [`CF_API_TOKEN_ENV`] (optionally
    /// [`CF_API_BASE_URL_ENV`]). Returns `None` if either required value is
    /// unset/empty, so callers can treat "no Cloudflare Secrets Store
    /// configured" as a normal, non-error case (mirrors Vault).
    ///
    /// The token variable is checked for presence only — its **value is never
    /// read into the returned struct**; `api_token_ref` is the reference
    /// `env://CLOUDFLARE_API_TOKEN`, resolved per request downstream.
    pub fn from_env() -> Option<Self> {
        let account_id = non_empty_env(CF_ACCOUNT_ID_ENV)?;
        // Presence probe only: the value is deliberately dropped here.
        non_empty_env(CF_API_TOKEN_ENV)?;
        Some(Self {
            account_id,
            api_token_ref: format!("env://{CF_API_TOKEN_ENV}"),
            api_base_url: non_empty_env(CF_API_BASE_URL_ENV),
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
#[derive(serde::Serialize)]
struct CfSecretCreate<'a> {
    name: &'a str,
    value: &'a str,
    scopes: [&'a str; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

/// Hand-written so the secret being WRITTEN cannot reach a log line, an
/// `anyhow` chain or a panic message (#417 review item 1; same precedent as
/// #489/#492 and as `CfSecretsStoreConfig` in this file).
///
/// This is the request body of the write path, so it carries the plaintext at
/// the one moment FerroGate holds it deliberately. `value_len` is kept because
/// the beta cap is a byte limit and "which secret was too large" is the
/// question an operator actually asks.
impl std::fmt::Debug for CfSecretCreate<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CfSecretCreate")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("value_len", &self.value.len())
            .field("scopes", &self.scopes)
            .field("comment", &self.comment)
            .finish()
    }
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
/// [`create_secret`](Self::create_secret) write path enforces both fail-fast
/// through the attached [`CfSecretsCapacityPolicy`] (issue #418): the
/// value-size cap client-side before any network call, and the secret-count
/// budget (hard error for a new secret at the budget, soft warning near it)
/// against the store's current secret listing — instead of letting Cloudflare
/// reject the write server-side with an opaque error. See
/// `docs/cloudflare-secrets-tenancy.md` for the tenancy decision the budget
/// protects.
pub struct CloudflareSecretResolver {
    client: CloudflareClient,
    capacity: CfSecretsCapacityPolicy,
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
    /// transport via [`CloudflareClient::new`].
    ///
    /// The token **reference** — not the token — is what lands in
    /// [`CloudflareConfig`] (whose `api_token` field is documented as a
    /// reference and which derives `Debug + Serialize`). The attached
    /// [`EnvTokenResolver`] materializes the live token per request, at the
    /// `Authorization` header and nowhere else, so no plaintext CF API token is
    /// ever reachable from a `{:?}` or a serialization of this resolver's
    /// config (issue #492's rule; #405's `TokenResolver` seam).
    pub fn new(config: CfSecretsStoreConfig) -> AnyResult<Self> {
        let mut cf_config = CloudflareConfig::new(config.account_id, config.api_token_ref);
        if let Some(base) = config.api_base_url {
            cf_config.api_base_url = base;
        }
        let client = CloudflareClient::new(cf_config, Arc::new(EnvTokenResolver::default()))
            .map_err(|error| {
                anyhow::anyhow!("failed to build Cloudflare Secrets Store client: {error}")
            })?;
        Ok(Self {
            client,
            capacity: CfSecretsCapacityPolicy::from_env(),
        })
    }

    /// Assemble a resolver from an already-built [`CloudflareClient`] — the
    /// seam tests use to inject a scripted [`ferrogate_cloudflare::HttpTransport`]
    /// so resolution is exercised with no network. Uses the default (beta-cap)
    /// [`CfSecretsCapacityPolicy`]; override with
    /// [`with_capacity_policy`](Self::with_capacity_policy).
    pub fn from_client(client: CloudflareClient) -> Self {
        Self {
            client,
            capacity: CfSecretsCapacityPolicy::default(),
        }
    }

    /// Replace the capacity guardrail policy enforced by
    /// [`create_secret`](Self::create_secret).
    pub fn with_capacity_policy(mut self, capacity: CfSecretsCapacityPolicy) -> Self {
        self.capacity = capacity;
        self
    }

    /// The shared Cloudflare API client backing this resolver. Exposed so
    /// callers (and the tests that pin the "reference, never a token value"
    /// invariant on [`CloudflareClient::config`]) can inspect the client's
    /// configuration; `CloudflareClient` itself holds no plaintext credential.
    pub fn client(&self) -> &CloudflareClient {
        &self.client
    }

    /// Create (or overwrite) a secret value in the store — the **write** side
    /// of the manage plane (`POST .../secrets`). Guardrails (issue #418) run
    /// fail-fast through the attached [`CfSecretsCapacityPolicy`]:
    ///
    /// 1. value-size check **before any network call** — an oversized value
    ///    errors with its exact byte count and the cap in force;
    /// 2. secret-count budget check against the store's current listing —
    ///    creating a **new** secret with the budget already consumed errors
    ///    before the create request is issued (overwriting an existing name
    ///    consumes no slot and stays allowed), and a write landing near the
    ///    budget logs a capacity warning.
    ///
    /// Returns the new secret's id on success.
    pub fn create_secret(
        &self,
        store: &str,
        name: &str,
        value: &str,
        comment: Option<&str>,
    ) -> AnyResult<String> {
        self.capacity.check_value_size(store, name, value)?;
        if name.is_empty() {
            bail!("Cloudflare Secrets Store secret name must not be empty");
        }
        // #417 review item 2: the aliasing guard was read-side only, so
        // FerroGate itself could write `openai_api_key` into a store already
        // holding `openai-api-key`. Both export to
        // FERROGATE_CF_SECRET_OPENAI_API_KEY, and the CANONICAL reference --
        // which sails past the read-side guard -- then reads whichever the
        // deploy glue exported last. The read guard refuses a non-canonical
        // *reference*; it cannot tell that the variable a canonical reference
        // reads was written by a non-canonical sibling. Refusing the write is
        // what makes the read guard's premise true.
        //
        // It also stops the write path minting secrets the resolver is then
        // guaranteed to refuse to read.
        if !crate::cloudflare_bindings::cf_binding_name_is_unambiguous(name) {
            bail!(
                "Cloudflare Secrets Store secret name {name:?} is not canonical: it must match \
                 [a-z0-9-]+ so that exactly one secret maps to \
                 {prefix}{upper}. Writing a non-canonical name would let it \
                 collide with a canonical sibling under the same environment variable, and the \
                 resolver would refuse to read it back",
                prefix = crate::cloudflare_bindings::CF_BINDING_ENV_PREFIX,
                upper = name.to_ascii_uppercase().replace('-', "_"),
            );
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
        // Secret-count budget guardrail (issue #418): reuse the existing
        // manage-plane listing to count the store's secrets and detect whether
        // this write overwrites an existing name (no new slot) or creates a
        // new one — and fail fast / warn per the capacity policy BEFORE the
        // create request is issued.
        let existing = self.list_secrets(&store_id).await?;
        let name_already_exists = existing.iter().any(|candidate| candidate.name == name);
        if let Some(warning) =
            self.capacity
                .check_secret_budget(store, name, existing.len(), name_already_exists)?
        {
            tracing::warn!(
                used_after_write = warning.used_after_write,
                max_secrets = warning.max_secrets,
                warn_at_secrets = warning.warn_at_secrets,
                "{warning}"
            );
        }
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

    /// List a store's secrets (metadata only — ids and names, never values).
    /// Shared by the existence check ([`resolve_secret_id`](Self::resolve_secret_id))
    /// and the #418 secret-count budget guardrail in the write path.
    async fn list_secrets(&self, store_id: &str) -> AnyResult<Vec<CfNamedResource>> {
        self.client
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
            })
    }

    /// List a store's secrets and resolve `name` to a secret id.
    async fn resolve_secret_id(&self, store_id: &str, name: &str) -> AnyResult<Option<String>> {
        Ok(self
            .list_secrets(store_id)
            .await?
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
