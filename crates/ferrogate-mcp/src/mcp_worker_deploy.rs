// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Deploy/status/teardown pipeline for the FerroGate-hosted MCP server Worker
//   (issue #409): constructs the Workers Script PUT (module + metadata declaring the McpAgent
//   Durable Object binding, the OAUTH_KV binding, and the SQLite DO migration) and drives
//   status/list/teardown against the #405 ferrogate-cloudflare transport seam (fully mockable).

//! Deploy / status / teardown pipeline for the FerroGate-hosted MCP server
//! Worker (issue #409).
//!
//! This is the Rust side of standing up a tenant's **own** MCP server on
//! Cloudflare (the inverse of consuming CF's MCP servers, #408): it gets
//! [`workers/mcp-server`](../../../../workers/mcp-server) — an Agents SDK
//! `McpAgent` Durable Object mounted at `/mcp` with an OAuth provider — onto
//! Cloudflare and tears it back down.
//!
//! ## What it constructs
//!
//! A module-Worker upload is a **`multipart/form-data` `PUT`** to
//! `PUT /accounts/{account_id}/workers/scripts/{script_name}` carrying:
//!
//! - a `metadata` part (JSON): `main_module`, the **Durable Object binding** for
//!   the `McpAgent` session class, the **`kv_namespace` binding** the OAuth
//!   provider persists grants in (`OAUTH_KV`), any **`secrets_store_secret`
//!   bindings** (see below), the DO **`migrations`** (`new_sqlite_classes` — the
//!   Agents SDK stores session state in an embedded per-instance SQLite DB),
//!   `compatibility_date`, `compatibility_flags`, and `keep_bindings`;
//! - one module part carrying the Worker's ES-module source.
//!
//! ## Secrets: the `cf://` Secrets Store seam (#423)
//!
//! Cloudflare Secrets Store values are write-only over REST — the only way one
//! reaches a consumer is a Worker binding. [`McpWorkerSpec::secrets_store_bindings`]
//! puts that binding in the deploy metadata, so the Worker's automation bearer
//! is sourced from the account's Secrets Store instead of being seeded by hand.
//! Binding names are validated against the canonical
//! [`ferrogate_secrets::cf_binding_name_is_unambiguous`] shape so the *same*
//! secret stays addressable as `cf://<store>/<name>` from the Rust side (where
//! the `FERROGATE_CF_SECRET_*` env convention is lossy for non-canonical names).
//!
//! ## `keep_bindings`: why a redeploy does not strip `wrangler secret put`
//!
//! A Workers Script-API `PUT` replaces the script's **entire** binding set. A
//! `secret_text` binding seeded out of band (`wrangler secret put
//! MCP_BEARER_TOKEN`) is therefore silently removed by the next deploy through
//! this pipeline — disabling the automation path — unless the upload asks
//! Cloudflare to preserve it. [`McpWorkerSpec::keep_bindings`] carries that
//! list, defaulting to `["secret_text"]`.
//!
//! [`McpWorkerSpec`] models that upload and produces the metadata JSON, the
//! multipart body, and the content type **deterministically** (fixed boundary)
//! so the exact request is unit-assertable. Teardown is a plain
//! `DELETE /accounts/{account_id}/workers/scripts/{script_name}`.
//!
//! ## The transport seam (why it is mockable)
//!
//! [`McpWorkerDeployer`] talks to Cloudflare through the **#405
//! [`HttpTransport`]** + [`TokenResolver`] seams — the same ones
//! [`ferrogate_cloudflare::CloudflareClient`] is built on. The **read** side
//! (`status`/`list`, plain enveloped GETs) is served by building a
//! [`CloudflareClient`] from those parts and calling
//! [`CloudflareClient::get_json`], directly consuming the #405 client. The
//! **write** side (`deploy`/`teardown`) issues the request through the transport
//! directly (see the multipart caveat below). Tests inject a scripted transport
//! + inline-token resolver and assert the constructed request with zero network.
//!
//! ## Relationship to the #413 agent-gateway deployer (duplication note)
//!
//! The multipart script-upload construction here **intentionally duplicates** the
//! shape of `ferrogate_runtime::cloudflare_gateway_deploy` (#413).
//!
//! **Correction (#409 review, 2026-07-25):** an earlier revision of this note
//! justified the copy with "a dependency cycle: runtime already depends on this
//! crate's siblings". **There is no cycle** — `ferrogate-runtime` depends on
//! `ferrogate-core` / `ferrogate-cloudflare` / `ferrogate-storage`, and the only
//! crates depending on `ferrogate-mcp` are `ferrogate-gateway` and
//! `ferrogate-config`. The real reason is narrower and weaker: `ferrogate-mcp`
//! should not take a dependency on a *sibling deployer* to reach ~60 lines of
//! multipart framing. With three Worker deployers now on `main` (#409, #411,
//! #413) the correct destination is the shared `WorkerScriptUpload` builder in
//! `ferrogate-cloudflare` — the extraction every one of them should move to,
//! not a fourth copy.
//!
//! ## Auth mode: authless vs OAuth
//!
//! [`McpWorkerSpec::auth_mode`] selects which front door the deployed Worker
//! puts in front of `/mcp` + `/sse`, and it is carried to the Worker as a
//! `plain_text` binding (`env.MCP_AUTH_MODE`) rather than by shipping a second
//! module: one template, two behaviours, so the two variants cannot drift apart.
//! [`McpAuthMode::Authless`] additionally **omits** the `OAUTH_KV` binding —
//! an authless deploy has no grants to persist, and emitting the binding with an
//! unset namespace id is exactly the deploy that fails at Cloudflare for a
//! reason unrelated to what the operator asked for.
//!
//! ## Registering the deployed server back as an upstream
//!
//! A deployed server is only useful once the gateway routes to it, so
//! [`McpWorkerSpec::upstream_config`] turns a spec (plus the account's
//! `workers.dev` subdomain) into the [`crate::McpServerConfig`] that registers
//! it as an MCP upstream — URL, transport, and an `auth_type` derived from the
//! deployed [`auth_mode`](McpWorkerSpec::auth_mode). It runs the gateway's own
//! [`crate::validate_mcp_server_config`] before returning, so "deployed" and
//! "routable" are proved by the same call instead of by two hopeful ones.
//!
//! ## Deliberately NOT in this module (open follow-ups on #409)
//!
//! - **Admin CRUD surface.** #409 asks for an admin API to create/update/delete
//!   a hosted MCP server and report its URL/status. That belongs in the admin
//!   HTTP layer (`ferrogate-cli`), not here: this module is the typed deploy
//!   seam it would call. Until that lands, the only callers of
//!   [`McpWorkerDeployer`] are tests — the pipeline is reachable from an
//!   operator only via a program that constructs it.
//! - **Live-account proof.** Every request here is construction-faithful and
//!   asserted offline; no `keep_bindings` / `secrets_store_secret` /
//!   `workers.dev`-subdomain response has been exercised against a real
//!   Cloudflare account. That is the test lane's to prove.
//!
//! ## Multipart content type
//!
//! The deploy `PUT` carries [`McpWorkerSpec::content_type`] (the
//! `multipart/form-data; boundary=…` value) on its [`HttpRequest`], and the #411
//! [`HttpRequest::content_type`] field is honored by
//! `ferrogate_cloudflare::ReqwestTransport` (which defaults to `application/json`
//! only when it is `None`). So the production multipart upload is sent with the
//! correct type end to end; the documented `wrangler deploy` shell-out
//! ([`McpWorkerSpec::wrangler_deploy_command`]) remains an equivalent CLI
//! fallback. The request *construction* is faithful and fully modeled/tested;
//! the live upload against real Cloudflare is the test agent's to prove.

use std::collections::HashSet;
use std::sync::Arc;

use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, CloudflareEnvelope, CloudflareError, HttpMethod,
    HttpRequest, HttpTransport, RetryPolicy, TokenResolver, TokioClock,
};
use serde::Deserialize;
use serde_json::json;

use crate::config::{
    validate_mcp_server_config, McpAuthType, McpHeaderConfig, McpServerConfig, McpTransport,
};

/// The fixed multipart boundary. A constant (not random) boundary keeps the
/// constructed request deterministic so tests can assert the exact bytes.
pub const MCP_MULTIPART_BOUNDARY: &str = "----FerroGateMcpServerBoundary";

/// Default deployed script name for the MCP server Worker. Matches the `name` in
/// `workers/mcp-server/wrangler.toml`.
pub const DEFAULT_MCP_SCRIPT_NAME: &str = "ferrogate-mcp-server";

/// Default `McpAgent` Durable Object class name (see the Worker source).
pub const DEFAULT_MCP_DO_CLASS: &str = "FerroGateMcp";

/// Default Durable Object binding name (`env.MCP_OBJECT`).
pub const DEFAULT_MCP_DO_BINDING: &str = "MCP_OBJECT";

/// Default KV binding name the OAuth provider persists grants in
/// (`env.OAUTH_KV`).
pub const DEFAULT_OAUTH_KV_BINDING: &str = "OAUTH_KV";

/// Default Worker binding name for the Secrets-Store-sourced automation bearer
/// (`env.MCP_BEARER_TOKEN_STORE`, read as `await binding.get()`).
///
/// Deliberately **not** `MCP_BEARER_TOKEN`: that name is the `secret_text`
/// binding a `wrangler secret put` seeds, and the Worker prefers the store
/// binding while still accepting the plain one (see `workers/mcp-server`).
pub const DEFAULT_MCP_BEARER_SECRET_BINDING: &str = "MCP_BEARER_TOKEN_STORE";

/// Default Worker binding name carrying the deployed auth mode
/// (`env.MCP_AUTH_MODE`, a `plain_text` binding — it holds no credential).
pub const DEFAULT_MCP_AUTH_MODE_BINDING: &str = "MCP_AUTH_MODE";

/// Default Cloudflare Secrets Store secret **name** holding the automation
/// bearer. Canonical (`^[a-z0-9-]+$`) so the same secret is also addressable as
/// `cf://<store>/mcp-bearer-token` from the Rust side without the
/// `FERROGATE_CF_SECRET_*` aliasing hazard (#423).
pub const DEFAULT_MCP_BEARER_SECRET_NAME: &str = "mcp-bearer-token";

/// Binding types a Workers Script-API `PUT` must be told to preserve rather than
/// replace. `secret_text` covers a `wrangler secret put`-seeded value, which the
/// upload body itself can never carry (the plaintext lives only in Cloudflare).
///
/// **`secrets_store_secret` is deliberately NOT in this list, and that has an
/// operator-visible consequence.** A `[[secrets_store_secrets]]` binding declared
/// only in `wrangler.toml` is erased by the next deploy through this pipeline
/// unless that deploy also declares it (see
/// [`McpWorkerSpec::with_bearer_token_from_secrets_store`]) — the Worker's
/// `env.MCP_BEARER_TOKEN_STORE` then becomes `undefined` and the automation path
/// silently degrades to OAuth-only.
///
/// It is excluded rather than added because adding it is unverifiable from here:
/// Cloudflare documents `keep_bindings` only for Workers for Platforms, its
/// multipart-upload-metadata reference does not list the key at all, and
/// `secrets_store_secret` does not appear among its binding-type examples. An
/// unrecognised value in `keep_bindings` risks a 400 on *every* upload — trading
/// a documented, one-line operator constraint for a chance of breaking the whole
/// deploy path. The constraint is therefore written down (`workers/mcp-server/
/// README.md`, `wrangler.toml`, `docs/cloudflare-mcp-hosting.md`) rather than
/// guessed at, and
/// `a_store_binding_declared_only_in_wrangler_toml_is_not_preserved_by_a_redeploy`
/// pins the behaviour so a future change to it is deliberate.
pub const DEFAULT_KEEP_BINDINGS: &[&str] = &["secret_text"];

/// Environment variable an OAuth-mode upstream registration reads the
/// `Authorization` header value from.
///
/// It carries the **complete header value**, i.e. `Bearer <token>`, not the bare
/// token: FerroGate's static-header config (`McpHeaderConfig::value_env`) is
/// substituted verbatim, so a bare token here would be sent as an
/// `Authorization: <token>` the Worker's `Bearer `-prefix gate rejects.
pub const MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV: &str = "FERROGATE_MCP_WORKER_AUTHORIZATION";

/// Which front door the deployed Worker puts in front of `/mcp` and `/sse`.
///
/// Carried to the Worker as the `env.MCP_AUTH_MODE` `plain_text` binding, so a
/// single template serves both variants #409 asks for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum McpAuthMode {
    /// OAuth 2.1 via `@cloudflare/workers-oauth-provider`, with the automation
    /// bearer as a machine-to-machine shortcut. Requires a KV namespace for
    /// grant persistence, so [`McpWorkerSpec::kv_namespace_id`] must be set.
    #[default]
    Oauth,
    /// No authentication at all: `/mcp` and `/sse` are served straight from the
    /// Durable Object. The reference variant for a private/dev deployment; it
    /// needs no KV namespace, and the deploy therefore omits that binding.
    Authless,
}

impl McpAuthMode {
    /// The wire value of the `MCP_AUTH_MODE` binding. The Worker compares
    /// against exactly this string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::Authless => "authless",
        }
    }

    /// Whether a deploy in this mode needs the `OAUTH_KV` binding.
    pub fn requires_oauth_kv(&self) -> bool {
        matches!(self, Self::Oauth)
    }
}

/// One Cloudflare **Secrets Store** binding to declare on the deployed Worker.
///
/// The runtime read is `await env.<binding_name>.get()` with **no** name
/// argument: `store_id` + `secret_name` are fixed at deploy time. A Worker
/// cannot bind a store and look secrets up by name, which is why every secret
/// the Worker needs is a separate binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSecretsStoreBinding {
    /// The Worker binding name (`env.<NAME>`).
    pub binding_name: String,
    /// The Secrets Store id the secret lives in.
    pub store_id: String,
    /// The secret's name within that store.
    pub secret_name: String,
}

impl McpSecretsStoreBinding {
    /// A binding for the automation bearer, using FerroGate's default binding
    /// and secret names, in the given store.
    pub fn bearer_token(store_id: impl Into<String>) -> Self {
        Self {
            binding_name: DEFAULT_MCP_BEARER_SECRET_BINDING.to_string(),
            store_id: store_id.into(),
            secret_name: DEFAULT_MCP_BEARER_SECRET_NAME.to_string(),
        }
    }

    /// Reject a binding that cannot be deployed or that would be ambiguous on
    /// the `cf://` side.
    ///
    /// The store id and secret name are required (Cloudflare rejects an empty
    /// one at deploy with an opaque error; failing here names the field). The
    /// secret name must additionally be **canonical** — see
    /// [`ferrogate_secrets::cf_binding_name_is_unambiguous`]: a non-canonical
    /// name deploys fine, but the identical secret then cannot be resolved
    /// through the `cf://` env convention from the Rust gateway, so FerroGate
    /// would have two spellings of "the same secret" that only agree by luck.
    pub fn validate(&self) -> Result<(), CloudflareError> {
        if self.wire_binding_name().is_empty() {
            return Err(CloudflareError::Config(
                "secrets-store binding name must not be empty".to_string(),
            ));
        }
        if self.wire_store_id().is_empty() {
            return Err(CloudflareError::Config(format!(
                "secrets-store binding {:?} has no store_id: create the store once \
                 (`wrangler secrets-store store create`) and set its id",
                self.wire_binding_name()
            )));
        }
        // Checked before the canonical-shape test below, which would otherwise
        // report an absent secret_name as "not the canonical [a-z0-9-]+ shape" —
        // misleading advice for a field that was simply never filled in.
        if self.wire_secret_name().is_empty() {
            return Err(CloudflareError::Config(format!(
                "secrets-store binding {:?} has no secret_name: name the secret within \
                 store {:?} (`wrangler secrets-store secret create <STORE_ID> --name <NAME>`)",
                self.wire_binding_name(),
                self.wire_store_id(),
            )));
        }
        if !ferrogate_secrets::cf_binding_name_is_unambiguous(self.wire_secret_name()) {
            return Err(CloudflareError::Config(format!(
                "secrets-store binding {:?} names secret {:?}, which is not the canonical \
                 [a-z0-9-]+ shape: the same secret would not be resolvable as \
                 cf://<store>/{} from the gateway, because the {} variable that name maps \
                 to is shared with other distinct secrets (see \
                 docs/cloudflare-secrets-resolution.md)",
                self.wire_binding_name(),
                self.wire_secret_name(),
                self.wire_secret_name(),
                ferrogate_secrets::cf_binding_env_var(self.wire_secret_name()),
            )));
        }
        Ok(())
    }

    /// The binding name as it reaches Cloudflare.
    ///
    /// Trimmed at the wire boundary, and every check in [`validate`](Self::validate)
    /// reads the same trimmed view: validating a trimmed value while sending the raw
    /// one is how `" store-9f3 "` passes here and comes back as an opaque
    /// Cloudflare 400 that names nothing.
    fn wire_binding_name(&self) -> &str {
        self.binding_name.trim()
    }

    /// The Secrets Store id as it reaches Cloudflare (see [`wire_binding_name`](Self::wire_binding_name)).
    fn wire_store_id(&self) -> &str {
        self.store_id.trim()
    }

    /// The secret name as it reaches Cloudflare (see [`wire_binding_name`](Self::wire_binding_name)).
    fn wire_secret_name(&self) -> &str {
        self.secret_name.trim()
    }

    /// The metadata `bindings[]` entry Cloudflare expects.
    fn metadata_entry(&self) -> serde_json::Value {
        json!({
            "type": "secrets_store_secret",
            "name": self.wire_binding_name(),
            "store_id": self.wire_store_id(),
            "secret_name": self.wire_secret_name(),
        })
    }
}

/// A modeled Workers Script-API upload for the FerroGate-hosted MCP server
/// Worker.
///
/// Everything needed to build the
/// `PUT /accounts/{account_id}/workers/scripts/{name}` multipart request: the
/// script name, the ES-module source, the `McpAgent` Durable Object binding +
/// SQLite migration, and the `OAUTH_KV` namespace binding the OAuth provider
/// requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpWorkerSpec {
    /// The deployed script name (the `{script_name}` path segment).
    pub script_name: String,
    /// The module filename referenced by `main_module` in the metadata.
    pub module_filename: String,
    /// The ES-module Worker source (bundled `src/index.ts`, or the raw module
    /// for `wrangler`-less uploads).
    pub module_source: String,
    /// The `McpAgent` Durable Object class name to bind.
    pub do_class_name: String,
    /// The Durable Object binding name (`env.<NAME>`).
    pub do_binding_name: String,
    /// The KV binding name the OAuth provider uses (`env.<NAME>`).
    pub kv_binding_name: String,
    /// Which front door the deployed Worker enforces. Defaults to
    /// [`McpAuthMode::Oauth`].
    pub auth_mode: McpAuthMode,
    /// The KV namespace **id** the binding points at. REQUIRED for a live
    /// deploy: create it once (`wrangler kv namespace create OAUTH_KV`) and set
    /// it here. Empty by default so an unset id is obvious in the metadata.
    pub kv_namespace_id: String,
    /// The DO migration tag (idempotency key for the migration).
    pub migration_tag: String,
    /// Worker compatibility date.
    pub compatibility_date: String,
    /// Worker compatibility flags.
    pub compatibility_flags: Vec<String>,
    /// Cloudflare Secrets Store bindings to declare on the script (#423 seam).
    /// Empty by default: the automation bearer is optional, and a binding that
    /// names a store the account does not have fails the deploy.
    pub secrets_store_bindings: Vec<McpSecretsStoreBinding>,
    /// Binding **types** Cloudflare must preserve across this upload rather
    /// than replace. Defaults to [`DEFAULT_KEEP_BINDINGS`]; see the module docs
    /// for why dropping it silently disables the automation bearer.
    pub keep_bindings: Vec<String>,
    /// The account's `workers.dev` subdomain, when known. Set it to have the
    /// pipeline report the deployed server's URL
    /// (`https://<script>.<subdomain>.workers.dev/mcp`) — the exact shape the
    /// #408 upstream detector accepts, so a deployed server can be registered
    /// back as an MCP upstream. Resolve it once with
    /// [`McpWorkerDeployer::workers_dev_subdomain`].
    pub workers_dev_subdomain: Option<String>,
}

impl McpWorkerSpec {
    /// A spec with FerroGate's defaults for the given module source. The
    /// `kv_namespace_id` starts empty — set it (or use
    /// [`with_kv_namespace_id`](Self::with_kv_namespace_id)) before a live
    /// deploy.
    pub fn new(module_source: impl Into<String>) -> Self {
        Self {
            script_name: DEFAULT_MCP_SCRIPT_NAME.to_string(),
            module_filename: "index.js".to_string(),
            module_source: module_source.into(),
            do_class_name: DEFAULT_MCP_DO_CLASS.to_string(),
            do_binding_name: DEFAULT_MCP_DO_BINDING.to_string(),
            kv_binding_name: DEFAULT_OAUTH_KV_BINDING.to_string(),
            auth_mode: McpAuthMode::default(),
            kv_namespace_id: String::new(),
            migration_tag: "v1".to_string(),
            compatibility_date: "2025-06-01".to_string(),
            compatibility_flags: vec!["nodejs_compat".to_string()],
            secrets_store_bindings: Vec::new(),
            keep_bindings: DEFAULT_KEEP_BINDINGS
                .iter()
                .map(|kind| (*kind).to_string())
                .collect(),
            workers_dev_subdomain: None,
        }
    }

    /// Builder: set the `OAUTH_KV` namespace id.
    pub fn with_kv_namespace_id(mut self, id: impl Into<String>) -> Self {
        self.kv_namespace_id = id.into();
        self
    }

    /// Builder: select the deployed front door.
    pub fn with_auth_mode(mut self, mode: McpAuthMode) -> Self {
        self.auth_mode = mode;
        self
    }

    /// Builder: deploy the authless variant ([`McpAuthMode::Authless`]).
    pub fn authless(self) -> Self {
        self.with_auth_mode(McpAuthMode::Authless)
    }

    /// The Durable Object binding name as it reaches Cloudflare (trimmed — see
    /// [`McpSecretsStoreBinding::wire_binding_name`]).
    fn wire_do_binding_name(&self) -> &str {
        self.do_binding_name.trim()
    }

    /// The `McpAgent` class name as it reaches Cloudflare. Trimmed, and the DO
    /// binding and the `new_sqlite_classes` migration must read the *same* view:
    /// a class name that disagrees between them declares a migration for a class
    /// nothing binds.
    fn wire_do_class_name(&self) -> &str {
        self.do_class_name.trim()
    }

    /// The KV binding name as it reaches Cloudflare (trimmed).
    fn wire_kv_binding_name(&self) -> &str {
        self.kv_binding_name.trim()
    }

    /// The KV namespace id as it reaches Cloudflare (trimmed).
    fn wire_kv_namespace_id(&self) -> &str {
        self.kv_namespace_id.trim()
    }

    /// Builder: declare one Secrets Store binding on the deployed Worker.
    pub fn with_secrets_store_binding(mut self, binding: McpSecretsStoreBinding) -> Self {
        self.secrets_store_bindings.push(binding);
        self
    }

    /// Builder: source the automation bearer from `store_id` under the default
    /// binding/secret names ([`McpSecretsStoreBinding::bearer_token`]).
    pub fn with_bearer_token_from_secrets_store(self, store_id: impl Into<String>) -> Self {
        self.with_secrets_store_binding(McpSecretsStoreBinding::bearer_token(store_id))
    }

    /// Builder: record the account's `workers.dev` subdomain so the pipeline can
    /// report the deployed [`mcp_endpoint_url`](Self::mcp_endpoint_url).
    pub fn with_workers_dev_subdomain(mut self, subdomain: impl Into<String>) -> Self {
        self.workers_dev_subdomain = Some(subdomain.into());
        self
    }

    /// The deployed MCP endpoint, or `None` when the account's `workers.dev`
    /// subdomain is not known to this spec.
    ///
    /// `None` rather than a guessed host: the subdomain is per-account and not
    /// derivable from the script name, and a wrong upstream URL registered on a
    /// tenant is worse than an absent one.
    pub fn mcp_endpoint_url(&self) -> Option<String> {
        self.workers_dev_subdomain
            .as_deref()
            .map(str::trim)
            .filter(|subdomain| !subdomain.is_empty())
            .map(|subdomain| {
                format!(
                    "https://{}.{}.workers.dev/mcp",
                    self.wire_script_name(),
                    subdomain
                )
            })
    }

    /// The script name as it reaches Cloudflare (trimmed): it is both a URL path
    /// segment and the deployed hostname label, so a stray space is a 404 rather
    /// than a validation error.
    pub fn wire_script_name(&self) -> &str {
        self.script_name.trim()
    }

    /// The MCP **upstream name** this deployed server registers under.
    ///
    /// Derived from the script name with `-` replaced by `_`, because FerroGate
    /// namespaces MCP tools as `serverName-toolName` and therefore refuses a
    /// server name containing `-` — while Cloudflare Worker script names
    /// conventionally use `-` (`ferrogate-mcp-server`). Without the mapping the
    /// default deploy could never be registered at all.
    pub fn upstream_name(&self) -> String {
        self.wire_script_name().replace('-', "_")
    }

    /// The [`McpServerConfig`] that registers this deployed server as an MCP
    /// upstream — the "once deployed, register it back" leg of #409.
    ///
    /// `tools_to_execute` is required by the caller because MCP execution is
    /// deny-by-default in FerroGate; pass `["*"]` to allow the Worker's whole
    /// tool surface.
    ///
    /// The `auth_type` follows the deployed [`auth_mode`](Self::auth_mode):
    ///
    /// - [`McpAuthMode::Authless`] → [`McpAuthType::None`], no headers.
    /// - [`McpAuthMode::Oauth`] → [`McpAuthType::SharedHeaders`] carrying an
    ///   `Authorization` header read from
    ///   [`MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV`]. That is the Worker's
    ///   automation-bearer shortcut, not the interactive OAuth flow: the gateway
    ///   calls this server machine-to-machine, and `McpAuthType::Oauth` is
    ///   rejected by [`validate_mcp_server_config`] as unimplemented.
    ///
    /// # Errors
    ///
    /// [`CloudflareError::Config`] when the spec cannot produce a routable
    /// upstream: no known `workers.dev` subdomain (nothing to point at), or a
    /// config the gateway's own validator rejects. Validating here rather than
    /// at load time means "deployed" and "routable" are settled by one call.
    pub fn upstream_config(
        &self,
        tools_to_execute: Vec<String>,
    ) -> Result<McpServerConfig, CloudflareError> {
        let url = self.mcp_endpoint_url().ok_or_else(|| {
            CloudflareError::Config(format!(
                "cannot register script {:?} as an MCP upstream: the account's workers.dev \
                 subdomain is unknown, so there is no URL to route to (resolve it with \
                 McpWorkerDeployer::workers_dev_subdomain and set it with \
                 McpWorkerSpec::with_workers_dev_subdomain)",
                self.wire_script_name()
            ))
        })?;

        let (auth_type, headers) = match self.auth_mode {
            McpAuthMode::Authless => (McpAuthType::None, Vec::new()),
            McpAuthMode::Oauth => (
                McpAuthType::SharedHeaders,
                vec![McpHeaderConfig {
                    name: "Authorization".to_string(),
                    value: None,
                    value_env: Some(MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV.to_string()),
                }],
            ),
        };

        let config = McpServerConfig {
            name: self.upstream_name(),
            transport: McpTransport::StreamableHttp,
            url: Some(url),
            command: None,
            args: Vec::new(),
            auth_type,
            headers,
            oauth: None,
            signed_jwt_audience: None,
            tools_to_execute,
            tools_to_auto_execute: Vec::new(),
            approval_policy: Default::default(),
            tool_include: Vec::new(),
            tool_regex: Vec::new(),
            tls: Default::default(),
            timeout_ms: crate::config::default_timeout_ms(),
            health_ping_interval_secs: crate::config::default_health_ping_interval_secs(),
            max_reconnect_attempts: crate::config::default_max_reconnect_attempts(),
            min_reconnect_backoff_secs: crate::config::default_min_reconnect_backoff_secs(),
            max_reconnect_backoff_secs: crate::config::default_max_reconnect_backoff_secs(),
        };

        validate_mcp_server_config(&config).map_err(|e| {
            CloudflareError::Config(format!(
                "deployed MCP server {:?} does not form a routable upstream: {e:#}",
                self.wire_script_name()
            ))
        })?;
        Ok(config)
    }

    /// Reject a spec that cannot produce a usable deploy.
    ///
    /// Called by [`McpWorkerDeployer::build_deploy_request`], so an invalid
    /// binding is a typed error **before** the request is signed and sent
    /// rather than an opaque Cloudflare 400.
    pub fn validate(&self) -> Result<(), CloudflareError> {
        if self.wire_script_name().is_empty() {
            return Err(CloudflareError::Config(
                "MCP Worker script_name must not be empty: it is the {script_name} path \
                 segment of the upload and the deployed hostname label"
                    .to_string(),
            ));
        }
        for binding in &self.secrets_store_bindings {
            binding.validate()?;
        }

        // `bindings[]` is a flat list keyed by `name`, and Cloudflare is free to
        // resolve a duplicate either way — so two entries sharing a name mean
        // `env.<NAME>` is whichever one won, which is not a thing to discover in
        // production. Checked across the whole set (DO + KV + every secret), not
        // just among the secrets, because that is the namespace they share.
        let mut seen = HashSet::new();
        let kv_binding = self
            .auth_mode
            .requires_oauth_kv()
            .then(|| self.wire_kv_binding_name());
        for name in [Some(self.wire_do_binding_name()), kv_binding]
            .into_iter()
            .flatten()
            .chain([DEFAULT_MCP_AUTH_MODE_BINDING])
            .chain(
                self.secrets_store_bindings
                    .iter()
                    .map(McpSecretsStoreBinding::wire_binding_name),
            )
        {
            if !seen.insert(name) {
                return Err(CloudflareError::Config(format!(
                    "binding name {name:?} is declared more than once: every entry in the \
                     upload's bindings[] is a distinct env.<NAME>, so a duplicate makes \
                     which binding the Worker sees undefined"
                )));
            }
        }
        Ok(())
    }

    /// The Workers Script-API `metadata` part as JSON.
    ///
    /// Registers the module entrypoint, the `McpAgent` Durable Object namespace
    /// binding, the `MCP_AUTH_MODE` `plain_text` binding, the `OAUTH_KV`
    /// KV-namespace binding (OAuth mode only — an authless deploy persists no
    /// grants), any
    /// [`secrets_store_bindings`](Self::secrets_store_bindings), the
    /// **`new_sqlite_classes`** migration (NOT `new_classes`: the Agents SDK
    /// requires the SQLite storage backend for session state), and
    /// [`keep_bindings`](Self::keep_bindings).
    pub fn metadata_json(&self) -> serde_json::Value {
        let mut bindings = vec![json!({
            "type": "durable_object_namespace",
            "name": self.wire_do_binding_name(),
            "class_name": self.wire_do_class_name(),
        })];
        // An authless deploy persists no OAuth grants, so it declares no KV
        // binding. Emitting one anyway would carry the unset `kv_namespace_id`
        // and fail the upload for a reason the operator never asked about.
        if self.auth_mode.requires_oauth_kv() {
            bindings.push(json!({
                "type": "kv_namespace",
                "name": self.wire_kv_binding_name(),
                "namespace_id": self.wire_kv_namespace_id(),
            }));
        }
        bindings.extend(
            self.secrets_store_bindings
                .iter()
                .map(McpSecretsStoreBinding::metadata_entry),
        );
        // Which front door the single template enforces. `plain_text`, not a
        // secret: it carries no credential, and an operator reading the script's
        // bindings should be able to see the auth mode it is running in.
        bindings.push(json!({
            "type": "plain_text",
            "name": DEFAULT_MCP_AUTH_MODE_BINDING,
            "text": self.auth_mode.as_str(),
        }));
        json!({
            "main_module": self.module_filename,
            "compatibility_date": self.compatibility_date,
            "compatibility_flags": self.compatibility_flags,
            "bindings": bindings,
            // Binding types Cloudflare carries over from the live script instead
            // of replacing. Without this, the PUT's binding array IS the new
            // binding set and an out-of-band `wrangler secret put` is erased.
            "keep_bindings": self.keep_bindings,
            "migrations": {
                "new_tag": self.migration_tag,
                "new_sqlite_classes": [self.wire_do_class_name()],
            },
        })
    }

    /// The `Content-Type` for the multipart upload, including the boundary.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={MCP_MULTIPART_BOUNDARY}")
    }

    /// The multipart body bytes: a `metadata` JSON part plus the module part.
    ///
    /// Deterministic (fixed boundary + stable metadata key order) so the exact
    /// request is assertable in tests.
    pub fn multipart_body(&self) -> Vec<u8> {
        let metadata = serde_json::to_string(&self.metadata_json())
            .expect("metadata JSON is always serializable");
        let b = MCP_MULTIPART_BOUNDARY;
        let mut body = String::new();
        // metadata part
        body.push_str(&format!("--{b}\r\n"));
        body.push_str(
            "Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n",
        );
        body.push_str("Content-Type: application/json\r\n\r\n");
        body.push_str(&metadata);
        body.push_str("\r\n");
        // module part
        body.push_str(&format!("--{b}\r\n"));
        body.push_str(&format!(
            "Content-Disposition: form-data; name=\"{0}\"; filename=\"{0}\"\r\n",
            self.module_filename
        ));
        body.push_str("Content-Type: application/javascript+module\r\n\r\n");
        body.push_str(&self.module_source);
        body.push_str("\r\n");
        // closing boundary
        body.push_str(&format!("--{b}--\r\n"));
        body.into_bytes()
    }

    /// The equivalent `wrangler deploy` invocation, for the documented CLI
    /// fallback when a live multipart PUT is not used.
    pub fn wrangler_deploy_command(&self) -> String {
        format!(
            "wrangler deploy --name {} --compatibility-date {}",
            self.wire_script_name(),
            self.compatibility_date
        )
    }
}

/// Outcome of a successful deploy: the script name Cloudflare acknowledged, and
/// the MCP endpoint it is reachable at when the account's `workers.dev`
/// subdomain is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDeployOutcome {
    pub script_name: String,
    /// `https://<script>.<subdomain>.workers.dev/mcp`, or `None` when the spec
    /// carries no [`workers_dev_subdomain`](McpWorkerSpec::workers_dev_subdomain).
    /// This is the value a caller registers as an `McpServerConfig` upstream.
    pub mcp_url: Option<String>,
}

/// One entry of the Workers scripts collection (only `id` is consumed).
#[derive(Debug, Clone, Deserialize)]
pub struct McpScriptSummary {
    #[serde(default)]
    pub id: String,
}

/// Deploy status for a named MCP server script: whether Cloudflare currently
/// hosts it, and where it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScriptStatus {
    pub script_name: String,
    pub deployed: bool,
    /// The MCP endpoint, when the caller asked via
    /// [`McpWorkerDeployer::status_for`] with a spec carrying the account's
    /// `workers.dev` subdomain **and** [`deployed`](Self::deployed) is true.
    ///
    /// `None` says "no URL to report" — either the subdomain is not known, or
    /// nothing is deployed at that name. It never says "deployed but not
    /// reachable": a `Some` here is safe to register as an `McpServerConfig`
    /// upstream, which is the whole reason it is not filled in for a script
    /// Cloudflare is not currently hosting.
    pub mcp_url: Option<String>,
}

/// Deploys / inspects / tears down the MCP server Worker via the #405 seams.
///
/// Holds a [`CloudflareConfig`], a [`TokenResolver`], and an [`HttpTransport`] —
/// the same parts [`CloudflareClient::from_parts`] takes — so it resolves the
/// Bearer token and templates `{account_id}` identically, and is mockable with
/// an inline-token resolver + scripted transport.
pub struct McpWorkerDeployer {
    config: CloudflareConfig,
    resolver: Arc<dyn TokenResolver>,
    transport: Arc<dyn HttpTransport>,
}

impl McpWorkerDeployer {
    /// Assemble from the shared #405 seams.
    pub fn new(
        config: CloudflareConfig,
        resolver: Arc<dyn TokenResolver>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            config,
            resolver,
            transport,
        }
    }

    /// The absolute Workers Script-API URL for `script_name`.
    pub fn script_url(&self, script_name: &str) -> String {
        format!(
            "{}/accounts/{}/workers/scripts/{}",
            self.config.api_base_url.trim_end_matches('/'),
            self.config.account_id,
            script_name,
        )
    }

    fn resolve_token(&self) -> Result<String, CloudflareError> {
        let token = self.resolver.resolve(self.config.token_reference(None))?;
        Ok(token.expose().to_string())
    }

    /// Build a #405 [`CloudflareClient`] over the same config/resolver/transport,
    /// used for the enveloped read-side GETs (`status`/`list`). This directly
    /// consumes the shared client (retry/backoff + typed-error mapping included);
    /// the write-side multipart `PUT` cannot, see the module-level caveat.
    fn read_client(&self) -> CloudflareClient {
        CloudflareClient::from_parts(
            self.config.clone(),
            Arc::clone(&self.resolver),
            Arc::clone(&self.transport),
            Arc::new(TokioClock),
            RetryPolicy::default(),
        )
    }

    /// Build the exact [`HttpRequest`] the deploy issues (module + metadata +
    /// DO/KV bindings + DO migration multipart `PUT`). Exposed so tests — and
    /// callers wiring a multipart-aware transport — can inspect it without
    /// sending.
    pub fn build_deploy_request(
        &self,
        spec: &McpWorkerSpec,
    ) -> Result<HttpRequest, CloudflareError> {
        spec.validate()?;
        Ok(HttpRequest {
            method: HttpMethod::Put,
            url: self.script_url(spec.wire_script_name()),
            bearer_token: self.resolve_token()?,
            body: Some(spec.multipart_body()),
            // The module upload is `multipart/form-data` framed by the spec's
            // fixed boundary; carry that content type so the #411-honoring
            // transport (`ReqwestTransport`) sends it instead of defaulting to
            // `application/json`, which Cloudflare would reject for a script PUT.
            content_type: Some(spec.content_type()),
        })
    }

    /// Deploy the Worker: `PUT` the script + DO migration, decode the envelope.
    pub async fn deploy(&self, spec: &McpWorkerSpec) -> Result<McpDeployOutcome, CloudflareError> {
        let request = self.build_deploy_request(spec)?;
        let response = self.transport.execute(request).await?;
        let envelope: CloudflareEnvelope<ScriptResult> = serde_json::from_slice(&response.body)
            .map_err(|e| {
                CloudflareError::Decode(format!("failed to decode script-upload envelope: {e}"))
            })?;
        let result = envelope.into_result(response.status, response.retry_after)?;
        Ok(McpDeployOutcome {
            // Prefer the id Cloudflare echoes; fall back to the requested name.
            script_name: result
                .id
                .unwrap_or_else(|| spec.wire_script_name().to_string()),
            mcp_url: spec.mcp_endpoint_url(),
        })
    }

    /// The account's `workers.dev` subdomain
    /// (`GET /accounts/{account_id}/workers/subdomain`).
    ///
    /// Resolve it once and feed it to
    /// [`McpWorkerSpec::with_workers_dev_subdomain`] so deploy/status report the
    /// server's URL. Kept off the deploy path deliberately: a deploy stays one
    /// request, and a subdomain lookup failure must not fail an upload that
    /// otherwise succeeded.
    ///
    /// # Errors
    ///
    /// A blank result is an error, not an empty `Ok`. An account with no
    /// workers.dev subdomain enabled answers `{"result":{}}`, and a response
    /// whose shape does not match decodes the same way — both would otherwise
    /// return `Ok("")`, which
    /// [`with_workers_dev_subdomain`](McpWorkerSpec::with_workers_dev_subdomain)
    /// accepts and [`mcp_endpoint_url`](McpWorkerSpec::mcp_endpoint_url) turns
    /// back into `None`. The operator then sees "there is just no URL" with
    /// nothing pointing at the subdomain lookup as the cause.
    pub async fn workers_dev_subdomain(&self) -> Result<String, CloudflareError> {
        let subdomain: WorkersSubdomain = self
            .read_client()
            .get_json("accounts/{account_id}/workers/subdomain", None)
            .await?;
        let subdomain = subdomain.subdomain.trim();
        if subdomain.is_empty() {
            return Err(CloudflareError::Config(format!(
                "GET /accounts/{}/workers/subdomain returned no subdomain: the account may \
                 not have workers.dev enabled (enable it in the dashboard, or deploy behind \
                 a custom domain and set the URL explicitly)",
                self.config.account_id
            )));
        }
        Ok(subdomain.to_string())
    }

    /// List the account's deployed Worker scripts (each `{ id, .. }`), via the
    /// #405 [`CloudflareClient`].
    pub async fn list(&self) -> Result<Vec<McpScriptSummary>, CloudflareError> {
        self.read_client()
            .get_json::<Vec<McpScriptSummary>>("accounts/{account_id}/workers/scripts", None)
            .await
    }

    /// Whether `script_name` is currently deployed, derived from [`list`](Self::list).
    ///
    /// Uses the enveloped collection endpoint (rather than the single-script GET,
    /// which returns raw module bytes, not an envelope) so status is one
    /// cleanly-decodable request.
    pub async fn status(&self, script_name: &str) -> Result<McpScriptStatus, CloudflareError> {
        let scripts = self.list().await?;
        Ok(McpScriptStatus {
            script_name: script_name.to_string(),
            deployed: scripts.iter().any(|s| s.id == script_name),
            mcp_url: None,
        })
    }

    /// [`status`](Self::status) for a spec, additionally reporting the MCP
    /// endpoint when the spec knows the account's `workers.dev` subdomain **and**
    /// the script is actually deployed.
    ///
    /// The `deployed` conjunct is load-bearing: a spec carries a subdomain
    /// whether or not anything was ever uploaded, so filling the URL in
    /// unconditionally would report a live-looking endpoint for a script
    /// Cloudflare is not hosting — and callers register that field as an
    /// `McpServerConfig` upstream.
    pub async fn status_for(
        &self,
        spec: &McpWorkerSpec,
    ) -> Result<McpScriptStatus, CloudflareError> {
        let status = self.status(spec.wire_script_name()).await?;
        Ok(McpScriptStatus {
            mcp_url: status.deployed.then(|| spec.mcp_endpoint_url()).flatten(),
            ..status
        })
    }

    /// Tear the Worker down: `DELETE` the script.
    pub async fn teardown(&self, script_name: &str) -> Result<(), CloudflareError> {
        let request = HttpRequest {
            method: HttpMethod::Delete,
            url: self.script_url(script_name),
            bearer_token: self.resolve_token()?,
            body: None,
            content_type: None,
        };
        let response = self.transport.execute(request).await?;
        // A DELETE success envelope carries no meaningful `result`.
        let envelope: CloudflareEnvelope<serde_json::Value> =
            serde_json::from_slice(&response.body).map_err(|e| {
                CloudflareError::Decode(format!("failed to decode script-delete envelope: {e}"))
            })?;
        envelope.into_ack(response.status, response.retry_after)
    }
}

/// The `result` shape of a Workers Script-API upload (only `id` is consumed).
#[derive(Debug, Clone, Deserialize)]
struct ScriptResult {
    #[serde(default)]
    id: Option<String>,
}

/// The `result` shape of `GET /accounts/{account_id}/workers/subdomain`.
#[derive(Debug, Clone, Deserialize)]
struct WorkersSubdomain {
    #[serde(default)]
    subdomain: String,
}

#[cfg(test)]
#[path = "mcp_worker_deploy_test.rs"]
mod tests;
