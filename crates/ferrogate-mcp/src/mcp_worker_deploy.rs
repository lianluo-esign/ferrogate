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
//!   provider persists grants in (`OAUTH_KV`), the DO **`migrations`**
//!   (`new_sqlite_classes` — the Agents SDK stores session state in an embedded
//!   per-instance SQLite DB), `compatibility_date`, and `compatibility_flags`;
//! - one module part carrying the Worker's ES-module source.
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
//! shape of `ferrogate_runtime::cloudflare_gateway_deploy` (#413). We do NOT
//! depend on `ferrogate-runtime` (that would introduce a dependency cycle:
//! runtime already depends on this crate's siblings), so the minimal
//! multipart-upload construction is copied rather than shared. When a third
//! Cloudflare Worker deployer appears, this belongs in a small shared helper in
//! `ferrogate-cloudflare` (e.g. a `WorkerScriptUpload` builder) — tracked as a
//! future extraction.
//!
//! ## Live caveat: multipart content type
//!
//! `ferrogate_cloudflare::ReqwestTransport` hard-codes `application/json` for any
//! request body, so the **production** multipart `PUT` should go through either a
//! transport that honors [`McpWorkerSpec::content_type`] or the documented
//! `wrangler deploy` shell-out ([`McpWorkerSpec::wrangler_deploy_command`]). The
//! request *construction* here is faithful and fully modeled/tested; the live
//! upload is the test agent's to prove (see the issue's deploy-fallback clause).

use std::sync::Arc;

use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, CloudflareEnvelope, CloudflareError, HttpMethod,
    HttpRequest, HttpTransport, RetryPolicy, TokenResolver, TokioClock,
};
use serde::Deserialize;
use serde_json::json;

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
            kv_namespace_id: String::new(),
            migration_tag: "v1".to_string(),
            compatibility_date: "2025-06-01".to_string(),
            compatibility_flags: vec!["nodejs_compat".to_string()],
        }
    }

    /// Builder: set the `OAUTH_KV` namespace id.
    pub fn with_kv_namespace_id(mut self, id: impl Into<String>) -> Self {
        self.kv_namespace_id = id.into();
        self
    }

    /// The Workers Script-API `metadata` part as JSON.
    ///
    /// Registers the module entrypoint, the `McpAgent` Durable Object namespace
    /// binding, the `OAUTH_KV` KV-namespace binding, and the
    /// **`new_sqlite_classes`** migration (NOT `new_classes`: the Agents SDK
    /// requires the SQLite storage backend for session state).
    pub fn metadata_json(&self) -> serde_json::Value {
        json!({
            "main_module": self.module_filename,
            "compatibility_date": self.compatibility_date,
            "compatibility_flags": self.compatibility_flags,
            "bindings": [
                {
                    "type": "durable_object_namespace",
                    "name": self.do_binding_name,
                    "class_name": self.do_class_name,
                },
                {
                    "type": "kv_namespace",
                    "name": self.kv_binding_name,
                    "namespace_id": self.kv_namespace_id,
                }
            ],
            "migrations": {
                "new_tag": self.migration_tag,
                "new_sqlite_classes": [self.do_class_name],
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
            self.script_name, self.compatibility_date
        )
    }
}

/// Outcome of a successful deploy: the script name Cloudflare acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDeployOutcome {
    pub script_name: String,
}

/// One entry of the Workers scripts collection (only `id` is consumed).
#[derive(Debug, Clone, Deserialize)]
pub struct McpScriptSummary {
    #[serde(default)]
    pub id: String,
}

/// Deploy status for a named MCP server script: whether Cloudflare currently
/// hosts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScriptStatus {
    pub script_name: String,
    pub deployed: bool,
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
        Ok(HttpRequest {
            method: HttpMethod::Put,
            url: self.script_url(&spec.script_name),
            bearer_token: self.resolve_token()?,
            body: Some(spec.multipart_body()),
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
            script_name: result.id.unwrap_or_else(|| spec.script_name.clone()),
        })
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
        })
    }

    /// Tear the Worker down: `DELETE` the script.
    pub async fn teardown(&self, script_name: &str) -> Result<(), CloudflareError> {
        let request = HttpRequest {
            method: HttpMethod::Delete,
            url: self.script_url(script_name),
            bearer_token: self.resolve_token()?,
            body: None,
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

#[cfg(test)]
#[path = "mcp_worker_deploy_test.rs"]
mod tests;
