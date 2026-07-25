// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Deploy/teardown pipeline for the FerroGate agent-gateway Worker (issue #413):
//   constructs the Workers Script PUT (module + metadata + DO SQLite migration) and the
//   teardown DELETE against the #405 CloudflareClient transport seam (fully mockable).

//! Deploy / teardown pipeline for the agent-gateway Worker (issue #413).
//!
//! Cloudflare exposes **no first-party REST API** to drive an individual agent
//! (Durable Object) instance, so FerroGate must deploy a *fronting Worker*
//! ([`workers/agent-gateway`](../../../../workers/agent-gateway)) that hosts the
//! agent DO class and exposes lifecycle control routes. This module is the Rust
//! side of getting that Worker onto Cloudflare and tearing it back down.
//!
//! ## What it constructs
//!
//! A module-Worker upload is a **`multipart/form-data` `PUT`** to
//! `PUT /accounts/{account_id}/workers/scripts/{script_name}` carrying:
//!
//! - a `metadata` part (JSON): `main_module`, the Durable Object `bindings`, the
//!   DO `migrations` (`new_sqlite_classes` — the Agents SDK stores agent state in
//!   an embedded per-instance SQLite DB), `compatibility_date`, and
//!   `compatibility_flags`;
//! - one module part carrying the Worker's ES-module source.
//!
//! [`GatewayWorkerSpec`] models that upload and produces the metadata JSON, the
//! multipart body, and the content type **deterministically** (fixed boundary)
//! so the exact request is unit-assertable. Teardown is a plain
//! `DELETE /accounts/{account_id}/workers/scripts/{script_name}`.
//!
//! ## The transport seam (why it is mockable)
//!
//! [`GatewayWorkerDeployer`] talks to Cloudflare through the **#405
//! [`HttpTransport`]** and **[`TokenResolver`]** seams (the same ones
//! `ferrogate_cloudflare::CloudflareClient` is built on), not a live network
//! client. Tests inject a scripted transport + an inline-token resolver and
//! assert the constructed request byte-for-byte, with zero network — mirroring
//! the shared client's own backoff tests.
//!
//! ## Multipart content type
//!
//! The deploy `PUT` sets [`HttpRequest::content_type`] to
//! [`GatewayWorkerSpec::content_type`] (`multipart/form-data; boundary=…`), which
//! `ferrogate_cloudflare::ReqwestTransport` honors as of #411 (it defaults to
//! `application/json` only when `content_type` is `None`). The documented
//! `wrangler deploy` shell-out ([`wrangler_deploy_command`]) remains available as
//! a CLI fallback. The request *construction* here is faithful and fully
//! modeled/tested; the live upload is the test agent's to prove (see the issue's
//! deploy-fallback clause).

use std::sync::Arc;

use ferrogate_cloudflare::{
    CloudflareConfig, CloudflareEnvelope, CloudflareError, HttpMethod, HttpRequest, HttpTransport,
    TokenResolver,
};
use serde::Deserialize;
use serde_json::json;

/// The fixed multipart boundary. A constant (not random) boundary keeps the
/// constructed request deterministic so tests can assert the exact bytes.
pub const GATEWAY_MULTIPART_BOUNDARY: &str = "----FerroGateAgentGatewayBoundary";

/// Default deployed script name for the agent-gateway Worker. Matches the
/// `name` in `workers/agent-gateway/wrangler.toml`.
pub const DEFAULT_GATEWAY_SCRIPT_NAME: &str = "ferrogate-agent-gateway";

/// Default Durable Object class name hosting the agent (see the Worker source).
pub const DEFAULT_AGENT_DO_CLASS: &str = "AgentGateway";

/// Default Durable Object binding name (`env.AGENT_GATEWAY`).
pub const DEFAULT_AGENT_DO_BINDING: &str = "AGENT_GATEWAY";

/// A modeled Workers Script-API upload for the agent-gateway Worker.
///
/// Everything needed to build the `PUT /accounts/{account_id}/workers/scripts/{name}`
/// multipart request: the script name, the ES-module source, and the Durable
/// Object binding + SQLite migration that make the agent class deployable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayWorkerSpec {
    /// The deployed script name (the `{script_name}` path segment).
    pub script_name: String,
    /// The module filename referenced by `main_module` in the metadata.
    pub module_filename: String,
    /// The ES-module Worker source (the contents of `src/index.ts` bundled, or
    /// the raw module for `wrangler`-less uploads).
    pub module_source: String,
    /// The Durable Object class name to bind (the agent class).
    pub do_class_name: String,
    /// The Durable Object binding name (`env.<NAME>`).
    pub do_binding_name: String,
    /// The DO migration tag (idempotency key for the migration).
    pub migration_tag: String,
    /// Worker compatibility date.
    pub compatibility_date: String,
    /// Worker compatibility flags.
    pub compatibility_flags: Vec<String>,
}

impl GatewayWorkerSpec {
    /// A spec with FerroGate's defaults for the given module source.
    pub fn new(module_source: impl Into<String>) -> Self {
        Self {
            script_name: DEFAULT_GATEWAY_SCRIPT_NAME.to_string(),
            module_filename: "index.js".to_string(),
            module_source: module_source.into(),
            do_class_name: DEFAULT_AGENT_DO_CLASS.to_string(),
            do_binding_name: DEFAULT_AGENT_DO_BINDING.to_string(),
            migration_tag: "v1".to_string(),
            compatibility_date: "2025-06-01".to_string(),
            compatibility_flags: vec!["nodejs_compat".to_string()],
        }
    }

    /// The Workers Script-API `metadata` part as JSON.
    ///
    /// Registers the module entrypoint, the Durable Object namespace binding for
    /// the agent class, and the **`new_sqlite_classes`** migration (NOT
    /// `new_classes`: the Agents SDK requires the SQLite storage backend).
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
        format!("multipart/form-data; boundary={GATEWAY_MULTIPART_BOUNDARY}")
    }

    /// The multipart body bytes: a `metadata` JSON part plus the module part.
    ///
    /// Deterministic (fixed boundary + stable metadata key order) so the exact
    /// request is assertable in tests.
    pub fn multipart_body(&self) -> Vec<u8> {
        let metadata = serde_json::to_string(&self.metadata_json())
            .expect("metadata JSON is always serializable");
        let b = GATEWAY_MULTIPART_BOUNDARY;
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
pub struct GatewayDeployOutcome {
    pub script_name: String,
}

/// Deploys / tears down the agent-gateway Worker via the #405 transport seam.
///
/// Holds the same parts `CloudflareClient::from_parts` does — a
/// [`CloudflareConfig`], a [`TokenResolver`], and an [`HttpTransport`] — so it
/// resolves the Bearer token and templates `{account_id}` identically, and is
/// mockable with an inline-token resolver + scripted transport.
pub struct GatewayWorkerDeployer {
    config: CloudflareConfig,
    resolver: Arc<dyn TokenResolver>,
    transport: Arc<dyn HttpTransport>,
}

impl GatewayWorkerDeployer {
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

    /// Build the exact [`HttpRequest`] the deploy issues (module + metadata +
    /// DO migration multipart `PUT`). Exposed so tests — and callers wiring a
    /// multipart-aware transport — can inspect it without sending.
    pub fn build_deploy_request(
        &self,
        spec: &GatewayWorkerSpec,
    ) -> Result<HttpRequest, CloudflareError> {
        Ok(HttpRequest {
            method: HttpMethod::Put,
            url: self.script_url(&spec.script_name),
            bearer_token: self.resolve_token()?,
            body: Some(spec.multipart_body()),
            // A module-Worker upload is `multipart/form-data`; carry the spec's
            // boundary-bearing content type so #411's honoring transport
            // (`ReqwestTransport`) sends it instead of defaulting to
            // `application/json` (which the live Script API would reject).
            content_type: Some(spec.content_type()),
        })
    }

    /// Deploy the Worker: `PUT` the script + DO migration, decode the envelope.
    pub async fn deploy(
        &self,
        spec: &GatewayWorkerSpec,
    ) -> Result<GatewayDeployOutcome, CloudflareError> {
        let request = self.build_deploy_request(spec)?;
        let response = self.transport.execute(request).await?;
        let envelope: CloudflareEnvelope<ScriptResult> = serde_json::from_slice(&response.body)
            .map_err(|e| {
                CloudflareError::Decode(format!("failed to decode script-upload envelope: {e}"))
            })?;
        let result = envelope.into_result(response.status, response.retry_after)?;
        Ok(GatewayDeployOutcome {
            // Prefer the id Cloudflare echoes; fall back to the requested name.
            script_name: result.id.unwrap_or_else(|| spec.script_name.clone()),
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

#[cfg(test)]
#[path = "cloudflare_gateway_deploy_test.rs"]
mod tests;
