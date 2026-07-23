// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Cloudflare AI Gateway upstream routing (issue #406) -- rewrites a
// prepared provider request onto a tenant's Cloudflare AI Gateway while keeping
// the OpenAI/Anthropic request shape (pass-through caching/limits/observability).

//! Cloudflare AI Gateway routing for upstream providers (issue #406).
//!
//! This is a pure request-shaping layer on top of the existing provider
//! dispatch path: an adapter (OpenAI-compatible, Anthropic, ...) first builds a
//! [`ProviderHttpRequest`] exactly as today, then -- when the provider opts into
//! Cloudflare routing via [`ProviderConfig::cloudflare_ai_gateway`] -- the
//! registry calls [`apply_cloudflare_ai_gateway_routing`] to rewrite the
//! outbound URL onto the gateway host and inject the `cf-aig-*` headers. The
//! request body and the per-request `Authorization` / `x-api-key` (BYOK) header
//! are preserved so per-tenant provider keys keep working and the normalized
//! response shape is unchanged (Cloudflare is a transparent pass-through).
//!
//! Two Cloudflare surfaces are supported, selected by
//! [`CloudflareAiGatewayMode`]:
//!
//! * [`CloudflareAiGatewayMode::Compat`] -- the per-provider passthrough
//!   endpoints under
//!   `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/{provider}/...`.
//!   The provider request shape (and its native auth header) is forwarded
//!   verbatim, so this is the safest pass-through and covers all four surfaces.
//! * [`CloudflareAiGatewayMode::Unified`] -- the unified REST API under
//!   `https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1/{surface}`
//!   with the gateway selected by the `cf-aig-gateway-id` header and the body
//!   `model` rewritten to Cloudflare's `author/model` form.

use std::fmt;

use serde_json::Value;

use crate::{
    AdapterError, ProviderAdapterFamily, ProviderHeader, ProviderHttpRequest, SecretValue,
};

/// Which Cloudflare AI Gateway surface a provider routes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudflareAiGatewayMode {
    /// Per-provider passthrough (`.../{gateway_id}/{provider}/...`). Default:
    /// it forwards the provider request shape verbatim, so it is the safest
    /// pass-through and needs no body mutation.
    #[default]
    Compat,
    /// Unified REST API (`.../accounts/{account_id}/ai/v1/{surface}`), gateway
    /// selected via the `cf-aig-gateway-id` header, `model` in `author/model`
    /// form.
    Unified,
}

/// The logical upstream surface being dispatched. Chosen by the registry from
/// the `prepare_*` entry point plus the resolved provider family (an Anthropic
/// provider's chat/responses both dispatch as `messages`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareAiGatewaySurface {
    ChatCompletions,
    Responses,
    Messages,
    Embeddings,
}

/// Per-provider Cloudflare AI Gateway routing parameters.
///
/// Absent (`ProviderConfig::cloudflare_ai_gateway == None`) means the provider
/// dispatches directly, exactly as before -- the rewrite is fully opt-in and
/// non-breaking. `account_id` and the base URLs come from the global
/// `[cloudflare]` config (issue #405); `gateway_id`, `aig_token`, `mode`, and
/// the optional slug override come from the per-provider `cloudflare_ai_gateway`
/// block.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudflareAiGatewayRouting {
    /// Cloudflare account id (the `{account_id}` path segment).
    pub account_id: String,
    /// AI Gateway id (the `{gateway_id}` path segment / `cf-aig-gateway-id`).
    pub gateway_id: String,
    /// AI Gateway base host, e.g. `https://gateway.ai.cloudflare.com`
    /// (compat mode). From `[cloudflare].ai_gateway_base_url`.
    pub gateway_base_url: String,
    /// Cloudflare REST API base, e.g. `https://api.cloudflare.com/client/v4`
    /// (unified mode). From `[cloudflare].api_base_url`.
    pub api_base_url: String,
    /// Resolved AI Gateway token for an *authenticated* gateway, injected as
    /// `cf-aig-authorization: Bearer <token>`. `None` for an unauthenticated
    /// gateway. Resolved from `aig_token_secret_ref` through the existing
    /// [`SecretValue`] path before it reaches this struct (never a raw ref).
    pub aig_token: Option<SecretValue>,
    /// Which Cloudflare surface to route through.
    pub mode: CloudflareAiGatewayMode,
    /// Explicit Cloudflare provider slug (path segment in compat mode / `author`
    /// prefix in unified mode). When `None` it is derived from the provider
    /// family (`openai` / `anthropic`). Set this to route a provider whose
    /// family maps to a different Cloudflare slug (e.g. `grok`,
    /// `google-ai-studio`).
    pub provider_slug: Option<String>,
}

impl fmt::Debug for CloudflareAiGatewayRouting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareAiGatewayRouting")
            .field("account_id", &self.account_id)
            .field("gateway_id", &self.gateway_id)
            .field("gateway_base_url", &self.gateway_base_url)
            .field("api_base_url", &self.api_base_url)
            .field("aig_token", &self.aig_token)
            .field("mode", &self.mode)
            .field("provider_slug", &self.provider_slug)
            .finish()
    }
}

/// The default Cloudflare provider slug for a family, or `None` when the family
/// has no OpenAI/Anthropic-shaped Cloudflare passthrough (the caller must then
/// supply an explicit [`CloudflareAiGatewayRouting::provider_slug`]).
fn default_slug_for_family(family: ProviderAdapterFamily) -> Option<&'static str> {
    match family {
        // Every OpenAI-shaped family forwards through Cloudflare's `openai`
        // passthrough by default; operators route xAI/OpenRouter/Azure/etc.
        // through a different slug via `provider_slug` when needed.
        ProviderAdapterFamily::OpenAiCompatible => Some("openai"),
        ProviderAdapterFamily::Anthropic => Some("anthropic"),
        _ => None,
    }
}

/// The provider-native path suffix appended after the compat passthrough
/// `.../{provider}` segment. OpenAI-shaped surfaces drop the `/v1` (Cloudflare's
/// `openai` passthrough already stands in for `https://api.openai.com/v1`);
/// Anthropic keeps `/v1/messages` (its passthrough stands in for the host only).
fn compat_native_suffix(
    family: ProviderAdapterFamily,
    surface: CloudflareAiGatewaySurface,
) -> Result<&'static str, AdapterError> {
    match (family, surface) {
        (ProviderAdapterFamily::Anthropic, CloudflareAiGatewaySurface::Messages) => {
            Ok("/v1/messages")
        }
        (_, CloudflareAiGatewaySurface::ChatCompletions) => Ok("/chat/completions"),
        (_, CloudflareAiGatewaySurface::Responses) => Ok("/responses"),
        (_, CloudflareAiGatewaySurface::Embeddings) => Ok("/embeddings"),
        (_, CloudflareAiGatewaySurface::Messages) => Ok("/v1/messages"),
    }
}

/// The `/ai/v1/{...}` suffix for the unified REST surface.
fn unified_surface_path(surface: CloudflareAiGatewaySurface) -> &'static str {
    match surface {
        CloudflareAiGatewaySurface::ChatCompletions => "chat/completions",
        CloudflareAiGatewaySurface::Responses => "responses",
        CloudflareAiGatewaySurface::Messages => "messages",
        CloudflareAiGatewaySurface::Embeddings => "embeddings",
    }
}

/// Resolve the Cloudflare provider slug: the explicit override, else the family
/// default. Fails closed when neither is available so an enabled-but-unroutable
/// provider errors at preparation time instead of dispatching to a wrong host.
fn resolve_slug(
    routing: &CloudflareAiGatewayRouting,
    family: ProviderAdapterFamily,
) -> Result<String, AdapterError> {
    if let Some(slug) = routing
        .provider_slug
        .as_deref()
        .map(str::trim)
        .filter(|slug| !slug.is_empty())
    {
        return Ok(slug.to_string());
    }
    default_slug_for_family(family)
        .map(ToString::to_string)
        .ok_or_else(|| AdapterError::InvalidRequest {
            message: format!(
                "cloudflare ai gateway routing requires an explicit provider_slug for family {family:?}"
            ),
        })
}

/// Rewrite `request` in place to route through a Cloudflare AI Gateway.
///
/// * URL -> the gateway host + surface path (compat or unified).
/// * Injects `cf-aig-authorization: Bearer <aig_token>` when a token is set,
///   and (unified mode) `cf-aig-gateway-id: <gateway_id>`.
/// * Preserves the request body and the per-request BYOK auth header; unified
///   mode additionally rewrites `model` to `author/model` form.
pub fn apply_cloudflare_ai_gateway_routing(
    routing: &CloudflareAiGatewayRouting,
    family: ProviderAdapterFamily,
    surface: CloudflareAiGatewaySurface,
    request: &mut ProviderHttpRequest,
) -> Result<(), AdapterError> {
    let account_id = non_empty(&routing.account_id, "cloudflare account_id")?;
    let gateway_id = non_empty(&routing.gateway_id, "cloudflare gateway_id")?;
    let slug = resolve_slug(routing, family)?;

    match routing.mode {
        CloudflareAiGatewayMode::Compat => {
            let base = non_empty(&routing.gateway_base_url, "cloudflare ai_gateway_base_url")?;
            let suffix = compat_native_suffix(family, surface)?;
            request.endpoint = format!(
                "{}/v1/{}/{}/{}{}",
                base.trim_end_matches('/'),
                account_id,
                gateway_id,
                slug,
                suffix
            );
        }
        CloudflareAiGatewayMode::Unified => {
            let base = non_empty(&routing.api_base_url, "cloudflare api_base_url")?;
            request.endpoint = format!(
                "{}/accounts/{}/ai/v1/{}",
                base.trim_end_matches('/'),
                account_id,
                unified_surface_path(surface)
            );
            rewrite_model_to_author_form(&mut request.body, &slug);
            upsert_header(&mut request.headers, "cf-aig-gateway-id", gateway_id);
        }
    }

    if let Some(token) = routing
        .aig_token
        .as_ref()
        .map(SecretValue::expose_secret)
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        upsert_header(
            &mut request.headers,
            "cf-aig-authorization",
            &format!("Bearer {token}"),
        );
    }

    Ok(())
}

fn non_empty<'a>(value: &'a str, label: &str) -> Result<&'a str, AdapterError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(AdapterError::InvalidRequest {
            message: format!("{label} must not be empty for cloudflare ai gateway routing"),
        })
    } else {
        Ok(trimmed)
    }
}

/// Prefix the body `model` with the Cloudflare `author/` segment required by the
/// unified REST API, unless it already carries an `author/` prefix. Preserves
/// the response shape (Cloudflare still returns the provider-native envelope).
fn rewrite_model_to_author_form(body: &mut Value, author: &str) {
    let Some(model) = body.get("model").and_then(Value::as_str) else {
        return;
    };
    if model.contains('/') {
        return;
    }
    let rewritten = format!("{author}/{model}");
    body["model"] = Value::String(rewritten);
}

/// Insert a header, replacing any existing header with the same
/// (case-insensitive) name so a rewrite never emits a duplicate `cf-aig-*`.
fn upsert_header(headers: &mut Vec<ProviderHeader>, name: &str, value: &str) {
    headers.retain(|header| !header.name.eq_ignore_ascii_case(name));
    headers.push(ProviderHeader {
        name: name.to_string(),
        value: SecretValue::new(value),
    });
}

#[cfg(test)]
#[path = "cloudflare_test.rs"]
mod cloudflare_test;
