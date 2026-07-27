// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-side TLS egress executor for brokered edge-function calls (#120).
//!
//! Given an already-built, already-governed [`EdgeFunctionHttpRequest`] (target
//! validated https + allowlisted upstream, credential injected by the runtime
//! builder), this performs the real `reqwest` (rustls) request and returns a
//! bounded [`FunctionInvocationOutcome`]. It is transport-agnostic on purpose —
//! the https/allowlist policy lives upstream, so this stays unit-testable against
//! a local server. Credentials are never logged.
//!
//! `prepare_brokered_invocation` composes the fail-closed pipeline
//! (allowlist authorize → mint scoped token → build request) and is what the
//! `/v1/functions/execute` route (#119) runs before handing off to the executor.

use std::{sync::OnceLock, time::Duration};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_runtime::{
    EdgeFunctionHttpRequest, FunctionCredential, FunctionEgressAllowlist, FunctionEgressDenied,
    FunctionEgressRule, FunctionInvocationOutcome, FunctionInvocationRequest, FunctionTokenError,
    FunctionTokenMinter, SupabaseEdgeFunctionError, SupabaseEdgeFunctionInvocation,
    DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS, DEFAULT_FUNCTION_TOKEN_TTL_SECS,
};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
    Client, Method,
};
// The private-network DNS guard (and its imports) is only wired into the
// non-test client; under test the mock upstream is a loopback address it would
// reject.
#[cfg(not(test))]
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
#[cfg(not(test))]
use std::net::SocketAddr;

const BODY_EXCERPT_MAX_BYTES: usize = 2048;
/// Capability recorded in the minted token for edge-function-side authorization.
const FUNCTION_CAPABILITY: &str = "function";
/// Shared token issuer for both hosted-function broker branches (Supabase here,
/// Cloudflare Worker in `function_egress_cloudflare`).
pub(crate) const FUNCTION_TOKEN_ISSUER: &str = "ferrogate";

/// Runtime configuration for the gateway function egress broker.
///
/// Sourced from the environment (recommended secure default): the signing
/// secret is resolved at runtime and never persisted to the control-plane DB.
/// The broker is disabled unless `FG_FN_JWT_SECRET` is set, so it is
/// fail-closed by default.
pub struct FunctionEgressGatewayConfig {
    allowlist: FunctionEgressAllowlist,
    minter: FunctionTokenMinter,
    apikey: String,
}

/// Why the gateway rejected a brokered function invocation before executing it.
#[derive(Debug)]
pub enum FunctionBrokerError {
    Denied(FunctionEgressDenied),
    Token(FunctionTokenError),
    Build(SupabaseEdgeFunctionError),
}

impl std::fmt::Display for FunctionBrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(error) => write!(f, "{error}"),
            Self::Token(error) => write!(f, "{error}"),
            Self::Build(error) => write!(f, "{error}"),
        }
    }
}

impl FunctionEgressGatewayConfig {
    /// Load from the environment. Returns `None` (broker disabled) unless a
    /// signing secret is configured. Allowlist is `FG_FN_ALLOWLIST` (JSON array
    /// of rules); apikey is `FG_FN_APIKEY`.
    ///
    /// The Supabase branch is the default: it stays active when the
    /// `FG_FN_TARGET_KIND` discriminant (#435) is unset or `supabase`, and is
    /// disabled (fail-closed, no shared credentials misrouted) when the
    /// operator declared a Cloudflare Worker target or an unknown kind.
    pub(crate) fn from_env() -> Option<Self> {
        if !matches!(
            super::function_egress_cloudflare::env_function_target_kind(),
            Some(super::function_egress_cloudflare::FunctionTargetKind::Supabase)
        ) {
            return None;
        }
        Self::from_values(
            std::env::var("FG_FN_JWT_SECRET").ok(),
            std::env::var("FG_FN_APIKEY").ok(),
            std::env::var("FG_FN_ALLOWLIST").ok(),
        )
    }

    fn from_values(
        signing_secret: Option<String>,
        apikey: Option<String>,
        allowlist_json: Option<String>,
    ) -> Option<Self> {
        let signing_secret = signing_secret.filter(|value| !value.trim().is_empty())?;
        // The Supabase `apikey` header is required, so the broker stays disabled
        // (fail-closed) unless it is configured too. Enabling it without an apikey
        // would surface as a misleading per-call denial instead of a clear 503.
        let apikey = apikey.filter(|value| !value.trim().is_empty())?;
        let minter = FunctionTokenMinter::new(FUNCTION_TOKEN_ISSUER, signing_secret).ok()?;
        let rules: Vec<FunctionEgressRule> = match allowlist_json {
            Some(json) => match serde_json::from_str(&json) {
                Ok(rules) => rules,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "function egress broker disabled: FG_FN_ALLOWLIST is not valid JSON"
                    );
                    return None;
                }
            },
            None => Vec::new(),
        };
        // Single-project enforcement (TOK-6). The broker signs every token with
        // one process-wide `FG_FN_JWT_SECRET` and sends one process-wide
        // `FG_FN_APIKEY`; both are per-Supabase-project. An allowlist that spans
        // more than one distinct project `base_url` would silently hand the same
        // apikey and same-secret-signed token to every project, and at most one
        // could verify them. Rather than let that footgun be configured silently,
        // refuse to enable the broker (fail-closed) until per-project credential
        // resolution lands. See docs/design/function-egress-broker.md.
        if !allowlist_is_single_project(&rules) {
            tracing::warn!(
                "function egress broker disabled: FG_FN_ALLOWLIST spans multiple project \
                 base_urls but the broker uses a single shared apikey/JWT secret. List rules \
                 for exactly one project base_url, or wait for per-project credentials (TOK-6)."
            );
            return None;
        }
        Some(Self {
            allowlist: FunctionEgressAllowlist::new(rules),
            minter,
            apikey,
        })
    }
}

/// Normalize a project base URL for comparison, matching the allowlist's own
/// normalization (trim surrounding whitespace and any trailing slash). Shared
/// with the Cloudflare Worker broker branch.
pub(crate) fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

/// True when the allowlist targets at most one distinct project `base_url`.
///
/// An empty allowlist is trivially single-project (the broker is deny-by-default
/// and rejects every call anyway). Two or more distinct normalized base URLs mean
/// the shared apikey/signing-secret model cannot serve them, so the broker must
/// stay disabled.
fn allowlist_is_single_project(rules: &[FunctionEgressRule]) -> bool {
    let mut project: Option<String> = None;
    for rule in rules {
        let base = normalize_base_url(&rule.base_url);
        match &project {
            Some(existing) if existing != &base => return false,
            Some(_) => {}
            None => project = Some(base),
        }
    }
    true
}

/// Process-wide broker config, resolved once from the environment.
pub fn function_egress_config() -> Option<&'static FunctionEgressGatewayConfig> {
    static CONFIG: OnceLock<Option<FunctionEgressGatewayConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(FunctionEgressGatewayConfig::from_env)
        .as_ref()
}

/// Fail-closed pipeline: authorize the target against the tenant's allowlist,
/// mint a short-lived scoped token, and build the governed HTTP request. Returns
/// the request and the function slug for the outcome. No network I/O.
pub fn prepare_brokered_invocation(
    config: &FunctionEgressGatewayConfig,
    tenant: &str,
    request: &FunctionInvocationRequest,
    now_unix: u64,
) -> Result<(EdgeFunctionHttpRequest, String, u64), FunctionBrokerError> {
    config
        .allowlist
        .authorize(tenant, &request.target)
        .map_err(FunctionBrokerError::Denied)?;

    let slug = request.target.function_slug.trim().to_string();
    let token = config
        .minter
        .mint(
            tenant,
            &slug,
            FUNCTION_CAPABILITY,
            now_unix,
            DEFAULT_FUNCTION_TOKEN_TTL_SECS,
        )
        .map_err(FunctionBrokerError::Token)?;

    let credential = FunctionCredential::scoped_token(token, config.apikey.clone());
    let invocation = SupabaseEdgeFunctionInvocation {
        target: request.target.clone(),
        method: request.method.clone(),
        body_json: request.body_json.clone(),
        timeout_millis: DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS,
    };
    let timeout_millis = invocation.timeout_millis;
    let http_request = invocation
        .build_http_request(&credential)
        .map_err(FunctionBrokerError::Build)?;
    Ok((http_request, slug, timeout_millis))
}

/// Execute a brokered edge-function request and return a bounded outcome.
pub async fn execute_edge_function_request(
    request: &EdgeFunctionHttpRequest,
    function_slug: &str,
    timeout: Duration,
    max_body_bytes: usize,
) -> AnyResult<FunctionInvocationOutcome> {
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("invalid function method: {}", request.method))?;
    let url = reqwest::Url::parse(&request.url)
        .with_context(|| format!("invalid function url: {}", request.url))?;
    if url.scheme() != "https" {
        bail!("unsupported function url scheme: {}", url.scheme());
    }

    let headers = build_headers(request)?;
    let mut response = function_http_client()?
        .request(method, url)
        .headers(headers)
        .timeout(timeout)
        .body(request.body.clone())
        .send()
        .await
        .context("edge-function request failed")?;

    let status_code = response.status().as_u16();
    // Cheap early out when the upstream sends an honest `Content-Length`.
    if let Some(content_length) = response.content_length() {
        if content_length > max_body_bytes as u64 {
            bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
        }
    }
    // Stream the body chunk-by-chunk with a hard cap so a chunked or
    // `Content-Length`-lying upstream cannot force us to buffer an arbitrarily
    // large response: we abort as soon as the accumulated length would exceed
    // the cap, never holding more than `max_body_bytes` + one chunk in memory.
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read edge-function response body")?
    {
        if body.len() + chunk.len() > max_body_bytes {
            bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
        }
        body.extend_from_slice(&chunk);
    }

    let body_excerpt = String::from_utf8_lossy(&body)
        .chars()
        .take(BODY_EXCERPT_MAX_BYTES)
        .collect();

    Ok(FunctionInvocationOutcome {
        function_slug: function_slug.to_string(),
        status_code,
        body_excerpt,
    })
}

fn build_headers(request: &EdgeFunctionHttpRequest) -> AnyResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid function header name: {name}"))?;
        let header_value = HeaderValue::from_str(value).context("invalid function header value")?;
        headers.insert(header_name, header_value);
    }
    Ok(headers)
}

/// DNS resolver that refuses to resolve a brokered function host to a private,
/// loopback, link-local, or cloud-metadata address. The per-tenant allowlist
/// only constrains the *hostname*, so without this a DNS-rebound allowlisted
/// host could still point the request at an internal service. Reuses the same
/// address classification the guardrail detector egress uses.
#[cfg(not(test))]
#[derive(Debug, Clone, Copy)]
struct FunctionEgressDnsResolver;

#[cfg(not(test))]
impl Resolve for FunctionEgressDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0)).await.map_err(
                |_| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(
                        "function egress DNS resolution failed",
                    ))
                },
            )?;
            let filtered: Vec<SocketAddr> = addresses
                .filter(|address| !ferrogate_guardrails::is_disallowed_detector_ip(address.ip()))
                .collect();
            if filtered.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "function egress DNS resolved only disallowed (internal) addresses",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(filtered.into_iter()) as Addrs)
        })
    }
}

fn function_http_client() -> AnyResult<Client> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    let result = CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Never follow redirects: the https + per-tenant allowlist check runs
        // once on the initial URL, so following a 3xx to an attacker-chosen
        // Location (e.g. a tenant-authored edge function returning
        // `302 http://169.254.169.254/...`) would bypass the allowlist and
        // exfiltrate internal/metadata responses (plus forward the apikey
        // header). The upstream must reach its result in one hop.
        let builder = Client::builder()
            .redirect(Policy::none())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate();
        // The private-network DNS guard is disabled under test, where the mock
        // upstream is a loopback address the guard would otherwise reject.
        #[cfg(not(test))]
        let builder = builder.dns_resolver(std::sync::Arc::new(FunctionEgressDnsResolver));
        #[cfg(test)]
        let builder = builder.danger_accept_invalid_certs(true);
        builder.build().map_err(|error| error.to_string())
    });
    match result {
        Ok(client) => Ok(client.clone()),
        Err(error) => bail!("failed to initialize function HTTP client: {error}"),
    }
}

#[cfg(test)]
#[path = "function_egress_test.rs"]
mod function_egress_test;
