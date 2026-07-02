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
    Client, Method,
};

const BODY_EXCERPT_MAX_BYTES: usize = 2048;
/// Capability recorded in the minted token for edge-function-side authorization.
const FUNCTION_CAPABILITY: &str = "function";
const FUNCTION_TOKEN_ISSUER: &str = "ferrogate";

/// Runtime configuration for the gateway function egress broker.
///
/// Sourced from the environment (recommended secure default): the signing
/// secret is resolved at runtime and never persisted to the control-plane DB.
/// The broker is disabled unless `FG_FN_JWT_SECRET` is set, so it is
/// fail-closed by default.
pub(super) struct FunctionEgressGatewayConfig {
    allowlist: FunctionEgressAllowlist,
    minter: FunctionTokenMinter,
    apikey: String,
}

/// Why the gateway rejected a brokered function invocation before executing it.
#[derive(Debug)]
pub(super) enum FunctionBrokerError {
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
    pub(super) fn from_env() -> Option<Self> {
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
        let minter = FunctionTokenMinter::new(FUNCTION_TOKEN_ISSUER, signing_secret).ok()?;
        let rules: Vec<FunctionEgressRule> = allowlist_json
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        Some(Self {
            allowlist: FunctionEgressAllowlist::new(rules),
            minter,
            apikey: apikey.unwrap_or_default(),
        })
    }
}

/// Process-wide broker config, resolved once from the environment.
pub(super) fn function_egress_config() -> Option<&'static FunctionEgressGatewayConfig> {
    static CONFIG: OnceLock<Option<FunctionEgressGatewayConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(FunctionEgressGatewayConfig::from_env)
        .as_ref()
}

/// Fail-closed pipeline: authorize the target against the tenant's allowlist,
/// mint a short-lived scoped token, and build the governed HTTP request. Returns
/// the request and the function slug for the outcome. No network I/O.
pub(super) fn prepare_brokered_invocation(
    config: &FunctionEgressGatewayConfig,
    tenant: &str,
    request: &FunctionInvocationRequest,
    now_unix: u64,
) -> Result<(EdgeFunctionHttpRequest, String), FunctionBrokerError> {
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
    let http_request = invocation
        .build_http_request(&credential)
        .map_err(FunctionBrokerError::Build)?;
    Ok((http_request, slug))
}

/// Execute a brokered edge-function request and return a bounded outcome.
pub(super) async fn execute_edge_function_request(
    request: &EdgeFunctionHttpRequest,
    function_slug: &str,
    timeout: Duration,
    max_body_bytes: usize,
) -> AnyResult<FunctionInvocationOutcome> {
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("invalid function method: {}", request.method))?;
    let url = reqwest::Url::parse(&request.url)
        .with_context(|| format!("invalid function url: {}", request.url))?;
    match url.scheme() {
        "https" | "http" => {}
        other => bail!("unsupported function url scheme: {other}"),
    }

    let headers = build_headers(request)?;
    let response = function_http_client()?
        .request(method, url)
        .headers(headers)
        .timeout(timeout)
        .body(request.body.clone())
        .send()
        .await
        .context("edge-function request failed")?;

    let status_code = response.status().as_u16();
    if let Some(content_length) = response.content_length() {
        if content_length > max_body_bytes as u64 {
            bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
        }
    }
    let body = response
        .bytes()
        .await
        .context("failed to read edge-function response body")?;
    if body.len() > max_body_bytes {
        bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
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

fn function_http_client() -> AnyResult<Client> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    let result = CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::builder()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()
            .map_err(|error| error.to_string())
    });
    match result {
        Ok(client) => Ok(client.clone()),
        Err(error) => bail!("failed to initialize function HTTP client: {error}"),
    }
}

#[cfg(test)]
#[path = "function_egress_test.rs"]
mod function_egress_test;
