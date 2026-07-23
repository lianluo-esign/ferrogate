// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! One typed transport to the FerroGate Control Plane API (issue #360).
//!
//! Every remote command builds a [`RequestSpec`] (method, path, query, body)
//! and runs it through a [`Transport`]. Request construction and response
//! classification are pure functions ([`prepare_request`], [`classify`]) that
//! never touch the network, so the load-bearing behavior — URL assembly, auth
//! header injection, error-envelope decoding, request/trace-id and retry-hint
//! extraction, and pagination planning — is unit-testable in isolation. The
//! actual bytes move through [`ReqwestTransport`], the workspace async HTTP
//! stack, behind the same [`Transport`] trait a test fake implements.
//!
//! The transport is deliberately schema-agnostic at this layer: it carries
//! `serde_json::Value` bodies and preserves the server's error envelope shape
//! from the enforced OpenAPI contract. Typed per-resource request/response
//! structs are layered *on top* by later issues (#361–#365) without changing
//! this module — that is what "contract-friendly, not contract-hardwired"
//! means here.

use std::future::Future;
use std::pin::Pin;

use http::Method;

use crate::auth::Credential;
use crate::context::EffectiveContext;
use crate::error::{ApiError, CliError, CliResult, ExitClass};

/// Media type the client sends and accepts.
const JSON_MEDIA_TYPE: &str = "application/json";

/// A logical request against the Control Plane API, independent of endpoint,
/// credentials, and HTTP client.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestSpec {
    pub method: Method,
    /// Absolute API path beginning with `/` (e.g. `/admin/v1/tenants`).
    pub path: String,
    /// Query parameters, appended in order and percent-encoded at build time.
    pub query: Vec<(String, String)>,
    /// Optional JSON body for mutating requests.
    pub body: Option<serde_json::Value>,
}

impl RequestSpec {
    /// A body-less request (GET/DELETE/HEAD).
    pub fn new(method: Method, path: impl Into<String>) -> RequestSpec {
        RequestSpec {
            method,
            path: path.into(),
            query: Vec::new(),
            body: None,
        }
    }

    /// A GET request.
    pub fn get(path: impl Into<String>) -> RequestSpec {
        RequestSpec::new(Method::GET, path)
    }

    /// Attach a JSON body.
    pub fn with_json_body(mut self, body: serde_json::Value) -> RequestSpec {
        self.body = Some(body);
        self
    }

    /// Append a query parameter.
    pub fn with_query(mut self, key: impl Into<String>, value: impl Into<String>) -> RequestSpec {
        self.query.push((key.into(), value.into()));
        self
    }

    /// Merge a page request's `offset`/`limit` into the query.
    pub fn with_page(mut self, page: &PageRequest) -> RequestSpec {
        self.query.extend(page.query_params());
        self
    }
}

/// A fully materialized HTTP request: absolute URL, headers, and body bytes.
/// This is what a [`Transport`] executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl PreparedRequest {
    /// Value of a header by (case-insensitive) name, for assertions/tests.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Build the absolute URL from an endpoint base and an absolute API path,
/// percent-encoding query parameters. A base path in the endpoint (e.g.
/// `https://host/gw`) is preserved as a prefix.
fn build_url(endpoint: &str, path: &str, query: &[(String, String)]) -> CliResult<String> {
    if !path.starts_with('/') {
        return Err(CliError::usage(format!(
            "internal request path must be absolute, got '{path}'"
        )));
    }
    let base = endpoint.trim_end_matches('/');
    let joined = format!("{base}{path}");
    let mut url = reqwest::Url::parse(&joined)
        .map_err(|error| CliError::usage(format!("invalid endpoint URL '{joined}': {error}")))?;
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

/// Turn a [`RequestSpec`] plus resolved connection context and optional
/// credential into a [`PreparedRequest`]. Pure: no network, no clock.
///
/// Injects `Accept: application/json`, a `User-Agent` carrying the client
/// version, `Content-Type` when a body is present, and `Authorization: Bearer`
/// when a credential was resolved. An anonymous context simply omits the
/// authorization header.
pub fn prepare_request(
    spec: &RequestSpec,
    context: &EffectiveContext,
    credential: Option<&Credential>,
) -> CliResult<PreparedRequest> {
    let url = build_url(&context.endpoint, &spec.path, &spec.query)?;

    let mut headers = vec![
        ("accept".to_string(), JSON_MEDIA_TYPE.to_string()),
        ("user-agent".to_string(), crate::version::user_agent()),
    ];
    if let Some(tenant) = &context.tenant {
        // Tenant selection is an explicit, inspectable header rather than a
        // hidden default so audit evidence can attribute the request.
        headers.push(("x-ferrogate-tenant".to_string(), tenant.clone()));
    }
    let body = match &spec.body {
        Some(value) => {
            headers.push(("content-type".to_string(), JSON_MEDIA_TYPE.to_string()));
            serde_json::to_vec(value).map_err(|error| {
                CliError::usage(format!("failed to encode request body as JSON: {error}"))
            })?
        }
        None => Vec::new(),
    };
    if let Some(credential) = credential {
        headers.push((
            "authorization".to_string(),
            credential.authorization_header(),
        ));
    }

    Ok(PreparedRequest {
        method: spec.method.clone(),
        url,
        headers,
        body,
    })
}

/// A raw HTTP response as seen by the transport, before classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    /// Value of a response header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A successfully classified response: 2xx body plus preserved correlation
/// metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiResponse {
    pub status: u16,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub body: serde_json::Value,
}

/// Classify a [`RawResponse`] into either a decoded [`ApiResponse`] or a typed
/// [`ApiError`]. Preserves HTTP status, the server error code/message, request
/// id, trace id, and any `Retry-After` retry hint. Pure.
///
/// This is the single, deliberate constructor of an unboxed [`ApiError`];
/// callers box it at the [`crate::error::CliError`] boundary (which keeps every
/// `CliResult` small), so the large-`Err` lint is not meaningful here.
#[allow(clippy::result_large_err)]
pub fn classify(response: &RawResponse) -> Result<ApiResponse, ApiError> {
    let request_id = response
        .header("x-request-id")
        .map(str::to_string)
        .or_else(|| envelope_request_id(&response.body));
    let trace_id = response.header("x-trace-id").map(str::to_string);
    let retry_after_secs = response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok());

    if ExitClass::from_http_status(response.status) == ExitClass::Success {
        let body = if response.body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&response.body).unwrap_or_else(|_| {
                // A 2xx with a non-JSON body (e.g. a raw asset download) is
                // surfaced as a JSON string so callers still get a value.
                serde_json::Value::String(String::from_utf8_lossy(&response.body).into_owned())
            })
        };
        return Ok(ApiResponse {
            status: response.status,
            request_id,
            trace_id,
            body,
        });
    }

    // Error path: decode the `ferrogate_error` envelope when present, else
    // synthesize one so every failure still yields a typed, coded error.
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&response.body).ok();
    let error_object = parsed.as_ref().and_then(|value| value.get("error"));
    let code = error_object
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| default_code_for_status(response.status).to_string());
    let message = error_object
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let text = String::from_utf8_lossy(&response.body);
            if text.trim().is_empty() {
                format!("request failed with HTTP {}", response.status)
            } else {
                text.trim().to_string()
            }
        });
    let request_id = error_object
        .and_then(|error| error.get("request_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or(request_id);

    Err(ApiError {
        http_status: response.status,
        code,
        message,
        request_id,
        trace_id,
        retry_after_secs,
        details: error_object.and_then(collect_extra_details),
    })
}

fn envelope_request_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("error")?
        .get("request_id")?
        .as_str()
        .map(str::to_string)
}

/// Preserve any error fields beyond the known `message`/`type`/`code`/
/// `request_id` so resource-specific error details are not silently dropped.
fn collect_extra_details(error_object: &serde_json::Value) -> Option<serde_json::Value> {
    let map = error_object.as_object()?;
    let extra: serde_json::Map<String, serde_json::Value> = map
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "message" | "type" | "code" | "request_id"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if extra.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(extra))
    }
}

fn default_code_for_status(status: u16) -> &'static str {
    match ExitClass::from_http_status(status) {
        ExitClass::Auth => "unauthorized",
        ExitClass::NotFoundConflict => "not_found",
        ExitClass::Validation => "invalid_request",
        ExitClass::Transport => "retryable_error",
        ExitClass::Server => "server_error",
        ExitClass::Success | ExitClass::Usage => "error",
    }
}

/// A request for one page of a list endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub offset: u64,
    /// `None` lets the server apply its default/clamped page size.
    pub limit: Option<u64>,
}

impl PageRequest {
    /// The first page with an explicit limit.
    pub fn first(limit: u64) -> PageRequest {
        PageRequest {
            offset: 0,
            limit: Some(limit),
        }
    }

    /// The `offset`/`limit` query parameters this page contributes.
    pub fn query_params(&self) -> Vec<(String, String)> {
        let mut params = vec![("offset".to_string(), self.offset.to_string())];
        if let Some(limit) = self.limit {
            params.push(("limit".to_string(), limit.to_string()));
        }
        params
    }
}

/// Given how many items the current page returned and an optional known
/// `total`, compute the next page — or `None` when iteration is complete.
///
/// Two stop conditions, so `--all-pages` never silently truncates *and* never
/// loops forever: when `total` is known, stop once the next offset reaches it;
/// when it is unknown, stop as soon as a page returns fewer items than the
/// requested limit (a short page is the last page). A page that returns zero
/// items always ends iteration.
pub fn next_page(current: &PageRequest, returned: u64, total: Option<u64>) -> Option<PageRequest> {
    if returned == 0 {
        return None;
    }
    let next_offset = current.offset.saturating_add(returned);
    if let Some(total) = total {
        if next_offset >= total {
            return None;
        }
    } else if let Some(limit) = current.limit {
        if returned < limit {
            return None;
        }
    }
    Some(PageRequest {
        offset: next_offset,
        limit: current.limit,
    })
}

/// Plan the full sequence of page requests needed to cover `total` items at a
/// fixed `limit`. Empty when `total` is zero; `limit` of zero is rejected by
/// clamping to one to avoid a division-by-zero / infinite plan.
pub fn plan_all_pages(total: u64, limit: u64) -> Vec<PageRequest> {
    let limit = limit.max(1);
    let mut pages = Vec::new();
    let mut offset = 0;
    while offset < total {
        pages.push(PageRequest {
            offset,
            limit: Some(limit),
        });
        offset += limit;
    }
    pages
}

/// The transport seam: execute a prepared request and return the raw response.
/// Async so the real implementation can use the workspace async HTTP stack; a
/// test fake implements it synchronously.
pub trait Transport {
    /// Execute one prepared request.
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> Pin<Box<dyn Future<Output = CliResult<RawResponse>> + Send + 'a>>;
}

/// `reqwest`-backed transport over the workspace async HTTP/TLS stack.
///
/// TLS provider installation is the composing binary's responsibility (the
/// workspace pins `reqwest` to `rustls-no-provider`); this type only builds
/// the client and maps transport-level failures onto [`ExitClass::Transport`].
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with the effective context's timeout and TLS policy.
    pub fn new(context: &EffectiveContext) -> CliResult<ReqwestTransport> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(context.timeout_millis));
        if context.tls_insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build().map_err(|error| {
            CliError::transport(format!("failed to build HTTP client: {error}"))
        })?;
        Ok(ReqwestTransport { client })
    }
}

impl Transport for ReqwestTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> Pin<Box<dyn Future<Output = CliResult<RawResponse>> + Send + 'a>> {
        Box::pin(async move {
            let mut builder = self.client.request(request.method, &request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            if !request.body.is_empty() {
                builder = builder.body(request.body);
            }
            let response = builder.send().await.map_err(|error| {
                CliError::transport(format!("request to {} failed: {error}", request.url))
            })?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            let body = response
                .bytes()
                .await
                .map_err(|error| {
                    CliError::transport(format!("failed to read response body: {error}"))
                })?
                .to_vec();
            Ok(RawResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// High-level client: prepare a spec, execute it through a [`Transport`], and
/// classify the response into a typed result. Generic over the transport so a
/// fake can drive it in tests without a live server.
pub struct ControlPlaneClient<T: Transport> {
    context: EffectiveContext,
    credential: Option<Credential>,
    transport: T,
}

impl<T: Transport> ControlPlaneClient<T> {
    /// Assemble a client from resolved context, optional credential, and a
    /// transport.
    pub fn new(context: EffectiveContext, credential: Option<Credential>, transport: T) -> Self {
        ControlPlaneClient {
            context,
            credential,
            transport,
        }
    }

    /// Prepare, send, and classify one request.
    pub async fn send(&self, spec: &RequestSpec) -> CliResult<ApiResponse> {
        let prepared = prepare_request(spec, &self.context, self.credential.as_ref())?;
        let raw = self.transport.execute(prepared).await?;
        classify(&raw).map_err(CliError::from)
    }
}

#[cfg(test)]
#[path = "transport_test.rs"]
mod transport_test;
