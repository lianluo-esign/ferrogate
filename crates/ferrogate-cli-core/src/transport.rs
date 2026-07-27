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
///
/// `pub(crate)` so [`crate::receipt`] can derive a mutation's canonical action
/// target from the *same* URL the transport will send, rather than re-deriving
/// (and potentially disagreeing with) it.
pub(crate) fn build_url(
    endpoint: &str,
    path: &str,
    query: &[(String, String)],
) -> CliResult<String> {
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
        // hidden default, so a proxy or audit log can attribute the request.
        //
        // Read this together with `context::unhonored_scope_notice`: **no
        // Control Plane API operation declares this header** (pinned by
        // `tenant_scope_is_not_yet_an_openapi_parameter`), so today it is
        // inspectable but not acted upon — admin requests are scoped by the
        // bearer token. It is still sent, because the client inventing a
        // tenancy parameter the contract does not define would be worse than
        // sending an ignored one; the operator is told on stderr instead.
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

/// Default page size for an all-pages walk when the caller named none.
pub const DEFAULT_PAGE_SIZE: u64 = 100;

/// Hard cap on how many pages one all-pages walk will fetch. A server that
/// never reports a final page is a bug; failing loudly at the cap beats
/// looping forever or silently returning a partial answer.
///
/// This is the *last* backstop, not the first: an endpoint that ignores
/// `offset`/`limit` is refused up front by
/// [`ControlPlaneClient::send_all_pages`]'s window check, and a cursor endpoint
/// by its cursor check. What is left for the cap is a server that *claims* an
/// offset window (it echoes `offset`/`limit`) and then never advances through
/// it — reaching the cap there is 10 000 requests at the operator's control
/// plane, so the failure names the server rather than blaming the invocation.
/// `send_all_pages_gives_up_at_the_page_cap_when_the_server_never_advances`
/// exercises that path, so the cap cannot be deleted while the suite stays
/// green.
const MAX_PAGES: u32 = 10_000;

/// Response keys under which the Control Plane API returns a list page.
/// Shared by the all-pages walker and by the table renderer so both agree on
/// what "a page" looks like instead of each keeping its own list.
///
/// This list is deliberately **one entry**, derived from a structural parse of
/// `docs/openapi/admin-api.openapi.json` rather than from guesswork: every
/// schema in the contract that carries an array-typed page property spells it
/// `data`, and none spells it `items`, `results`, or `records`. A speculative
/// alias list reads as generosity but is the opposite: it lets the walker, the
/// truncation notice, and the envelope-metadata table be "proven" against a
/// payload shape no endpoint emits, so deleting the one real key would leave
/// every test green while the feature died in production.
/// `page_item_keys_match_the_openapi_contract` in `transport_test.rs` re-derives
/// the list from the spec and fails if the contract ever grows another spelling.
pub const PAGE_ITEM_KEYS: [&str; 1] = ["data"];

/// Response keys carrying the collection-wide row count. Also spec-derived:
/// `total` is the only collection-count property in the contract. `count` was
/// removed because it is the natural spelling of a *per-page* count — reading
/// one as the collection total would stop the walk after page one.
const PAGE_TOTAL_KEYS: [&str; 1] = ["total"];

/// Envelope keys that describe the *window* one page covers rather than the
/// collection, so they misdescribe a merged multi-page document.
const PAGE_WINDOW_KEYS: [&str; 2] = ["offset", "limit"];

/// Envelope keys that mark a **cursor**-paginated endpoint. The walker speaks
/// `offset`/`limit` only; a cursor endpoint ignores those parameters and would
/// return page one forever, so their presence is a hard stop rather than an
/// accidental fallback (see [`ControlPlaneClient::send_all_pages`]).
///
/// Spec-derived, like [`PAGE_ITEM_KEYS`] — and, since #352, derived by
/// something that **runs**: `page_cursor_keys_match_the_openapi_contract` in
/// `transport_test.rs` re-collects the contract's cursor markers structurally
/// and fails when this list is missing one.
///
/// That test exists because the previous, hand-maintained version of this list
/// went stale silently. It recorded that a speculative `next_cursor` alias had
/// been removed "because the string appears nowhere in the contract" — true
/// when written, and false the moment `AdminPaymentAttemptList` landed the
/// admin contract's first `next_cursor` envelope. In that window
/// `--all-pages` walked a cursor endpoint by offset: the server ignores
/// `offset`, so every one of up to [`MAX_PAGES`] iterations re-fetched page one
/// and merged it again. A list documented as derived from the contract must be
/// derived by a test, not re-audited by a reader.
const PAGE_CURSOR_KEYS: [&str; 5] = [
    "after_event_id",
    "cursor_reset",
    "has_more",
    "next_after_event_id",
    "next_cursor",
];

/// A decoded list page: the item array, the envelope key it lived under
/// (`None` for a bare top-level array), the server-reported collection total
/// when the envelope carried one, the server-applied page size, and whether the
/// envelope is cursor- rather than offset-paginated.
#[derive(Debug, Clone, PartialEq)]
pub struct PageEnvelope<'a> {
    pub items_key: Option<&'static str>,
    pub items: &'a [serde_json::Value],
    pub total: Option<u64>,
    /// The page size the *server* applied, from the envelope's own `limit`.
    /// Distinct from any `--limit` the operator passed: an endpoint with a
    /// server-side default page size reports one here even when the caller
    /// named none, which is what lets the truncation notice fire on a default
    /// `list` instead of staying silent.
    pub limit: Option<u64>,
    /// The window start the *server* applied, from the envelope's own `offset`.
    /// Carried for the same reason as `limit`: it is the endpoint's only
    /// evidence that it read the `offset` the walk asked for.
    pub offset: Option<u64>,
    /// True when the envelope carries cursor-pagination markers.
    pub cursor: bool,
}

impl PageEnvelope<'_> {
    /// Whether the envelope says **anything** about the page window it just
    /// served — its own `offset`, its own `limit`, or the collection `total`.
    ///
    /// This is the signal that separates "an offset-paginated endpoint" from
    /// "an endpoint that ignored `offset`/`limit` and handed back the whole
    /// collection". A structural parse of the contract puts 43 of 65 `list*`
    /// operations in the second group — they declare no `limit`/`offset` query
    /// parameter and echo none back — so treating a silent envelope as
    /// offset-paginated is the common case, not the exotic one. When such an
    /// endpoint returns a full page the walk would advance the offset, receive
    /// the identical rows, and repeat: a request storm that stays invisible in
    /// a dev tenant small enough to fit in one page.
    pub fn echoes_page_window(&self) -> bool {
        self.total.is_some() || self.limit.is_some() || self.offset.is_some()
    }
}

/// What a cursor-paginated page says about its own continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCursorState {
    /// The server handed back a non-null resume token: more rows exist and this
    /// is what to ask for them with. The key is the envelope property carrying
    /// it — the *response* spelling, which is not necessarily the query
    /// parameter's, so a caller must quote it rather than invent a flag.
    Resume { key: &'static str, value: String },
    /// The page is the definitive end of the listing (`next_cursor: null`, or
    /// `has_more: false`).
    Exhausted,
    /// Cursor-paginated, but the envelope carries no continuation evidence
    /// either way (`has_more: true` with no token, say).
    Unknown,
}

/// Read a cursor envelope's continuation, so a caller can tell the operator
/// whether a single page was the whole answer without teaching it any
/// resource's cursor spelling.
///
/// Returns `None` for a page that is not cursor-paginated. Pure.
pub fn page_cursor_state(body: &serde_json::Value) -> Option<PageCursorState> {
    let map = body.as_object()?;
    if !PAGE_CURSOR_KEYS.iter().any(|key| map.contains_key(*key)) {
        return None;
    }
    // An explicit `has_more: false` is the strongest statement available and
    // outranks a token, so a server that echoes the request cursor back on the
    // last page is not misread as having more rows.
    if map.get("has_more").and_then(serde_json::Value::as_bool) == Some(false) {
        return Some(PageCursorState::Exhausted);
    }
    // Only the `next_*` markers are continuations: the bare `after_event_id` is
    // the echo of the cursor the caller already used, and resuming from it would
    // re-fetch the page in hand forever.
    let next_keys = || {
        PAGE_CURSOR_KEYS
            .iter()
            .filter(|key| key.starts_with("next_"))
    };
    if let Some((key, value)) = next_keys().find_map(|key| {
        map.get(*key)
            .filter(|value| !value.is_null())
            .map(|value| (*key, value))
    }) {
        let value = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        return Some(PageCursorState::Resume { key, value });
    }
    if next_keys().any(|key| map.contains_key(*key)) {
        return Some(PageCursorState::Exhausted);
    }
    Some(PageCursorState::Unknown)
}

/// Recognize a list response shape. Returns `None` when the document is not a
/// list at all (a single object, a scalar, `null`), which is how callers tell
/// "this verb does not paginate" apart from "this page is empty". Pure.
pub fn page_envelope(body: &serde_json::Value) -> Option<PageEnvelope<'_>> {
    match body {
        serde_json::Value::Array(items) => Some(PageEnvelope {
            items_key: None,
            items,
            total: None,
            limit: None,
            offset: None,
            cursor: false,
        }),
        serde_json::Value::Object(map) => {
            let key = PAGE_ITEM_KEYS
                .iter()
                .copied()
                .find(|key| matches!(map.get(*key), Some(serde_json::Value::Array(_))))?;
            let items = map.get(key)?.as_array()?;
            let total = PAGE_TOTAL_KEYS
                .iter()
                .find_map(|total_key| map.get(*total_key)?.as_u64());
            let limit = map.get("limit").and_then(serde_json::Value::as_u64);
            let offset = map.get("offset").and_then(serde_json::Value::as_u64);
            let cursor = PAGE_CURSOR_KEYS.iter().any(|key| map.contains_key(*key));
            Some(PageEnvelope {
                items_key: Some(key),
                items,
                total,
                limit,
                offset,
                cursor,
            })
        }
        _ => None,
    }
}

/// Rebuild one response document from every page's items.
///
/// Per-page window keys (`offset`/`limit`) **and** per-page cursor keys
/// (`next_offset`, `has_more`, `next_after_event_id`, …) are dropped because
/// they describe a single page and would misdescribe the merged whole; `total`
/// is left exactly as the server reported it so the operator can still
/// cross-check the row count the walk produced.
fn merge_pages(
    body: serde_json::Value,
    items_key: Option<&'static str>,
    merged: Vec<serde_json::Value>,
) -> serde_json::Value {
    match (items_key, body) {
        (Some(key), serde_json::Value::Object(mut map)) => {
            map.insert(key.to_string(), serde_json::Value::Array(merged));
            for stale in PAGE_WINDOW_KEYS
                .iter()
                .chain(PAGE_CURSOR_KEYS.iter())
                .chain(["next_offset"].iter())
            {
                map.remove(*stale);
            }
            serde_json::Value::Object(map)
        }
        _ => serde_json::Value::Array(merged),
    }
}

/// Given how many items the current page returned and an optional known
/// `total`, compute the next page — or `None` when iteration should stop.
///
/// Three stop conditions, so a walk never loops forever: a page that returned
/// **zero** items cannot advance the cursor (the next request would be
/// byte-identical to the one that just came back empty); when `total` is known,
/// stop once the next offset reaches it; when it is unknown, stop as soon as a
/// page returns fewer items than the requested limit (a short page is the last
/// page).
///
/// Note carefully what this function does **not** decide: whether stopping was
/// *legitimate*. An empty page in the middle of a collection the server said
/// held 500 rows stops iteration here and is nonetheless a truncated answer.
/// Deciding that is [`ControlPlaneClient::send_all_pages`]'s job — it compares
/// the merged row count against the reported total after the walk and fails
/// rather than returning a short answer with exit 0. Claiming the stop
/// conditions alone make truncation impossible (as the previous comment here
/// did) was wrong: this arm is exactly how the silent truncation got in.
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
        if let Some(path) = &context.ca_bundle_path {
            // A configured CA bundle is honored, not decorative: an unreadable
            // or malformed bundle fails the command rather than silently
            // falling back to the system roots. A field that deserializes but
            // never reaches the client is the #188 ignored-field failure mode.
            let pem = std::fs::read(path).map_err(|error| {
                CliError::usage(format!("failed to read CA bundle '{path}': {error}"))
            })?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
                CliError::usage(format!(
                    "CA bundle '{path}' is not a valid PEM certificate bundle: {error}"
                ))
            })?;
            if certificates.is_empty() {
                return Err(CliError::usage(format!(
                    "CA bundle '{path}' contains no certificates"
                )));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
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

    /// Walk every page of a list request and return one merged response.
    ///
    /// This is the executable half of the "explicit all-pages behavior without
    /// silently truncating results" contract — [`next_page`] and
    /// [`plan_all_pages`] describe the arithmetic, this is what actually runs
    /// it. `spec` must **not** already carry `offset`/`limit`: the walk owns
    /// the cursor, and a caller-supplied offset would make "every page"
    /// ambiguous.
    ///
    /// Five refusals, each preferring a loud failure to a plausible-looking
    /// partial answer:
    ///
    /// 1. **A non-`GET` spec is rejected before anything is sent.** `--all-pages`
    ///    on `delete` is a malformed invocation; discovering that *after* the
    ///    DELETE committed would tell the operator their command was invalid
    ///    while the destructive change had already happened.
    /// 2. **A non-list response** is a usage error rather than a silently
    ///    single-page answer: `--all-pages` on a non-list verb is a mistake
    ///    worth telling the operator about.
    /// 3. **A cursor-paginated endpoint is refused.** The walk speaks
    ///    `offset`/`limit`; an endpoint paginating by cursor ignores both and
    ///    would hand back page one on every iteration until `MAX_PAGES`,
    ///    buffering 10 000 pages of duplicated rows. Refusing states the rule
    ///    instead of leaving a request storm as the accidental behavior.
    /// 4. **An endpoint that echoes no page window at all is refused before the
    ///    second request.** Cursor markers are the *narrow* case; the broad one
    ///    is an endpoint supporting neither pagination style, which carries no
    ///    cursor key and so slipped past refusal 3 and was walked as if it were
    ///    offset-paginated. It ignores `offset`/`limit`, returns the whole
    ///    collection every time, and — being a full page with no `total` —
    ///    makes [`next_page`] advance forever: 10 000 requests at the
    ///    operator's control plane and a million duplicated rows buffered
    ///    before the cap errors. It passes unnoticed in a dev tenant whose
    ///    collections fit in one page and storms in production, which is
    ///    exactly the shape of bug a rule must catch rather than a fixture.
    ///    The signal is [`PageEnvelope::echoes_page_window`] — generic, keyed
    ///    on the response shape, naming no resource.
    /// 5. **A walk that ends short of a reported `total` fails.** Iteration
    ///    itself stops on [`next_page`]'s conditions, one of which is an empty
    ///    page — and an empty page can arrive in the *middle* of a collection
    ///    (a concurrent delete, or a server that filters after paging). Without
    ///    this check that path returned fewer rows than the server said existed,
    ///    with exit 0 and no diagnostic, which is precisely the silent
    ///    truncation this code exists to prevent.
    pub async fn send_all_pages(
        &self,
        spec: &RequestSpec,
        page_size: u64,
    ) -> CliResult<ApiResponse> {
        if spec.method != Method::GET {
            return Err(CliError::usage(format!(
                "--all-pages only applies to a list read, but this verb issues {} {}; \
                 re-run without --all-pages",
                spec.method, spec.path
            )));
        }
        let mut page = PageRequest::first(page_size.max(1));
        let mut merged: Vec<serde_json::Value> = Vec::new();
        let mut first: Option<ApiResponse> = None;
        let mut items_key: Option<&'static str> = None;
        // The freshest total the server stated. Later pages win, so a
        // collection that legitimately shrank mid-walk is judged against the
        // count the server most recently reported, not a stale one.
        let mut reported_total: Option<u64> = None;

        for _ in 0..MAX_PAGES {
            let paged = spec.clone().with_page(&page);
            let response = self.send(&paged).await?;
            let (returned, total, echoes_window) = {
                let envelope = page_envelope(&response.body).ok_or_else(|| {
                    CliError::usage(format!(
                        "--all-pages requires a list response, but {} returned a non-list document",
                        spec.path
                    ))
                })?;
                if envelope.cursor {
                    return Err(CliError::usage(format!(
                        "--all-pages cannot walk {}: it is cursor-paginated, and the walk only \
                         speaks offset/limit — every iteration would re-fetch the first page. \
                         Page it explicitly with --filter and the cursor field the endpoint \
                         documents",
                        spec.path
                    )));
                }
                // The first page fixes the envelope shape the merged result is
                // rebuilt into; later pages only contribute rows.
                if first.is_none() {
                    items_key = envelope.items_key;
                }
                merged.extend(envelope.items.iter().cloned());
                (
                    envelope.items.len() as u64,
                    envelope.total,
                    envelope.echoes_page_window(),
                )
            };
            if let Some(total) = total {
                reported_total = Some(total);
            }
            let next = next_page(&page, returned, total);
            // Keep the FIRST page's correlation metadata: it identifies the
            // request the operator actually issued.
            if first.is_none() {
                first = Some(response);
            }
            match next {
                Some(next) => {
                    // Only refuse where it would actually matter: a *short*
                    // page from a windowless endpoint already ended the walk
                    // above with every row in hand, and failing that would be
                    // gratuitous. It is the full page — the one that makes the
                    // walk want another request it has no evidence the server
                    // will honor — that must stop here.
                    if !echoes_window {
                        return Err(CliError::usage(format!(
                            "--all-pages cannot walk {}: its response echoes no offset, limit, or \
                             total, so nothing shows the endpoint honored the page window this \
                             walk asked for. An endpoint that ignores offset/limit returns the \
                             same rows on every iteration, so continuing would issue up to \
                             {MAX_PAGES} identical requests. Re-run without --all-pages — the one \
                             page is the whole answer this endpoint gives — and narrow it with \
                             --filter",
                            spec.path
                        )));
                    }
                    page = next;
                }
                None => {
                    let fetched = merged.len() as u64;
                    if let Some(total) = reported_total {
                        if fetched < total {
                            return Err(CliError::transport(format!(
                                "--all-pages fetched {fetched} of the {total} rows {} reports; \
                                 the walk ended early (an empty or short page mid-collection), so \
                                 the result would have been silently truncated",
                                spec.path
                            )));
                        }
                    }
                    let mut whole = first.expect("the first page was recorded above");
                    whole.body = merge_pages(whole.body, items_key, merged);
                    return Ok(whole);
                }
            }
        }

        Err(CliError::transport(format!(
            "--all-pages gave up after {MAX_PAGES} pages of {}; the endpoint echoed a page window \
             but never advanced through it, so it never reported a final page",
            spec.path
        )))
    }
}

#[cfg(test)]
#[path = "transport_test.rs"]
mod transport_test;
