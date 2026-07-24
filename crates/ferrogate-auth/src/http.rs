// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Hardened HTTP/1.1 plumbing shared with sibling side services (issues
//! #147/#328) plus the JSON error-envelope helpers every handler uses.

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, io::Read, net::TcpStream};

pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;

pub(crate) fn unauthorized(message: &str) -> HttpResponse {
    HttpResponse::json(
        401,
        json!({
            "error": {
                "code": "unauthorized",
                "message": message,
            }
        }),
    )
}

pub(crate) fn conflict(message: &str) -> HttpResponse {
    HttpResponse::json(
        409,
        json!({ "error": { "code": "conflict", "message": message } }),
    )
}

pub(crate) fn unprocessable(message: &str) -> HttpResponse {
    HttpResponse::json(
        422,
        json!({ "error": { "code": "invalid_request", "message": message } }),
    )
}

pub(crate) fn internal_error(message: &str) -> HttpResponse {
    HttpResponse::json(
        500,
        json!({ "error": { "code": "internal_error", "message": message } }),
    )
}

pub(crate) fn storage_error(error: &ferrogate_storage::StorageError) -> HttpResponse {
    HttpResponse::json(
        503,
        json!({ "error": { "code": "storage_unavailable", "message": error.to_string() } }),
    )
}

pub(crate) fn forbidden(message: &str) -> HttpResponse {
    HttpResponse::json(
        403,
        json!({ "error": { "code": "forbidden", "message": message } }),
    )
}

pub(crate) fn not_found(message: &str) -> HttpResponse {
    HttpResponse::json(
        404,
        json!({ "error": { "code": "not_found", "message": message } }),
    )
}

pub(crate) fn bad_request(error: serde_json::Error) -> HttpResponse {
    HttpResponse::json(
        400,
        json!({
            "error": {
                "code": "invalid_json",
                "message": error.to_string()
            }
        }),
    )
}

/// A parsed HTTP/1.1 request as read by the side-service plumbing below.
///
/// Public (like [`HttpResponse`] and [`read_http_request_bounded`]) so
/// sibling side services in the same binary -- specifically `ferrogate
/// admin-api serve` (issue #315) -- can REUSE this #147-hardened HTTP
/// plumbing instead of growing yet another hand-rolled copy (the exact
/// duplication #147 had to fix across auth and billing).
#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    /// Raw query string (no leading `?`), empty if the request line had
    /// none. Needed for the OIDC SSO callback (issue #160), which -- being
    /// a standard OAuth2 redirect from the IdP -- always arrives as
    /// `GET /.../callback?code=...&state=...`, not a JSON body.
    pub query: String,
    /// Header names lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn bearer_token(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }

    /// Looks up a single value from the URL-decoded query string.
    pub(crate) fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            if key != name {
                return None;
            }
            Some(urldecode(value))
        })
    }
}

/// Minimal percent-decoding for query values (the inverse of `urlencode`).
/// Unrecognized `%XX` sequences and `+` are passed through unchanged rather
/// than erroring -- this is a best-effort read of a query string we don't
/// control the shape of (the IdP's redirect).
pub(crate) fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        decoded.push(byte);
                        index += 3;
                    }
                    None => {
                        decoded.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

pub(crate) fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    read_http_request_bounded(stream, MAX_REQUEST_BYTES)
}

/// A request-length precondition [`read_http_request_bounded`] rejects
/// *before* reading a body, so callers can map it to the correct HTTP
/// status instead of dropping the connection (issue #328, finding 2).
///
/// This parser frames a body solely from `Content-Length`; it does NOT
/// implement chunked transfer decoding. Rather than silently treating an
/// unlengthed or chunked body as empty -- which forwards a truncated
/// request downstream -- it refuses these shapes up front. Callers that
/// speak HTTP to a real client (the auth service and the `admin-api`
/// reverse proxy) surface these as a proper error response;
/// [`RequestLengthError`] is returned inside the parser's `anyhow::Error`
/// and recovered with [`anyhow::Error::downcast_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestLengthError {
    /// A body-bearing method (`POST`/`PUT`/`PATCH`) arrived with no
    /// `Content-Length` header (and no chunked framing). Surfaced as
    /// `411 Length Required` -- the caller must send an explicit length,
    /// even `Content-Length: 0` for an empty body.
    LengthRequired,
    /// A `Transfer-Encoding` other than `identity` (e.g. `chunked`) was
    /// present. This parser does not decode chunked bodies, and a
    /// `Content-Length`+`Transfer-Encoding` combination is a
    /// request-smuggling shape we refuse outright. Surfaced as
    /// `400 Bad Request`.
    ChunkedUnsupported,
}

impl RequestLengthError {
    /// The HTTP status a caller should return for this rejection.
    pub fn http_status(self) -> u16 {
        match self {
            RequestLengthError::LengthRequired => 411,
            RequestLengthError::ChunkedUnsupported => 400,
        }
    }

    /// A stable, machine-readable code for the JSON error envelope.
    pub fn code(self) -> &'static str {
        match self {
            RequestLengthError::LengthRequired => "length_required",
            RequestLengthError::ChunkedUnsupported => "unsupported_transfer_encoding",
        }
    }

    /// A human-readable message for the JSON error envelope.
    pub fn message(self) -> &'static str {
        match self {
            RequestLengthError::LengthRequired => {
                "a request with a body-bearing method must declare a Content-Length header \
                 (send Content-Length: 0 for an empty body)"
            }
            RequestLengthError::ChunkedUnsupported => {
                "Transfer-Encoding is not supported by this endpoint; send the body with an \
                 explicit Content-Length header instead of chunked encoding"
            }
        }
    }
}

impl std::fmt::Display for RequestLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RequestLengthError {}

/// Read and parse one HTTP/1.1 request (headers + `Content-Length` body)
/// from `reader`, rejecting anything larger than `max_request_bytes` --
/// including a declared `Content-Length` that would exceed it, checked
/// BEFORE it is used as a slice bound ([`bounded_body_end`], issue #147).
///
/// Public so sibling side services (`ferrogate admin-api serve`, #315) can
/// reuse this hardened parser with their own byte caps (e.g. the gateway's
/// `[limits]` section, #312) over any transport (plain TCP or TLS).
pub fn read_http_request_bounded<R: Read>(
    reader: &mut R,
    max_request_bytes: usize,
) -> anyhow::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = reader.read(&mut chunk).context("failed to read request")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request headers"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > max_request_bytes {
            return Err(anyhow!("request exceeds {max_request_bytes} bytes"));
        }
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let raw_target = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?;
    let mut target_parts = raw_target.splitn(2, '?');
    let path = target_parts.next().unwrap_or("/").to_string();
    let query = target_parts.next().unwrap_or("").to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();

    // Body framing (issue #328, finding 2). This parser frames the body
    // solely from `Content-Length`, so reject anything it cannot frame
    // rather than silently reading a zero-length body and forwarding a
    // truncated request downstream:
    //   * any `Transfer-Encoding` other than `identity` (e.g. chunked) ->
    //     400, since we do not implement chunked decoding (and a CL+TE
    //     combination is a smuggling shape we refuse outright);
    //   * a body-bearing method (POST/PUT/PATCH) with no `Content-Length`
    //     -> 411, forcing an explicit length (even `Content-Length: 0`).
    // GET/HEAD/DELETE/OPTIONS with no body are unaffected: they are not
    // body-bearing and so require no length.
    if let Some(transfer_encoding) = headers.get("transfer-encoding") {
        if !transfer_encoding.eq_ignore_ascii_case("identity") {
            return Err(anyhow::Error::new(RequestLengthError::ChunkedUnsupported));
        }
    }
    if !headers.contains_key("content-length")
        && matches!(method.as_str(), "POST" | "PUT" | "PATCH")
    {
        return Err(anyhow::Error::new(RequestLengthError::LengthRequired));
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end + 4;
    let body_end = bounded_body_end(body_start, content_length, max_request_bytes)?;
    while buffer.len() < body_end {
        let read = reader
            .read(&mut chunk)
            .context("failed to read request body")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request body"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > max_request_bytes {
            return Err(anyhow!("request exceeds {max_request_bytes} bytes"));
        }
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body: buffer[body_start..body_end].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Bound a declared `Content-Length` before it is used as a slice index, so a
/// malformed/huge header cannot overflow the `body_start + content_length`
/// addition or produce a `start > end` slice panic (issue #147, ported from
/// the billing service's #138 fix). Pure and independently testable.
pub(crate) fn bounded_body_end(
    body_start: usize,
    content_length: usize,
    max_request_bytes: usize,
) -> anyhow::Result<usize> {
    if content_length > max_request_bytes {
        return Err(anyhow!(
            "content-length {content_length} exceeds {max_request_bytes} bytes"
        ));
    }
    body_start
        .checked_add(content_length)
        .ok_or_else(|| anyhow!("content-length overflow"))
}

/// A minimal `Connection: close` JSON response writer, shared (like
/// [`HttpRequest`]) with sibling side services so the #147 hardening work
/// stays in one place instead of being copied per service.
#[derive(Debug)]
pub struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    pub fn json<T>(status: u16, body: T) -> Self
    where
        T: Serialize,
    {
        let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Self { status, body }
    }

    pub fn no_content(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
        }
    }

    pub fn to_bytes(&self, cors_allowed_origin: Option<&str>) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            411 => "Length Required",
            413 => "Payload Too Large",
            422 => "Unprocessable Entity",
            429 => "Too Many Requests",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        let cors_headers = cors_allowed_origin
            .map(|origin| {
                format!(
                    "access-control-allow-origin: {origin}\r\n\
                     access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n\
                     access-control-allow-headers: authorization, content-type\r\n\
                     access-control-max-age: 600\r\n"
                )
            })
            .unwrap_or_default();
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{cors_headers}connection: close\r\n\r\n",
            self.status,
            status_text,
            self.body.len()
        );
        [headers.as_bytes(), &self.body].concat()
    }
}
