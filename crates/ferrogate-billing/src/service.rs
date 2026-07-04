// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Standalone billing microservice HTTP boundary (issue #129).
//!
//! An isolated process that receives token-usage [`BillingEvent`]s from the
//! gateway over REST and returns settled [`LedgerEntry`]s. It deliberately
//! mirrors the `ferrogate-auth` service shape: a blocking `TcpListener` with a
//! thread per connection and a hand-rolled HTTP/1.1 parser, so it carries no
//! async runtime and no framework dependency. Persistence is injected as an
//! `Arc<dyn LedgerSink>` so the same server runs against the in-memory sink in
//! tests and a durable Supabase-backed sink in production.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::json;

use crate::{
    charge,
    ledger::{LedgerListFilter, LedgerSink, LedgerTotals},
    pricing::PriceBook,
    BillingError, BillingEvent, LedgerEntry,
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const DEFAULT_LEDGER_PAGE_LIMIT: usize = 100;
const MAX_LEDGER_PAGE_LIMIT: usize = 1000;
/// Read/write deadline per connection so a slow or idle client cannot park a
/// handler thread forever (slowloris mitigation, issue #138).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound on concurrently-served connections so an anonymous flood cannot
/// exhaust threads/memory (issue #138).
const MAX_CONCURRENT_CONNECTIONS: usize = 512;

/// Runtime configuration for [`serve`]. Ownership of the rate card and the
/// persistence sink is transferred to the service.
#[derive(Clone)]
pub struct BillingServiceConfig {
    pub listen: String,
    pub price_book: PriceBook,
    pub sink: Arc<dyn LedgerSink>,
    /// Optional shared secret for service-to-service auth (issue #136). When
    /// set, charge/ledger requests must present `Authorization: Bearer <token>`;
    /// `/healthz` stays open for readiness probes. When `None`, the service is
    /// unauthenticated (only appropriate for a trusted loopback deployment).
    pub token: Option<String>,
}

impl std::fmt::Debug for BillingServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BillingServiceConfig")
            .field("listen", &self.listen)
            .field("price_book_entries", &self.price_book.len())
            .field("credits_per_usd", &self.price_book.credits_per_usd)
            .field("sink", &"dyn LedgerSink")
            .field("auth_required", &self.token.is_some())
            .finish()
    }
}

/// The service state shared across connection threads.
struct BillingService {
    price_book: PriceBook,
    sink: Arc<dyn LedgerSink>,
    token: Option<String>,
}

impl BillingService {
    /// Price a usage event and persist the resulting ledger entry.
    fn charge_and_record(&self, event: &BillingEvent) -> Result<LedgerEntry, BillingError> {
        let entry = charge(&self.price_book, event)?;
        self.sink.record(&entry)?;
        Ok(entry)
    }
}

/// RAII counter guard that decrements the live-connection count on drop.
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bind and run the billing service until the process is terminated. Blocking.
pub fn serve(config: BillingServiceConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("failed to bind ferrogate-billing on {}", config.listen))?;
    let token = config.token.clone();
    let service = Arc::new(BillingService {
        price_book: config.price_book,
        sink: config.sink,
        token: config.token,
    });
    let live_connections = Arc::new(AtomicUsize::new(0));
    println!(
        "ferrogate-billing listening on {} ({} price rules, {} credits/USD, auth {})",
        config.listen,
        service.price_book.len(),
        service.price_book.credits_per_usd,
        if token.is_some() { "required" } else { "off" }
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Shed load rather than spawn unbounded threads under a flood.
                if live_connections.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                live_connections.fetch_add(1, Ordering::SeqCst);
                let guard = ConnectionGuard(live_connections.clone());
                let service = service.clone();
                std::thread::spawn(move || {
                    let _guard = guard;
                    if let Err(error) = handle_connection(stream, &service) {
                        eprintln!("ferrogate-billing request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("ferrogate-billing accept failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, service: &BillingService) -> anyhow::Result<()> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set billing read timeout")?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set billing write timeout")?;
    let request = read_http_request(&mut stream)?;
    let response = route_request(service, &request);
    stream
        .write_all(&response.to_bytes())
        .context("failed to write billing service response")
}

fn route_request(service: &BillingService, request: &HttpRequest) -> HttpResponse {
    let is_health = matches!(
        (request.method.as_str(), request.path.as_str()),
        ("GET", "/healthz") | ("GET", "/v1/healthz")
    );
    // Every route except the readiness probe requires the shared secret when
    // one is configured (issue #136).
    if !is_health {
        if let Some(expected) = service.token.as_deref() {
            if !request_is_authorized(request, expected) {
                return HttpResponse::json(
                    401,
                    json!({ "error": { "code": "unauthorized", "message": "missing or invalid bearer token" } }),
                );
            }
        }
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") | ("GET", "/v1/healthz") => HttpResponse::json(
            200,
            json!({ "service": "ferrogate-billing", "status": "ok" }),
        ),
        ("POST", "/v1/billing/charge") => {
            match serde_json::from_slice::<BillingEvent>(&request.body) {
                Ok(event) => match service.charge_and_record(&event) {
                    Ok(entry) => HttpResponse::json(200, entry),
                    Err(error) => billing_error_response(&error),
                },
                Err(error) => bad_request(&error.to_string()),
            }
        }
        ("GET", "/v1/billing/ledger") => {
            let offset = request.query_param("offset").unwrap_or(0);
            let limit = request
                .query_param("limit")
                .unwrap_or(DEFAULT_LEDGER_PAGE_LIMIT)
                .clamp(1, MAX_LEDGER_PAGE_LIMIT);
            // Optional per-tenant scoping (issue #136), pushed into the sink's
            // query itself (issue #149) rather than filtering a fetched page
            // after the fact — otherwise a scoped page can silently come back
            // empty/incomplete in a busy, multi-tenant ledger.
            let filter = tenant_filter_from_request(request);
            match service.sink.list(&filter, offset, limit) {
                Ok(entries) => {
                    let totals = ledger_totals(&entries);
                    HttpResponse::json(200, json!({ "entries": entries, "page_totals": totals }))
                }
                Err(error) => billing_error_response(&error),
            }
        }
        ("GET", path) if path.starts_with("/v1/billing/ledger/") => {
            let id = path.trim_start_matches("/v1/billing/ledger/");
            match service.sink.get(id) {
                Ok(Some(entry)) => HttpResponse::json(200, entry),
                Ok(None) => HttpResponse::json(
                    404,
                    json!({ "error": { "code": "ledger_entry_not_found", "message": "no ledger entry with that id" } }),
                ),
                Err(error) => billing_error_response(&error),
            }
        }
        _ => HttpResponse::json(
            404,
            json!({ "error": { "code": "not_found", "message": "billing service endpoint not found" } }),
        ),
    }
}

fn ledger_totals(entries: &[LedgerEntry]) -> LedgerTotals {
    let mut totals = LedgerTotals {
        entries: entries.len(),
        ..LedgerTotals::default()
    };
    for entry in entries {
        totals.total_cost_usd += entry.cost.total_cost;
        totals.total_credits += entry.credits;
        totals.total_tokens += entry.usage.total_tokens;
    }
    totals
}

fn billing_error_response(error: &BillingError) -> HttpResponse {
    // Missing rate-card price is a client/config problem the caller must fix;
    // surface it as 422 (fail-closed, never bill zero). Everything else is 500.
    let status = if error.code == "price_not_found" {
        422
    } else {
        500
    };
    HttpResponse::json(
        status,
        json!({ "error": { "code": error.code, "message": error.message } }),
    )
}

fn bad_request(message: &str) -> HttpResponse {
    HttpResponse::json(
        400,
        json!({ "error": { "code": "invalid_json", "message": message } }),
    )
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn query_param(&self, key: &str) -> Option<usize> {
        self.query_str(key).and_then(|value| value.parse::<usize>().ok())
    }

    fn query_str(&self, key: &str) -> Option<&str> {
        self.query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == key).then_some(value)
        })
    }
}

/// Build a [`LedgerListFilter`] from the tenant identifiers present in the
/// query string. Any of `organization_id` / `project_id` / `api_key_id` may
/// be supplied; an absent field matches everything (issue #136). Pushed into
/// [`LedgerSink::list`] itself rather than filtering a fetched page after the
/// fact (issue #149).
fn tenant_filter_from_request(request: &HttpRequest) -> LedgerListFilter {
    LedgerListFilter {
        organization_id: request.query_str("organization_id").map(str::to_string),
        project_id: request.query_str("project_id").map(str::to_string),
        api_key_id: request.query_str("api_key_id").map(str::to_string),
    }
}

/// Constant-time check that the request presents `Authorization: Bearer <expected>`.
fn request_is_authorized(request: &HttpRequest, expected: &str) -> bool {
    let Some(header) = request.authorization.as_deref() else {
        return false;
    };
    let presented = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .unwrap_or("")
        .trim();
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).context("failed to read request")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request headers"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST_BYTES {
            return Err(anyhow!("request exceeds {MAX_REQUEST_BYTES} bytes"));
        }
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers.lines();
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
    let (path, query) = match raw_target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (raw_target.to_string(), String::new()),
    };
    let header_fields: Vec<(&str, &str)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()))
        .collect();
    let content_length = header_fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let authorization = header_fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.to_string());

    // Bound the declared body length before using it as a slice index so a
    // malformed/huge Content-Length cannot overflow or panic (issue #138).
    if content_length > MAX_REQUEST_BYTES {
        return Err(anyhow!(
            "content-length {content_length} exceeds {MAX_REQUEST_BYTES} bytes"
        ));
    }
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(content_length)
        .ok_or_else(|| anyhow!("content-length overflow"))?;
    while buffer.len() < body_end {
        let read = stream
            .read(&mut chunk)
            .context("failed to read request body")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request body"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST_BYTES {
            return Err(anyhow!("request exceeds {MAX_REQUEST_BYTES} bytes"));
        }
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        authorization,
        body: buffer[body_start..body_end].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json<T>(status: u16, body: T) -> Self
    where
        T: Serialize,
    {
        let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Self { status, body }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            422 => "Unprocessable Entity",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.status,
            status_text,
            self.body.len()
        );
        [headers.as_bytes(), &self.body].concat()
    }
}

#[cfg(test)]
#[path = "service_test.rs"]
mod tests;
