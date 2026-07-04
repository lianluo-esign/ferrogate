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
    sync::Arc,
};

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::json;

use crate::{
    charge,
    ledger::{LedgerSink, LedgerTotals},
    pricing::PriceBook,
    BillingError, BillingEvent, LedgerEntry,
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const DEFAULT_LEDGER_PAGE_LIMIT: usize = 100;
const MAX_LEDGER_PAGE_LIMIT: usize = 1000;

/// Runtime configuration for [`serve`]. Ownership of the rate card and the
/// persistence sink is transferred to the service.
#[derive(Clone)]
pub struct BillingServiceConfig {
    pub listen: String,
    pub price_book: PriceBook,
    pub sink: Arc<dyn LedgerSink>,
}

impl std::fmt::Debug for BillingServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BillingServiceConfig")
            .field("listen", &self.listen)
            .field("price_book_entries", &self.price_book.len())
            .field("credits_per_usd", &self.price_book.credits_per_usd)
            .field("sink", &"dyn LedgerSink")
            .finish()
    }
}

/// The service state shared across connection threads.
struct BillingService {
    price_book: PriceBook,
    sink: Arc<dyn LedgerSink>,
}

impl BillingService {
    /// Price a usage event and persist the resulting ledger entry.
    fn charge_and_record(&self, event: &BillingEvent) -> Result<LedgerEntry, BillingError> {
        let entry = charge(&self.price_book, event)?;
        self.sink.record(&entry)?;
        Ok(entry)
    }
}

/// Bind and run the billing service until the process is terminated. Blocking.
pub fn serve(config: BillingServiceConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("failed to bind ferrogate-billing on {}", config.listen))?;
    let service = Arc::new(BillingService {
        price_book: config.price_book,
        sink: config.sink,
    });
    println!(
        "ferrogate-billing listening on {} ({} price rules, {} credits/USD)",
        config.listen,
        service.price_book.len(),
        service.price_book.credits_per_usd
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let service = service.clone();
                std::thread::spawn(move || {
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
    let request = read_http_request(&mut stream)?;
    let response = route_request(service, &request);
    stream
        .write_all(&response.to_bytes())
        .context("failed to write billing service response")
}

fn route_request(service: &BillingService, request: &HttpRequest) -> HttpResponse {
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
            match service.sink.list(offset, limit) {
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
    body: Vec<u8>,
}

impl HttpRequest {
    fn query_param(&self, key: &str) -> Option<usize> {
        self.query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            if name == key {
                value.parse::<usize>().ok()
            } else {
                None
            }
        })
    }
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
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
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
        body: buffer[body_start..body_start + content_length].to_vec(),
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
mod tests {
    use super::*;
    use crate::pricing::PriceEntry;
    use crate::{BillingUsageSource, ModelPrice, TokenUsage};
    use ferrogate_core::TenantContext;

    fn service() -> BillingService {
        BillingService {
            price_book: PriceBook::new(vec![PriceEntry::new(
                "openai",
                "gpt-5.5",
                ModelPrice::usd(5.0, 15.0),
            )]),
            sink: Arc::new(crate::ledger::InMemoryLedgerSink::default()),
        }
    }

    fn event_json(provider: &str, model: &str) -> Vec<u8> {
        serde_json::to_vec(&BillingEvent {
            request_id: "req-http".into(),
            trace_id: Some("trace-http".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            logical_model: "fast-chat".into(),
            provider: provider.into(),
            provider_model: model.into(),
            usage: TokenUsage::new(1_000, 2_000, 3_000),
            usage_source: BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1),
            cost_usd: None,
            latency_ms: None,
        })
        .unwrap()
    }

    fn request(method: &str, path: &str, query: &str, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            body,
        }
    }

    #[test]
    fn charge_route_records_and_returns_ledger_entry() {
        let service = service();
        let response = route_request(
            &service,
            &request(
                "POST",
                "/v1/billing/charge",
                "",
                event_json("openai", "gpt-5.5"),
            ),
        );
        assert_eq!(response.status, 200);
        let entry: LedgerEntry = serde_json::from_slice(&response.body).unwrap();
        assert!((entry.cost.total_cost - 0.035).abs() < 1e-9);
        assert_eq!(service.sink.list(0, 10).unwrap().len(), 1);
    }

    #[test]
    fn charge_route_fails_closed_with_422() {
        let response = route_request(
            &service(),
            &request(
                "POST",
                "/v1/billing/charge",
                "",
                event_json("mystery", "model"),
            ),
        );
        assert_eq!(response.status, 422);
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["error"]["code"], "price_not_found");
    }

    #[test]
    fn ledger_route_lists_with_totals() {
        let service = service();
        route_request(
            &service,
            &request(
                "POST",
                "/v1/billing/charge",
                "",
                event_json("openai", "gpt-5.5"),
            ),
        );
        let response = route_request(
            &service,
            &request("GET", "/v1/billing/ledger", "limit=10", Vec::new()),
        );
        assert_eq!(response.status, 200);
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["entries"].as_array().unwrap().len(), 1);
        assert_eq!(value["page_totals"]["entries"], 1);
    }

    #[test]
    fn healthz_ok() {
        let response = route_request(&service(), &request("GET", "/healthz", "", Vec::new()));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn query_param_parsing() {
        let req = request("GET", "/v1/billing/ledger", "offset=5&limit=20", Vec::new());
        assert_eq!(req.query_param("offset"), Some(5));
        assert_eq!(req.query_param("limit"), Some(20));
        assert_eq!(req.query_param("missing"), None);
    }
}
