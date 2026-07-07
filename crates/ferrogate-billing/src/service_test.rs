// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the billing HTTP service: routing, auth (#136), and
//! tenant-scoped ledger reads.

use super::*;
use crate::pricing::PriceEntry;
use crate::{BillingUsageSource, ModelPrice, TokenUsage};
use ferrogate_core::TenantContext;

fn service() -> BillingService {
    service_with_token(None)
}

fn service_with_token(token: Option<&str>) -> BillingService {
    BillingService {
        price_book: PriceBook::new(vec![PriceEntry::new(
            "openai",
            "gpt-5.5",
            ModelPrice::usd(5.0, 15.0),
        )]),
        sink: Arc::new(crate::ledger::InMemoryLedgerSink::default()),
        token: token.map(str::to_string),
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
        metadata: std::collections::BTreeMap::new(),
    })
    .unwrap()
}

fn request(method: &str, path: &str, query: &str, body: Vec<u8>) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        authorization: None,
        body,
    }
}

fn authed_request(
    method: &str,
    path: &str,
    query: &str,
    body: Vec<u8>,
    bearer: &str,
) -> HttpRequest {
    let mut request = request(method, path, query, body);
    request.authorization = Some(format!("Bearer {bearer}"));
    request
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
    assert_eq!(
        service
            .sink
            .list(&LedgerListFilter::default(), 0, 10)
            .unwrap()
            .len(),
        1
    );
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

#[test]
fn auth_required_rejects_missing_or_wrong_token() {
    let service = service_with_token(Some("s3cret"));
    // No Authorization header.
    let unauth = route_request(
        &service,
        &request("GET", "/v1/billing/ledger", "", Vec::new()),
    );
    assert_eq!(unauth.status, 401);
    // Wrong token.
    let wrong = route_request(
        &service,
        &authed_request("GET", "/v1/billing/ledger", "", Vec::new(), "nope"),
    );
    assert_eq!(wrong.status, 401);
    // Charge is protected too.
    let charge = route_request(
        &service,
        &request(
            "POST",
            "/v1/billing/charge",
            "",
            event_json("openai", "gpt-5.5"),
        ),
    );
    assert_eq!(charge.status, 401);
    // Nothing was recorded.
    assert_eq!(
        service
            .sink
            .list(&LedgerListFilter::default(), 0, 10)
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn auth_required_allows_correct_token_and_leaves_health_open() {
    let service = service_with_token(Some("s3cret"));
    let ok = route_request(
        &service,
        &authed_request(
            "POST",
            "/v1/billing/charge",
            "",
            event_json("openai", "gpt-5.5"),
            "s3cret",
        ),
    );
    assert_eq!(ok.status, 200);
    // Readiness probe stays open even with auth configured.
    let health = route_request(&service, &request("GET", "/healthz", "", Vec::new()));
    assert_eq!(health.status, 200);
}

#[test]
fn constant_time_eq_matches_only_equal_slices() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
}

#[test]
fn ledger_read_scopes_by_tenant_query() {
    let service = service();
    for org in ["org-a", "org-b"] {
        let mut event: BillingEvent =
            serde_json::from_slice(&event_json("openai", "gpt-5.5")).unwrap();
        event.request_id = format!("req-{org}");
        event.trace_id = Some(format!("trace-{org}"));
        event.tenant.organization_id = Some(org.into());
        service.charge_and_record(&event).unwrap();
    }
    // Unfiltered: both orgs.
    let all = route_request(
        &service,
        &request("GET", "/v1/billing/ledger", "", Vec::new()),
    );
    let all: serde_json::Value = serde_json::from_slice(&all.body).unwrap();
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
    // Scoped to org-a: only that tenant's row.
    let scoped = route_request(
        &service,
        &request(
            "GET",
            "/v1/billing/ledger",
            "organization_id=org-a",
            Vec::new(),
        ),
    );
    let scoped: serde_json::Value = serde_json::from_slice(&scoped.body).unwrap();
    let entries = scoped["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["tenant"]["organization_id"], "org-a");
}
