// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 proxy-Worker client tests against a scripted (mocked) transport — no network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::client::{HttpRequest, HttpResponse, HttpTransport};
use crate::d1_proxy::{D1ProxyClient, D1ProxyStatement};
use crate::error::CloudflareError;
use crate::resolver::EnvTokenResolver;

/// Records every request and replays scripted responses (mirrors the REST
/// client's `d1_test` transport).
struct RecordingTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<Result<HttpResponse, CloudflareError>>>,
}

impl RecordingTransport {
    fn new(responses: Vec<Result<HttpResponse, CloudflareError>>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }

    fn recorded(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted transport ran out of responses")
    }
}

fn ok(status: u16, body: &str) -> Result<HttpResponse, CloudflareError> {
    Ok(HttpResponse {
        status,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    })
}

fn proxy_client(transport: Arc<RecordingTransport>) -> D1ProxyClient {
    D1ProxyClient::new(
        "https://ferrogate-d1-proxy.example.workers.dev/",
        transport,
        Arc::new(EnvTokenResolver::from_process_env()),
        "plaintext-proxy-token",
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn body_json(request: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(request.body.as_ref().expect("request should carry a body")).unwrap()
}

#[test]
fn batch_posts_statements_with_bearer_and_decodes_per_statement_results() {
    // Two per-statement results; the first carries a RETURNING row.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[
            {"results":[{"billing_event_id":"evt-1"}],"success":true,
             "meta":{"changes":1,"last_row_id":7}},
            {"results":[],"success":true,"meta":{"changes":1}}
        ]}"#,
    )]));
    let client = proxy_client(transport.clone());

    let statements = vec![
        D1ProxyStatement::with_params(
            "INSERT INTO billing_events (billing_event_id) VALUES (?) \
             ON CONFLICT DO NOTHING RETURNING billing_event_id",
            vec!["evt-1".to_string()],
        ),
        D1ProxyStatement::with_params(
            "INSERT INTO billing_report_outbox (id) VALUES (?) ON CONFLICT DO NOTHING",
            vec!["evt-1".to_string()],
        ),
    ];
    let results = runtime()
        .block_on(client.batch(&statements))
        .expect("batch should decode");

    // One D1QueryResult per statement, in order.
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].results.len(), 1);
    assert_eq!(results[0].results[0]["billing_event_id"], "evt-1");
    assert_eq!(results[0].changes(), 1);
    assert!(results[1].results.is_empty());

    // The request is POSTed to /d1/batch with the Bearer token and the exact
    // { statements: [{ sql, params }, ...] } envelope.
    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(
        request.url.ends_with("/d1/batch"),
        "url was {}",
        request.url
    );
    // base_url's trailing slash is not doubled.
    assert!(!request.url.contains("workers.dev//d1"));
    assert_eq!(request.bearer_token, "plaintext-proxy-token");
    let json = body_json(request);
    let sent = json["statements"].as_array().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["params"][0], "evt-1");
    assert!(sent[0]["sql"].as_str().unwrap().contains("RETURNING"));
    assert_eq!(sent[1]["sql"], statements[1].sql);
}

#[test]
fn query_posts_single_statement_and_decodes_returning_rows() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{"success":true,"errors":[],"result":
            {"results":[{"id":"row-1","state":"active"}],"success":true,"meta":{"changes":1}}}"#,
    )]));
    let client = proxy_client(transport.clone());

    let statement = D1ProxyStatement::with_params(
        "UPDATE wallets SET state = ? WHERE id = ? RETURNING id, state",
        vec!["active".to_string(), "row-1".to_string()],
    );
    let result = runtime()
        .block_on(client.query(&statement))
        .expect("query should decode");

    assert_eq!(result.results.len(), 1);
    assert_eq!(result.results[0]["state"], "active");

    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/query"));
    // The query body IS the statement object { sql, params } (no wrapper).
    let json = body_json(&requests[0]);
    assert_eq!(json["params"][0], "active");
    assert_eq!(json["params"][1], "row-1");
    assert!(json["sql"].as_str().unwrap().contains("RETURNING"));
}

#[test]
fn batch_on_carries_the_selected_database_binding() {
    // A tenant-scoped batch (issue #455) tags the body with the target binding
    // NAME; the control-DB default (`None`) omits it.
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{"success":true,"errors":[],"result":[{"results":[],"success":true,"meta":{}}]}"#,
        ),
        ok(
            200,
            r#"{"success":true,"errors":[],"result":[{"results":[],"success":true,"meta":{}}]}"#,
        ),
    ]));
    let client = proxy_client(transport.clone());
    let statements = vec![D1ProxyStatement::new(
        "INSERT INTO wallet_reservations DEFAULT VALUES",
    )];

    runtime()
        .block_on(client.batch_on(Some("TENANT_DB_ACME"), &statements))
        .expect("tenant batch should decode");
    runtime()
        .block_on(client.batch_on(None, &statements))
        .expect("control batch should decode");

    let requests = transport.recorded();
    // The tenant batch names the binding.
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    // The control-DB batch omits `database` entirely (unchanged #450 wire shape).
    assert!(body_json(&requests[1]).get("database").is_none());
    assert!(body_json(&requests[1])["statements"].is_array());
}

#[test]
fn query_on_carries_the_selected_database_binding() {
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{"success":true,"errors":[],"result":{"results":[],"success":true,"meta":{}}}"#,
        ),
        ok(
            200,
            r#"{"success":true,"errors":[],"result":{"results":[],"success":true,"meta":{}}}"#,
        ),
    ]));
    let client = proxy_client(transport.clone());
    let statement = D1ProxyStatement::with_params(
        "UPDATE wallet_reservations SET status = ? WHERE id = ? RETURNING id",
        vec!["released".to_string(), "hold-1".to_string()],
    );

    runtime()
        .block_on(client.query_on(Some("TENANT_DB_ACME"), &statement))
        .expect("tenant query should decode");
    runtime()
        .block_on(client.query_on(None, &statement))
        .expect("control query should decode");

    let requests = transport.recorded();
    // The tenant query flattens the statement AND names the binding.
    let tenant = body_json(&requests[0]);
    assert_eq!(tenant["database"], "TENANT_DB_ACME");
    assert_eq!(tenant["params"][1], "hold-1");
    assert!(tenant["sql"].as_str().unwrap().contains("RETURNING"));
    // The control query omits `database`; the body is the bare `{ sql, params }`.
    let control = body_json(&requests[1]);
    assert!(control.get("database").is_none());
    assert_eq!(control["params"][0], "released");
}

#[test]
fn proxy_bearer_rejection_maps_to_unauthorized() {
    // The Worker's fail-closed 403 (invalid bearer) — even as a bare `{error}`
    // body — maps through the shared envelope path to a typed Unauthorized.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        403,
        r#"{"error":"invalid bearer token"}"#,
    )]));
    let client = proxy_client(transport);

    let error = runtime()
        .block_on(client.query(&D1ProxyStatement::new("SELECT 1")))
        .expect_err("a 403 must surface as an error");
    assert!(
        matches!(error, CloudflareError::Unauthorized { .. }),
        "expected Unauthorized, got {error:?}"
    );
}

#[test]
fn proxy_batch_rollback_error_surfaces_as_api_error() {
    // A failing statement rolls the whole batch back; the Worker answers a
    // 502 error envelope, which the client surfaces as a typed API error.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        502,
        r#"{"success":false,"errors":[{"code":5001,"message":"d1 batch failed (rolled back)"}],
            "result":null}"#,
    )]));
    let client = proxy_client(transport);

    let error = runtime()
        .block_on(client.batch(&[D1ProxyStatement::new("INSERT INTO t VALUES (1)")]))
        .expect_err("a rolled-back batch must surface as an error");
    match error {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 502);
            assert_eq!(errors[0].code, 5001);
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}
