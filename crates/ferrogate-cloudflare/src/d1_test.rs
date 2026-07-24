// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 REST endpoint wrapper tests against a scripted (mocked) transport — no network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{
    Clock, CloudflareClient, HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use crate::config::CloudflareConfig;
use crate::d1::{D1Client, D1CreateDatabaseRequest};
use crate::error::CloudflareError;
use crate::resolver::EnvTokenResolver;

/// Clock that never sleeps (retries would otherwise stall the test).
struct InstantClock;

#[async_trait]
impl Clock for InstantClock {
    async fn sleep(&self, _duration: Duration) {}
}

/// Transport that records every request and replays scripted responses.
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

fn d1_client(transport: Arc<RecordingTransport>) -> D1Client {
    D1Client::new(Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport,
        Arc::new(InstantClock),
        RetryPolicy::default(),
    )))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn create_database_posts_name_and_decodes_uuid() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": {
            "uuid": "db-uuid-1", "name": "ferrogate-tenant-acme",
            "version": "production", "created_at": "2026-07-24T00:00:00Z" } }"#,
    )]));
    let d1 = d1_client(transport.clone());

    let created = runtime()
        .block_on(d1.create_database(&D1CreateDatabaseRequest::named("ferrogate-tenant-acme")))
        .expect("create should succeed");
    assert_eq!(created.uuid.as_deref(), Some("db-uuid-1"));
    assert_eq!(created.name.as_deref(), Some("ferrogate-tenant-acme"));

    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/accounts/acct-test/d1/database"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["name"], "ferrogate-tenant-acme");
    // Optional fields are omitted, not sent as null.
    assert!(body.get("primary_location_hint").is_none());
    assert!(body.get("jurisdiction").is_none());
}

#[test]
fn list_databases_decodes_descriptor_array() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": [
            { "uuid": "db-1", "name": "a" }, { "uuid": "db-2", "name": "b" } ] }"#,
    )]));
    let d1 = d1_client(transport.clone());

    let databases = runtime().block_on(d1.list_databases()).unwrap();
    assert_eq!(databases.len(), 2);
    assert_eq!(databases[1].uuid.as_deref(), Some("db-2"));
    assert!(transport.recorded()[0].url.contains("per_page=1000"));
}

#[test]
fn delete_database_is_ack_style_and_tolerates_null_result() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": null }"#,
    )]));
    let d1 = d1_client(transport.clone());

    runtime()
        .block_on(d1.delete_database("db-uuid-1"))
        .expect("delete should ack");
    assert!(transport.recorded()[0]
        .url
        .ends_with("/accounts/acct-test/d1/database/db-uuid-1"));
}

#[test]
fn query_posts_sql_with_string_params_and_decodes_rows_and_meta() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": [ {
            "results": [ { "id": "t1", "name": "Acme", "created_at_unix": 1753 } ],
            "success": true,
            "meta": { "changes": 1, "last_row_id": 7, "rows_read": 3,
                      "rows_written": 1, "duration": 0.5, "served_by_region": "WNAM" }
        } ] }"#,
    )]));
    let d1 = d1_client(transport.clone());

    let results = runtime()
        .block_on(d1.query(
            "db-uuid-1",
            "SELECT id, name, created_at_unix FROM tenants WHERE id = ?",
            &["t1".to_string()],
        ))
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].results[0]["name"], "Acme");
    let meta = results[0].meta.clone().unwrap();
    assert_eq!(meta.changes, Some(1));
    assert_eq!(meta.last_row_id, Some(7));
    assert_eq!(meta.rows_read, Some(3));
    assert_eq!(meta.rows_written, Some(1));
    assert_eq!(results[0].changes(), 1);

    let requests = transport.recorded();
    assert!(requests[0]
        .url
        .ends_with("/accounts/acct-test/d1/database/db-uuid-1/query"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["params"], serde_json::json!(["t1"]));
    // Params are STRINGS per the documented REST schema.
    assert!(body["params"][0].is_string());
}

#[test]
fn query_error_envelope_maps_to_typed_api_error() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        400,
        r#"{ "success": false, "errors": [ { "code": 7500, "message": "no such table: nope" } ] }"#,
    )]));
    let d1 = d1_client(transport);

    let error = runtime()
        .block_on(d1.query("db-uuid-1", "SELECT * FROM nope", &[]))
        .unwrap_err();
    match error {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 400);
            assert_eq!(errors[0].code, 7500);
            assert!(errors[0].message.contains("no such table"));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[test]
fn malformed_database_id_is_rejected_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let d1 = d1_client(transport.clone());

    let error = runtime()
        .block_on(d1.query("../secrets", "SELECT 1", &[]))
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Config(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}
