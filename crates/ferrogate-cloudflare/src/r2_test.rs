// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: R2 bucket-provisioning REST surface tests against a scripted (mocked) transport — no network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{
    Clock, CloudflareClient, HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use crate::config::CloudflareConfig;
use crate::error::CloudflareError;
use crate::r2::{r2_bucket_name_for_tenant, R2BucketCreation, R2CreateBucketRequest};
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

fn cf_client(transport: Arc<RecordingTransport>) -> CloudflareClient {
    CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport,
        Arc::new(InstantClock),
        RetryPolicy::default(),
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn create_bucket_posts_name_and_decodes_descriptor() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": {
            "name": "ferrogate-tenant-acme", "creation_date": "2026-07-24T00:00:00Z",
            "location": "wnam", "storage_class": "Standard", "jurisdiction": "default" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-tenant-acme")))
        .expect("create should succeed");
    match outcome {
        R2BucketCreation::Created(bucket) => {
            assert_eq!(bucket.name.as_deref(), Some("ferrogate-tenant-acme"));
            assert_eq!(bucket.location.as_deref(), Some("wnam"));
            assert_eq!(bucket.storage_class.as_deref(), Some("Standard"));
            assert_eq!(bucket.jurisdiction.as_deref(), Some("default"));
        }
        other => panic!("expected Created, got {other:?}"),
    }

    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, crate::client::HttpMethod::Post);
    assert!(requests[0].url.ends_with("/accounts/acct-test/r2/buckets"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["name"], "ferrogate-tenant-acme");
    // Optional fields are omitted, not sent as null.
    assert!(body.get("locationHint").is_none());
    assert!(body.get("storageClass").is_none());
}

#[test]
fn create_bucket_serializes_optional_fields_as_camel_case() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "name": "b" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let request = R2CreateBucketRequest {
        name: "b".to_string(),
        location_hint: Some("weur".to_string()),
        storage_class: Some("InfrequentAccess".to_string()),
    };
    runtime()
        .block_on(client.create_r2_bucket(&request))
        .expect("create should succeed");

    let body: serde_json::Value =
        serde_json::from_slice(transport.recorded()[0].body.as_ref().unwrap()).unwrap();
    // REST schema uses camelCase for the request body's optional fields.
    assert_eq!(body["locationHint"], "weur");
    assert_eq!(body["storageClass"], "InfrequentAccess");
}

#[test]
fn create_bucket_already_exists_code_10004_maps_to_ok() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [ { "code": 10004,
            "message": "The bucket you tried to create already exists, and you own it." } ] }"#,
    )]));
    let client = cf_client(transport.clone());

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("already-exists should map to Ok");
    assert_eq!(outcome, R2BucketCreation::AlreadyExists);
    assert!(!outcome.was_created());
    // The idempotent create still issued exactly one request.
    assert_eq!(transport.recorded().len(), 1);
}

#[test]
fn create_bucket_already_exists_s3_sibling_code_10073_maps_to_ok() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [ { "code": 10073, "message": "Bucket name already exists." } ] }"#,
    )]));
    let client = cf_client(transport);

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("BucketConflict should map to Ok");
    assert_eq!(outcome, R2BucketCreation::AlreadyExists);
}

#[test]
fn create_bucket_bare_409_conflict_maps_to_ok() {
    // A 409 with no structured code on the create path is still an already-exists
    // conflict and is treated idempotently.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [] }"#,
    )]));
    let client = cf_client(transport);

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("bare 409 should map to Ok");
    assert_eq!(outcome, R2BucketCreation::AlreadyExists);
}

#[test]
fn create_bucket_already_exists_code_10004_without_409_status_maps_to_ok() {
    // Non-vacuity guard for `R2_BUCKET_ALREADY_EXISTS_CODES` membership.
    // The account REST API (`client/v4`) can answer a duplicate create with
    // HTTP 200 + `success: false` carrying code 10004 -- i.e. WITHOUT an HTTP
    // 409. The sibling `code_10004_maps_to_ok` test uses status 409, so the
    // `status == 409` fast-path in `is_bucket_already_exists` subsumes it and
    // it would still pass even if 10004 were dropped from the code list. This
    // case removes the 409 crutch so the code-list membership itself is pinned:
    // drop 10004 from `R2_BUCKET_ALREADY_EXISTS_CODES` and this test fails.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": false, "errors": [ { "code": 10004,
            "message": "The bucket you tried to create already exists, and you own it." } ] }"#,
    )]));
    let client = cf_client(transport);

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("code 10004 at HTTP 200 must map to Ok via the already-exists code list");
    assert_eq!(outcome, R2BucketCreation::AlreadyExists);
}

#[test]
fn create_bucket_already_exists_code_10073_without_409_status_maps_to_ok() {
    // Companion non-vacuity guard for the S3-sibling code 10073, again at a
    // non-409 status so the assertion exercises the code list rather than the
    // `status == 409` fast-path.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": false, "errors": [ { "code": 10073, "message": "Bucket name already exists." } ] }"#,
    )]));
    let client = cf_client(transport);

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("code 10073 at HTTP 200 must map to Ok via the already-exists code list");
    assert_eq!(outcome, R2BucketCreation::AlreadyExists);
}

#[test]
fn list_buckets_decodes_wrapped_buckets_array() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "buckets": [
            { "name": "one", "creation_date": "2026-07-24T00:00:00Z" },
            { "name": "two", "jurisdiction": "eu" } ] } }"#,
    )]));
    let client = cf_client(transport.clone());

    let buckets = runtime()
        .block_on(client.list_r2_buckets())
        .expect("list should succeed");
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].name.as_deref(), Some("one"));
    assert_eq!(buckets[1].name.as_deref(), Some("two"));
    assert_eq!(buckets[1].jurisdiction.as_deref(), Some("eu"));

    let requests = transport.recorded();
    assert_eq!(requests[0].method, crate::client::HttpMethod::Get);
    assert!(requests[0].url.ends_with("/accounts/acct-test/r2/buckets"));
}

#[test]
fn delete_bucket_is_ack_style_and_targets_the_name() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": null }"#,
    )]));
    let client = cf_client(transport.clone());

    runtime()
        .block_on(client.delete_r2_bucket("ferrogate-tenant-acme"))
        .expect("delete should ack");
    let requests = transport.recorded();
    assert_eq!(requests[0].method, crate::client::HttpMethod::Delete);
    assert!(requests[0]
        .url
        .ends_with("/accounts/acct-test/r2/buckets/ferrogate-tenant-acme"));
}

#[test]
fn malformed_bucket_name_is_rejected_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let client = cf_client(transport.clone());

    let error = runtime()
        .block_on(client.delete_r2_bucket("../secrets"))
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Config(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

#[test]
fn unauthorized_create_maps_to_typed_unauthorized() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        401,
        r#"{ "success": false, "errors": [ { "code": 10000, "message": "Authentication error" } ] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-x")))
        .unwrap_err();
    match error {
        CloudflareError::Unauthorized { errors } => {
            assert_eq!(errors[0].code, 10000);
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn not_found_delete_maps_to_typed_api_error() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        404,
        r#"{ "success": false, "errors": [ { "code": 10006, "message": "The specified bucket does not exist." } ] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(client.delete_r2_bucket("ferrogate-missing"))
        .unwrap_err();
    match error {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 404);
            assert_eq!(errors[0].code, 10006);
            assert!(errors[0].message.contains("does not exist"));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[test]
fn ensure_tenant_bucket_creates_and_reports_endpoint() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "name": "ferrogate-tenant-acme" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let provision = runtime()
        .block_on(client.ensure_tenant_r2_bucket("tenant-acme"))
        .expect("ensure should succeed");
    assert_eq!(provision.name, "ferrogate-tenant-acme");
    assert!(provision.created);
    assert_eq!(
        provision.s3_endpoint,
        "https://acct-test.r2.cloudflarestorage.com"
    );

    // The derived name is what was POSTed.
    let body: serde_json::Value =
        serde_json::from_slice(transport.recorded()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["name"], "ferrogate-tenant-acme");
}

#[test]
fn ensure_tenant_bucket_is_idempotent_when_bucket_exists() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [ { "code": 10004, "message": "already exists" } ] }"#,
    )]));
    let client = cf_client(transport);

    let provision = runtime()
        .block_on(client.ensure_tenant_r2_bucket("tenant-acme"))
        .expect("ensure should be idempotent");
    assert_eq!(provision.name, "ferrogate-tenant-acme");
    // Already existed -> not created this call, but still reported as provisioned.
    assert!(!provision.created);
}

#[test]
fn tenant_bucket_name_convention_is_deterministic_and_r2_valid() {
    assert_eq!(
        r2_bucket_name_for_tenant("tenant-acme"),
        "ferrogate-tenant-acme"
    );
    // Uppercase is lowercased; non-alphanumerics become hyphens.
    assert_eq!(
        r2_bucket_name_for_tenant("Acme_Corp"),
        "ferrogate-acme-corp"
    );
    // A trailing non-alphanumeric does not leave a trailing hyphen.
    assert_eq!(r2_bucket_name_for_tenant("acme."), "ferrogate-acme");
    // Empty tenant collapses to the bare, still-valid prefix.
    assert_eq!(r2_bucket_name_for_tenant(""), "ferrogate");
    // Result never exceeds R2's 63-char cap.
    let long = r2_bucket_name_for_tenant(&"a".repeat(200));
    assert!(long.len() <= 63);
}
