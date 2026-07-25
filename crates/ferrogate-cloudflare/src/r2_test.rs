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
use crate::r2::{
    r2_bucket_name_for_tenant, r2_legacy_bucket_name_for_tenant, R2BucketCreation,
    R2CreateBucketRequest, R2_BUCKET_NAME_MAX_LEN, R2_BUCKET_NAME_MIN_LEN,
};
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
    let expected = r2_bucket_name_for_tenant("tenant-acme");
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        &format!(r#"{{ "success": true, "errors": [], "result": {{ "name": "{expected}" }} }}"#),
    )]));
    let client = cf_client(transport.clone());

    let provision = runtime()
        .block_on(client.ensure_tenant_r2_bucket("tenant-acme"))
        .expect("ensure should succeed");
    assert_eq!(provision.name, expected);
    assert!(provision.created);
    assert_eq!(
        provision.s3_endpoint,
        "https://acct-test.r2.cloudflarestorage.com"
    );

    // The derived name is what was POSTed.
    let body: serde_json::Value =
        serde_json::from_slice(transport.recorded()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["name"], expected);
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
    assert_eq!(provision.name, r2_bucket_name_for_tenant("tenant-acme"));
    // Already existed -> not created this call, but still reported as provisioned.
    assert!(!provision.created);
}

/// R2's documented bucket-name rules: 3-63 chars, `[a-z0-9-]` only, never
/// leading/trailing `-`.
fn assert_r2_valid(name: &str) {
    assert!(
        (R2_BUCKET_NAME_MIN_LEN..=R2_BUCKET_NAME_MAX_LEN).contains(&name.len()),
        "{name:?} has length {} outside R2's {R2_BUCKET_NAME_MIN_LEN}..={R2_BUCKET_NAME_MAX_LEN}",
        name.len()
    );
    assert!(
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "{name:?} contains a character R2 rejects"
    );
    assert!(
        !name.starts_with('-') && !name.ends_with('-'),
        "{name:?} starts or ends with a hyphen"
    );
}

#[test]
fn tenant_bucket_name_convention_is_deterministic_and_r2_valid() {
    // Pinned: `ferrogate-{cosmetic slug}-{32 hex of sha256 over
    // "ferrogate.r2.bucket.v1:{len}:{tenant}"}`. A change here is a bucket
    // migration, not a refactor.
    assert_eq!(
        r2_bucket_name_for_tenant("tenant-acme"),
        "ferrogate-tenant-acme-ca15640909342a7e67f6ae5a9dc32049"
    );
    // Deterministic across calls.
    assert_eq!(
        r2_bucket_name_for_tenant("tenant-acme"),
        r2_bucket_name_for_tenant("tenant-acme")
    );
    // The readable slug is lowercased/hyphen-folded, but the digest carries the
    // identity, so `Acme_Corp` and `acme-corp` share a slug and differ in name.
    assert!(r2_bucket_name_for_tenant("Acme_Corp").starts_with("ferrogate-acme-corp-"));
    assert!(r2_bucket_name_for_tenant("acme-corp").starts_with("ferrogate-acme-corp-"));
    // A trailing non-alphanumeric leaves no double hyphen before the digest.
    assert!(r2_bucket_name_for_tenant("acme.").starts_with("ferrogate-acme-"));
    assert!(!r2_bucket_name_for_tenant("acme.").contains("--"));
    // A tenant id with no alphanumerics at all drops the slug segment entirely
    // and is still a valid, tenant-unique name.
    assert_eq!(
        r2_bucket_name_for_tenant(""),
        "ferrogate-8785c4553f8630e6c14fd8e22a998d48"
    );
    assert_r2_valid(&r2_bucket_name_for_tenant(""));
    assert_ne!(
        r2_bucket_name_for_tenant(""),
        r2_bucket_name_for_tenant("_")
    );
}

/// Issue #490: the pre-#490 derivation folded case + every non-alphanumeric to
/// `-` and truncated at 63, so distinct tenants shared one bucket — and with
/// #462 layered on, each got a read+write credential for that *shared* bucket.
/// This is the tenant-isolation regression test.
#[test]
fn tenant_bucket_names_are_injective_for_the_490_colliding_ids() {
    // 1) The character-folding family from the issue: four distinct tenants,
    //    one legacy bucket.
    let folding = ["Acme_Corp", "acme-corp", "acme corp", "ACME.CORP"];
    for tenant in folding {
        assert_eq!(
            r2_legacy_bucket_name_for_tenant(tenant),
            "ferrogate-acme-corp",
            "the legacy derivation is expected to collide on {tenant:?}"
        );
    }
    assert_distinct(&folding);

    // 2) The truncation family: ids agreeing on their first 53 characters (63
    //    minus the 10-char `ferrogate-` prefix) collided under the legacy cap.
    let head = "t".repeat(53);
    let truncating = [
        format!("{head}alpha"),
        format!("{head}beta"),
        format!("{head}{}", "z".repeat(400)),
    ];
    let legacy: Vec<String> = truncating
        .iter()
        .map(|t| r2_legacy_bucket_name_for_tenant(t))
        .collect();
    assert_eq!(
        legacy[0], legacy[1],
        "the legacy derivation is expected to collide after truncation"
    );
    assert_eq!(legacy[0], legacy[2]);
    let truncating: Vec<&str> = truncating.iter().map(String::as_str).collect();
    assert_distinct(&truncating);

    // 3) Length-prefixed canonicalisation: a separator inside a tenant id
    //    cannot be used to imitate another identity.
    assert_distinct(&["a:b", "a", ":b", "3:a:b", "1:a"]);
}

/// Every derived name is R2-legal at both ends of the length range: the longest
/// possible tenant id still fits in 63 chars, and the shortest still clears 3.
#[test]
fn tenant_bucket_names_respect_r2_length_bounds() {
    // Longest shape: 10 (`ferrogate-`) + 20 (slug cap) + 1 (`-`) + 32 (digest).
    let longest = r2_bucket_name_for_tenant(&"a".repeat(4096));
    assert_eq!(longest.len(), R2_BUCKET_NAME_MAX_LEN);
    assert_r2_valid(&longest);
    // Shortest shape: no slug at all -> 10 + 32 = 42, comfortably over the min.
    let shortest = r2_bucket_name_for_tenant("");
    assert_eq!(shortest.len(), 42);
    assert_r2_valid(&shortest);

    // Sweep the boundary where the slug starts being truncated (and a mix of
    // multi-byte and folded characters, which must never produce an invalid or
    // over-long name).
    for len in 0..40 {
        for tenant in [
            "a".repeat(len),
            "A_".repeat(len),
            format!("{}é!", "9".repeat(len)),
        ] {
            assert_r2_valid(&r2_bucket_name_for_tenant(&tenant));
        }
    }
}

/// Truncated-slug tenants must still be distinguished by the digest — the exact
/// case the legacy 63-char truncation lost.
fn assert_distinct(tenants: &[&str]) {
    let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for tenant in tenants {
        let name = r2_bucket_name_for_tenant(tenant);
        assert_r2_valid(&name);
        if let Some(other) = seen.insert(name.clone(), tenant) {
            panic!("tenants {other:?} and {tenant:?} both map to bucket {name:?}");
        }
    }
}
