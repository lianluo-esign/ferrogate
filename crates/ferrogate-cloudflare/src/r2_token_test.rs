// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Scoped per-tenant R2 API-token creation tests against a scripted (mocked) transport — no network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{
    Clock, CloudflareClient, HttpMethod, HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use crate::config::CloudflareConfig;
use crate::error::CloudflareError;
use crate::r2::r2_bucket_name_for_tenant;
use crate::r2_token::{
    CreateTokenResult, R2ScopedTokenRequest, R2TokenAccess,
    R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID, R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
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

/// The canonical SHA-256 test vector: SHA-256("abc").
const SHA256_OF_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn create_scoped_token_posts_bucket_scoped_policy_and_derives_credential() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        // The token `value` here is "abc" so the derived secret is a known vector.
        r#"{ "success": true, "errors": [], "result": {
            "id": "tok-abc123", "value": "abc", "name": "ferrogate-r2-ferrogate-tenant-acme",
            "status": "active" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let request = R2ScopedTokenRequest::read_write(
        "ferrogate-r2-ferrogate-tenant-acme",
        "ferrogate-tenant-acme",
    );
    let token = runtime()
        .block_on(client.create_scoped_r2_token(&request))
        .expect("create should succeed");

    // Credential shape: Access Key ID == token id; Secret == SHA-256(value).
    assert_eq!(token.token_id, "tok-abc123");
    assert_eq!(token.access_key_id, "tok-abc123");
    assert_eq!(token.secret_access_key, SHA256_OF_ABC);

    // The POST hit the account-owned tokens endpoint.
    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, HttpMethod::Post);
    assert!(
        requests[0].url.ends_with("/accounts/acct-test/tokens"),
        "unexpected url: {}",
        requests[0].url
    );

    // The policy is a single allow scoped to exactly the one bucket resource, with
    // the read+write R2 Bucket Item permission group.
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["name"], "ferrogate-r2-ferrogate-tenant-acme");
    let policies = body["policies"].as_array().expect("policies array");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["effect"], "allow");
    let resources = policies[0]["resources"]
        .as_object()
        .expect("resources object");
    assert_eq!(
        resources.len(),
        1,
        "token must be scoped to a single bucket"
    );
    let (scope_key, scope_val) = resources.iter().next().unwrap();
    assert_eq!(
        scope_key,
        "com.cloudflare.edge.r2.bucket.acct-test_default_ferrogate-tenant-acme"
    );
    assert_eq!(scope_val, "*");
    let groups = policies[0]["permission_groups"].as_array().expect("groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["id"], R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID);
}

#[test]
fn read_only_access_attaches_the_read_permission_group() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "tok-ro", "value": "abc" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let request = R2ScopedTokenRequest::read_only("ferrogate-r2-ro", "ferrogate-tenant-acme");
    runtime()
        .block_on(client.create_scoped_r2_token(&request))
        .expect("create should succeed");

    let body: serde_json::Value =
        serde_json::from_slice(transport.recorded()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(
        body["policies"][0]["permission_groups"][0]["id"],
        R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID
    );
    assert_eq!(
        R2TokenAccess::ReadOnly.permission_group_name(),
        "Workers R2 Storage Bucket Item Read"
    );
}

#[test]
fn secret_access_key_is_sha256_hex_lowercase_64_chars() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "tok", "value": "abc" } }"#,
    )]));
    let client = cf_client(transport);

    let token = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "ferrogate-b")),
        )
        .unwrap();
    assert_eq!(token.secret_access_key.len(), 64);
    assert_eq!(token.secret_access_key, SHA256_OF_ABC);
    assert!(token
        .secret_access_key
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn custom_jurisdiction_appears_in_resource_scope() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "tok", "value": "abc" } }"#,
    )]));
    let client = cf_client(transport.clone());

    let request = R2ScopedTokenRequest {
        token_name: "n".to_string(),
        bucket: "ferrogate-eu".to_string(),
        jurisdiction: "eu".to_string(),
        access: R2TokenAccess::ReadWrite,
    };
    runtime()
        .block_on(client.create_scoped_r2_token(&request))
        .unwrap();

    let body: serde_json::Value =
        serde_json::from_slice(transport.recorded()[0].body.as_ref().unwrap()).unwrap();
    let resources = body["policies"][0]["resources"].as_object().unwrap();
    assert!(resources.contains_key("com.cloudflare.edge.r2.bucket.acct-test_eu_ferrogate-eu"));
}

#[test]
fn missing_token_value_in_response_is_a_decode_error() {
    // A create response with no `value` cannot yield an S3 secret.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "tok" } }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "ferrogate-b")),
        )
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Decode(_)), "{error:?}");
}

#[test]
fn invalid_bucket_name_is_rejected_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let client = cf_client(transport.clone());

    // Underscore is invalid (and would corrupt the `_`-delimited resource id).
    let error = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "bad_bucket")),
        )
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Config(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

#[test]
fn invalid_jurisdiction_is_rejected_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let client = cf_client(transport.clone());

    let request = R2ScopedTokenRequest {
        token_name: "n".to_string(),
        bucket: "ferrogate-b".to_string(),
        jurisdiction: "eu_1".to_string(),
        access: R2TokenAccess::ReadWrite,
    };
    let error = runtime()
        .block_on(client.create_scoped_r2_token(&request))
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Config(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

#[test]
fn empty_token_name_is_rejected_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let client = cf_client(transport.clone());

    let error = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("  ", "ferrogate-b")),
        )
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
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "ferrogate-b")),
        )
        .unwrap_err();
    match error {
        CloudflareError::Unauthorized { errors } => assert_eq!(errors[0].code, 10000),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn under_scoped_create_maps_to_missing_scope() {
    // 9109 = "Unauthorized to access requested resource" — the token authenticates
    // but lacks the Account API Tokens Write permission to mint tokens.
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        403,
        r#"{ "success": false, "errors": [ { "code": 9109, "message": "Unauthorized to access requested resource" } ] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "ferrogate-b")),
        )
        .unwrap_err();
    assert!(
        matches!(error, CloudflareError::MissingScope { .. }),
        "{error:?}"
    );
}

#[test]
fn revoke_token_deletes_by_id_ack_style() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        // Real Cloudflare token ids are 32-char hex (no separators).
        r#"{ "success": true, "errors": [], "result": { "id": "ed17574386854bf78a67040be0a770b0" } }"#,
    )]));
    let client = cf_client(transport.clone());

    runtime()
        .block_on(client.revoke_r2_token("ed17574386854bf78a67040be0a770b0"))
        .expect("revoke should ack");
    let requests = transport.recorded();
    assert_eq!(requests[0].method, HttpMethod::Delete);
    assert!(requests[0]
        .url
        .ends_with("/accounts/acct-test/tokens/ed17574386854bf78a67040be0a770b0"));
}

#[test]
fn revoke_rejects_malformed_token_id_before_any_request() {
    let transport = Arc::new(RecordingTransport::new(vec![]));
    let client = cf_client(transport.clone());

    let error = runtime()
        .block_on(client.revoke_r2_token("../accounts"))
        .unwrap_err();
    assert!(matches!(error, CloudflareError::Config(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

#[test]
fn ensure_tenant_credentials_ensures_bucket_then_mints_scoped_token() {
    // The bucket name is the #490 injective derivation, not a slug of the id.
    let bucket = r2_bucket_name_for_tenant("tenant-acme");
    let transport = Arc::new(RecordingTransport::new(vec![
        // 1) ensure_tenant_r2_bucket -> create bucket.
        ok(
            200,
            &format!(r#"{{ "success": true, "errors": [], "result": {{ "name": "{bucket}" }} }}"#),
        ),
        // 2) create_scoped_r2_token -> mint token.
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "id": "tok-xyz", "value": "abc" } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());

    let provision = runtime()
        .block_on(client.ensure_tenant_r2_credentials("tenant-acme"))
        .expect("ensure should succeed");

    assert_eq!(provision.bucket.name, bucket);
    assert!(provision.bucket.created);
    assert_eq!(
        provision.bucket.s3_endpoint,
        "https://acct-test.r2.cloudflarestorage.com"
    );
    assert_eq!(provision.token.access_key_id, "tok-xyz");
    assert_eq!(provision.token.secret_access_key, SHA256_OF_ABC);

    let requests = transport.recorded();
    assert_eq!(requests.len(), 2);
    // Bucket create first.
    assert!(requests[0].url.ends_with("/accounts/acct-test/r2/buckets"));
    // Then a token minted, scoped to the derived bucket, named after it.
    assert!(requests[1].url.ends_with("/accounts/acct-test/tokens"));
    let token_body: serde_json::Value =
        serde_json::from_slice(requests[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(token_body["name"], format!("ferrogate-r2-{bucket}"));
    let resources = token_body["policies"][0]["resources"].as_object().unwrap();
    assert!(resources.contains_key(&format!(
        "com.cloudflare.edge.r2.bucket.acct-test_default_{bucket}"
    )));
}

#[test]
fn ensure_tenant_credentials_mints_token_even_when_bucket_already_exists() {
    let transport = Arc::new(RecordingTransport::new(vec![
        // Bucket already exists (idempotent create -> AlreadyExists).
        ok(
            409,
            r#"{ "success": false, "errors": [ { "code": 10004, "message": "already exists" } ] }"#,
        ),
        // Token still minted.
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "id": "tok-2", "value": "abc" } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());

    let provision = runtime()
        .block_on(client.ensure_tenant_r2_credentials("tenant-acme"))
        .expect("ensure should succeed even when the bucket pre-exists");
    assert!(!provision.bucket.created);
    assert_eq!(provision.token.token_id, "tok-2");
    assert_eq!(transport.recorded().len(), 2);
}

#[test]
fn debug_redacts_the_secret_access_key() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "tok", "value": "abc" } }"#,
    )]));
    let client = cf_client(transport);

    let token = runtime()
        .block_on(
            client.create_scoped_r2_token(&R2ScopedTokenRequest::read_write("n", "ferrogate-b")),
        )
        .unwrap();
    let rendered = format!("{token:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        !rendered.contains(SHA256_OF_ABC),
        "secret leaked into Debug: {rendered}"
    );
}

/// Issue #492: `CreateTokenResult` holds Cloudflare's **one-time plaintext**
/// token value — the input the R2 secret access key is derived from — in a
/// `String`, so a derived `Debug` renders it verbatim. That is strictly worse
/// than the `Vec<u8>` response body #489 closed one frame earlier on this same
/// path: no decoding needed, and it is one `{:?}`, `unwrap()` or `anyhow`
/// context away from a log line.
#[test]
fn create_token_result_debug_redacts_the_one_time_value() {
    const ONE_TIME_VALUE: &str = "v1.0-cloudflare-one-time-token-value";

    let result = CreateTokenResult {
        id: "tok123".to_string(),
        value: Some(ONE_TIME_VALUE.to_string()),
    };
    let rendered = format!("{result:?}");

    assert!(
        !rendered.contains(ONE_TIME_VALUE),
        "one-time token value leaked into CreateTokenResult Debug: {rendered}"
    );
    // A prefix is a leak too (this value is machine-generated entropy).
    for prefix_len in [4usize, 8, 16] {
        assert!(
            !rendered.contains(&ONE_TIME_VALUE[..prefix_len]),
            "a {prefix_len}-char prefix of the one-time token value leaked: {rendered}"
        );
    }
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The token id is not secret and is what a revoke/triage needs.
    assert!(rendered.contains("tok123"), "{rendered}");
}

/// Present-vs-absent must survive the redaction: `create_scoped_r2_token` turns
/// a missing `value` into a typed `Decode` error, and a `Debug` that rendered
/// `<redacted>` either way would make that failure undiagnosable.
#[test]
fn create_token_result_debug_distinguishes_a_missing_value() {
    let rendered = format!(
        "{:?}",
        CreateTokenResult {
            id: "tok123".to_string(),
            value: None,
        }
    );

    assert!(rendered.contains("None"), "{rendered}");
    assert!(!rendered.contains("<redacted>"), "{rendered}");
}
