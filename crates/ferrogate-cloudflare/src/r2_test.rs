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
    r2_bucket_name_for_tenant, R2BucketCreation, R2CreateBucketRequest, R2_BUCKET_NAME_MAX_LEN,
    R2_BUCKET_NAME_MIN_LEN,
};
use crate::resolver::EnvTokenResolver;

/// The **pre-#490** tenant bucket-name derivation, reproduced here as a test
/// fixture. This is a historical record, not production code.
///
/// It used to live in `r2.rs` as a `pub fn r2_legacy_bucket_name_for_tenant`
/// "for migration lookups only". Issue #496 removed it from the crate's public
/// surface: it had no non-test caller, no migration tool ever consumed it, and
/// a `pub` helper with no caller advertises a capability the project does not
/// have. Nothing in this tree has ever provisioned a bucket under a
/// tenant-derived name (`ensure_tenant_r2_bucket` reaches only
/// `ensure_tenant_r2_credentials`, which has no non-test caller; the live
/// probes create ad-hoc `ferrogate-gate-probe-…` buckets and delete them), so
/// there is no legacy bucket to look up. See the `r2` module docs for what a
/// migration would owe if one is ever found.
///
/// The algorithm is copied verbatim from the deleted function: prefix, then
/// lowercase every ASCII alphanumeric and fold everything else to `-`,
/// truncate at 63, trim trailing `-`. The constants are **hardcoded on
/// purpose** — this reproduces what the code did in the past, so it must not
/// drift when `R2_BUCKET_NAME_MAX_LEN` or the prefix change.
fn legacy_bucket_name_pre_490(tenant: &str) -> String {
    let mut name = String::from("ferrogate-");
    for c in tenant.chars() {
        name.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        });
    }
    // All pushed bytes are ASCII, so truncating at a byte index is char-safe.
    name.truncate(63);
    name.trim_end_matches('-').to_string()
}

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

/// Issue #490: the create path used to absorb **any** HTTP 409 into
/// `AlreadyExists`. A swallowed error must not be indistinguishable from
/// success — `AlreadyExists` tells the caller a bucket exists, and #462 then
/// mints a read+write credential scoped to that name. A 409 with no recognised
/// code is not the documented already-exists case, so it must surface.
#[test]
fn create_bucket_bare_409_conflict_surfaces_as_a_typed_api_error() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect_err("a codeless 409 is not the idempotent already-exists case");
    match error {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 409);
            assert!(errors.is_empty());
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

/// A 409 carrying some *other* conflict code (here: the bucket is mid-deletion)
/// is a real failure — the bucket does not exist, so reporting it as provisioned
/// would hand #462 a credential for a name with nothing behind it.
#[test]
fn create_bucket_unrelated_409_conflict_code_surfaces_as_a_typed_api_error() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [ { "code": 10035,
            "message": "The bucket you tried to create is being deleted." } ] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect_err("an unrelated 409 conflict must not read as successful provisioning");
    match error {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 409);
            assert_eq!(errors[0].code, 10035);
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

/// The idempotency signal is the error *code*, not the status: Cloudflare also
/// answers a duplicate create with `success: false` + `10004` under HTTP 200.
#[test]
fn create_bucket_already_exists_code_is_absorbed_regardless_of_status() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        200,
        r#"{ "success": false, "errors": [ { "code": 10004, "message": "already exists" } ] }"#,
    )]));
    let client = cf_client(transport);

    let outcome = runtime()
        .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-existing")))
        .expect("a 10004 code is the idempotent case whatever the status");
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

    // A response with no `result_info` is the last (and only) page.
    let requests = transport.recorded();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, crate::client::HttpMethod::Get);
    assert!(
        requests[0]
            .url
            .ends_with("/accounts/acct-test/r2/buckets?per_page=1000"),
        "{}",
        requests[0].url
    );
}

/// Issue #490: R2's bucket list is cursor-paginated and the client used to send
/// no `per_page` and follow no cursor, so it returned Cloudflare's first page
/// (default 20 rows) as if it were the whole account. That made "bucket absent"
/// indistinguishable from "bucket not on page 1" — the live probe's
/// absent-after-delete check could pass vacuously.
#[test]
fn list_buckets_follows_the_result_info_cursor_across_pages() {
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "one" } ] },
                 "result_info": { "cursor": "cur/one+two=", "per_page": 1 } }"#,
        ),
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "two" } ] },
                 "result_info": { "cursor": "cur-2", "per_page": 1 } }"#,
        ),
        // Empty cursor = last page (Cloudflare signals the end both by omitting
        // the field and by sending "").
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "three" } ] },
                 "result_info": { "cursor": "", "per_page": 1 } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());

    let buckets = runtime()
        .block_on(client.list_r2_buckets())
        .expect("list should walk every page");
    let names: Vec<&str> = buckets.iter().filter_map(|b| b.name.as_deref()).collect();
    assert_eq!(names, ["one", "two", "three"]);

    let requests = transport.recorded();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0].url.ends_with("?per_page=1000"),
        "{}",
        requests[0].url
    );
    // The opaque cursor is percent-encoded, so `/` and `+` cannot corrupt the
    // query string or be re-read as a path separator.
    assert!(
        requests[1]
            .url
            .ends_with("?per_page=1000&cursor=cur%2Fone%2Btwo%3D"),
        "{}",
        requests[1].url
    );
    assert!(
        requests[2].url.ends_with("?per_page=1000&cursor=cur-2"),
        "{}",
        requests[2].url
    );
}

/// A server that repeats the cursor it was just handed makes no progress; the
/// walk must terminate rather than spin. Same for a page with no rows.
#[test]
fn list_buckets_terminates_on_a_repeated_cursor_or_an_empty_page() {
    let repeated = |body: &str| ok(200, body);
    let transport = Arc::new(RecordingTransport::new(vec![
        repeated(
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "one" } ] },
                 "result_info": { "cursor": "stuck" } }"#,
        ),
        repeated(
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "two" } ] },
                 "result_info": { "cursor": "stuck" } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());
    let buckets = runtime()
        .block_on(client.list_r2_buckets())
        .expect("a repeated cursor must stop the walk");
    assert_eq!(buckets.len(), 2);
    assert_eq!(transport.recorded().len(), 2);

    // An empty page ends the walk even when a fresh cursor is offered.
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "one" } ] },
                 "result_info": { "cursor": "c1" } }"#,
        ),
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [] },
                 "result_info": { "cursor": "c2" } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());
    let buckets = runtime()
        .block_on(client.list_r2_buckets())
        .expect("an empty page must stop the walk");
    assert_eq!(buckets.len(), 1);
    assert_eq!(transport.recorded().len(), 2);
}

/// A failure on page 2 must surface, not be reported as a short-but-complete
/// list — the partial answer is the vacuous-pass hazard all over again.
#[test]
fn list_buckets_propagates_an_error_from_a_later_page() {
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [ { "name": "one" } ] },
                 "result_info": { "cursor": "c1" } }"#,
        ),
        ok(
            400,
            r#"{ "success": false, "errors": [ { "code": 10001, "message": "bad cursor" } ] }"#,
        ),
    ]));
    let client = cf_client(transport);
    let error = runtime()
        .block_on(client.list_r2_buckets())
        .expect_err("a mid-walk failure must not read as a complete list");
    assert!(
        matches!(error, CloudflareError::Api { status: 400, .. }),
        "{error:?}"
    );
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

/// Issue #490: `r2_bucket_name_for_tenant` is infallible by design and happily
/// derives `ferrogate-8785c455…` for `""`. That is fine for a derivation and
/// wrong for a provisioning entry point — an identity-free tenant id is a caller
/// bug, and provisioning real storage (and, via #462, a real credential) for it
/// would hide the bug behind a success.
#[test]
fn ensure_tenant_bucket_rejects_an_identity_free_tenant_id_before_any_request() {
    for tenant in ["", "   ", "___", "-", "..."] {
        let transport = Arc::new(RecordingTransport::new(vec![]));
        let client = cf_client(transport.clone());
        let error = runtime()
            .block_on(client.ensure_tenant_r2_bucket(tenant))
            .unwrap_err();
        assert!(
            matches!(error, CloudflareError::Config(_)),
            "tenant {tenant:?} produced {error:?}"
        );
        // Rejected before the wire, so nothing was provisioned.
        assert!(transport.recorded().is_empty());
    }

    // The derivation itself stays infallible — only the entry point gates.
    assert_eq!(
        r2_bucket_name_for_tenant(""),
        "ferrogate-8785c4553f8630e6c14fd8e22a998d48"
    );
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

/// Issue #496: guard the fixture the collision demonstration now rests on.
///
/// When `r2_legacy_bucket_name_for_tenant` was a real function in `r2.rs`, the
/// collision tests below were checking production code. Now they check
/// [`legacy_bucket_name_pre_490`], so the fixture itself must be pinned — a
/// fixture that quietly became `|_| "ferrogate-x".to_string()` would make every
/// "these tenants collide" assertion pass while demonstrating nothing, which is
/// exactly the vacuous-green failure mode this repo keeps hitting (#500).
///
/// So: exact outputs across the shapes that matter, AND non-constancy.
#[test]
fn legacy_fixture_still_reproduces_the_pre_490_derivation() {
    // Lowercasing + non-alphanumeric folding, the whole reason the old
    // derivation lost injectivity.
    assert_eq!(
        legacy_bucket_name_pre_490("Acme_Corp"),
        "ferrogate-acme-corp"
    );
    assert_eq!(
        legacy_bucket_name_pre_490("ACME.CORP"),
        "ferrogate-acme-corp"
    );
    // Unlike the #490 slug, the old fold did NOT collapse runs of separators,
    // so `a__b` kept both hyphens. Pinning this distinguishes the fixture from
    // an accidental copy of `tenant_bucket_slug`.
    assert_eq!(legacy_bucket_name_pre_490("a__b"), "ferrogate-a--b");
    // Trailing separators were trimmed, leading ones were not.
    assert_eq!(legacy_bucket_name_pre_490("acme..."), "ferrogate-acme");
    assert_eq!(legacy_bucket_name_pre_490("_acme"), "ferrogate--acme");
    // An empty / all-separator id degenerated to the bare prefix, trimmed —
    // note this is 9 chars and does NOT end in `-`.
    assert_eq!(legacy_bucket_name_pre_490(""), "ferrogate");
    assert_eq!(legacy_bucket_name_pre_490("___"), "ferrogate");
    // Truncation at exactly 63, before the trailing-hyphen trim.
    assert_eq!(legacy_bucket_name_pre_490(&"a".repeat(200)).len(), 63);
    assert_eq!(
        legacy_bucket_name_pre_490(&"a".repeat(200)),
        format!("ferrogate-{}", "a".repeat(53))
    );
    // The fixture must NOT be constant: it agreed with itself only on the
    // families the old rule genuinely folded together.
    assert_ne!(
        legacy_bucket_name_pre_490("alpha"),
        legacy_bucket_name_pre_490("beta")
    );
    assert_ne!(
        legacy_bucket_name_pre_490("tenant-1"),
        legacy_bucket_name_pre_490("tenant-2")
    );
    // And it must not be the CURRENT derivation: no digest, so the ids that
    // #490 separates are still folded together here. If someone "fixes" the
    // fixture by delegating to `r2_bucket_name_for_tenant`, this fails.
    assert_ne!(
        legacy_bucket_name_pre_490("Acme_Corp"),
        r2_bucket_name_for_tenant("Acme_Corp")
    );
    assert_eq!(
        legacy_bucket_name_pre_490("Acme_Corp"),
        legacy_bucket_name_pre_490("acme corp"),
        "the fixture must still FOLD what #490 separates — otherwise the \
         collision tests below prove nothing"
    );
}

/// Issue #496: the pre-#490 derivation is no longer part of this crate's public
/// surface. It was `pub` in `r2.rs` and re-exported from `lib.rs` "for
/// migration lookups only", with no non-test caller and no migration tool —
/// API that advertised a capability the project does not have.
///
/// Re-add it and this test fails: the source of both files is checked for the
/// symbol. That is the only mechanism available, since a test inside the crate
/// cannot observe the absence of an export by naming it.
///
/// If a migration is ever actually built, it belongs behind a real entry point
/// (see the `r2` module docs for what it would owe, including refusing an
/// ambiguous legacy name) — not behind a bare name-derivation helper, so this
/// test is not in the way of that work.
#[test]
fn legacy_bucket_name_derivation_is_not_public_api() {
    const LEGACY_SYMBOL: &str = "r2_legacy_bucket_name_for_tenant";
    for (file, source) in [
        ("r2.rs", include_str!("r2.rs")),
        ("lib.rs", include_str!("lib.rs")),
    ] {
        // Doc prose is allowed to name the removed function (the module docs
        // explain why it went); a definition or re-export of it is not.
        for forbidden in [
            format!("pub fn {LEGACY_SYMBOL}"),
            format!("fn {LEGACY_SYMBOL}"),
            format!("{LEGACY_SYMBOL},"),
        ] {
            assert!(
                !source.contains(&forbidden),
                "{file} reintroduces the pre-#490 derivation as crate API ({forbidden:?}); \
                 issue #496 removed it — keep it a private fixture in r2_test.rs"
            );
        }
    }
    // The deletion is only defensible because the knowledge survived: `r2.rs`
    // must still carry the note saying what a migration would owe, so whoever
    // finds a legacy bucket is not left reconstructing it from git history.
    // Delete that section and this fails.
    let r2_source = include_str!("r2.rs");
    for required in [
        "No legacy-name compatibility surface",
        // The ambiguity refusal — the acceptance criterion of the migration
        // this crate did NOT build.
        "refuse to run when that name is ambiguous",
        // The reason the control-plane surface here cannot be the migration.
        "S3-compatible data plane",
    ] {
        assert!(
            r2_source.contains(required),
            "r2.rs no longer records {required:?}; issue #496 removed the legacy helper on the \
             condition that this note stays"
        );
    }
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
            legacy_bucket_name_pre_490(tenant),
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
        .map(|t| legacy_bucket_name_pre_490(t))
        .collect();
    assert_eq!(
        legacy[0], legacy[1],
        "the legacy derivation is expected to collide after truncation"
    );
    assert_eq!(legacy[0], legacy[2]);
    // Pin the collided value, not just the equality: a fixture that returned a
    // constant would satisfy every `assert_eq!` above while demonstrating
    // nothing. 10 (`ferrogate-`) + 53 leading `t` = the 63-char cap exactly.
    assert_eq!(legacy[0], format!("ferrogate-{head}"));
    assert_eq!(legacy[0].len(), 63);
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

// ---------------------------------------------------------------------------
// Test-gate coverage for #490 (added by the gate, independent of the fix
// author's tests). Each of the three findings gets one test that is written to
// go RED if the corresponding fix is reverted; the mutation runs are recorded
// in the gate report.
// ---------------------------------------------------------------------------

/// GATE #490 finding 1. Every colliding tenant id named in the issue — the
/// four folding variants AND a truncation family sharing 53+ leading
/// characters — must be PAIRWISE distinct in one pool (not just distinct
/// within its own family), and every derived name must still be a legal R2
/// bucket name. Revert the digest and this fails on the first pair.
#[test]
fn gate_490_all_issue_colliding_tenant_ids_are_pairwise_distinct_and_r2_valid() {
    let long_head = "t".repeat(53);
    let longer_head = "q".repeat(70);
    let tenants: Vec<String> = vec![
        // The exact four from the issue body: all -> "ferrogate-acme-corp".
        "Acme_Corp".to_string(),
        "acme-corp".to_string(),
        "acme corp".to_string(),
        "ACME.CORP".to_string(),
        // Two ids sharing their first 53 characters (the truncation family).
        format!("{long_head}alpha"),
        format!("{long_head}beta"),
        // And two sharing far more than 53 (70) leading characters.
        format!("{longer_head}-one"),
        format!("{longer_head}-two"),
    ];

    // Sanity: the pre-#490 derivation really did collide on these, so this test
    // is not vacuous about what it is guarding.
    assert_eq!(
        legacy_bucket_name_pre_490(&tenants[0]),
        legacy_bucket_name_pre_490(&tenants[3]),
        "the legacy derivation must collide on the issue's folding family"
    );
    assert_eq!(
        legacy_bucket_name_pre_490(&tenants[4]),
        legacy_bucket_name_pre_490(&tenants[5]),
        "the legacy derivation must collide after 63-char truncation"
    );
    assert_eq!(
        legacy_bucket_name_pre_490(&tenants[6]),
        legacy_bucket_name_pre_490(&tenants[7]),
    );

    // The property under test: pairwise distinct across the WHOLE pool.
    for (i, left) in tenants.iter().enumerate() {
        let left_name = r2_bucket_name_for_tenant(left);
        assert_r2_valid(&left_name);
        for right in tenants.iter().skip(i + 1) {
            let right_name = r2_bucket_name_for_tenant(right);
            assert_ne!(
                left_name, right_name,
                "tenants {left:?} and {right:?} share bucket {left_name:?}"
            );
        }
    }
    // 8 distinct tenants -> 8 distinct buckets.
    let unique: std::collections::HashSet<String> = tenants
        .iter()
        .map(|t| r2_bucket_name_for_tenant(t))
        .collect();
    assert_eq!(unique.len(), tenants.len());

    // Broader corpus: every separator/case/length permutation an operator or a
    // buggy caller could realistically produce, all sharing one slug family, so
    // the digest is the only thing keeping them apart.
    let mut corpus: Vec<String> = Vec::new();
    for sep in ["_", "-", " ", ".", "/", "", "::", "\u{a0}"] {
        for case in ["acme", "ACME", "Acme", "aCmE"] {
            for tail in ["corp", "CORP", "corp1"] {
                corpus.push(format!("{case}{sep}{tail}"));
            }
        }
    }
    for len in 50..60 {
        corpus.push("z".repeat(len));
        corpus.push(format!("{}-a", "z".repeat(len)));
    }
    let unique_corpus: std::collections::HashSet<String> = corpus
        .iter()
        .map(|t| {
            let name = r2_bucket_name_for_tenant(t);
            assert_r2_valid(&name);
            assert!(!name.contains("--"), "{name:?} has a doubled hyphen");
            name
        })
        .collect();
    let distinct_tenants: std::collections::HashSet<&String> = corpus.iter().collect();
    assert_eq!(
        unique_corpus.len(),
        distinct_tenants.len(),
        "{} distinct tenant ids collapsed to {} bucket names",
        distinct_tenants.len(),
        unique_corpus.len()
    );
}

/// GATE #490 finding 2. Two pages of buckets, with the second page ending the
/// walk. The caller must receive BOTH pages' rows, and the second request must
/// echo the cursor the first page handed back. Delete the pagination loop and
/// this fails: `names` is short and only one request is recorded.
#[test]
fn gate_490_list_buckets_returns_every_page_not_just_the_first() {
    let transport = Arc::new(RecordingTransport::new(vec![
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [
                { "name": "page1-a" }, { "name": "page1-b" } ] },
                 "result_info": { "cursor": "next-page-token", "per_page": 2 } }"#,
        ),
        ok(
            200,
            r#"{ "success": true, "errors": [], "result": { "buckets": [
                { "name": "page2-a" }, { "name": "page2-b" } ] },
                 "result_info": { "per_page": 2 } }"#,
        ),
    ]));
    let client = cf_client(transport.clone());

    let buckets = runtime()
        .block_on(client.list_r2_buckets())
        .expect("list should walk both pages");
    let names: Vec<&str> = buckets.iter().filter_map(|b| b.name.as_deref()).collect();
    assert_eq!(
        names,
        ["page1-a", "page1-b", "page2-a", "page2-b"],
        "the caller must receive every page, not just page 1"
    );

    let requests = transport.recorded();
    assert_eq!(
        requests.len(),
        2,
        "the cursor from page 1 must trigger a second request"
    );
    assert!(
        requests[1].url.contains("cursor=next-page-token"),
        "page 2 must echo the server's cursor: {}",
        requests[1].url
    );
    // A bucket that only exists on page 2 must be findable — this is the
    // "absent after delete passes vacuously" hazard the issue names.
    assert!(names.contains(&"page2-b"));
}

/// GATE #490 finding 3. The create path absorbs ONLY a documented
/// already-exists code. Restore the blanket `status == 409` branch and the
/// three surfacing cases below fail.
#[test]
fn gate_490_only_documented_already_exists_codes_are_swallowed() {
    // Absorbed: the two documented codes.
    for body in [
        r#"{ "success": false, "errors": [ { "code": 10004, "message": "already exists, you own it" } ] }"#,
        r#"{ "success": false, "errors": [ { "code": 10073, "message": "BucketConflict" } ] }"#,
    ] {
        let transport = Arc::new(RecordingTransport::new(vec![ok(409, body)]));
        let client = cf_client(transport);
        let outcome = runtime()
            .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-x")))
            .unwrap_or_else(|e| panic!("documented already-exists code must be absorbed: {e:?}"));
        assert_eq!(outcome, R2BucketCreation::AlreadyExists);
    }

    // NOT absorbed: any other 409 must reach the caller as a typed error.
    for (label, body) in [
        ("codeless", r#"{ "success": false, "errors": [] }"#),
        (
            "mid-deletion",
            r#"{ "success": false, "errors": [ { "code": 10035, "message": "being deleted" } ] }"#,
        ),
        (
            "name held by another account",
            r#"{ "success": false, "errors": [ { "code": 10014, "message": "bucket name unavailable" } ] }"#,
        ),
    ] {
        let transport = Arc::new(RecordingTransport::new(vec![ok(409, body)]));
        let client = cf_client(transport);
        let error = runtime()
            .block_on(client.create_r2_bucket(&R2CreateBucketRequest::named("ferrogate-x")))
            .expect_err(&format!("a {label} 409 must not read as provisioned"));
        assert!(
            matches!(error, CloudflareError::Api { status: 409, .. }),
            "{label}: {error:?}"
        );
    }
}

/// GATE #490 finding 3, at the caller the issue actually cares about: a
/// non-already-exists 409 must NOT reach `ensure_tenant_r2_bucket` as a
/// `created: false` provision, because #462 then mints a read+write credential
/// for a bucket that may not exist.
#[test]
fn gate_490_ensure_tenant_bucket_does_not_report_a_phantom_bucket_on_an_unrelated_409() {
    let transport = Arc::new(RecordingTransport::new(vec![ok(
        409,
        r#"{ "success": false, "errors": [ { "code": 10035, "message": "The bucket you tried to create is being deleted." } ] }"#,
    )]));
    let client = cf_client(transport);

    let error = runtime()
        .block_on(client.ensure_tenant_r2_bucket("tenant-acme"))
        .expect_err("an unrelated 409 must not be reported as a provisioned bucket");
    assert!(
        matches!(error, CloudflareError::Api { status: 409, .. }),
        "{error:?}"
    );
}
