// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Transport-type tests for the Cloudflare client — Debug redaction of credential-bearing requests and responses.

use std::time::Duration;

use crate::client::{HttpMethod, HttpRequest, HttpResponse};

/// A create-token response body shaped like the real
/// `POST /accounts/{account_id}/tokens` reply: the one-time token `value` is
/// the plaintext credential the R2 secret access key is derived from.
const MINTED_SECRET: &str = "v1.0-super-secret-token-value";

fn create_token_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: format!(
            r#"{{"success":true,"errors":[],"result":{{"id":"tok123","value":"{MINTED_SECRET}"}}}}"#
        )
        .into_bytes(),
    }
}

/// The #489 regression guard: `{:?}` of a response whose body carries a minted
/// credential must never render the body bytes. A single `tracing::debug!(?res)`
/// — or an `unwrap()`/`expect()` panic, or an assertion failure — would
/// otherwise print every R2 secret this client mints.
///
/// Both renderings of the secret are checked. The plaintext form catches a
/// future `String::from_utf8_lossy` `Debug`; the **decimal byte-list** form is
/// what `#[derive(Debug)]` over `Vec<u8>` actually emits (`body: [118, 49, …]`),
/// which is a trivially decodable leak and is precisely the regression this
/// guards.
#[test]
fn response_debug_never_prints_the_body_bytes() {
    let rendered = format!("{:?}", create_token_response());

    assert!(
        !rendered.contains(MINTED_SECRET),
        "minted credential leaked into HttpResponse Debug as plaintext: {rendered}"
    );

    // `[118, 49, …]` -> `118, 49, …`: the contiguous run a derived `Debug` over
    // `Vec<u8>` would emit inside the enclosing body slice.
    let as_byte_list = format!("{:?}", MINTED_SECRET.as_bytes());
    let byte_run = as_byte_list
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    assert!(
        !rendered.contains(&byte_run),
        "minted credential leaked into HttpResponse Debug as raw bytes: {rendered}"
    );

    assert!(
        !rendered.contains("body:"),
        "HttpResponse Debug must expose only body_len, never the body: {rendered}"
    );
}

/// The redacted `Debug` is still useful for triage: status, retry hint and the
/// body *length* survive, so a failing call can be diagnosed without the bytes.
#[test]
fn response_debug_keeps_status_retry_after_and_body_len() {
    let response = HttpResponse {
        status: 429,
        retry_after: Some(Duration::from_secs(7)),
        body: b"0123456789".to_vec(),
    };
    let rendered = format!("{response:?}");

    assert!(rendered.contains("HttpResponse"), "{rendered}");
    assert!(rendered.contains("429"), "{rendered}");
    assert!(rendered.contains("body_len: 10"), "{rendered}");
    assert!(rendered.contains('7'), "{rendered}");
}

/// A body that is not valid UTF-8 must not panic or lossily surface bytes.
#[test]
fn response_debug_handles_non_utf8_bodies() {
    let response = HttpResponse {
        status: 200,
        retry_after: None,
        body: vec![0xff, 0xfe, 0x00, 0x01],
    };
    let rendered = format!("{response:?}");

    assert!(rendered.contains("body_len: 4"), "{rendered}");
    assert!(!rendered.contains("255"), "{rendered}");
}

/// The sibling invariant that already held for the request side, pinned here so
/// the two credential-bearing transport types are guarded in one place.
#[test]
fn request_debug_redacts_the_bearer_token_and_body() {
    let request = HttpRequest {
        method: HttpMethod::Post,
        url: "https://api.cloudflare.com/client/v4/accounts/acct/tokens".to_string(),
        bearer_token: MINTED_SECRET.to_string(),
        body: br#"{"name":"ferrogate-r2-tenant"}"#.to_vec().into(),
        content_type: None,
    };
    let rendered = format!("{request:?}");

    assert!(
        !rendered.contains(MINTED_SECRET),
        "bearer token leaked into HttpRequest Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("ferrogate-r2-tenant"), "{rendered}");
    assert!(rendered.contains("body_len: Some(30)"), "{rendered}");
}
