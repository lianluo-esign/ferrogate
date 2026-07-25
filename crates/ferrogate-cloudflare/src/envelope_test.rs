// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit tests for Cloudflare envelope decoding; kept out of the business-logic file.

use serde::Deserialize;

use crate::envelope::CloudflareEnvelope;
use crate::error::CloudflareError;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Account {
    id: String,
    name: String,
}

#[test]
fn decodes_success_envelope_with_result() {
    let body = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": { "id": "acct-123", "name": "FerroGate" }
    }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    assert!(env.success);
    assert!(env.errors.is_empty());

    let account = env.into_result(200, None).unwrap();
    assert_eq!(
        account,
        Account {
            id: "acct-123".to_string(),
            name: "FerroGate".to_string()
        }
    );
}

#[test]
fn decodes_error_envelope_into_typed_error() {
    let body = r#"{
        "success": false,
        "errors": [{ "code": 7003, "message": "Could not route to endpoint" }],
        "messages": [],
        "result": null
    }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    assert!(!env.success);
    assert_eq!(env.errors.len(), 1);
    assert_eq!(env.errors[0].code, 7003);

    let err = env.into_result(404, None).unwrap_err();
    match err {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 404);
            assert_eq!(errors[0].code, 7003);
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[test]
fn success_true_but_missing_result_is_a_decode_error() {
    let body = r#"{ "success": true, "errors": [], "result": null }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    let err = env.into_result(200, None).unwrap_err();
    assert!(matches!(err, CloudflareError::Decode(_)), "got {err:?}");
}

#[test]
fn missing_optional_fields_default_gracefully() {
    // Only `result` present — `success`/`errors`/`messages` all defaulted.
    let body = r#"{ "result": { "id": "a", "name": "b" } }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    assert!(!env.success);
    assert!(env.errors.is_empty());
    assert!(env.messages.is_empty());
    // success defaulted false -> mapped to an error, not the result.
    assert!(env.into_result(200, None).is_err());
}

#[test]
fn into_ack_accepts_resultless_success() {
    let body = r#"{ "success": true, "errors": [], "messages": [] }"#;
    let env: CloudflareEnvelope<serde_json::Value> = serde_json::from_str(body).unwrap();
    assert!(env.into_ack(200, None).is_ok());
}

#[test]
fn into_ack_rejects_success_with_error_status() {
    let body =
        r#"{ "success": false, "errors": [{ "code": 10000, "message": "Authentication error" }] }"#;
    let env: CloudflareEnvelope<serde_json::Value> = serde_json::from_str(body).unwrap();
    let err = env.into_ack(401, None).unwrap_err();
    assert!(
        matches!(err, CloudflareError::Unauthorized { .. }),
        "got {err:?}"
    );
}

/// Issue #490: `result_info` used to be discarded, so a caller of a
/// cursor-paginated list could not tell a complete answer from page 1 of many.
#[test]
fn decodes_result_info_and_normalises_the_next_cursor() {
    let body = r#"{
        "success": true,
        "errors": [],
        "result": { "id": "acct-123", "name": "FerroGate" },
        "result_info": { "cursor": "opaque+cursor/=", "per_page": 1000 }
    }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    let (_, info) = env.into_result_with_info(200, None).unwrap();
    let info = info.expect("result_info should decode");
    assert_eq!(info.per_page, Some(1000));
    assert_eq!(info.next_cursor(), Some("opaque+cursor/="));

    // Cloudflare ends a cursor walk either by omitting the field or by sending
    // an empty string; both must read as "no next page".
    let last_page = r#"{ "success": true, "errors": [], "result": { "id": "a", "name": "b" },
                         "result_info": { "cursor": "" } }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(last_page).unwrap();
    let (_, info) = env.into_result_with_info(200, None).unwrap();
    assert_eq!(info.unwrap().next_cursor(), None);

    let no_info = r#"{ "success": true, "errors": [], "result": { "id": "a", "name": "b" } }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(no_info).unwrap();
    assert!(env.into_result_with_info(200, None).unwrap().1.is_none());
}

/// The page-numbered dialect (D1's list) reports `page`/`count`/`total_count`
/// and no cursor; the same struct must carry it.
#[test]
fn decodes_the_page_numbered_result_info_dialect() {
    let body = r#"{ "success": true, "errors": [], "result": { "id": "a", "name": "b" },
                    "result_info": { "page": 2, "per_page": 20, "count": 7, "total_count": 27 } }"#;
    let env: CloudflareEnvelope<Account> = serde_json::from_str(body).unwrap();
    let info = env.result_info.clone().expect("result_info should decode");
    assert_eq!(info.page, Some(2));
    assert_eq!(info.count, Some(7));
    assert_eq!(info.total_count, Some(27));
    assert_eq!(info.next_cursor(), None);
}
