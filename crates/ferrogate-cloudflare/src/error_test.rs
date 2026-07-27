// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit tests for typed Cloudflare error mapping; kept out of the business-logic file.

use std::time::Duration;

use crate::error::{CloudflareApiError, CloudflareError};

fn err(code: i64, message: &str) -> CloudflareApiError {
    CloudflareApiError {
        code,
        message: message.to_string(),
    }
}

#[test]
fn maps_429_status_to_rate_limited() {
    let mapped = CloudflareError::from_response(429, Some(Duration::from_secs(7)), vec![]);
    match mapped {
        CloudflareError::RateLimited { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(7)));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
fn r2_incomplete_body_code_10013_is_not_misclassified_as_rate_limited() {
    // Issue #493: R2's `IncompleteBody` (code 10013, HTTP 400 — "request
    // body terminated before expected Content-Length") must NOT be treated
    // as a rate limit. It is a genuine client-side truncation that fails
    // identically on every retry, so it must also be classified as a
    // non-retryable `Api` error rather than something the backoff loop will
    // burn its whole retry budget on.
    let mapped = CloudflareError::from_response(400, None, vec![err(10013, "IncompleteBody")]);
    match mapped {
        CloudflareError::Api { status, ref errors } => {
            assert_eq!(status, 400);
            assert_eq!(errors[0].code, 10013);
        }
        other => panic!("expected Api, got {other:?}"),
    }
    assert!(
        !mapped.is_retryable(),
        "R2 IncompleteBody (10013/400) must not be retried, got {mapped:?}"
    );
}

#[test]
fn r2_rate_limit_is_classified_by_status_429_not_by_code_10058() {
    // Issue #493: R2's actual rate-limit code is 10058 / `TooManyRequests`,
    // which always arrives with HTTP 429. There is deliberately NO numeric
    // branch for 10058 in the mapper — a bare `code == 10058` match would
    // reintroduce the very collision class #493 removed, because in
    // Cloudflare's Lists/Bulk-Redirect namespace 10058 means "list items
    // incompatible with list type" (HTTP 400). So both halves below are
    // load-bearing: the status decides, the code does not.
    let by_status =
        CloudflareError::from_response(429, None, vec![err(10058, "TooManyRequests")]);
    assert!(
        matches!(by_status, CloudflareError::RateLimited { .. }),
        "429 must classify as a rate limit, got {by_status:?}"
    );
    assert!(by_status.is_retryable(), "rate limits must be retryable");

    // The half that makes the name true: the same code WITHOUT 429 must not
    // become a rate limit. Adding a `code == 10058` branch reds this.
    let by_code = CloudflareError::from_response(
        400,
        None,
        vec![err(10058, "list items incompatible with list type")],
    );
    match by_code {
        CloudflareError::Api { status, ref errors } => {
            assert_eq!(status, 400, "got {by_code:?}");
            assert_eq!(errors[0].code, 10058, "got {by_code:?}");
        }
        other => panic!("code 10058 without 429 must stay Api, got {other:?}"),
    }
}

#[test]
fn maps_missing_scope_code_to_missing_scope_with_required_groups() {
    let mapped = CloudflareError::from_response(
        403,
        None,
        vec![err(9109, "Unauthorized to access requested resource")],
    );
    match mapped {
        CloudflareError::MissingScope { required, errors } => {
            // The whole remediation list, not spot-checks: two `any(...)`
            // probes let a row be deleted with the suite green, which is how
            // the #489 defect came back (see scopes_test.rs for the
            // preflight-level pin of the same invariant).
            assert_eq!(
                required,
                vec![
                    "AI Gateway",
                    "Secrets Store",
                    "D1",
                    "Workers Scripts",
                    "Workers R2 Storage",
                    "API Tokens",
                    "Cloudflare Pages",
                    "Workflows (Workers Scripts)",
                ],
                "the required-permission-group list a caller is handed changed"
            );
            assert_eq!(errors[0].code, 9109);
        }
        other => panic!("expected MissingScope, got {other:?}"),
    }
}

#[test]
fn missing_scope_display_names_the_permission_groups() {
    let mapped = CloudflareError::from_response(403, None, vec![err(9109, "denied")]);
    let text = mapped.to_string();
    assert!(text.contains("AI Gateway"), "message was: {text}");
    assert!(text.contains("permission group"), "message was: {text}");
}

#[test]
fn maps_authentication_code_to_unauthorized() {
    let mapped =
        CloudflareError::from_response(400, None, vec![err(10000, "Authentication error")]);
    assert!(
        matches!(mapped, CloudflareError::Unauthorized { .. }),
        "got {mapped:?}"
    );
}

#[test]
fn maps_401_status_without_codes_to_unauthorized() {
    let mapped = CloudflareError::from_response(401, None, vec![]);
    assert!(
        matches!(mapped, CloudflareError::Unauthorized { .. }),
        "got {mapped:?}"
    );
}

#[test]
fn maps_unknown_error_to_generic_api_error() {
    let mapped = CloudflareError::from_response(404, None, vec![err(7003, "no route")]);
    match mapped {
        CloudflareError::Api { status, errors } => {
            assert_eq!(status, 404);
            assert_eq!(errors[0].code, 7003);
        }
        other => panic!("expected Api, got {other:?}"),
    }
}

#[test]
fn rate_limit_precedence_beats_missing_scope() {
    // A 429 that also carries a scope code is still classified rate-limited.
    let mapped = CloudflareError::from_response(429, None, vec![err(9109, "denied")]);
    assert!(
        matches!(mapped, CloudflareError::RateLimited { .. }),
        "got {mapped:?}"
    );
}

#[test]
fn transport_and_rate_limited_are_retryable_others_are_not() {
    assert!(CloudflareError::Transport("boom".into()).is_retryable());
    assert!(CloudflareError::RateLimited {
        retry_after: None,
        attempts: 1
    }
    .is_retryable());
    assert!(!CloudflareError::Unauthorized { errors: vec![] }.is_retryable());
    assert!(!CloudflareError::Api {
        status: 400,
        errors: vec![]
    }
    .is_retryable());
}
