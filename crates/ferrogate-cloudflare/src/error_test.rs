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
fn maps_rate_limit_error_code_to_rate_limited() {
    // Code 10013 is a rate-limit code even on a non-429 status.
    let mapped = CloudflareError::from_response(403, None, vec![err(10013, "rate limited")]);
    assert!(
        matches!(mapped, CloudflareError::RateLimited { .. }),
        "got {mapped:?}"
    );
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
            assert!(
                !required.is_empty(),
                "required permission groups must be named"
            );
            assert!(required.iter().any(|g| g.contains("AI Gateway")));
            assert!(required.iter().any(|g| g.contains("Workers R2 Storage")));
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
