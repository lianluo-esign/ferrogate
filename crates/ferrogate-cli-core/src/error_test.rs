// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the exit-code classification and error envelope mapping.

use super::*;

#[test]
fn exit_codes_are_stable_and_distinct() {
    let classes = [
        ExitClass::Success,
        ExitClass::Usage,
        ExitClass::Auth,
        ExitClass::NotFoundConflict,
        ExitClass::Validation,
        ExitClass::Transport,
        ExitClass::Server,
    ];
    let codes: Vec<i32> = classes.iter().map(|class| class.code()).collect();
    assert_eq!(codes, vec![0, 2, 3, 4, 5, 6, 7]);
    // Every class maps to a distinct code so scripts can branch on them.
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len());
}

#[test]
fn http_status_classification_matches_failure_taxonomy() {
    assert_eq!(ExitClass::from_http_status(200), ExitClass::Success);
    assert_eq!(ExitClass::from_http_status(204), ExitClass::Success);
    assert_eq!(ExitClass::from_http_status(400), ExitClass::Validation);
    assert_eq!(ExitClass::from_http_status(401), ExitClass::Auth);
    assert_eq!(ExitClass::from_http_status(403), ExitClass::Auth);
    assert_eq!(
        ExitClass::from_http_status(404),
        ExitClass::NotFoundConflict
    );
    assert_eq!(
        ExitClass::from_http_status(409),
        ExitClass::NotFoundConflict
    );
    assert_eq!(ExitClass::from_http_status(422), ExitClass::Validation);
    assert_eq!(ExitClass::from_http_status(429), ExitClass::Transport);
    assert_eq!(ExitClass::from_http_status(408), ExitClass::Transport);
    assert_eq!(ExitClass::from_http_status(500), ExitClass::Server);
    assert_eq!(ExitClass::from_http_status(503), ExitClass::Server);
}

#[test]
fn api_error_exit_class_follows_status_not_code() {
    // A resource-specific code must never override the status-derived class:
    // scripts depend on the class, not the free-form code string.
    let error = ApiError {
        http_status: 404,
        code: "asset_not_found".to_string(),
        message: "no such asset".to_string(),
        request_id: Some("fgadm-01".to_string()),
        trace_id: None,
        retry_after_secs: None,
        details: None,
    };
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
    assert_eq!(error.exit_class().code(), 4);
}

#[test]
fn cli_error_variants_pick_expected_classes() {
    assert_eq!(CliError::usage("bad flag").exit_class(), ExitClass::Usage);
    assert_eq!(CliError::auth("no token").exit_class(), ExitClass::Auth);
    assert_eq!(
        CliError::transport("connection refused").exit_class(),
        ExitClass::Transport
    );
    let api = ApiError {
        http_status: 401,
        code: "unauthorized".to_string(),
        message: "bad key".to_string(),
        request_id: None,
        trace_id: None,
        retry_after_secs: None,
        details: None,
    };
    assert_eq!(CliError::from(api).exit_class(), ExitClass::Auth);
}

#[test]
fn api_error_display_includes_request_id() {
    let error = ApiError {
        http_status: 403,
        code: "forbidden".to_string(),
        message: "wrong scope".to_string(),
        request_id: Some("fgadm-abc".to_string()),
        trace_id: None,
        retry_after_secs: None,
        details: None,
    };
    let rendered = error.to_string();
    assert!(rendered.contains("403"));
    assert!(rendered.contains("forbidden"));
    assert!(rendered.contains("wrong scope"));
    assert!(rendered.contains("fgadm-abc"));
}
