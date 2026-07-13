// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Focused harness regressions for MCP identity live process management.

use super::*;

fn assert_error_message_contains(response: &HttpResponse, expected: &str) -> Result<()> {
    let body: Value = serde_json::from_str(&response.body)?;
    let message = body["error"]["message"]
        .as_str()
        .context("error response did not contain a message")?;
    if !message.contains(expected) {
        bail!("expected error message to contain {expected:?}, got {message:?}");
    }
    Ok(())
}

fn verify_refresh_material_unchanged(
    before: &CredentialSnapshot,
    after: &CredentialSnapshot,
) -> Result<()> {
    if after.version != before.version
        || after.authorization_generation != before.authorization_generation
        || after.expires_at_unix != before.expires_at_unix
        || after.access_token_nonce != before.access_token_nonce
        || after.access_token_ciphertext != before.access_token_ciphertext
        || after.refresh_token_nonce != before.refresh_token_nonce
        || after.refresh_token_ciphertext != before.refresh_token_ciphertext
        || after.revoked_at_unix != before.revoked_at_unix
    {
        bail!("storage deadline persisted refreshed MCP credential material");
    }
    Ok(())
}

#[test]
fn gateway_process_log_accepts_more_than_pipe_capacity_without_a_reader() {
    let mut log = gateway_process_log(false)
        .unwrap()
        .expect("non-debug process output must use a file-backed sink");
    let mut child_stderr = log.reopen().unwrap();
    let payload = vec![b'x'; 256 * 1024];

    child_stderr.write_all(&payload).unwrap();
    child_stderr.flush().unwrap();
    log.as_file_mut().rewind().unwrap();

    let mut observed = Vec::new();
    log.as_file_mut().read_to_end(&mut observed).unwrap();
    assert_eq!(observed, payload);
}

#[test]
fn diagnostic_log_tail_respects_utf8_boundaries() {
    let input = format!("prefix{}suffix", "¥".repeat(20));
    let tail = text_tail(&input, 17);

    assert!(tail.ends_with("suffix"));
    assert!(tail.len() <= 17);
}

#[test]
fn response_request_id_falls_back_to_json_rpc_response_header() {
    let response = HttpResponse {
        status: 503,
        body: r#"{"jsonrpc":"2.0","error":{"code":-32000}}"#.into(),
        raw: "HTTP/1.1 503 Service Unavailable\r\nX-Request-Id: fg-deadline\r\nContent-Length: 49\r\n\r\n{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000}}".into(),
    };

    assert_eq!(response_request_id(&response).unwrap(), "fg-deadline");
}

#[test]
fn early_refresh_diagnostic_reports_status_code_and_request_id_without_body() {
    let response = HttpResponse {
        status: 503,
        body: r#"{"error":{"code":"mcp_identity_refresh_timeout","message":"do not echo"}}"#.into(),
        raw: "HTTP/1.1 503 Service Unavailable\r\nx-request-id: fg-timeout\r\n\r\n".into(),
    };

    let summary = early_refresh_response_summary(&response);
    assert_eq!(
        summary,
        "http_status=503 error_code=mcp_identity_refresh_timeout request_id=fg-timeout"
    );
    assert!(!summary.contains("do not echo"));
}

#[test]
fn concurrent_refresh_diagnostic_preserves_code_request_and_gateway_evidence() {
    let response = HttpResponse {
        status: 503,
        body: r#"{"error":{"code":"mcp_identity_storage_deadline","message":"do not echo"},"request_id":"fg-concurrent"}"#.into(),
        raw: String::new(),
    };
    let log = "old line\nrequest_id=fg-concurrent operation=\"claim MCP refresh lease\" outcome=\"storage_cancelled\"";

    let diagnostic = concurrent_refresh_failure_diagnostic(&response, log);

    assert!(diagnostic.contains("http_status=503"));
    assert!(diagnostic.contains("error_code=mcp_identity_storage_deadline"));
    assert!(diagnostic.contains("request_id=fg-concurrent"));
    assert!(diagnostic.contains("operation=\"claim MCP refresh lease\""));
    assert!(diagnostic.contains("outcome=\"storage_cancelled\""));
    assert!(!diagnostic.contains("do not echo"));
}

#[test]
fn refresh_material_check_allows_heartbeat_lease_change_but_rejects_token_change() {
    let before = refreshing_snapshot();
    let mut renewed = before.clone();
    renewed.refresh_lease_expires_at_unix = Some(20);
    assert!(verify_refresh_material_unchanged(&before, &renewed).is_ok());

    renewed.access_token_ciphertext = vec![99];
    assert!(verify_refresh_material_unchanged(&before, &renewed).is_err());
}

#[test]
fn deferred_commit_requires_durable_refreshed_material_and_cleared_lease() {
    let before = refreshing_snapshot();
    let mut committed = before.clone();
    committed.version += 1;
    committed.expires_at_unix = 300;
    committed.access_token_nonce = vec![11];
    committed.access_token_ciphertext = vec![12];
    committed.refresh_token_nonce = Some(vec![13]);
    committed.refresh_token_ciphertext = Some(vec![14]);
    committed.refresh_lease_id = None;
    committed.refresh_lease_expires_at_unix = None;
    committed.last_refresh_outcome = Some("refreshed".into());

    assert!(verify_refresh_completion_persisted(&before, &committed).is_ok());

    let mut unchanged = committed.clone();
    unchanged.access_token_ciphertext = before.access_token_ciphertext.clone();
    assert!(verify_refresh_completion_persisted(&before, &unchanged).is_err());

    let mut leased = committed;
    leased.refresh_lease_id = before.refresh_lease_id.clone();
    assert!(verify_refresh_completion_persisted(&before, &leased).is_err());
}

fn refreshing_snapshot() -> CredentialSnapshot {
    CredentialSnapshot {
        version: 4,
        authorization_generation: 2,
        refresh_lease_id: Some("lease".into()),
        refresh_lease_expires_at_unix: Some(10),
        expires_at_unix: 1,
        revoked_at_unix: None,
        access_token_nonce: vec![1],
        access_token_ciphertext: vec![2],
        refresh_token_nonce: Some(vec![3]),
        refresh_token_ciphertext: Some(vec![4]),
        last_refresh_outcome: Some("refreshing".into()),
        last_revocation_outcome: None,
    }
}

#[test]
fn error_message_assertion_distinguishes_postgres_statement_timeout() {
    let response = HttpResponse {
        status: 503,
        body: r#"{"error":{"code":"mcp_identity_storage_unavailable","message":"canceling statement due to statement timeout (SQLSTATE 57014)"}}"#.into(),
        raw: String::new(),
    };

    assert!(assert_error_message_contains(&response, "SQLSTATE 57014").is_ok());
    assert!(assert_error_message_contains(&response, "SQLSTATE 55P03").is_err());
}

#[test]
fn synchronous_storage_cancellation_is_one_complete_evidence_alternative() {
    let evidence = concat!(
        "2026-07-13 WARN cancelled operation=\"claim MCP refresh lease\" ",
        "storage_stage=\"SQL execution\" outcome=\"storage_cancelled\""
    );
    assert!(assert_storage_cancellation_evidence(
        evidence,
        "claim MCP refresh lease",
        "SQL execution",
        "watchdog_cancel_requested"
    )
    .is_ok());
    assert!(assert_storage_cancellation_evidence(
        evidence,
        "renew MCP refresh lease",
        "transaction commit",
        "watchdog_commit_cancel_requested"
    )
    .is_err());
}

#[test]
fn response_deadline_requires_its_matching_watchdog_cancellation_evidence() {
    let response = concat!(
        "WARN operation=\"claim MCP refresh lease\" cancel_outcome=AlreadyCancelled ",
        "outcome=\"response_deadline\"\n"
    );
    let watchdog = concat!(
        "WARN operation=\"claim MCP refresh lease\" storage_stage=\"SQL execution\" ",
        "outcome=\"watchdog_cancel_requested\""
    );
    assert!(assert_storage_cancellation_evidence(
        &format!("{response}{watchdog}"),
        "claim MCP refresh lease",
        "SQL execution",
        "watchdog_cancel_requested"
    )
    .is_ok());
    assert!(assert_storage_cancellation_evidence(
        response,
        "claim MCP refresh lease",
        "SQL execution",
        "watchdog_cancel_requested"
    )
    .is_err());

    let synchronous = concat!(
        "WARN operation=\"claim MCP refresh lease\" storage_stage=\"SQL execution\" ",
        "outcome=\"storage_cancelled\"\n"
    );
    assert!(assert_storage_cancellation_evidence(
        &format!("{synchronous}{response}{watchdog}"),
        "claim MCP refresh lease",
        "SQL execution",
        "watchdog_cancel_requested"
    )
    .is_err());

    let renewal_response = concat!(
        "WARN operation=\"renew MCP refresh lease\" cancel_outcome=CommitStarted ",
        "outcome=\"response_deadline\"\n"
    );
    let renewal_watchdog = concat!(
        "WARN operation=\"renew MCP refresh lease\" storage_stage=\"transaction commit\" ",
        "outcome=\"watchdog_commit_cancel_requested\""
    );
    assert!(assert_storage_cancellation_evidence(
        &format!("{renewal_response}{renewal_watchdog}"),
        "renew MCP refresh lease",
        "transaction commit",
        "watchdog_commit_cancel_requested"
    )
    .is_ok());
}

#[test]
fn optimistic_claim_lock_conflict_log_requires_operation_stage_and_busy_outcome() {
    let evidence = concat!(
        "INFO operation=\"claim MCP refresh lease\" ",
        "storage_stage=\"refresh claim CAS\" outcome=\"lock_conflict_busy\""
    );
    assert!(assert_lock_conflict_busy_log(evidence, "claim MCP refresh lease").is_ok());
    assert!(assert_lock_conflict_busy_log(evidence, "renew MCP refresh lease").is_err());
    assert!(assert_lock_conflict_busy_log(
        "INFO operation=\"claim MCP refresh lease\" outcome=\"cas_busy\"",
        "claim MCP refresh lease"
    )
    .is_err());
}

#[test]
fn live_refresh_contention_is_only_one_owner_and_one_waiter() {
    assert_eq!(LIVE_REFRESH_CONTENTION_CALLERS, 2);
}
