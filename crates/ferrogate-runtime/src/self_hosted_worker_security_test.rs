// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Security regressions for self-hosted worker identity validation (#113, #114).

use super::*;

fn registration(expires_at: Option<u64>) -> SelfHostedWorkerRegistration {
    SelfHostedWorkerRegistration {
        tenant_id: "tenant-sec".to_string(),
        workspace_id: "workspace-sec".to_string(),
        worker_id: "worker-sec".to_string(),
        framework_adapter: "codex".to_string(),
        token_id: "token-sec".to_string(),
        token_secret: "s3cr3t-value".to_string(),
        identity_expires_at_unix: expires_at,
        capabilities: vec!["heartbeat".to_string()],
    }
}

// #114: constant-time secret comparison.
#[test]
fn constant_time_secret_eq_matches_only_identical_secrets() {
    assert!(constant_time_secret_eq("abc123", "abc123"));
    // Same length, differs at the last byte — must not be treated as equal.
    assert!(!constant_time_secret_eq("abc123", "abc124"));
    // Same length, differs at the first byte.
    assert!(!constant_time_secret_eq("abc123", "zbc123"));
    // Different length.
    assert!(!constant_time_secret_eq("abc123", "abc1234"));
    assert!(!constant_time_secret_eq("", "x"));
    assert!(constant_time_secret_eq("", ""));
}

#[test]
fn validate_identity_rejects_wrong_secret_of_equal_length() {
    let mut registry = SelfHostedWorkerRegistry::default();
    let worker = registry.register(registration(None)).unwrap();

    // A correct identity is accepted.
    assert!(registry.validate_identity(&worker.identity()).is_ok());

    // A same-length but wrong secret must be rejected (and, per #114, compared
    // in constant time so the rejection reveals nothing via timing).
    let mut forged = worker.identity();
    assert_eq!(forged.token_secret.len(), "s3cr3t-value".len());
    forged.token_secret = "s3cr3t-valuX".to_string();
    assert_eq!(forged.token_secret.len(), "s3cr3t-value".len());
    let error = registry.validate_identity(&forged).unwrap_err();
    assert!(matches!(error, SelfHostedWorkerError::InvalidIdentity(_)));
}

// #113: the registry rejects an identity observed at/after its expiry. The
// enforcement contract is that the *server* stamps observed_at_unix with its
// trusted clock; a stale/expired token cannot self-report a pre-expiry
// observed_at to pass. This test pins the comparison the callers rely on.
#[test]
fn validate_identity_rejects_expired_worker_regardless_of_claimed_observed_time() {
    let mut registry = SelfHostedWorkerRegistry::default();
    let worker = registry.register(registration(Some(100))).unwrap();

    // Server-stamped observed time at/after expiry → rejected.
    let mut at_expiry = worker.identity();
    at_expiry.observed_at_unix = Some(100);
    let error = registry.validate_identity(&at_expiry).unwrap_err();
    assert!(matches!(error, SelfHostedWorkerError::InvalidIdentity(_)));

    let mut past_expiry = worker.identity();
    past_expiry.observed_at_unix = Some(101);
    assert!(registry.validate_identity(&past_expiry).is_err());

    // Before expiry → accepted.
    let mut before_expiry = worker.identity();
    before_expiry.observed_at_unix = Some(99);
    assert!(registry.validate_identity(&before_expiry).is_ok());
}
