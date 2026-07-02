// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Regression for the self-hosted worker identity-expiry bypass (#113): the
//! server must judge expiry against its own trusted clock, never a
//! client-supplied observed_at_unix.

use super::*;

fn stored_registration(expires_at: Option<u64>) -> StoredSelfHostedWorkerRegistration {
    StoredSelfHostedWorkerRegistration {
        id: "worker-sec".to_string(),
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("tenant-sec".to_string()),
            ..Default::default()
        },
        workspace_id: "workspace-sec".to_string(),
        worker_name: "worker-sec".to_string(),
        status: "active".to_string(),
        identity_fingerprint: "fp-sec-secret".to_string(),
        identity_expires_at_unix: expires_at,
        orchestration_enabled: false,
        registered_at_unix: Some(1),
        last_seen_at_unix: None,
        trust_level: "reported".to_string(),
        capability_envelope_json: "{\"capabilities\":[\"heartbeat\"]}".to_string(),
    }
}

#[test]
fn expired_worker_cannot_bypass_expiry_with_client_supplied_observed_time() {
    let mut dispatch = SelfHostedWorkerDispatchRuntime::default();
    dispatch
        .register_worker(&stored_registration(Some(1)))
        .unwrap();

    let mut identity = self_hosted_worker_runtime_identity(&stored_registration(Some(1)));
    // A stale/malicious worker claims it observed itself before its expiry.
    identity.observed_at_unix = Some(0);

    // Before #113 the server kept the client's observed_at (0 >= 1 is false →
    // accepted). After the fix it stamps its own trusted clock (now >> 1),
    // so the expired identity is rejected.
    let result = dispatch.validate_worker_identity(&identity);
    assert!(
        matches!(result, Err(SelfHostedWorkerError::InvalidIdentity(_))),
        "expired identity must be rejected regardless of client observed_at, got {result:?}"
    );
}

#[test]
fn active_worker_with_future_expiry_is_accepted() {
    let far_future = 4_000_000_000u64; // ~year 2096, well beyond the server clock.
    let mut dispatch = SelfHostedWorkerDispatchRuntime::default();
    dispatch
        .register_worker(&stored_registration(Some(far_future)))
        .unwrap();

    let identity = self_hosted_worker_runtime_identity(&stored_registration(Some(far_future)));
    assert!(dispatch.validate_worker_identity(&identity).is_ok());
}
