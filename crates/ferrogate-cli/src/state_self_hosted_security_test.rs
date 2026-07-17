// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Regression for the self-hosted worker identity-expiry bypass (#113): the
//! server must judge expiry against its own trusted clock, never a
//! client-supplied observed_at_unix.
//!
//! Also covers the transport key-reuse fix (round-4 audit): the AEAD/bearer
//! secret must be the server-provisioned `token_secret`, never the public
//! `identity_fingerprint` (which is returned in admin listings and carried in
//! cleartext in every frame).

use super::*;

/// A worker's public identity fingerprint -- returned to admin.read callers and
/// carried in the cleartext `token_id` of every frame. It must NOT be usable as
/// the transport secret.
const PUBLIC_FINGERPRINT: &str = "fp-sec-public";
/// The server-provisioned, independent transport secret (>= 32 chars).
const PROVISIONED_SECRET: &str = "transport-secret-cccccccccccccccccccccccc";

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
        identity_fingerprint: PUBLIC_FINGERPRINT.to_string(),
        identity_expires_at_unix: expires_at,
        orchestration_enabled: false,
        registered_at_unix: Some(1),
        last_seen_at_unix: None,
        trust_level: "reported".to_string(),
        capability_envelope_json: "{\"capabilities\":[\"heartbeat\"]}".to_string(),
        token_secret: PROVISIONED_SECRET.to_string(),
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

/// Round-4 audit regression: the transport bearer/AEAD secret is the
/// server-provisioned `token_secret`, never the public `identity_fingerprint`.
/// An attacker who learns the fingerprint (admin listing, logs, or a passively
/// observed cleartext frame) must NOT be able to authenticate as the worker.
#[test]
fn public_fingerprint_cannot_be_used_as_the_transport_secret() {
    let mut dispatch = SelfHostedWorkerDispatchRuntime::default();
    dispatch
        .register_worker(&stored_registration(None))
        .unwrap();

    // The legitimate runtime identity carries the provisioned secret (not the
    // fingerprint) and authenticates.
    let legit = self_hosted_worker_runtime_identity(&stored_registration(None));
    assert_eq!(legit.token_id, PUBLIC_FINGERPRINT);
    assert_eq!(legit.token_secret, PROVISIONED_SECRET);
    assert_ne!(
        legit.token_secret, legit.token_id,
        "the transport secret must not equal the public token_id/fingerprint"
    );
    assert!(dispatch.validate_worker_identity(&legit).is_ok());

    // An attacker who only knows the public fingerprint tries to authenticate
    // by presenting it as the secret (the pre-fix wiring accepted this). It
    // must be rejected.
    let mut forged = legit.clone();
    forged.token_secret = PUBLIC_FINGERPRINT.to_string();
    assert!(
        matches!(
            dispatch.validate_worker_identity(&forged),
            Err(SelfHostedWorkerError::InvalidIdentity(_))
        ),
        "presenting the public fingerprint as the secret must be rejected"
    );
}
