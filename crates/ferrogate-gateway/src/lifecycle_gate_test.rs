// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: What is left of the gateway's #514 unit tests after the
// decision moved into `ferrogate-storage`: only the HTTP mapping this crate
// owns. The decision, the chain walk and the fail-closed-on-storage-error rule
// are pinned in `ferrogate-storage/src/lifecycle_gate_test.rs`;
// `tests/tenant_suspension_e2e.rs` pins the wiring against a live gateway.

use super::*;

use ferrogate_storage::{check_lifecycle_chain, LifecycleRef, LifecycleSeam};

#[test]
fn a_rejection_converts_into_a_403_auth_error() {
    let rejection = check_lifecycle_chain(
        LifecycleSeam::Request,
        &[LifecycleRef::new("tenant", "tenant-susp", "suspended")],
    )
    .unwrap_err();
    let auth_error: crate::auth::AuthError = LifecycleGateError::Inactive(rejection).into();
    assert_eq!(auth_error.status, StatusCode::FORBIDDEN);
    assert_eq!(auth_error.code, "tenancy_suspended");
    assert!(!auth_error.message.is_empty());
}

/// A control-plane outage must reach the client as a retryable 503, not as a
/// 403 (which a client would treat as permanent) and not as a silent success.
#[test]
fn an_unavailable_lifecycle_lookup_converts_into_a_503_auth_error() {
    let auth_error: crate::auth::AuthError =
        LifecycleGateError::Unavailable("pool exhausted".into()).into();
    assert_eq!(auth_error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(auth_error.code, "lifecycle_status_unavailable");
    assert!(
        auth_error.message.contains("pool exhausted"),
        "{}",
        auth_error.message
    );
}

/// The attach seam's refusal keeps its own code through the conversion, so a
/// client can still tell "you pointed a new key at a suspended workspace" from
/// "your own tenancy is suspended".
#[test]
fn an_attach_rejection_keeps_its_distinguishable_code() {
    let rejection = check_lifecycle_chain(
        LifecycleSeam::Attach,
        &[LifecycleRef::new("workspace", "ws-1", "deleted")],
    )
    .unwrap_err();
    let auth_error: crate::auth::AuthError = LifecycleGateError::Inactive(rejection).into();
    assert_eq!(auth_error.status, StatusCode::FORBIDDEN);
    assert_eq!(auth_error.code, "inactive_tenancy_reference");
}
