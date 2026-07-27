// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Unit tests for the #514 lifecycle enforcement seams. These pin
// the PURE decision; `tests/tenant_suspension_e2e.rs` pins the wiring against a
// live gateway (the same probe that found the defect).

use super::*;

fn chain(entries: &[(&'static str, &str, &str)]) -> Vec<LifecycleRef> {
    entries
        .iter()
        .map(|(kind, id, status)| LifecycleRef::new(kind, *id, status))
        .collect()
}

#[test]
fn an_active_chain_passes_both_seams() {
    let chain = chain(&[
        ("tenant", "tenant-1", "active"),
        ("project", "proj-1", "active"),
        ("workspace", "ws-1", "active"),
    ]);
    assert!(check_lifecycle_chain(LifecycleSeam::Request, &chain).is_ok());
    assert!(check_lifecycle_chain(LifecycleSeam::Attach, &chain).is_ok());
}

#[test]
fn an_empty_chain_passes_both_seams() {
    // Platform-operator keys (no organization_id) and keys pointing at rows
    // that do not exist resolve to an empty chain: absence is not suspension.
    assert!(check_lifecycle_chain(LifecycleSeam::Request, &[]).is_ok());
    assert!(check_lifecycle_chain(LifecycleSeam::Attach, &[]).is_ok());
}

/// The billing-critical assertion: the live probe showed a pre-existing virtual
/// key still returning 200 from `/v1/models` after its tenant was suspended.
#[test]
fn a_suspended_tenant_stops_requests() {
    let chain = chain(&[
        ("tenant", "tenant-susp", "suspended"),
        ("project", "proj-susp", "active"),
        ("workspace", "ws-susp", "active"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
        .expect_err("a suspended tenant must stop serving traffic");
    assert_eq!(rejection.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(rejection.code(), "tenancy_suspended");
    assert_eq!(rejection.reference.kind, "tenant");
    assert_eq!(rejection.reference.id, "tenant-susp");
    assert!(
        rejection
            .message()
            .contains("tenant tenant-susp is suspended"),
        "{}",
        rejection.message()
    );
}

/// Suspension at any depth counts -- an operator who suspends only the
/// workspace must not be silently ignored because the tenant above it is fine.
#[test]
fn a_suspended_workspace_alone_stops_requests() {
    let chain = chain(&[
        ("tenant", "tenant-1", "active"),
        ("project", "proj-1", "active"),
        ("workspace", "ws-susp", "suspended"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
        .expect_err("a suspended workspace must stop serving traffic");
    assert_eq!(rejection.reference.kind, "workspace");
    assert_eq!(rejection.code(), "tenancy_suspended");
}

#[test]
fn disabled_and_deleted_also_stop_requests_with_distinct_codes() {
    for (raw, expected_code) in [
        ("disabled", "tenancy_disabled"),
        ("deleted", "tenancy_deleted"),
    ] {
        let chain = chain(&[("tenant", "tenant-1", raw)]);
        let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
            .expect_err("a non-active tenant must stop serving traffic");
        assert_eq!(rejection.code(), expected_code, "for status {raw}");
    }
}

/// The rejection names the ROOT cause: when a suspension cascades down the
/// hierarchy the caller is told about the tenant, not sent chasing the leaf.
#[test]
fn the_shallowest_inactive_row_wins_the_rejection() {
    let chain = chain(&[
        ("tenant", "tenant-susp", "suspended"),
        ("project", "proj-susp", "deleted"),
        ("workspace", "ws-susp", "disabled"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain).unwrap_err();
    assert_eq!(rejection.reference.kind, "tenant");
    assert_eq!(rejection.reference.status, LifecycleStatus::Suspended);
}

/// The attach-time assertion: the live probe minted a brand-new virtual key
/// under a fully suspended chain and got a 201 with a live secret.
#[test]
fn a_suspended_chain_refuses_new_attachments() {
    for raw in ["suspended", "disabled", "deleted"] {
        let chain = chain(&[("tenant", "tenant-1", "active"), ("project", "proj-1", raw)]);
        let rejection = check_lifecycle_chain(LifecycleSeam::Attach, &chain)
            .expect_err("a non-active project must refuse new children");
        assert_eq!(rejection.status(), http::StatusCode::FORBIDDEN, "for {raw}");
        assert_eq!(rejection.code(), "inactive_tenancy_reference", "for {raw}");
        assert!(
            rejection
                .message()
                .contains("cannot be referenced by a new resource"),
            "{}",
            rejection.message()
        );
    }
}

/// The dangerous default, restated at this seam: a legacy row whose `status`
/// column was never written must keep working. If this test ever goes red,
/// shipping #514 revokes every pre-existing tenant.
#[test]
fn absent_or_unknown_status_never_blocks() {
    for raw in ["", "   ", "ACTIVE", "pending_review"] {
        let chain = chain(&[
            ("tenant", "legacy-tenant", raw),
            ("project", "legacy-project", raw),
            ("workspace", "legacy-workspace", raw),
        ]);
        assert!(
            check_lifecycle_chain(LifecycleSeam::Request, &chain).is_ok(),
            "status {raw:?} must not block requests"
        );
        assert!(
            check_lifecycle_chain(LifecycleSeam::Attach, &chain).is_ok(),
            "status {raw:?} must not block attachments"
        );
    }
}

/// A control-plane outage is a retryable 503, never a silent "active" --
/// otherwise flapping storage would be a suspension bypass.
#[test]
fn a_storage_failure_is_a_retryable_503_not_a_bypass() {
    let error = LifecycleGateError::Unavailable("pool exhausted".into());
    assert_eq!(error.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code(), "lifecycle_status_unavailable");
    assert!(
        error.message().contains("pool exhausted"),
        "{}",
        error.message()
    );
}

#[test]
fn a_rejection_converts_into_a_403_auth_error() {
    let rejection = check_lifecycle_chain(
        LifecycleSeam::Request,
        &chain(&[("tenant", "tenant-susp", "suspended")]),
    )
    .unwrap_err();
    let auth_error: crate::auth::AuthError = LifecycleGateError::Inactive(rejection).into();
    assert_eq!(auth_error.status, http::StatusCode::FORBIDDEN);
    assert_eq!(auth_error.code, "tenancy_suspended");
    assert!(!auth_error.message.is_empty());
}
