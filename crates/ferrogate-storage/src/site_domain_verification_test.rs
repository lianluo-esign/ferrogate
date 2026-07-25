// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Backend + state-machine coverage for the #488 site-domain
// ownership proof: the `(tenant, hostname)` key never aliases, the explicit
// state machine only serves on a live proof, expiry is applied at READ time,
// and a failed/impossible check never promotes a record.

use crate::{
    site_domain_verification_key, RuntimeStorageRepositories, SiteDomainVerificationState,
    StorageProviderKind, StoredSiteDomainVerification, SITE_DOMAIN_CHALLENGE_TTL_SECONDS,
    SITE_DOMAIN_VERIFICATION_TTL_SECONDS,
};

use crate::schema_routing_test_support::block_on;

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

#[test]
fn verification_key_is_length_prefixed_and_cannot_alias() {
    // Without the length prefix `("a", "b:c")` and `("a:b", "c")` would collide
    // -- which would let one tenant's challenge answer for another's.
    assert_ne!(
        site_domain_verification_key("a", "b:c"),
        site_domain_verification_key("a:b", "c"),
    );
    assert_eq!(
        site_domain_verification_key("org_a", "example.com"),
        site_domain_verification_key("org_a", "example.com"),
    );
    assert_ne!(
        site_domain_verification_key("org_a", "example.com"),
        site_domain_verification_key("org_b", "example.com"),
    );
}

#[test]
fn a_pending_challenge_never_serves_and_expires_at_read_time() {
    let pending =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "tok", 1_000);
    assert_eq!(
        pending.effective_state(1_000),
        SiteDomainVerificationState::PendingVerification
    );
    assert!(
        !pending.serves(1_000),
        "an unverified domain must never serve",
    );

    // Past the token TTL the record resolves to `expired` WITHOUT any sweeper
    // having run, and still does not serve.
    let after = 1_000 + SITE_DOMAIN_CHALLENGE_TTL_SECONDS;
    assert_eq!(
        pending.effective_state(after),
        SiteDomainVerificationState::Expired
    );
    assert!(!pending.serves(after));
}

#[test]
fn a_verified_proof_serves_until_the_reverification_deadline() {
    let mut record =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "tok", 1_000);
    record.mark_verified(2_000);
    assert_eq!(record.state, SiteDomainVerificationState::Verified);
    assert_eq!(record.verified_at_unix, Some(2_000));
    assert!(record.serves(2_000));
    assert!(record.last_failure_reason.is_none());

    let deadline = 2_000 + SITE_DOMAIN_VERIFICATION_TTL_SECONDS;
    assert!(record.serves(deadline - 1));
    assert_eq!(
        record.effective_state(deadline),
        SiteDomainVerificationState::Expired,
        "a proof from an unbounded past is not a proof of present control",
    );
    assert!(!record.serves(deadline));
}

#[test]
fn a_failed_or_impossible_check_never_promotes_a_record() {
    let mut record =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "tok", 1_000);
    record.mark_check_failed(1_100, "resolver unavailable: connection refused");
    assert_eq!(
        record.state,
        SiteDomainVerificationState::PendingVerification,
        "an unreachable resolver is not a verification",
    );
    assert!(!record.serves(1_100));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_checked_at_unix, Some(1_100));
    assert!(record
        .last_failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("resolver unavailable")));

    record.mark_check_failed(1_200, "no matching TXT record");
    assert_eq!(record.attempt_count, 2);
    assert!(!record.serves(1_200));
}

#[test]
fn grandfathered_records_serve_but_are_distinguishable_from_verified() {
    let record = StoredSiteDomainVerification::grandfathered(
        "org_a",
        "legacy.example.com",
        "docs",
        "tok",
        5,
    );
    assert_eq!(record.state, SiteDomainVerificationState::Grandfathered);
    assert!(
        record.serves(i64::MAX / 2),
        "a pre-#488 binding keeps serving instead of going dark",
    );
    assert_ne!(record.state.as_str(), "verified");
    assert_eq!(record.state.as_str(), "grandfathered");
    assert!(
        record.verified_at_unix.is_none(),
        "grandfathering is a migration decision, never evidence of ownership",
    );
}

#[test]
fn state_strings_round_trip_and_unknown_states_are_not_servable_defaults() {
    for state in [
        SiteDomainVerificationState::PendingVerification,
        SiteDomainVerificationState::Verified,
        SiteDomainVerificationState::Grandfathered,
        SiteDomainVerificationState::Expired,
    ] {
        assert_eq!(
            SiteDomainVerificationState::from_str_opt(state.as_str()),
            Some(state),
        );
    }
    assert_eq!(SiteDomainVerificationState::from_str_opt("ok"), None);
    assert_eq!(SiteDomainVerificationState::from_str_opt(""), None);
    assert!(!SiteDomainVerificationState::PendingVerification.serves());
    assert!(!SiteDomainVerificationState::Expired.serves());
    assert!(SiteDomainVerificationState::Verified.serves());
    assert!(SiteDomainVerificationState::Grandfathered.serves());
}

#[test]
fn in_memory_verification_crud_is_scoped_per_tenant() {
    let repositories = memory_repositories();
    let tenant_a =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "token_a", 1_000);
    let tenant_b =
        StoredSiteDomainVerification::pending("org_b", "example.com", "landing", "token_b", 1_000);
    block_on(repositories.upsert_site_domain_verification(tenant_a.clone())).expect("issue a");
    block_on(repositories.upsert_site_domain_verification(tenant_b.clone())).expect("issue b");

    // Two tenants can hold a PENDING challenge for the same hostname at once
    // (so a squatter cannot block the real owner), each with its own token.
    let fetched_a = block_on(repositories.get_site_domain_verification("org_a", "example.com"))
        .expect("get a")
        .expect("present");
    let fetched_b = block_on(repositories.get_site_domain_verification("org_b", "example.com"))
        .expect("get b")
        .expect("present");
    assert_eq!(fetched_a, tenant_a);
    assert_eq!(fetched_b, tenant_b);
    assert_ne!(fetched_a.challenge_token, fetched_b.challenge_token);

    assert!(
        block_on(repositories.get_site_domain_verification("org_c", "example.com"))
            .expect("get c")
            .is_none(),
        "a third tenant inherits nothing from either challenge",
    );

    let scoped =
        block_on(repositories.list_site_domain_verifications(Some("org_a"))).expect("list scoped");
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].tenant_id, "org_a");
    assert_eq!(
        block_on(repositories.list_site_domain_verifications(None))
            .expect("list all")
            .len(),
        2
    );

    // Deleting one tenant's proof leaves the other's untouched.
    assert!(
        block_on(repositories.delete_site_domain_verification("org_a", "example.com"))
            .expect("delete a")
    );
    assert!(
        block_on(repositories.get_site_domain_verification("org_a", "example.com"))
            .expect("get a")
            .is_none()
    );
    assert!(
        block_on(repositories.get_site_domain_verification("org_b", "example.com"))
            .expect("get b")
            .is_some()
    );
    assert!(
        !block_on(repositories.delete_site_domain_verification("org_a", "example.com"))
            .expect("delete a again"),
        "deleting a missing proof reports no row removed",
    );
}
