// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Unit tests for the custom-domain binding pure logic (#265) --
// hostname normalization/validation -- kept out of the async gateway handler
// so they run without a live database.

use super::*;

#[test]
fn valid_hostnames_normalize_to_lowercase_without_port() {
    assert_eq!(
        validate_site_domain_hostname(Some("MySite.Example.COM")).unwrap(),
        "mysite.example.com"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("mysite.example.com:8443")).unwrap(),
        "mysite.example.com"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("  docs.internal.example  ")).unwrap(),
        "docs.internal.example"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("a-1.b-2.example.io")).unwrap(),
        "a-1.b-2.example.io"
    );
}

#[test]
fn missing_or_empty_hostname_is_rejected() {
    assert!(validate_site_domain_hostname(None).is_err());
    assert!(validate_site_domain_hostname(Some("")).is_err());
    assert!(validate_site_domain_hostname(Some("   ")).is_err());
}

#[test]
fn single_label_hostnames_are_rejected() {
    let error = validate_site_domain_hostname(Some("localhost")).unwrap_err();
    assert!(error.contains("fully qualified"), "{error}");
    assert!(validate_site_domain_hostname(Some("intranet")).is_err());
}

#[test]
fn wildcards_and_ip_literals_are_rejected() {
    assert!(validate_site_domain_hostname(Some("*.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("192.168.1.10")).is_err());
    assert!(validate_site_domain_hostname(Some("[::1]:443")).is_err());
}

#[test]
fn malformed_dns_labels_are_rejected() {
    // Empty label (double dot / leading dot / trailing dot).
    assert!(validate_site_domain_hostname(Some("a..example.com")).is_err());
    assert!(validate_site_domain_hostname(Some(".example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("example.com.")).is_err());
    // Hyphen at a label edge.
    assert!(validate_site_domain_hostname(Some("-bad.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("bad-.example.com")).is_err());
    // Disallowed characters.
    assert!(validate_site_domain_hostname(Some("under_score.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("spa ce.example.com")).is_err());
    // Oversized label / hostname.
    let long_label = format!("{}.example.com", "a".repeat(64));
    assert!(validate_site_domain_hostname(Some(&long_label)).is_err());
    let long_hostname = format!("{}.example.com", "a.".repeat(130));
    assert!(validate_site_domain_hostname(Some(&long_hostname)).is_err());
}

/// #530: the handler answers 200/201/**202**, but the OpenAPI document declared
/// only 200/201. This couples the two so they cannot drift apart again: the
/// statuses the handler can actually produce, enumerated over every input, must
/// all be declared for `bindSiteDomain`.
///
/// The assertion is on the produced status set, not on the source text — adding
/// a fourth terminal to `site_domain_bind_status` without declaring it reds
/// this, and deleting the `202` declaration from the spec reds it too.
#[test]
fn every_bind_terminal_is_declared_in_the_openapi_document() {
    const SPEC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/admin-api.openapi.json"
    ));

    let produced: std::collections::BTreeSet<u16> = [true, false]
        .into_iter()
        .flat_map(|proven| {
            [true, false]
                .into_iter()
                .map(move |existing| site_domain_bind_status(proven, existing).status().as_u16())
        })
        .collect();
    // The three-way terminal the issue names. If this changes, the spec below
    // must change with it -- that coupling is the whole point of the test.
    assert_eq!(
        produced,
        [200u16, 201, 202].into_iter().collect(),
        "bind terminals changed"
    );

    let spec: serde_json::Value =
        serde_json::from_str(SPEC).expect("admin-api.openapi.json parses");
    let declared = spec["paths"]["/admin/v1/site-domains"]["post"]["responses"]
        .as_object()
        .expect("bindSiteDomain declares responses");
    for status in &produced {
        assert!(
            declared.contains_key(&status.to_string()),
            "handler can return {status} but bindSiteDomain does not declare it; \
             declared = {:?}",
            declared.keys().collect::<Vec<_>>()
        );
    }

    // Direction (b), added on review: a declared SUCCESS status the runtime can
    // never produce is drift too, and the first cut asserted only direction (a)
    // -- adding `"203": {...}` to the spec left it green. Only 2xx is compared,
    // because the error terminals come from shared `#/components/responses`
    // refs raised by helpers (`storage_error` -> 503, the validation arms ->
    // 400/404/409/413) rather than from `site_domain_bind_status`, so they are
    // not derivable here; item 2 of this review declares them explicitly
    // instead.
    let declared_success: std::collections::BTreeSet<u16> = declared
        .keys()
        .filter_map(|code| code.parse::<u16>().ok())
        .filter(|code| (200..300).contains(code))
        .collect();
    assert_eq!(
        declared_success, produced,
        "bindSiteDomain's declared 2xx set must equal what site_domain_bind_status \
         can produce -- a declared-but-unreachable success code is drift in the \
         other direction"
    );
}

/// Sibling audit: `verifySiteDomain` answers `400 invalid_site_domain` when
/// the `tenant_id` query parameter is absent (`site_domains.rs`, the `None =>`
/// arm of the tenant resolution), which the document did not declare.
///
/// NAMED FOR WHAT IT ACTUALLY PINS (#530 review): this asserts the
/// DECLARATION only. It derives nothing from the verify handler, so deleting
/// that `None =>` arm leaves it green and the runtime side of the gap can
/// reopen. The earlier name claimed it stopped exactly that. Closing the
/// runtime half needs the same newtype treatment the bind terminal got, or a
/// derivation from the runtime contract; neither is done here.
#[test]
fn verify_declares_a_400_for_the_missing_tenant_arm() {
    const SPEC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/admin-api.openapi.json"
    ));
    let spec: serde_json::Value =
        serde_json::from_str(SPEC).expect("admin-api.openapi.json parses");
    let declared = spec["paths"]["/admin/v1/site-domains/{hostname}/verify"]["post"]["responses"]
        .as_object()
        .expect("verifySiteDomain declares responses");
    assert!(
        declared.contains_key("400"),
        "verifySiteDomain returns 400 when tenant_id is missing; declared = {:?}",
        declared.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// #547 Verification: the bind terminal, driven.
//
// The three earlier rounds of this issue landed the decision and the contract
// text but no coverage, because the bind terminal was reachable only through a
// pingora `Session`. `apply_site_domain_bind` is that decision with the
// connection removed, so these tests drive the real code path against an
// in-memory control plane -- no `FERROGATE_SUPABASE_DSN`, no gateway process.
//
// THE MUTATION EACH TEST IS BUILT TO CATCH is named on the test itself. The
// load-bearing one: delete the `existing.tenant_id != tenant_id` arm in
// `apply_site_domain_bind`. That does NOT change any observable storage state
// -- the guarded claim refuses the same write one step later -- so a test that
// asserted "no binding was stolen" or "409" would stay green. Only the outcome
// IDENTITY moves, from `NonHolderRefused` to `ClaimLostToAnotherTenant`, which
// is what `a_non_holder_bind_...` asserts.

use crate::state::AppState;
use ferrogate_storage::{StoredSiteDomain, StoredSiteDomainVerification};

const HOSTNAME: &str = "app.example.com";
const NOW: i64 = 1_700_000_000;

fn state() -> AppState {
    AppState::new(ferrogate_config::Config::default())
}

fn binding(tenant_id: &str, site: &str, created_at_unix: i64) -> StoredSiteDomain {
    StoredSiteDomain {
        hostname: HOSTNAME.to_string(),
        tenant_id: tenant_id.to_string(),
        site: site.to_string(),
        created_at_unix,
        updated_at_unix: created_at_unix,
    }
}

/// A live DNS ownership proof: `verified` and not yet expired at [`NOW`].
fn live_proof(tenant_id: &str, site: &str) -> StoredSiteDomainVerification {
    let mut proof = StoredSiteDomainVerification::pending(tenant_id, HOSTNAME, site, "tok", NOW);
    proof.mark_verified(NOW);
    proof
}

/// Seeds tenant B as the incumbent holding an UNPROVEN claim -- the exact
/// precondition of #547's reachable sequence, and the one the pre-#547 handler
/// answered with a 200 that claimed a same-tenant re-bind.
async fn seed_unproven_incumbent(state: &AppState) {
    state
        .claim_site_domain(binding("tenant-b", "b-site", NOW - 1_000))
        .await
        .expect("seed incumbent binding");
    state
        .upsert_site_domain_verification(StoredSiteDomainVerification::pending(
            "tenant-b",
            HOSTNAME,
            "b-site",
            "b-token",
            NOW - 1_000,
        ))
        .await
        .expect("seed incumbent pending proof");
}

/// #547's reachable sequence, end to end: B holds an unproven claim, A binds
/// the same hostname carrying a live ownership proof of its own. The pre-#547
/// handler answered 200 "re-bound within the same tenant" and serialized a
/// binding row it never wrote.
///
/// MUTATION THIS CATCHES: delete the `existing.tenant_id != tenant_id` refusal
/// arm in `apply_site_domain_bind` -> the outcome becomes
/// `ClaimLostToAnotherTenant` and the first assertion fails. Also caught:
/// restoring the two-argument confusion by feeding the terminal selector the
/// unfiltered incumbent, which cannot even be expressed now that the refusal
/// consumes it -- `same_tenant_rebind` is only reachable inside `Bound`.
#[tokio::test]
async fn a_non_holder_bind_against_an_unproven_incumbent_is_refused_by_identity() {
    let state = state();
    seed_unproven_incumbent(&state).await;
    state
        .upsert_site_domain_verification(live_proof("tenant-a", "a-site"))
        .await
        .expect("seed caller's live proof");

    let outcome = apply_site_domain_bind(&state, "tenant-a", "a-site", HOSTNAME, NOW).await;

    assert!(
        matches!(outcome, SiteDomainBindOutcome::NonHolderRefused),
        "a bind by a non-holder must be refused at preflight, by identity -- not \
         merely end in some 409-shaped terminal"
    );
    // The body half of #547's Ask 2: identity, not status class. The incumbent
    // row must still be B's, unchanged, and A must not have been handed one.
    let incumbent = state
        .get_site_domain(HOSTNAME)
        .await
        .expect("read binding")
        .expect("incumbent binding survives the refusal");
    assert_eq!(
        incumbent.tenant_id, "tenant-b",
        "the refused bind must not move the binding to the caller"
    );
    assert_eq!(incumbent.site, "b-site");
    assert_eq!(incumbent.created_at_unix, NOW - 1_000);
    // A's own pre-existing proof is evidence about the HOSTNAME, so it survives;
    // what must NOT happen is the refused bind re-pointing it at A's site.
    let caller_proof = state
        .get_site_domain_verification("tenant-a", HOSTNAME)
        .await
        .expect("read caller proof")
        .expect("the caller's pre-existing proof is untouched");
    assert_eq!(
        caller_proof.site, "a-site",
        "the refusal must not rewrite the caller's proof row"
    );
}

/// The 409's contract promise, asserted directly: a refused non-holder bind
/// creates NO challenge row. This is the assertion the write reorder exists to
/// make true -- with the proof write ahead of the claim, a caller with no prior
/// proof walked away from a 409 holding a freshly issued challenge for a
/// hostname it does not own, while the OpenAPI 409 said "no challenge is
/// created".
///
/// MUTATION THIS CATCHES: move the `upsert_site_domain_verification` call in
/// `apply_site_domain_bind` back ahead of `claim_site_domain` AND delete the
/// preflight refusal -- the orphan row reappears and this goes red. (With the
/// refusal in place the reorder alone is not observable here, which is the
/// point of pairing this with the identity assertion above.)
#[tokio::test]
async fn a_refused_bind_leaves_the_caller_no_challenge_row() {
    let state = state();
    seed_unproven_incumbent(&state).await;

    let outcome = apply_site_domain_bind(&state, "tenant-a", "a-site", HOSTNAME, NOW).await;

    // The storage footprint is asserted BEFORE the terminal on purpose: this
    // test exists for the write ordering, so it must fail on the orphan row
    // rather than on the outcome variant its sibling above already pins.
    assert!(
        state
            .get_site_domain_verification("tenant-a", HOSTNAME)
            .await
            .expect("read caller proof")
            .is_none(),
        "a refused bind must not issue the caller a challenge for a hostname \
         another tenant holds -- the 409 description promises exactly this"
    );
    assert!(matches!(outcome, SiteDomainBindOutcome::NonHolderRefused));
}

/// An unbound hostname: the binding is recorded, a challenge is issued, and the
/// terminal is 202 -- NOT serving, and not a same-tenant re-bind.
///
/// MUTATION THIS CATCHES: returning `same_tenant_rebind: true` when the
/// hostname was unbound (the selector would answer 201 for a hostname that is
/// not serving, and 200 once it is).
#[tokio::test]
async fn binding_an_unbound_hostname_records_the_claim_and_a_fresh_challenge() {
    let state = state();

    let outcome = apply_site_domain_bind(&state, "tenant-a", "a-site", HOSTNAME, NOW).await;

    let SiteDomainBindOutcome::Bound(bound) = outcome else {
        panic!("binding an unbound hostname must succeed");
    };
    assert!(
        !bound.same_tenant_rebind,
        "there was no prior binding to re-bind"
    );
    assert!(!bound.serving, "#488: an unproven hostname does not serve");
    assert_eq!(
        site_domain_bind_status(bound.serving, bound.same_tenant_rebind).status(),
        http::StatusCode::ACCEPTED
    );
    // The response body is built from the row the STORE returned (#547 Ask 2).
    assert_eq!(bound.domain.tenant_id, "tenant-a");
    assert_eq!(
        state
            .get_site_domain(HOSTNAME)
            .await
            .expect("read binding")
            .expect("binding persisted")
            .tenant_id,
        "tenant-a",
        "the serialized domain must be a row that was actually persisted"
    );
    assert_eq!(
        state
            .get_site_domain_verification("tenant-a", HOSTNAME)
            .await
            .expect("read proof")
            .expect("challenge issued")
            .challenge_token,
        bound.verification.challenge_token,
        "the challenge handed to the caller must be the one that was stored"
    );
}

/// The 200 terminal, and the only sequence entitled to it: the SAME tenant
/// re-binds a hostname it already holds with a live proof. `created_at_unix` is
/// preserved from the prior row, which is what makes it a re-bind rather than a
/// new binding.
///
/// MUTATION THIS CATCHES: widening `same_tenant_rebind` back to "a row exists"
/// -- combined with the refusal deletion, that is the exact pre-#547 defect,
/// and `a_non_holder_bind_...` above is its other half.
#[tokio::test]
async fn a_same_tenant_rebind_with_a_live_proof_is_the_200_terminal() {
    let state = state();
    state
        .claim_site_domain(binding("tenant-a", "old-site", NOW - 5_000))
        .await
        .expect("seed the caller's own binding");
    state
        .upsert_site_domain_verification(live_proof("tenant-a", "old-site"))
        .await
        .expect("seed the caller's live proof");

    let outcome = apply_site_domain_bind(&state, "tenant-a", "new-site", HOSTNAME, NOW).await;

    let SiteDomainBindOutcome::Bound(bound) = outcome else {
        panic!("a tenant re-binding its own hostname must succeed");
    };
    assert!(
        bound.same_tenant_rebind,
        "the caller held this binding already"
    );
    assert!(
        bound.serving,
        "a live proof keeps the hostname serving across a re-bind"
    );
    assert_eq!(
        site_domain_bind_status(bound.serving, bound.same_tenant_rebind).status(),
        http::StatusCode::OK,
        "this is the sequence the 200's \"re-bound within the same tenant\" \
         description is a true statement about"
    );
    assert_eq!(
        bound.domain.created_at_unix,
        NOW - 5_000,
        "a re-bind preserves the original binding's creation time"
    );
    assert_eq!(bound.domain.site, "new-site");
    // The live proof is reused rather than reissued, and follows the site.
    assert_eq!(bound.verification.site, "new-site");
    assert!(bound.verification.has_live_dns_ownership_proof(NOW));
}
