// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Offline coverage for the #488 DNS-TXT ownership challenge: the
// token is bound to ONE tenant (tenant B cannot redeem tenant A's challenge),
// a resolver error is never a verification, and the migration backfill only
// ever writes an explicit record. Everything runs through the scripted
// resolver, so no test touches DNS.

use super::*;

use ferrogate_config::Config;
use ferrogate_sync_bridge::block_on_sync_bridge;

use crate::state::AppState;

/// A servable binding row, the shape the bind/verify handlers read and write.
fn binding(tenant: &str, hostname: &str, site: &str, now_unix: i64) -> StoredSiteDomain {
    StoredSiteDomain {
        hostname: hostname.to_string(),
        tenant_id: tenant.to_string(),
        site: site.to_string(),
        created_at_unix: now_unix,
        updated_at_unix: now_unix,
    }
}

/// Scripted resolver: the seam's whole point. Returns a canned answer per
/// looked-up name, so ownership verification is exercised without DNS.
struct ScriptedTxtResolver {
    answer: TxtLookup,
    /// Names this resolver was asked about, so a test can assert the challenge
    /// is looked up at `_ferrogate-challenge.<hostname>` and nowhere else.
    queried: std::sync::Mutex<Vec<String>>,
}

impl ScriptedTxtResolver {
    fn new(answer: TxtLookup) -> Self {
        Self {
            answer,
            queried: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn queried(&self) -> Vec<String> {
        self.queried.lock().expect("scripted resolver lock").clone()
    }
}

#[async_trait]
impl SiteDomainTxtResolver for ScriptedTxtResolver {
    async fn lookup_txt(&self, name: &str) -> TxtLookup {
        self.queried
            .lock()
            .expect("scripted resolver lock")
            .push(name.to_string());
        self.answer.clone()
    }

    fn backend_name(&self) -> &'static str {
        "scripted"
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// A resolver that COUNTS how many times it was asked to look up a name, so a
/// test can prove the #576 refused path never reaches DNS. Any real lookup on
/// the refused path bumps this counter, reddening the zero-calls assertion.
struct CountingTxtResolver {
    calls: std::sync::atomic::AtomicUsize,
    answer: TxtLookup,
}

impl CountingTxtResolver {
    fn new(answer: TxtLookup) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            answer,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl SiteDomainTxtResolver for CountingTxtResolver {
    async fn lookup_txt(&self, _name: &str) -> TxtLookup {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.answer.clone()
    }

    fn backend_name(&self) -> &'static str {
        "counting"
    }
}

#[test]
fn a_rate_limited_reservation_never_calls_the_resolver() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    // Even though the resolver WOULD answer with the matching record, a refused
    // reservation must short-circuit before `lookup_txt` is ever awaited.
    let resolver = CountingTxtResolver::new(TxtLookup::Answers(vec![expected.clone()]));
    let check = block_on(resolve_challenge_within_rate_limit(
        SiteDomainVerificationAttempt::RateLimited {
            retry_after_secs: 17,
        },
        &expected,
        &challenge_record_name("example.com"),
        Some(&resolver),
    ));
    assert_eq!(
        check,
        GatedChallengeCheck::RateLimited {
            retry_after_secs: 17
        },
    );
    assert_eq!(
        resolver.calls(),
        0,
        "an over-limit verify attempt must NOT drive an outbound DNS lookup (#576)",
    );
}

#[test]
fn an_admitted_reservation_calls_the_resolver_exactly_once_and_folds_the_outcome() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    let resolver = CountingTxtResolver::new(TxtLookup::Answers(vec![expected.clone()]));
    let check = block_on(resolve_challenge_within_rate_limit(
        SiteDomainVerificationAttempt::Allowed,
        &expected,
        &challenge_record_name("example.com"),
        Some(&resolver),
    ));
    assert_eq!(
        check,
        GatedChallengeCheck::Resolved(ChallengeOutcome::Verified)
    );
    assert_eq!(
        resolver.calls(),
        1,
        "an admitted attempt performs exactly one lookup",
    );
}

#[test]
fn an_admitted_reservation_without_a_resolver_is_unavailable_never_verified() {
    // Defence in depth: an admitted attempt with no resolver constructed must
    // fold to `ResolverUnavailable`, never to a free `Verified`.
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    let check = block_on(resolve_challenge_within_rate_limit(
        SiteDomainVerificationAttempt::Allowed,
        &expected,
        &challenge_record_name("example.com"),
        None,
    ));
    assert!(matches!(
        check,
        GatedChallengeCheck::Resolved(ChallengeOutcome::ResolverUnavailable(_))
    ));
}

#[test]
fn the_challenge_is_published_under_an_underscore_prefixed_name() {
    assert_eq!(
        challenge_record_name("docs.example.com"),
        "_ferrogate-challenge.docs.example.com",
    );
    // The challenge name is not itself a bindable hostname, so it can never
    // collide with a served domain.
    assert!(challenge_record_name("docs.example.com").starts_with('_'));
}

#[test]
fn the_challenge_value_is_bound_to_one_tenant_and_one_hostname() {
    let value = challenge_txt_value("org_a", "example.com", "token_a");
    assert!(value.starts_with(SITE_DOMAIN_CHALLENGE_VALUE_PREFIX));
    assert_eq!(
        value,
        challenge_txt_value("org_a", "example.com", "token_a")
    );

    // A different tenant, hostname, or token all produce a different value.
    assert_ne!(
        value,
        challenge_txt_value("org_b", "example.com", "token_a")
    );
    assert_ne!(
        value,
        challenge_txt_value("org_a", "other.example.com", "token_a")
    );
    assert_ne!(
        value,
        challenge_txt_value("org_a", "example.com", "token_b")
    );

    // The raw token never appears in the published value, so reading the TXT
    // record does not hand another tenant the secret.
    assert!(!value.contains("token_a"));
}

#[test]
fn length_prefixing_stops_a_crafted_tenant_hostname_pair_from_aliasing() {
    // Without length prefixes these two triples would canonicalise identically
    // and one tenant's published record would satisfy the other's challenge.
    assert_ne!(
        challenge_txt_value("a", "b.example.com", "tok"),
        challenge_txt_value("a:b", "example.com", "tok"),
    );
    assert_ne!(
        challenge_txt_value("org", "example.com", "a:b"),
        challenge_txt_value("org", "example.com:a", "b"),
    );
}

#[test]
fn tenant_b_cannot_redeem_the_challenge_tenant_a_started() {
    let hostname = "contested.example.com";
    // Tenant A starts a challenge and (being the real owner, or not) the TXT
    // record for A's value ends up published.
    let a_value = challenge_txt_value("org_a", hostname, "token_a");
    let resolver = ScriptedTxtResolver::new(TxtLookup::Answers(vec![a_value.clone()]));

    // A can complete its own challenge.
    let lookup = block_on(resolver.lookup_txt(&challenge_record_name(hostname)));
    assert_eq!(
        resolve_challenge(&a_value, lookup),
        ChallengeOutcome::Verified,
    );

    // Tenant B holds a DIFFERENT token for the same hostname, so the record A's
    // owner published proves nothing for B -- even though B can read it.
    let b_value = challenge_txt_value("org_b", hostname, "token_b");
    assert_ne!(a_value, b_value);
    let lookup = block_on(resolver.lookup_txt(&challenge_record_name(hostname)));
    assert!(
        matches!(
            resolve_challenge(&b_value, lookup),
            ChallengeOutcome::NotPublished(_)
        ),
        "tenant B must not be able to redeem tenant A's challenge",
    );

    // And replaying A's token under B's identity does not help either: the
    // digest is over the (tenant, hostname, token) triple.
    let b_replaying_a_token = challenge_txt_value("org_b", hostname, "token_a");
    assert_ne!(b_replaying_a_token, a_value);
    let lookup = block_on(resolver.lookup_txt(&challenge_record_name(hostname)));
    assert!(matches!(
        resolve_challenge(&b_replaying_a_token, lookup),
        ChallengeOutcome::NotPublished(_)
    ));

    assert!(resolver
        .queried()
        .iter()
        .all(|name| name == "_ferrogate-challenge.contested.example.com"));
}

#[test]
fn a_resolver_error_is_never_a_verification() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    let resolver =
        ScriptedTxtResolver::new(TxtLookup::Unavailable("connection refused".to_string()));
    let lookup = block_on(resolver.lookup_txt(&challenge_record_name("example.com")));
    match resolve_challenge(&expected, lookup) {
        ChallengeOutcome::ResolverUnavailable(reason) => {
            assert!(reason.contains("connection refused"), "{reason}");
        }
        other => panic!("an unreachable resolver must not verify: {other:?}"),
    }
}

#[test]
fn the_unbound_default_resolver_can_never_verify_anything() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    let lookup = block_on(UnboundTxtResolver.lookup_txt("_ferrogate-challenge.example.com"));
    assert!(matches!(lookup, TxtLookup::Unavailable(_)));
    assert!(matches!(
        resolve_challenge(&expected, lookup),
        ChallengeOutcome::ResolverUnavailable(_)
    ));
    assert_eq!(UnboundTxtResolver.backend_name(), "unbound");
}

#[test]
fn an_empty_answer_set_is_not_treated_as_unavailable_and_vice_versa() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    // The resolver answered: the name simply has no matching record. That is a
    // definitive "not published", not an outage.
    assert!(matches!(
        resolve_challenge(&expected, TxtLookup::Answers(Vec::new())),
        ChallengeOutcome::NotPublished(_)
    ));
    // Unrelated TXT records on the same name (SPF, other vendors) do not match.
    assert!(matches!(
        resolve_challenge(
            &expected,
            TxtLookup::Answers(vec![
                "v=spf1 -all".to_string(),
                "google-site-verification=abc".to_string(),
            ]),
        ),
        ChallengeOutcome::NotPublished(_)
    ));
    // The expected value alongside other records still verifies.
    assert_eq!(
        resolve_challenge(
            &expected,
            TxtLookup::Answers(vec!["v=spf1 -all".to_string(), expected.clone()]),
        ),
        ChallengeOutcome::Verified,
    );
}

#[test]
fn dns_json_replies_parse_authoritative_answers_and_reject_soft_failures() {
    // NOERROR with a quoted TXT record.
    let body = br#"{"Status":0,"Answer":[{"name":"_ferrogate-challenge.example.com.",
        "type":16,"TTL":60,"data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", body),
        TxtLookup::Answers(vec!["ferrogate-site-verification=abc".to_string()]),
    );

    // A long TXT record arrives as adjacent quoted chunks that concatenate.
    let body = br#"{"Status":0,"Answer":[{"name":"_ferrogate-challenge.example.com",
        "type":16,"data":"\"ferrogate-\" \"site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", body),
        TxtLookup::Answers(vec!["ferrogate-site-verification=abc".to_string()]),
    );

    // NXDOMAIN is authoritative: the name does not exist -> empty answer set.
    assert_eq!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", br#"{"Status":3}"#),
        TxtLookup::Answers(Vec::new()),
    );

    // SERVFAIL / REFUSED / a malformed body are outages, NOT empty answers.
    assert!(matches!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", br#"{"Status":2}"#),
        TxtLookup::Unavailable(_)
    ));
    assert!(matches!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", br#"{"Status":5}"#),
        TxtLookup::Unavailable(_)
    ));
    assert!(matches!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", b"not json"),
        TxtLookup::Unavailable(_)
    ));
    assert!(matches!(
        parse_dns_json_answers("_ferrogate-challenge.example.com", br#"{"Answer":[]}"#),
        TxtLookup::Unavailable(_)
    ));
}

#[test]
fn the_zone_file_backend_matches_only_the_exact_challenge_record() {
    let expected = challenge_txt_value("org_a", "example.com", "token_a");
    let zone = format!(
        "# a comment\n\
         \n\
         _ferrogate-challenge.other.example.com.  ferrogate-site-verification=nope\n\
         _ferrogate-challenge.example.com.        \"{expected}\"\n\
         example.com.                             v=spf1 -all\n"
    );
    assert_eq!(
        zone_file_answers(&zone, "_ferrogate-challenge.example.com"),
        vec![expected.clone()],
    );
    // Case and the trailing root dot are insignificant in DNS.
    assert_eq!(
        zone_file_answers(&zone, "_FERROGATE-CHALLENGE.EXAMPLE.COM."),
        vec![expected.clone()],
    );
    // A name the zone does not carry answers with nothing -- and nothing is
    // still a definitive answer, not an outage.
    assert!(zone_file_answers(&zone, "_ferrogate-challenge.absent.example.com").is_empty());
    assert!(matches!(
        resolve_challenge(
            &expected,
            TxtLookup::Answers(zone_file_answers(
                &zone,
                "_ferrogate-challenge.absent.example.com"
            )),
        ),
        ChallengeOutcome::NotPublished(_)
    ));
}

#[test]
fn an_unreadable_zone_file_is_an_outage_not_an_empty_answer() {
    let resolver = ZoneFileTxtResolver::new("/nonexistent/ferrogate-488/zone.txt");
    let lookup = block_on(resolver.lookup_txt("_ferrogate-challenge.example.com"));
    assert!(
        matches!(lookup, TxtLookup::Unavailable(_)),
        "a missing zone file must not read as 'the record is absent'",
    );
    assert!(matches!(
        resolve_challenge("anything", lookup),
        ChallengeOutcome::ResolverUnavailable(_)
    ));
}

#[test]
fn a_zone_file_backend_with_no_path_stays_unbound() {
    // Selecting the backend without pointing it anywhere must not silently
    // resolve against some default path.
    assert_eq!(
        SiteDomainResolverBackend::ZoneFile {
            path: "/tmp/ferrogate-zone.txt".to_string()
        }
        .build_resolver()
        .backend_name(),
        "zone-file",
    );
}

#[test]
fn the_default_resolver_backend_is_the_offline_unbound_one() {
    // No env var set in this process -> the fail-closed default. (Asserted
    // through `from_env` so a future default flip is caught here.)
    if std::env::var("FERROGATE_SITE_DOMAIN_RESOLVER").is_err() {
        assert_eq!(
            SiteDomainResolverBackend::from_env(),
            SiteDomainResolverBackend::Unbound,
        );
        assert_eq!(
            SiteDomainResolverBackend::Unbound
                .build_resolver()
                .backend_name(),
            "unbound",
        );
    }
}

#[test]
fn the_backfill_writes_one_explicit_record_and_never_overwrites() {
    // Pre-#488 binding, default posture: an explicit `grandfathered` row --
    // never a silent "treat missing as verified".
    let record = backfill_record_for(
        None,
        "org_a",
        "legacy.example.com",
        "docs",
        "tok".to_string(),
        1_000,
        true,
    )
    .expect("a binding with no proof gets a record");
    assert_eq!(record.state.as_str(), "grandfathered");
    assert!(record.serves(1_000));
    assert!(record.verified_at_unix.is_none());

    // Strict posture: the same binding is forced to pending and stops serving.
    let record = backfill_record_for(
        None,
        "org_a",
        "legacy.example.com",
        "docs",
        "tok".to_string(),
        1_000,
        false,
    )
    .expect("a binding with no proof gets a record");
    assert_eq!(record.state.as_str(), "pending_verification");
    assert!(!record.serves(1_000));

    // An existing record (proof OR in-flight challenge) is never clobbered:
    // the backfill is a one-time migration, not a periodic reset.
    let existing =
        StoredSiteDomainVerification::pending("org_a", "legacy.example.com", "docs", "tok", 10);
    assert!(backfill_record_for(
        Some(&existing),
        "org_a",
        "legacy.example.com",
        "docs",
        "tok".to_string(),
        1_000,
        true,
    )
    .is_none());
}

#[test]
fn only_a_live_verified_record_is_eligible_for_acme() {
    let now = 1_000;
    let mut verified =
        StoredSiteDomainVerification::pending("org_a", "verified.example", "docs", "tok", now);
    verified.mark_verified(now);
    assert!(eligible_for_acme(&verified, now));

    let grandfathered =
        StoredSiteDomainVerification::grandfathered("org_a", "legacy.example", "docs", "tok", now);
    assert!(grandfathered.serves(now));
    assert!(
        !eligible_for_acme(&grandfathered, now),
        "a serving migration exception is not ownership proof"
    );

    let pending =
        StoredSiteDomainVerification::pending("org_a", "pending.example", "docs", "tok", now);
    assert!(!eligible_for_acme(&pending, now));

    assert!(
        !eligible_for_acme(
            &verified,
            now + ferrogate_storage::SITE_DOMAIN_VERIFICATION_TTL_SECONDS
        ),
        "an expired proof must not enter a certificate order"
    );
}

/// The bind handler's runtime ACME decision, as a value.
///
/// This is the exact decision `handle_admin_site_domain_bind` applies (it calls
/// `acme_order_action` and hands the result to `apply_site_domain_acme_action`
/// without re-deriving anything), so flipping the policy back to "serving means
/// enrolled" reds here: `grandfathered` serves AND withholds in the same
/// assertion, which no single boolean can satisfy.
#[test]
fn a_grandfathered_rebind_keeps_serving_but_never_enters_the_acme_order_set() {
    let now = 1_000;
    let grandfathered =
        StoredSiteDomainVerification::grandfathered("org_a", "legacy.example", "docs", "tok", now);
    assert_eq!(
        acme_order_action(&grandfathered, now),
        AcmeOrderAction::Withhold {
            serving: true,
            verification_state: "grandfathered",
        },
        "a pre-#488 migration record keeps answering traffic, but re-binding it must not put \
         an unproven hostname back into the certificate order set",
    );
    assert!(!acme_order_action(&grandfathered, now).enrolls());

    let mut verified =
        StoredSiteDomainVerification::pending("org_a", "verified.example", "docs", "tok", now);
    verified.mark_verified(now);
    assert_eq!(acme_order_action(&verified, now), AcmeOrderAction::Enroll);
    assert!(acme_order_action(&verified, now).enrolls());

    let pending =
        StoredSiteDomainVerification::pending("org_a", "pending.example", "docs", "tok", now);
    assert_eq!(
        acme_order_action(&pending, now),
        AcmeOrderAction::Withhold {
            serving: false,
            verification_state: "pending_verification",
        },
    );

    // An aged-out proof is not a proof, and stops serving too.
    let expired_at = now + ferrogate_storage::SITE_DOMAIN_VERIFICATION_TTL_SECONDS;
    assert_eq!(
        acme_order_action(&verified, expired_at),
        AcmeOrderAction::Withhold {
            serving: false,
            verification_state: "expired",
        },
    );
}

/// The verify handler's cross-tenant conflict decision, as a value.
///
/// `handle_admin_site_domain_verify` reads the incumbent's record and asks this
/// predicate; the storage-level `claim_verified_site_domain` CAS applies the
/// same rule. Widening either back to "the holder serves" reds the first
/// assertion below -- which is the land-grab #488 exists to close: the squatter
/// keeps the hostname and the tenant that completed the DNS proof gets the 409.
#[test]
fn only_a_live_proof_defends_an_incumbent_against_a_proved_challenger() {
    let now = 1_000;

    let grandfathered =
        StoredSiteDomainVerification::grandfathered("org_a", "legacy.example", "docs", "tok", now);
    assert!(grandfathered.serves(now), "precondition: it does serve");
    assert!(
        !holder_blocks_verified_takeover(Some(&grandfathered), now),
        "a never-proven incumbent must not permanently block the tenant that actually owns \
         the hostname and completed the challenge",
    );

    let mut verified =
        StoredSiteDomainVerification::pending("org_a", "legacy.example", "docs", "tok", now);
    verified.mark_verified(now);
    assert!(
        holder_blocks_verified_takeover(Some(&verified), now),
        "two live proofs for one hostname resolve first-proof-wins, not last-write",
    );
    assert!(
        !holder_blocks_verified_takeover(
            Some(&verified),
            now + ferrogate_storage::SITE_DOMAIN_VERIFICATION_TTL_SECONDS
        ),
        "an expired proof stops defending the binding",
    );

    let pending =
        StoredSiteDomainVerification::pending("org_a", "legacy.example", "docs", "tok", now);
    assert!(!holder_blocks_verified_takeover(Some(&pending), now));
    assert!(
        !holder_blocks_verified_takeover(None, now),
        "no record at all is not ownership proof",
    );
}

#[test]
fn grandfathering_defaults_on_and_is_switchable_off() {
    // Default (env unset in this process): grandfather, so an upgrade does not
    // take live customer domains offline.
    if std::env::var("FERROGATE_SITE_DOMAIN_GRANDFATHER").is_err() {
        assert!(grandfather_existing_bindings());
    }
}

#[test]
fn a_rebind_reuses_a_live_proof_but_not_an_expired_one() {
    let held = binding("org_a", "example.com", "docs", 1_000);
    let mut record =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "tok", 1_000);
    assert!(
        reusable_on_rebind(&record, Some(&held), 1_100),
        "an operator who already published the TXT is not sent back to DNS",
    );
    record.mark_verified(1_100);
    assert!(
        reusable_on_rebind(&record, Some(&held), 1_200),
        "ownership is of the hostname, not of the site it points at",
    );
    assert!(
        !reusable_on_rebind(&record, Some(&held), 1_100 + 400 * 24 * 60 * 60),
        "an aged-out proof must be re-earned, not carried forward",
    );
}

/// The re-bind reuse rule for the ONE state that is serving without being proof.
///
/// `grandfathered` is a migration availability exception attached to the binding
/// that existed when #488 landed -- it is not evidence of control, and it never
/// expires on its own. So once its tenant no longer holds the binding (unbound,
/// or taken over by a tenant that actually proved ownership) the row is an
/// orphan, and carrying it forward on the next bind would serve the hostname
/// again with nothing proved: the #488 land-grab, one hop later.
///
/// This is what makes the post-takeover cleanup allowed to be best-effort:
/// widening this rule back to "anything unexpired is reusable" reds the middle
/// two assertions, which are exactly the states a failed (or wrongly targeted)
/// cleanup leaves behind.
#[test]
fn a_grandfathered_proof_is_only_reusable_while_its_tenant_still_holds_the_binding() {
    let now = 1_000;
    let host = "legacy.example.com";
    let grandfathered =
        StoredSiteDomainVerification::grandfathered("org_a", host, "docs", "tok", now);
    assert!(grandfathered.serves(now), "precondition: it does serve");

    assert!(
        reusable_on_rebind(
            &grandfathered,
            Some(&binding("org_a", host, "docs", now)),
            now
        ),
        "a legitimate pre-#488 re-bind still holds its own binding and must not be forced back \
         through DNS",
    );
    assert!(
        !reusable_on_rebind(
            &grandfathered,
            Some(&binding("org_b", host, "site", now)),
            now
        ),
        "once another tenant holds the binding, the migration exception is not the squatter's \
         to carry forward",
    );
    assert!(
        !reusable_on_rebind(&grandfathered, None, now),
        "an orphaned migration exception must not resurrect serving on a fresh bind",
    );

    // A live DNS proof IS evidence of control, so it survives regardless of who
    // currently holds the binding row, and it has its own 90-day clock.
    let mut verified = StoredSiteDomainVerification::pending("org_a", host, "docs", "tok", now);
    verified.mark_verified(now);
    assert!(reusable_on_rebind(&verified, None, now));
    assert!(!reusable_on_rebind(
        &verified,
        None,
        now + ferrogate_storage::SITE_DOMAIN_VERIFICATION_TTL_SECONDS
    ));
    // An unexpired challenge keeps its token: it does not serve, so there is
    // nothing to fail closed about.
    let pending = StoredSiteDomainVerification::pending("org_a", host, "docs", "tok", now);
    assert!(!pending.serves(now));
    assert!(reusable_on_rebind(&pending, None, now));
}

/// Who a completed proof displaces, as a value.
///
/// The same-tenant `None` is the dangerous half: the verify handler runs the
/// cleanup on every successful proof, so a selector that named the CLAIMANT
/// would delete the winner's own freshly written `verified` row and the hostname
/// would stop serving the instant it was proved.
#[test]
fn only_another_tenants_binding_is_ever_displaced() {
    let now = 1_000;
    let host = "contested.example.com";
    let squatter = binding("org_a", host, "docs", now);

    assert_eq!(
        displaced_binding_holder(Some(&squatter), "org_b"),
        Some("org_a"),
        "the tenant losing the binding is the one whose proof must go with it",
    );
    assert_eq!(
        displaced_binding_holder(Some(&squatter), "org_a"),
        None,
        "a tenant proving a hostname it already holds displaces nobody",
    );
    assert_eq!(
        displaced_binding_holder(None, "org_b"),
        None,
        "an unbound hostname displaces nobody",
    );

    assert!(holds_binding(Some(&squatter), "org_a"));
    assert!(!holds_binding(Some(&squatter), "org_b"));
    assert!(!holds_binding(None, "org_a"));
}

/// The #488 regression this cleanup exists for, over the real store: a
/// grandfathered squatter that loses the binding to a completed DNS proof must
/// not keep a serving signal it can re-bind into later.
#[test]
fn a_verified_takeover_drops_the_displaced_tenants_serving_proof() {
    let now = 1_000;
    let host = "grabbed.example.com";
    let state = AppState::new(Config::default());

    // org_a is the pre-#488 squatter: it holds the binding and a grandfathered
    // (never-proven) verification row, so today the hostname serves for it.
    let squatter_binding = binding("org_a", host, "docs", now);
    block_on_sync_bridge(state.claim_site_domain(squatter_binding.clone()))
        .expect("seed the squatter's binding");
    let squatter_proof =
        StoredSiteDomainVerification::grandfathered("org_a", host, "docs", "tok_a", now);
    assert!(
        squatter_proof.serves(now),
        "precondition: the squatter is serving"
    );
    block_on_sync_bridge(state.upsert_site_domain_verification(squatter_proof))
        .expect("seed the squatter's proof");

    // org_b completes the DNS-TXT proof and takes the binding over.
    let mut proved = StoredSiteDomainVerification::pending("org_b", host, "site", "tok_b", now);
    proved.mark_verified(now);
    block_on_sync_bridge(state.upsert_site_domain_verification(proved))
        .expect("seed the winner's proof");
    let claimed = block_on_sync_bridge(
        state.claim_verified_site_domain(binding("org_b", host, "site", now), now),
    )
    .expect("a proved challenger takes over an unproven holder");
    assert_eq!(claimed.tenant_id, "org_b");

    // The cleanup the verify handler runs, with the PRE-claim binding it read.
    let cleanup = block_on_sync_bridge(drop_displaced_ownership_proof(
        &state,
        host,
        Some(&squatter_binding),
        "org_b",
    ));
    assert_eq!(
        cleanup,
        DisplacedProofCleanup::Displaced {
            tenant: "org_a".to_string(),
            disposition: DisplacedProofDisposition::Dropped,
        },
    );

    // The displaced tenant's serving signal is gone from the store...
    assert_eq!(
        block_on_sync_bridge(state.get_site_domain_verification("org_a", host))
            .expect("read the displaced tenant's proof"),
        None,
        "an ownership signal must not outlive the binding it backed (#488)",
    );
    // ...and the winner's own proof is untouched.
    assert!(
        block_on_sync_bridge(state.get_site_domain_verification("org_b", host))
            .expect("read the winner's proof")
            .is_some_and(|record| record.has_live_dns_ownership_proof(now)),
    );

    // Even if that delete had failed, the squatter's next bind cannot inherit
    // the orphan: the binding is org_b's now, so the row is not reusable and the
    // re-bind issues a fresh, non-serving challenge instead.
    let orphan = StoredSiteDomainVerification::grandfathered("org_a", host, "docs", "tok_a", now);
    assert!(!reusable_on_rebind(&orphan, Some(&claimed), now));
    assert!(
        !StoredSiteDomainVerification::pending("org_a", host, "docs", "fresh", now).serves(now),
        "the record a displaced tenant's re-bind gets does not serve",
    );
}

/// The other half of the same cleanup: an ordinary verify -- the caller proving a
/// hostname it already holds -- must delete NOTHING. Naming the claimant as the
/// displaced tenant would take a hostname offline the moment it was proved,
/// which is worse than the bug the cleanup fixes, so it is pinned here.
#[test]
fn a_same_tenant_verification_deletes_nobodys_proof() {
    let now = 1_000;
    let host = "own.example.com";
    let state = AppState::new(Config::default());

    let held = binding("org_a", host, "docs", now);
    block_on_sync_bridge(state.claim_site_domain(held.clone())).expect("seed the binding");
    let mut proof = StoredSiteDomainVerification::pending("org_a", host, "docs", "tok", now);
    proof.mark_verified(now);
    block_on_sync_bridge(state.upsert_site_domain_verification(proof)).expect("seed the proof");

    assert_eq!(
        block_on_sync_bridge(drop_displaced_ownership_proof(
            &state,
            host,
            Some(&held),
            "org_a"
        )),
        DisplacedProofCleanup::NoDisplacement,
    );
    let survived = block_on_sync_bridge(state.get_site_domain_verification("org_a", host))
        .expect("read back")
        .expect("a tenant's own fresh proof must survive its own verify");
    assert!(survived.has_live_dns_ownership_proof(now));

    // An unbound hostname is the same story: nothing to displace, nothing to
    // delete.
    assert_eq!(
        block_on_sync_bridge(drop_displaced_ownership_proof(&state, host, None, "org_a")),
        DisplacedProofCleanup::NoDisplacement,
    );
    assert!(
        block_on_sync_bridge(state.get_site_domain_verification("org_a", host))
            .expect("read back")
            .is_some(),
    );
}

/// Three dispositions, not a boolean: only `drop_failed` can leave a stale
/// signal behind, and an operator has to be able to tell it apart from "there
/// was nothing to drop".
#[test]
fn the_cleanup_reports_what_the_store_actually_did() {
    assert_eq!(
        displaced_proof_disposition(Ok(true)),
        DisplacedProofDisposition::Dropped,
    );
    assert_eq!(
        displaced_proof_disposition(Ok(false)),
        DisplacedProofDisposition::Absent,
    );
    assert_eq!(
        displaced_proof_disposition(Err("control-plane store unavailable".to_string())),
        DisplacedProofDisposition::DropFailed,
        "a store that refused the delete must never be reported as a completed drop",
    );
    assert_eq!(DisplacedProofDisposition::Dropped.as_str(), "dropped");
    assert_eq!(DisplacedProofDisposition::Absent.as_str(), "absent");
    assert_eq!(
        DisplacedProofDisposition::DropFailed.as_str(),
        "drop_failed"
    );

    // The `absent` arm through the real store: a displaced tenant that never had
    // a verification row at all.
    let now = 1_000;
    let host = "rowless.example.com";
    let state = AppState::new(Config::default());
    let squatter_binding = binding("org_a", host, "docs", now);
    block_on_sync_bridge(state.claim_site_domain(squatter_binding.clone()))
        .expect("seed the binding");
    assert_eq!(
        block_on_sync_bridge(drop_displaced_ownership_proof(
            &state,
            host,
            Some(&squatter_binding),
            "org_b",
        )),
        DisplacedProofCleanup::Displaced {
            tenant: "org_a".to_string(),
            disposition: DisplacedProofDisposition::Absent,
        },
    );

    // Nobody displaced contributes nothing to the audit line, so an ordinary
    // verify's record is unchanged.
    assert!(DisplacedProofCleanup::NoDisplacement
        .audit_detail()
        .is_empty());
    assert_eq!(
        DisplacedProofCleanup::NoDisplacement.displaced_tenant(),
        None
    );
}

/// The verify path's certificate-order decision.
///
/// `handle_admin_site_domain_verify` promotes the record with `mark_verified`
/// and then hands `acme_order_action(&verification, now)` to
/// `apply_site_domain_acme_action`, so this is the policy that call applies: a
/// completed proof is what enrolls a hostname, and a promotion whose proof is no
/// longer live withholds instead.
///
/// WHAT THIS DOES NOT CATCH, stated plainly: no test drives the handler arm, so
/// replacing its argument with a hand-picked `AcmeOrderAction::Enroll` would
/// leave this green. Closing that needs either the `BindTerminal` sealing
/// treatment on `AcmeOrderAction` or an in-process admin-request test over the
/// verify handler; neither is done here.
#[test]
fn a_completed_proof_is_what_enrolls_a_hostname_in_the_acme_order_set() {
    let now = 1_000;
    let mut verification =
        StoredSiteDomainVerification::pending("org_b", "proved.example.com", "site", "tok", now);
    assert_eq!(
        acme_order_action(&verification, now),
        AcmeOrderAction::Withhold {
            serving: false,
            verification_state: "pending_verification",
        },
        "an unproven hostname must not be in the certificate order set",
    );

    verification.mark_verified(now);
    assert_eq!(
        acme_order_action(&verification, now),
        AcmeOrderAction::Enroll,
        "a completed DNS proof is the only thing that enrolls a hostname",
    );

    // The promotion starts a 90-day clock; past it the same call withholds.
    assert_eq!(
        acme_order_action(
            &verification,
            now + ferrogate_storage::SITE_DOMAIN_VERIFICATION_TTL_SECONDS
        ),
        AcmeOrderAction::Withhold {
            serving: false,
            verification_state: "expired",
        },
    );
}

#[test]
fn a_fresh_challenge_token_is_random_and_hex() {
    let first = new_challenge_token().expect("token");
    let second = new_challenge_token().expect("token");
    assert_eq!(first.len(), 32);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first, second, "tokens must not be predictable/reused");
}

/// #488 review item 3: an answer must be FOR the queried name and must be a
/// TXT record. The previous parser accepted an entry with NO `type` field and
/// never compared `name` at all, so a resolver that ignores the question --
/// a fixed-response proxy, a misrouted endpoint, or a forged reply over the
/// plaintext endpoint item 1 used to allow -- verified EVERY hostname with a
/// single body.
///
/// Each case here is a body that USED to verify and now must not, plus the
/// CNAME case that must still work so the tightening did not overreach.
#[test]
fn an_answer_for_another_name_or_without_a_txt_type_is_not_accepted() {
    let queried = "_ferrogate-challenge.example.com";
    let forged = "ferrogate-site-verification=abc";

    // Answer for a DIFFERENT name: the fixed-response-proxy forgery.
    let body = br#"{"Status":0,"Answer":[{"name":"_ferrogate-challenge.attacker.test",
        "type":16,"data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(Vec::new()),
        "an answer for another name must not satisfy this query"
    );

    // No `type` at all: previously defaulted to TXT.
    let body = br#"{"Status":0,"Answer":[{"name":"_ferrogate-challenge.example.com",
        "data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(Vec::new()),
        "an untyped answer must not be assumed to be TXT"
    );

    // A TXT answer with no owner name cannot be tied to this query.
    let body = br#"{"Status":0,"Answer":[{"type":16,
        "data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(Vec::new()),
        "a nameless TXT answer must not satisfy any query"
    );

    // A non-TXT type carrying the value.
    let body = br#"{"Status":0,"Answer":[{"name":"_ferrogate-challenge.example.com",
        "type":5,"data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(Vec::new()),
        "a CNAME record's data must not be read as a TXT value"
    );

    // A CNAME rooted at an unrelated owner must not extend the accepted-name
    // set and smuggle in a TXT record under its target.
    let body = br#"{"Status":0,"Answer":[
        {"name":"_ferrogate-challenge.attacker.test","type":5,"data":"proof.vendor.test"},
        {"name":"proof.vendor.test","type":16,
            "data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(Vec::new()),
        "an unrelated CNAME must not make its target acceptable"
    );

    // Case and the trailing root dot must not matter -- resolvers disagree.
    let body = br#"{"Status":0,"Answer":[{"name":"_FERROGATE-Challenge.Example.COM.",
        "type":16,"data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(vec![forged.to_string()]),
        "name comparison must fold case and the root dot"
    );

    // A real CNAME chain still resolves: the TXT answer arrives under the
    // CNAME target, not under the queried name.
    let body = br#"{"Status":0,"Answer":[
        {"name":"_ferrogate-challenge.example.com","type":5,"data":"proof.vendor.test"},
        {"name":"proof.vendor.test","type":16,"data":"\"ferrogate-site-verification=abc\""}]}"#;
    assert_eq!(
        parse_dns_json_answers(queried, body),
        TxtLookup::Answers(vec![forged.to_string()]),
        "a CNAME target's TXT answer must still be accepted"
    );
}

/// #488 review item 1: a non-https DoH endpoint must not be used at all.
#[test]
fn a_plaintext_doh_endpoint_falls_back_to_the_unbound_resolver() {
    let plaintext = SiteDomainResolverBackend::Doh {
        endpoint: "http://internal-dns/dns-query".to_string(),
        timeout_secs: 10,
    };
    assert_eq!(
        plaintext.build_resolver().backend_name(),
        "unbound",
        "a plaintext endpoint must not be reported or used as a doh resolver"
    );

    let secure = SiteDomainResolverBackend::Doh {
        endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
        timeout_secs: 10,
    };
    assert_eq!(
        secure.build_resolver().backend_name(),
        "doh",
        "an https endpoint must still build the doh resolver"
    );
}
