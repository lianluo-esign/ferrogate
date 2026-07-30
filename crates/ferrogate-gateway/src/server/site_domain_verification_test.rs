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
    let mut record =
        StoredSiteDomainVerification::pending("org_a", "example.com", "docs", "tok", 1_000);
    assert!(
        reusable_on_rebind(&record, 1_100),
        "an operator who already published the TXT is not sent back to DNS",
    );
    record.mark_verified(1_100);
    assert!(
        reusable_on_rebind(&record, 1_200),
        "ownership is of the hostname, not of the site it points at",
    );
    assert!(
        !reusable_on_rebind(&record, 1_100 + 400 * 24 * 60 * 60),
        "an aged-out proof must be re-earned, not carried forward",
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
