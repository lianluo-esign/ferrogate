// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tests for the client action identity (issue #548).
//!
//! Each test below states the line it pins and the one-token mutation that
//! reds it, per `docs/testing/testing-architecture.md` § "Assertions must be
//! able to fail". The tests that matter most are the ones holding a *contract*
//! rather than a value:
//!
//! * [`the_only_local_clock_read_in_the_audit_path_is_the_one_named_for_it`] —
//!   a source guard. The acceptance criterion is "a test that fails if
//!   `SystemTime::now()` reaches the audit timestamp field", and no value
//!   assertion can express that: a clock read *anywhere* in the audit path is
//!   the defect, and it would produce a perfectly plausible number.
//! * [`the_fingerprint_declares_exactly_the_reviewed_field_set`] — the privacy
//!   decision is a *field set*, so it is pinned as a field set. An assertion
//!   that only checks "the token is absent" cannot fail when someone adds a
//!   username, and the field set is what was reviewed.
//! * [`the_fingerprint_never_carries_the_token_it_was_built_from`] — #489/#492/
//!   #537's live defect class, asserted on the rendered form, on `Debug`, and
//!   on the token's decimal-byte spelling, with a positive shape assertion so an
//!   impl that drops every field is not silently accepted.

use super::*;
use crate::auth::AuthSource;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::output::OutputFormat;

/// A token whose 4-, 8- and 16-character prefixes appear nowhere else in a
/// rendered fingerprint by accident.
const SECRET: &str = "zqx7f3k9wvbn2m5t8ur4jhg6dpsl1coy";

fn context_with_auth(auth: AuthSource) -> EffectiveContext {
    EffectiveContext {
        context_name: Some("prod-eu".to_string()),
        endpoint: "https://control.example.com".to_string(),
        tenant: Some("org_acme".to_string()),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth,
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

/// The decimal-byte spelling a derived `Debug` would print for a `Vec<u8>`
/// holding the secret. A plaintext-only assertion is vacuous against that
/// rendering (#537), so it is checked explicitly.
fn decimal_bytes(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Pins: [`ActionId::mint`]'s use of `getrandom` and the
/// `{ACTION_ID_PREFIX}{32 hex}` shape.
///
/// Catches: replacing the CSPRNG read with a constant, a counter, or a clock
/// read — 64 mints would then collide and the uniqueness assertion reds; and
/// shortening the id (`[0u8; 16]` → `[0u8; 8]`), which reds the shape assertion.
#[test]
fn a_minted_action_id_is_unique_and_well_formed() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..64 {
        let id = ActionId::mint().expect("the OS random source is available in the test env");
        assert!(
            is_well_formed_action_id(id.as_str()),
            "'{id}' is not {ACTION_ID_PREFIX}<32 lowercase hex>"
        );
        assert!(
            seen.insert(id.as_str().to_string()),
            "'{id}' was minted twice in 64 draws; the id is not random"
        );
    }
}

/// Pins: [`is_well_formed_action_id`]'s three conditions (prefix, length, and
/// lowercase-hex alphabet), which [`crate::receipt::MutationReceipt::validate`]
/// leans on.
///
/// Catches: dropping the length check (the 31-hex case passes), dropping the
/// case check (the uppercase case passes), or dropping the prefix check (the
/// bare-hex case passes).
#[test]
fn action_id_shape_rejects_the_near_misses() {
    let valid = format!("{ACTION_ID_PREFIX}{}", "a".repeat(32));
    assert!(is_well_formed_action_id(&valid));
    assert!(
        !is_well_formed_action_id(&format!("{ACTION_ID_PREFIX}{}", "a".repeat(31))),
        "31 hex characters must not pass"
    );
    assert!(
        !is_well_formed_action_id(&format!("{ACTION_ID_PREFIX}{}", "A".repeat(32))),
        "uppercase hex must not pass"
    );
    assert!(
        !is_well_formed_action_id(&"a".repeat(32)),
        "a bare digest with no prefix must not pass"
    );
    assert!(
        !is_well_formed_action_id(&format!("{ACTION_ID_PREFIX}{}", "z".repeat(32))),
        "non-hex characters must not pass"
    );
}

/// Pins: the exact contents of [`FINGERPRINT_FIELDS`] and
/// [`ClientFingerprint::fields`] agreeing with each other.
///
/// Catches: **any** field added to or removed from the fingerprint. That is the
/// point — the reviewed privacy decision is a field set, and the alternative
/// assertion ("the credential is absent") stays green when someone adds a
/// username, a working directory, or an argv. Adding `("user", …)` to `fields()`
/// without updating `FINGERPRINT_FIELDS` reds here; adding it to both reds the
/// review, which is where the decision belongs.
#[test]
fn the_fingerprint_declares_exactly_the_reviewed_field_set() {
    let fingerprint = ClientFingerprint::detect(
        &context_with_auth(AuthSource::Inline {
            token: SECRET.to_string(),
        }),
        &FingerprintEnv::default(),
    );
    let declared: Vec<&str> = fingerprint.fields().iter().map(|(key, _)| *key).collect();
    assert_eq!(
        declared,
        FINGERPRINT_FIELDS.to_vec(),
        "the fingerprint's field set is the reviewed privacy decision; changing it is a review \
         event, not a refactor"
    );
}

/// Pins: [`ClientFingerprint::detect`] reading [`AuthSource::audit_source`]
/// rather than the token, and the hand-written `Debug`.
///
/// Catches: `credential_source: token.clone()` in `detect` (plaintext
/// assertion reds); storing a prefix or a truncated key id (the 4/8/16-prefix
/// assertions red); replacing the hand-written `Debug` with a derive **and**
/// adding a byte-vector field (the decimal-byte assertion reds — a derived
/// `Debug` prints `[122, 113, 120, …]`, which a plaintext-only check misses).
/// The positive-shape assertion catches the mirror mutation: an impl that
/// simply drops every field would satisfy every absence check.
#[test]
fn the_fingerprint_never_carries_the_token_it_was_built_from() {
    let context = context_with_auth(AuthSource::Inline {
        token: SECRET.to_string(),
    });
    let fingerprint = ClientFingerprint::detect(&context, &FingerprintEnv::default());
    let rendered = fingerprint.render();
    let debug = format!("{fingerprint:?}");
    let identity = ClientActionIdentity {
        action_id: ActionId::mint().expect("mint"),
        fingerprint: fingerprint.clone(),
        clock: ClientClockReading::from_unix_seconds(1_800_000_000),
        server_time: Arc::new(Mutex::new(None)),
    };
    let headers = identity
        .headers()
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let identity_debug = format!("{identity:?}");

    for (label, haystack) in [
        ("rendered fingerprint", &rendered),
        ("fingerprint Debug", &debug),
        ("sent headers", &headers),
        ("identity Debug", &identity_debug),
    ] {
        assert!(
            !haystack.contains(SECRET),
            "{label} carries the bearer token verbatim: {haystack}"
        );
        for prefix_len in [4usize, 8, 16] {
            let prefix = &SECRET[..prefix_len];
            assert!(
                !haystack.contains(prefix),
                "{label} carries a {prefix_len}-character prefix of the bearer token, which is \
                 an offline-guessing oracle: {haystack}"
            );
        }
        assert!(
            !haystack.contains(&decimal_bytes(SECRET)),
            "{label} carries the token's decimal-byte spelling — the rendering a DERIVED Debug \
             produces for a Vec<u8>, against which a plaintext-only assertion is vacuous: \
             {haystack}"
        );
    }

    // Positive shape: an impl that drops every field would pass every absence
    // check above, so the fields that MUST be there are asserted too.
    assert!(rendered.starts_with(IDENTITY_SCHEMA_VERSION));
    assert!(rendered.contains(&format!("cli={}", crate::version::CLI_VERSION)));
    assert!(rendered.contains(&format!("os={}", std::env::consts::OS)));
    assert!(rendered.contains(&format!("arch={}", std::env::consts::ARCH)));
    assert!(rendered.contains("context=prod-eu"));
    assert!(
        rendered.contains("cred=inline"),
        "the credential SOURCE is what the fingerprint carries, and dropping it would make the \
         absence assertions above vacuous: {rendered}"
    );
}

/// Pins: the `env:VAR` / `stdin` / `inline` / `none` mapping in
/// [`AuthSource::audit_source`], which both the fingerprint and
/// [`crate::receipt::ReceiptActor::credential_source`] now share.
///
/// Catches: an `Inline` arm that returns the token (the `inline` assertion
/// reds), or collapsing `Env` to a bare `"env"` (the named-variable assertion
/// reds, and with it the ability to tell two credential sources apart).
#[test]
fn the_credential_source_label_names_the_shape_never_the_material() {
    assert_eq!(AuthSource::None.audit_source(), "none");
    assert_eq!(
        AuthSource::Env {
            var: "FERROGATE_TOKEN".to_string()
        }
        .audit_source(),
        "env:FERROGATE_TOKEN"
    );
    assert_eq!(AuthSource::Stdin.audit_source(), "stdin");
    assert_eq!(
        AuthSource::Inline {
            token: SECRET.to_string()
        }
        .audit_source(),
        "inline"
    );
}

/// Pins: the opt-in default of `host` and `client_reported_ip` — the whole
/// privacy decision in one assertion.
///
/// Catches: making either field auto-detected (reading the real hostname, or
/// probing an interface address). Either mutation makes the absent-by-default
/// assertions red, which is the alarm this decision needs: collection without
/// an operator's consent is the failure mode, not a missing value.
#[test]
fn the_pii_bearing_fields_are_absent_until_the_operator_opts_in() {
    let context = context_with_auth(AuthSource::None);
    let default = ClientFingerprint::detect(&context, &FingerprintEnv::default());
    assert_eq!(default.host_label(), None);
    assert_eq!(default.reported_ip(), None);
    assert!(
        !default.render().contains("host="),
        "an undisclosed host label must be omitted, not rendered blank: {}",
        default.render()
    );

    let disclosed = ClientFingerprint::detect(
        &context,
        &FingerprintEnv {
            host_label: Some("ci-runner-7".to_string()),
            reported_ip: Some("10.4.2.9".to_string()),
        },
    );
    assert_eq!(disclosed.host_label(), Some("ci-runner-7"));
    assert!(disclosed.render().contains("host=ci-runner-7"));
}

/// Pins: [`ClientFingerprint::render`]'s `continue` on `client_reported_ip`,
/// and the separate [`CLIENT_REPORTED_IP_HEADER`].
///
/// Catches: folding the client-asserted address into the fingerprint blob. The
/// owner's rule is that a client-reported address is never merged with the
/// authoritative one; a fingerprint blob is exactly where such a merge would
/// become invisible, because a sink stores the blob as one value.
#[test]
fn the_client_reported_ip_never_rides_inside_the_fingerprint_blob() {
    let identity = ClientActionIdentity {
        action_id: ActionId::mint().expect("mint"),
        fingerprint: ClientFingerprint::detect(
            &context_with_auth(AuthSource::None),
            &FingerprintEnv {
                host_label: None,
                reported_ip: Some("10.4.2.9".to_string()),
            },
        ),
        clock: ClientClockReading::from_unix_seconds(1_800_000_000),
        server_time: Arc::new(Mutex::new(None)),
    };
    let headers = identity.headers();
    let fingerprint = headers
        .iter()
        .find(|(name, _)| name == CLIENT_FINGERPRINT_HEADER)
        .map(|(_, value)| value.clone())
        .expect("the fingerprint header is unconditional");
    assert!(
        !fingerprint.contains("10.4.2.9"),
        "the client-asserted address must not be inside the fingerprint value: {fingerprint}"
    );
    assert_eq!(
        headers
            .iter()
            .find(|(name, _)| name == CLIENT_REPORTED_IP_HEADER)
            .map(|(_, value)| value.as_str()),
        Some("10.4.2.9"),
        "it rides its own header, whose NAME says it is client-reported"
    );
}

/// Pins: [`sanitize_header_value`]'s filter set.
///
/// Catches: dropping the filter (a `\r\n` in an operator-supplied label would
/// then split the header and let a value forge `x-ferrogate-action-id`), and
/// dropping `';'` (which would let a label forge extra fingerprint segments —
/// `host=a;cred=none` reading back as two fields).
#[test]
fn an_operator_supplied_label_cannot_forge_a_header_or_a_field() {
    let fingerprint = ClientFingerprint::detect(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv {
            host_label: Some("box\r\nx-ferrogate-action-id: fgact_evil;cred=none".to_string()),
            reported_ip: None,
        },
    );
    let rendered = fingerprint.render();
    assert!(!rendered.contains('\r') && !rendered.contains('\n'));
    assert_eq!(
        rendered.matches("cred=").count(),
        1,
        "a label must not be able to inject a second field: {rendered}"
    );
}

/// Pins: the action-id binding check at the top of
/// [`ServerIssuedTime::accept_for`].
///
/// Catches: deleting that check, or weakening `!=` to a prefix/`contains`
/// comparison. Either would let a token minted for one action be replayed onto
/// another — the exact move the binding exists to stop, and the one refusal the
/// client can make without trusting a clock.
#[test]
fn a_time_token_issued_for_another_action_is_refused() {
    let mine = ActionId::mint().expect("mint");
    let theirs = ActionId::mint().expect("mint");
    let raw = format!("v1;issued_at=1800000000;ttl=30;action_id={theirs};sig=abc");
    let refusal = ServerIssuedTime::parse(&raw)
        .expect("parses")
        .accept_for(&mine, &ClientClockReading::from_unix_seconds(1_800_000_010))
        .expect_err("a token bound to another action must be refused");
    assert_eq!(refusal.code(), "time_token_action_id_mismatch");

    // The mirror case must still be accepted, or the assertion above would pass
    // on an `accept_for` that refuses everything.
    let raw = format!("v1;issued_at=1800000000;ttl=30;action_id={mine};sig=abc");
    let accepted = ServerIssuedTime::parse(&raw)
        .expect("parses")
        .accept_for(&mine, &ClientClockReading::from_unix_seconds(1_800_000_010))
        .expect("a token bound to THIS action inside its TTL is accepted");
    assert_eq!(accepted.bound_action_id(), mine.as_str());
}

/// Pins: both halves of the TTL window check in
/// [`ServerIssuedTime::accept_for`] — `now > expires_at` and
/// `now < issued_at`.
///
/// Catches: deleting the upper bound (the expired case is then accepted, which
/// is what lets an attacker pre-fetch tokens and backdate an action); deleting
/// the lower bound (a pre-dated token is accepted); and an off-by-one that
/// turns `>` into `>=` (the exactly-at-the-boundary case reds).
#[test]
fn a_time_token_outside_its_window_is_refused_at_both_ends() {
    let action = ActionId::mint().expect("mint");
    let token = |now: u64| {
        ServerIssuedTime::parse(&format!(
            "v1;issued_at=1800000000;ttl=30;action_id={action};sig=abc"
        ))
        .expect("parses")
        .accept_for(&action, &ClientClockReading::from_unix_seconds(now))
    };
    assert_eq!(
        token(1_800_000_031)
            .expect_err("one second past the window is outside it")
            .code(),
        "time_token_expired"
    );
    assert_eq!(
        token(1_799_999_999)
            .expect_err("a token from the future is as suspect as an expired one")
            .code(),
        "time_token_expired"
    );
    // The boundaries themselves are inside the window; without these two the
    // assertions above would also pass on an `accept_for` that refuses every
    // token it is ever handed.
    assert!(
        token(1_800_000_000).is_ok(),
        "issued_at is inside the window"
    );
    assert!(
        token(1_800_000_030).is_ok(),
        "issued_at + ttl is inside the window"
    );
}

/// Pins: [`ServerIssuedTime::parse`]'s required fields — the schema marker, a
/// numeric `issued_at`, a numeric `ttl`, a non-empty `action_id`, and a
/// non-empty `sig`.
///
/// Catches: making `sig` optional, which would let a token stripped of its
/// signature be accepted as an unsigned claim; and dropping the schema check,
/// which would have a future `v2` token silently mis-parsed as `v1`.
#[test]
fn a_malformed_time_token_is_refused_field_by_field() {
    let complete = "v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=abc";
    assert!(ServerIssuedTime::parse(complete).is_ok());
    for (label, raw) in [
        ("wrong schema", "v2;issued_at=1;ttl=30;action_id=a;sig=abc"),
        ("no issued_at", "v1;ttl=30;action_id=a;sig=abc"),
        (
            "non-numeric issued_at",
            "v1;issued_at=soon;ttl=30;action_id=a;sig=abc",
        ),
        ("no ttl", "v1;issued_at=1;action_id=a;sig=abc"),
        ("no action_id", "v1;issued_at=1;ttl=30;sig=abc"),
        (
            "empty action_id",
            "v1;issued_at=1;ttl=30;action_id=;sig=abc",
        ),
        ("no sig", "v1;issued_at=1;ttl=30;action_id=a"),
        ("empty sig", "v1;issued_at=1;ttl=30;action_id=a;sig="),
        ("not key=value", "v1;issued_at=1;ttl=30;action_id=a;abc"),
    ] {
        assert_eq!(
            ServerIssuedTime::parse(raw)
                .expect_err(&format!("'{label}' must be refused"))
                .code(),
            "time_token_malformed",
            "'{label}' was accepted: {raw}"
        );
    }
    // An unknown segment is forward-compatible, not malformed.
    assert!(ServerIssuedTime::parse(&format!("{complete};region=eu")).is_ok());
}

/// Pins: [`ClientActionIdentity::accept_server_time`] storing only an accepted
/// token, and [`ClientActionIdentity::headers`] emitting
/// [`TIME_TOKEN_HEADER`] only when one is held.
///
/// Catches: storing the token before validating it (the refused-token case
/// would then leave a foreign instant in the slot and the `None` assertion
/// reds), and emitting the header unconditionally (the no-token assertion
/// reds, which is what would let an empty header be read as an instant).
#[test]
fn only_an_accepted_token_is_held_and_only_a_held_token_is_sent() {
    let identity = ClientActionIdentity::mint(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv::default(),
    )
    .expect("mint");
    assert!(identity.server_issued_time().is_none());
    assert!(
        !identity
            .headers()
            .iter()
            .any(|(name, _)| name == TIME_TOKEN_HEADER),
        "with no token held, the header must be absent rather than empty"
    );

    let foreign = ActionId::mint().expect("mint");
    identity
        .accept_server_time(&format!(
            "v1;issued_at={};ttl=30;action_id={foreign};sig=abc",
            identity.client_clock().unverified_unix_seconds()
        ))
        .expect_err("a token bound to another action is refused");
    assert!(
        identity.server_issued_time().is_none(),
        "a refused token must not be stored"
    );

    let issued_at = identity.client_clock().unverified_unix_seconds();
    identity
        .accept_server_time(&format!(
            "v1;issued_at={issued_at};ttl=300;action_id={};sig=abc",
            identity.action_id()
        ))
        .expect("a token bound to this action inside its TTL is accepted");
    let held = identity.server_issued_time().expect("token is held");
    assert_eq!(held.issued_at_unix(), issued_at);
    assert_eq!(
        identity
            .headers()
            .iter()
            .find(|(name, _)| name == TIME_TOKEN_HEADER)
            .map(|(_, value)| value.clone()),
        Some(held.render()),
        "a held token is echoed verbatim on the next request of this action"
    );
}

/// Pins: the `Arc` in [`ClientActionIdentity`]'s `server_time` field.
///
/// Catches: replacing it with a plain `Mutex` (or cloning the held value into
/// an independent slot). The transport holds one clone and the mutation plan
/// another; without shared state the receipt would report `client_sent_at:
/// null` on a request that in fact carried an instant — a silent divergence
/// between what was sent and what was recorded.
#[test]
fn every_clone_of_an_identity_is_the_same_action() {
    let identity = ClientActionIdentity::mint(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv::default(),
    )
    .expect("mint");
    let held_by_transport = identity.clone();
    assert_eq!(
        held_by_transport.action_id().as_str(),
        identity.action_id().as_str()
    );
    let issued_at = identity.client_clock().unverified_unix_seconds();
    held_by_transport
        .accept_server_time(&format!(
            "v1;issued_at={issued_at};ttl=300;action_id={};sig=abc",
            identity.action_id()
        ))
        .expect("accepted");
    assert!(
        identity.server_issued_time().is_some(),
        "a token harvested by one clone must be visible to the other, or the receipt would \
         report an instant the request did not carry"
    );
}

/// Pins: [`ClientActionIdentity::headers`]'s three unconditional entries and
/// the `-unverified` suffix on [`CLIENT_CLOCK_HEADER`].
///
/// Catches: renaming the clock header to `x-ferrogate-client-timestamp` — the
/// rename the issue explicitly forbids, because the suffix is the one word
/// standing between an untrusted reading and a sink that stores it as the event
/// time; and dropping any of the three unconditional headers.
#[test]
fn the_unconditional_headers_are_present_and_the_clock_header_says_it_is_unverified() {
    let identity = ClientActionIdentity::mint(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv::default(),
    )
    .expect("mint");
    let headers = identity.headers();
    let value = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(
        value(ACTION_ID_HEADER).as_deref(),
        Some(identity.action_id().as_str())
    );
    assert_eq!(
        value(CLIENT_FINGERPRINT_HEADER),
        Some(identity.fingerprint().render())
    );
    assert_eq!(
        value(CLIENT_CLOCK_HEADER),
        Some(
            identity
                .client_clock()
                .unverified_unix_seconds()
                .to_string()
        )
    );
    assert!(
        CLIENT_CLOCK_HEADER.ends_with("-unverified"),
        "the client's own clock travels under a name that says so; renaming it to \
         'x-ferrogate-client-timestamp' is exactly the mistake issue #548 forbids"
    );
    assert_ne!(
        CLIENT_CLOCK_HEADER, TIME_TOKEN_HEADER,
        "the two instants are two authorities and never share a field"
    );
}

/// Pins: `ClientClockReading::read_local_clock` being the sole `SystemTime::now()`
/// in the audit path.
///
/// Catches: the acceptance criterion's named defect — `SystemTime::now()`
/// reaching `client_sent_at`. Any of these mutations reds it: filling
/// `client_sent_at` from the clock in `receipt.rs`; stamping a request in
/// `prepare_request`; adding a `ServerIssuedTime::now()` constructor. No value
/// assertion can catch those, because each produces a plausible number.
///
/// Comment lines are stripped before the scan: this crate documents the rule in
/// prose that quotes the call, and a guard that could be defeated (or falsely
/// tripped) by a doc comment is not a guard.
#[test]
fn the_only_local_clock_read_in_the_audit_path_is_the_one_named_for_it() {
    const AUDIT_PATH: [(&str, &str); 3] = [
        ("action_identity.rs", include_str!("action_identity.rs")),
        ("transport.rs", include_str!("transport.rs")),
        ("receipt.rs", include_str!("receipt.rs")),
    ];
    let mut reads: Vec<(&str, String)> = Vec::new();
    for (name, source) in AUDIT_PATH {
        let mut enclosing = String::from("<file scope>");
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("fn "))
                .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
            {
                enclosing = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("<unnamed>")
                    .to_string();
            }
            if line.contains("SystemTime::now()") || line.contains("Instant::now()") {
                reads.push((name, enclosing.clone()));
            }
        }
    }
    assert_eq!(
        reads,
        vec![("action_identity.rs", "read_local_clock".to_string())],
        "the audit path reads the local clock in exactly one place, named for what it does. \
         Anything else is the defect issue #548's acceptance list names: a client clock \
         reaching the audit timestamp, where it would look like a perfectly plausible instant"
    );
}
