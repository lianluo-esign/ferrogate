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
//!   on the token's decimal-byte spelling **crossed with** its truncated
//!   prefixes, for `Inline` *and* `Env` credentials, with a positive shape
//!   assertion so an impl that drops every field is not silently accepted.
//! * [`the_headers_sent_are_exactly_the_reviewed_set_in_every_shape`] — the
//!   wire-side twin of the field-set tripwire. Every other assertion here looks
//!   a header up by name, so nothing else reds when a header is *added*.
//! * [`a_non_ascii_context_name_or_label_still_produces_a_sendable_header`] —
//!   asserted on the **output byte range** and on a hand-computed literal, not
//!   on `http::HeaderValue::try_from`. `try_from` reads like the real predicate
//!   and is not one: `http` 1.4.0 accepts 0x80–0xFF, so the version of this test
//!   that rested on it stayed green under the mutation it was written to catch.
//!   The predicate that really refuses is `ferrogate-cli`'s
//!   `render_header_block`, one crate to the right, and its range is what is
//!   asserted here.
//! * [`a_time_token_outside_its_window_is_refused_at_both_ends`] — its fixtures
//!   deliberately do **not** tie the server's `issued_at` to the client's frozen
//!   reading. Tying them together is what hid a check that dropped every token
//!   under any positive clock skew.

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

/// Every spelling of a leak this suite refuses, for one candidate string:
/// verbatim, the 4/8/16-character prefixes an offline guesser wants, and the
/// decimal-byte rendering a **derived** `Debug` produces for a `Vec<u8>`.
///
/// The two axes are crossed rather than run separately. Checking plaintext for
/// prefixes and decimal bytes only for the whole secret leaves a hole exactly
/// the width of a truncated `Vec<u8>` behind a derived `Debug` — a 16-byte key
/// id, the single most likely shape for a "safe" credential handle to take —
/// which matches neither axis alone.
fn leak_spellings(secret: &str) -> Vec<(String, String)> {
    let mut spellings = vec![
        ("the bearer token verbatim".to_string(), secret.to_string()),
        (
            "the token's decimal-byte spelling (what a DERIVED Debug prints for a Vec<u8>)"
                .to_string(),
            decimal_bytes(secret),
        ),
    ];
    for prefix_len in [4usize, 8, 16] {
        let prefix = &secret[..prefix_len];
        spellings.push((
            format!("a {prefix_len}-character prefix of the bearer token"),
            prefix.to_string(),
        ));
        spellings.push((
            format!(
                "a {prefix_len}-byte prefix of the bearer token in decimal bytes (a truncated \
                 key id behind a derived Debug)"
            ),
            decimal_bytes(prefix),
        ));
    }
    spellings
}

/// Assert that none of [`leak_spellings`] appears in `haystack`.
fn assert_no_leak(label: &str, haystack: &str, secret: &str) {
    for (spelling, needle) in leak_spellings(secret) {
        assert!(
            !haystack.contains(&needle),
            "{label} carries {spelling}, which is an offline-guessing oracle: {haystack}"
        );
    }
}

/// The `;`-delimited segments of a rendered fingerprint whose key is `key`.
///
/// Counting raw `"cred="` substrings across the whole blob is *not* the same
/// question and was the bug in this file's first cut: it counts text that a
/// parser would never read as a field, so it reds on correct code the moment an
/// operator-supplied value happens to contain the characters. A parser splits on
/// `;` and then on the first `=`; so does this.
fn segments_named<'a>(rendered: &'a str, key: &str) -> Vec<&'a str> {
    rendered
        .split(';')
        .filter_map(|segment| segment.split_once('='))
        .filter(|(name, _)| *name == key)
        .map(|(_, value)| value)
        .collect()
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
/// rather than the token, and the hand-written `Debug`, for **every credential
/// source that can hold material** — `Inline`, which carries the token in the
/// variant, and `Env`, which names a variable whose *value* is the token.
///
/// Catches: `credential_source: token.clone()` in `detect` (the `Inline`
/// plaintext assertion reds); the `Env` special case the earlier cut of this
/// test could not see — `AuthSource::Env { var } => std::env::var(var).unwrap_or_default()`,
/// which puts the token in the header on the credential source this repo's own
/// auth docs call the recommended default for scripting (the `Env` block reds);
/// storing a prefix or a truncated key id (the 4/8/16-prefix assertions red);
/// replacing the hand-written `Debug` with a derive **and** adding a byte-vector
/// field (the decimal-byte assertions red — a derived `Debug` prints
/// `[122, 113, 120, …]`, which a plaintext-only check misses), including for a
/// *truncated* byte vector, which neither axis caught alone.
/// The positive-shape assertion catches the mirror mutation: an impl that
/// simply drops every field would satisfy every absence check.
#[test]
fn the_fingerprint_never_carries_the_token_it_was_built_from() {
    // A variable name no other test uses, so the two credential shapes below
    // cannot interfere with a parallel test through the process environment.
    const TOKEN_VAR: &str = "FERROGATE_TOKEN_FOR_THE_548_LEAK_GUARD";
    std::env::set_var(TOKEN_VAR, SECRET);

    for (source_label, auth, expected_cred) in [
        (
            "inline",
            AuthSource::Inline {
                token: SECRET.to_string(),
            },
            "cred=inline".to_string(),
        ),
        (
            "env",
            AuthSource::Env {
                var: TOKEN_VAR.to_string(),
            },
            format!("cred=env:{TOKEN_VAR}"),
        ),
    ] {
        let context = context_with_auth(auth);
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

        for (surface, haystack) in [
            ("rendered fingerprint", &rendered),
            ("fingerprint Debug", &debug),
            ("sent headers", &headers),
            ("identity Debug", &identity_debug),
        ] {
            assert_no_leak(&format!("[{source_label}] {surface}"), haystack, SECRET);
        }

        // Positive shape: an impl that drops every field would pass every
        // absence check above, so the fields that MUST be there are asserted.
        assert!(rendered.starts_with(IDENTITY_SCHEMA_VERSION));
        assert!(rendered.contains(&format!("cli={}", crate::version::CLI_VERSION)));
        assert!(rendered.contains(&format!("os={}", std::env::consts::OS)));
        assert!(rendered.contains(&format!("arch={}", std::env::consts::ARCH)));
        assert!(rendered.contains("context=prod-eu"));
        assert!(
            rendered.contains(&expected_cred),
            "[{source_label}] the credential SOURCE is what the fingerprint carries, and \
             dropping it would make the absence assertions above vacuous: {rendered}"
        );
    }

    std::env::remove_var(TOKEN_VAR);
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

/// Pins: [`encode_header_value`]'s escape set — CR, LF, `;`, `=` and every
/// control character.
///
/// Catches: dropping CR/LF (a `\r\n` in an operator-supplied label splits the
/// header and forges `x-ferrogate-action-id`; there is no `http::HeaderValue`
/// between this string and the socket on the `assets`/`plans` path), and
/// dropping `;`/`=` (which lets a label forge extra fingerprint segments —
/// `host=a;cred=none` reading back as two fields).
///
/// The assertion counts `;`-delimited **segments named `cred`**, not raw
/// `"cred="` substrings. That distinction is the whole reason this test was
/// rewritten: the previous cut asserted `rendered.matches("cred=").count() == 1`
/// against a sanitizer that *deleted* the offending characters, and deletion
/// welded the label's own `;cred=none` onto the text in front of it — leaving a
/// literal `cred=` inside the host segment that no parser would ever read as a
/// field. The count was 2, the assertion demanded 1, and the test reded on
/// correct code, deterministically, on the first run.
#[test]
fn an_operator_supplied_label_cannot_forge_a_header_or_a_field() {
    let hostile = "box\r\nx-ferrogate-action-id: fgact_evil;cred=none";
    let fingerprint = ClientFingerprint::detect(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv {
            host_label: Some(hostile.to_string()),
            reported_ip: None,
        },
    );
    let rendered = fingerprint.render();

    assert!(
        !rendered.contains('\r') && !rendered.contains('\n'),
        "a CR or LF in the value splits the header: {rendered}"
    );
    assert_eq!(
        segments_named(&rendered, "cred"),
        vec!["none"],
        "a label must not be able to inject a second field: {rendered}"
    );
    assert_eq!(
        segments_named(&rendered, "host").len(),
        1,
        "the label occupies exactly one segment however hostile it is: {rendered}"
    );
    assert_eq!(
        segments_named(&rendered, "x-ferrogate-action-id"),
        Vec::<&str>::new(),
        "the label must not be able to name a header, let alone the action id: {rendered}"
    );
    // Lossless, not lossy: the operator's own text is still recoverable. Without
    // this the whole assertion set would also pass on an encoder that threw the
    // label away, which is the mutation that quietly deletes evidence.
    assert_eq!(
        segments_named(&rendered, "host"),
        vec!["box%0D%0Ax-ferrogate-action-id:%20fgact_evil%3Bcred%3Dnone"],
        "the escaped label is the operator's text, percent-decodable back to it: {rendered}"
    );
}

/// A context name or host label outside ASCII must not brick the CLI.
///
/// Pins: `action_identity.rs` routing every byte outside
/// [`is_header_value_safe`] through percent encoding. That predicate, not a
/// redundant `byte.is_ascii()` precheck, closes the output to visible ASCII.
///
/// Catches: widening [`is_header_value_safe`] to admit a non-ASCII byte or
/// emitting an unsafe character directly. Either re-arms the defect this test
/// is named for: `ferrogate-cli`'s `render_header_block` refuses any character
/// outside `0x20..=0x7E`. Named contexts break the typed path's visible-ASCII
/// contract; the raw `assets`/`plans` path has no named context, but the same
/// encoder protects its reachable host-label and reported-address inputs.
///
/// # Why the assertion is not `HeaderValue::try_from(..).is_ok()`
///
/// It used to be, with a doc claiming `TryFrom<&str>` "rejects every byte
/// outside `32..=126`". Both are withdrawn. The pinned `http` is 1.4.0 and its
/// validator is `b >= 32 && b != 127 || b == b'\t'`, which **accepts**
/// 0x80–0xFF; `is_visible_ascii` is reached only from `from_static`, `to_str`
/// and `Debug`, and `transport.rs` passes a `&String`, selecting `from_bytes`,
/// which is more permissive still. So `try_from(..).is_ok()` survives the
/// mutation above — as do a `== encode_header_value(..)` comparison, which is a
/// tautology through the mutated function, and a length floor, because raw UTF-8
/// is *longer* than the character count it is compared against.
///
/// What replaces it discriminates by construction: the byte range is asserted
/// directly (the idiom `assets_cli_test.rs` already uses at the other
/// chokepoint), and the escaped spellings are **literals** no mutated encoder
/// can restate. Once the byte-range assertion passes, constructing and reading
/// an `http::HeaderValue` would only reassert a weaker predicate.
#[test]
fn a_non_ascii_context_name_or_label_still_produces_a_sendable_header() {
    // A literal, computed by hand from UTF-8, so it cannot be restated by
    // whatever `encode_header_value` currently does. `生` is E7 94 9F and `产`
    // is E4 BA A7.
    assert_eq!(
        encode_header_value("生产"),
        "%E7%94%9F%E4%BA%A7",
        "the escaped spelling of a Chinese context name is fixed, byte for byte"
    );
    assert_eq!(
        encode_header_value("prod-café"),
        "prod-caf%C3%A9",
        "one non-ASCII scalar inside an otherwise safe label escapes to its two UTF-8 bytes"
    );
    assert_eq!(
        encode_header_value("~/"),
        "~/",
        "the two reviewed visible-ASCII boundary characters remain readable"
    );
    assert_eq!(
        encode_header_value("\u{7e}\u{7f}"),
        "~%7F",
        "0x7E is the inclusive safe boundary and 0x7F is encoded"
    );

    for (label, context_name, host_label, reported_ip) in [
        ("chinese context", "生产", None, None),
        ("accented context", "prod-café", None, None),
        ("emoji host label", "prod-eu", Some("🚀-runner"), None),
        ("cyrillic host label", "prod-eu", Some("сервер-1"), None),
        (
            "del and high-ascii",
            "prod-eu",
            Some("a\u{7f}b\u{80}c"),
            None,
        ),
        // The reported IP rides its own header and goes through the same
        // encoder. Every other test in this file passes `10.4.2.9`, which is a
        // fixed point of the encoder and therefore holds nothing (#548 review,
        // minor 12).
        (
            "hostile reported ip",
            "prod-eu",
            None,
            Some("203.0.113.9\r\nx-ferrogate-action-id: fgact_evil"),
        ),
        ("non-ascii reported ip", "prod-eu", None, Some("сервер")),
    ] {
        let mut context = context_with_auth(AuthSource::None);
        context.context_name = Some(context_name.to_string());
        let fingerprint = ClientFingerprint::detect(
            &context,
            &FingerprintEnv {
                host_label: host_label.map(str::to_string),
                reported_ip: reported_ip.map(str::to_string),
            },
        );
        let rendered = fingerprint.render();
        let identity = ClientActionIdentity {
            action_id: ActionId::mint().expect("mint"),
            fingerprint,
            clock: ClientClockReading::from_unix_seconds(1_800_000_000),
            server_time: Arc::new(Mutex::new(None)),
        };
        for (name, value) in identity.headers() {
            // The discriminating assertion. `render_header_block` on the
            // raw-TCP path applies exactly this range and *refuses* — so a byte
            // outside it is not a cosmetic problem, it is seven verbs that stop
            // working.
            if let Some(offending) = value.bytes().find(|byte| !(0x20..=0x7E).contains(byte)) {
                panic!(
                    "[{label}] '{name}: {value}' carries byte {offending:#04X}, outside \
                     0x20..=0x7E. ferrogate-cli's render_header_block refuses this and every \
                     `assets`/`plans` request bails; on the reqwest path it leaves as RFC 9110 \
                     obs-text, which an intermediary may drop or reinterpret"
                );
            }
        }
        // And it is escaped, not discarded: an encoder that dropped every
        // non-ASCII byte would satisfy the assertions above while silently
        // erasing which context an action was taken in.
        let context_segment = segments_named(&rendered, "context");
        assert_eq!(
            context_segment,
            vec![encode_header_value(context_name)],
            "[{label}] the context name must survive as escaped text, not be deleted: {rendered}"
        );
        assert!(
            context_segment[0].len() >= context_name.chars().count(),
            "[{label}] an escaped name is never shorter than the characters it encodes: \
             {rendered}"
        );
    }
}

/// Percent-decoding a fingerprint value returns the operator's own text.
///
/// Pins: `'%'` being **absent** from `is_header_value_safe`'s allow-list, which
/// is what makes [`encode_header_value`] injective.
///
/// Catches: adding `'%'` to that set. Nothing else in this file contains a `%`
/// in an *input*, so today every `%` in an output is one the encoder wrote and
/// the escape is unpinned. With `'%'` safe, an operator label of `%3B` is
/// carried through unchanged and every audit consumer that percent-decodes the
/// blob — which the module docs promise it may — reads back a `;`, the
/// fingerprint's own delimiter. That is the forgery
/// `an_operator_supplied_label_cannot_forge_a_header_or_a_field` prevents,
/// reintroduced one layer down where that test cannot see it.
#[test]
fn an_operator_label_that_already_looks_escaped_is_escaped_again() {
    assert_eq!(
        encode_header_value("%3B"),
        "%253B",
        "a literal percent must become %25 or the encoding is not injective"
    );
    assert_eq!(
        encode_header_value("100%"),
        "100%25",
        "a trailing percent is escaped too"
    );

    let fingerprint = ClientFingerprint::detect(
        &context_with_auth(AuthSource::None),
        &FingerprintEnv {
            host_label: Some("%3Bcred%3Devil".to_string()),
            reported_ip: None,
        },
    );
    let rendered = fingerprint.render();
    assert_eq!(
        segments_named(&rendered, "host"),
        vec!["%253Bcred%253Devil"],
        "an already-escaped-looking label decodes back to itself, not to a delimiter: {rendered}"
    );
    assert_eq!(
        segments_named(&rendered, "cred"),
        vec!["none"],
        "and it cannot become a second cred field after one decode pass: {rendered}"
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
/// [`ServerIssuedTime::accept_for`], **and**
/// [`CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS`] being applied to each.
///
/// Catches: deleting the upper bound (the day-stale case is then accepted,
/// which is what lets an attacker pre-fetch tokens and backdate an action);
/// deleting the lower bound (a token pre-dated by a year is accepted); an
/// off-by-one that turns `>` into `>=` (the exactly-at-the-boundary cases red);
/// and — the reason this test was rewritten — **setting the allowance back to
/// zero**, which the `one second after the frozen reading` case reds.
///
/// That last one is not hypothetical, it is the defect this slice shipped with.
/// The reading is taken once at [`ClientActionIdentity::mint`] and frozen, so a
/// token the server issues one second into the invocation has
/// `issued_at > now`; a bare `now < issued_at` check called it "from the
/// future" and dropped it, silently, to stderr. It dropped every token under
/// any positive server-minus-client skew and every invocation that crossed a
/// second boundary — which is to say it dropped the feature. The four fixtures
/// in the original test all built the token with
/// `issued_at = identity.client_clock().unverified_unix_seconds()`, exactly the
/// frozen value, so none of them could see it.
#[test]
fn a_time_token_outside_its_window_is_refused_at_both_ends() {
    const MINTED_AT: u64 = 1_800_000_000;
    const TTL: u64 = 30;
    let action = ActionId::mint().expect("mint");
    // `issued_at` is the SERVER's instant and `now` the client's frozen reading;
    // the two are deliberately independent here, because a fixture that ties
    // them together is what hid the defect.
    let token = |issued_at: u64, now: u64| {
        ServerIssuedTime::parse(&format!(
            "v1;issued_at={issued_at};ttl={TTL};action_id={action};sig=abc"
        ))
        .expect("parses")
        .accept_for(&action, &ClientClockReading::from_unix_seconds(now))
    };

    // The regression case. Everything else in this test would pass with the
    // allowance set to zero; this is the assertion that would not.
    assert!(
        token(MINTED_AT + 1, MINTED_AT).is_ok(),
        "a token the server issued one second after this process read its clock is the NORMAL \
         case, not a token from the future"
    );
    assert!(
        token(MINTED_AT + CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS, MINTED_AT).is_ok(),
        "skew up to the full allowance is tolerated"
    );
    assert!(
        token(
            MINTED_AT,
            MINTED_AT + TTL + CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS
        )
        .is_ok(),
        "the far edge of the widened window is inside it"
    );
    assert!(
        token(MINTED_AT, MINTED_AT).is_ok(),
        "issued_at is inside the window"
    );

    // Both ends still refuse, one second past the widened boundary.
    assert_eq!(
        token(
            MINTED_AT,
            MINTED_AT + TTL + CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS + 1
        )
        .expect_err("one second past the widened window is outside it")
        .code(),
        "time_token_expired"
    );
    assert_eq!(
        token(
            MINTED_AT + CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS + 1,
            MINTED_AT
        )
        .expect_err("a token pre-dated by more than the allowance is still refused")
        .code(),
        "time_token_expired"
    );
    // The absurd cases the courtesy check exists for at all.
    assert_eq!(
        token(MINTED_AT, MINTED_AT + 86_400)
            .expect_err("a day-stale token is refused")
            .code(),
        "time_token_expired"
    );
    assert_eq!(
        token(MINTED_AT + 86_400, MINTED_AT)
            .expect_err("a token dated a day ahead is refused")
            .code(),
        "time_token_expired"
    );
}

/// Pins: [`ServerIssuedTime::render`] returning the stored raw token rather
/// than re-rendering the four parsed fields.
///
/// Catches: reconstructing the string with
/// `format!("v1;issued_at={};ttl={};action_id={};sig={}", …)`. That looks
/// equivalent and is not: [`ServerIssuedTime::parse`] tolerates unknown segments
/// on purpose, so the first forward-compatible field a server adds is dropped by
/// the reconstruction — a different byte string, over which the server's own
/// `sig` no longer verifies, silently invalidating every echoed token. The
/// OpenAPI description and this method's own doc both say "echoed verbatim";
/// nothing held them to it.
#[test]
fn a_time_token_is_echoed_byte_for_byte_including_fields_this_client_does_not_know() {
    let action = ActionId::mint().expect("mint");
    let forward_compatible =
        format!("v1;issued_at=1800000000;ttl=30;action_id={action};sig=abc;region=eu;nonce=7");
    let parsed = ServerIssuedTime::parse(&forward_compatible).expect("unknown segments are fine");
    assert_eq!(
        parsed.render(),
        forward_compatible,
        "the echoed token must be the bytes the server sent, unknown segments included"
    );
    // Positive shape: the known fields are still parsed out, so a `render` that
    // simply stored the string and parsed nothing would not pass.
    assert_eq!(parsed.issued_at_unix(), 1_800_000_000);
    assert_eq!(parsed.ttl_seconds(), 30);
    assert_eq!(parsed.bound_action_id(), action.as_str());
}

/// Pins: the printable-ASCII guard at the top of [`ServerIssuedTime::parse`].
///
/// Catches: deleting it. A token is echoed back onto the wire verbatim, and on
/// the `assets`/`plans` path it is written into a socket with no
/// `http::HeaderValue` in between — so a server (or an intermediary) that
/// answered with a `\r\n` inside the token would have this client splice a
/// header of its choosing into the *next* request of the same action.
#[test]
fn a_time_token_carrying_bytes_no_header_may_hold_is_refused() {
    for (label, raw) in [
        (
            "CRLF request splitting",
            "v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=a\r\nx-ferrogate-tenant: org_evil",
        ),
        (
            "bare newline",
            "v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=a\nb",
        ),
        (
            "NUL",
            "v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=a\0b",
        ),
        (
            "non-ASCII",
            "v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=a生b",
        ),
    ] {
        assert_eq!(
            ServerIssuedTime::parse(raw)
                .expect_err(&format!("'{label}' must be refused"))
                .code(),
            "time_token_malformed",
            "'{label}' was accepted"
        );
    }
    // The mirror: a token made only of printable ASCII still parses, so the
    // guard above cannot be satisfied by refusing everything.
    assert!(
        ServerIssuedTime::parse("v1;issued_at=1800000000;ttl=30;action_id=fgact_x;sig=abc").is_ok()
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

/// The header **set** — not just "these names are present" — in each of the
/// three shapes an invocation can be in.
///
/// Pins: the exact, ordered vector [`ClientActionIdentity::headers`] returns.
///
/// Catches: **adding** a header. Every other assertion in this file looks a
/// header up by name, so pushing `("x-ferrogate-client-username", env USER)`
/// onto that vector reds nothing — and `client_reported_ip` already proves that
/// a field can be declared in [`FINGERPRINT_FIELDS`], kept out of the blob, and
/// still be carried out-of-band on its own header. [`FINGERPRINT_FIELDS`] is a
/// tripwire for the blob; this is the tripwire for the wire. Removing a header
/// reds it too, from the other side.
///
/// The privacy decision is a set, so it is pinned as a set, in the same spirit
/// as `the_fingerprint_declares_exactly_the_reviewed_field_set`.
#[test]
fn the_headers_sent_are_exactly_the_reviewed_set_in_every_shape() {
    let identity_with = |reported_ip: Option<&str>| ClientActionIdentity {
        action_id: ActionId::mint().expect("mint"),
        fingerprint: ClientFingerprint::detect(
            &context_with_auth(AuthSource::None),
            &FingerprintEnv {
                host_label: None,
                reported_ip: reported_ip.map(str::to_string),
            },
        ),
        clock: ClientClockReading::from_unix_seconds(1_800_000_000),
        server_time: Arc::new(Mutex::new(None)),
    };
    let names = |identity: &ClientActionIdentity| -> Vec<String> {
        identity
            .headers()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    };

    let plain = identity_with(None);
    assert_eq!(
        names(&plain),
        vec![
            ACTION_ID_HEADER.to_string(),
            CLIENT_FINGERPRINT_HEADER.to_string(),
            CLIENT_CLOCK_HEADER.to_string(),
        ],
        "the default invocation discloses these three headers and nothing else"
    );

    let disclosed = identity_with(Some("10.4.2.9"));
    assert_eq!(
        names(&disclosed),
        vec![
            ACTION_ID_HEADER.to_string(),
            CLIENT_FINGERPRINT_HEADER.to_string(),
            CLIENT_CLOCK_HEADER.to_string(),
            CLIENT_REPORTED_IP_HEADER.to_string(),
        ],
        "opting in to a reported address adds exactly one header"
    );

    let with_token = identity_with(None);
    with_token
        .accept_server_time(&format!(
            "v1;issued_at=1800000000;ttl=300;action_id={};sig=abc",
            with_token.action_id()
        ))
        .expect("accepted");
    assert_eq!(
        names(&with_token),
        vec![
            ACTION_ID_HEADER.to_string(),
            CLIENT_FINGERPRINT_HEADER.to_string(),
            CLIENT_CLOCK_HEADER.to_string(),
            TIME_TOKEN_HEADER.to_string(),
        ],
        "holding a server time token adds exactly one header"
    );
}

/// Pins: `ClientClockReading::read_local_clock` being the sole wall-clock read
/// in the audit path.
///
/// Catches: a *new* clock read in this crate's audit path — stamping a request
/// in `prepare_request`, adding a `ServerIssuedTime::now()` constructor, timing
/// a call and folding the reading into a receipt. No value assertion can catch
/// those, because each produces a plausible number.
///
/// **What it does not catch, stated because an earlier revision of this doc
/// claimed it:** "filling `client_sent_at` from the clock in `receipt.rs`" is
/// only caught when the fill *takes a new reading*. The cheaper mutation
/// launders a reading that was already taken — `client_clock_unverified_unix`
/// is right there on the receipt — and adds no clock read at all. `receipt.rs`
/// says so at the `(true, None)` arm, and that statement is the correct one.
/// The guard for the laundering mutation is
/// `the_only_way_to_mint_a_client_sent_at_is_from_a_parsed_server_token` here,
/// and `no_ferrogate_cli_module_mints_a_client_sent_at` in `ferrogate-cli`.
///
/// The needle list is not one string. `UNIX_EPOCH.elapsed()` yields the
/// identical `u64` with no new dependency and never spells `now()`, and
/// `chrono::Utc::now()` is a zero-`Cargo.toml` bypass wherever chrono is already
/// a dependency; both are matched.
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
    const CLOCK_READS: [&str; 5] = [
        "SystemTime::now()",
        "Instant::now()",
        "Utc::now()",
        "Local::now()",
        "UNIX_EPOCH.elapsed()",
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
            if CLOCK_READS.iter().any(|needle| line.contains(needle)) {
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

/// The two opt-in variables are documented where an operator will actually
/// find them.
///
/// Pins: `docs/cli-audit-attribution.md` naming [`HOST_LABEL_ENV`] and
/// [`REPORTED_IP_ENV`], and explaining server issuance without granting the
/// client clock authority.
///
/// Catches: renaming either constant without updating the documentation, and
/// deleting the page. Neither variable is a clap flag, so
/// `docs/cli-reference.md` — which is generated from the command tree — can
/// never pick them up, and before this page they appeared in **no** `.md` file
/// in the repository: two operator-facing knobs, one of them controlling PII
/// disclosure, discoverable only by reading the source.
///
/// It also pins the "not honored today" statement, which is this repo's
/// established shape for a shipped-but-inert capability (`--tenant` carries
/// "NOT HONORED BY THE SERVER TODAY" in ten places plus an stderr notice). The
/// contract-side half is
/// `crate::transport_test::every_response_declares_the_server_time_token`,
/// which holds the shipped response-side contract.
#[test]
fn the_opt_in_variables_are_documented_where_an_operator_will_find_them() {
    const PAGE: &str = include_str!("../../../docs/cli-audit-attribution.md");
    let prose = PAGE.split_whitespace().collect::<Vec<_>>().join(" ");
    for needle in [
        HOST_LABEL_ENV,
        REPORTED_IP_ENV,
        ACTION_ID_HEADER,
        CLIENT_FINGERPRINT_HEADER,
        CLIENT_CLOCK_HEADER,
        TIME_TOKEN_HEADER,
        CLIENT_REPORTED_IP_HEADER,
    ] {
        assert!(
            PAGE.contains(needle),
            "'{needle}' is not documented in docs/cli-audit-attribution.md; it is not a clap \
             flag, so the generated cli-reference.md will never mention it either"
        );
    }
    assert!(prose.contains("server validates its HMAC signature"));
    assert!(prose.contains("server's own receive clock"));
    assert!(
        PAGE.contains(crate::receipt::absence_codes::NO_SERVER_TIME_TOKEN),
        "the page must name the absence code an operator will actually see on a receipt"
    );
    // The opt-in default is the privacy decision; a page that documented the
    // variables without saying they are off would misdescribe it.
    assert!(
        PAGE.contains("off by default"),
        "the page must say both variables are off by default"
    );
    // The header-stripping case. It is in this crate's module docs, which
    // satisfies the issue's literal wording and reaches nobody: the operator who
    // needs it is behind a corporate proxy and reads the `.md`.
    assert!(
        PAGE.contains("strip") || PAGE.contains("forward list"),
        "the page must tell an operator that an intermediary can drop these headers silently; \
         there is no fallback and no error, so an unattributed audit trail looks identical to a \
         CLI that never sent them"
    );

    // `include_str!` makes deleting this page a compile error. Nothing made
    // deleting the *links* to it fail anything, and a page nothing points at is
    // a page nobody finds.
    for (name, source) in [
        ("security-controls.md", SECURITY_CONTROLS),
        ("cli-migration.md", CLI_MIGRATION),
    ] {
        assert!(
            source.contains("cli-audit-attribution.md"),
            "{name} no longer links docs/cli-audit-attribution.md. That page documents two \
             operator-facing variables which are not clap flags, so nothing generated will ever \
             mention them; the inbound links are the only way an operator arrives"
        );
    }
}

/// The two inbound links pinned by
/// [`the_opt_in_variables_are_documented_where_an_operator_will_find_them`].
const SECURITY_CONTROLS: &str = include_str!("../../../docs/security-controls.md");
const CLI_MIGRATION: &str = include_str!("../../../docs/cli-migration.md");

/// The production reader of the two opt-in variables works.
///
/// Pins: [`FingerprintEnv::from_process`] reading [`HOST_LABEL_ENV`] and
/// [`REPORTED_IP_ENV`], trimming, and treating an empty value as unset.
///
/// Catches: `from_process` reading the wrong variable names, or dropping the
/// trim/empty filter so an exported-but-blank `FERROGATE_CLIENT_HOST_LABEL`
/// sends `host=` on every request. It had **zero** test callers before this:
/// every other test in this file injects a [`FingerprintEnv`] by hand, so the
/// one function the three real `mint` call sites actually use was unexercised,
/// and `the_pii_bearing_fields_are_absent_until_the_operator_opts_in` could not
/// have caught a `from_process` that auto-detected a hostname.
///
/// The variable names are deliberately unique to this test, and the process
/// environment is restored, because the whole crate's tests share one process.
#[test]
fn from_process_reads_the_two_opt_in_variables_and_nothing_else() {
    // Distinct from any other test's, so a parallel test cannot observe these.
    const HOST_VALUE: &str = "  ci-runner-548  ";
    let previous_host = std::env::var(HOST_LABEL_ENV).ok();
    let previous_ip = std::env::var(REPORTED_IP_ENV).ok();

    std::env::remove_var(HOST_LABEL_ENV);
    std::env::remove_var(REPORTED_IP_ENV);
    let unset = FingerprintEnv::from_process();
    assert_eq!(
        unset,
        FingerprintEnv::default(),
        "with neither variable set, from_process must disclose nothing — not a detected hostname \
         and not an empty string"
    );

    std::env::set_var(HOST_LABEL_ENV, HOST_VALUE);
    std::env::set_var(REPORTED_IP_ENV, "   ");
    let partial = FingerprintEnv::from_process();
    assert_eq!(
        partial.host_label.as_deref(),
        Some("ci-runner-548"),
        "the label is read from {HOST_LABEL_ENV} and trimmed"
    );
    assert_eq!(
        partial.reported_ip, None,
        "a whitespace-only value is unset, not a blank disclosure; `host=` or an empty reported \
         IP on every request would be a field the operator never chose to send"
    );

    // Restore, so nothing after this observes the fixture.
    match previous_host {
        Some(value) => std::env::set_var(HOST_LABEL_ENV, value),
        None => std::env::remove_var(HOST_LABEL_ENV),
    }
    match previous_ip {
        Some(value) => std::env::set_var(REPORTED_IP_ENV, value),
        None => std::env::remove_var(REPORTED_IP_ENV),
    }
}
