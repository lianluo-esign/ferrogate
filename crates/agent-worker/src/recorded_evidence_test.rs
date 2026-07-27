// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The shared recorded-evidence chokepoint (#526).
//!
//! #353 proved the REST family's excerpt does not leak. These tests pin the
//! properties that make that true for EVERY family — the ordering, the scope
//! split, and the metadata sweep — at the one place they are implemented, so a
//! family added later inherits proven behaviour instead of a copied fix.
//!
//! Every assertion here is on the RECORDED VALUE. None of them asserts that a
//! function was called or that a line of source exists.

use super::*;

/// A fake credential long enough that a surviving PREFIX would still be an
/// obvious leak. Nothing here is a real secret.
const FAKE_PROOF: &str = "FAKEPROOFDONOTLOG0123456789abcdefghijklmnopqrstuvwxyz\
                          FAKEPROOFDONOTLOG0123456789abcdefghijklmnopqrstuvwxyz";

// ---------------------------------------------------------------------------
// Ordering: redaction precedes truncation, in every excerpt helper
// ---------------------------------------------------------------------------

/// The byte-excerpt helper that every non-REST family now uses must redact
/// BEFORE it truncates. Truncating first leaves a `limit`-long prefix of the
/// credential in the record, which is not meaningfully safer than the whole
/// thing.
///
/// The credential is placed FIRST, exactly where a surviving prefix would land.
#[test]
fn recorded_excerpt_redacts_before_it_truncates() {
    let raw = format!("authorization: Bearer {FAKE_PROOF}\nbody line\n");

    let excerpt = recorded_excerpt(raw.as_bytes(), 64);

    assert!(excerpt.len() <= 64, "limit not honored: {excerpt:?}");
    // Not just the whole proof — no usable prefix of it either.
    for prefix_len in [8, 16, 32] {
        assert!(
            !excerpt.contains(&FAKE_PROOF[..prefix_len]),
            "a {prefix_len}-char credential prefix survived truncation: {excerpt:?}"
        );
    }
    assert!(
        excerpt.contains("authorization"),
        "the header NAME must survive so the record still shows a credential was present: \
         {excerpt:?}"
    );
}

/// Same ordering obligation for the line-oriented helper (microVM serial /
/// hypervisor logs). Cutting to `max_lines` first and redacting after would
/// still record the credential when it sits inside the kept lines.
#[test]
fn recorded_line_excerpt_redacts_before_it_cuts_lines() {
    let raw = format!("boot line\nauthorization: Bearer {FAKE_PROOF}\ntail line\n");

    let excerpt = recorded_line_excerpt(&raw, 2);

    assert!(!excerpt.contains(FAKE_PROOF), "{excerpt:?}");
    assert!(!excerpt.contains(&FAKE_PROOF[..8]), "{excerpt:?}");
    assert!(excerpt.starts_with("boot line"), "{excerpt:?}");
    assert!(
        !excerpt.contains("tail line"),
        "line cap not honored: {excerpt:?}"
    );
}

/// The REST helper keeps #353's contract verbatim: redact, then cap at
/// `char_limit` characters.
#[test]
fn recorded_http_excerpt_redacts_before_it_truncates() {
    let raw = format!("HTTP/1.1 200 OK\r\nPAYMENT-SIGNATURE: {FAKE_PROOF}\r\n\r\nbody");

    let excerpt = recorded_http_excerpt(&raw, 48);

    assert_eq!(
        excerpt.chars().count(),
        48,
        "char cap not honored: {excerpt:?}"
    );
    for prefix_len in [8, 16, 32] {
        assert!(
            !excerpt.contains(&FAKE_PROOF[..prefix_len]),
            "a {prefix_len}-char proof prefix survived truncation: {excerpt:?}"
        );
    }
}

/// A credential sitting beyond the excerpt limit but inside the scan window
/// must not be recorded, and must not corrupt what IS recorded: the window
/// exists to bound work, never to bound protection.
#[test]
fn nothing_outside_the_scan_window_can_be_recorded() {
    let filler = "x".repeat(4096);
    let raw = format!("head line\n{filler}\nset-cookie: session={FAKE_PROOF}\n");

    // Limit smaller than the offset of the credential: it must be truncated
    // away AND redacted, not one or the other.
    let excerpt = recorded_excerpt(raw.as_bytes(), 32);
    assert!(!excerpt.contains(&FAKE_PROOF[..8]), "{excerpt:?}");

    // Limit large enough to reach the credential: it must be redacted.
    let wide = recorded_excerpt(raw.as_bytes(), 1_000_000);
    assert!(!wide.contains(&FAKE_PROOF[..8]), "{wide}");
    assert!(
        wide.contains("set-cookie"),
        "header name must survive: {wide}"
    );
    assert!(wide.contains("head line"), "{wide}");
}

// ---------------------------------------------------------------------------
// Scope: an HTTP message has a header section, stdout does not
// ---------------------------------------------------------------------------

/// The two scopes differ in exactly one way, and it is the way that matters:
/// unstructured text has no header/body separator to hide behind.
///
/// A tool that prints a `curl -i` dump puts its credential lines somewhere in
/// the middle of its stdout. Under HTTP scope those lines are "body" and are
/// left alone — correct for a real response, catastrophic for stdout.
#[test]
fn any_text_scope_redacts_below_a_blank_line_where_http_scope_does_not() {
    let text = format!("running curl -i\n\nauthorization: Bearer {FAKE_PROOF}\n");

    let as_http = redact_bearer_headers(&text);
    let as_text = redact_recorded_text(&text);

    // #353's HTTP behaviour is unchanged: below the separator is body.
    assert!(
        as_http.contains(FAKE_PROOF),
        "HTTP-scope redaction must still treat post-separator content as body: {as_http}"
    );
    // Unstructured text gets no such benefit of the doubt.
    assert!(!as_text.contains(&FAKE_PROOF[..8]), "{as_text}");
    assert!(as_text.contains("authorization"), "{as_text}");
}

/// Unstructured text has no status line either, so line 0 is eligible. A
/// process whose very first stdout line is a credential is the easy case to get
/// wrong by copying the HTTP parser wholesale.
#[test]
fn the_first_line_of_unstructured_text_is_not_treated_as_a_status_line() {
    let text = format!("x-api-key: {FAKE_PROOF}\nsecond line\n");

    let redacted = redact_recorded_text(&text);

    assert!(!redacted.contains(&FAKE_PROOF[..8]), "{redacted}");
    assert!(redacted.contains("x-api-key"), "{redacted}");
    assert!(redacted.contains("second line"), "{redacted}");
}

// ---------------------------------------------------------------------------
// The metadata sweep: the net under the excerpt helpers
// ---------------------------------------------------------------------------

/// The inheritance property, stated as a test.
///
/// This map is what a family that never heard of an "excerpt helper" produces:
/// a key nobody classified, holding raw observed text. It must still come out
/// clean, because that is what "recorded" means in this crate.
#[test]
fn recorded_metadata_sweeps_values_that_never_went_through_an_excerpt_helper() {
    let metadata = recorded_metadata([
        ("external_action".to_string(), "some.new.family".to_string()),
        (
            "a_key_nobody_called_an_excerpt".to_string(),
            format!(
                "HTTP/1.1 200 OK\nauthorization: Bearer {FAKE_PROOF}\ncookie: sid={FAKE_PROOF}"
            ),
        ),
    ]);

    let recorded = metadata
        .get("a_key_nobody_called_an_excerpt")
        .expect("value recorded");
    assert!(!recorded.contains(&FAKE_PROOF[..8]), "{recorded}");
    assert_eq!(
        recorded.matches(REDACTED_HEADER_VALUE).count(),
        2,
        "both credential values must be replaced: {recorded}"
    );
    // Values that are not credentials are untouched, so the record stays useful.
    assert_eq!(
        metadata.get("external_action").map(String::as_str),
        Some("some.new.family")
    );
}

/// The in-place sweep used by maps that are built incrementally (the REST
/// builders, the microVM guest event writer) has to behave identically.
#[test]
fn the_in_place_sweep_matches_the_constructor() {
    let mut built = std::collections::BTreeMap::from([(
        "output_excerpt".to_string(),
        format!("set-cookie: session={FAKE_PROOF}"),
    )]);

    redact_recorded_values(built.values_mut());

    let recorded = built.get("output_excerpt").expect("value recorded");
    assert!(!recorded.contains(&FAKE_PROOF[..8]), "{recorded}");
    assert!(recorded.contains("set-cookie"), "{recorded}");
}

/// The sweep runs on top of already-redacted excerpts, so it must be a no-op
/// there. If it were not idempotent, every value would accumulate `<redacted>`
/// markers and the counts the #353 tests assert would drift.
#[test]
fn redaction_is_idempotent() {
    let raw = format!("HTTP/1.1 200 OK\r\nauthorization: Bearer {FAKE_PROOF}\r\n\r\nbody");

    let once = redact_recorded_text(&raw);
    let twice = redact_recorded_text(&once);

    assert_eq!(once, twice);
    assert_eq!(once.matches(REDACTED_HEADER_VALUE).count(), 1, "{once}");
}

// ---------------------------------------------------------------------------
// The recorded-header-value policy (#526)
// ---------------------------------------------------------------------------

/// The decision, pinned: NAMES and non-credential VALUES are recorded; only
/// bearer values are replaced. A future edit that switches to "record nothing"
/// or to a whitelist breaks this, which is the point — it would silently
/// destroy the #354 payment audit trail and the diagnostic value of every
/// excerpt in the crate.
#[test]
fn non_credential_header_values_are_recorded_verbatim() {
    let text = format!(
        "retry-after: 30\nPAYMENT-RESPONSE: settlement-blob\nauthorization: Bearer {FAKE_PROOF}\n"
    );

    let redacted = redact_recorded_text(&text);

    assert!(redacted.contains("retry-after: 30"), "{redacted}");
    assert!(
        redacted.contains("PAYMENT-RESPONSE: settlement-blob"),
        "public settlement evidence must survive verbatim (#354): {redacted}"
    );
    assert!(!redacted.contains(&FAKE_PROOF[..8]), "{redacted}");
    assert_eq!(
        redacted.matches(REDACTED_HEADER_VALUE).count(),
        1,
        "{redacted}"
    );
}

/// Every name on the deny-list is covered in the unstructured scope too, not
/// just in a real HTTP header section.
#[test]
fn every_bearer_header_name_is_redacted_in_unstructured_text() {
    for name in [
        "authorization",
        "Proxy-Authorization",
        "cookie",
        "SET-COOKIE",
        "authentication",
        "x-api-key",
        "X-Auth-Token",
        "PAYMENT-SIGNATURE",
    ] {
        let text = format!("prelude\n{name}: {FAKE_PROOF}\n");

        let redacted = redact_recorded_text(&text);

        assert!(
            !redacted.contains(&FAKE_PROOF[..8]),
            "{name} was not treated as bearer material: {redacted}"
        );
        assert!(redacted.contains(name), "{name} lost its name: {redacted}");
    }
}
