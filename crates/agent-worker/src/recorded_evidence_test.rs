// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The shared recorded-evidence chokepoint (#526).
//!
//! #353 proved the REST family's excerpt does not leak. These tests pin the
//! properties that make that true for EVERY family — the truncation sweep, the
//! scope split, the argv join and the metadata net — at the one place they are
//! implemented, so a family added later inherits proven behaviour instead of a
//! copied fix.
//!
//! Every assertion here is on the RECORDED VALUE. None of them asserts that a
//! function was called or that a line of source exists.

use super::*;

/// A fake credential long enough that a surviving PREFIX would still be an
/// obvious leak. Nothing here is a real secret.
const FAKE_PROOF: &str = "FAKEPROOFDONOTLOG0123456789abcdefghijklmnopqrstuvwxyz\
                          FAKEPROOFDONOTLOG0123456789abcdefghijklmnopqrstuvwxyz";

// ---------------------------------------------------------------------------
// Truncation cannot leave a usable credential prefix — at ANY cut point
// ---------------------------------------------------------------------------

/// The property the excerpt helpers actually owe, swept over the WHOLE
/// truncation space rather than at one hand-picked limit.
///
/// This deliberately replaces an earlier `recorded_excerpt_redacts_before_it_
/// truncates`, which claimed to hold an ORDERING and did not: this redactor is
/// line-anchored and prefix-stable, so swapping redaction and truncation
/// changes only the LENGTH of the record, never its safety (see the module
/// docs). What is real, and what this holds, is that no cut point of a
/// credential-bearing blob yields a recorded excerpt containing any usable
/// prefix of the credential — while the header NAME still survives wherever the
/// cut left room for it.
#[test]
fn no_truncation_point_of_recorded_excerpt_leaves_a_usable_credential_prefix() {
    // Credential FIRST, exactly where a surviving prefix would land.
    let raw = format!("authorization: Bearer {FAKE_PROOF}\nbody line\n");

    let mut saw_a_surviving_header_name = false;
    for byte_limit in 0..=raw.len() {
        let excerpt = recorded_excerpt(
            RecordedSurface::CliOutput,
            raw.as_bytes(),
            byte_limit as u64,
        );

        assert!(
            excerpt.len() <= byte_limit,
            "limit {byte_limit} not honored: {excerpt:?}"
        );
        for prefix_len in [8, 16, 32] {
            assert!(
                !excerpt.contains(&FAKE_PROOF[..prefix_len]),
                "a {prefix_len}-char credential prefix survived a {byte_limit}-byte cut: \
                 {excerpt:?}"
            );
        }
        saw_a_surviving_header_name |= excerpt.contains("authorization");
    }

    // Non-vacuity: the loop is not passing because everything was cut away.
    assert!(
        saw_a_surviving_header_name,
        "the header NAME must survive at wide limits so the record still shows a credential \
         was present"
    );
    let wide = recorded_excerpt(RecordedSurface::CliOutput, raw.as_bytes(), 4_096);
    assert!(wide.contains("body line"), "{wide:?}");
    assert!(wide.contains(REDACTED_HEADER_VALUE), "{wide:?}");
}

/// Same obligation for the line-oriented helper (microVM serial / hypervisor
/// logs), swept over every line cap: the credential must never be recorded, at
/// any cap that keeps its line.
#[test]
fn no_line_cap_of_recorded_line_excerpt_records_the_credential() {
    let raw = format!("boot line\nauthorization: Bearer {FAKE_PROOF}\ntail line\n");

    for max_lines in 0..=4 {
        let excerpt =
            recorded_line_excerpt(RecordedSurface::FirecrackerBootEvidence, &raw, max_lines);
        assert!(!excerpt.contains(&FAKE_PROOF[..8]), "{excerpt:?}");
        assert!(
            excerpt.lines().count() <= max_lines,
            "line cap {max_lines} not honored: {excerpt:?}"
        );
    }

    // Non-vacuity at the cap that keeps exactly the credential's line.
    let two = recorded_line_excerpt(RecordedSurface::FirecrackerBootEvidence, &raw, 2);
    assert!(two.starts_with("boot line"), "{two:?}");
    assert!(two.contains("authorization"), "{two:?}");
    assert!(two.contains(REDACTED_HEADER_VALUE), "{two:?}");
    assert!(!two.contains("tail line"), "{two:?}");
}

/// The REST helper keeps #353's contract verbatim: the response excerpt is
/// capped at `char_limit` characters and no prefix of the proof survives.
#[test]
fn the_rest_response_excerpt_records_no_proof_prefix_under_its_char_cap() {
    let raw = format!("HTTP/1.1 200 OK\r\nPAYMENT-SIGNATURE: {FAKE_PROOF}\r\n\r\nbody");

    let excerpt = recorded_http_excerpt(RecordedSurface::RestResponse, &raw, 48);

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
    assert!(excerpt.contains("PAYMENT-SIGNATURE"), "{excerpt:?}");
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
    let excerpt = recorded_excerpt(RecordedSurface::CliOutput, raw.as_bytes(), 32);
    assert!(!excerpt.contains(&FAKE_PROOF[..8]), "{excerpt:?}");

    // Limit large enough to reach the credential: it must be redacted.
    let wide = recorded_excerpt(RecordedSurface::CliOutput, raw.as_bytes(), 1_000_000);
    assert!(!wide.contains(&FAKE_PROOF[..8]), "{wide}");
    assert!(
        wide.contains("set-cookie"),
        "header name must survive: {wide}"
    );
    assert!(wide.contains("head line"), "{wide}");
}

/// The scan window is a WORK bound, and the invariant that makes it safe is
/// that it is never smaller than the record — which is what this pins.
///
/// Stated plainly, because the test above is named as if the window were a
/// protection boundary and the review found its 4 KiB fixture never reached the
/// 64 KiB boundary at all: no edit to the window expression can leak. The
/// record is built FROM the window, so a smaller window can only produce a
/// shorter record, never an unscanned one. That is the same kind of comforting
/// claim as the withdrawn redaction-before-truncation one, and it gets the same
/// treatment — the property is named for what it is rather than dressed up.
///
/// What the window CAN get wrong is usefulness, and that is observable.
/// Redaction shortens a credential line from hundreds of bytes to
/// `<redacted>`, so content that sat far beyond `byte_limit` in the RAW buffer
/// is pulled up into the record. It must therefore have been scanned. Pins
/// `recorded_excerpt`'s `byte_limit.max(EVIDENCE_SCAN_BYTES)`: replacing that
/// `max` with `min` — the one edit that makes the scan smaller than what the
/// caller asked to record — drops the second credential's line out of the
/// record entirely and reds this test.
#[test]
fn the_scan_window_is_never_smaller_than_what_it_records() {
    assert_eq!(
        EVIDENCE_SCAN_BYTES,
        64 * 1024,
        "this fixture is sized against the window; resize it deliberately"
    );

    // A very long credential line, then a second credential line far beyond any
    // sane excerpt limit.
    let long_value = "a".repeat(4_096);
    let raw =
        format!("set-cookie: session={long_value}\nauthorization: Bearer {FAKE_PROOF}\nend\n");
    // The second credential starts well past the limit we are about to ask for.
    assert!(raw.find("authorization").expect("fixture") > 4_000);

    let excerpt = recorded_excerpt(RecordedSurface::CliOutput, raw.as_bytes(), 128);

    assert!(excerpt.len() <= 128, "limit not honored: {excerpt:?}");
    assert!(!excerpt.contains(&FAKE_PROOF[..8]), "{excerpt:?}");
    assert!(!excerpt.contains(&long_value[..64]), "{excerpt:?}");
    // Both lines are IN the 128-byte record, because redaction shortened the
    // first one. The scan therefore had to reach the second.
    assert!(excerpt.starts_with("set-cookie: "), "{excerpt:?}");
    assert!(
        excerpt.contains("authorization"),
        "content beyond byte_limit is pulled into the record by redaction, so the window must \
         have scanned it: {excerpt:?}"
    );
    assert_eq!(
        excerpt.matches(REDACTED_HEADER_VALUE).count(),
        2,
        "{excerpt:?}"
    );

    // And the other half of the bound: content beyond the WINDOW is dropped,
    // never recorded, so a buffer larger than the window is safe to excerpt.
    let filler = "f".repeat(EVIDENCE_SCAN_BYTES);
    let huge = format!("head\n{filler}\nset-cookie: tail={FAKE_PROOF}\n");
    assert!(
        huge.len() > EVIDENCE_SCAN_BYTES,
        "fixture must exceed window"
    );
    let capped = recorded_excerpt(RecordedSurface::CliOutput, huge.as_bytes(), 256);
    assert!(!capped.contains(&FAKE_PROOF[..8]), "{}", &capped[..64]);
    assert!(capped.starts_with("head\n"), "{}", &capped[..16]);
}

// ---------------------------------------------------------------------------
// Scope is a property of the SURFACE, not of the call site
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

/// Exactly ONE recorded surface may be parsed as a raw HTTP message. Narrowing
/// any other surface to `HttpMessage` re-opens the leak above: a process's
/// stdout has no header section, so everything below its first blank line would
/// stop being scanned.
///
/// The list is written out rather than derived from `scope()`, so a future edit
/// that reclassifies a surface has to argue with this test instead of dragging
/// it along.
#[test]
fn only_the_rest_response_surface_is_parsed_as_a_raw_http_message() {
    // A credential below a blank line: recorded iff the surface is HTTP-scoped.
    let text = format!("preamble\n\nx-api-key: {FAKE_PROOF}\n");

    for surface in [
        RecordedSurface::ToolOutput,
        RecordedSurface::McpToolOutput,
        RecordedSurface::SkillOutput,
        RecordedSurface::MemoryValue,
        RecordedSurface::FilesystemContent,
        RecordedSurface::CliOutput,
        RecordedSurface::HandlerBinaryOutput,
        RecordedSurface::GuestWorkloadOutput,
        RecordedSurface::FirecrackerBootEvidence,
        RecordedSurface::GovernedWorkloadOutput,
        RecordedSurface::Argv,
    ] {
        let recorded = recorded_value(surface, &text);
        assert!(
            !recorded.contains(&FAKE_PROOF[..8]),
            "{surface:?} is not a raw HTTP message, so a credential below a blank line is \
             still a credential: {recorded}"
        );
    }

    // And the one surface that IS a raw HTTP message keeps #353's structure.
    let rest = recorded_value(RecordedSurface::RestResponse, &text);
    assert!(
        rest.contains(FAKE_PROOF),
        "the REST surface must keep treating post-separator content as body: {rest}"
    );
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
// Argument vectors: the join is the leak
// ---------------------------------------------------------------------------

/// `recorded_argv` owns the separator because the separator is the defect.
///
/// The scanner classifies a line by its FIRST colon, so two argv entries sharing
/// one line hide the credential's header name behind whatever flag preceded it:
/// `--header authorization: Bearer …` parses as the field `--header
/// authorization`, which is not a bearer name, and the whole credential is
/// recorded. Giving every argument its own line is the entire fix, and this is
/// the assertion that holds it.
#[test]
fn a_credential_bearing_argument_is_not_recorded_whatever_flag_precedes_it() {
    for flag in ["--header", "-H", "--data", "--reject-with"] {
        let argv = [
            flag.to_string(),
            format!("authorization: Bearer {FAKE_PROOF}"),
        ];

        let recorded = recorded_argv(&argv);

        assert!(
            !recorded.contains(&FAKE_PROOF[..8]),
            "argument after {flag} was recorded verbatim: {recorded}"
        );
        // Non-vacuity: the argv really was recorded, names and all.
        assert!(recorded.contains(flag), "{recorded}");
        assert!(recorded.contains("authorization"), "{recorded}");
        assert!(recorded.contains(REDACTED_HEADER_VALUE), "{recorded}");
    }
}

/// Every credential header name FerroGate itself sends is a plausible argv
/// value too (`curl --header "x-goog-api-key: …"`), so the argv join has to
/// cover the same list, not just `authorization`.
#[test]
fn every_credential_header_ferrogate_emits_is_covered_by_the_argv_join() {
    for (header, definition_site) in CREDENTIAL_HEADERS_FERROGATE_EMITS {
        let argv = ["--header".to_string(), format!("{header}: {FAKE_PROOF}")];

        let recorded = recorded_argv(&argv);

        assert!(
            !recorded.contains(&FAKE_PROOF[..8]),
            "{header} (defined at {definition_site}) survived the argv join: {recorded}"
        );
    }
}

/// A single argument holding no credential is recorded verbatim, so the record
/// still says what was actually run.
#[test]
fn a_credential_free_argv_is_recorded_verbatim() {
    let argv = [
        "/usr/bin/curl",
        "--max-time",
        "5",
        "https://example.invalid",
    ];

    let recorded = recorded_argv(&argv);

    assert_eq!(
        recorded,
        "/usr/bin/curl\n--max-time\n5\nhttps://example.invalid"
    );
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
// The deny-list, enumerated from the OTHER side (#526 rework)
// ---------------------------------------------------------------------------

/// The credential headers FERROGATE ITSELF puts on the wire, each paired with
/// the file that defines it.
///
/// This table is the point of the whole section. A test that loops over
/// `is_bearer_header`'s own array is definitionally incapable of catching an
/// omission from that array — it asserts the list covers itself. This one is
/// derived from a DIFFERENT source of truth: the header names the provider,
/// secret-resolver and credential-broker crates emit. Five of these were
/// missing from the deny-list when #526 first landed, which meant a workload
/// that printed its own upstream call leaked in full against Azure OpenAI,
/// Gemini, Bedrock, Cloudflare AI Gateway and Vault.
///
/// Adding a provider means adding its credential header here. That is the
/// maintenance cost, and it is the correct place to pay it — a name in this
/// table with no entry in `is_bearer_header` fails; the reverse is harmless.
const CREDENTIAL_HEADERS_FERROGATE_EMITS: [(&str, &str); 10] = [
    ("authorization", "ferrogate-providers/src/openai.rs"),
    ("authorization", "ferrogate-providers/src/vertex.rs"),
    (
        "authorization",
        "ferrogate-providers/src/bedrock.rs (SigV4)",
    ),
    ("x-api-key", "ferrogate-providers/src/anthropic.rs"),
    ("api-key", "ferrogate-providers/src/azure.rs"),
    ("x-goog-api-key", "ferrogate-providers/src/gemini.rs"),
    ("x-amz-security-token", "ferrogate-providers/src/bedrock.rs"),
    (
        "cf-aig-authorization",
        "ferrogate-providers/src/cloudflare.rs",
    ),
    ("X-Vault-Token", "ferrogate-secrets/src/lib.rs"),
    (
        "x-access-token",
        "ferrogate-runtime/src/coding_agent/credential_broker.rs",
    ),
];

/// Every credential header this repository sends must be redacted out of
/// unstructured recorded text — that is the `curl -i` dump the `AnyText` scope
/// exists for, and it is worthless if it only knows `authorization`.
#[test]
fn every_credential_header_ferrogate_emits_is_redacted_in_unstructured_text() {
    for (header, definition_site) in CREDENTIAL_HEADERS_FERROGATE_EMITS {
        // Mid-blob, below a blank line, exactly as a tool's `curl -i` output
        // would land in a stdout excerpt.
        let text = format!("$ curl -i https://upstream.invalid\n\n{header}: {FAKE_PROOF}\nok\n");

        let redacted = redact_recorded_text(&text);

        assert!(
            !redacted.contains(&FAKE_PROOF[..8]),
            "{header} (sent by FerroGate at {definition_site}) is not on the deny-list: \
             {redacted}"
        );
        assert!(
            redacted.contains(header),
            "{header} lost its name: {redacted}"
        );
        assert!(redacted.contains("ok"), "{redacted}");
    }
}

/// The generic credential names that are not tied to one provider: browser
/// session material, proxy credentials and the x402 payment proof.
#[test]
fn the_generic_bearer_names_are_redacted_in_unstructured_text() {
    for name in [
        "Proxy-Authorization",
        "cookie",
        "SET-COOKIE",
        "authentication",
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

/// A deny-list entry must not swallow a NEIGHBOURING name. `cf-aig-authorization`
/// and `authorization` are different credentials on different hops, and
/// `x-api-key` and `api-key` are different providers' headers; matching by
/// substring rather than by whole name would blank diagnostics that are not
/// credentials at all (`x-request-cookie-count`).
#[test]
fn deny_list_matching_is_by_whole_name_not_by_substring() {
    let text = "x-request-cookie-count: 4\nauthorization-scheme-debug: negotiate\n";

    let redacted = redact_recorded_text(text);

    assert_eq!(redacted, text, "non-credential diagnostics must survive");
}
