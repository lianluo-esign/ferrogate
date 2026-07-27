// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, unit gates for the #470
// governed-decision value: the source scan that keeps the error vocabulary
// honest, canonical serialisation, decimal-string money parsing, and the
// directional-conformance predicate for a veto-only second host.

use super::*;

/// Every governed error code literal the proxy can emit, recovered from the
/// source rather than from a hand-maintained list.
///
/// This is the mechanism that makes the coverage gate load-bearing: adding a
/// new governed outcome to `chat.rs` or `auth.rs` makes this scan find a code
/// with no vocabulary entry, which fails
/// [`scanner_finds_no_governed_code_outside_the_vocabulary`] and forces the
/// author to state the stage and the fixture obligation.
///
/// Three literal shapes are recognised, matching how the two files actually
/// write codes today:
///
/// 1. `code: "..."` -- the struct-literal form used by `AuthError`,
///    `AiRequestRejection` and `AiWorkflowRejection`;
/// 2. a bare `"...",` line whose preceding lines carry a `StatusCode::` (the
///    positional `write_json_error(session, status, code, ...)` form); and
/// 3. a bare `"...",` line immediately followed by `format!(` -- the
///    `(code, message)` tuple form used for `model_disabled` /
///    `model_not_found`.
fn scan_governed_codes(source: &str) -> BTreeSet<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(code) = scan_struct_field_code(line) {
            found.insert(code);
        }
        let Some(literal) = scan_bare_string_literal(line) else {
            continue;
        };
        let preceded_by_status = lines[index.saturating_sub(3)..index]
            .iter()
            .any(|previous| previous.contains("StatusCode::") || previous.contains(".status"));
        let followed_by_message = lines
            .get(index + 1)
            .is_some_and(|next| next.trim_start().starts_with("format!("));
        if preceded_by_status || followed_by_message {
            found.insert(literal);
        }
    }
    found
}

/// `... code: "some_code" ...` -> `some_code`.
fn scan_struct_field_code(line: &str) -> Option<String> {
    let rest = line.split_once("code:")?.1.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (code, _) = rest.split_once('"')?;
    is_code_shaped(code).then(|| code.to_string())
}

/// A line that is exactly `"some_code",` -> `some_code`.
fn scan_bare_string_literal(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let inner = trimmed.strip_prefix('"')?.strip_suffix("\",")?;
    is_code_shaped(inner).then(|| inner.to_string())
}

fn is_code_shaped(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn scanned_governed_codes() -> BTreeSet<String> {
    let mut codes = scan_governed_codes(include_str!("chat.rs"));
    // #553 stage 3b-0 split the old `auth.rs` in two -- the credential and
    // tenant-isolation refusals (`invalid_api_key`, `scope_denied`,
    // `tenant_scope_denied`, ...) went to `ferrogate-gateway` with the
    // vocabulary that emits them, while the governance refusals
    // (`monthly_budget_exceeded`, `rate_limit_exceeded`, ...) stayed with the
    // admission pipeline -- so this scanned BOTH halves through two
    // `include_str!` paths. Stage 3b merged them back into one module, and
    // both of those paths now name the SAME file. One of them is therefore
    // gone: scanning it twice is harmless, but leaving a stale second path
    // that silently resolves to something else is not, because
    // `vocabulary_carries_no_stale_entries` would start deleting real entries
    // rather than failing. `../auth.rs` is `ferrogate-gateway/src/auth.rs`
    // from here, and it holds every refusal both halves used to emit.
    codes.extend(scan_governed_codes(include_str!("../auth.rs")));
    codes
}

#[test]
fn scanner_finds_no_governed_code_outside_the_vocabulary() {
    let known = governed_error_code_set();
    let unknown: Vec<String> = scanned_governed_codes()
        .into_iter()
        .filter(|code| !known.contains(code.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "these governed error codes are emitted by the proxy but have no entry in \
         GOVERNED_ERROR_VOCABULARY: {unknown:?}. Add one, declaring the stage it is produced at \
         and whether a conformance fixture is required."
    );
}

#[test]
fn vocabulary_carries_no_stale_entries() {
    let scanned = scanned_governed_codes();
    let stale: Vec<&str> = GOVERNED_ERROR_VOCABULARY
        .iter()
        .map(|entry| entry.code)
        .filter(|code| !scanned.contains(*code))
        .collect();
    assert!(
        stale.is_empty(),
        "these vocabulary entries no longer correspond to any code in chat.rs or auth.rs: \
         {stale:?}. A renamed or removed governed outcome must not leave the vocabulary \
         claiming coverage of something that cannot happen."
    );
}

#[test]
fn vocabulary_has_no_duplicate_codes() {
    let mut seen = BTreeSet::new();
    for entry in GOVERNED_ERROR_VOCABULARY {
        assert!(
            seen.insert(entry.code),
            "{} appears twice in GOVERNED_ERROR_VOCABULARY; the second entry's coverage \
             decision would be silently ignored",
            entry.code
        );
    }
}

#[test]
fn every_uncovered_code_states_why_in_prose() {
    for entry in GOVERNED_ERROR_VOCABULARY {
        if entry.coverage.is_required() {
            continue;
        }
        let reason = entry
            .coverage
            .reason()
            .unwrap_or_else(|| panic!("{} has no coverage reason", entry.code));
        assert!(
            reason.len() > 30,
            "{}'s reason for having no fixture is too thin to review: {reason:?}",
            entry.code
        );
    }
}

#[test]
fn dispatch_stage_codes_are_the_only_pending_seam_entries() {
    // Guards the boundary claim in the module docs: the "not a value yet"
    // excuse belongs to the dispatch loop and nowhere else. If an admission
    // code ever acquires it, the seam has regressed.
    for entry in GOVERNED_ERROR_VOCABULARY {
        if matches!(entry.coverage, FixtureCoverage::PendingDispatchSeam(_)) {
            assert_eq!(
                entry.stage,
                GovernedStage::Dispatch,
                "{} claims the dispatch seam is why it has no fixture, but it is not a \
                 dispatch-stage code",
                entry.code
            );
        }
    }
}

#[test]
fn canonical_json_sorts_keys_and_omits_delivery_context() {
    let record = GovernedDecisionRecord::deny(StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded");
    assert_eq!(
        record.canonical_json(),
        r#"{"audit_events":[],"code":"rate_limit_exceeded","durable_writes":["request_log"],"metered":{"completion_tokens":0,"credits_captured":"0","credits_reserved":"0","prompt_tokens":0},"outcome":"deny","schema":1,"status":429}"#
    );
}

#[test]
fn canonical_json_round_trips_byte_identically() {
    let record = GovernedDecisionRecord::deny(StatusCode::FORBIDDEN, "region_not_allowed");
    let json = record.canonical_json();
    let parsed: GovernedDecisionRecord =
        serde_json::from_str(&json).expect("canonical JSON must parse back into the record");
    assert_eq!(parsed.canonical_json(), json);
    assert_eq!(parsed, record);
}

#[test]
fn amounts_must_be_non_negative_base_ten_integers_in_strings() {
    assert_eq!(parse_amount("0"), Ok(0));
    assert_eq!(parse_amount("1000"), Ok(1000));
    // The #469 discipline: a float, a sign, padding or an empty string is not
    // an amount, and must be rejected before anything compares it.
    for rejected in ["1.0", "1e3", "-1", " 1", "1 ", "", "0x10", "1_000"] {
        assert!(
            parse_amount(rejected).is_err(),
            "{rejected:?} must not parse as a credit amount"
        );
    }
}

#[test]
fn a_veto_only_host_may_defer_or_deny_but_never_allow() {
    let authority = GovernedDecisionRecord::admitted();

    let mut defer = GovernedDecisionRecord::admitted();
    defer.outcome = GovernedOutcome::Defer;
    defer.status = 0;
    assert!(directional_conformance(&authority, &defer).is_ok());

    let deny = GovernedDecisionRecord::deny(StatusCode::UNAUTHORIZED, "invalid_api_key");
    assert!(directional_conformance(&authority, &deny).is_ok());

    let error = directional_conformance(&authority, &GovernedDecisionRecord::admitted())
        .expect_err("a veto-only host authoring an allow must fail");
    assert!(error.contains("may never author an allow"), "{error}");
}

#[test]
fn a_veto_only_host_may_never_author_a_metered_amount() {
    let authority = GovernedDecisionRecord::deny(StatusCode::FORBIDDEN, "model_not_allowed");
    let mut candidate = GovernedDecisionRecord::deny(StatusCode::FORBIDDEN, "model_not_allowed");
    candidate.metered.credits_reserved = "1".to_string();
    let error = directional_conformance(&authority, &candidate)
        .expect_err("a veto-only host reserving credits must fail");
    assert!(error.contains("authored a metered amount"), "{error}");

    let mut estimating = GovernedDecisionRecord::deny(StatusCode::FORBIDDEN, "model_not_allowed");
    estimating.metered.prompt_tokens = 12;
    assert!(directional_conformance(&authority, &estimating).is_err());
}

#[test]
fn a_veto_only_host_must_deny_in_the_shared_vocabulary() {
    let authority = GovernedDecisionRecord::admitted();
    let mut candidate = GovernedDecisionRecord::deny(StatusCode::FORBIDDEN, "invalid_api_key");
    candidate.code = Some("worker_said_no".to_string());
    let error = directional_conformance(&authority, &candidate)
        .expect_err("an off-vocabulary deny code must fail");
    assert!(error.contains("not in the governed vocabulary"), "{error}");

    candidate.code = None;
    assert!(directional_conformance(&authority, &candidate).is_err());
}

#[test]
fn a_veto_only_host_may_not_serve_from_cache() {
    // Trap 3 of the decision record's §3: answering from an edge cache skips
    // the request log, the cache-hit metric and everything the origin would
    // have done. It is a governed decision, not a transport optimisation.
    let authority = GovernedDecisionRecord::admitted();
    let mut candidate = GovernedDecisionRecord::admitted();
    candidate.outcome = GovernedOutcome::CacheHit;
    assert!(directional_conformance(&authority, &candidate).is_err());
}
